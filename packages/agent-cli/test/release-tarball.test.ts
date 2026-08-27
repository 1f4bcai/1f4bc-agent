import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'
import {
  EXPECTED_PACKAGE_FILES,
  findSecretFindings,
  validateReleaseTarball,
  validateSourceMap,
} from '../scripts/validate-release-tarball.mjs'
import { compareReviewedBuild } from '../scripts/verify-independent-rebuild.mjs'
import { generateReleaseSbom } from '../scripts/generate-release-sbom.mjs'

const execFileAsync = promisify(execFile)
const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

describe('release tarball validation', () => {
  it('uses an exact self-contained 17-file allowlist', () => {
    expect([...EXPECTED_PACKAGE_FILES.keys()]).toHaveLength(17)
    expect([...EXPECTED_PACKAGE_FILES.keys()]).toEqual(
      expect.arrayContaining([
        'package.json',
        'README.md',
        'LICENSE',
        'dist/index.js',
        'dist/index.d.ts',
        'dist/runtime.js',
        'dist/THIRD_PARTY_COMPONENTS.cdx.json',
        'dist/THIRD_PARTY_NOTICES.txt',
      ]),
    )
  })

  it('rejects credential-shaped content without flagging public hashes', () => {
    expect(findSecretFindings(
      'CURRENT_TERMS_SHA256=cc6b85e1e686d6b19ef30e87488511d66aeedbc99d9e76ea36b36f7ee8823ed9',
    )).toEqual([])
    expect(findSecretFindings(
      'CURRENT_ACCEPTABLE_USE_SHA256=6b5f50ad76df7f773635731ec33c4f77598e03a02ddc6d0b8ac06d627abff0cd',
    )).toEqual([])
    expect(findSecretFindings(
      'CURRENT_PRIVACY_SHA256=561f162c21e445f41dd8e93908ecd2174432909a8d572bcf755a870da245dca1',
    )).toEqual([])
    expect(findSecretFindings(
      'PREVIOUS_TERMS_SHA256=e5b4de1e70d82743363a6c158a8f317c76b953fbee2d1d952795f3cb5313736e',
    )).toEqual([])
    expect(findSecretFindings(
      'PREVIOUS_PRIVACY_SHA256=cd1f2ef3b25439a53d311a2158698dc71a89f104b0a81a94e13f714d46622ec3',
    )).toEqual([])
    expect(findSecretFindings(
      'const topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"',
    )).toEqual([])
    expect(findSecretFindings(
      'NODE20_ARCHIVE_SHA256=2dd1f5c0e01732024ba1f5de4517fa3976eb0976fa7976ff687ec09b62dd73fa',
    )).toEqual([])
    expect(findSecretFindings(
      `"integrity":"sha512-${'a'.repeat(36)}/${'c'.repeat(49)}=="`,
    )).toEqual([])
    expect(findSecretFindings(
      `"integrity":"sha256-${Buffer.alloc(32, 9).toString('base64')}"`,
    )).toEqual([])
    expect(findSecretFindings(`"sha512-${'a'.repeat(36)}"`))
      .toContain('secret-shaped 32-byte Base64 value')
    expect(findSecretFindings('const key = "0x' + 'a'.repeat(64) + '"'))
      .toContain('secret-shaped 32-byte hex value')
    expect(findSecretFindings('const key = "' + 'b'.repeat(64) + '"'))
      .toContain('secret-shaped 32-byte hex value')
    expect(findSecretFindings(Buffer.alloc(32, 7).toString('base64')))
      .toContain('secret-shaped 32-byte Base64 value')
    for (const value of ['/'.repeat(42) + '8', '+'.repeat(42) + '8']) {
      expect(findSecretFindings(value))
        .toContain('secret-shaped 32-byte Base64 value')
      expect(findSecretFindings(`const value='${value}'`))
        .toContain('secret-shaped 32-byte Base64 value')
    }
    expect(findSecretFindings(Buffer.alloc(32, 8).toString('base64url')))
      .toContain('secret-shaped 32-byte Base64 value')
    expect(findSecretFindings(
      `const value='${Buffer.alloc(32, 8).toString('base64url')}'`,
    )).toContain('secret-shaped 32-byte Base64 value')
    const randomBase64Url = [
      'PqjTPNyTycbynCQl9lN8tfF6',
      'nXoqU-DS6OYg7FyQgdo',
    ].join('')
    expect(findSecretFindings(`const value='${randomBase64Url}'`))
      .toContain('secret-shaped 32-byte Base64 value')
    for (const property of ['token', 'apiKey', 'privateKey']) {
      expect(findSecretFindings(`{"${property}":"abcdefghijklmnop"}`))
        .toContain('quoted literal assigned credential')
    }
    for (const name of ['API_KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PRIVATE_KEY']) {
      expect(findSecretFindings(`${name}=abcdefghijklmnop`))
        .toContain('unquoted environment credential')
    }
    expect(findSecretFindings('token=npm_' + 'a'.repeat(36))).toContain('npm access token')
    expect(findSecretFindings('glpat-' + 'a'.repeat(24))).toContain('GitLab token')
    expect(findSecretFindings('CF_API_TOKEN=' + 'a'.repeat(40)))
      .toContain('unquoted environment credential')
    expect(findSecretFindings('https://alice' + ':password@example.test')).toContain(
      'credential-bearing URL',
    )
    expect(findSecretFindings('-----BEGIN ' + 'PRIVATE KEY-----')).toContain('private key PEM')
  })

  it('rejects source-map source contents and absolute paths', () => {
    expect(() =>
      validateSourceMap('dist/index.js.map', {
        version: 3,
        sources: ['../src/index.ts'],
        sourcesContent: ['secret source'],
      }),
    ).toThrow(/sourcesContent/)
    expect(() =>
      validateSourceMap('dist/index.js.map', {
        version: 3,
        sources: ['/Users/releaser/src/index.ts'],
      }),
    ).toThrow(/relative/)
  })

  const packIntegration = process.env.F4BC_RELEASE_PACK_ONCE === '1' ? it.skip : it

  packIntegration('validates the actual npm tarball and records exact file hashes and sizes', async () => {
    const output = await mkdtemp(join(tmpdir(), 'agent-cli-pack-test-'))
    try {
      const { stdout } = await execFileAsync(
        'npm',
        ['pack', '--ignore-scripts', '--json', '--pack-destination', output],
        { cwd: packageRoot },
      )
      const pack = JSON.parse(stdout) as Array<Record<string, unknown>>
      expect(pack).toHaveLength(1)
      const filename = String(pack[0]?.filename)
      const result = await validateReleaseTarball({
        tarballPath: join(output, filename),
        packResult: pack[0],
      })

      expect(result.package).toEqual({ name: '@1f4bcai/agent', version: '0.1.5' })
      expect(result.files).toHaveLength(17)
      expect(result.tarball.integrity).toMatch(/^sha512-/)
      expect(result.tarball.size).toBeGreaterThan(0)
      expect(result.files.every((file) => file.sha512.startsWith('sha512-'))).toBe(true)
      expect(result.files.find((file) => file.path === 'dist/index.js')?.mode).toBe(0o755)
      expect(
        result.files
          .filter((file) => file.path !== 'dist/index.js')
          .every((file) => file.mode === 0o644),
      ).toBe(true)

      const consumer = await mkdtemp(join(tmpdir(), 'agent-cli-private-import-test-'))
      try {
        await writeFile(
          join(consumer, 'package.json'),
          `${JSON.stringify({ name: 'private-import-test', private: true, type: 'module' })}\n`,
        )
        await execFileAsync('npm', [
          'install',
          '--ignore-scripts',
          '--offline',
          '--no-audit',
          '--no-fund',
          '--package-lock=false',
          join(output, filename),
        ], { cwd: consumer })
        const privateImports = [
          '@1f4bcai/agent/terminal-clear',
          '@1f4bcai/agent/dist/runtime.js',
        ]
        const probe = [
          `for (const specifier of ${JSON.stringify(privateImports)}) {`,
          '  try {',
          '    await import(specifier)',
          '    throw new Error(`${specifier} unexpectedly exposed a private module`)',
          '  } catch (error) {',
          "    if (error?.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error",
          '  }',
          '}',
        ].join('\n')
        await expect(execFileAsync('node', ['--input-type=module', '--eval', probe], {
          cwd: consumer,
        })).resolves.toBeDefined()
      } finally {
        await rm(consumer, { recursive: true, force: true })
      }

      const sbom = JSON.parse(
        await readFile(join(packageRoot, 'dist/THIRD_PARTY_COMPONENTS.cdx.json'), 'utf8'),
      ) as { components: unknown[] }
      expect(sbom.components.length).toBeGreaterThan(20)

      const commit = 'a'.repeat(40)
      await writeFile(join(output, 'npm-pack.json'), `${JSON.stringify(pack, null, 2)}\n`)
      await writeFile(
        join(output, 'release-manifest.json'),
        `${JSON.stringify({ ...result, source: { gitCommit: commit } }, null, 2)}\n`,
      )
      await expect(
        compareReviewedBuild({ releaseDirectory: output, expectedCommit: commit }),
      ).resolves.toMatchObject({
        package: { name: '@1f4bcai/agent', version: '0.1.5' },
        sourceCommit: commit,
        comparedFiles: 17,
      })
      await expect(generateReleaseSbom(output, commit)).resolves.toMatchObject({
        sbom: 'agent-cli.cdx.json',
        sha512: expect.stringMatching(/^[0-9a-f]{128}$/),
      })
    } finally {
      await rm(output, { recursive: true, force: true })
    }
  })
})
