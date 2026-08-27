import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

type ExportTarget = { types: string; import: string }
type PackageManifest = {
  name: string
  version: string
  bin?: Record<string, string>
  private?: boolean
  types?: string
  files?: string[]
  scripts?: Record<string, string>
  exports?: Record<string, string | ExportTarget>
  publishConfig?: { access?: string; registry?: string; provenance?: boolean }
  repository?: { type?: string; url?: string; directory?: string }
  homepage?: string
  bugs?: { url?: string }
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  bundledDependencies?: string[]
  bundleDependencies?: string[]
  license?: string
}

describe('published package contract', () => {
  it('publishes a documented, typed public package without source or tests', async () => {
    const manifest = JSON.parse(
      await readFile(new URL('../package.json', import.meta.url), 'utf8'),
    ) as PackageManifest
    const rootManifest = JSON.parse(
      await readFile(new URL('../../../package.json', import.meta.url), 'utf8'),
    ) as { version?: string }
    const lock = JSON.parse(
      await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'),
    ) as {
      version?: string
      packages?: Record<string, { version?: string }>
    }
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const license = await readFile(new URL('../LICENSE', import.meta.url), 'utf8')

    expect(manifest.name).toBe('@1f4bcai/agent')
    expect(manifest.version).toBe('0.1.4')
    expect(rootManifest.version).toBe('0.1.4')
    expect(lock.version).toBe('0.1.4')
    expect(lock.packages?.['']?.version).toBe('0.1.4')
    expect(lock.packages?.['packages/agent-cli']?.version).toBe('0.1.4')
    expect(manifest.bin).toEqual({ '1f4bc': 'dist/index.js' })
    expect(manifest.private).not.toBe(true)
    expect(manifest.publishConfig).toEqual({
      access: 'public',
      registry: 'https://registry.npmjs.org/',
      provenance: true,
    })
    expect(manifest.repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/1f4bcai/1f4bc-agent.git',
      directory: 'packages/agent-cli',
    })
    expect(manifest.homepage).toBe(
      'https://github.com/1f4bcai/1f4bc-agent/tree/main/packages/agent-cli#readme',
    )
    expect(manifest.bugs).toEqual({ url: 'https://github.com/1f4bcai/1f4bc-agent/issues' })
    expect(manifest.license).toBe('MIT')
    expect(manifest.types).toBe('./dist/index.d.ts')
    expect(manifest.files).toEqual(expect.arrayContaining(['dist', 'README.md', 'LICENSE']))
    expect(manifest.files).not.toEqual(expect.arrayContaining(['src', 'test']))
    expect(manifest.scripts?.prepack).toBeUndefined()
    expect(manifest.dependencies).toEqual({})
    expect(readme).toContain('Keep credential-bearing RPC URLs out of process arguments')
    expect(readme).toContain('returns that block\'s `blockTimestamp` as Unix seconds')
    expect(readme).not.toContain('--rpc-url "$F4BC_RPC_URL"')
    for (const lifecycle of ['preinstall', 'install', 'postinstall', 'prepare', 'postpack']) {
      expect(manifest.scripts?.[lifecycle]).toBeUndefined()
    }
    for (const version of Object.values({
      ...manifest.dependencies,
      ...manifest.devDependencies,
    })) {
      expect(version).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
    }
    expect(manifest.optionalDependencies).toBeUndefined()
    expect(manifest.peerDependencies).toBeUndefined()
    expect(manifest.bundledDependencies).toBeUndefined()
    expect(manifest.bundleDependencies).toBeUndefined()

    for (const target of Object.values(manifest.exports ?? {})) {
      expect(target).not.toBeTypeOf('string')
      expect(target).toMatchObject({
        types: expect.stringMatching(/^\.\/dist\/.+\.d\.ts$/),
        import: expect.stringMatching(/^\.\/dist\/.+\.js$/),
      })
    }
    expect(manifest.exports).not.toHaveProperty('./keys')
    expect(manifest.exports).not.toHaveProperty('./mcp-payments')
    expect(manifest.exports).not.toHaveProperty('./terminal-clear')
    expect(manifest.exports).not.toHaveProperty('./dist/runtime.js')
    expect(manifest.exports).toHaveProperty('./spend-policy')

    expect(readme).toContain('Private keys never intentionally leave your machine')
    expect(readme).toContain('~/.1f4bc/identity.json')
    expect(readme).toContain('**Public preview:**')
    expect(readme).not.toContain('not yet published')
    expect(readme).toContain('Pre-release identities')
    expect(readme).toContain('npm pack --dry-run')
    expect(readme).toContain('npm-agent-release')
    expect(readme).toContain('trusted publishing')
    expect(readme).toContain('agent-v0.1.0')
    expect(readme).toContain('agent-v0.1.2')
    expect(readme).toContain('agent-v0.1.3')
    expect(readme).toContain('0.1.4')
    expect(readme).toContain('historical registry evidence')
    expect(readme).toContain('do not establish the replacement repository')
    expect(readme).toContain('One-time repository-history exception')
    expect(readme).toContain('no predecessor commits, tags, branches, or Git objects')
    expect(readme).toContain('remain permanently retired and must not be recreated')
    expect(readme).toContain('snapshot-only')
    expect(readme).toContain('does not approve Git history or refs')
    expect(readme).toContain('repository_dispatch')
    expect(readme).toContain('RELEASE_APP_ACTOR')
    expect(readme).toContain('RELEASE_APP_ACTOR_ID')
    expect(readme).toContain('RELEASE_APP_ID')
    expect(readme).toContain('RELEASE_APP_PRIVATE_KEY')
    expect(readme).not.toContain('workflow_dispatch')
    expect(readme).toContain('replacement bootstrap complete')
    expect(readme).toContain('That transaction is complete')
    expect(readme).toContain('privileged introduction workflow was retired')
    expect(readme).toContain('private source audit archive')
    expect(readme).toContain('must not be copied back into `.github/workflows`')
    expect(readme).toContain('Replacement version `0.1.3` was bootstrapped')
    expect(readme).not.toContain('replacement bootstrap in progress')
    expect(readme).not.toContain('Before `0.1.4`, complete')
    expect(readme).not.toContain('For replacement version `0.1.3`, bootstrap')
    expect(readme).toContain('zero required reviewers')
    expect(readme).not.toContain('one required reviewer')
    expect(readme).not.toContain('approval-gated')
    expect(readme).toContain('agent-candidate-*')
    expect(readme).toContain('promote-agent-candidate')
    expect(readme).toContain('lease-protected atomic Git push')
    expect(readme).toContain('cannot authorize their own introduction')
    expect(readme).toContain('proposal snapshot checks')
    expect(readme).toContain('GitHub-managed `refs/pull/<positive-id>/{head,merge}`')
    expect(readme).toContain('only permitted operator-created source-bearing ref')
    expect(readme).toContain('ignores only the exact GitHub-managed pull-ref shape')
    expect(readme).toContain('no-bypass update and deletion')
    expect(readme).toContain('authority pinned from canonical `main`')
    expect(license).toContain('Permission is hereby granted, free of charge')
  })
})

describe('release workflow contract', () => {
  it('stages only a reviewed tarball through a protected tokenless OIDC job', async () => {
    const workflow = await readFile(
      new URL('../../../.github/workflows/release-agent-cli.yml', import.meta.url),
      'utf8',
    )
    const ordinaryWorkflows = await Promise.all([
      readFile(
        new URL('../../../.github/workflows/agent-cli-public-ci.yml', import.meta.url),
        'utf8',
      ),
    ])
    await expect(
      readFile(
        new URL(
          '../../../.github/workflows/bootstrap-agent-cli-promotion-authority.yml',
          import.meta.url,
        ),
        'utf8',
      ),
    ).rejects.toMatchObject({ code: 'ENOENT' })

    expect(workflow).toContain('environment: npm-agent-release')
    expect(workflow).toContain('1f4bcai/1f4bc-agent')
    expect(workflow).toContain('id-token: write')
    expect(workflow).toContain('persist-credentials: false')
    expect(workflow).toContain('npm ci --ignore-scripts')
    expect(workflow).toContain('npm audit signatures --ignore-scripts')
    expect(workflow).toContain('check-release-dependencies.mjs')
    expect(workflow).toContain('release-preflight.mjs tagged-ci')
    expect(workflow).toContain('pack-release.mjs')
    expect(workflow).toContain('generate-release-sbom.mjs')
    expect(workflow).toContain('cmp --silent')
    expect(workflow).toContain('stage publish')
    expect(workflow).toContain('NODE_ARCHIVE_SHA256')
    expect(workflow).toContain('independent-rebuild-verification')
    expect(workflow).not.toContain('--snapshot-only')
    expect(workflow).not.toContain('NODE_AUTH_TOKEN')
    expect(workflow).not.toContain('NPM_TOKEN')
    expect(workflow).not.toMatch(/uses:\s+[^\s]+@v\d/)
    for (const ordinaryWorkflow of ordinaryWorkflows) {
      expect(ordinaryWorkflow).not.toMatch(/uses:\s+[^\s]+@v\d/)
    }
    for (const checkedOutWorkflow of [workflow, ...ordinaryWorkflows]) {
      const checkouts = [...checkedOutWorkflow.matchAll(/^\s+uses: actions\/checkout@[^\n]+$/gm)]
      expect(checkouts.length).toBeGreaterThan(0)
      for (const checkout of checkouts) {
        const afterCheckout = checkedOutWorkflow.slice(checkout.index + checkout[0].length)
        const nextStep = /\n {6}- name: ([^\n]+)/.exec(afterCheckout)
        expect(nextStep?.[1]).toBe("Remove checkout's inert worktree config compatibility file")
        const guardStart = nextStep?.index ?? -1
        const followingStep = afterCheckout.indexOf('\n      - name:', guardStart + 1)
        const guard = afterCheckout.slice(
          guardStart,
          followingStep === -1 ? undefined : followingStep,
        )
        expect(guard).toContain('test ! -L "${checkout_worktree_config}"')
        expect(guard).toContain('test "$(stat -c \'%h\' "${checkout_worktree_config}")" = "1"')
        expect(guard).toContain('worktree_extension_status=0')
        const extensionProbe =
          'git config --file .git/config --no-includes --get-all extensions.worktreeConfig'
        const exactStatusCheck = 'test "${worktree_extension_status}" -eq 1'
        const fileBranch = 'if [[ -e "${checkout_worktree_config}" || -L "${checkout_worktree_config}" ]]'
        expect(guard).toContain(extensionProbe)
        expect(guard).toContain('|| worktree_extension_status=$?')
        expect(guard).toContain(exactStatusCheck)
        expect(guard.indexOf(extensionProbe)).toBeLessThan(guard.indexOf(exactStatusCheck))
        expect(guard.indexOf(exactStatusCheck)).toBeLessThan(guard.indexOf(fileBranch))
        expect(guard).toContain('worktree_size="$(stat -c \'%s\' "${checkout_worktree_config}")"')
        expect(guard).toContain('test "${worktree_size}" -le 256')
        expect(guard).toContain('worktree_parse_output="$(mktemp)"')
        expect(guard).toContain('test -f "${worktree_parse_output}"')
        expect(guard).toContain('test ! -L "${worktree_parse_output}"')
        expect(guard).toContain(
          'test "$(stat -c \'%h\' "${worktree_parse_output}")" = "1"',
        )
        expect(guard).toContain('trap \'unlink "${worktree_parse_output}"\' EXIT')
        expect(guard).toContain('worktree_parse_status=0')
        expect(guard).toContain('>"${worktree_parse_output}" 2>/dev/null')
        expect(guard).toContain('|| worktree_parse_status=$?')
        expect(guard).toContain('test "${worktree_parse_status}" -eq 0')
        expect(guard).toContain(
          "mapfile -d '' -t worktree_entries <\"${worktree_parse_output}\"",
        )
        const parserCommands = guard.match(
          /git config --file "\$\{checkout_worktree_config\}" --no-includes/g,
        )
        expect(parserCommands).toHaveLength(1)
        expect(guard.indexOf('|| worktree_parse_status=$?')).toBeLessThan(
          guard.indexOf('test "${worktree_parse_status}" -eq 0'),
        )
        expect(guard.indexOf('test "${worktree_parse_status}" -eq 0')).toBeLessThan(
          guard.indexOf('mapfile -d'),
        )
        expect(guard).toContain('unlink "${worktree_parse_output}"')
        expect(guard).toContain('trap - EXIT')
        expect(guard).not.toContain('coproc ')
        expect(guard).not.toContain('< <(')
        expect(guard).toContain('test "${#worktree_entries[@]}" -eq 3')
        expect(guard).toContain("$'core.sparsecheckout\\nfalse')")
        expect(guard).toContain("$'core.sparsecheckoutcone\\nfalse')")
        expect(guard).toContain("$'index.sparse\\nfalse')")
        expect(guard).toContain('test "${seen_core_sparse_checkout}" -eq 0')
        expect(guard).toContain('test "${seen_core_sparse_checkout_cone}" -eq 0')
        expect(guard).toContain('test "${seen_index_sparse}" -eq 0')
        expect(guard).toContain('test "${seen_core_sparse_checkout}" -eq 1')
        expect(guard).toContain('test "${seen_core_sparse_checkout_cone}" -eq 1')
        expect(guard).toContain('test "${seen_index_sparse}" -eq 1')
        expect(guard).toMatch(/\n {18}\*\)\n {20}exit 1\n {20};;/)
        expect(guard).toContain('unlink "${checkout_worktree_config}"')
        expect(guard).not.toContain('|| true')
      }
    }
    expect(workflow.match(/\bnpm\s+pack\b/g) ?? []).toHaveLength(0)
    expect(workflow).not.toContain('cache: npm')
  })

  it('runs the actual checkout guard against valid and malformed worktree configs on Linux', async () => {
    if (process.platform !== 'linux') return
    const workflow = await readFile(
      new URL('../../../.github/workflows/agent-cli-public-ci.yml', import.meta.url),
      'utf8',
    )
    const guardStep = workflow.match(
      /      - name: Remove checkout's inert worktree config compatibility file\n[\s\S]*?(?=\n      - name:)/,
    )?.[0]
    expect(guardStep).toBeTruthy()
    const script = guardStep!
      .slice(guardStep!.indexOf('        run: |\n') + '        run: |\n'.length)
      .split('\n')
      .map((line) => line.startsWith('          ') ? line.slice(10) : line)
      .join('\n')
    const directory = await mkdtemp(join(tmpdir(), '1f4bc-worktree-guard-'))
    try {
      const validDirectory = join(directory, 'valid')
      const malformedDirectory = join(directory, 'malformed')
      for (const fixtureDirectory of [validDirectory, malformedDirectory]) {
        await mkdir(join(fixtureDirectory, '.git'), { recursive: true, mode: 0o700 })
        await writeFile(join(fixtureDirectory, '.git/config'), '', { mode: 0o600 })
      }
      const validConfig = [
        '[core]',
        '\tsparsecheckout = false',
        '\tsparsecheckoutcone = false',
        '[index]',
        '\tsparse = false',
      ].join('\n')
      await writeFile(
        join(validDirectory, '.git/config.worktree'),
        validConfig,
        { encoding: 'utf8', mode: 0o600 },
      )
      await writeFile(
        join(malformedDirectory, '.git/config.worktree'),
        `${validConfig}\n[malformed`,
        { encoding: 'utf8', mode: 0o600 },
      )
      const valid = spawnSync('bash', ['-c', script], {
        cwd: validDirectory,
        encoding: 'utf8',
      })
      expect(valid.status, valid.stderr).toBe(0)
      const malformed = spawnSync('bash', ['-c', script], {
        cwd: malformedDirectory,
        encoding: 'utf8',
      })
      expect(malformed.status).not.toBe(0)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
