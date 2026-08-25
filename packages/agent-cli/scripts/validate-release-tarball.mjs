import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { lstat, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const SOURCE_PACKAGE_MANIFEST = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
)

const DECLARATION_MODULES = [
  'api',
  'index',
  'keys',
  'mcp-payments',
  'mcp',
  'peer-payments',
]
const JAVASCRIPT_MODULES = ['api', 'index', 'mcp-payments', 'mcp', 'peer-payments', 'runtime']

const MAX_TARBALL_BYTES = 4 * 1024 * 1024
const MAX_UNPACKED_BYTES = 10 * 1024 * 1024

const exactFiles = [
  ['LICENSE', { mode: 0o644, maxBytes: 8 * 1024 }],
  ['README.md', { mode: 0o644, maxBytes: 32 * 1024 }],
  ['dist/THIRD_PARTY_COMPONENTS.cdx.json', { mode: 0o644, maxBytes: 256 * 1024 }],
  ['dist/THIRD_PARTY_NOTICES.txt', { mode: 0o644, maxBytes: 256 * 1024 }],
  ...DECLARATION_MODULES.map((name) =>
    [`dist/${name}.d.ts`, { mode: 0o644, maxBytes: 32 * 1024 }],
  ),
  ...JAVASCRIPT_MODULES.map((name) =>
    [`dist/${name}.js`, {
      mode: name === 'index' ? 0o755 : 0o644,
      maxBytes: name === 'index' || name === 'runtime' ? 4 * 1024 * 1024 : 8 * 1024,
    }],
  ),
  ['package.json', { mode: 0o644, maxBytes: 16 * 1024 }],
]

export const EXPECTED_PACKAGE_FILES = new Map(
  exactFiles.sort(([left], [right]) => left.localeCompare(right)),
)

const SECRET_PATTERNS = [
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ['npm access token', /\bnpm_[A-Za-z0-9]{30,}\b/],
  ['OpenAI-style API key', /\bsk-[A-Za-z0-9_-]{32,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/],
  ['private key PEM', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['credential-bearing URL', /https?:\/\/[^\s/@:]+:[^\s/@]+@/],
  [
    'quoted literal assigned credential',
    /(?:["'](?:api[_-]?key|secret|password|token|private[_-]?key)["']|\b(?:api[_-]?key|secret|password|token|private[_-]?key)\b)\s*[:=]\s*["'][^"'\s]{16,}["']/i,
  ],
  [
    'unquoted environment credential',
    /\b(?:[A-Z][A-Z0-9_]{0,60}_)?(?:API_?KEY|ACCESS_?KEY|SECRET(?:_?KEY)?|PASSWORD|TOKEN|PRIVATE_?KEY)\s*=\s*[A-Za-z0-9_./+=-]{16,}(?=\s|$)/,
  ],
  [
    'literal wallet private key',
    /\b(?:walletPrivateKey|privateKey)\b\s*[:=]\s*["']0x[0-9a-fA-F]{64}["']/,
  ],
]

const PUBLIC_32_BYTE_HEX_ALLOWLIST = new Set([
  // SHA-256 digests of current and historical immutable policy artifacts.
  '0xcc6b85e1e686d6b19ef30e87488511d66aeedbc99d9e76ea36b36f7ee8823ed9',
  '0xe5b4de1e70d82743363a6c158a8f317c76b953fbee2d1d952795f3cb5313736e',
  '0x6b5f50ad76df7f773635731ec33c4f77598e03a02ddc6d0b8ac06d627abff0cd',
  '0x561f162c21e445f41dd8e93908ecd2174432909a8d572bcf755a870da245dca1',
  '0xcd1f2ef3b25439a53d311a2158698dc71a89f104b0a81a94e13f714d46622ec3',
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  '0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5',
  // SHA-256 of the exact official Node archive used by the OIDC-only stage job.
  '0x14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647',
  // SHA-256 of the exact official Node 20 floor archive used by the consumer job.
  '0x2dd1f5c0e01732024ba1f5de4517fa3976eb0976fa7976ff687ec09b62dd73fa',
])

const RELEASE_SCRIPTS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepack',
  'postpack',
])

function fail(message) {
  throw new Error(`release tarball validation failed: ${message}`)
}

function sha512(buffer) {
  return `sha512-${createHash('sha512').update(buffer).digest('base64')}`
}

function assertExactSet(actual, expected, label) {
  const actualSorted = [...actual].sort()
  const expectedSorted = [...expected].sort()
  if (new Set(actualSorted).size !== actualSorted.length) {
    fail(`${label} contains a duplicate path`)
  }
  if (JSON.stringify(actualSorted) !== JSON.stringify(expectedSorted)) {
    const missing = expectedSorted.filter((item) => !actualSorted.includes(item))
    const extra = actualSorted.filter((item) => !expectedSorted.includes(item))
    fail(`${label} differs from the allowlist (missing: ${missing.join(', ') || 'none'}; extra: ${extra.join(', ') || 'none'})`)
  }
}

function assertSafeRelativePath(value, label) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\\') ||
    value.includes('\0') ||
    isAbsolute(value) ||
    value.split('/').includes('..')
  ) {
    fail(`${label} must be a normalized relative path`)
  }
}

export function findSecretFindings(text, options = {}) {
  const findings = SECRET_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name)
  if (options.opaqueKeyShapes !== false) {
    const isInsideCompleteSri = (offset, length) => {
      // A match may begin at the SRI algorithm label (the URL-safe detector)
      // or at the digest immediately after it (the standard Base64 detector).
      // Only exempt a complete, correctly-sized scalar that contains this exact
      // match; a prefix such as `sha512-aaaa` must still be rejected.
      for (const start of [offset, offset - 'sha512-'.length]) {
        if (start < 0) continue
        const before = text[start - 1]
        if (before && /[A-Za-z0-9_-]/.test(before)) continue
        const sri = text.slice(start).match(
          /^(?:sha256-[A-Za-z0-9+/]{43}=|sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])/,
        )?.[0]
        if (sri && offset >= start && offset + length <= start + sri.length) return true
      }
      return false
    }
    for (const match of text.matchAll(/(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/g)) {
      const value = match[0].toLowerCase()
      const normalized = value.startsWith('0x') ? value : `0x${value}`
      if (!PUBLIC_32_BYTE_HEX_ALLOWLIST.has(normalized)) {
        findings.push('secret-shaped 32-byte hex value')
        break
      }
    }
    const standardBase64 = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])/g
    for (const match of text.matchAll(standardBase64)) {
      if (!isInsideCompleteSri(match.index ?? 0, match[0].length)) {
        findings.push('secret-shaped 32-byte Base64 value')
        break
      }
    }
    // Standard Base64 padding is optional. A 32-byte value is 43 characters
    // without `=`; unlike Base64URL, `+` or `/` may be the only characters that
    // distinguish it from an ordinary identifier.
    const unpaddedStandardBase64 = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}(?![A-Za-z0-9+/=])/g
    for (const match of text.matchAll(unpaddedStandardBase64)) {
      const token = match[0]
      if ((/[+/]/.test(token) || text.trim() === token) && !isInsideCompleteSri(match.index ?? 0, token.length)) {
        findings.push('secret-shaped 32-byte Base64 value')
        break
      }
    }
    const base64Url = /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g
    for (const match of text.matchAll(base64Url)) {
      const token = match[0]
      const offset = match.index ?? 0
      const quote = text[offset - 1]
      const quotedScalar = (quote === '"' || quote === "'") && text[offset + token.length] === quote
      // Subresource Integrity labels can form a 43-character URL-safe-looking
      // prefix when the following standard Base64 digest is interrupted by
      // '+' or '/'. Exempt it only when the bytes at this exact offset form a
      // complete correctly-sized SRI scalar, never from the prefix alone.
      if (isInsideCompleteSri(offset, token.length)) continue
      const before = text.slice(Math.max(0, offset - 100), offset)
      const credentialContext = /(?:private[_-]?key|secret|token|seed|wallet[_-]?key)[^\n]{0,40}$/i
        .test(before)
      // Unpadded Base64URL shares its alphabet with ordinary 43-character
      // all-alphanumeric identifiers. '-' or '_' proves the URL-safe alphabet;
      // all-alphanumeric values still require a credential label or exact input.
      if (/[-_]/.test(token) || quotedScalar || text.trim() === token || credentialContext) {
        findings.push('secret-shaped 32-byte Base64 value')
        break
      }
    }
  }
  return [...new Set(findings)]
}

export function validateSourceMap(path, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${path} must contain a JSON object`)
  }
  if (Object.prototype.hasOwnProperty.call(value, 'sourcesContent')) {
    fail(`${path} must not contain sourcesContent`)
  }
  if (!Array.isArray(value.sources) || value.sources.length !== 1) {
    fail(`${path} must reference exactly one source`)
  }
  const source = value.sources[0]
  if (
    typeof source !== 'string' ||
    !/^\.\.\/src\/[a-z0-9-]+\.ts$/.test(source) ||
    isAbsolute(source) ||
    source.includes('\\')
  ) {
    fail(`${path} sources must contain one expected relative TypeScript path`)
  }
  if (value.sourceRoot !== undefined && value.sourceRoot !== '') {
    fail(`${path} sourceRoot must be empty`)
  }
}

function validatePublishedManifest(manifest) {
  if (manifest.name !== '@1f4bcai/agent' || !/^\d+\.\d+\.\d+$/.test(manifest.version)) {
    fail('package name or version is invalid')
  }
  if (JSON.stringify(manifest) !== JSON.stringify(SOURCE_PACKAGE_MANIFEST)) {
    fail('published package.json differs from the tagged source manifest')
  }
  if (JSON.stringify(manifest.files) !== JSON.stringify(['dist', 'README.md', 'LICENSE'])) {
    fail('package files allowlist changed')
  }
  for (const field of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'bundledDependencies',
    'bundleDependencies',
  ]) {
    const value = manifest[field]
    const count = Array.isArray(value) ? value.length : Object.keys(value ?? {}).length
    if (count !== 0) fail(`published package must not declare ${field}`)
  }
  if (JSON.stringify(manifest.bin) !== JSON.stringify({ '1f4bc': 'dist/index.js' })) {
    fail('CLI bin mapping changed')
  }
  if (
    manifest.repository?.type !== 'git' ||
    manifest.repository?.url !== 'git+https://github.com/1f4bcai/1f4bc-agent.git' ||
    manifest.repository?.directory !== 'packages/agent-cli'
  ) {
    fail('repository metadata must identify the public package source')
  }
  if (
    manifest.publishConfig?.access !== 'public' ||
    manifest.publishConfig?.registry !== 'https://registry.npmjs.org/' ||
    manifest.publishConfig?.provenance !== true
  ) {
    fail('publishConfig must require public npm provenance')
  }
  for (const script of RELEASE_SCRIPTS) {
    if (manifest.scripts?.[script] !== undefined) {
      fail(`published package must not define lifecycle script ${script}`)
    }
  }
  for (const [name, version] of Object.entries(manifest.dependencies ?? {})) {
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
      fail(`runtime dependency ${name} must use an exact version`)
    }
  }
  return { name: manifest.name, version: manifest.version }
}

async function listTarball(tarballPath) {
  const { stdout } = await execFileAsync('tar', ['-tzf', tarballPath], {
    maxBuffer: 1024 * 1024,
  })
  return stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

async function extractTarball(tarballPath, destination) {
  await execFileAsync('tar', ['-xzf', tarballPath, '-C', destination], {
    maxBuffer: 1024 * 1024,
  })
}

function normalizePackResult(packResult) {
  if (!packResult || typeof packResult !== 'object' || Array.isArray(packResult)) {
    fail('npm pack result must be one JSON object')
  }
  if (!Array.isArray(packResult.files)) fail('npm pack result has no file list')
  return packResult
}

export async function validateReleaseTarball({ tarballPath, packResult }) {
  const absoluteTarball = resolve(tarballPath)
  const tarballName = basename(absoluteTarball)
  const pack = normalizePackResult(packResult)
  if (pack.filename !== tarballName) fail('tarball filename differs from npm pack metadata')

  const tarballBuffer = await readFile(absoluteTarball)
  if (tarballBuffer.byteLength === 0 || tarballBuffer.byteLength > MAX_TARBALL_BYTES) {
    fail(`tarball size ${tarballBuffer.byteLength} exceeds the release limit`)
  }
  const tarballIntegrity = sha512(tarballBuffer)
  if (pack.integrity !== tarballIntegrity) fail('tarball SHA-512 differs from npm pack metadata')
  if (pack.size !== tarballBuffer.byteLength) fail('tarball byte size differs from npm pack metadata')

  const expectedPaths = [...EXPECTED_PACKAGE_FILES.keys()]
  const packPaths = pack.files.map((entry) => entry?.path)
  assertExactSet(packPaths, expectedPaths, 'npm pack file list')
  if (pack.entryCount !== expectedPaths.length) fail('npm pack entry count is invalid')

  const tarPaths = await listTarball(absoluteTarball)
  for (const tarPath of tarPaths) {
    if (!tarPath.startsWith('package/')) fail(`archive path is outside package/: ${tarPath}`)
    assertSafeRelativePath(tarPath.slice('package/'.length), 'archive member')
  }
  assertExactSet(
    tarPaths.map((path) => path.slice('package/'.length)),
    expectedPaths,
    'archive member list',
  )

  const extractionRoot = await mkdtemp(join(tmpdir(), 'agent-cli-release-validate-'))
  try {
    await extractTarball(absoluteTarball, extractionRoot)
    const packageDirectory = join(extractionRoot, 'package')
    const files = []
    let unpackedSize = 0

    for (const path of expectedPaths) {
      const policy = EXPECTED_PACKAGE_FILES.get(path)
      const absolutePath = resolve(packageDirectory, ...path.split('/'))
      const relativePath = relative(packageDirectory, absolutePath)
      if (relativePath.startsWith(`..${sep}`) || relativePath === '..') {
        fail(`resolved path escaped the package directory: ${path}`)
      }
      const fileStat = await lstat(absolutePath)
      if (!fileStat.isFile() || fileStat.nlink !== 1) fail(`${path} is not one regular file`)
      if (fileStat.size <= 0 || fileStat.size > policy.maxBytes) {
        fail(`${path} size ${fileStat.size} violates its release limit`)
      }
      const metadata = pack.files.find((entry) => entry.path === path)
      if (metadata.size !== fileStat.size) fail(`${path} size differs from npm pack metadata`)
      const actualMode = fileStat.mode & 0o777
      if (actualMode !== policy.mode) {
        fail(`${path} archive mode ${actualMode} differs from required mode ${policy.mode}`)
      }
      if (metadata.mode !== policy.mode) {
        fail(`${path} mode ${metadata.mode} differs from required mode ${policy.mode}`)
      }

      const content = await readFile(absolutePath)
      if (content.includes(0)) fail(`${path} contains binary NUL data`)
      const text = content.toString('utf8')
      if (!Buffer.from(text, 'utf8').equals(content)) fail(`${path} is not valid UTF-8`)
      // Opaque crypto constants are abundant in the reviewed vendored JS.
      // They are scanned in the exact public TypeScript inputs before build;
      // compiled JS still receives all contextual/provider/PEM checks here.
      const secretFindings = findSecretFindings(text, {
        opaqueKeyShapes:
          !path.endsWith('.js') &&
          !path.startsWith('dist/THIRD_PARTY_'),
      })
      if (secretFindings.length > 0) {
        fail(`${path} contains ${secretFindings.join(', ')}`)
      }
      if (path.endsWith('.map')) {
        let map
        try {
          map = JSON.parse(text)
        } catch {
          fail(`${path} is not valid JSON`)
        }
        validateSourceMap(path, map)
      }

      unpackedSize += fileStat.size
      files.push({
        path,
        type: 'file',
        size: fileStat.size,
        mode: actualMode,
        sha512: sha512(content),
      })
    }

    if (unpackedSize !== pack.unpackedSize || unpackedSize > MAX_UNPACKED_BYTES) {
      fail('unpacked size differs from npm pack metadata or exceeds the release limit')
    }
    const manifest = JSON.parse(await readFile(join(packageDirectory, 'package.json'), 'utf8'))
    const packageIdentity = validatePublishedManifest(manifest)
    if (pack.name !== packageIdentity.name || pack.version !== packageIdentity.version) {
      fail('npm pack identity differs from package.json')
    }
    const sbom = JSON.parse(
      await readFile(join(packageDirectory, 'dist/THIRD_PARTY_COMPONENTS.cdx.json'), 'utf8'),
    )
    if (
      sbom.bomFormat !== 'CycloneDX' ||
      sbom.specVersion !== '1.6' ||
      !Array.isArray(sbom.components) ||
      sbom.components.length < 20
    ) {
      fail('embedded bundled-component SBOM is incomplete')
    }
    const componentIds = new Set()
    for (const component of sbom.components) {
      const id = `${component.group ? `${component.group}/` : ''}${component.name}@${component.version}`
      if (
        typeof component['bom-ref'] !== 'string' ||
        componentIds.has(component['bom-ref']) ||
        !Array.isArray(component.hashes) ||
        !component.hashes.some((hash) => hash.alg === 'SHA-512' && /^[0-9a-f]{128}$/.test(hash.content))
      ) {
        fail(`embedded SBOM component is invalid: ${id}`)
      }
      componentIds.add(component['bom-ref'])
    }
    const names = new Set(sbom.components.map((component) =>
      `${component.group ? `${component.group}/` : ''}${component.name}`,
    ))
    for (const required of [
      '@modelcontextprotocol/server',
      '@noble/ed25519',
      '@x402/core',
      '@x402/evm',
      '@x402/fetch',
      'viem',
      'zod',
    ]) {
      if (!names.has(required)) fail(`embedded SBOM omits bundled component ${required}`)
    }
    const notices = await readFile(
      join(packageDirectory, 'dist/THIRD_PARTY_NOTICES.txt'),
      'utf8',
    )
    for (const component of sbom.components) {
      const id = `${component.group ? `${component.group}/` : ''}${component.name}@${component.version}`
      if (!notices.includes(id)) fail(`third-party notices omit bundled component ${id}`)
    }

    return {
      schemaVersion: 1,
      package: packageIdentity,
      tarball: {
        filename: tarballName,
        size: tarballBuffer.byteLength,
        unpackedSize,
        entryCount: files.length,
        integrity: tarballIntegrity,
      },
      files,
    }
  } finally {
    await rm(extractionRoot, { recursive: true, force: true })
  }
}

function parseArguments(argv) {
  const values = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]
    const value = argv[index + 1]
    if (!key?.startsWith('--') || value === undefined) fail(`invalid argument ${key ?? ''}`)
    values.set(key.slice(2), value)
  }
  return values
}

export async function validateReleaseDirectory(directory, expectedCommit) {
  const releaseDirectory = resolve(directory)
  const manifestPath = join(releaseDirectory, 'release-manifest.json')
  const packPath = join(releaseDirectory, 'npm-pack.json')
  const expected = JSON.parse(await readFile(manifestPath, 'utf8'))
  const packArray = JSON.parse(await readFile(packPath, 'utf8'))
  if (!Array.isArray(packArray) || packArray.length !== 1) fail('npm-pack.json is invalid')
  const actual = await validateReleaseTarball({
    tarballPath: join(releaseDirectory, expected.tarball?.filename ?? ''),
    packResult: packArray[0],
  })
  const expectedCore = { ...expected }
  delete expectedCore.source
  if (JSON.stringify(actual) !== JSON.stringify(expectedCore)) {
    fail('release-manifest.json differs from the validated tarball')
  }
  if (expectedCommit !== undefined && expected.source?.gitCommit !== expectedCommit) {
    fail('release manifest commit differs from the release commit')
  }
  return expected
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined
if (invokedPath === fileURLToPath(import.meta.url)) {
  const args = parseArguments(process.argv.slice(2))
  const directory = args.get('release-directory')
  if (!directory) fail('--release-directory is required')
  const result = await validateReleaseDirectory(directory, args.get('git-commit'))
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}
