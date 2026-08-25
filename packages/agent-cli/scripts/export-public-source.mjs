import { execFile } from 'node:child_process'
import {
  chmod,
  lstat,
  mkdir,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { developmentDependencyClosure } from './check-release-dependencies.mjs'
import { findSecretFindings } from './validate-release-tarball.mjs'

const execFileAsync = promisify(execFile)
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')
const WORKSPACE_PATH = 'packages/agent-cli'
const OMIT_DIRECTORIES = new Set(['dist', 'node_modules', '.git'])
const OMIT_FILES = new Set(['.DS_Store'])
const MAX_PUBLIC_SOURCE_FILE_BYTES = 8 * 1_024 * 1_024
const IS_UNIX = process.platform !== 'win32'

function currentUserId() {
  if (!IS_UNIX) return undefined
  if (typeof process.geteuid === 'function') return process.geteuid()
  if (typeof process.getuid === 'function') return process.getuid()
  return undefined
}

function assertSafeExportTarget(stat) {
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('public export destination must be an absent or empty regular directory')
  }
  if (!IS_UNIX) return
  const userId = currentUserId()
  if (userId !== undefined && stat.uid !== userId) {
    throw new Error('public export destination must be owned by the current user')
  }
  if ((stat.mode & 0o777) !== 0o700) {
    throw new Error('public export destination must have private 0700 permissions')
  }
}

export const PUBLIC_PACKAGE_FILES = Object.freeze([
  'LICENSE',
  'README.md',
  'licenses/Apache-2.0.txt',
  'licenses/MIT.txt',
  'licenses/x402-NOTICE-2.23.0.txt',
  'package.json',
  'scripts/bundle.mjs',
  'scripts/check-release-dependencies.d.mts',
  'scripts/check-release-dependencies.mjs',
  'scripts/clean-dist.mjs',
  'scripts/export-public-source.d.mts',
  'scripts/export-public-source.mjs',
  'scripts/generate-release-sbom.d.mts',
  'scripts/generate-release-sbom.mjs',
  'scripts/pack-release.mjs',
  'scripts/release-preflight.d.mts',
  'scripts/release-preflight.mjs',
  'scripts/validate-release-tarball.d.mts',
  'scripts/validate-release-tarball.mjs',
  'scripts/verify-independent-rebuild.d.mts',
  'scripts/verify-independent-rebuild.mjs',
  'scripts/verify-public-tree.d.mts',
  'scripts/verify-public-tree.mjs',
  'scripts/verify-release-context.mjs',
  'src/api.ts',
  'src/index.ts',
  'src/keys.ts',
  'src/local-journal.ts',
  'src/mcp-payments.ts',
  'src/mcp.ts',
  'src/peer-payments.ts',
  'src/public-runtime.ts',
  'src/secret-safety.ts',
  'src/spend-scope.ts',
  'src/terminal-clear.ts',
  'src/usdc-domain.ts',
  'test/api-security.test.ts',
  'test/bundle-runtime.test.ts',
  'test/cli.test.ts',
  'test/keys-security.test.ts',
  'test/local-journal.test.ts',
  'test/mcp-payments.test.ts',
  'test/mcp.test.ts',
  'test/package.test.ts',
  'test/peer-payments.test.ts',
  'test/public-export.test.ts',
  'test/release-pipeline.test.ts',
  'test/release-preflight.test.ts',
  'test/release-tarball.test.ts',
  'tsconfig.json',
  'vitest.config.ts',
])

export const PUBLIC_ROOT_MANIFEST = Object.freeze({
  name: '1f4bc-agent-release-source',
  version: '0.1.3',
  private: true,
  type: 'module',
  workspaces: [WORKSPACE_PATH],
})

async function writeSnapshotFile(targetRoot, destination, contents) {
  const parent = dirname(destination)
  await mkdir(parent, { recursive: true, mode: 0o755 })
  const parentStat = await lstat(parent)
  const canonicalParent = await realpath(parent)
  const withinTarget = relative(targetRoot, canonicalParent)
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    withinTarget === '..' ||
    withinTarget.startsWith(`..${sep}`)
  ) {
    throw new Error('public export destination path escaped through a symbolic link')
  }
  await writeFile(destination, contents, { mode: 0o644, flag: 'wx' })
  await chmod(destination, 0o644)
}

async function sourcePackageFiles(directory, root = directory) {
  const files = []
  for (const name of (await readdir(directory)).sort()) {
    if (OMIT_FILES.has(name) || name.endsWith('.tgz')) continue
    const path = join(directory, name)
    const stat = await lstat(path)
    const relativePath = relative(root, path).split(sep).join('/')
    if (stat.isSymbolicLink()) throw new Error(`public export refuses symbolic link ${relativePath}`)
    if (stat.isDirectory()) {
      if (OMIT_DIRECTORIES.has(name)) continue
      files.push(...await sourcePackageFiles(path, root))
    } else if (stat.isFile()) {
      files.push(relativePath)
    } else {
      throw new Error(`public export refuses non-file ${relativePath}`)
    }
  }
  return files
}

async function assertExactPackageSource(sourcePackage) {
  const actual = await sourcePackageFiles(sourcePackage)
  const expected = [...PUBLIC_PACKAGE_FILES].sort()
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const expectedSet = new Set(expected)
    const actualSet = new Set(actual)
    const unexpected = actual.filter((path) => !expectedSet.has(path))
    const missing = expected.filter((path) => !actualSet.has(path))
    throw new Error(
      `public export package allowlist mismatch; unexpected=${unexpected.join(',') || '<none>'}; missing=${missing.join(',') || '<none>'}`,
    )
  }
}

async function readCredentialFreeSource(path, label) {
  const before = await lstat(path)
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error(`public export refuses non-regular source ${label}`)
  }
  if (before.size > MAX_PUBLIC_SOURCE_FILE_BYTES) {
    throw new Error(`public export source exceeds 8 MiB: ${label}`)
  }
  const bytes = await readFile(path)
  const after = await lstat(path)
  if (
    after.isSymbolicLink() ||
    !after.isFile() ||
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    bytes.byteLength !== after.size
  ) {
    throw new Error(`public export source changed while being read: ${label}`)
  }
  if (bytes.includes(0)) throw new Error(`public export source contains binary data: ${label}`)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new Error(`public export source is not UTF-8 text: ${label}`)
  }
  const findings = findSecretFindings(text)
  if (findings.length > 0) {
    throw new Error(`public export source contains ${findings.join(', ')} in ${label}`)
  }
  return Buffer.from(bytes)
}

function assertCredentialFreeGenerated(text, label) {
  const findings = findSecretFindings(text)
  if (findings.length > 0) {
    throw new Error(`public export generated ${label} contains ${findings.join(', ')}`)
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return value.map(stableJson)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, stableJson(entry)]),
    )
  }
  return value
}

function publicLock(sourceLock, packageManifest) {
  const closure = developmentDependencyClosure(sourceLock, packageManifest)
  const packageRecords = {
    '': {
      name: PUBLIC_ROOT_MANIFEST.name,
      version: PUBLIC_ROOT_MANIFEST.version,
      workspaces: [WORKSPACE_PATH],
    },
    [WORKSPACE_PATH]: {
      name: packageManifest.name,
      version: packageManifest.version,
      license: packageManifest.license,
      bin: packageManifest.bin,
      devDependencies: packageManifest.devDependencies,
      engines: packageManifest.engines,
    },
    'node_modules/@1f4bcai/agent': {
      resolved: WORKSPACE_PATH,
      link: true,
    },
  }
  for (const { lockPath } of closure) {
    // Every executable dependency in the public source repository is reached
    // exclusively from this package's devDependencies. Normalize the flag now
    // rather than letting npm mutate a private-monorepo production flag during
    // the offline completeness check.
    packageRecords[lockPath] = { ...sourceLock.packages[lockPath], dev: true }
  }
  return {
    name: PUBLIC_ROOT_MANIFEST.name,
    version: PUBLIC_ROOT_MANIFEST.version,
    lockfileVersion: 3,
    requires: true,
    packages: Object.fromEntries(
      Object.entries(packageRecords).sort(([left], [right]) => left.localeCompare(right)),
    ),
  }
}

export async function exportPublicSource(destination, sourceRoot = repositoryRoot, hooks = {}) {
  const canonicalSourceRoot = await realpath(resolve(sourceRoot))
  const sourceRootStat = await lstat(canonicalSourceRoot)
  if (!sourceRootStat.isDirectory()) throw new Error('public export source root is not a directory')
  const requestedTarget = resolve(destination)
  let target
  let targetExists = false
  let targetIdentity
  try {
    const existing = await lstat(requestedTarget)
    assertSafeExportTarget(existing)
    if ((await readdir(requestedTarget)).length !== 0) {
      throw new Error('public export destination must be an absent or empty regular directory')
    }
    target = await realpath(requestedTarget)
    targetExists = true
    targetIdentity = { dev: existing.dev, ino: existing.ino }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
    const requestedParent = dirname(requestedTarget)
    const parent = await lstat(requestedParent)
    if (!parent.isDirectory()) throw new Error('public export destination parent is not a directory')
    target = join(await realpath(requestedParent), basename(requestedTarget))
  }
  const targetWithinSource = relative(canonicalSourceRoot, target)
  if (
    targetWithinSource === '' ||
    (targetWithinSource !== '..' && !targetWithinSource.startsWith(`..${sep}`))
  ) {
    throw new Error('public export destination must be outside the private repository')
  }

  const sourcePackage = resolve(canonicalSourceRoot, WORKSPACE_PATH)
  await assertExactPackageSource(sourcePackage)
  const workflows = ['agent-cli-public-ci.yml', 'release-agent-cli.yml']
  const packageSnapshots = new Map()
  for (const path of PUBLIC_PACKAGE_FILES) {
    packageSnapshots.set(
      path,
      await readCredentialFreeSource(
        resolve(sourcePackage, path),
        `${WORKSPACE_PATH}/${path}`,
      ),
    )
  }
  const workflowSnapshots = new Map()
  for (const workflow of workflows) {
    workflowSnapshots.set(
      workflow,
      await readCredentialFreeSource(
        resolve(canonicalSourceRoot, '.github/workflows', workflow),
        `.github/workflows/${workflow}`,
      ),
    )
  }
  const sourceLockBytes = await readCredentialFreeSource(
    resolve(canonicalSourceRoot, 'package-lock.json'),
    'package-lock.json',
  )
  const packageManifest = JSON.parse(packageSnapshots.get('package.json').toString('utf8'))
  const sourceLock = JSON.parse(sourceLockBytes.toString('utf8'))
  const rootManifestText = `${JSON.stringify(PUBLIC_ROOT_MANIFEST, null, 2)}\n`
  const lockText = `${JSON.stringify(publicLock(sourceLock, packageManifest), null, 2)}\n`
  const ignoreText = 'node_modules/\npackages/agent-cli/dist/\n*.tgz\nagent-cli-release/\n'
  assertCredentialFreeGenerated(rootManifestText, 'package.json')
  assertCredentialFreeGenerated(lockText, 'package-lock.json')
  await hooks.afterSourceSnapshot?.()

  let createdTarget = false
  if (!targetExists) {
    await mkdir(target, { recursive: false, mode: 0o700 })
    createdTarget = true
  }
  const finalTargetStat = await lstat(target)
  assertSafeExportTarget(finalTargetStat)
  if (
    targetIdentity &&
    (finalTargetStat.dev !== targetIdentity.dev || finalTargetStat.ino !== targetIdentity.ino)
  ) {
    throw new Error('public export destination changed after it was inspected')
  }
  if ((await readdir(target)).length !== 0) {
    throw new Error('public export destination changed after it was inspected')
  }
  if (await realpath(target) !== target) {
    if (createdTarget) await rm(target, { recursive: true, force: true })
    throw new Error('public export destination changed after canonicalization')
  }
  try {
    for (const path of PUBLIC_PACKAGE_FILES) {
      await writeSnapshotFile(
        target,
        resolve(target, WORKSPACE_PATH, path),
        packageSnapshots.get(path),
      )
    }
    for (const workflow of workflows) {
      await writeSnapshotFile(
        target,
        resolve(target, '.github/workflows', workflow),
        workflowSnapshots.get(workflow),
      )
    }
    await writeSnapshotFile(target, resolve(target, 'package.json'), rootManifestText)
    await writeSnapshotFile(target, resolve(target, 'package-lock.json'), lockText)
    await writeSnapshotFile(target, resolve(target, '.gitignore'), ignoreText)

    // Prove the pruned lock is internally complete without running lifecycle code.
    await execFileAsync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--offline'], {
      cwd: target,
      env: { ...process.env, npm_config_audit: 'false', npm_config_fund: 'false' },
    })
    const verifiedLockText = await readFile(resolve(target, 'package-lock.json'), 'utf8')
    assertCredentialFreeGenerated(verifiedLockText, 'offline-verified package-lock.json')
    if (
      JSON.stringify(stableJson(JSON.parse(verifiedLockText))) !==
      JSON.stringify(stableJson(JSON.parse(lockText)))
    ) {
      throw new Error('offline npm verification changed the generated public lock')
    }
    // Restore the reviewed deterministic formatting/key order after npm has
    // proved the pruned graph complete without semantically changing it.
    await writeFile(resolve(target, 'package-lock.json'), lockText, { mode: 0o644 })
    return target
  } catch (error) {
    if (createdTarget) await rm(target, { recursive: true, force: true })
    throw error
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const destination = process.argv[2]
  if (!destination) throw new Error('usage: node export-public-source.mjs <empty-destination>')
  process.stdout.write(`${await exportPublicSource(destination)}\n`)
}
