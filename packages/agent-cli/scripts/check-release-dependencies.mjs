import { lstat, readFile } from 'node:fs/promises'
import { dirname, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')
const WORKSPACE_PATH = 'packages/agent-cli'
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const NPM_REGISTRY_ORIGIN = 'https://registry.npmjs.org'

// This is the complete allowlist of third-party packages whose code may be
// executed while producing the release. The release runner is pinned to
// ubuntu/x64, so esbuild must use this exact platform package.
export const RELEASE_BUILD_PACKAGES = Object.freeze([
  'esbuild',
  '@esbuild/linux-x64',
])

// These direct inputs are compiled into the self-contained public artifact.
// They are devDependencies only so npm/npx consumers never resolve a mutable
// runtime tree, but their complete transitive closure remains release-gated.
export const BUNDLED_RUNTIME_PACKAGES = Object.freeze([
  '@modelcontextprotocol/server',
  '@noble/ed25519',
  '@x402/core',
  '@x402/evm',
  '@x402/extensions',
  '@x402/fetch',
  'viem',
  'zod',
])

function packageNameFromLockPath(lockPath) {
  const marker = 'node_modules/'
  const index = lockPath.lastIndexOf(marker)
  if (index < 0) throw new Error(`not a dependency lock path: ${lockPath}`)
  return lockPath.slice(index + marker.length)
}

/** Resolve a dependency using the same nearest-node_modules search order Node uses. */
export function resolveLockedDependency(lockPackages, parentPath, name) {
  let directory = parentPath
  while (true) {
    const candidate = `${directory ? `${directory}/` : ''}node_modules/${name}`
    if (lockPackages[candidate]) return candidate
    if (!directory) return undefined
    const slash = directory.lastIndexOf('/')
    directory = slash < 0 ? '' : directory.slice(0, slash)
  }
}

/**
 * Return every installed package compiled into the public runtime bundle.
 * Optional dependencies are included when present;
 * optional peers are deliberately excluded. Each physical lock path remains
 * distinct so a nested copy cannot hide behind a verified top-level version.
 */
export function runtimeDependencyClosure(lock, workspacePath = WORKSPACE_PATH) {
  const lockPackages = lock?.packages
  const workspace = lockPackages?.[workspacePath]
  if (!lockPackages || !workspace) {
    throw new Error(`package-lock.json has no ${workspacePath} workspace entry`)
  }

  const pending = BUNDLED_RUNTIME_PACKAGES.map((name) => ({
    parentPath: workspacePath,
    name,
    optional: false,
  }))
  const closure = new Map()

  while (pending.length > 0) {
    const dependency = pending.shift()
    const lockPath = resolveLockedDependency(
      lockPackages,
      dependency.parentPath,
      dependency.name,
    )
    if (!lockPath) {
      if (dependency.optional) continue
      throw new Error(
        `locked runtime dependency ${dependency.name} required by ${dependency.parentPath} is missing`,
      )
    }
    const required = dependency.optional !== true
    const existing = closure.get(lockPath)
    if (existing?.required === true || (existing && !required)) continue

    const entry = lockPackages[lockPath]
    if (existing) existing.required = true
    else {
      closure.set(lockPath, {
        lockPath,
        name: packageNameFromLockPath(lockPath),
        entry,
        direct: dependency.parentPath === workspacePath,
        production: true,
        required,
      })
    }

    for (const name of Object.keys(entry.dependencies ?? {})) {
      pending.push({ parentPath: lockPath, name, optional: !required })
    }
    for (const name of Object.keys(entry.optionalDependencies ?? {})) {
      pending.push({ parentPath: lockPath, name, optional: true })
    }
    for (const name of Object.keys(entry.peerDependencies ?? {})) {
      if (entry.peerDependenciesMeta?.[name]?.optional === true) continue
      pending.push({ parentPath: lockPath, name, optional: !required })
    }
  }

  return [...closure.values()].sort((left, right) =>
    left.lockPath.localeCompare(right.lockPath),
  )
}

export function developmentDependencyClosure(
  lock,
  manifest,
  workspacePath = WORKSPACE_PATH,
) {
  const lockPackages = lock?.packages
  if (!lockPackages?.[workspacePath]) {
    throw new Error(`package-lock.json has no ${workspacePath} workspace entry`)
  }
  const pending = Object.keys(manifest.devDependencies ?? {}).map((name) => ({
    parentPath: workspacePath,
    name,
    optional: false,
  }))
  const closure = new Map()
  while (pending.length > 0) {
    const dependency = pending.shift()
    const lockPath = resolveLockedDependency(lockPackages, dependency.parentPath, dependency.name)
    if (!lockPath) {
      if (dependency.optional) continue
      throw new Error(
        `locked build dependency ${dependency.name} required by ${dependency.parentPath} is missing`,
      )
    }
    const required = dependency.optional !== true
    const existing = closure.get(lockPath)
    if (existing?.required === true || (existing && !required)) continue
    const entry = lockPackages[lockPath]
    if (existing) existing.required = true
    else {
      closure.set(lockPath, {
        lockPath,
        name: packageNameFromLockPath(lockPath),
        entry,
        direct: dependency.parentPath === workspacePath,
        production: false,
        build: true,
        required,
      })
    }
    for (const name of Object.keys(entry.dependencies ?? {})) {
      pending.push({ parentPath: lockPath, name, optional: !required })
    }
    for (const name of Object.keys(entry.optionalDependencies ?? {})) {
      pending.push({ parentPath: lockPath, name, optional: true })
    }
    for (const name of Object.keys(entry.peerDependencies ?? {})) {
      if (entry.peerDependenciesMeta?.[name]?.optional === true) continue
      pending.push({ parentPath: lockPath, name, optional: !required })
    }
  }
  return [...closure.values()].sort((left, right) => left.lockPath.localeCompare(right.lockPath))
}

function releaseBuildDependencies(lock) {
  return RELEASE_BUILD_PACKAGES.map((name) => {
    const lockPath = `node_modules/${name}`
    const entry = lock.packages?.[lockPath]
    if (!entry) throw new Error(`allowlisted release build dependency ${name} is missing`)
    return {
      lockPath,
      name,
      entry,
      direct: false,
      production: false,
      releaseBuild: true,
      required: true,
    }
  })
}

export function assertReleaseBuildPolicy(lock, records, failures) {
  const byName = new Map(records.map((record) => [record.name, record.entry]))
  const esbuild = byName.get('esbuild')
  const platform = byName.get('@esbuild/linux-x64')

  if (esbuild?.hasInstallScript !== true) {
    failures.push('esbuild must remain the one explicitly allowlisted lifecycle package')
  }
  if (platform?.hasInstallScript === true) {
    failures.push('@esbuild/linux-x64 must not define an install script')
  }
  if (esbuild?.optionalDependencies?.['@esbuild/linux-x64'] !== platform?.version) {
    failures.push('esbuild and @esbuild/linux-x64 versions are not exactly linked')
  }
  if (
    JSON.stringify(platform?.os) !== JSON.stringify(['linux']) ||
    JSON.stringify(platform?.cpu) !== JSON.stringify(['x64'])
  ) {
    failures.push('@esbuild/linux-x64 platform constraints must be exactly linux/x64')
  }
  for (const [lockPath] of Object.entries(lock.packages ?? {})) {
    const name = lockPath.includes('node_modules/')
      ? packageNameFromLockPath(lockPath)
      : undefined
    if (
      RELEASE_BUILD_PACKAGES.includes(name) &&
      lockPath !== `node_modules/${name}`
    ) {
      failures.push(`duplicate executable build dependency is forbidden: ${lockPath}`)
    }
  }
}

function assertLockRecord(record, failures) {
  const { entry, lockPath, name } = record
  if (!EXACT_VERSION.test(entry?.version ?? '')) {
    failures.push(`${lockPath} has no exact semantic version`)
  }
  if (typeof entry?.integrity !== 'string' || !entry.integrity.startsWith('sha512-')) {
    failures.push(`${lockPath} has no SHA-512 lock integrity`)
  }
  let resolved
  try {
    resolved = new URL(entry?.resolved)
  } catch {
    failures.push(`${lockPath} has no valid resolved registry URL`)
    return
  }
  if (
    resolved.origin !== NPM_REGISTRY_ORIGIN ||
    resolved.username !== '' ||
    resolved.password !== '' ||
    resolved.protocol !== 'https:'
  ) {
    failures.push(`${lockPath} is not resolved from the credential-free npm registry`)
  }
  if (record.production && entry?.hasInstallScript === true) {
    failures.push(`${name}@${entry.version} has a forbidden runtime install script`)
  }
}

function encodedPackage(name) {
  return encodeURIComponent(name)
}

export function requiresProvenance(record) {
  return (record.production === true && record.direct === true) || record.releaseBuild === true
}

async function fetchRegistryRecord(name, version, minimumAgeHours, fetcher) {
  const response = await fetcher(
    `${NPM_REGISTRY_ORIGIN}/${encodedPackage(name)}/${encodeURIComponent(version)}`,
    { signal: AbortSignal.timeout(15_000) },
  )
  if (!response.ok) throw new Error(`registry metadata request failed for ${name}@${version}`)
  const metadata = await response.json()
  if (metadata.name !== name || metadata.version !== version) {
    throw new Error(`registry metadata identity differs for ${name}@${version}`)
  }

  const packumentResponse = await fetcher(`${NPM_REGISTRY_ORIGIN}/${encodedPackage(name)}`, {
    signal: AbortSignal.timeout(15_000),
  })
  if (!packumentResponse.ok) throw new Error(`registry history request failed for ${name}`)
  const packument = await packumentResponse.json()
  if (packument.name !== name) throw new Error(`registry history identity differs for ${name}`)
  const publishedAt = packument.time?.[version]
  const publishedMillis = typeof publishedAt === 'string' ? Date.parse(publishedAt) : Number.NaN
  const ageHours = (Date.now() - publishedMillis) / 3_600_000
  if (!Number.isFinite(ageHours) || ageHours < minimumAgeHours) {
    throw new Error(
      `${name}@${version} is only ${Number.isFinite(ageHours) ? ageHours.toFixed(1) : 'unknown'} hours old`,
    )
  }

  return { metadata, ageHours: Number(ageHours.toFixed(1)) }
}

function validateRegistryRecord(record, registry, failures) {
  const { entry, name, production, direct, lockPath } = record
  const version = entry.version
  const { metadata, ageHours } = registry
  // These comparisons are intentionally per physical lock path. Two copies of
  // the same name/version may not borrow a verified sibling's URL or integrity.
  if (metadata.dist?.integrity !== entry.integrity) {
    failures.push(`${lockPath} registry integrity differs from package-lock.json`)
  }
  if (metadata.dist?.tarball !== entry.resolved) {
    failures.push(`${lockPath} registry tarball URL differs from package-lock.json`)
  }
  if (!Array.isArray(metadata.dist?.signatures) || metadata.dist.signatures.length === 0) {
    failures.push(`${name}@${version} has no npm registry signature`)
  }
  if (
    requiresProvenance(record) &&
    metadata.dist?.attestations?.provenance?.predicateType !== 'https://slsa.dev/provenance/v1'
  ) {
    failures.push(`${name}@${version} has no SLSA provenance attestation`)
  }
  return {
    lockPath,
    name,
    version,
    production,
    direct,
    releaseBuild: record.releaseBuild === true,
    ageHours,
  }
}

export async function verifyInstalledDependencyRecords(records, installRoot) {
  const root = resolve(installRoot)
  const failures = []
  await Promise.all(records.map(async (record) => {
    const packageDirectory = resolve(root, ...record.lockPath.split('/'))
    const withinRoot = relative(root, packageDirectory)
    if (withinRoot === '..' || withinRoot.startsWith(`..${sep}`)) {
      failures.push(`${record.lockPath} escapes the installed dependency root`)
      return
    }
    let directoryStat
    try {
      directoryStat = await lstat(packageDirectory)
    } catch (error) {
      if (error?.code === 'ENOENT' && record.required !== true && record.releaseBuild !== true) return
      failures.push(`${record.lockPath} is missing from the installed dependency tree`)
      return
    }
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      failures.push(`${record.lockPath} is not an installed regular package directory`)
      return
    }
    const manifestPath = resolve(packageDirectory, 'package.json')
    try {
      const manifestStat = await lstat(manifestPath)
      if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 1024 * 1024) {
        failures.push(`${record.lockPath} has an unsafe installed package.json`)
        return
      }
      const bytes = await readFile(manifestPath)
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      const manifest = JSON.parse(text)
      if (manifest.name !== record.name || manifest.version !== record.entry.version) {
        failures.push(`${record.lockPath} installed package identity differs from package-lock.json`)
      }
    } catch (error) {
      failures.push(`${record.lockPath} has an unreadable installed package.json`)
    }
  }))
  if (failures.length > 0) {
    throw new Error(`installed dependency gate failed:\n- ${[...new Set(failures)].sort().join('\n- ')}`)
  }
}

export async function checkReleaseDependencies({
  lock,
  manifest,
  minimumAgeHours,
  fetcher = fetch,
  installedRoot,
}) {
  if (!Number.isSafeInteger(minimumAgeHours) || minimumAgeHours < 24) {
    throw new Error('MIN_DEPENDENCY_AGE_HOURS must be an integer of at least 24')
  }
  const workspace = lock.packages?.[WORKSPACE_PATH]
  if (!workspace) throw new Error('package-lock.json has no agent CLI workspace entry')

  const failures = []
  if (lock.lockfileVersion !== 3) {
    failures.push('package-lock.json must remain lockfileVersion 3')
  }
  const manifestDependencies = {
    ...(manifest.dependencies ?? {}),
    ...(manifest.devDependencies ?? {}),
  }
  const workspaceDependencies = {
    ...(workspace.dependencies ?? {}),
    ...(workspace.devDependencies ?? {}),
  }
  for (const [name, version] of Object.entries(manifestDependencies)) {
    if (!EXACT_VERSION.test(version)) failures.push(`${name} is not pinned to an exact version`)
    if (workspaceDependencies[name] !== version) {
      failures.push(`${name}@${version} differs from the workspace lock declaration`)
    }
  }
  for (const [name, version] of Object.entries(workspaceDependencies)) {
    if (manifestDependencies[name] !== version) {
      failures.push(`${name}@${version} exists only in the workspace lock declaration`)
    }
  }

  const runtime = runtimeDependencyClosure(lock)
  const development = developmentDependencyClosure(lock, manifest)
  const releaseBuild = releaseBuildDependencies(lock)
  assertReleaseBuildPolicy(lock, releaseBuild, failures)

  const recordsByPath = new Map()
  for (const record of [...runtime, ...development, ...releaseBuild]) {
    const existing = recordsByPath.get(record.lockPath)
    if (existing) {
      existing.direct ||= record.direct
      existing.production ||= record.production
      existing.releaseBuild ||= record.releaseBuild === true
      existing.required ||= record.required === true
    } else {
      recordsByPath.set(record.lockPath, { ...record })
    }
  }
  const records = [...recordsByPath.values()].sort((left, right) =>
    left.lockPath.localeCompare(right.lockPath),
  )
  for (const record of records) assertLockRecord(record, failures)

  // Network responses are cached by immutable package identity only. Security
  // comparisons still run separately for every physical lock record below.
  const registryChecks = new Map()
  const checked = await Promise.all(
    records.map(async (record) => {
      const key = `${record.name}@${record.entry.version}`
      let pending = registryChecks.get(key)
      if (!pending) {
        pending = fetchRegistryRecord(record.name, record.entry.version, minimumAgeHours, fetcher)
        registryChecks.set(key, pending)
      }
      return validateRegistryRecord(record, await pending, failures)
    }),
  )

  if (installedRoot !== undefined) {
    await verifyInstalledDependencyRecords(records, installedRoot)
  }

  if (failures.length > 0) {
    throw new Error(`release dependency gate failed:\n- ${[...new Set(failures)].sort().join('\n- ')}`)
  }
  return {
    minimumAgeHours,
    runtimeClosureCount: runtime.length,
    buildClosureCount: development.length,
    checked,
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined
if (invokedPath === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'))
  const lock = JSON.parse(await readFile(resolve(repositoryRoot, 'package-lock.json'), 'utf8'))
  const result = await checkReleaseDependencies({
    lock,
    manifest,
    minimumAgeHours: Number(process.env.MIN_DEPENDENCY_AGE_HOURS ?? '72'),
    installedRoot: repositoryRoot,
  })
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}
