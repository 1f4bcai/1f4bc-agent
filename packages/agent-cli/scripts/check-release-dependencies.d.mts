export type LockPackage = {
  version?: string
  resolved?: string
  integrity?: string
  hasInstallScript?: boolean
  dependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  peerDependenciesMeta?: Record<string, { optional?: boolean }>
  os?: string[]
  cpu?: string[]
  optional?: boolean
}

export type PackageLock = {
  lockfileVersion?: number
  packages?: Record<string, LockPackage>
}

export type DependencyClosureRecord = {
  lockPath: string
  name: string
  entry: LockPackage
  direct: boolean
  production: boolean
  build?: boolean
  releaseBuild?: boolean
  required?: boolean
}

export const RELEASE_BUILD_PACKAGES: readonly string[]
export const BUNDLED_RUNTIME_PACKAGES: readonly string[]
export function requiresProvenance(record: {
  production?: boolean
  direct?: boolean
  releaseBuild?: boolean
}): boolean
export function assertReleaseBuildPolicy(
  lock: PackageLock,
  records: DependencyClosureRecord[],
  failures: string[],
): void
export function resolveLockedDependency(
  lockPackages: Record<string, LockPackage>,
  parentPath: string,
  name: string,
): string | undefined
export function runtimeDependencyClosure(
  lock: PackageLock,
  workspacePath?: string,
): DependencyClosureRecord[]
export function developmentDependencyClosure(
  lock: PackageLock,
  manifest: { devDependencies?: Record<string, string> },
  workspacePath?: string,
): DependencyClosureRecord[]
export function verifyInstalledDependencyRecords(
  records: DependencyClosureRecord[],
  installRoot: string,
): Promise<void>
export function checkReleaseDependencies(options: {
  lock: PackageLock
  manifest: {
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }
  minimumAgeHours: number
  fetcher?: typeof fetch
  installedRoot?: string
}): Promise<{
  minimumAgeHours: number
  runtimeClosureCount: number
  buildClosureCount: number
  checked: Array<Record<string, unknown>>
}>
