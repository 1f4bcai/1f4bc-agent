export type ReleaseFile = {
  path: string
  type: 'file'
  size: number
  mode: number
  sha512: string
}

export type ReleaseManifest = {
  schemaVersion: 1
  package: { name: string; version: string }
  tarball: {
    filename: string
    size: number
    unpackedSize: number
    entryCount: number
    integrity: string
  }
  files: ReleaseFile[]
  source?: { gitCommit: string }
}

export const EXPECTED_PACKAGE_FILES: ReadonlyMap<
  string,
  { mode: number; maxBytes: number }
>

export function findSecretFindings(text: string): string[]

export function validateSourceMap(path: string, value: unknown): void

export function validateReleaseTarball(options: {
  tarballPath: string
  packResult: unknown
}): Promise<ReleaseManifest>

export function validateReleaseDirectory(
  directory: string,
  expectedCommit?: string,
): Promise<ReleaseManifest>
