export function allowedPublicPath(path: string): boolean
export type PublicTreeVerificationMode = 'full' | 'snapshot-only'
export interface PublicTreeVerificationOptions {
  mode?: PublicTreeVerificationMode
}
export function assertPublicCiAuthorityRepairPlacement(input: {
  commit: string
  parent: string
  version: string
  authorTimestamp: string
}): void
export function assertReleasePromotionAuthorityRepairMetadata(input: {
  commit: string
  parent: string
  version: string
  authorTimestamp: string
}): void
export function assertReleasePromotionAuthorityRepairContent(
  repository: string,
  commit: string,
): Promise<void>
export function verifyPublicTree(root?: string, options?: PublicTreeVerificationOptions): Promise<{
  trackedFiles: number
  lockedPackages: number
}>
