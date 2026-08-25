export function allowedPublicPath(path: string): boolean
export type PublicTreeVerificationMode = 'full' | 'snapshot-only'
export interface PublicTreeVerificationOptions {
  mode?: PublicTreeVerificationMode
}
export function verifyPublicTree(root?: string, options?: PublicTreeVerificationOptions): Promise<{
  trackedFiles: number
  lockedPackages: number
}>
