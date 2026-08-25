export type ReleasePreflightMode = 'prepare' | 'tagged-ci'

export type ReleasePreflightGit = (
  args: string[],
  cwd: string,
) => Promise<{ status: number; stdout: string }>

export function releasePreflight(options: {
  mode: ReleasePreflightMode
  tag?: string
  commit?: string
  manifest?: unknown
  fetcher?: typeof fetch
  git?: ReleasePreflightGit
  cwd?: string
}): Promise<{
  packageName: '@1f4bcai/agent'
  version: string
  tag: string
  mode: ReleasePreflightMode
}>
