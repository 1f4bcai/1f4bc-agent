export function compareReviewedBuild(options: {
  releaseDirectory: string
  expectedCommit: string
  sourcePackageRoot?: string
}): Promise<{
  package: { name: string; version: string }
  sourceCommit: string
  comparedFiles: number
}>
