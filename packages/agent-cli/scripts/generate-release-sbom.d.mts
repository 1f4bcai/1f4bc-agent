export function generateReleaseSbom(
  inputDirectory: string,
  expectedCommit?: string,
): Promise<{ sbom: string; sha512: string }>
