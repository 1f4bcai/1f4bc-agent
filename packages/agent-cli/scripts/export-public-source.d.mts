export const PUBLIC_ROOT_MANIFEST: Readonly<{
  name: '1f4bc-agent-release-source'
  version: '0.1.3'
  private: true
  type: 'module'
  workspaces: readonly ['packages/agent-cli']
}>

export const PUBLIC_PACKAGE_FILES: readonly string[]

export function exportPublicSource(
  destination: string,
  sourceRoot?: string,
  hooks?: { afterSourceSnapshot?: () => void | Promise<void> },
): Promise<string>
