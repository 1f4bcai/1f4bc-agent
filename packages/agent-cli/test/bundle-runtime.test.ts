import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

describe('self-contained public runtime', () => {
  it('shares every security-sensitive class and singleton across public subpaths', async () => {
    // These are runtime artifact probes, not TypeScript source imports. Keeping
    // the specifiers data-driven lets a clean checkout typecheck before dist/
    // exists; the canonical test command builds the artifact first.
    const artifactModules: string[] = [
      '../dist/runtime.js',
      '../dist/index.js',
      '../dist/api.js',
      '../dist/mcp.js',
      '../dist/mcp-payments.js',
      '../dist/peer-payments.js',
    ]
    const [runtime, root, api, mcp, spend, peer] = await Promise.all(
      artifactModules.map((specifier) => import(specifier)),
    )

    expect(root.runCli).toBe(runtime.runCli)
    expect(api.AgentApi).toBe(runtime.AgentApi)
    expect(mcp.createAgentMcpServer).toBe(runtime.createAgentMcpServer)
    expect(spend.McpSpendGuard).toBe(runtime.McpSpendGuard)
    expect(peer.PeerPaymentClient).toBe(runtime.PeerPaymentClient)
  })

  it('ships no declared runtime dependency and records every vendored component', async () => {
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    const sbom = JSON.parse(
      await readFile(new URL('../dist/THIRD_PARTY_COMPONENTS.cdx.json', import.meta.url), 'utf8'),
    )
    const notices = await readFile(
      new URL('../dist/THIRD_PARTY_NOTICES.txt', import.meta.url),
      'utf8',
    )

    expect(manifest.dependencies).toEqual({})
    expect(notices).toContain('Copyright 2026 x402 Foundation')
    expect(sbom.components.length).toBeGreaterThan(20)
    expect(new Set(sbom.components.map((component: { 'bom-ref': string }) => component['bom-ref'])).size)
      .toBe(sbom.components.length)
    for (const component of sbom.components as Array<{
      group?: string
      name: string
      version: string
    }>) {
      expect(notices).toContain(
        `${component.group ? `${component.group}/` : ''}${component.name}@${component.version}`,
      )
    }
  })

  it('publishes only the safe terminal-clear orchestration in its declarations', async () => {
    const apiDeclaration = await readFile(
      new URL('../dist/api.d.ts', import.meta.url),
      'utf8',
    )
    expect(apiDeclaration).toContain('clearTerminalPostJob(')
    expect(apiDeclaration).not.toContain('stageTerminalPostJobClear')
    expect(apiDeclaration).not.toContain('finalizeTerminalPostJobClear')
    expect(apiDeclaration).not.toContain('terminal-clear')
    await expect(readFile(new URL('../dist/terminal-clear.d.ts', import.meta.url), 'utf8'))
      .rejects.toMatchObject({ code: 'ENOENT' })
  })
})
