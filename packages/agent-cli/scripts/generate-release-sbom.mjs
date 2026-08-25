import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { validateReleaseDirectory } from './validate-release-tarball.mjs'

const execFileAsync = promisify(execFile)
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')

export async function generateReleaseSbom(inputDirectory, expectedCommit = process.env.GITHUB_SHA) {
  const releaseDirectory = resolve(inputDirectory)
  const release = await validateReleaseDirectory(releaseDirectory, expectedCommit)
  const tarball = resolve(releaseDirectory, release.tarball.filename)
  if (basename(tarball) !== release.tarball.filename) throw new Error('invalid release tarball filename')

  const consumer = await mkdtemp(join(tmpdir(), 'agent-cli-release-consumer-'))
  try {
  await writeFile(
    join(consumer, 'package.json'),
    `${JSON.stringify({ name: 'agent-cli-release-consumer', version: '0.0.0', private: true }, null, 2)}\n`,
  )
  await execFileAsync(
    'npm',
    ['install', tarball, '--save-exact', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund'],
    { cwd: consumer, maxBuffer: 10 * 1024 * 1024 },
  )
  const installedPackage = join(consumer, 'node_modules', '@1f4bcai', 'agent')
  await execFileAsync(
    process.execPath,
    [join(installedPackage, 'dist', 'index.js'), '--help'],
    { cwd: consumer, maxBuffer: 1024 * 1024 },
  )
  const exportProbe = `
    const expected = ${JSON.stringify({
      '@1f4bcai/agent': ['main', 'runCli'],
      '@1f4bcai/agent/api': [
        'AgentApi', 'BID_FEE_ATOMIC', 'CURRENT_ACCEPTABLE_USE_SHA256',
        'CURRENT_ACCEPTABLE_USE_URL', 'CURRENT_ACCEPTABLE_USE_VERSION',
        'CURRENT_PRIVACY_SHA256', 'CURRENT_PRIVACY_URL',
        'CURRENT_PRIVACY_VERSION', 'CURRENT_TERMS_SHA256', 'CURRENT_TERMS_URL',
        'CURRENT_TERMS_VERSION', 'MARKETPLACE_PAY_TO_BY_CHAIN_ID',
        'MAX_PAYMENT_ATTEMPT_ENTRIES', 'MarketplaceHttpError', 'POST_FEE_ATOMIC',
        'STAGING_CRASH_HEADER', 'TERMS_ACCEPTANCE_SIGNATURE_VERSION',
        'TERMS_ACCEPTANCE_STATEMENT', 'attestationMessage', 'createSigningFetch',
        'paymentMayHaveOccurred', 'registrationMessage', 'requestEnvelopeMessage',
        'sha256Hex', 'signEnvelope', 'termsAcceptanceMessage', 'walletOwnershipMessage',
      ],
      '@1f4bcai/agent/mcp': [
        'createAgentMcpServer', 'mcpSpendJournalPath', 'paymentScope', 'runAgentMcp',
        'spendJournalPath',
      ],
      '@1f4bcai/agent/spend-policy': [
        'MAX_MCP_SPEND_JOURNAL_BYTES', 'MAX_MCP_SPEND_JOURNAL_ENTRIES',
        'MAX_MCP_SPEND_RESULT_BYTES', 'McpSpendGuard', 'SpendGuard',
        'assertAuthorizedPaymentControl', 'claimAuthorizedPaymentControl',
      ],
      '@1f4bcai/agent/peer-payments': [
        'PeerPaymentClient', 'USDC_BY_CHAIN_ID', 'inspectUsdcReceipt',
        'peerPaymentSpendInput', 'readUsdcBalance',
      ],
    })};
    for (const [specifier, names] of Object.entries(expected)) {
      const actual = Object.keys(await import(specifier)).sort();
      if (JSON.stringify(actual) !== JSON.stringify([...names].sort())) {
        throw new Error('public export surface differs for ' + specifier + ': ' + actual.join(','));
      }
    }
  `
  await execFileAsync(process.execPath, ['--input-type=module', '--eval', exportProbe], {
    cwd: consumer,
    maxBuffer: 2 * 1024 * 1024,
  })
  await writeFile(join(consumer, 'consumer.mts'), `
    import { runCli } from '@1f4bcai/agent'
    import { AgentApi, type PaymentRequestOptions } from '@1f4bcai/agent/api'
    import { createAgentMcpServer, type AgentMcpServer } from '@1f4bcai/agent/mcp'
    import { SpendGuard, type SpendControl } from '@1f4bcai/agent/spend-policy'
    import { PeerPaymentClient, type PeerPaymentRequest } from '@1f4bcai/agent/peer-payments'
    void [runCli, AgentApi, createAgentMcpServer, SpendGuard, PeerPaymentClient]
    type PublicTypes = PaymentRequestOptions | AgentMcpServer | SpendControl | PeerPaymentRequest
    const value: PublicTypes | undefined = undefined
    void value
  `)
  await writeFile(join(consumer, 'tsconfig.json'), `${JSON.stringify({
    compilerOptions: {
      target: 'ES2022',
      module: 'NodeNext',
      moduleResolution: 'NodeNext',
      strict: true,
      noEmit: true,
      skipLibCheck: false,
    },
    include: ['consumer.mts'],
  }, null, 2)}\n`)
  await execFileAsync(
    process.execPath,
    [resolve(repositoryRoot, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'],
    { cwd: consumer, maxBuffer: 4 * 1024 * 1024 },
  )
  const { stdout: treeOutput } = await execFileAsync('npm', ['ls', '--all', '--json'], {
    cwd: consumer,
    maxBuffer: 4 * 1024 * 1024,
  })
  const tree = JSON.parse(treeOutput)
  const installed = tree.dependencies?.['@1f4bcai/agent']
  if (!installed || Object.keys(installed.dependencies ?? {}).length !== 0) {
    throw new Error('installed package unexpectedly resolves third-party runtime dependencies')
  }
  await execFileAsync('npm', ['audit', '--omit=dev', '--audit-level=low'], {
    cwd: consumer,
    maxBuffer: 10 * 1024 * 1024,
  })
  const sbom = JSON.parse(await readFile(
    join(installedPackage, 'dist', 'THIRD_PARTY_COMPONENTS.cdx.json'),
    'utf8',
  ))
  if (
    sbom.metadata?.component?.version !== release.package.version ||
    !Array.isArray(sbom.components) ||
    sbom.components.length < 20
  ) {
    throw new Error('embedded vendored-component SBOM is incomplete')
  }
  const serialized = `${JSON.stringify(sbom, null, 2)}\n`
  const sbomName = 'agent-cli.cdx.json'
  await writeFile(join(releaseDirectory, sbomName), serialized)
  const digest = createHash('sha512').update(serialized).digest('hex')
  await writeFile(join(releaseDirectory, `${sbomName}.sha512`), `${digest}  ${sbomName}\n`)
    return { sbom: sbomName, sha512: digest }
  } finally {
    await rm(consumer, { recursive: true, force: true })
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined
if (invokedPath === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) throw new Error('release directory argument is required')
  const result = await generateReleaseSbom(process.argv[2])
  process.stdout.write(`${JSON.stringify(result)}\n`)
}
