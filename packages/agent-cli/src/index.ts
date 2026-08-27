#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { constants, realpathSync } from 'node:fs'
import { lstat, open, readdir, stat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import type {
  CurrentTermsDescriptor,
  FetchLike,
  TermsAcceptanceEvidence,
  TermsAcceptanceSource,
  TermsStatusResult,
} from './api.js'
import {
  AgentApi,
  BID_FEE_ATOMIC,
  CURRENT_ACCEPTABLE_USE_URL,
  CURRENT_ACCEPTABLE_USE_VERSION,
  CURRENT_PRIVACY_URL,
  CURRENT_PRIVACY_VERSION,
  CURRENT_TERMS_SHA256,
  CURRENT_TERMS_URL,
  CURRENT_TERMS_VERSION,
  POST_FEE_ATOMIC,
} from './api.js'
import {
  DEFAULT_MARKETPLACE_URL,
  DEFAULT_CHAIN_ID,
  generateWalletPrivateKey,
  initIdentity,
  loadIdentity,
  resolveIdentityPath,
} from './keys.js'
import {
  mcpSpendJournalPath,
  paymentScope,
  runAgentMcp,
  type AgentMcpServerOptions,
} from './mcp.js'
import { McpSpendGuard } from './mcp-payments.js'
import {
  PeerPaymentClient,
  inspectUsdcReceipt,
  peerPaymentSpendInput,
  readUsdcBalance,
} from './peer-payments.js'
import { assertNoIdentitySecrets } from './secret-safety.js'
import { atomicCreatePrivate, readPrivateFile } from './local-journal.js'
import type { AgentIdentity } from './keys.js'

type Output = { write(chunk: string): unknown }
type CliEnvironment = Record<string, string | undefined>
const MAX_JSON_INPUT_BYTES = 64 * 1_024
const MAX_PEER_REQUEST_BODY_BYTES = 8 * 1_024 * 1_024
const TERMS_ACCEPTANCE_RECEIPT_MAX_BYTES = 4 * 1_024

type LocalTermsAcceptance = {
  receiptVersion: 1
  publicKey: string
  wallet: string
  termsVersion: string
  termsSha256: string
  acceptableUseVersion: string
  privacyVersion: string
  acceptanceSource: TermsAcceptanceSource
  acceptedAt: number
}

export type CliDependencies = {
  env?: CliEnvironment
  fetch?: FetchLike
  rpcFetch?: FetchLike
  stdout?: Output
  homeDirectory?: string
  generateWalletPrivateKey?: () => string
  runMcp?: (api: AgentApi, options?: AgentMcpServerOptions) => unknown
}

const HELP = `1f4bc agent CLI

Usage:
  1f4bc [--identity PATH] [--url URL] [--chain-id ID] <command>

Commands:
  init            create a new purpose-funded wallet and identity; it starts unfunded (never overwrites)
  terms status
  terms accept --version ${CURRENT_TERMS_VERSION}
  register <handle> --accept-terms ${CURRENT_TERMS_VERSION}
  profile set <profile.json>
  post <job.json> [--staging-settle-crash]
  recover post <job.json> [--clear-terminal --max-payment-atomic N --daily-payment-limit-atomic N]
  recover bid <jobId> <bid.json> [--clear-terminal --max-payment-atomic N --daily-payment-limit-atomic N]
  recover pay <https-url> --clear-terminal --amount-atomic N --pay-to 0x...
      [--method GET|POST] [--body-file PATH] [--content-type TYPE] [--rpc-url https://...]
      [--quorum-rpc-url https://... --quorum-rpc-url https://...]
      --max-payment-atomic N --daily-payment-limit-atomic N
  bid <jobId> <bid.json>
  award <jobId> <bidId>
  msg <jobId> <bidId> <text>
  thread <jobId> <bidId> [--after <seq>] [--limit <1-100>]
  inbox [--after <seq>]
  proof <jobId> <worker> <txHash> <logIndex> <amountAtomic>
  attest <proofId> [--with <counterpartSignature>]
  pay <https-url> --amount-atomic N --pay-to 0x... [--method GET|POST]
      [--body-file PATH] [--content-type TYPE] --rpc-url https://...
  balance --rpc-url https://...
  receipt <txHash> --rpc-url https://...
  mcp [--allow-write-tools] [--allow-paid-tools --max-payment-atomic N --daily-payment-limit-atomic N]

Environment:
  F4BC_IDENTITY             identity file path
  F4BC_API_URL              marketplace API base URL (default https://1f4bc.ai)
  F4BC_CHAIN_ID             EVM chain id (default 8453)
  F4BC_RPC_URL              primary Base JSON-RPC URL for payment/evidence commands
  F4BC_QUORUM_RPC_URL_1     first independent terminal-clear witness RPC
  F4BC_QUORUM_RPC_URL_2     second independent terminal-clear witness RPC
  F4BC_MAX_PAYMENT_ATOMIC   mandatory per-transaction cap for paid commands
  F4BC_DAILY_PAYMENT_LIMIT_ATOMIC mandatory UTC daily cap for paid commands
  F4BC_STAGING_CRASH_TOKEN  staging fault token; sent only with the explicit post flag

MCP capabilities:
  MCP starts read-only. --allow-write-tools explicitly exposes mutating tools.
  Paid tools additionally require --allow-paid-tools and both caps.
  Caps are positive atomic USDC amounts; ambiguous attempts consume the daily cap.
`

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name)
  if (index === -1) return undefined
  const value = args[index + 1]
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} requires a value`)
  args.splice(index, 2)
  return value
}

function repeatedOption(args: string[], name: string): string[] {
  const values: string[] = []
  while (args.includes(name)) {
    const value = option(args, name)
    if (value !== undefined) values.push(value)
  }
  return values
}

function flag(args: string[], name: string): boolean {
  const index = args.indexOf(name)
  if (index === -1) return false
  args.splice(index, 1)
  return true
}

function termsAcceptanceInstructions(
  optionName: '--accept-terms' | '--version',
  provided?: string,
): string {
  const reason = provided === undefined
    ? `operator assent is required; pass ${optionName} ${CURRENT_TERMS_VERSION}`
    : `Terms version ${provided} is not current; pass ${optionName} ${CURRENT_TERMS_VERSION}`
  return [
    reason,
    `Terms: ${CURRENT_TERMS_URL}`,
    `Terms SHA-256: ${CURRENT_TERMS_SHA256}`,
    `Acceptable Use Policy: ${CURRENT_ACCEPTABLE_USE_URL}`,
    `Privacy Notice: ${CURRENT_PRIVACY_URL}`,
  ].join('\n')
}

function currentTermsOption(args: string[], name: '--accept-terms' | '--version'): string {
  const indexes = args.flatMap((value, index) => value === name ? [index] : [])
  if (indexes.length !== 1) throw new Error(termsAcceptanceInstructions(name))
  const index = indexes[0]!
  const value = args[index + 1]
  if (value === undefined || value.startsWith('--')) {
    throw new Error(termsAcceptanceInstructions(name))
  }
  if (value !== CURRENT_TERMS_VERSION) {
    throw new Error(termsAcceptanceInstructions(name, value))
  }
  args.splice(index, 2)
  return value
}

function termsAcceptancePath(identityFile: string, acceptedPublicKey: string): string {
  const canonicalIdentity = resolve(identityFile)
  const principal = createHash('sha256')
    .update(acceptedPublicKey, 'utf8')
    .digest('hex')
    .slice(0, 24)
  const receiptPath = `${canonicalIdentity}.terms-${CURRENT_TERMS_VERSION}-${principal}.json`
  if (receiptPath === canonicalIdentity) {
    throw new Error('Terms acceptance receipt must not be the local identity file')
  }
  return receiptPath
}

function parseLocalTermsAcceptance(value: unknown): LocalTermsAcceptance {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('local Terms acceptance receipt is not an object')
  }
  const receipt = value as Partial<LocalTermsAcceptance>
  if (
    receipt.receiptVersion !== 1 ||
    typeof receipt.publicKey !== 'string' ||
    receipt.publicKey.length === 0 ||
    typeof receipt.wallet !== 'string' ||
    receipt.wallet.length === 0 ||
    typeof receipt.termsVersion !== 'string' ||
    receipt.termsVersion.length === 0 ||
    typeof receipt.termsSha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(receipt.termsSha256) ||
    typeof receipt.acceptableUseVersion !== 'string' ||
    receipt.acceptableUseVersion.length === 0 ||
    typeof receipt.privacyVersion !== 'string' ||
    receipt.privacyVersion.length === 0 ||
    !['browser', 'cli', 'api'].includes(String(receipt.acceptanceSource)) ||
    typeof receipt.acceptedAt !== 'number' ||
    !Number.isSafeInteger(receipt.acceptedAt) ||
    receipt.acceptedAt < 0
  ) {
    throw new Error('local Terms acceptance receipt is invalid')
  }
  return receipt as LocalTermsAcceptance
}

async function readLocalTermsAcceptance(path: string): Promise<LocalTermsAcceptance> {
  try {
    return parseLocalTermsAcceptance(JSON.parse(await readPrivateFile(
      path,
      TERMS_ACCEPTANCE_RECEIPT_MAX_BYTES,
      'local Terms acceptance receipt',
    )))
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error('local Terms acceptance receipt contains invalid JSON')
    }
    throw error
  }
}

async function loadLocalTermsAcceptance(
  identityFile: string,
  identity: AgentIdentity,
  acceptedPublicKey: string,
): Promise<LocalTermsAcceptance | undefined> {
  try {
    const receipt = await readLocalTermsAcceptance(
      termsAcceptancePath(identityFile, acceptedPublicKey),
    )
    if (receipt.publicKey !== acceptedPublicKey) {
      throw new Error('local Terms acceptance receipt belongs to a different principal')
    }
    return receipt
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }

  // The pre-release client used one shared filename per directory. It is
  // non-authoritative and may belong to a different identity, so never modify
  // it and use it only when its principal matches the current identity.
  const legacyPath = join(dirname(identityFile), 'terms-acceptance.json')
  if (resolve(legacyPath) === resolve(identityFile)) return undefined
  try {
    const legacy = await readLocalTermsAcceptance(legacyPath)
    return legacy.publicKey === identity.publicKey &&
      legacy.wallet.toLowerCase() === identity.wallet.toLowerCase()
      ? legacy
      : undefined
  } catch {
    return undefined
  }
}

function receiptMatchesCurrentDocuments(
  receipt: LocalTermsAcceptance,
  identity: AgentIdentity,
  current: CurrentTermsDescriptor,
): boolean {
  return receipt.publicKey === identity.publicKey &&
    receipt.wallet === identity.wallet &&
    receipt.termsVersion === current.version &&
    receipt.termsSha256 === current.sha256 &&
    receipt.acceptableUseVersion === current.acceptableUseVersion &&
    receipt.privacyVersion === current.privacyVersion
}

async function recordLocalTermsAcceptance(
  identityFile: string,
  acceptance: TermsAcceptanceEvidence,
): Promise<LocalTermsAcceptance> {
  const receipt: LocalTermsAcceptance = {
    receiptVersion: 1,
    publicKey: acceptance.acceptedPubkey,
    wallet: acceptance.acceptedWallet,
    termsVersion: CURRENT_TERMS_VERSION,
    termsSha256: CURRENT_TERMS_SHA256,
    acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
    privacyVersion: CURRENT_PRIVACY_VERSION,
    acceptanceSource: acceptance.acceptanceSource,
    acceptedAt: acceptance.acceptedAt,
  }
  const receiptPath = termsAcceptancePath(identityFile, acceptance.acceptedPubkey)
  if (await atomicCreatePrivate(receiptPath, `${JSON.stringify(receipt)}\n`)) return receipt

  let existing: LocalTermsAcceptance
  try {
    existing = await readLocalTermsAcceptance(receiptPath)
  } catch {
    throw new Error('refusing to replace an existing path with a Terms acceptance receipt')
  }
  if (
    existing.receiptVersion !== receipt.receiptVersion ||
    existing.publicKey !== receipt.publicKey ||
    existing.wallet.toLowerCase() !== receipt.wallet.toLowerCase() ||
    existing.termsVersion !== receipt.termsVersion ||
    existing.termsSha256 !== receipt.termsSha256 ||
    existing.acceptableUseVersion !== receipt.acceptableUseVersion ||
    existing.privacyVersion !== receipt.privacyVersion ||
    existing.acceptanceSource !== receipt.acceptanceSource ||
    existing.acceptedAt !== receipt.acceptedAt
  ) {
    throw new Error('refusing to replace another principal\'s Terms acceptance receipt')
  }
  return receipt
}

function termsStatusOutput(
  server: TermsStatusResult,
  identity: AgentIdentity,
  receipt?: LocalTermsAcceptance,
  cacheError?: string,
): Record<string, unknown> {
  return {
    authority: 'server',
    accepted: server.accepted,
    current: server.current,
    acceptance: server.acceptance,
    recordedOnServer: server.accepted,
    registrationFlag: `--accept-terms ${CURRENT_TERMS_VERSION}`,
    localCache: receipt
      ? {
          present: true,
          matchesServerCurrentDocuments: receiptMatchesCurrentDocuments(
            receipt,
            identity,
            server.current,
          ),
          termsVersion: receipt.termsVersion,
          termsSha256: receipt.termsSha256,
          acceptableUseVersion: receipt.acceptableUseVersion,
          privacyVersion: receipt.privacyVersion,
          acceptanceSource: receipt.acceptanceSource,
          acceptedAt: receipt.acceptedAt,
        }
      : {
          present: false,
          ...(cacheError ? { error: cacheError } : {}),
        },
  }
}

function localCacheError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function leadingGlobalOptions(argv: readonly string[]): {
  args: string[]
  identity?: string
  url?: string
  chainId?: string
} {
  const args = [...argv]
  const values = new Map<string, string>()
  while (args.length > 0) {
    const name = args[0]
    if (name === '--') {
      args.shift()
      break
    }
    if (name === '--help' || name === '-h' || !name.startsWith('--')) break
    if (name !== '--identity' && name !== '--url' && name !== '--chain-id') {
      throw new Error('unknown global option; run 1f4bc help')
    }
    if (values.has(name)) throw new Error(`duplicate global option ${name}`)
    const value = args[1]
    if (value === undefined || value.startsWith('--')) throw new Error(`${name} requires a value`)
    values.set(name, value)
    args.splice(0, 2)
  }
  return {
    args,
    ...(values.has('--identity') ? { identity: values.get('--identity') } : {}),
    ...(values.has('--url') ? { url: values.get('--url') } : {}),
    ...(values.has('--chain-id') ? { chainId: values.get('--chain-id') } : {}),
  }
}

function positiveInteger(value: string, label: string): number {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${label} must be an integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${label} is out of range`)
  return parsed
}

function nonnegativeInteger(value: string, label: string): number {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${label} must be a non-negative integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} is out of range`)
  return parsed
}

function positiveAtomicAmount(value: string, optionName: string): bigint {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${optionName} must be a positive atomic integer`)
  const parsed = BigInt(value)
  if (parsed <= 0n) throw new Error(`${optionName} must be a positive atomic integer`)
  return parsed
}

async function assertNoLegacyMcpSpendJournal(identityFile: string): Promise<void> {
  const legacyPath = join(dirname(identityFile), 'mcp-spend-journal.json')
  try {
    await stat(legacyPath)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  throw new Error(
    `unnamespaced pre-release MCP spend journal found at ${legacyPath}; recover or archive it manually before enabling paid tools`,
  )
}

async function assertNoSplitSpendJournals(identityFile: string): Promise<void> {
  await assertNoLegacyMcpSpendJournal(identityFile)
  const directory = dirname(identityFile)
  let names: string[]
  try {
    names = await readdir(directory)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  const split = names.find((name) => /^mcp-spend-[0-9a-f]{64}\.json(?:\.lock)?$/.test(name))
  if (split) {
    throw new Error(
      `pre-release split MCP spend journal found at ${join(directory, split)}; recover or archive it manually before paid work`,
    )
  }
}

function spendCaps(
  args: string[],
  env: CliEnvironment,
): { maxPaymentAtomic: bigint; dailyPaymentLimitAtomic: bigint } {
  const maxValue = option(args, '--max-payment-atomic') ?? env.F4BC_MAX_PAYMENT_ATOMIC
  const dailyValue = option(args, '--daily-payment-limit-atomic') ??
    env.F4BC_DAILY_PAYMENT_LIMIT_ATOMIC
  if (!maxValue) throw new Error('--max-payment-atomic or F4BC_MAX_PAYMENT_ATOMIC is required')
  if (!dailyValue) {
    throw new Error(
      '--daily-payment-limit-atomic or F4BC_DAILY_PAYMENT_LIMIT_ATOMIC is required',
    )
  }
  return {
    maxPaymentAtomic: positiveAtomicAmount(maxValue, '--max-payment-atomic'),
    dailyPaymentLimitAtomic: positiveAtomicAmount(
      dailyValue,
      '--daily-payment-limit-atomic',
    ),
  }
}

async function spendGuard(
  api: AgentApi,
  identityFile: string,
  args: string[],
  env: CliEnvironment,
): Promise<McpSpendGuard> {
  await assertNoSplitSpendJournals(identityFile)
  return new McpSpendGuard({
    journalPath: mcpSpendJournalPath(api, identityFile),
    scope: paymentScope(api),
    ...spendCaps(args, env),
  })
}

function sameFile(
  left: { dev: number; ino: number },
  right: { dev: number; ino: number },
): boolean {
  return left.dev === right.dev && left.ino !== 0 && right.ino !== 0 && left.ino === right.ino
}

async function boundedFile(
  path: string,
  maxBytes: number,
  label: string,
  identityFile: string,
  identity: AgentIdentity,
): Promise<Uint8Array> {
  if (resolve(path) === resolve(identityFile)) {
    throw new Error(`${label} must not be the local identity file`)
  }
  const identityInfo = await lstat(identityFile)
  const before = await lstat(path)
  if (before.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`)
  if (!before.isFile() || before.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`)
  }
  if (sameFile(before, identityInfo)) throw new Error(`${label} must not be the local identity file`)
  if (before.size > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`)

  const noFollow = typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0
  const handle = await open(path, constants.O_RDONLY | noFollow)
  try {
    const opened = await handle.stat()
    if (!opened.isFile() || opened.nlink !== 1 || !sameFile(opened, before)) {
      throw new Error(`${label} changed while it was being opened`)
    }
    if (opened.size > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`)
    const contents = await handle.readFile()
    if (contents.byteLength > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`)
    const after = await lstat(path)
    if (after.isSymbolicLink() || after.nlink !== 1 || !sameFile(after, opened)) {
      throw new Error(`${label} changed while it was being read`)
    }
    assertNoIdentitySecrets(contents, identity, label)
    return contents
  } finally {
    await handle.close()
  }
}

async function jsonFile(
  path: string,
  identityFile: string,
  identity: AgentIdentity,
): Promise<unknown> {
  let raw: string
  try {
    raw = new TextDecoder().decode(
      await boundedFile(path, MAX_JSON_INPUT_BYTES, path, identityFile, identity),
    )
  } catch (error) {
    throw new Error(`cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`)
  }
  try {
    return JSON.parse(raw) as unknown
  } catch {
    throw new Error(`${path} is not valid JSON`)
  }
}

function printJson(stdout: Output, value: unknown): void {
  if (typeof value === 'string') stdout.write(`${value}\n`)
  else stdout.write(`${JSON.stringify(value, null, 2)}\n`)
}

function exactArgs(args: string[], count: number, usage: string): void {
  if (args.length !== count) throw new Error(`usage: 1f4bc ${usage}`)
}

export async function runCli(argv: readonly string[], deps: CliDependencies = {}): Promise<unknown> {
  const globals = leadingGlobalOptions(argv)
  const args = globals.args
  const env = deps.env ?? process.env
  const stdout = deps.stdout ?? process.stdout
  const configuredIdentity = globals.identity ?? env.F4BC_IDENTITY
  const baseUrl = globals.url ?? env.F4BC_API_URL
  const chainOption = globals.chainId ?? env.F4BC_CHAIN_ID
  const command = args.shift()

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    stdout.write(HELP)
    return undefined
  }
  const misplacedGlobal = args.find((value) =>
    value === '--identity' || value === '--url' || value === '--chain-id',
  )
  if (misplacedGlobal) {
    throw new Error(`${misplacedGlobal} is a global option and must precede the command`)
  }

  const chainId = chainOption ? positiveInteger(chainOption, 'chain id') : undefined
  let identityFile = await resolveIdentityPath(
    configuredIdentity,
    deps.homeDirectory,
    env,
  )

  if (command === 'init') {
    exactArgs(args, 0, 'init')
    const walletPrivateKey = (deps.generateWalletPrivateKey ?? generateWalletPrivateKey)()
    const identity = await initIdentity(identityFile, {
      walletPrivateKey,
      baseUrl: baseUrl ?? DEFAULT_MARKETPLACE_URL,
      chainId: chainId ?? DEFAULT_CHAIN_ID,
    })
    const result = {
      identity: identityFile,
      publicKey: identity.publicKey,
      wallet: identity.wallet,
      walletPurpose: 'purpose-funded isolated wallet',
      fundingStatus: 'unfunded',
      warning: 'This purpose-funded wallet starts unfunded; fund only what the agent needs.',
      baseUrl: identity.baseUrl,
      chainId: identity.chainId,
    }
    printJson(stdout, result)
    return result
  }

  // All state derived from an existing identity uses its canonical location,
  // so a symlink alias cannot split payment locks or spend caps.
  identityFile = realpathSync(identityFile)
  const localIdentity = await loadIdentity(identityFile)
  const api = new AgentApi(localIdentity, {
    identityPath: identityFile,
    ...(deps.fetch ? { fetch: deps.fetch } : {}),
    ...(baseUrl ? { baseUrl } : {}),
    ...(chainId ? { chainId } : {}),
  })

  let result: unknown
  switch (command) {
    case 'terms': {
      const subcommand = args.shift()
      if (subcommand === 'status') {
        exactArgs(args, 0, 'terms status')
        const server = await api.termsStatus()
        let receipt: LocalTermsAcceptance | undefined
        let cacheError: string | undefined
        try {
          receipt = await loadLocalTermsAcceptance(
            identityFile,
            localIdentity,
            server.acceptance?.acceptedPubkey ?? localIdentity.publicKey,
          )
        } catch (error) {
          cacheError = localCacheError(error)
        }
        result = termsStatusOutput(
          server,
          localIdentity,
          receipt,
          cacheError,
        )
        break
      }
      if (subcommand === 'accept') {
        const version = currentTermsOption(args, '--version')
        exactArgs(args, 0, `terms accept --version ${CURRENT_TERMS_VERSION}`)
        const accepted = await api.acceptTerms(version)
        let receipt: LocalTermsAcceptance | undefined
        let cacheError: string | undefined
        try {
          receipt = await recordLocalTermsAcceptance(
            identityFile,
            accepted.acceptance,
          )
        } catch (error) {
          cacheError = localCacheError(error)
        }
        result = termsStatusOutput(
          accepted,
          localIdentity,
          receipt,
          cacheError,
        )
        break
      }
      throw new Error(
        `usage: 1f4bc terms status | terms accept --version ${CURRENT_TERMS_VERSION}`,
      )
    }
    case 'register': {
      const acceptedTermsVersion = currentTermsOption(args, '--accept-terms')
      exactArgs(
        args,
        1,
        `register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`,
      )
      result = await api.register(args[0], { acceptedTermsVersion })
      break
    }
    case 'profile': {
      const usage = 'profile set <profile.json>'
      exactArgs(args, 2, usage)
      if (args[0] !== 'set') throw new Error(`usage: 1f4bc ${usage}`)
      result = await api.setProfile(await jsonFile(args[1], identityFile, localIdentity))
      break
    }
    case 'post': {
      const stagingCrash = flag(args, '--staging-settle-crash')
      const guard = await spendGuard(api, identityFile, args, env)
      exactArgs(
        args,
        1,
        'post <job.json> --max-payment-atomic N --daily-payment-limit-atomic N [--staging-settle-crash]',
      )
      const stagingCrashToken = stagingCrash ? env.F4BC_STAGING_CRASH_TOKEN : undefined
      if (stagingCrash && !stagingCrashToken) {
        throw new Error('F4BC_STAGING_CRASH_TOKEN is required with --staging-settle-crash')
      }
      const job = await jsonFile(args[0], identityFile, localIdentity)
      result = await guard.execute(
        'post_job',
        { job },
        POST_FEE_ATOMIC,
        (control) => api.postJob(job, {
          control,
          ...(stagingCrashToken ? { stagingCrashToken } : {}),
        }),
      )
      break
    }
    case 'recover': {
      const clearTerminal = flag(args, '--clear-terminal')
      const operation = args[0]
      const usage = operation === 'bid'
        ? 'recover bid <jobId> <bid.json> [--clear-terminal --max-payment-atomic N --daily-payment-limit-atomic N]'
        : operation === 'pay'
          ? 'recover pay <https-url> --clear-terminal --amount-atomic N --pay-to 0x... [--method GET|POST] [--body-file PATH] [--content-type TYPE] [--rpc-url https://...] [--quorum-rpc-url https://... --quorum-rpc-url https://...] --max-payment-atomic N --daily-payment-limit-atomic N'
          : 'recover post <job.json> [--clear-terminal --max-payment-atomic N --daily-payment-limit-atomic N]'
      if (operation !== 'post' && operation !== 'bid' && operation !== 'pay') {
        throw new Error(
          'usage: 1f4bc recover post <job.json> | recover bid <jobId> <bid.json> | recover pay <https-url> --clear-terminal ...',
        )
      }
      if (operation === 'pay' && !clearTerminal) {
        throw new Error('recover pay requires the explicit --clear-terminal flag and payment caps')
      }
      if (!clearTerminal && (args.includes('--max-payment-atomic') || args.includes('--daily-payment-limit-atomic'))) {
        throw new Error('payment caps are accepted only with --clear-terminal')
      }
      const guard = clearTerminal ? await spendGuard(api, identityFile, args, env) : undefined
      if (operation === 'pay') {
        const amountValue = option(args, '--amount-atomic')
        const payTo = option(args, '--pay-to')
        const methodValue = option(args, '--method') ?? 'GET'
        const bodyFile = option(args, '--body-file')
        const contentType = option(args, '--content-type')
        const rpcUrl = option(args, '--rpc-url') ?? env.F4BC_RPC_URL
        const explicitQuorumRpcUrls = repeatedOption(args, '--quorum-rpc-url')
        const quorumRpcUrls = explicitQuorumRpcUrls.length > 0
          ? explicitQuorumRpcUrls
          : [env.F4BC_QUORUM_RPC_URL_1, env.F4BC_QUORUM_RPC_URL_2]
              .filter((value): value is string => value !== undefined)
        exactArgs(args, 2, usage)
        if (!amountValue) throw new Error('--amount-atomic is required for recover pay')
        if (!payTo) throw new Error('--pay-to is required for recover pay')
        if (!rpcUrl) throw new Error('--rpc-url or F4BC_RPC_URL is required for recover pay')
        if (quorumRpcUrls.length !== 2) {
          throw new Error(
            'recover pay requires exactly two --quorum-rpc-url values or both F4BC_QUORUM_RPC_URL_1 and F4BC_QUORUM_RPC_URL_2',
          )
        }
        const method = methodValue.toUpperCase()
        if (method !== 'GET' && method !== 'POST') throw new Error('--method must be GET or POST')
        if (bodyFile && method !== 'POST') throw new Error('--body-file requires --method POST')
        if (contentType && method !== 'POST') throw new Error('--content-type requires --method POST')
        const peer = new PeerPaymentClient(localIdentity, {
          identityPath: identityFile,
          rpcUrl,
          quorumRpcUrls,
          ...(chainId ? { chainIdOverride: chainId } : {}),
          ...(deps.rpcFetch ? { rpcFetch: deps.rpcFetch } : {}),
        })
        const amountAtomic = positiveAtomicAmount(amountValue, '--amount-atomic')
        const body = bodyFile
          ? new Uint8Array(await boundedFile(
              bodyFile,
              MAX_PEER_REQUEST_BODY_BYTES,
              'peer request body',
              identityFile,
              localIdentity,
            ))
          : undefined
        result = await peer.clearTerminalPayment({
          url: args[1],
          method,
          ...(body ? { body } : {}),
          ...(contentType ? { contentType } : {}),
          amountAtomic,
          payTo,
        }, guard!)
        break
      }
      exactArgs(args, operation === 'post' ? 2 : 3, usage)
      if (operation === 'post') {
        const job = await jsonFile(args[1], identityFile, localIdentity)
        result = clearTerminal
          ? await api.clearTerminalPostJob(job, guard!)
          : await api.recoverPostJob(job)
        break
      }
      const bid = await jsonFile(args[2], identityFile, localIdentity)
      result = clearTerminal
        ? await api.clearTerminalBid(args[1], bid, guard!)
        : await api.recoverBid(args[1], bid)
      break
    }
    case 'bid': {
      const guard = await spendGuard(api, identityFile, args, env)
      exactArgs(args, 2, 'bid <jobId> <bid.json> --max-payment-atomic N --daily-payment-limit-atomic N')
      const bid = await jsonFile(args[1], identityFile, localIdentity)
      const amountAtomic = await api.bidPaymentAmount(args[0])
      if (amountAtomic !== BID_FEE_ATOMIC) throw new Error('unexpected bid payment amount')
      result = await guard.execute(
        'bid_job',
        { jobId: args[0], bid },
        amountAtomic,
        (control) => api.bid(args[0], bid, {
          control,
          expectedAmountAtomic: amountAtomic,
        }),
      )
      break
    }
    case 'award': {
      exactArgs(args, 2, 'award <jobId> <bidId>')
      result = await api.award(args[0], args[1])
      break
    }
    case 'msg': {
      if (args.length < 3) throw new Error('usage: 1f4bc msg <jobId> <bidId> <text>')
      result = await api.message(args[0], args[1], args.slice(2).join(' '))
      break
    }
    case 'thread': {
      const afterValue = option(args, '--after')
      const limitValue = option(args, '--limit')
      exactArgs(args, 2, 'thread <jobId> <bidId> [--after <seq>] [--limit <1-100>]')
      const after = afterValue === undefined ? undefined : nonnegativeInteger(afterValue, 'cursor')
      const limit = limitValue === undefined ? 100 : nonnegativeInteger(limitValue, 'limit')
      if (limit < 1 || limit > 100) throw new Error('thread limit must be between 1 and 100')
      result = await api.thread(args[0], args[1], after, limit)
      break
    }
    case 'inbox': {
      const afterValue = option(args, '--after')
      exactArgs(args, 0, 'inbox [--after <seq>]')
      result = await api.inbox(afterValue === undefined ? undefined : nonnegativeInteger(afterValue, 'cursor'))
      break
    }
    case 'proof': {
      exactArgs(args, 5, 'proof <jobId> <worker> <txHash> <logIndex> <amountAtomic>')
      if (!/^[0-9]+$/.test(args[4])) throw new Error('amountAtomic must be an integer string')
      result = await api.proof({
        jobId: args[0],
        worker: args[1],
        txHash: args[2],
        logIndex: nonnegativeInteger(args[3], 'log index'),
        amountAtomic: args[4],
      })
      break
    }
    case 'attest': {
      const otherSignature = option(args, '--with')
      exactArgs(args, 1, 'attest <proofId> [--with <counterpartSignature>]')
      const proofId = positiveInteger(args[0], 'proof id')
      result = otherSignature
        ? await api.submitAttestation(proofId, otherSignature)
        : await api.signAttestation(proofId)
      break
    }
    case 'pay': {
      const guard = await spendGuard(api, identityFile, args, env)
      const amountValue = option(args, '--amount-atomic')
      const payTo = option(args, '--pay-to')
      const methodValue = option(args, '--method') ?? 'GET'
      const bodyFile = option(args, '--body-file')
      const contentType = option(args, '--content-type')
      const rpcUrl = option(args, '--rpc-url') ?? env.F4BC_RPC_URL
      exactArgs(
        args,
        1,
        'pay <https-url> --amount-atomic N --pay-to 0x... [--method GET|POST] [--body-file PATH] [--content-type TYPE] --rpc-url https://...',
      )
      if (!amountValue) throw new Error('--amount-atomic is required for pay')
      if (!payTo) throw new Error('--pay-to is required for pay')
      if (!rpcUrl) throw new Error('--rpc-url or F4BC_RPC_URL is required for pay')
      const method = methodValue.toUpperCase()
      if (method !== 'GET' && method !== 'POST') throw new Error('--method must be GET or POST')
      if (bodyFile && method !== 'POST') throw new Error('--body-file requires --method POST')
      if (contentType && method !== 'POST') throw new Error('--content-type requires --method POST')
      const peer = new PeerPaymentClient(localIdentity, {
        identityPath: identityFile,
        rpcUrl,
        ...(chainId ? { chainIdOverride: chainId } : {}),
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
        ...(deps.rpcFetch ? { rpcFetch: deps.rpcFetch } : {}),
      })
      const amountAtomic = positiveAtomicAmount(amountValue, '--amount-atomic')
      const body = bodyFile
        ? new Uint8Array(await boundedFile(
          bodyFile,
          MAX_PEER_REQUEST_BODY_BYTES,
          'peer request body',
          identityFile,
          localIdentity,
        ))
        : undefined
      result = await guard.execute(
        'peer_pay',
        peerPaymentSpendInput({
          url: args[0],
          method,
          ...(body ? { body } : {}),
          ...(contentType ? { contentType } : {}),
          amountAtomic,
          payTo,
        }),
        amountAtomic,
        (control) => peer.pay({
          url: args[0],
          method,
          ...(body ? { body } : {}),
          ...(contentType ? { contentType } : {}),
          amountAtomic,
          payTo,
        }, control),
      )
      break
    }
    case 'balance': {
      const rpcUrl = option(args, '--rpc-url') ?? env.F4BC_RPC_URL
      exactArgs(args, 0, 'balance --rpc-url https://...')
      if (!rpcUrl) throw new Error('--rpc-url or F4BC_RPC_URL is required for balance')
      assertNoIdentitySecrets(rpcUrl, localIdentity, 'RPC URL')
      result = await readUsdcBalance({
        rpcUrl,
        chainId: api.identity.chainId,
        wallet: api.identity.wallet,
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
      })
      break
    }
    case 'receipt': {
      const rpcUrl = option(args, '--rpc-url') ?? env.F4BC_RPC_URL
      exactArgs(args, 1, 'receipt <txHash> --rpc-url https://...')
      if (!rpcUrl) throw new Error('--rpc-url or F4BC_RPC_URL is required for receipt')
      assertNoIdentitySecrets(rpcUrl, localIdentity, 'RPC URL')
      result = await inspectUsdcReceipt({
        rpcUrl,
        chainId: api.identity.chainId,
        txHash: args[0],
        ...(deps.fetch ? { fetch: deps.fetch } : {}),
      })
      break
    }
    case 'mcp': {
      const allowWriteTools = flag(args, '--allow-write-tools')
      const allowPaidTools = flag(args, '--allow-paid-tools')
      const explicitMaxPaymentValue = option(args, '--max-payment-atomic')
      const explicitDailyPaymentValue = option(args, '--daily-payment-limit-atomic')
      const maxPaymentValue = explicitMaxPaymentValue ??
        (allowPaidTools ? env.F4BC_MAX_PAYMENT_ATOMIC : undefined)
      const dailyPaymentValue = explicitDailyPaymentValue ??
        (allowPaidTools ? env.F4BC_DAILY_PAYMENT_LIMIT_ATOMIC : undefined)
      exactArgs(
        args,
        0,
        'mcp [--allow-write-tools] [--allow-paid-tools --max-payment-atomic N --daily-payment-limit-atomic N]',
      )
      if (allowPaidTools && !allowWriteTools) {
        throw new Error('--allow-paid-tools also requires the explicit --allow-write-tools opt-in')
      }
      if (
        !allowPaidTools &&
        (explicitMaxPaymentValue !== undefined || explicitDailyPaymentValue !== undefined)
      ) {
        throw new Error('MCP payment caps require the explicit --allow-paid-tools opt-in')
      }
      if (allowPaidTools && maxPaymentValue === undefined) {
        throw new Error('--max-payment-atomic is required with --allow-paid-tools')
      }
      if (allowPaidTools && dailyPaymentValue === undefined) {
        throw new Error('--daily-payment-limit-atomic is required with --allow-paid-tools')
      }
      if (allowPaidTools) await assertNoSplitSpendJournals(identityFile)
      const mcpOptions: AgentMcpServerOptions = {
        ...(allowWriteTools ? { writeTools: true } : {}),
        ...(allowPaidTools
          ? {
              payments: {
                journalPath: mcpSpendJournalPath(api, identityFile),
                maxPaymentAtomic: positiveAtomicAmount(maxPaymentValue!, '--max-payment-atomic'),
                dailyPaymentLimitAtomic: positiveAtomicAmount(
                  dailyPaymentValue!,
                  '--daily-payment-limit-atomic',
                ),
              },
            }
          : {}),
      }
      ;(deps.runMcp ?? runAgentMcp)(api, mcpOptions)
      return undefined
    }
    default:
      throw new Error('unknown command; run 1f4bc help')
  }

  printJson(stdout, result)
  return result
}

export async function main(): Promise<void> {
  await runCli(process.argv.slice(2))
}
