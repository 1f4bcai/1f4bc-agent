import { createHash, timingSafeEqual } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { open, readdir, unlink } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
} from '@x402/core/http'
import type { PaymentRequired } from '@x402/core/types'
import { x402Client, wrapFetchWithPayment } from '@x402/fetch'
import { ExactEvmScheme, authorizationTypes } from '@x402/evm'
import {
  PAYMENT_IDENTIFIER,
  appendPaymentIdentifierToExtensions,
  generatePaymentId,
} from '@x402/extensions/payment-identifier'
import {
  encodeFunctionData,
  getAddress,
  isAddress,
  recoverTypedDataAddress,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import type { FetchLike } from './api.js'
import { sha256Hex } from './api.js'
import {
  deriveEd25519PublicKey,
  fromBase64,
  identityPath as normalizeIdentityPath,
  loadIdentity,
  normalizeBaseUrl,
  normalizeWalletPrivateKey,
  toBase64,
  type AgentIdentity,
} from './keys.js'
import {
  atomicCreatePrivate,
  atomicWritePrivate,
  ensurePrivateDirectory,
  readPrivateFile,
  withFileLock,
} from './local-journal.js'
import {
  claimAuthorizedPaymentControl,
  McpSpendGuard,
  type McpPaymentControl,
} from './mcp-payments.js'
import { assertNoIdentitySecrets } from './secret-safety.js'
import { spendPolicyScope } from './spend-scope.js'
import {
  claimedSpendControlMetadata,
  consumeTerminalPaymentClear,
  terminalPaymentCleared,
  TerminalPaymentCleared,
} from './terminal-clear.js'
import { usdcEip712Domain } from './usdc-domain.js'

const ZERO_ADDRESS = `0x${'0'.repeat(40)}`
const MAX_PEER_PAYMENT_ENTRIES = 4_096
const MAX_PEER_PAYMENT_JOURNAL_BYTES = 256 * 1_024
const MAX_EVIDENCE_RESPONSE_BYTES = 64 * 1_024 * 1_024
const MAX_RPC_RESPONSE_BYTES = 1 * 1_024 * 1_024
const DEFAULT_NETWORK_TIMEOUT_MS = 30_000
const MAX_UINT256 = (1n << 256n) - 1n
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
const AUTHORIZATION_USED_TOPIC =
  '0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5'
const TERMINAL_RPC_QUORUM_SIZE = 3
const AUTHORIZATION_STATE_ABI = [{
  type: 'function',
  name: 'authorizationState',
  stateMutability: 'view',
  inputs: [
    { name: 'authorizer', type: 'address' },
    { name: 'nonce', type: 'bytes32' },
  ],
  outputs: [{ name: '', type: 'bool' }],
}] as const
export const USDC_BY_CHAIN_ID: Readonly<Record<number, `0x${string}`>> = Object.freeze({
  8453: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  84532: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
})
type JsonRecord = Record<string, unknown>

class TerminalPeerPaymentBlocked extends Error {
  readonly paymentMayHaveOccurred = false as const

  constructor() {
    super('peer-payment authorization is terminal; clear it before retrying')
    this.name = 'TerminalPeerPaymentBlocked'
  }
}

type PeerPaymentAttemptBase = {
  version: 1
  state: 'pending' | 'settled' | 'terminal'
  paymentId: string
  publicKey: string
  wallet: `0x${string}`
  chainId: number
  url: string
  method: 'GET' | 'POST'
  contentType?: string
  bodyHash: string
  amountAtomic: string
  payTo: `0x${string}`
  asset: `0x${string}`
  headerName: 'payment-signature' | 'x-payment'
  headerValue: string
  createdAt: number
}

type PendingPeerPaymentAttempt = PeerPaymentAttemptBase & { state: 'pending' }
type SettledPeerPaymentAttempt = PeerPaymentAttemptBase & {
  state: 'settled'
  settledAt: number
  evidence: PeerPaymentEvidence
}
type PeerAuthorizationExpiryProof = {
  rpcOriginHash: string
  finalizedBlockNumber: string
  finalizedBlockHash: `0x${string}`
  finalizedBlockTimestamp: string
  authorizationState: false
}
type TerminalPeerPaymentAttempt = PeerPaymentAttemptBase & {
  state: 'terminal'
  terminalAt: number
  terminalProofVersion: 1
  authorizationNonce: `0x${string}`
  validBefore: string
  quorum: [
    PeerAuthorizationExpiryProof,
    PeerAuthorizationExpiryProof,
    PeerAuthorizationExpiryProof,
  ]
}
type PeerPaymentAttempt =
  | PendingPeerPaymentAttempt
  | SettledPeerPaymentAttempt
  | TerminalPeerPaymentAttempt

export type PeerPaymentRequest = {
  url: string
  method?: 'GET' | 'POST'
  body?: Uint8Array
  contentType?: string
  amountAtomic: bigint
  payTo: string
}

type PreparedPeerPaymentRequest = {
  readonly url: string
  readonly method: 'GET' | 'POST'
  readonly body: Uint8Array
  readonly contentType?: string
  readonly amountAtomic: bigint
  readonly payTo: `0x${string}`
}

export type PeerPaymentEvidence = {
  state: 'settled'
  paymentId: string
  url: string
  queryPresent: boolean
  method: 'GET' | 'POST'
  chainId: number
  network: string
  asset: `0x${string}`
  amountAtomic: string
  payTo: `0x${string}`
  payer: `0x${string}`
  transaction: `0x${string}`
  logIndex: number
  responseStatus: number
  responseContentType: string | null
  responseBytes: number
  responseSha256: string
}

export type PeerPaymentClientOptions = {
  identityPath: string
  /** Explicit payment-network override; the bound identity file remains authoritative. */
  chainIdOverride?: number
  /** Trusted Base RPC used to prove the exact finalized USDC transfer. */
  rpcUrl: string
  /** Two additional, independently operated RPC origins required for terminal clear. */
  quorumRpcUrls?: readonly string[]
  fetch?: FetchLike
  rpcFetch?: FetchLike
  now?: () => number
  timeoutMs?: number
}

export type PeerPaymentTerminalClearResult = {
  state: 'terminal'
  cleared: true
  archived: true
}

export type UsdcBalanceEvidence = {
  chainId: number
  network: string
  asset: `0x${string}`
  wallet: `0x${string}`
  balanceAtomic: string
  blockTag: 'finalized'
}

export type UsdcTransferEvidence = {
  logIndex: number
  from: `0x${string}`
  to: `0x${string}`
  amountAtomic: string
}

export type UsdcReceiptEvidence = {
  chainId: number
  network: string
  asset: `0x${string}`
  transaction: `0x${string}`
  blockNumber: string
  /** Canonical receipt-block timestamp in Unix seconds. */
  blockTimestamp: string
  finalizedBlockNumber: string
  transfers: UsdcTransferEvidence[]
  authorizations: Array<{
    logIndex: number
    authorizer: `0x${string}`
    nonce: `0x${string}`
  }>
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function samePeerPaymentPrincipal(
  persisted: AgentIdentity,
  active: AgentIdentity,
  boundChainId: number,
): boolean {
  return persisted.privateKey === active.privateKey &&
    persisted.publicKey === active.publicKey &&
    persisted.walletPrivateKey === active.walletPrivateKey &&
    persisted.wallet === active.wallet &&
    persisted.chainId === boundChainId
}

function classifiedPeerPaymentError(error: unknown, mayHaveOccurred: boolean): Error {
  if (!mayHaveOccurred && isRecord(error) && typeof error.paymentMayHaveOccurred === 'boolean') {
    return error as unknown as Error
  }
  const wrapped = error instanceof Error ? error : new Error(String(error))
  try {
    return Object.assign(wrapped, { paymentMayHaveOccurred: mayHaveOccurred })
  } catch {
    return Object.assign(new Error(wrapped.message, { cause: wrapped }), {
      paymentMayHaveOccurred: mayHaveOccurred,
    })
  }
}

function expectedUsdc(chainId: number): `0x${string}` {
  const asset = USDC_BY_CHAIN_ID[chainId]
  if (!asset) throw new Error(`USDC tooling is not configured for chain ${chainId}`)
  return asset
}

function networkFor(chainId: number): `eip155:${number}` {
  return `eip155:${chainId}`
}

function normalizeHttpsUrl(value: string, label: string): URL {
  const url = new URL(value)
  if (url.protocol !== 'https:') throw new Error(`${label} must use HTTPS`)
  if (url.username || url.password) throw new Error(`${label} must not contain credentials`)
  if (url.hash) throw new Error(`${label} must not contain a fragment`)
  return url
}

function canonicalAddress(value: string, label: string): `0x${string}` {
  if (!isAddress(value)) throw new Error(`${label} must be an EVM address`)
  const address = getAddress(value)
  if (address.toLowerCase() === ZERO_ADDRESS) throw new Error(`${label} must not be the zero address`)
  return address
}

function displayUrl(target: URL): string {
  return `${target.origin}${target.pathname}`
}

function bodyHash(body: Uint8Array): string {
  return createHash('sha256').update(body).digest('hex')
}

function preparePeerPaymentRequest(input: PeerPaymentRequest): PreparedPeerPaymentRequest {
  if (!isRecord(input)) throw new Error('peer payment request must be an object')
  // Read each caller-owned property exactly once, synchronously. Everything
  // below uses canonical primitives and a private byte copy, so getters,
  // proxies, or mutation after this boundary cannot redirect an authorization.
  const rawUrl = input.url
  const rawMethod = input.method
  const rawBody = input.body
  const rawAmountAtomic = input.amountAtomic
  const rawPayTo = input.payTo
  if (typeof rawUrl !== 'string') throw new Error('worker endpoint must be a URL string')
  const target = normalizeHttpsUrl(rawUrl, 'worker endpoint')
  const method = rawMethod ?? 'GET'
  if (method !== 'GET' && method !== 'POST') throw new Error('worker method must be GET or POST')
  if (rawBody !== undefined && !(rawBody instanceof Uint8Array)) {
    throw new Error('worker request body must be a Uint8Array')
  }
  const body = new Uint8Array(rawBody ?? new Uint8Array())
  if (body.byteLength > MAX_EVIDENCE_RESPONSE_BYTES) {
    throw new Error('worker request body exceeds the 64 MiB safety limit')
  }
  if (method === 'GET' && body.byteLength > 0) {
    throw new Error('GET worker payments cannot include a body')
  }
  if (typeof rawAmountAtomic !== 'bigint' || rawAmountAtomic <= 0n || rawAmountAtomic > MAX_UINT256) {
    throw new Error('amount must be a positive uint256 atomic integer')
  }
  if (typeof rawPayTo !== 'string') throw new Error('pay-to address must be an EVM address')
  const payTo = canonicalAddress(rawPayTo, 'pay-to address')
  const rawContentType = method === 'POST' ? input.contentType : undefined
  if (rawContentType !== undefined && typeof rawContentType !== 'string') {
    throw new Error('content type is invalid')
  }
  const contentType = method === 'POST'
    ? (rawContentType ?? 'application/octet-stream')
    : undefined
  if (contentType && (contentType.length > 200 || /[\r\n]/.test(contentType))) {
    throw new Error('content type is invalid')
  }
  return Object.freeze({
    url: target.href,
    method,
    body,
    ...(contentType ? { contentType } : {}),
    amountAtomic: rawAmountAtomic,
    payTo,
  })
}

function spendInputFromPrepared(input: PreparedPeerPaymentRequest): Record<string, unknown> {
  return {
    url: input.url,
    method: input.method,
    bodySha256: bodyHash(input.body),
    ...(input.contentType ? { contentType: input.contentType } : {}),
    amountAtomic: input.amountAtomic.toString(),
    payTo: input.payTo,
  }
}

export function peerPaymentSpendInput(input: PeerPaymentRequest): Record<string, unknown> {
  return spendInputFromPrepared(preparePeerPaymentRequest(input))
}

function logicalKey(
  identity: AgentIdentity,
  target: URL,
  method: 'GET' | 'POST',
  body: Uint8Array,
  contentType: string | undefined,
  amountAtomic: bigint,
  payTo: `0x${string}`,
  asset: `0x${string}`,
): string {
  return sha256Hex([
    identity.publicKey,
    identity.wallet.toLowerCase(),
    String(identity.chainId),
    method,
    target.href,
    contentType ?? '',
    bodyHash(body),
    amountAtomic.toString(),
    payTo.toLowerCase(),
    asset.toLowerCase(),
  ].join('\n'))
}

function expectedAttemptFromPrepared(
  identity: AgentIdentity,
  input: PreparedPeerPaymentRequest,
  asset: `0x${string}`,
): Omit<
  PeerPaymentAttemptBase,
  'version' | 'state' | 'paymentId' | 'headerName' | 'headerValue' | 'createdAt'
> {
  return {
    publicKey: identity.publicKey,
    wallet: identity.wallet,
    chainId: identity.chainId,
    url: input.url,
    method: input.method,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    bodyHash: bodyHash(input.body),
    amountAtomic: input.amountAtomic.toString(),
    payTo: input.payTo,
    asset,
  }
}

function peerPaymentRoot(identityPath: string): string {
  return join(dirname(identityPath), 'peer-payment-attempts')
}

function peerPaymentDirectory(identityPath: string, publicKey: string): string {
  return join(peerPaymentRoot(identityPath), sha256Hex(publicKey))
}

function peerPaymentFile(identityPath: string, publicKey: string, key: string): string {
  return join(peerPaymentDirectory(identityPath, publicKey), `${key}.json`)
}

function peerPaymentArchiveDirectory(identityPath: string, publicKey: string): string {
  return join(peerPaymentDirectory(identityPath, publicKey), 'terminal-archive')
}

async function ensurePrivateJournalDirectories(identityPath: string, publicKey: string): Promise<void> {
  const root = peerPaymentRoot(identityPath)
  const directory = peerPaymentDirectory(identityPath, publicKey)
  await ensurePrivateDirectory(root)
  await ensurePrivateDirectory(directory)
}

async function ensurePrivateArchiveDirectory(identityPath: string, publicKey: string): Promise<void> {
  await ensurePrivateJournalDirectories(identityPath, publicKey)
  const directory = peerPaymentArchiveDirectory(identityPath, publicKey)
  await ensurePrivateDirectory(directory)
}

function parseAuthorizationExpiryProof(value: unknown): PeerAuthorizationExpiryProof {
  if (
    !isRecord(value) ||
    typeof value.rpcOriginHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.rpcOriginHash) ||
    typeof value.finalizedBlockNumber !== 'string' ||
    !/^(?:0|[1-9][0-9]*)$/.test(value.finalizedBlockNumber) ||
    typeof value.finalizedBlockHash !== 'string' ||
    !/^0x[0-9a-f]{64}$/.test(value.finalizedBlockHash) ||
    typeof value.finalizedBlockTimestamp !== 'string' ||
    !/^(?:0|[1-9][0-9]*)$/.test(value.finalizedBlockTimestamp) ||
    value.authorizationState !== false
  ) {
    throw new Error('peer-payment terminal proof is invalid')
  }
  return value as PeerAuthorizationExpiryProof
}

function parseEvidence(value: unknown): PeerPaymentEvidence {
  if (
    !isRecord(value) ||
    value.state !== 'settled' ||
    typeof value.paymentId !== 'string' ||
    typeof value.url !== 'string' ||
    typeof value.queryPresent !== 'boolean' ||
    (value.method !== 'GET' && value.method !== 'POST') ||
    typeof value.chainId !== 'number' ||
    typeof value.network !== 'string' ||
    typeof value.asset !== 'string' ||
    typeof value.amountAtomic !== 'string' ||
    typeof value.payTo !== 'string' ||
    typeof value.payer !== 'string' ||
    typeof value.transaction !== 'string' ||
    typeof value.logIndex !== 'number' ||
    !Number.isSafeInteger(value.logIndex) ||
    value.logIndex < 0 ||
    typeof value.responseStatus !== 'number' ||
    (value.responseContentType !== null && typeof value.responseContentType !== 'string') ||
    typeof value.responseBytes !== 'number' ||
    typeof value.responseSha256 !== 'string'
  ) {
    throw new Error('peer-payment journal contains invalid evidence')
  }
  return value as PeerPaymentEvidence
}

function parseAttempt(value: unknown): PeerPaymentAttempt {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    (value.state !== 'pending' && value.state !== 'settled' && value.state !== 'terminal') ||
    typeof value.paymentId !== 'string' ||
    typeof value.publicKey !== 'string' ||
    typeof value.wallet !== 'string' ||
    typeof value.chainId !== 'number' ||
    typeof value.url !== 'string' ||
    (value.method !== 'GET' && value.method !== 'POST') ||
    (value.contentType !== undefined && typeof value.contentType !== 'string') ||
    typeof value.bodyHash !== 'string' ||
    typeof value.amountAtomic !== 'string' ||
    typeof value.payTo !== 'string' ||
    typeof value.asset !== 'string' ||
    (value.headerName !== 'payment-signature' && value.headerName !== 'x-payment') ||
    typeof value.headerValue !== 'string' ||
    typeof value.createdAt !== 'number'
  ) {
    throw new Error('peer-payment journal entry is invalid')
  }
  if (value.state === 'pending') return value as PendingPeerPaymentAttempt
  if (value.state === 'terminal') {
    if (
      typeof value.terminalAt !== 'number' ||
      !Number.isSafeInteger(value.terminalAt) ||
      value.terminalAt < 0 ||
      value.terminalProofVersion !== 1 ||
      typeof value.authorizationNonce !== 'string' ||
      !/^0x[0-9a-f]{64}$/.test(value.authorizationNonce) ||
      typeof value.validBefore !== 'string' ||
      !/^[1-9][0-9]*$/.test(value.validBefore) ||
      !Array.isArray(value.quorum) ||
      value.quorum.length !== TERMINAL_RPC_QUORUM_SIZE
    ) {
      throw new Error('terminal peer-payment journal entry is invalid')
    }
    const quorum = value.quorum.map(
      parseAuthorizationExpiryProof,
    ) as TerminalPeerPaymentAttempt['quorum']
    const validBefore = BigInt(value.validBefore)
    if (
      new Set(quorum.map((proof) => proof.rpcOriginHash)).size !== TERMINAL_RPC_QUORUM_SIZE ||
      quorum.some((proof) => BigInt(proof.finalizedBlockTimestamp) < validBefore)
    ) {
      throw new Error('terminal peer-payment quorum proof contradicts the signed expiry')
    }
    return {
      ...(value as unknown as TerminalPeerPaymentAttempt),
      quorum,
    }
  }
  if (typeof value.settledAt !== 'number') {
    throw new Error('settled peer-payment journal entry is invalid')
  }
  return {
    ...(value as unknown as SettledPeerPaymentAttempt),
    evidence: parseEvidence(value.evidence),
  }
}

function peerPaymentContents(attempt: PeerPaymentAttempt): string {
  const contents = `${JSON.stringify(attempt)}\n`
  if (Buffer.byteLength(contents, 'utf8') > MAX_PEER_PAYMENT_JOURNAL_BYTES) {
    throw new Error('peer-payment journal entry exceeds its byte-size safety limit')
  }
  return contents
}

async function loadAttempt(path: string): Promise<PeerPaymentAttempt | undefined> {
  try {
    return parseAttempt(JSON.parse(await readPrivateFile(
      path,
      MAX_PEER_PAYMENT_JOURNAL_BYTES,
      'peer-payment journal entry',
    )) as unknown)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    if (error instanceof SyntaxError) throw new Error('peer-payment journal contains invalid JSON')
    throw error
  }
}

async function loadArchivedTerminalAttempt(
  identityPath: string,
  publicKey: string,
  key: string,
  expected?: Pick<PeerPaymentAttemptBase, 'paymentId' | 'headerName' | 'headerValue'>,
): Promise<TerminalPeerPaymentAttempt | undefined> {
  const directory = peerPaymentArchiveDirectory(identityPath, publicKey)
  await ensurePrivateArchiveDirectory(identityPath, publicKey)
  let names: string[]
  try {
    const directoryNames = await readdir(directory)
    const archiveNames = directoryNames.filter((name) => name.endsWith('.json'))
    if (archiveNames.length > MAX_PEER_PAYMENT_ENTRIES) {
      throw new Error('terminal peer-payment archive exceeds its entry safety limit')
    }
    names = archiveNames.filter((name) =>
      new RegExp(`^${key}\\.[0-9]+\\.[0-9a-f]{16}\\.json$`).test(name))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (names.length === 0) return undefined
  const matches: Array<{ name: string; attempt: TerminalPeerPaymentAttempt }> = []
  for (const name of names.sort()) {
    const raw = await readPrivateFile(
      join(directory, name),
      MAX_PEER_PAYMENT_JOURNAL_BYTES,
      'archived peer-payment journal entry',
    )
    let parsed: PeerPaymentAttempt
    try {
      parsed = parseAttempt(JSON.parse(raw) as unknown)
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('archived peer-payment journal contains invalid JSON')
      }
      throw error
    }
    if (
      parsed.state !== 'terminal' ||
      !name.endsWith(`.${parsed.terminalAt}.${sha256Hex(raw).slice(0, 16)}.json`)
    ) {
      throw new Error('archived peer-payment journal entry is inconsistent')
    }
    matches.push({ name, attempt: parsed })
  }
  const byAuthorization = new Map<string, number>()
  for (const { attempt } of matches) {
    const authorizationKey = sha256Hex([
      attempt.paymentId,
      attempt.headerName,
      attempt.headerValue,
    ].join('\n'))
    byAuthorization.set(authorizationKey, (byAuthorization.get(authorizationKey) ?? 0) + 1)
  }
  if ([...byAuthorization.values()].some((count) => count > 1)) {
    throw new Error('duplicate terminal archives exist for one peer-payment authorization')
  }
  const candidates = expected
    ? matches.filter(({ attempt }) =>
        attempt.paymentId === expected.paymentId &&
        attempt.headerName === expected.headerName &&
        attempt.headerValue === expected.headerValue)
    : matches
  candidates.sort((left, right) =>
    right.attempt.terminalAt - left.attempt.terminalAt ||
    right.name.localeCompare(left.name))
  return candidates[0]?.attempt
}

async function stageTerminalPeerPaymentArchive(
  identityPath: string,
  publicKey: string,
  key: string,
  attempt: TerminalPeerPaymentAttempt,
): Promise<void> {
  await ensurePrivateArchiveDirectory(identityPath, publicKey)
  const contents = peerPaymentContents(attempt)
  const directory = peerPaymentArchiveDirectory(identityPath, publicKey)
  const target = join(
    directory,
    `${key}.${attempt.terminalAt}.${sha256Hex(contents).slice(0, 16)}.json`,
  )
  await withFileLock(join(directory, '.entry-count'), async () => {
    const existing = await loadArchivedTerminalAttempt(identityPath, publicKey, key, attempt)
    if (existing) {
      if (peerPaymentContents(existing) !== contents) {
        throw new Error('terminal peer-payment archive conflicts with the exact journal')
      }
      return
    }
    const entries = (await readdir(directory)).filter((name) => name.endsWith('.json'))
    if (entries.length >= MAX_PEER_PAYMENT_ENTRIES) {
      throw new Error('terminal peer-payment archive reached its entry safety limit')
    }
    if (!await atomicCreatePrivate(target, contents)) {
      const raced = await readPrivateFile(
        target,
        MAX_PEER_PAYMENT_JOURNAL_BYTES,
        'archived peer-payment journal entry',
      )
      if (raced !== contents) {
        throw new Error('terminal peer-payment archive conflicts with the exact journal')
      }
    }
  })
}

async function removeAndSync(path: string): Promise<void> {
  try {
    await unlink(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  const directory = await open(dirname(path), 'r')
  try {
    await directory.sync()
  } finally {
    await directory.close()
  }
}

function assertAttemptMatches(
  attempt: PeerPaymentAttempt,
  expected: Omit<PeerPaymentAttemptBase, 'version' | 'state' | 'paymentId' | 'headerName' | 'headerValue' | 'createdAt'>,
): void {
  if (
    attempt.publicKey !== expected.publicKey ||
    attempt.wallet.toLowerCase() !== expected.wallet.toLowerCase() ||
    attempt.chainId !== expected.chainId ||
    attempt.url !== expected.url ||
    attempt.method !== expected.method ||
    attempt.contentType !== expected.contentType ||
    attempt.bodyHash !== expected.bodyHash ||
    attempt.amountAtomic !== expected.amountAtomic ||
    attempt.payTo.toLowerCase() !== expected.payTo.toLowerCase() ||
    attempt.asset.toLowerCase() !== expected.asset.toLowerCase()
  ) {
    throw new Error('peer-payment journal entry does not match the requested operation')
  }
}

async function persistNewPending(
  identityPath: string,
  publicKey: string,
  path: string,
  attempt: PendingPeerPaymentAttempt,
): Promise<PeerPaymentAttempt> {
  const directory = peerPaymentDirectory(identityPath, publicKey)
  await ensurePrivateJournalDirectories(identityPath, publicKey)
  return withFileLock(join(directory, '.entry-count'), async () => {
    const existing = await loadAttempt(path)
    if (existing) return existing
    const entries = (await readdir(directory)).filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    if (entries.length >= MAX_PEER_PAYMENT_ENTRIES) {
      throw new Error(`peer-payment journal reached its ${MAX_PEER_PAYMENT_ENTRIES}-entry safety limit`)
    }
    const contents = `${JSON.stringify(attempt)}\n`
    if (Buffer.byteLength(contents, 'utf8') > MAX_PEER_PAYMENT_JOURNAL_BYTES) {
      throw new Error('peer-payment journal entry exceeds its byte-size safety limit')
    }
    await atomicWritePrivate(path, contents)
    return attempt
  })
}

function validateChallenge(
  response: Response,
  target: URL,
  chainId: number,
  asset: `0x${string}`,
  amountAtomic: bigint,
  payTo: `0x${string}`,
): PaymentRequired {
  const encoded = response.headers.get('PAYMENT-REQUIRED') ?? response.headers.get('X-PAYMENT-REQUIRED')
  if (!encoded) throw new Error('worker returned 402 without PAYMENT-REQUIRED')
  let required: PaymentRequired
  try {
    required = decodePaymentRequiredHeader(encoded)
  } catch {
    throw new Error('worker returned an invalid x402 challenge')
  }
  if (required.x402Version !== 2) throw new Error('worker must use x402 v2')
  let resource: URL
  try {
    resource = normalizeHttpsUrl(required.resource.url, 'x402 resource URL')
  } catch {
    throw new Error('x402 resource URL is invalid')
  }
  if (resource.href !== target.href) throw new Error('x402 resource URL does not match the requested endpoint')
  const identifier = required.extensions?.[PAYMENT_IDENTIFIER]
  if (!isRecord(identifier) || !isRecord(identifier.info) || identifier.info.required !== true) {
    throw new Error('worker must require the x402 payment-identifier extension')
  }
  const network = networkFor(chainId)
  const domain = usdcEip712Domain(chainId)
  const matches = required.accepts.filter((entry) =>
    entry.scheme === 'exact' &&
    entry.network === network &&
    entry.asset.toLowerCase() === asset.toLowerCase() &&
    entry.amount === amountAtomic.toString() &&
    isAddress(entry.payTo) &&
    entry.payTo.toLowerCase() === payTo.toLowerCase() &&
    Number.isSafeInteger(entry.maxTimeoutSeconds) &&
    entry.maxTimeoutSeconds > 0 &&
    entry.maxTimeoutSeconds <= 300 &&
    isRecord(entry.extra) &&
    entry.extra.name === domain.name &&
    entry.extra.version === domain.version &&
    (entry.extra.assetTransferMethod === undefined ||
      entry.extra.assetTransferMethod === 'eip3009'),
  )
  if (matches.length === 0) {
    throw new Error('worker challenge does not match the exact x402 policy')
  }
  return required
}

async function validatePaymentHeader(
  value: string,
  paymentId: string,
  target: URL,
  chainId: number,
  asset: `0x${string}`,
  amountAtomic: bigint,
  payTo: `0x${string}`,
  payer: `0x${string}`,
  nowMilliseconds: number,
  requireFresh: boolean,
): Promise<{ nonce: `0x${string}`; validBefore: bigint }> {
  let payload: ReturnType<typeof decodePaymentSignatureHeader>
  try {
    payload = decodePaymentSignatureHeader(value)
  } catch {
    throw new Error('x402 client created an invalid payment authorization')
  }
  const identifier = payload.extensions?.[PAYMENT_IDENTIFIER]
  const accepted = payload.accepted
  const authorization = payload.payload.authorization
  const signature = payload.payload.signature
  const domain = usdcEip712Domain(chainId)
  if (
    payload.x402Version !== 2 ||
    !isRecord(identifier) ||
    !isRecord(identifier.info) ||
    identifier.info.id !== paymentId ||
    accepted.scheme !== 'exact' ||
    accepted.network !== networkFor(chainId) ||
    accepted.asset.toLowerCase() !== asset.toLowerCase() ||
    accepted.amount !== amountAtomic.toString() ||
    !isAddress(accepted.payTo) ||
    accepted.payTo.toLowerCase() !== payTo.toLowerCase() ||
    !Number.isSafeInteger(accepted.maxTimeoutSeconds) ||
    accepted.maxTimeoutSeconds <= 0 ||
    accepted.maxTimeoutSeconds > 300 ||
    !isRecord(accepted.extra) ||
    accepted.extra.name !== domain.name ||
    accepted.extra.version !== domain.version ||
    (accepted.extra.assetTransferMethod !== undefined &&
      accepted.extra.assetTransferMethod !== 'eip3009') ||
    !payload.resource ||
    payload.resource.url !== target.href ||
    !isRecord(authorization) ||
    typeof authorization.from !== 'string' ||
    !isAddress(authorization.from) ||
    authorization.from.toLowerCase() !== payer.toLowerCase() ||
    typeof authorization.to !== 'string' ||
    !isAddress(authorization.to) ||
    authorization.to.toLowerCase() !== payTo.toLowerCase() ||
    authorization.value !== amountAtomic.toString() ||
    authorization.validAfter !== '0' ||
    typeof authorization.validBefore !== 'string' ||
    !/^[0-9]+$/.test(authorization.validBefore) ||
    typeof authorization.nonce !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/.test(authorization.nonce) ||
    typeof signature !== 'string' ||
    !/^0x[0-9a-fA-F]{130}$/.test(signature)
  ) {
    throw new Error('x402 payment authorization does not match the exact policy')
  }
  const validBefore = BigInt(authorization.validBefore)
  const nowSeconds = BigInt(Math.floor(nowMilliseconds / 1_000))
  if (validBefore <= 0n || (requireFresh && (
    validBefore <= nowSeconds ||
    validBefore > nowSeconds + BigInt(accepted.maxTimeoutSeconds) + 5n
  ))) {
    throw new Error('x402 payment authorization has an invalid validity window')
  }
  let recovered: string
  try {
    recovered = await recoverTypedDataAddress({
      domain: {
        name: domain.name,
        version: domain.version,
        chainId,
        verifyingContract: asset,
      },
      types: authorizationTypes,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: authorization.from,
        to: authorization.to,
        value: BigInt(authorization.value as string),
        validAfter: 0n,
        validBefore,
        nonce: authorization.nonce as Hex,
      },
      signature: signature as Hex,
    })
  } catch {
    throw new Error('x402 client created an invalid EIP-3009 signature')
  }
  if (recovered.toLowerCase() !== payer.toLowerCase()) {
    throw new Error('x402 EIP-3009 authorization signer does not match the local wallet')
  }
  return {
    nonce: authorization.nonce.toLowerCase() as `0x${string}`,
    validBefore,
  }
}

function peerAuthorizationHash(
  attempt: Pick<
    PeerPaymentAttemptBase,
    'publicKey' | 'wallet' | 'chainId' | 'headerName' | 'headerValue'
  >,
  nonce: `0x${string}`,
): string {
  return sha256Hex([
    attempt.publicKey,
    attempt.wallet.toLowerCase(),
    String(attempt.chainId),
    nonce.toLowerCase(),
    attempt.headerName,
    attempt.headerValue,
  ].join('\n'))
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (!response.body || response.bodyUsed) return
  await response.body.cancel().catch(() => undefined)
}

async function bodylessPaymentChallenge(response: Response): Promise<Response> {
  const headers = new Headers()
  for (const name of ['PAYMENT-REQUIRED', 'X-PAYMENT-REQUIRED']) {
    const value = response.headers.get(name)
    if (value) headers.set(name, value)
  }
  await cancelResponseBody(response)
  return new Response(null, { status: 402, headers })
}

async function responseDigest(response: Response): Promise<{ bytes: number; sha256: string }> {
  const hash = createHash('sha256')
  let bytes = 0
  if (response.body) {
    const reader = response.body.getReader()
    try {
      while (true) {
        const chunk = await reader.read()
        if (chunk.done) break
        bytes += chunk.value.byteLength
        if (bytes > MAX_EVIDENCE_RESPONSE_BYTES) {
          await reader.cancel().catch(() => undefined)
          throw new Error('worker response exceeds the 64 MiB evidence safety limit')
        }
        hash.update(chunk.value)
      }
    } catch (error) {
      await reader.cancel().catch(() => undefined)
      throw error
    } finally {
      reader.releaseLock()
    }
  }
  return { bytes, sha256: hash.digest('hex') }
}

function decodeSettlement(
  response: Response,
  chainId: number,
  amountAtomic: bigint,
  payer: `0x${string}`,
): { transaction: `0x${string}` } {
  const encoded = response.headers.get('PAYMENT-RESPONSE') ?? response.headers.get('X-PAYMENT-RESPONSE')
  if (!encoded) throw new Error('paid worker response has no PAYMENT-RESPONSE settlement evidence')
  let settlement: ReturnType<typeof decodePaymentResponseHeader>
  try {
    settlement = decodePaymentResponseHeader(encoded)
  } catch {
    throw new Error('paid worker response contains invalid settlement evidence')
  }
  if (
    settlement.success !== true ||
    settlement.network !== networkFor(chainId) ||
    !/^0x[0-9a-fA-F]{64}$/.test(settlement.transaction) ||
    (settlement.amount !== undefined && settlement.amount !== amountAtomic.toString()) ||
    (settlement.payer !== undefined && (
      !isAddress(settlement.payer) || settlement.payer.toLowerCase() !== payer.toLowerCase()
    ))
  ) {
    throw new Error('paid worker response settlement evidence does not match the payment policy')
  }
  return { transaction: settlement.transaction.toLowerCase() as `0x${string}` }
}

function safeMediaType(value: string | null): string | null {
  if (!value) return null
  const mediaType = value.split(';', 1)[0]!.trim().toLowerCase()
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType) ? mediaType : null
}

export class PeerPaymentClient {
  readonly #identity: AgentIdentity
  readonly #fetcher: FetchLike
  readonly #rpcFetcher: FetchLike
  readonly #rpcUrl: string
  readonly #terminalRpcUrls?: readonly [string, string, string]
  readonly #now: () => number
  readonly #identityPath: string
  readonly #boundIdentityChainId: number
  readonly #timeoutMs: number

  constructor(
    identity: AgentIdentity,
    options: PeerPaymentClientOptions,
  ) {
    const privateKey = fromBase64(identity.privateKey)
    const publicKey = fromBase64(identity.publicKey)
    if (privateKey.byteLength !== 32 || publicKey.byteLength !== 32) {
      throw new Error('peer-payment identity must contain canonical 32-byte Ed25519 keys')
    }
    const derivedPublicKey = deriveEd25519PublicKey(privateKey)
    if (!timingSafeEqual(Buffer.from(publicKey), Buffer.from(derivedPublicKey))) {
      throw new Error('peer-payment identity public key does not match its private key')
    }
    let canonicalWalletPrivateKey: `0x${string}` | undefined
    let derivedWallet: `0x${string}` | undefined
    try {
      canonicalWalletPrivateKey = normalizeWalletPrivateKey(identity.walletPrivateKey)
      derivedWallet = privateKeyToAccount(canonicalWalletPrivateKey).address
    } catch {
      derivedWallet = undefined
    }
    if (
      !canonicalWalletPrivateKey ||
      !derivedWallet ||
      !isAddress(identity.wallet) ||
      derivedWallet !== getAddress(identity.wallet)
    ) {
      throw new Error('identity wallet does not match its private key')
    }
    if (identity.handle !== undefined && !/^[a-z0-9-]{3,32}$/.test(identity.handle)) {
      throw new Error('peer-payment identity has an invalid handle')
    }
    if (
      identity.version !== 1 ||
      !Number.isSafeInteger(identity.chainId) ||
      identity.chainId <= 0 ||
      !Number.isSafeInteger(identity.createdAt) ||
      identity.createdAt < 0
    ) {
      throw new Error('peer-payment identity has invalid metadata')
    }
    const configuredIdentityPath = normalizeIdentityPath(options.identityPath)
    const boundIdentityPath = realpathSync(configuredIdentityPath)
    let persisted: Partial<AgentIdentity>
    try {
      const raw = readFileSync(boundIdentityPath, 'utf8')
      if (Buffer.byteLength(raw, 'utf8') > 64 * 1_024) throw new Error('identity file is too large')
      persisted = JSON.parse(raw) as Partial<AgentIdentity>
    } catch {
      throw new Error('cannot bind the peer-payment client to its identity file')
    }
    if (
      persisted.privateKey !== identity.privateKey ||
      persisted.publicKey !== identity.publicKey ||
      persisted.walletPrivateKey !== identity.walletPrivateKey ||
      persisted.chainId !== identity.chainId ||
      typeof persisted.wallet !== 'string' ||
      persisted.wallet.toLowerCase() !== identity.wallet.toLowerCase()
    ) {
      throw new Error('peer-payment identity does not match the bound identity file')
    }
    const effectiveChainId = options.chainIdOverride ?? identity.chainId
    if (!Number.isSafeInteger(effectiveChainId) || effectiveChainId <= 0) {
      throw new Error('peer-payment chain override must be a positive safe integer')
    }
    this.#identity = {
      ...identity,
      privateKey: toBase64(privateKey),
      publicKey: toBase64(derivedPublicKey),
      walletPrivateKey: canonicalWalletPrivateKey,
      wallet: derivedWallet,
      baseUrl: normalizeBaseUrl(identity.baseUrl),
      chainId: effectiveChainId,
    }
    // Preserve the configured path rather than replacing it with its realpath.
    // The async payment boundary must still observe and reject a symlink swap.
    this.#identityPath = configuredIdentityPath
    this.#boundIdentityChainId = identity.chainId
    this.#fetcher = options.fetch ?? globalThis.fetch
    this.#rpcFetcher = options.rpcFetch ?? globalThis.fetch
    assertNoIdentitySecrets(options.rpcUrl, this.#identity, 'RPC URL')
    this.#rpcUrl = normalizeHttpsUrl(options.rpcUrl, 'RPC URL').href
    if (options.quorumRpcUrls !== undefined) {
      if (
        !Array.isArray(options.quorumRpcUrls) ||
        options.quorumRpcUrls.length !== TERMINAL_RPC_QUORUM_SIZE - 1
      ) {
        throw new Error('terminal clear requires exactly two independent quorum RPC URLs')
      }
      const urls = [this.#rpcUrl, ...options.quorumRpcUrls.map((value) => {
        if (typeof value !== 'string') throw new Error('quorum RPC URL must be a string')
        assertNoIdentitySecrets(value, this.#identity, 'quorum RPC URL')
        return normalizeHttpsUrl(value, 'quorum RPC URL').href
      })] as [string, string, string]
      const origins = new Set(urls.map((value) => new URL(value).origin))
      if (origins.size !== TERMINAL_RPC_QUORUM_SIZE) {
        throw new Error('terminal clear requires three distinct RPC origins')
      }
      this.#terminalRpcUrls = Object.freeze(urls)
    }
    this.#now = options.now ?? Date.now
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_NETWORK_TIMEOUT_MS
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs <= 0 || this.#timeoutMs > 120_000) {
      throw new Error('network timeout must be an integer between 1 and 120000 milliseconds')
    }
  }

  static async fromIdentityFile(
    path: string,
    options: Omit<PeerPaymentClientOptions, 'identityPath'>,
  ): Promise<PeerPaymentClient> {
    const identityPath = normalizeIdentityPath(path)
    const identity = await loadIdentity(identityPath)
    return new PeerPaymentClient(identity, {
      ...options,
      identityPath,
    })
  }

  async pay(
    input: PeerPaymentRequest,
    control: McpPaymentControl,
  ): Promise<PeerPaymentEvidence> {
    let durablePaymentEvidenceMayExist = false
    try {
      const persisted = await loadIdentity(this.#identityPath)
      if (!samePeerPaymentPrincipal(
        persisted,
        this.#identity,
        this.#boundIdentityChainId,
      )) {
        throw new Error('peer-payment identity principal changed; reload before paying')
      }
      const prepared = preparePeerPaymentRequest(input)
      const spendInput = spendInputFromPrepared(prepared)
      claimAuthorizedPaymentControl(
        control,
        'peer_pay',
        spendInput,
        prepared.amountAtomic,
        spendPolicyScope(this.#identity.chainId, this.#identity.wallet),
      )
      return await this.payClaimed(prepared, (value) => {
        durablePaymentEvidenceMayExist = value
      })
    } catch (error) {
      if (error instanceof TerminalPeerPaymentBlocked) throw error
      throw classifiedPeerPaymentError(error, durablePaymentEvidenceMayExist)
    }
  }

  /** @internal Two-phase capability boundary; use clearTerminalPayment(). */
  async stageTerminalPaymentClear(
    input: PeerPaymentRequest,
    control: McpPaymentControl,
  ): Promise<never> {
    const prepared = preparePeerPaymentRequest(input)
    claimAuthorizedPaymentControl(
      control,
      'peer_pay',
      spendInputFromPrepared(prepared),
      prepared.amountAtomic,
      spendPolicyScope(this.#identity.chainId, this.#identity.wallet),
    )
    const spendMetadata = claimedSpendControlMetadata(control)
    try {
      const terminalRpcUrls = this.#terminalRpcUrls
      if (!terminalRpcUrls) {
        throw new Error('terminal clear requires exactly two independent quorum RPC URLs')
      }
      const persisted = await loadIdentity(this.#identityPath)
      if (!samePeerPaymentPrincipal(
        persisted,
        this.#identity,
        this.#boundIdentityChainId,
      )) {
        throw new Error('peer-payment identity principal changed; reload before recovery')
      }
      const asset = expectedUsdc(this.#identity.chainId)
      const target = new URL(prepared.url)
      const key = logicalKey(
        this.#identity,
        target,
        prepared.method,
        prepared.body,
        prepared.contentType,
        prepared.amountAtomic,
        prepared.payTo,
        asset,
      )
      const journalPath = peerPaymentFile(this.#identityPath, this.#identity.publicKey, key)
      const expected = expectedAttemptFromPrepared(this.#identity, prepared, asset)
      await ensurePrivateJournalDirectories(this.#identityPath, this.#identity.publicKey)
      return await withFileLock(journalPath, async () => {
        const current = await loadAttempt(journalPath)
        const archived = await loadArchivedTerminalAttempt(
          this.#identityPath,
          this.#identity.publicKey,
          key,
          current,
        )
        // A completed clear removes the active tombstone but deliberately keeps
        // its immutable terminal archive. The spend guard's released row is
        // only a same-day audit row and may already have been pruned, so an
        // archive-only retry with history "none" is still the exact idempotent
        // clear. In contrast, "uncertain" proves a newer spend generation was
        // reserved; an older archive must never clear that missing generation.
        if (!current && spendMetadata.reservationHistory === 'uncertain') {
          throw new Error(
            'active peer-payment journal is missing for the ambiguous spend generation',
          )
        }
        if (current && archived && (
          current.state !== 'terminal' ||
          peerPaymentContents(current) !== peerPaymentContents(archived)
        )) {
          throw new Error('active peer-payment journal conflicts with its terminal archive')
        }
        const attempt = current ?? archived
        if (!attempt) {
          if (spendMetadata.reservationHistory === 'none') {
            throw new Error(
              'active peer-payment journal is missing for the ambiguous spend generation',
            )
          }
          throw new Error('no retained peer-payment authorization exists for this exact request')
        }
        assertAttemptMatches(attempt, expected)
        if (attempt.state === 'settled') {
          throw new Error('a settled peer-payment authorization cannot be terminal-cleared')
        }
        const authorization = await validatePaymentHeader(
          attempt.headerValue,
          attempt.paymentId,
          target,
          this.#identity.chainId,
          asset,
          prepared.amountAtomic,
          prepared.payTo,
          this.#identity.wallet,
          this.#now(),
          false,
        )
        if (attempt.state === 'terminal' && (
          attempt.authorizationNonce !== authorization.nonce ||
          attempt.validBefore !== authorization.validBefore.toString()
        )) {
          throw new Error('terminal peer-payment journal contradicts its signed authorization')
        }
        const quorum = await proveExpiredUnusedAuthorizationQuorum({
          rpcUrls: terminalRpcUrls,
          chainId: this.#identity.chainId,
          asset,
          authorizer: this.#identity.wallet,
          nonce: authorization.nonce,
          validBefore: authorization.validBefore,
          fetch: this.#rpcFetcher,
          timeoutMs: this.#timeoutMs,
        })
        let terminal = attempt
        if (attempt.state === 'pending') {
          terminal = {
            ...attempt,
            state: 'terminal',
            terminalAt: this.#now(),
            terminalProofVersion: 1,
            authorizationNonce: authorization.nonce,
            validBefore: authorization.validBefore.toString(),
            quorum,
          }
          await atomicWritePrivate(journalPath, peerPaymentContents(terminal))
        }
        if (terminal.state !== 'terminal') {
          throw new Error('peer-payment authorization is not terminal')
        }
        await stageTerminalPeerPaymentArchive(
          this.#identityPath,
          this.#identity.publicKey,
          key,
          terminal,
        )
        throw terminalPaymentCleared({
          spendControl: control,
          spendReservationId: spendMetadata.reservationId,
          spendAmountAtomic: prepared.amountAtomic.toString(),
          publicKey: this.#identity.publicKey,
          attemptKey: key,
          paymentId: terminal.paymentId,
          bodyHash: terminal.bodyHash,
          authorizationHash: peerAuthorizationHash(terminal, authorization.nonce),
        })
      })
    } catch (error) {
      if (error instanceof TerminalPaymentCleared) throw error
      // The exact retained authorization remains ambiguous unless and until
      // the branded terminal-clear capability crosses the durable release.
      throw classifiedPeerPaymentError(error, true)
    }
  }

  /** @internal Two-phase capability boundary; use clearTerminalPayment(). */
  async finalizeTerminalPaymentClear(
    input: PeerPaymentRequest,
    completion: TerminalPaymentCleared,
  ): Promise<void> {
    const prepared = preparePeerPaymentRequest(input)
    const persisted = await loadIdentity(this.#identityPath)
    if (!samePeerPaymentPrincipal(
      persisted,
      this.#identity,
      this.#boundIdentityChainId,
    )) {
      throw new Error('peer-payment identity principal changed; reload before recovery')
    }
    const asset = expectedUsdc(this.#identity.chainId)
    const target = new URL(prepared.url)
    const key = logicalKey(
      this.#identity,
      target,
      prepared.method,
      prepared.body,
      prepared.contentType,
      prepared.amountAtomic,
      prepared.payTo,
      asset,
    )
    const journalPath = peerPaymentFile(this.#identityPath, this.#identity.publicKey, key)
    const expected = expectedAttemptFromPrepared(this.#identity, prepared, asset)
    await withFileLock(journalPath, async () => {
      const current = await loadAttempt(journalPath)
      const archived = await loadArchivedTerminalAttempt(
        this.#identityPath,
        this.#identity.publicKey,
        key,
        current,
      )
      if (!archived) throw new Error('terminal peer-payment archive is missing')
      assertAttemptMatches(archived, expected)
      if (current && (
        current.state !== 'terminal' ||
        peerPaymentContents(current) !== peerPaymentContents(archived)
      )) {
        throw new Error('active terminal peer-payment journal conflicts with its archive')
      }
      const authorization = await validatePaymentHeader(
        archived.headerValue,
        archived.paymentId,
        target,
        this.#identity.chainId,
        asset,
        prepared.amountAtomic,
        prepared.payTo,
        this.#identity.wallet,
        this.#now(),
        false,
      )
      if (
        archived.authorizationNonce !== authorization.nonce ||
        archived.validBefore !== authorization.validBefore.toString()
      ) {
        throw new Error('terminal peer-payment archive contradicts its signed authorization')
      }
      const binding = consumeTerminalPaymentClear(completion, {
        publicKey: this.#identity.publicKey,
        bodyHash: bodyHash(prepared.body),
        attemptKeys: [key],
        authorizationHashes: [peerAuthorizationHash(archived, authorization.nonce)],
      })
      if (binding.paymentId !== archived.paymentId) {
        throw new Error('terminal-payment completion belongs to another authorization')
      }
      if (current) await removeAndSync(journalPath)
    })
  }

  /**
   * Clear one expired, unanimously unused peer authorization. The active
   * tombstone is removed only after the exact shared spend reservation is
   * durably released and an immutable private archive exists.
   */
  async clearTerminalPayment(
    input: PeerPaymentRequest,
    guard: McpSpendGuard,
  ): Promise<PeerPaymentTerminalClearResult> {
    if (!(guard instanceof McpSpendGuard)) {
      throw new Error('terminal payment clear requires the official spend-policy guard')
    }
    const prepared = preparePeerPaymentRequest(input)
    try {
      await guard.execute(
        'peer_pay',
        spendInputFromPrepared(prepared),
        prepared.amountAtomic,
        (control) => this.stageTerminalPaymentClear(prepared, control),
      )
      throw new Error('terminal payment clear returned unexpectedly')
    } catch (error) {
      if (!(error instanceof TerminalPaymentCleared)) throw error
      await this.finalizeTerminalPaymentClear(prepared, error)
      return error.result
    }
  }

  private async payClaimed(
    input: PreparedPeerPaymentRequest,
    setDurablePaymentEvidenceMayExist: (value: boolean) => void,
  ): Promise<PeerPaymentEvidence> {
    const target = new URL(input.url)
    assertNoIdentitySecrets(input.url, this.#identity, 'peer request URL')
    assertNoIdentitySecrets(target.href, this.#identity, 'peer request URL')
    const { method, body, amountAtomic, payTo, contentType } = input
    assertNoIdentitySecrets(body, this.#identity, 'peer request body')
    const asset = expectedUsdc(this.#identity.chainId)
    const network = networkFor(this.#identity.chainId)
    const domain = usdcEip712Domain(this.#identity.chainId)
    if (contentType) assertNoIdentitySecrets(contentType, this.#identity, 'peer content type')
    const key = logicalKey(
      this.#identity,
      target,
      method,
      body,
      contentType,
      amountAtomic,
      payTo,
      asset,
    )
    const journalPath = peerPaymentFile(this.#identityPath, this.#identity.publicKey, key)
    // Once the durable path is known, any failure to inspect it is ambiguous: a
    // prior process may have persisted and sent an authorization. Only a clean
    // missing-entry read proves that no recoverable authorization exists.
    setDurablePaymentEvidenceMayExist(true)
    await ensurePrivateJournalDirectories(this.#identityPath, this.#identity.publicKey)

    return withFileLock(journalPath, async () => {
      const expected = expectedAttemptFromPrepared(this.#identity, input, asset)
      const existing = await loadAttempt(journalPath)
      if (existing) {
        assertAttemptMatches(existing, expected)
        if (existing.state === 'settled') return existing.evidence
        if (existing.state === 'terminal') {
          throw new TerminalPeerPaymentBlocked()
        }
        await validatePaymentHeader(
          existing.headerValue,
          existing.paymentId,
          target,
          this.#identity.chainId,
          asset,
          amountAtomic,
          payTo,
          this.#identity.wallet,
          this.#now(),
          false,
        )
        const response = await this.sendExact(target, method, body, contentType, existing)
        return this.settle(journalPath, existing, target, response)
      }
      setDurablePaymentEvidenceMayExist(false)

      const paymentId = generatePaymentId('1f4bc_peer_')
      let pending: PendingPeerPaymentAttempt | undefined
      const wallet = privateKeyToAccount(this.#identity.walletPrivateKey)
      const client = new x402Client()
        .register(network, new ExactEvmScheme(wallet))
        .registerPolicy((_version, requirements) => requirements.filter((entry) =>
          entry.scheme === 'exact' &&
          entry.network === network &&
          entry.asset.toLowerCase() === asset.toLowerCase() &&
          entry.amount === amountAtomic.toString() &&
          isAddress(entry.payTo) &&
          entry.payTo.toLowerCase() === payTo.toLowerCase() &&
          Number.isSafeInteger(entry.maxTimeoutSeconds) &&
          entry.maxTimeoutSeconds > 0 &&
          entry.maxTimeoutSeconds <= 300 &&
          isRecord(entry.extra) &&
          entry.extra.name === domain.name &&
          entry.extra.version === domain.version &&
          (entry.extra.assetTransferMethod === undefined ||
            entry.extra.assetTransferMethod === 'eip3009'),
        ))
        .registerExtension({
          key: PAYMENT_IDENTIFIER,
          enrichPaymentPayload: async (payload) => {
            const extensions = payload.extensions ? structuredClone(payload.extensions) : {}
            appendPaymentIdentifierToExtensions(extensions, paymentId)
            return { ...payload, extensions }
          },
        })

      const guardedFetch: FetchLike = async (requestInput, requestInit) => {
        let request = new Request(requestInput, { ...requestInit, redirect: 'manual' })
        if (new URL(request.url).href !== target.href) {
          throw new Error('x402 client attempted a different worker endpoint')
        }
        const paymentName = request.headers.has('PAYMENT-SIGNATURE')
          ? 'payment-signature'
          : request.headers.has('X-PAYMENT')
            ? 'x-payment'
            : undefined
        if (paymentName) {
          const headerValue = request.headers.get(paymentName)!
          await validatePaymentHeader(
            headerValue,
            paymentId,
            target,
            this.#identity.chainId,
            asset,
            amountAtomic,
            payTo,
            this.#identity.wallet,
            this.#now(),
            true,
          )
          const claimed = await persistNewPending(
            this.#identityPath,
            this.#identity.publicKey,
            journalPath,
            {
              version: 1,
              state: 'pending',
              paymentId,
              ...expected,
              headerName: paymentName,
              headerValue,
              createdAt: this.#now(),
            },
          )
          assertAttemptMatches(claimed, expected)
          setDurablePaymentEvidenceMayExist(true)
          if (claimed.state === 'settled') {
            throw new Error('peer payment settled concurrently; repeat the command to read its evidence')
          }
          if (claimed.state === 'terminal') {
            throw new TerminalPeerPaymentBlocked()
          }
          pending = claimed
          request = new Request(request, { redirect: 'manual' })
          request.headers.delete('PAYMENT-SIGNATURE')
          request.headers.delete('X-PAYMENT')
          request.headers.set(claimed.headerName, claimed.headerValue)
        }
        const response = await this.#fetcher(request as unknown as RequestInfo, {
          signal: AbortSignal.any([request.signal, AbortSignal.timeout(this.#timeoutMs)]),
        })
        if (response.status >= 300 && response.status < 400) {
          await cancelResponseBody(response)
          throw new Error('worker endpoint returned a redirect; redirects are never followed')
        }
        if (response.status === 402 && !paymentName) {
          try {
            validateChallenge(response, target, this.#identity.chainId, asset, amountAtomic, payTo)
          } catch (error) {
            await cancelResponseBody(response)
            throw error
          }
          return bodylessPaymentChallenge(response)
        }
        return response
      }
      const paidFetch = wrapFetchWithPayment(guardedFetch, client)
      const headers = new Headers({ Accept: '*/*' })
      if (contentType) headers.set('Content-Type', contentType)
      const response = await paidFetch(target, {
        method,
        headers,
        redirect: 'manual',
        ...(body.byteLength > 0 ? { body: body as BodyInit } : {}),
      })
      if (!pending) {
        await cancelResponseBody(response)
        throw new Error('worker endpoint did not complete an x402 payment')
      }
      return this.settle(journalPath, pending, target, response)
    })
  }

  private async sendExact(
    target: URL,
    method: 'GET' | 'POST',
    body: Uint8Array,
    contentType: string | undefined,
    pending: PendingPeerPaymentAttempt,
  ): Promise<Response> {
    const headers = new Headers({ Accept: '*/*', [pending.headerName]: pending.headerValue })
    if (contentType) headers.set('Content-Type', contentType)
    const request = new Request(target, {
      method,
      headers,
      redirect: 'manual',
      ...(body.byteLength > 0 ? { body: body as BodyInit } : {}),
    })
    const response = await this.#fetcher(request as unknown as RequestInfo, {
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(this.#timeoutMs)]),
    })
    if (response.status >= 300 && response.status < 400) {
      await cancelResponseBody(response)
      throw new Error('worker endpoint returned a redirect; redirects are never followed')
    }
    return response
  }

  private async settle(
    journalPath: string,
    pending: PendingPeerPaymentAttempt,
    target: URL,
    response: Response,
  ): Promise<PeerPaymentEvidence> {
    try {
      if (!response.ok) {
        throw new Error(
          `paid worker request returned HTTP ${response.status}; authorization retained for exact recovery`,
        )
      }
      const settlement = decodeSettlement(
        response,
        this.#identity.chainId,
        BigInt(pending.amountAtomic),
        this.#identity.wallet,
      )
      const authorization = await validatePaymentHeader(
        pending.headerValue,
        pending.paymentId,
        target,
        this.#identity.chainId,
        pending.asset,
        BigInt(pending.amountAtomic),
        pending.payTo,
        pending.wallet,
        this.#now(),
        false,
      )
      const receipt = await inspectUsdcReceipt({
        rpcUrl: this.#rpcUrl,
        chainId: this.#identity.chainId,
        txHash: settlement.transaction,
        fetch: this.#rpcFetcher,
        timeoutMs: this.#timeoutMs,
      })
      const transfer = receipt.transfers.find((entry) =>
        entry.from.toLowerCase() === this.#identity.wallet.toLowerCase() &&
        entry.to.toLowerCase() === pending.payTo.toLowerCase() &&
        entry.amountAtomic === pending.amountAtomic,
      )
      if (!transfer) {
        throw new Error('finalized transaction does not contain the exact expected USDC transfer')
      }
      const used = receipt.authorizations.some((entry) =>
        entry.authorizer.toLowerCase() === pending.wallet.toLowerCase() &&
        entry.nonce.toLowerCase() === authorization.nonce.toLowerCase())
      if (!used) {
        throw new Error(
          'finalized transaction does not consume the exact expected EIP-3009 authorization',
        )
      }
      const digest = await responseDigest(response)
      const evidence: PeerPaymentEvidence = {
        state: 'settled',
        paymentId: pending.paymentId,
        url: displayUrl(target),
        queryPresent: target.search.length > 0,
        method: pending.method,
        chainId: pending.chainId,
        network: networkFor(pending.chainId),
        asset: pending.asset,
        amountAtomic: pending.amountAtomic,
        payTo: pending.payTo,
        payer: pending.wallet,
        transaction: settlement.transaction,
        logIndex: transfer.logIndex,
        responseStatus: response.status,
        responseContentType: safeMediaType(response.headers.get('content-type')),
        responseBytes: digest.bytes,
        responseSha256: digest.sha256,
      }
      const settled: SettledPeerPaymentAttempt = {
        ...pending,
        state: 'settled',
        settledAt: this.#now(),
        evidence,
      }
      const settledContents = `${JSON.stringify(settled)}\n`
      if (Buffer.byteLength(settledContents, 'utf8') > MAX_PEER_PAYMENT_JOURNAL_BYTES) {
        throw new Error('settled peer-payment journal entry exceeds its byte-size safety limit')
      }
      await atomicWritePrivate(journalPath, settledContents)
      return evidence
    } catch (error) {
      await cancelResponseBody(response)
      throw error
    }
  }
}

type RpcOptions = {
  rpcUrl: string
  chainId: number
  fetch?: FetchLike
  timeoutMs?: number
}

async function boundedResponseText(
  response: Response,
  limit: number,
  label: string,
): Promise<string> {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let bytes = 0
  let text = ''
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      bytes += chunk.value.byteLength
      if (bytes > limit) {
        await reader.cancel().catch(() => undefined)
        throw new Error(`${label} exceeds its response-size safety limit`)
      }
      text += decoder.decode(chunk.value, { stream: true })
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  return text + decoder.decode()
}

async function rpcCall(
  options: RpcOptions,
  method: string,
  params: unknown[],
): Promise<unknown> {
  const target = normalizeHttpsUrl(options.rpcUrl, 'RPC URL')
  const timeoutMs = options.timeoutMs ?? DEFAULT_NETWORK_TIMEOUT_MS
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000) {
    throw new Error('RPC timeout must be an integer between 1 and 120000 milliseconds')
  }
  const response = await (options.fetch ?? globalThis.fetch)(target, {
    method: 'POST',
    redirect: 'manual',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (response.status >= 300 && response.status < 400) {
    await cancelResponseBody(response)
    throw new Error('RPC returned a redirect; redirects are never followed')
  }
  if (!response.ok) {
    await cancelResponseBody(response)
    throw new Error(`RPC returned HTTP ${response.status}`)
  }
  const rawPayload = await boundedResponseText(response, MAX_RPC_RESPONSE_BYTES, 'RPC response')
  let payload: unknown
  try {
    payload = JSON.parse(rawPayload)
  } catch {
    throw new Error('RPC returned invalid JSON')
  }
  if (!isRecord(payload) || payload.jsonrpc !== '2.0' || payload.id !== 1) {
    throw new Error('RPC returned an invalid response envelope')
  }
  if (payload.error !== undefined) {
    throw new Error('RPC returned an error response')
  }
  return payload.result
}

function parseHexInteger(value: unknown, label: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) {
    throw new Error(`${label} is not a canonical hex integer`)
  }
  return BigInt(value)
}

function parseHexDataInteger(value: unknown, label: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value)) {
    throw new Error(`${label} is not hex data`)
  }
  return BigInt(value)
}

function assertRpcChain(value: unknown, expectedChainId: number): void {
  const actual = parseHexInteger(value, 'RPC chain id')
  if (actual !== BigInt(expectedChainId)) {
    throw new Error(`RPC chain id does not match configured chain ${expectedChainId}`)
  }
}

type AuthorizationQuorumOptions = {
  rpcUrls: readonly [string, string, string]
  chainId: number
  asset: `0x${string}`
  authorizer: `0x${string}`
  nonce: `0x${string}`
  validBefore: bigint
  fetch: FetchLike
  timeoutMs: number
}

async function proveExpiredUnusedAuthorizationAtRpc(
  options: Omit<AuthorizationQuorumOptions, 'rpcUrls'> & { rpcUrl: string },
): Promise<PeerAuthorizationExpiryProof> {
  const chain = await rpcCall(options, 'eth_chainId', [])
  assertRpcChain(chain, options.chainId)
  const finalized = await rpcCall(options, 'eth_getBlockByNumber', ['finalized', false])
  if (!isRecord(finalized)) throw new Error('RPC finalized block was not found')
  const blockNumber = parseHexInteger(finalized.number, 'finalized block number')
  const blockTimestamp = parseHexInteger(finalized.timestamp, 'finalized block timestamp')
  if (
    typeof finalized.hash !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/.test(finalized.hash)
  ) {
    throw new Error('RPC finalized block has no canonical hash')
  }
  if (blockTimestamp < options.validBefore) {
    throw new Error('payment authorization has not expired at every finalized RPC head')
  }
  const data = encodeFunctionData({
    abi: AUTHORIZATION_STATE_ABI,
    functionName: 'authorizationState',
    args: [options.authorizer, options.nonce],
  })
  const state = await rpcCall(
    options,
    'eth_call',
    [{ to: options.asset, data }, {
      blockHash: finalized.hash.toLowerCase(),
      requireCanonical: true,
    }],
  )
  if (typeof state !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(state)) {
    throw new Error('RPC returned a non-canonical USDC authorization state')
  }
  if (BigInt(state) !== 0n) {
    throw new Error('payment authorization is already used and cannot be terminal-cleared')
  }
  return {
    rpcOriginHash: sha256Hex(new URL(options.rpcUrl).origin),
    finalizedBlockNumber: blockNumber.toString(),
    finalizedBlockHash: finalized.hash.toLowerCase() as `0x${string}`,
    finalizedBlockTimestamp: blockTimestamp.toString(),
    authorizationState: false,
  }
}

async function proveExpiredUnusedAuthorizationQuorum(
  options: AuthorizationQuorumOptions,
): Promise<TerminalPeerPaymentAttempt['quorum']> {
  const origins = options.rpcUrls.map((value) => normalizeHttpsUrl(value, 'RPC URL').origin)
  if (new Set(origins).size !== TERMINAL_RPC_QUORUM_SIZE) {
    throw new Error('terminal clear requires three distinct RPC origins')
  }
  const proofs = await Promise.all(options.rpcUrls.map((rpcUrl) =>
    proveExpiredUnusedAuthorizationAtRpc({
      ...options,
      rpcUrl,
    })))
  if (proofs.length !== TERMINAL_RPC_QUORUM_SIZE) {
    throw new Error('terminal clear did not obtain the required RPC quorum')
  }
  return proofs as TerminalPeerPaymentAttempt['quorum']
}

export async function readUsdcBalance(
  options: RpcOptions & { wallet: string },
): Promise<UsdcBalanceEvidence> {
  const wallet = canonicalAddress(options.wallet, 'wallet')
  const asset = expectedUsdc(options.chainId)
  const data = `0x70a08231${wallet.slice(2).toLowerCase().padStart(64, '0')}`
  // Chain identity is a fail-closed gate: never query a token contract on an
  // RPC that has not first proven it is the configured Base network.
  const chain = await rpcCall(options, 'eth_chainId', [])
  assertRpcChain(chain, options.chainId)
  const result = await rpcCall(options, 'eth_call', [{ to: asset, data }, 'finalized'])
  const balance = parseHexDataInteger(result, 'USDC balance')
  return {
    chainId: options.chainId,
    network: networkFor(options.chainId),
    asset,
    wallet,
    balanceAtomic: balance.toString(),
    blockTag: 'finalized',
  }
}

function topicAddress(topic: unknown, label: string): `0x${string}` {
  if (
    typeof topic !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/.test(topic) ||
    !/^0{24}$/i.test(topic.slice(2, 26))
  ) {
    throw new Error(`${label} is not a canonical indexed address`)
  }
  return getAddress(`0x${topic.slice(-40)}`)
}

export async function inspectUsdcReceipt(
  options: RpcOptions & { txHash: string },
): Promise<UsdcReceiptEvidence> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(options.txHash)) {
    throw new Error('transaction hash must be 32-byte hex')
  }
  const transaction = options.txHash.toLowerCase() as `0x${string}`
  const asset = expectedUsdc(options.chainId)
  // Do not accept receipt/finality data from an endpoint until its chain id is
  // verified. The subsequent independent reads can safely run in parallel.
  const chain = await rpcCall(options, 'eth_chainId', [])
  assertRpcChain(chain, options.chainId)
  const [receiptValue, finalizedValue] = await Promise.all([
    rpcCall(options, 'eth_getTransactionReceipt', [transaction]),
    rpcCall(options, 'eth_getBlockByNumber', ['finalized', false]),
  ])
  if (!isRecord(receiptValue)) throw new Error('transaction receipt was not found')
  if (receiptValue.status !== '0x1') throw new Error('transaction did not succeed')
  if (
    typeof receiptValue.transactionHash !== 'string' ||
    receiptValue.transactionHash.toLowerCase() !== transaction
  ) {
    throw new Error('transaction receipt hash does not match')
  }
  const blockNumber = parseHexInteger(receiptValue.blockNumber, 'receipt block number')
  if (typeof receiptValue.blockHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(receiptValue.blockHash)) {
    throw new Error('transaction receipt has no canonical block hash')
  }
  const receiptBlockHash = receiptValue.blockHash.toLowerCase()
  if (!isRecord(finalizedValue)) throw new Error('finalized block was not found')
  const finalizedBlockNumber = parseHexInteger(finalizedValue.number, 'finalized block number')
  if (blockNumber > finalizedBlockNumber) throw new Error('transaction receipt is not finalized')
  const receiptBlockValue = await rpcCall(
    options,
    'eth_getBlockByNumber',
    [receiptValue.blockNumber, false],
  )
  if (!isRecord(receiptBlockValue)) throw new Error('receipt block was not found')
  if (parseHexInteger(receiptBlockValue.number, 'receipt block lookup number') !== blockNumber) {
    throw new Error('receipt block lookup returned another height')
  }
  if (
    typeof receiptBlockValue.hash !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/.test(receiptBlockValue.hash) ||
    receiptBlockValue.hash.toLowerCase() !== receiptBlockHash
  ) {
    throw new Error('transaction receipt does not belong to the canonical block')
  }
  const blockTimestamp = parseHexInteger(
    receiptBlockValue.timestamp,
    'receipt block timestamp',
  )
  if (!Array.isArray(receiptValue.logs)) throw new Error('transaction receipt has no logs array')

  const transfers: UsdcTransferEvidence[] = []
  const authorizations: UsdcReceiptEvidence['authorizations'] = []
  for (const value of receiptValue.logs) {
    if (!isRecord(value) || typeof value.address !== 'string') continue
    if (value.address.toLowerCase() !== asset.toLowerCase()) continue
    if (value.removed === true) throw new Error('USDC receipt contains a removed log')
    if (
      value.transactionHash !== undefined &&
      (typeof value.transactionHash !== 'string' || value.transactionHash.toLowerCase() !== transaction)
    ) {
      throw new Error('USDC log transaction hash does not match its receipt')
    }
    if (
      value.blockHash !== undefined &&
      (typeof value.blockHash !== 'string' || value.blockHash.toLowerCase() !== receiptBlockHash)
    ) {
      throw new Error('USDC log block hash does not match its receipt')
    }
    if (
      value.blockNumber !== undefined &&
      parseHexInteger(value.blockNumber, 'USDC log block number') !== blockNumber
    ) {
      throw new Error('USDC log block number does not match its receipt')
    }
    if (!Array.isArray(value.topics) || typeof value.topics[0] !== 'string') continue
    const topic = value.topics[0].toLowerCase()
    if (topic === AUTHORIZATION_USED_TOPIC) {
      if (
        value.topics.length !== 3 ||
        typeof value.topics[2] !== 'string' ||
        !/^0x[0-9a-fA-F]{64}$/.test(value.topics[2]) ||
        value.data !== '0x'
      ) {
        throw new Error('USDC AuthorizationUsed log is malformed')
      }
      const logIndex = parseHexInteger(value.logIndex, 'USDC AuthorizationUsed logIndex')
      if (logIndex > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('USDC AuthorizationUsed logIndex is too large')
      }
      authorizations.push({
        logIndex: Number(logIndex),
        authorizer: topicAddress(value.topics[1], 'USDC AuthorizationUsed authorizer'),
        nonce: value.topics[2].toLowerCase() as `0x${string}`,
      })
      continue
    }
    if (topic !== TRANSFER_TOPIC) continue
    if (value.topics.length !== 3) throw new Error('USDC Transfer log has invalid topics')
    if (typeof value.data !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value.data)) {
      throw new Error('USDC Transfer log has invalid amount data')
    }
    const logIndex = parseHexInteger(value.logIndex, 'USDC Transfer logIndex')
    if (logIndex > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('USDC Transfer logIndex is too large')
    transfers.push({
      logIndex: Number(logIndex),
      from: topicAddress(value.topics[1], 'USDC Transfer from'),
      to: topicAddress(value.topics[2], 'USDC Transfer to'),
      amountAtomic: BigInt(value.data).toString(),
    })
  }
  transfers.sort((left, right) => left.logIndex - right.logIndex)
  authorizations.sort((left, right) => left.logIndex - right.logIndex)
  return {
    chainId: options.chainId,
    network: networkFor(options.chainId),
    asset,
    transaction,
    blockNumber: blockNumber.toString(),
    blockTimestamp: blockTimestamp.toString(),
    finalizedBlockNumber: finalizedBlockNumber.toString(),
    transfers,
    authorizations,
  }
}
