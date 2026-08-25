import { createHash, randomUUID, timingSafeEqual } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { chmod, link, mkdir, open, readdir, unlink } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import * as ed from '@noble/ed25519'
import {
  decodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
} from '@x402/core/http'
import { x402Client, wrapFetchWithPayment } from '@x402/fetch'
import { ExactEvmScheme, authorizationTypes } from '@x402/evm'
import {
  PAYMENT_IDENTIFIER,
  appendPaymentIdentifierToExtensions,
  generatePaymentId,
} from '@x402/extensions/payment-identifier'
import { getAddress, isAddress, recoverTypedDataAddress, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import {
  fromBase64,
  deriveEd25519PublicKey,
  identityPath as normalizeIdentityPath,
  loadIdentity,
  normalizeBaseUrl,
  normalizeWalletPrivateKey,
  resolveIdentityPath as discoverIdentityPath,
  saveIdentity,
  toBase64,
  type AgentIdentity,
} from './keys.js'
import { atomicWritePrivate, readPrivateFile, withFileLock } from './local-journal.js'
import {
  claimAuthorizedPaymentControl,
  McpSpendGuard,
  type SpendControl,
} from './mcp-payments.js'
import { assertNoIdentitySecrets } from './secret-safety.js'
import { spendPolicyScope } from './spend-scope.js'
import { usdcEip712Domain, type UsdcEip712Domain } from './usdc-domain.js'
import {
  consumeTerminalPaymentClear,
  terminalPaymentCleared,
  TerminalPaymentCleared,
} from './terminal-clear.js'

export type FetchLike = typeof globalThis.fetch

export type AgentApiOptions = {
  fetch?: FetchLike
  identityPath?: string
  baseUrl?: string
  chainId?: number
  now?: () => number
}

export type PaymentRequestOptions = {
  /** Active, process-local capability issued by a SpendGuard reservation. */
  control: SpendControl
  /** Refuse to pay if a fresh bid quote differs from the amount already reserved locally. */
  expectedAmountAtomic?: bigint
  /** Operator-held secret for the explicit Base Sepolia settle-crash launch gate. */
  stagingCrashToken?: string
}

export type RegisterResult = { handle: string }

export type RegisterOptions = {
  /** Exact Terms version the human operator explicitly accepted for this registration. */
  acceptedTermsVersion: string
}

export type RegistrationTermsProof = {
  version: string
  sha256: string
  acceptableUseVersion: string
  privacyVersion: string
  acceptanceSource: 'cli'
  acceptedAt: number
  signature: string
}

export type TermsAcceptanceSource = 'browser' | 'cli' | 'api'

export type CurrentTermsDescriptor = {
  version: string
  sha256: string
  url: string
  acceptableUseVersion: string
  acceptableUseUrl: string
  privacyVersion: string
  privacyUrl: string
  signatureVersion: string
  statement: string
}

export type TermsAcceptanceEvidence = {
  acceptedAt: number
  recordedAt: number
  acceptanceSource: TermsAcceptanceSource
  acceptedPubkey: string
  acceptedWallet: string
  signatureOrigin: string
  signatureChainId: number
  signatureVersion: string
}

export type TermsStatusResult = {
  accepted: boolean
  current: CurrentTermsDescriptor
  acceptance: TermsAcceptanceEvidence | null
}

export type TermsAcceptResult = TermsStatusResult & {
  accepted: true
  created: boolean
  acceptance: TermsAcceptanceEvidence
}

export type PublicAgentIdentity = Omit<AgentIdentity, 'privateKey' | 'walletPrivateKey'>

export type AttestationSignature = {
  proofId: number
  jobId: string
  handle: string
  role: 'poster' | 'worker'
  signature: string
  message: string
}

type JsonRecord = Record<string, unknown>

type PaymentAttemptBase = {
  paymentId: string
  publicKey: string
  handle: string
  baseUrl: string
  chainId: number
  wallet: string
  pathWithQuery: string
  bodyHash: string
  expectedAmountAtomic: string
  headerName: 'payment-signature' | 'x-payment'
  headerValue: string
  createdAt: number
  refreshCount: number
}

type LegacyPendingPaymentAttempt = Omit<
  PaymentAttemptBase,
  'publicKey' | 'handle' | 'refreshCount'
> & { version: 1; state?: never }

type PendingPaymentAttempt =
  | LegacyPendingPaymentAttempt
  | (PaymentAttemptBase & { version: 2; state: 'pending' })

type RefreshingPaymentAttempt = PaymentAttemptBase & {
  version: 2
  state: 'refreshing'
}

type SettledPaymentAttempt = PaymentAttemptBase & {
  version: 2
  state: 'settled'
  result: JsonRecord
  settledAt: number
}

type TerminalPaymentAttempt = PaymentAttemptBase & {
  version: 2
  state: 'terminal'
  terminalAt: number
  terminalProofVersion: 1
}

type PaymentAttempt =
  | PendingPaymentAttempt
  | RefreshingPaymentAttempt
  | SettledPaymentAttempt
  | TerminalPaymentAttempt

export type JobPaymentRecoveryResult = {
  operation: 'POST /jobs'
  paymentId: string
  bodyHash: string
  state: 'pending' | 'settled' | 'committed' | 'terminal'
  result: { id: string } | null
  cleared: boolean
  archived?: boolean
}

export type TerminalPostClearResult = Readonly<{
  state: 'terminal'
  cleared: true
  archived: true
}>

export const POST_FEE_ATOMIC = 10_000n
export const BID_FEE_ATOMIC = 10_000n
export const STAGING_CRASH_HEADER = 'X-1F4BC-Staging-Crash'
export const TERMS_ACCEPTANCE_SIGNATURE_VERSION = '1f4bc-terms/1'
export const CURRENT_TERMS_VERSION = '2026-08-25-r2'
export const CURRENT_TERMS_SHA256 =
  'cc6b85e1e686d6b19ef30e87488511d66aeedbc99d9e76ea36b36f7ee8823ed9'
export const CURRENT_TERMS_URL = 'https://1f4bc.ai/terms/2026-08-25-r2'
export const CURRENT_ACCEPTABLE_USE_VERSION = '2026-08-25'
export const CURRENT_ACCEPTABLE_USE_SHA256 =
  '6b5f50ad76df7f773635731ec33c4f77598e03a02ddc6d0b8ac06d627abff0cd'
export const CURRENT_ACCEPTABLE_USE_URL =
  'https://1f4bc.ai/acceptable-use/2026-08-25'
export const CURRENT_PRIVACY_VERSION = '2026-08-25-r2'
export const CURRENT_PRIVACY_SHA256 =
  '561f162c21e445f41dd8e93908ecd2174432909a8d572bcf755a870da245dca1'
export const CURRENT_PRIVACY_URL = 'https://1f4bc.ai/privacy/2026-08-25-r2'
export const TERMS_ACCEPTANCE_STATEMENT =
  'I am authorized to bind the operator, agree to the Terms and Acceptable Use Policy, and acknowledge the Privacy Notice.'
const MAX_PAYMENT_JOURNAL_BYTES = 64 * 1_024
const MAX_MARKETPLACE_RESPONSE_BYTES = 1_024 * 1_024
const MARKETPLACE_REQUEST_TIMEOUT_MS = 30_000
export const MAX_PAYMENT_ATTEMPT_ENTRIES = 4_096
const SETTLE_CRASH_STAGING_HOST = '1f4bc-staging.1f4bc.workers.dev'
const USDC_BY_CHAIN_ID: Readonly<Record<number, `0x${string}`>> = Object.freeze({
  8453: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  84532: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
})
export const MARKETPLACE_PAY_TO_BY_CHAIN_ID: Readonly<Record<number, `0x${string}`>> = Object.freeze({
  8453: '0x46088815b57Dd27FC63b32fce14ee6fFD4A6f636',
  84532: '0x46088815b57Dd27FC63b32fce14ee6fFD4A6f636',
})
const PAID_MARKETPLACE_ORIGIN_BY_CHAIN_ID: Readonly<Record<number, string>> = Object.freeze({
  8453: 'https://1f4bc.ai',
  84532: `https://${SETTLE_CRASH_STAGING_HOST}`,
})
function stagingCrashTokenForRequest(
  identity: AgentIdentity,
  pathWithQuery: string,
  token: string | undefined,
): string | undefined {
  if (token === undefined) return undefined
  const url = new URL(identity.baseUrl)
  if (
    identity.chainId !== 84532 ||
    pathWithQuery !== '/jobs' ||
    url.protocol !== 'https:' ||
    url.port !== '' ||
    url.hostname.toLowerCase() !== SETTLE_CRASH_STAGING_HOST
  ) {
    throw new Error(
      'the settle-crash gate is allowed only for POST /jobs on Base Sepolia HTTPS staging',
    )
  }
  if (token.length < 32 || token.length > 256 || !/^[\x21-\x7e]+$/.test(token)) {
    throw new Error('F4BC_STAGING_CRASH_TOKEN must contain 32-256 printable non-space characters')
  }
  assertNoIdentitySecrets(token, identity, 'staging crash token')
  return token
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requestBody(body: unknown): string | undefined {
  return body === undefined ? undefined : JSON.stringify(body)
}

function expectedUsdc(chainId: number): `0x${string}` {
  const asset = USDC_BY_CHAIN_ID[chainId]
  if (!asset) throw new Error(`paid requests are not configured for chain ${chainId}`)
  return asset
}

function expectedMarketplacePayTo(chainId: number): `0x${string}` {
  const payTo = MARKETPLACE_PAY_TO_BY_CHAIN_ID[chainId]
  if (!payTo) throw new Error(`marketplace payments are not configured for chain ${chainId}`)
  return payTo
}

function assertOfficialPaidMarketplace(target: URL, chainId: number): void {
  const expected = PAID_MARKETPLACE_ORIGIN_BY_CHAIN_ID[chainId]
  if (!expected || target.origin !== expected) {
    throw Object.assign(
      new Error(`paid marketplace calls are restricted to ${expected ?? 'a configured official origin'}`),
      { paymentMayHaveOccurred: false as const },
    )
  }
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

type ProtocolScalar = string | number

function protocolMessage(namespace: string, fields: readonly ProtocolScalar[]): string {
  return [namespace, ...fields.map(String)].join('\n')
}

function jobPaymentNonce(paymentId: string, bodyHash: string): Hex {
  if (!/^1f4bc_[A-Za-z0-9_-]{16,122}$/.test(paymentId)) {
    throw new Error('job payment identifier is invalid')
  }
  if (!/^[0-9a-f]{64}$/.test(bodyHash)) throw new Error('job payment body hash is invalid')
  return `0x${sha256Hex(`1f4bc:post-job:v1\n${paymentId}\n${bodyHash}`)}`
}

function jobPaymentRecoveryMessage(
  origin: string,
  chainId: string | number,
  paymentId: string,
  bodyHash: string,
  payer: string,
  nonce: string,
  validBefore: number,
): string {
  return protocolMessage('1f4bc-payment-recovery/1', [
    origin,
    chainId,
    'POST /jobs',
    paymentId,
    bodyHash,
    payer.toLowerCase(),
    nonce.toLowerCase(),
    validBefore,
  ])
}

export function requestEnvelopeMessage(
  origin: string,
  method: string,
  pathWithQuery: string,
  timestamp: ProtocolScalar,
  bodyHash: string,
): string {
  return protocolMessage('1f4bc-request/1', [
    origin,
    method,
    pathWithQuery,
    timestamp,
    bodyHash,
  ])
}

export function registrationMessage(
  origin: string,
  chainId: ProtocolScalar,
  handle: string,
  publicKey: string,
  wallet: string,
  timestamp: ProtocolScalar,
): string {
  return protocolMessage('1f4bc-register/1', [
    origin,
    chainId,
    handle,
    publicKey,
    wallet,
    timestamp,
  ])
}

export function walletOwnershipMessage(
  origin: string,
  chainId: ProtocolScalar,
  handle: string,
  publicKey: string,
): string {
  return protocolMessage('1f4bc-wallet/1', [origin, chainId, handle, publicKey])
}

export function termsAcceptanceMessage(
  origin: string,
  chainId: ProtocolScalar,
  handle: string,
  publicKey: string,
  wallet: string,
  termsVersion: string,
  termsSha256: string,
  acceptableUseVersion: string,
  privacyVersion: string,
  acceptanceSource: TermsAcceptanceSource,
  acceptedAt: ProtocolScalar,
): string {
  return protocolMessage(TERMS_ACCEPTANCE_SIGNATURE_VERSION, [
    origin,
    chainId,
    handle,
    publicKey,
    wallet.toLowerCase(),
    termsVersion,
    termsSha256,
    acceptableUseVersion,
    privacyVersion,
    acceptanceSource,
    acceptedAt,
    TERMS_ACCEPTANCE_STATEMENT,
  ])
}

function parseTermsDescriptor(value: unknown): CurrentTermsDescriptor | undefined {
  if (!isRecord(value)) return undefined
  if (
    typeof value.version !== 'string' || value.version.length === 0 ||
    typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256) ||
    typeof value.url !== 'string' || value.url.length === 0 ||
    typeof value.acceptableUseVersion !== 'string' || value.acceptableUseVersion.length === 0 ||
    typeof value.acceptableUseUrl !== 'string' || value.acceptableUseUrl.length === 0 ||
    typeof value.privacyVersion !== 'string' || value.privacyVersion.length === 0 ||
    typeof value.privacyUrl !== 'string' || value.privacyUrl.length === 0 ||
    typeof value.signatureVersion !== 'string' || value.signatureVersion.length === 0 ||
    typeof value.statement !== 'string' || value.statement.length === 0
  ) {
    return undefined
  }
  return value as CurrentTermsDescriptor
}

function parseTermsAcceptanceEvidence(value: unknown): TermsAcceptanceEvidence | undefined {
  if (!isRecord(value)) return undefined
  if (
    typeof value.acceptedAt !== 'number' ||
    !Number.isSafeInteger(value.acceptedAt) ||
    value.acceptedAt <= 0 ||
    typeof value.recordedAt !== 'number' ||
    !Number.isSafeInteger(value.recordedAt) ||
    value.recordedAt <= 0 ||
    !['browser', 'cli', 'api'].includes(String(value.acceptanceSource)) ||
    typeof value.acceptedPubkey !== 'string' || value.acceptedPubkey.length === 0 ||
    typeof value.acceptedWallet !== 'string' || value.acceptedWallet.length === 0 ||
    typeof value.signatureOrigin !== 'string' || value.signatureOrigin.length === 0 ||
    typeof value.signatureChainId !== 'number' ||
    !Number.isSafeInteger(value.signatureChainId) ||
    value.signatureChainId <= 0 ||
    typeof value.signatureVersion !== 'string' || value.signatureVersion.length === 0
  ) {
    return undefined
  }
  return value as TermsAcceptanceEvidence
}

function parseTermsStatusResponse(
  value: unknown,
  operation: 'status' | 'acceptance',
): TermsStatusResult {
  if (!isRecord(value) || typeof value.accepted !== 'boolean') {
    throw new Error(`Terms ${operation} returned an invalid response`)
  }
  const current = parseTermsDescriptor(value.current)
  const acceptance = value.acceptance === null
    ? null
    : parseTermsAcceptanceEvidence(value.acceptance)
  if (!current || acceptance === undefined || value.accepted !== (acceptance !== null)) {
    throw new Error(`Terms ${operation} returned an invalid response`)
  }
  return { accepted: value.accepted, current, acceptance }
}

function parseTermsAcceptResponse(value: unknown): TermsAcceptResult {
  const status = parseTermsStatusResponse(value, 'acceptance')
  if (!isRecord(value) || typeof value.created !== 'boolean' || !status.accepted || !status.acceptance) {
    throw new Error('Terms acceptance returned an invalid response')
  }
  return {
    ...status,
    accepted: true,
    created: value.created,
    acceptance: status.acceptance,
  }
}

function assertPinnedCurrentTerms(
  current: CurrentTermsDescriptor,
  operation: 'status' | 'acceptance',
): void {
  if (
    current.version !== CURRENT_TERMS_VERSION ||
    current.sha256 !== CURRENT_TERMS_SHA256 ||
    current.url !== CURRENT_TERMS_URL ||
    current.acceptableUseVersion !== CURRENT_ACCEPTABLE_USE_VERSION ||
    current.acceptableUseUrl !== CURRENT_ACCEPTABLE_USE_URL ||
    current.privacyVersion !== CURRENT_PRIVACY_VERSION ||
    current.privacyUrl !== CURRENT_PRIVACY_URL ||
    current.signatureVersion !== TERMS_ACCEPTANCE_SIGNATURE_VERSION ||
    current.statement !== TERMS_ACCEPTANCE_STATEMENT
  ) {
    throw new Error(`Terms ${operation} returned a descriptor that does not match this client`)
  }
}

export function attestationMessage(
  origin: string,
  chainId: ProtocolScalar,
  proofId: ProtocolScalar,
  jobId: string,
): string {
  return protocolMessage('1f4bc-attest/1', [origin, chainId, proofId, jobId])
}

function paymentAttemptKey(
  identity: AgentIdentity,
  pathWithQuery: string,
  rawBody: string,
  expectedAmountAtomic: bigint,
): string {
  return paymentAttemptKeyFromBodyHash(
    identity.publicKey,
    identity.handle ?? '',
    identity.baseUrl,
    identity.chainId,
    identity.wallet,
    pathWithQuery,
    sha256Hex(rawBody),
    expectedAmountAtomic.toString(),
  )
}

function paymentAttemptKeyFromBodyHash(
  publicKey: string,
  handle: string,
  baseUrl: string,
  chainId: number,
  wallet: string,
  pathWithQuery: string,
  bodyHash: string,
  expectedAmountAtomic: string,
): string {
  return sha256Hex([
    publicKey,
    handle,
    baseUrl,
    String(chainId),
    wallet.toLowerCase(),
    'POST',
    pathWithQuery,
    bodyHash,
    expectedAmountAtomic,
  ].join('\n'))
}

function legacyPaymentAttemptKey(
  identity: AgentIdentity,
  pathWithQuery: string,
  rawBody: string,
  expectedAmountAtomic: bigint,
): string {
  return legacyPaymentAttemptKeyFromBodyHash(
    identity.baseUrl,
    identity.chainId,
    identity.wallet,
    pathWithQuery,
    sha256Hex(rawBody),
    expectedAmountAtomic.toString(),
  )
}

function legacyPaymentAttemptKeyFromBodyHash(
  baseUrl: string,
  chainId: number,
  wallet: string,
  pathWithQuery: string,
  bodyHash: string,
  expectedAmountAtomic: string,
): string {
  return sha256Hex([
    baseUrl,
    String(chainId),
    wallet.toLowerCase(),
    'POST',
    pathWithQuery,
    bodyHash,
    expectedAmountAtomic,
  ].join('\n'))
}

function paymentAttemptRoot(identityFile: string): string {
  return join(dirname(normalizeIdentityPath(identityFile)), 'payment-attempts')
}

function paymentAttemptDirectory(identityFile: string, publicKey: string): string {
  return join(paymentAttemptRoot(identityFile), sha256Hex(publicKey))
}

function paymentAttemptFile(identityFile: string, publicKey: string, key: string): string {
  return join(paymentAttemptDirectory(identityFile, publicKey), `${key}.json`)
}

function paymentAttemptArchiveDirectory(identityFile: string, publicKey: string): string {
  return join(dirname(normalizeIdentityPath(identityFile)), 'payment-attempt-archive', sha256Hex(publicKey))
}

function paymentPrincipalLockFile(identityFile: string, publicKey: string): string {
  return join(paymentAttemptDirectory(identityFile, publicKey), '.principal')
}

function paymentHandleRebindFile(identityFile: string, publicKey: string): string {
  return join(paymentAttemptDirectory(identityFile, publicKey), '.handle-rebind.json')
}

function paymentHandleRebindStepFile(identityFile: string, publicKey: string): string {
  return join(paymentAttemptDirectory(identityFile, publicKey), '.handle-rebind-step.json')
}

type PaymentHandleRebind = {
  version: 1
  publicKey: string
  wallet: string
  oldHandle: string
  newHandle: string
  createdAt: number
}

type PaymentHandleRebindStep = {
  version: 1
  publicKey: string
  oldHandle: string
  newHandle: string
  oldKey: string
  newKey: string
  reboundHash: string
}

async function paymentAttemptEntryCount(directory: string): Promise<number> {
  const names = await readdir(directory)
  return names.filter((name) => /^[0-9a-f]{64}\.json$/.test(name)).length
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, 'r')
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function assertNoUnnamespacedPaymentAttempts(identityFile: string): Promise<void> {
  const root = paymentAttemptRoot(identityFile)
  let names: string[]
  try {
    names = await readdir(root)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return
    throw error
  }
  if (names.some((name) => name.endsWith('.json') || name.endsWith('.json.lock'))) {
    throw new Error(
      `unnamespaced pre-release payment-attempt journal found at ${root}; recover or archive it manually before paid requests`,
    )
  }
}

function parsePaymentAttempt(value: unknown): PaymentAttempt {
  if (!isRecord(value)) throw new Error('payment-attempt journal entry is not an object')
  if (
    (value.version !== 1 && value.version !== 2) ||
    typeof value.paymentId !== 'string' ||
    typeof value.baseUrl !== 'string' ||
    typeof value.chainId !== 'number' ||
    typeof value.wallet !== 'string' ||
    typeof value.pathWithQuery !== 'string' ||
    typeof value.bodyHash !== 'string' ||
    typeof value.expectedAmountAtomic !== 'string' ||
    (value.headerName !== 'payment-signature' && value.headerName !== 'x-payment') ||
    typeof value.headerValue !== 'string' ||
    value.headerValue.length === 0 ||
    typeof value.createdAt !== 'number'
  ) {
    throw new Error('payment-attempt journal entry is invalid')
  }
  if (value.version === 1 && value.state === undefined) {
    return value as LegacyPendingPaymentAttempt
  }
  if (
    value.version !== 2 ||
    typeof value.publicKey !== 'string' ||
    value.publicKey.length === 0 ||
    typeof value.handle !== 'string' ||
    !/^[a-z0-9-]{3,32}$/.test(value.handle) ||
    !Number.isSafeInteger(value.refreshCount) ||
    (value.refreshCount as number) < 0 ||
    (value.refreshCount as number) > 1
  ) {
    throw new Error('payment-attempt journal entry is invalid')
  }
  if (value.state === 'pending') return value as PendingPaymentAttempt
  if (value.state === 'refreshing') return value as RefreshingPaymentAttempt
  if (
    value.state === 'terminal' &&
    value.terminalProofVersion === 1 &&
    typeof value.terminalAt === 'number' &&
    Number.isSafeInteger(value.terminalAt) &&
    value.terminalAt >= 0
  ) {
    return value as TerminalPaymentAttempt
  }
  if (
    value.version === 2 &&
    value.state === 'settled' &&
    typeof value.settledAt === 'number' &&
    isRecord(value.result) &&
    typeof value.result.id === 'string' &&
    value.result.id.length > 0
  ) {
    return value as SettledPaymentAttempt
  }
  throw new Error('payment-attempt journal entry has an invalid state')
}

async function loadPaymentAttempt(
  identityFile: string,
  publicKey: string,
  key: string,
): Promise<PaymentAttempt | undefined> {
  try {
    return parsePaymentAttempt(JSON.parse(await readPrivateFile(
      paymentAttemptFile(identityFile, publicKey, key),
      MAX_PAYMENT_JOURNAL_BYTES,
      'payment-attempt journal entry',
    )))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    if (error instanceof SyntaxError) throw new Error('payment-attempt journal entry contains invalid JSON')
    throw error
  }
}

async function readOptionalPrivateJson(
  target: string,
  label: string,
): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readPrivateFile(target, MAX_PAYMENT_JOURNAL_BYTES, label))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    if (error instanceof SyntaxError) throw new Error(`${label} contains invalid JSON`)
    throw error
  }
}

function parsePaymentHandleRebind(value: unknown): PaymentHandleRebind {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    typeof value.publicKey !== 'string' ||
    value.publicKey.length === 0 ||
    typeof value.wallet !== 'string' ||
    !isAddress(value.wallet) ||
    typeof value.oldHandle !== 'string' ||
    !/^[a-z0-9-]{3,32}$/.test(value.oldHandle) ||
    typeof value.newHandle !== 'string' ||
    !/^[a-z0-9-]{3,32}$/.test(value.newHandle) ||
    value.oldHandle === value.newHandle ||
    !Number.isSafeInteger(value.createdAt) ||
    (value.createdAt as number) < 0
  ) {
    throw new Error('payment-journal handle-rebind marker is invalid')
  }
  return value as PaymentHandleRebind
}

function parsePaymentHandleRebindStep(value: unknown): PaymentHandleRebindStep {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    typeof value.publicKey !== 'string' ||
    value.publicKey.length === 0 ||
    typeof value.oldHandle !== 'string' ||
    !/^[a-z0-9-]{3,32}$/.test(value.oldHandle) ||
    typeof value.newHandle !== 'string' ||
    !/^[a-z0-9-]{3,32}$/.test(value.newHandle) ||
    value.oldHandle === value.newHandle ||
    typeof value.oldKey !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.oldKey) ||
    typeof value.newKey !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.newKey) ||
    value.oldKey === value.newKey ||
    typeof value.reboundHash !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.reboundHash)
  ) {
    throw new Error('payment-journal handle-rebind step is invalid')
  }
  return value as PaymentHandleRebindStep
}

async function loadPaymentHandleRebind(
  identityFile: string,
  publicKey: string,
): Promise<PaymentHandleRebind | undefined> {
  const value = await readOptionalPrivateJson(
    paymentHandleRebindFile(identityFile, publicKey),
    'payment-journal handle-rebind marker',
  )
  return value === undefined ? undefined : parsePaymentHandleRebind(value)
}

async function loadPaymentHandleRebindStep(
  identityFile: string,
  publicKey: string,
): Promise<PaymentHandleRebindStep | undefined> {
  const value = await readOptionalPrivateJson(
    paymentHandleRebindStepFile(identityFile, publicKey),
    'payment-journal handle-rebind step',
  )
  return value === undefined ? undefined : parsePaymentHandleRebindStep(value)
}

function paymentAttemptKeyFor(attempt: PaymentAttemptBase): string {
  return paymentAttemptKeyFromBodyHash(
    attempt.publicKey,
    attempt.handle,
    attempt.baseUrl,
    attempt.chainId,
    attempt.wallet,
    attempt.pathWithQuery,
    attempt.bodyHash,
    attempt.expectedAmountAtomic,
  )
}

/**
 * v1 journals were named before the local Ed25519 principal and registered
 * handle became part of the operation key. A legacy entry upgraded in place
 * remains under that old, deterministic filename until it is safely cleared.
 */
function paymentAttemptStorageKeyMatches(attempt: PaymentAttemptBase, key: string): boolean {
  return paymentAttemptKeyFor(attempt) === key ||
    legacyPaymentAttemptKeyFromBodyHash(
      attempt.baseUrl,
      attempt.chainId,
      attempt.wallet,
      attempt.pathWithQuery,
      attempt.bodyHash,
      attempt.expectedAmountAtomic,
    ) === key
}

function reboundPaymentAttempt(
  attempt: Exclude<PaymentAttempt, LegacyPendingPaymentAttempt>,
  newHandle: string,
): Exclude<PaymentAttempt, LegacyPendingPaymentAttempt> {
  return { ...attempt, handle: newHandle }
}

function paymentAttemptContents(attempt: PaymentAttempt): string {
  return `${JSON.stringify(attempt)}\n`
}

function assertRebindPrincipal(
  attempt: Exclude<PaymentAttempt, LegacyPendingPaymentAttempt>,
  publicKey: string,
  wallet: string,
): void {
  if (attempt.publicKey !== publicKey || attempt.wallet !== wallet) {
    throw new Error('payment-attempt journal principal does not match the local identity')
  }
}

async function removeAndSync(target: string): Promise<void> {
  await unlink(target)
  await syncDirectory(dirname(target))
}

async function writePaymentAttemptForRebind(
  target: string,
  contents: string,
): Promise<void> {
  if (Buffer.byteLength(contents, 'utf8') > MAX_PAYMENT_JOURNAL_BYTES) {
    throw new Error('rebound payment attempt exceeds the local journal safety limit')
  }
  const handle = await open(target, 'wx', 0o600)
  try {
    await handle.writeFile(contents, 'utf8')
    await handle.sync()
  } finally {
    await handle.close()
  }
  await chmod(target, 0o600)
  await syncDirectory(dirname(target))
}

async function completePaymentHandleRebindStep(
  identityFile: string,
  marker: PaymentHandleRebind,
  step: PaymentHandleRebindStep,
): Promise<void> {
  if (
    step.publicKey !== marker.publicKey ||
    step.oldHandle !== marker.oldHandle ||
    step.newHandle !== marker.newHandle
  ) {
    throw new Error('payment-journal handle-rebind step does not match its marker')
  }
  const oldTarget = paymentAttemptFile(identityFile, marker.publicKey, step.oldKey)
  const newTarget = paymentAttemptFile(identityFile, marker.publicKey, step.newKey)
  const oldAttempt = await loadPaymentAttempt(identityFile, marker.publicKey, step.oldKey)
  let expected: Exclude<PaymentAttempt, LegacyPendingPaymentAttempt> | undefined
  let expectedContents: string | undefined
  if (oldAttempt) {
    if (oldAttempt.version !== 2) {
      throw new Error('payment-journal handle rebind cannot rewrite a legacy attempt')
    }
    assertRebindPrincipal(oldAttempt, marker.publicKey, marker.wallet)
    if (oldAttempt.handle !== marker.oldHandle || paymentAttemptKeyFor(oldAttempt) !== step.oldKey) {
      throw new Error('payment-attempt journal source does not match its handle-rebind step')
    }
    expected = reboundPaymentAttempt(oldAttempt, marker.newHandle)
    expectedContents = paymentAttemptContents(expected)
    if (
      paymentAttemptKeyFor(expected) !== step.newKey ||
      sha256Hex(expectedContents) !== step.reboundHash
    ) {
      throw new Error('payment-attempt journal source changed during handle rebind')
    }
  }

  let newAttempt: PaymentAttempt | undefined
  try {
    newAttempt = await loadPaymentAttempt(identityFile, marker.publicKey, step.newKey)
  } catch (error) {
    if (!oldAttempt) throw error
    // The step marker was durably written while this destination was absent.
    // A malformed destination with the source still present is therefore a
    // partial write from this transaction and can be reconstructed safely.
    await removeAndSync(newTarget)
  }
  if (newAttempt) {
    if (newAttempt.version !== 2) {
      throw new Error('payment-journal handle-rebind destination is a legacy attempt')
    }
    assertRebindPrincipal(newAttempt, marker.publicKey, marker.wallet)
    const contents = paymentAttemptContents(newAttempt)
    if (
      newAttempt.handle !== marker.newHandle ||
      paymentAttemptKeyFor(newAttempt) !== step.newKey ||
      sha256Hex(contents) !== step.reboundHash ||
      (expectedContents !== undefined && contents !== expectedContents)
    ) {
      throw new Error('payment-journal handle-rebind destination conflicts with the source')
    }
  } else {
    if (!expected || !expectedContents) {
      throw new Error('payment-journal handle-rebind lost both source and destination')
    }
    await writePaymentAttemptForRebind(newTarget, expectedContents)
  }

  if (oldAttempt) await removeAndSync(oldTarget)
  await removeAndSync(paymentHandleRebindStepFile(identityFile, marker.publicKey))
}

async function rebindV2PaymentAttempts(
  identityFile: string,
  identity: AgentIdentity,
  oldHandle: string,
  newHandle: string,
  now: number,
): Promise<PaymentHandleRebind> {
  const publicKey = identity.publicKey
  let marker = await loadPaymentHandleRebind(identityFile, publicKey)
  const existingStep = await loadPaymentHandleRebindStep(identityFile, publicKey)
  if (!marker) {
    if (existingStep) {
      throw new Error('payment-journal handle-rebind step exists without its marker')
    }
    marker = {
      version: 1,
      publicKey,
      wallet: identity.wallet,
      oldHandle,
      newHandle,
      createdAt: now,
    }
    await atomicWritePrivate(
      paymentHandleRebindFile(identityFile, publicKey),
      `${JSON.stringify(marker)}\n`,
    )
  } else if (
    marker.publicKey !== publicKey ||
    marker.wallet !== identity.wallet ||
    marker.oldHandle !== oldHandle ||
    marker.newHandle !== newHandle
  ) {
    throw new Error('incomplete payment-journal handle rebind does not match this recovery')
  }

  if (existingStep) {
    await completePaymentHandleRebindStep(identityFile, marker, existingStep)
  }

  const directory = paymentAttemptDirectory(identityFile, publicKey)
  const names = (await readdir(directory))
    .filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    .sort()
  for (const name of names) {
    const key = name.slice(0, -'.json'.length)
    const attempt = await loadPaymentAttempt(identityFile, publicKey, key)
    if (!attempt) throw new Error('payment-attempt journal disappeared during handle rebind')
    if (attempt.version === 1) continue
    assertRebindPrincipal(attempt, publicKey, identity.wallet)
    if (paymentAttemptKeyFor(attempt) !== key) {
      throw new Error('payment-attempt journal filename does not match its bound principal')
    }
    if (attempt.handle === newHandle) continue
    if (attempt.handle !== oldHandle) {
      throw new Error('payment-attempt journal is bound to an unexpected agent handle')
    }
    const rebound = reboundPaymentAttempt(attempt, newHandle)
    const newKey = paymentAttemptKeyFor(rebound)
    if (await loadPaymentAttempt(identityFile, publicKey, newKey)) {
      throw new Error('payment-attempt journal collides with the recovered agent handle')
    }
    const contents = paymentAttemptContents(rebound)
    const step: PaymentHandleRebindStep = {
      version: 1,
      publicKey,
      oldHandle,
      newHandle,
      oldKey: key,
      newKey,
      reboundHash: sha256Hex(contents),
    }
    await atomicWritePrivate(
      paymentHandleRebindStepFile(identityFile, publicKey),
      `${JSON.stringify(step)}\n`,
    )
    await completePaymentHandleRebindStep(identityFile, marker, step)
  }
  return marker
}

function sameLocalPrincipal(first: AgentIdentity, second: AgentIdentity): boolean {
  return first.privateKey === second.privateKey &&
    first.publicKey === second.publicKey &&
    first.walletPrivateKey === second.walletPrivateKey &&
    first.wallet === second.wallet
}

async function assertPaymentPrincipalReady(
  identityFile: string,
  identity: AgentIdentity,
): Promise<void> {
  const marker = await loadPaymentHandleRebind(identityFile, identity.publicKey)
  const step = await loadPaymentHandleRebindStep(identityFile, identity.publicKey)
  if (marker || step) {
    const target = marker?.newHandle
    throw new Error(
      `payment-journal handle recovery is incomplete; rerun 1f4bc register${target ? ` ${target}` : ''}`,
    )
  }
  const persisted = await loadIdentity(identityFile)
  if (!sameLocalPrincipal(persisted, identity)) {
    throw new Error('API identity principal changed while preparing a paid request')
  }
  // Programmatic callers may bind a registered in-memory identity to an
  // otherwise matching pre-registration file. Once a handle is persisted,
  // however, a mismatch means another process completed a rename and this
  // stale client must not create an authorization under the old handle.
  if (persisted.handle !== undefined && persisted.handle !== identity.handle) {
    throw new Error('agent handle changed on disk; reload the CLI before making a paid request')
  }
}

async function persistPendingPayment(
  identityFile: string,
  publicKey: string,
  key: string,
  attempt: PaymentAttemptBase & { version: 2; state: 'pending' },
): Promise<PaymentAttempt> {
  const target = paymentAttemptFile(identityFile, publicKey, key)
  const directory = dirname(target)
  // Creating distinct operation files is serialized separately from each
  // operation's lock, otherwise concurrent unique inputs can exceed the
  // directory ceiling after racing on the same count.
  return withFileLock(join(directory, '.entry-count'), () => withFileLock(target, async () => {
    const existing = await loadPaymentAttempt(identityFile, publicKey, key)
    const contents = `${JSON.stringify(attempt)}\n`
    if (Buffer.byteLength(contents, 'utf8') > MAX_PAYMENT_JOURNAL_BYTES) {
      throw new Error('payment authorization exceeds the local journal safety limit')
    }
    if (existing) {
      if (
        existing.version === 2 &&
        existing.state === 'refreshing' &&
        existing.refreshCount === attempt.refreshCount &&
        existing.publicKey === attempt.publicKey &&
        existing.handle === attempt.handle &&
        existing.baseUrl === attempt.baseUrl &&
        existing.chainId === attempt.chainId &&
        existing.wallet.toLowerCase() === attempt.wallet.toLowerCase() &&
        existing.pathWithQuery === attempt.pathWithQuery &&
        existing.bodyHash === attempt.bodyHash &&
        existing.expectedAmountAtomic === attempt.expectedAmountAtomic
      ) {
        await atomicWritePrivate(target, contents)
        return attempt
      }
      return existing
    }
    if (await paymentAttemptEntryCount(directory) >= MAX_PAYMENT_ATTEMPT_ENTRIES) {
      throw new Error(
        `payment-attempt journal reached its ${MAX_PAYMENT_ATTEMPT_ENTRIES}-entry safety limit`,
      )
    }
    await mkdir(directory, { recursive: true, mode: 0o700 })
    await chmod(directory, 0o700)
    const temporary = join(directory, `.${key}.${process.pid}.${randomUUID()}.tmp`)
    const handle = await open(temporary, 'wx', 0o600)
    try {
      await handle.writeFile(contents, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await chmod(temporary, 0o600)
    try {
      // Linking a fully-written temporary file makes the no-overwrite claim
      // atomic even when an older client does not honor the lock file.
      await link(temporary, target)
      await chmod(target, 0o600)
      await syncDirectory(directory)
      return attempt
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const winner = await loadPaymentAttempt(identityFile, publicKey, key)
      if (!winner) throw new Error('payment-attempt journal claim disappeared')
      return winner
    } finally {
      await unlink(temporary).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== 'ENOENT') throw error
      })
      await syncDirectory(directory)
    }
  }))
}

async function settlePaymentAttempt(
  identityFile: string,
  principal: Pick<PaymentAttemptBase, 'publicKey' | 'handle'>,
  key: string,
  expected: Pick<PendingPaymentAttempt, 'paymentId' | 'headerName' | 'headerValue'>,
  result: JsonRecord,
  settledAt: number,
): Promise<JsonRecord> {
  const target = paymentAttemptFile(identityFile, principal.publicKey, key)
  return withFileLock(target, async () => {
    const current = await loadPaymentAttempt(identityFile, principal.publicKey, key)
    if (!current) throw new Error('payment-attempt journal disappeared before completion')
    if (
      current.paymentId !== expected.paymentId ||
      current.headerName !== expected.headerName ||
      current.headerValue !== expected.headerValue
    ) {
      throw new Error('payment-attempt journal changed before completion')
    }
    if (current.version === 2 && current.state === 'settled') return current.result
    if (current.version === 2 && current.state === 'terminal') {
      throw new Error('a terminal payment attempt cannot become settled')
    }
    const settled: SettledPaymentAttempt = {
      ...current,
      ...principal,
      version: 2,
      state: 'settled',
      refreshCount: current.version === 1 ? 0 : current.refreshCount,
      result,
      settledAt,
    }
    const contents = `${JSON.stringify(settled)}\n`
    if (Buffer.byteLength(contents, 'utf8') > MAX_PAYMENT_JOURNAL_BYTES) {
      throw new Error('paid request result exceeds the payment-journal safety limit')
    }
    await atomicWritePrivate(target, contents)
    return result
  })
}

async function markTerminalPaymentAttempt(
  identityFile: string,
  principal: Pick<PaymentAttemptBase, 'publicKey' | 'handle'>,
  key: string,
  expected: Pick<PaymentAttemptBase, 'paymentId' | 'headerName' | 'headerValue'>,
  terminalAt: number,
): Promise<TerminalPaymentAttempt> {
  const target = paymentAttemptFile(identityFile, principal.publicKey, key)
  return withFileLock(target, async () => {
    const current = await loadPaymentAttempt(identityFile, principal.publicKey, key)
    if (!current) throw new Error('payment-attempt journal disappeared before terminal recovery')
    if (
      current.paymentId !== expected.paymentId ||
      current.headerName !== expected.headerName ||
      current.headerValue !== expected.headerValue
    ) {
      throw new Error('payment-attempt journal changed before terminal recovery')
    }
    if (current.version === 2 && current.state === 'settled') {
      throw new Error('a settled payment attempt cannot become terminal')
    }
    if (current.version === 2 && current.state === 'terminal') return current
    const terminal: TerminalPaymentAttempt = {
      ...current,
      version: 2,
      state: 'terminal',
      ...principal,
      refreshCount: current.version === 1 ? 0 : current.refreshCount,
      terminalAt,
      terminalProofVersion: 1,
    }
    await atomicWritePrivate(target, paymentAttemptContents(terminal))
    return terminal
  })
}

async function stageTerminalPaymentArchive(
  identityFile: string,
  publicKey: string,
  key: string,
  expected: Pick<PaymentAttemptBase, 'paymentId' | 'headerName' | 'headerValue'>,
): Promise<void> {
  const target = paymentAttemptFile(identityFile, publicKey, key)
  await withFileLock(target, async () => {
    const current = await loadPaymentAttempt(identityFile, publicKey, key)
    if (!current || current.version !== 2 || current.state !== 'terminal') {
      throw new Error('only a server-confirmed terminal payment attempt can be archived')
    }
    if (
      current.paymentId !== expected.paymentId ||
      current.headerName !== expected.headerName ||
      current.headerValue !== expected.headerValue ||
      !paymentAttemptStorageKeyMatches(current, key)
    ) {
      throw new Error('terminal payment-attempt journal changed before archival')
    }
    const contents = paymentAttemptContents(current)
    const archiveDirectory = paymentAttemptArchiveDirectory(identityFile, publicKey)
    const archiveTarget = join(
      archiveDirectory,
      `${key}.${current.terminalAt}.${sha256Hex(contents).slice(0, 16)}.json`,
    )
    let existing: string | undefined
    try {
      existing = await readPrivateFile(
        archiveTarget,
        MAX_PAYMENT_JOURNAL_BYTES,
        'archived payment-attempt journal entry',
      )
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
    if (existing !== undefined && existing !== contents) {
      throw new Error('terminal payment-attempt archive conflicts with the exact journal')
    }
    if (existing === undefined) {
      const archiveEntries = (await readdir(archiveDirectory))
        .filter((name) => name.endsWith('.json')).length
      if (archiveEntries >= MAX_PAYMENT_ATTEMPT_ENTRIES) {
        throw new Error('terminal payment-attempt archive reached its entry safety limit')
      }
      await atomicWritePrivate(archiveTarget, contents)
    }
  })
}

async function finalizeTerminalPaymentArchive(
  identityFile: string,
  publicKey: string,
  key: string,
  expected: Pick<PaymentAttemptBase, 'paymentId' | 'headerName' | 'headerValue'>,
): Promise<void> {
  const target = paymentAttemptFile(identityFile, publicKey, key)
  await withFileLock(target, async () => {
    const archived = await loadArchivedTerminalPaymentAttempt(
      identityFile,
      publicKey,
      key,
      expected,
    )
    if (!archived) throw new Error('terminal payment-attempt archive is missing')
    if (
      archived.paymentId !== expected.paymentId ||
      archived.headerName !== expected.headerName ||
      archived.headerValue !== expected.headerValue
    ) {
      throw new Error('terminal payment-attempt archive does not match the exact recovery')
    }
    const current = await loadPaymentAttempt(identityFile, publicKey, key)
    if (!current) return
    if (
      current.version !== 2 ||
      current.state !== 'terminal' ||
      paymentAttemptContents(current) !== paymentAttemptContents(archived)
    ) {
      throw new Error('active terminal payment attempt conflicts with its archive')
    }
    await removeAndSync(target)
  })
}

async function loadArchivedTerminalPaymentAttempt(
  identityFile: string,
  publicKey: string,
  key: string,
  expected?: Pick<PaymentAttemptBase, 'paymentId' | 'headerName' | 'headerValue'>,
): Promise<TerminalPaymentAttempt | undefined> {
  const directory = paymentAttemptArchiveDirectory(identityFile, publicKey)
  let names: string[]
  try {
    names = (await readdir(directory)).filter((name) =>
      new RegExp(`^${key}\\.[0-9]+\\.[0-9a-f]{16}\\.json$`).test(name),
    )
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  if (names.length === 0) return undefined
  const archives: Array<{ name: string; attempt: TerminalPaymentAttempt }> = []
  for (const name of names.sort()) {
    const raw = await readPrivateFile(
      join(directory, name),
      MAX_PAYMENT_JOURNAL_BYTES,
      'archived payment-attempt journal entry',
    )
    let parsed: PaymentAttempt
    try {
      parsed = parsePaymentAttempt(JSON.parse(raw))
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('archived payment-attempt journal entry contains invalid JSON')
      }
      throw error
    }
    if (
      parsed.version !== 2 ||
      parsed.state !== 'terminal' ||
      !paymentAttemptStorageKeyMatches(parsed, key) ||
      !name.endsWith(`.${parsed.terminalAt}.${sha256Hex(raw).slice(0, 16)}.json`)
    ) {
      throw new Error('archived payment-attempt journal entry is inconsistent')
    }
    archives.push({ name, attempt: parsed })
  }
  if (expected) {
    const exact = archives.filter(({ attempt }) =>
      attempt.paymentId === expected.paymentId &&
      attempt.headerName === expected.headerName &&
      attempt.headerValue === expected.headerValue)
    if (exact.length > 1) {
      throw new Error('duplicate terminal archives exist for one payment authorization')
    }
    return exact[0]?.attempt
  }
  archives.sort((left, right) =>
    right.attempt.terminalAt - left.attempt.terminalAt ||
    right.name.localeCompare(left.name))
  return archives[0]?.attempt
}

function paymentFailure(error: unknown, mayHaveOccurred: boolean): Error {
  const failure = error instanceof Error ? error : new Error(String(error))
  const existing = (failure as { paymentMayHaveOccurred?: unknown }).paymentMayHaveOccurred
  // Once an authorization exists, no downstream or dependency-thrown
  // `paymentMayHaveOccurred: false` marker may release the spend reservation.
  // Wrap rather than mutate a possibly frozen/non-configurable foreign error.
  if (mayHaveOccurred && existing === false) {
    const wrapped = new Error(
      'paid request failed after a payment authorization was created',
      { cause: failure },
    )
    Object.defineProperty(wrapped, 'paymentMayHaveOccurred', {
      value: true,
      enumerable: true,
    })
    return wrapped
  }
  if (typeof existing !== 'boolean') {
    Object.defineProperty(failure, 'paymentMayHaveOccurred', {
      value: mayHaveOccurred,
      enumerable: true,
      configurable: true,
    })
  }
  return failure
}

export function paymentMayHaveOccurred(error: unknown): boolean | undefined {
  if (typeof error !== 'object' || error === null) return undefined
  const value = (error as { paymentMayHaveOccurred?: unknown }).paymentMayHaveOccurred
  return typeof value === 'boolean' ? value : undefined
}

function authorizationExplicitlyExpired(response: Response): boolean {
  return response.status === 410 && response.headers.get('X-1F4BC-Payment-Expired') === '1'
}

function authorizationExpiredLocally(
  header: { name: 'payment-signature' | 'x-payment'; value: string },
  now: number,
): boolean {
  try {
    const decoded = decodePaymentSignatureHeader(header.value)
    if (!isRecord(decoded.payload)) return false
    const authorization = decoded.payload.authorization
    if (!isRecord(authorization) || typeof authorization.validBefore !== 'string') return false
    if (!/^[0-9]+$/.test(authorization.validBefore)) return false
    return BigInt(authorization.validBefore) <= BigInt(Math.floor(now / 1_000))
  } catch {
    return false
  }
}

type MarketplacePaymentPolicy = {
  target: URL
  chainId: number
  network: `eip155:${number}`
  asset: `0x${string}`
  amount: string
  payTo: `0x${string}`
  domain: UsdcEip712Domain
}

function marketplacePaymentPolicy(
  target: URL,
  chainId: number,
  expectedAmountAtomic: bigint,
): MarketplacePaymentPolicy {
  return {
    target,
    chainId,
    network: `eip155:${chainId}`,
    asset: expectedUsdc(chainId),
    amount: expectedAmountAtomic.toString(),
    payTo: expectedMarketplacePayTo(chainId),
    domain: usdcEip712Domain(chainId),
  }
}

function isExactMarketplaceRequirement(
  value: unknown,
  policy: MarketplacePaymentPolicy,
): boolean {
  if (!isRecord(value) || !isRecord(value.extra)) return false
  const transferMethod = value.extra.assetTransferMethod
  return value.scheme === 'exact' &&
    value.network === policy.network &&
    typeof value.asset === 'string' &&
    value.asset.toLowerCase() === policy.asset.toLowerCase() &&
    value.amount === policy.amount &&
    typeof value.payTo === 'string' &&
    isAddress(value.payTo) &&
    value.payTo.toLowerCase() === policy.payTo.toLowerCase() &&
    Number.isSafeInteger(value.maxTimeoutSeconds) &&
    (value.maxTimeoutSeconds as number) >= 1 &&
    (value.maxTimeoutSeconds as number) <= 300 &&
    value.extra.name === policy.domain.name &&
    value.extra.version === policy.domain.version &&
    (transferMethod === undefined || transferMethod === 'eip3009')
}

function validateMarketplaceChallenge(
  response: Response,
  policy: MarketplacePaymentPolicy,
): void {
  const encoded = response.headers.get('PAYMENT-REQUIRED')
  if (!encoded) throw new Error('marketplace returned 402 without a valid x402 v2 challenge')
  let required: ReturnType<typeof decodePaymentRequiredHeader>
  try {
    required = decodePaymentRequiredHeader(encoded)
  } catch {
    throw new Error('marketplace returned an invalid x402 v2 challenge')
  }
  let resourceUrl: string
  try {
    resourceUrl = new URL(required.resource.url).href
  } catch {
    throw new Error('marketplace x402 challenge has an invalid resource URL')
  }
  const identifier = required.extensions?.[PAYMENT_IDENTIFIER]
  if (
    required.x402Version !== 2 ||
    resourceUrl !== policy.target.href ||
    !isRecord(identifier) ||
    !isRecord(identifier.info) ||
    identifier.info.required !== true ||
    !required.accepts.some((requirement) => isExactMarketplaceRequirement(requirement, policy))
  ) {
    throw new Error('marketplace x402 challenge does not match the pinned payment policy')
  }
}

async function validateMarketplacePaymentHeader(
  value: string,
  paymentId: string,
  payer: string,
  policy: MarketplacePaymentPolicy,
  requireFresh: boolean,
  nowMilliseconds: number,
): Promise<void> {
  let decoded: ReturnType<typeof decodePaymentSignatureHeader>
  try {
    decoded = decodePaymentSignatureHeader(value)
  } catch {
    throw new Error('x402 client created an invalid payment authorization')
  }
  const identifier = decoded.extensions?.[PAYMENT_IDENTIFIER]
  const resource = decoded.resource
  const authorization = decoded.payload.authorization
  const signature = decoded.payload.signature
  if (
    decoded.x402Version !== 2 ||
    !resource ||
    resource.url !== policy.target.href ||
    !isRecord(identifier) ||
    !isRecord(identifier.info) ||
    identifier.info.id !== paymentId ||
    !isExactMarketplaceRequirement(decoded.accepted, policy) ||
    !isRecord(authorization) ||
    typeof authorization.from !== 'string' ||
    !isAddress(authorization.from) ||
    authorization.from.toLowerCase() !== payer.toLowerCase() ||
    typeof authorization.to !== 'string' ||
    !isAddress(authorization.to) ||
    authorization.to.toLowerCase() !== policy.payTo.toLowerCase() ||
    authorization.value !== policy.amount ||
    authorization.validAfter !== '0' ||
    typeof authorization.validBefore !== 'string' ||
    !/^[0-9]+$/.test(authorization.validBefore) ||
    typeof authorization.nonce !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/.test(authorization.nonce) ||
    typeof signature !== 'string' ||
    !/^0x[0-9a-fA-F]{130}$/.test(signature)
  ) {
    throw new Error('x402 payment authorization does not match the pinned payment policy')
  }

  const validBefore = BigInt(authorization.validBefore)
  if (validBefore <= 0n) {
    throw new Error('x402 payment authorization has an invalid validity window')
  }
  if (requireFresh) {
    const nowSeconds = BigInt(Math.floor(nowMilliseconds / 1_000))
    const maxTimeout = BigInt(decoded.accepted.maxTimeoutSeconds)
    if (validBefore > nowSeconds + maxTimeout + 5n) {
      throw new Error('x402 payment authorization exceeds the pinned validity window')
    }
  }

  let recovered: string
  try {
    recovered = await recoverTypedDataAddress({
      domain: {
        name: policy.domain.name,
        version: policy.domain.version,
        chainId: policy.chainId,
        verifyingContract: policy.asset,
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
}

function assertMarketplaceResponse(response: Response, requestedUrl: string): void {
  if (
    response.type === 'opaqueredirect' ||
    response.redirected ||
    (response.status >= 300 && response.status <= 399)
  ) {
    throw new Error(`marketplace redirect rejected (HTTP ${response.status})`)
  }
  if (response.url) {
    let effectiveUrl: string
    try {
      effectiveUrl = new URL(response.url).href
    } catch {
      throw new Error('marketplace response reported an invalid effective URL')
    }
    if (effectiveUrl !== requestedUrl) {
      throw new Error('marketplace response URL does not match the requested URL')
    }
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (!response.body || response.bodyUsed) return
  await response.body.cancel().catch(() => undefined)
}

async function bodylessPaymentChallenge(response: Response): Promise<Response> {
  const headers = new Headers()
  const required = response.headers.get('PAYMENT-REQUIRED')
  if (required) headers.set('PAYMENT-REQUIRED', required)
  await cancelResponseBody(response)
  return new Response(null, { status: 402, headers })
}

async function marketplaceFetch(
  fetcher: FetchLike,
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const initialRequest = new Request(input, init)
  const signal = AbortSignal.any([
    initialRequest.signal,
    AbortSignal.timeout(MARKETPLACE_REQUEST_TIMEOUT_MS),
  ])
  const request = new Request(initialRequest, { redirect: 'manual', signal })
  const requestedUrl = new URL(request.url).href
  if (request.url !== requestedUrl || request.redirect !== 'manual') {
    throw new Error('marketplace request URL could not be pinned')
  }
  const response = await fetcher(request as unknown as RequestInfo)
  try {
    assertMarketplaceResponse(response, requestedUrl)
  } catch (error) {
    await cancelResponseBody(response)
    throw error
  }
  return response
}

export async function signEnvelope(
  identity: AgentIdentity,
  method: string,
  pathWithQuery: string,
  body: string,
  timestamp: number,
): Promise<Headers> {
  if (!identity.handle) {
    throw new Error(
      `identity is not registered; run 1f4bc register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`,
    )
  }
  const normalizedMethod = method.toUpperCase()
  const signedBody = normalizedMethod === 'GET' || normalizedMethod === 'HEAD' ? '' : body
  const message = requestEnvelopeMessage(
    normalizeBaseUrl(identity.baseUrl),
    normalizedMethod,
    pathWithQuery,
    timestamp,
    sha256Hex(signedBody),
  )
  const signature = await ed.signAsync(new TextEncoder().encode(message), fromBase64(identity.privateKey))
  return new Headers({
    'X-Agent': identity.handle,
    'X-Timestamp': String(timestamp),
    'X-Signature': toBase64(signature),
  })
}

/**
 * A fetch adapter that signs every actual network attempt. @x402/fetch calls
 * this once for the unpaid probe and again for the paid request, so both get a
 * distinct envelope while the payment extension retains one logical ID.
 */
export function createSigningFetch(
  identity: AgentIdentity,
  fetcher: FetchLike = globalThis.fetch,
  now: () => number = Date.now,
): FetchLike {
  let lastTimestamp = 0
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, { ...init, redirect: 'manual' })
    const method = request.method.toUpperCase()
    const url = new URL(request.url)
    if (url.origin !== new URL(identity.baseUrl).origin) {
      throw new Error('refusing to send marketplace credentials to another origin')
    }
    assertNoIdentitySecrets(url.href, identity, 'marketplace request URL')
    const body = method === 'GET' || method === 'HEAD' ? '' : await request.clone().text()
    if (body) assertNoIdentitySecrets(body, identity, 'marketplace request body')
    const wallClockTimestamp = Math.floor(now() / 1_000)
    // Ed25519 signatures are deterministic. An immediate x402 retry can fall in
    // the same Unix second, so make the protocol timestamp monotonically fresh.
    const timestamp = Math.max(wallClockTimestamp, lastTimestamp + 1)
    lastTimestamp = timestamp
    const auth = await signEnvelope(identity, method, url.pathname + url.search, body, timestamp)
    const signedRequest = request.clone()
    for (const [name, value] of auth) signedRequest.headers.set(name, value)
    return marketplaceFetch(fetcher, signedRequest as unknown as RequestInfo)
  }
}

export class MarketplaceHttpError extends Error {
  constructor(public readonly status: number) {
    super(`1f4bc marketplace returned HTTP ${status}`)
    this.name = 'MarketplaceHttpError'
  }
}

async function readBoundedResponseBody(response: Response): Promise<string> {
  const declaredLength = response.headers.get('content-length')
  if (declaredLength && /^[0-9]+$/.test(declaredLength)) {
    if (BigInt(declaredLength) > BigInt(MAX_MARKETPLACE_RESPONSE_BYTES)) {
      await cancelResponseBody(response)
      throw new Error('marketplace response exceeds the 1 MiB safety limit')
    }
  }
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let bytes = 0
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      bytes += chunk.value.byteLength
      if (bytes > MAX_MARKETPLACE_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw new Error('marketplace response exceeds the 1 MiB safety limit')
      }
      chunks.push(chunk.value)
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  const combined = new Uint8Array(bytes)
  let offset = 0
  for (const chunk of chunks) {
    combined.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(combined)
}

async function readResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? ''
  if (response.status === 204) await cancelResponseBody(response)
  const rawBody = response.status === 204 ? '' : await readBoundedResponseBody(response)
  if (!response.ok) throw new MarketplaceHttpError(response.status)
  let body: unknown
  if (response.status === 204) {
    body = null
  } else if (contentType.includes('application/json')) {
    try {
      body = rawBody.length === 0 ? null : JSON.parse(rawBody)
    } catch {
      body = null
    }
  } else {
    body = rawBody
  }
  return body
}

function cloneExtensions(extensions: Record<string, unknown> | undefined): Record<string, unknown> {
  return extensions ? structuredClone(extensions) : {}
}

export class AgentApi {
  readonly #fetcher: FetchLike
  readonly #identityPath?: string
  readonly #now: () => number
  #lastTimestamp = 0
  #identityValue: AgentIdentity

  constructor(identity: AgentIdentity, options: AgentApiOptions = {}) {
    const privateKey = fromBase64(identity.privateKey)
    const publicKey = fromBase64(identity.publicKey)
    if (privateKey.byteLength !== 32 || publicKey.byteLength !== 32) {
      throw new Error('agent identity must contain canonical 32-byte Ed25519 keys')
    }
    const derivedPublicKey = deriveEd25519PublicKey(privateKey)
    if (!timingSafeEqual(Buffer.from(publicKey), Buffer.from(derivedPublicKey))) {
      throw new Error('agent identity public key does not match its private key')
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
      throw new Error('agent identity has an invalid handle')
    }
    if (!Number.isSafeInteger(identity.chainId) || identity.chainId <= 0) {
      throw new Error('agent identity has an invalid chain id')
    }
    const selectedChainId = options.chainId ?? identity.chainId
    if (!Number.isSafeInteger(selectedChainId) || selectedChainId <= 0) {
      throw new Error('agent identity has an invalid chain id override')
    }
    if (
      identity.version !== 1 ||
      !Number.isSafeInteger(identity.createdAt) ||
      identity.createdAt < 0
    ) {
      throw new Error('agent identity has invalid metadata')
    }
    const boundIdentityPath = options.identityPath
      ? realpathSync(normalizeIdentityPath(options.identityPath))
      : undefined
    if (boundIdentityPath) {
      let persisted: Partial<AgentIdentity>
      try {
        const raw = readFileSync(boundIdentityPath, 'utf8')
        if (Buffer.byteLength(raw, 'utf8') > 64 * 1_024) throw new Error('identity file is too large')
        persisted = JSON.parse(raw) as Partial<AgentIdentity>
      } catch {
        throw new Error('cannot bind the API client to its identity file')
      }
      if (
        persisted.privateKey !== identity.privateKey ||
        persisted.publicKey !== identity.publicKey ||
        persisted.walletPrivateKey !== identity.walletPrivateKey ||
        typeof persisted.wallet !== 'string' ||
        persisted.wallet.toLowerCase() !== identity.wallet.toLowerCase()
      ) {
        throw new Error('API identity does not match the bound identity file')
      }
    }
    this.#identityValue = {
      ...identity,
      privateKey: toBase64(privateKey),
      publicKey: toBase64(derivedPublicKey),
      walletPrivateKey: canonicalWalletPrivateKey,
      wallet: derivedWallet,
      baseUrl: normalizeBaseUrl(options.baseUrl ?? identity.baseUrl),
      chainId: selectedChainId,
    }
    assertNoIdentitySecrets(this.#identityValue.baseUrl, this.#identityValue, 'marketplace base URL')
    this.#fetcher = options.fetch ?? globalThis.fetch
    this.#identityPath = boundIdentityPath
    this.#now = options.now ?? Date.now
  }

  static async fromIdentityFile(path?: string, options: Omit<AgentApiOptions, 'identityPath'> = {}) {
    const resolved = await discoverIdentityPath(path)
    return new AgentApi(await loadIdentity(resolved), { ...options, identityPath: resolved })
  }

  get identity(): Readonly<PublicAgentIdentity> {
    const { privateKey: _privateKey, walletPrivateKey: _walletPrivateKey, ...publicIdentity } =
      this.#identityValue
    return Object.freeze(publicIdentity)
  }

  /** Whether exact paid requests can recover their authorization/result across processes. */
  get hasDurablePaymentJournal(): boolean {
    return Boolean(this.#identityPath)
  }

  private url(pathWithQuery: string): URL {
    if (!pathWithQuery.startsWith('/')) throw new Error('API path must start with /')
    assertNoIdentitySecrets(pathWithQuery, this.#identityValue, 'marketplace request URL')
    const target = new URL(pathWithQuery, `${this.#identityValue.baseUrl}/`)
    assertNoIdentitySecrets(target.href, this.#identityValue, 'marketplace request URL')
    return target
  }

  private nextTimestamp(): number {
    const wallClockTimestamp = Math.floor(this.#now() / 1_000)
    const timestamp = Math.max(wallClockTimestamp, this.#lastTimestamp + 1)
    this.#lastTimestamp = timestamp
    return timestamp
  }

  private async signedRequest(
    method: string,
    pathWithQuery: string,
    body?: unknown,
  ): Promise<unknown> {
    const rawBody = requestBody(body)
    if (rawBody !== undefined) {
      assertNoIdentitySecrets(rawBody, this.#identityValue, 'marketplace request body')
    }
    const headers = await signEnvelope(
      this.#identityValue,
      method,
      pathWithQuery,
      rawBody ?? '',
      this.nextTimestamp(),
    )
    headers.set('Accept', 'application/json')
    if (rawBody !== undefined) headers.set('Content-Type', 'application/json')
    const response = await marketplaceFetch(this.#fetcher, this.url(pathWithQuery), {
      method,
      headers,
      ...(rawBody === undefined ? {} : { body: rawBody }),
    })
    return readResponse(response)
  }

  private async publicGet(pathWithQuery: string): Promise<unknown> {
    const response = await marketplaceFetch(this.#fetcher, this.url(pathWithQuery), {
      headers: { Accept: 'application/json' },
    })
    return readResponse(response)
  }

  private async createTermsAcceptanceProof(
    handle: string,
    acceptedAt: number,
  ): Promise<RegistrationTermsProof> {
    if (!Number.isSafeInteger(acceptedAt) || acceptedAt <= 0) {
      throw new Error('cannot create a Terms acceptance proof with an invalid timestamp')
    }
    const proof = {
      version: CURRENT_TERMS_VERSION,
      sha256: CURRENT_TERMS_SHA256,
      acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
      privacyVersion: CURRENT_PRIVACY_VERSION,
      acceptanceSource: 'cli',
      acceptedAt,
    } as const
    const message = termsAcceptanceMessage(
      this.#identityValue.baseUrl,
      this.#identityValue.chainId,
      handle,
      this.#identityValue.publicKey,
      this.#identityValue.wallet,
      proof.version,
      proof.sha256,
      proof.acceptableUseVersion,
      proof.privacyVersion,
      proof.acceptanceSource,
      proof.acceptedAt,
    )
    const signature = await ed.signAsync(
      new TextEncoder().encode(message),
      fromBase64(this.#identityValue.privateKey),
    )
    return { ...proof, signature: toBase64(signature) }
  }

  private paymentClient(
    paymentId: string,
    policy: MarketplacePaymentPolicy,
    nonce: Hex,
  ) {
    const wallet = privateKeyToAccount(this.#identityValue.walletPrivateKey)
    return new x402Client()
      .register(
        policy.network,
        new ExactEvmScheme(wallet),
      )
      .registerPolicy((version, requirements) =>
        version === 2
          ? requirements.filter((requirement) =>
            isExactMarketplaceRequirement(requirement, policy),
          )
          : [],
      )
      .registerExtension({
        key: PAYMENT_IDENTIFIER,
        enrichPaymentPayload: async (payload) => {
          const extensions = cloneExtensions(payload.extensions)
          appendPaymentIdentifierToExtensions(extensions, paymentId)
          if (!isRecord(payload.payload) || !isRecord(payload.payload.authorization)) {
            throw new Error('x402 client created an invalid EIP-3009 authorization')
          }
          const current = payload.payload.authorization
          if (
            typeof current.from !== 'string' ||
            typeof current.to !== 'string' ||
            typeof current.value !== 'string' ||
            typeof current.validAfter !== 'string' ||
            typeof current.validBefore !== 'string'
          ) {
            throw new Error('x402 client created an invalid EIP-3009 authorization')
          }
          const authorization = { ...current, nonce }
          const signature = await wallet.signTypedData({
            domain: {
              name: policy.domain.name,
              version: policy.domain.version,
              chainId: policy.chainId,
              verifyingContract: policy.asset,
            },
            types: authorizationTypes,
            primaryType: 'TransferWithAuthorization',
            message: {
              from: current.from as Hex,
              to: current.to as Hex,
              value: BigInt(current.value),
              validAfter: BigInt(current.validAfter),
              validBefore: BigInt(current.validBefore),
              nonce,
            },
          })
          return {
            ...payload,
            payload: { ...payload.payload, authorization, signature },
            extensions,
          }
        },
      })
  }

  private async paidRequest(
    pathWithQuery: string,
    body: unknown,
    expectedAmountAtomic: bigint,
    options: PaymentRequestOptions | undefined,
  ): Promise<unknown> {
    if (!options) throw new Error('paid operation requires spend-policy options')
    if (!this.#identityPath) {
      return this.paidRequestLocked(pathWithQuery, body, expectedAmountAtomic, options)
    }
    const identityPath = this.#identityPath
    const publicKey = this.#identityValue.publicKey
    let operationStarted = false
    try {
      return await withFileLock(
        paymentPrincipalLockFile(identityPath, publicKey),
        async () => {
          await assertPaymentPrincipalReady(identityPath, this.#identityValue)
          operationStarted = true
          return this.paidRequestLocked(pathWithQuery, body, expectedAmountAtomic, options)
        },
      )
    } catch (error) {
      if (paymentMayHaveOccurred(error) !== undefined) throw error
      throw paymentFailure(error, operationStarted)
    }
  }

  private async paidRequestLocked(
    pathWithQuery: string,
    body: unknown,
    expectedAmountAtomic: bigint,
    options: PaymentRequestOptions,
  ): Promise<unknown> {
    let paymentHeader:
      | {
          name: 'payment-signature' | 'x-payment'
          value: string
          paymentId: string
          refreshCount: number
        }
      | undefined
    let durablePaymentEvidenceMayExist = false
    try {
      const stagingCrashToken = stagingCrashTokenForRequest(
        this.#identityValue,
        pathWithQuery,
        options.stagingCrashToken,
      )
      if (!this.#identityPath) {
        throw new Error('paid marketplace calls require a durable payment-recovery journal')
      }
      const handle = this.#identityValue.handle
      if (!handle) {
        throw new Error(
          `identity is not registered; run 1f4bc register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`,
        )
      }
      const publicKey = this.#identityValue.publicKey
      const rawBody = JSON.stringify(body)
      assertNoIdentitySecrets(rawBody, this.#identityValue, 'marketplace payment body')
      const target = this.url(pathWithQuery)
      assertOfficialPaidMarketplace(target, this.#identityValue.chainId)
      const policy = marketplacePaymentPolicy(
        target,
        this.#identityValue.chainId,
        expectedAmountAtomic,
      )
      const payer = privateKeyToAccount(this.#identityValue.walletPrivateKey).address
      if (payer.toLowerCase() !== this.#identityValue.wallet.toLowerCase()) {
        throw new Error('local wallet address does not match the payment signing key')
      }
      let attemptKey = paymentAttemptKey(
        this.#identityValue,
        pathWithQuery,
        rawBody,
        expectedAmountAtomic,
      )
      const legacyAttemptKey = legacyPaymentAttemptKey(
        this.#identityValue,
        pathWithQuery,
        rawBody,
        expectedAmountAtomic,
      )
      const signingFetch = createSigningFetch(
        this.#identityValue,
        this.#fetcher,
        () => this.nextTimestamp() * 1_000,
      )
      const exactRetry = async () => {
        if (!paymentHeader) throw new Error('paid request has no captured payment authorization')
        await validateMarketplacePaymentHeader(
          paymentHeader.value,
          paymentHeader.paymentId,
          payer,
          policy,
          false,
          this.#now(),
        )
        return signingFetch(target, {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            [paymentHeader.name]: paymentHeader.value,
            ...(stagingCrashToken
              ? { [STAGING_CRASH_HEADER]: stagingCrashToken }
              : {}),
          },
          body: rawBody,
        })
      }
      const retryAmbiguous = async (
        initial: Response,
        initialWasExactRetry: boolean,
      ): Promise<{ response: Response; wasExactRetry: boolean }> => {
        let response = initial
        let wasExactRetry = initialWasExactRetry
        if (!paymentHeader) return { response, wasExactRetry }
        for (
          let attempt = 0;
          attempt < 3 && (response.status >= 500 || response.status === 409);
          attempt += 1
        ) {
          const retryAfter = Number(response.headers.get('Retry-After') ?? '0')
          await cancelResponseBody(response)
          if (Number.isFinite(retryAfter) && retryAfter > 0) {
            await new Promise((resolve) => setTimeout(resolve, Math.min(retryAfter, 60) * 1_000))
          }
          response = await exactRetry()
          wasExactRetry = true
        }
        return { response, wasExactRetry }
      }
      const complete = async (response: Response): Promise<unknown> => {
        const result = await readResponse(response)
        if (!isRecord(result) || typeof result.id !== 'string' || result.id.length === 0) {
          throw new Error('paid request returned an invalid success response; authorization retained for recovery')
        }
        // Persist the exact paid result before returning it to the spend guard.
        // A crash before the guard records its cap entry is recovered from this
        // payment-attempt journal without minting a new authorization.
        if (this.#identityPath && paymentHeader) {
          return settlePaymentAttempt(this.#identityPath, { publicKey, handle }, attemptKey, {
            paymentId: paymentHeader.paymentId,
            headerName: paymentHeader.name,
            headerValue: paymentHeader.value,
          }, result, this.#now())
        }
        return result
      }
      const finish = async (
        attempt: { response: Response; wasExactRetry: boolean },
      ): Promise<unknown> => {
        const terminalExpiredAuthorization =
          attempt.wasExactRetry &&
          authorizationExplicitlyExpired(attempt.response) &&
          paymentHeader &&
          authorizationExpiredLocally(paymentHeader, this.#now())
        if (terminalExpiredAuthorization && paymentHeader) {
          await cancelResponseBody(attempt.response)
          throw paymentFailure(
            new Error(
              'payment authorization expired; automatic replacement is disabled because the old nonce may already have been charged',
            ),
            true,
          )
        }
        return complete(attempt.response)
      }

      if (this.#identityPath) {
        // If reading an existing attempt fails validation, its authorization
        // may still have reached the server. Only a clean ENOENT proves there
        // is no durable evidence for this exact operation.
        durablePaymentEvidenceMayExist = true
        await assertNoUnnamespacedPaymentAttempts(this.#identityPath)
        const currentAttempt = await loadPaymentAttempt(this.#identityPath, publicKey, attemptKey)
        const legacyAttempt = legacyAttemptKey === attemptKey
          ? undefined
          : await loadPaymentAttempt(this.#identityPath, publicKey, legacyAttemptKey)
        if (currentAttempt && legacyAttempt) {
          throw new Error(
            'both principal-bound and legacy payment attempts exist for this operation; recover manually',
          )
        }
        const pending = currentAttempt ?? legacyAttempt
        if (!currentAttempt && legacyAttempt) attemptKey = legacyAttemptKey
        if (!pending) durablePaymentEvidenceMayExist = false
        if (pending) {
          const matches =
            (pending.version === 1 || (
              pending.publicKey === publicKey &&
              pending.handle === handle
            )) &&
            pending.baseUrl === this.#identityValue.baseUrl &&
            pending.chainId === this.#identityValue.chainId &&
            pending.wallet.toLowerCase() === this.#identityValue.wallet.toLowerCase() &&
            pending.pathWithQuery === pathWithQuery &&
            pending.bodyHash === sha256Hex(rawBody) &&
            pending.expectedAmountAtomic === expectedAmountAtomic.toString()
          if (!matches) throw new Error('payment-attempt journal entry does not match this request')
          if (pending.version === 2 && pending.state === 'terminal') {
            throw paymentFailure(
              new Error(
                'payment authorization is server-confirmed terminal; run 1f4bc recover post <job.json> --clear-terminal before retrying this exact post',
              ),
              true,
            )
          }
          if (pending.version === 2 && pending.state === 'refreshing') {
            throw paymentFailure(
              new Error(
                'legacy payment refresh state requires manual on-chain resolution; automatic replacement is disabled',
              ),
              true,
            )
          } else {
            paymentHeader = {
              name: pending.headerName,
              value: pending.headerValue,
              paymentId: pending.paymentId,
              refreshCount: pending.version === 1 ? 0 : pending.refreshCount,
            }
            if (pending.version === 2 && pending.state === 'settled') {
              return pending.result
            }
            return finish(await retryAmbiguous(await exactRetry(), true))
          }
        }
      }

      const paymentId = generatePaymentId('1f4bc_')
      const capturePaymentFetch: FetchLike = async (input, init) => {
        const request = new Request(input, { ...init, redirect: 'manual' })
        if (new URL(request.url).href !== target.href) {
          throw new Error('x402 client changed the pinned marketplace request URL')
        }
        const suppliedHeaders = (['payment-signature', 'x-payment'] as const)
          .map((name) => ({ name, value: request.headers.get(name) }))
          .filter((entry): entry is { name: 'payment-signature' | 'x-payment'; value: string } =>
            entry.value !== null,
          )
        if (suppliedHeaders.length > 1) {
          throw new Error('x402 client created conflicting payment authorization headers')
        }
        const carriesPayment = suppliedHeaders.length === 1
        for (const { name, value } of suppliedHeaders) {
          if (name !== 'payment-signature') {
            throw new Error('x402 client must use the v2 PAYMENT-SIGNATURE header')
          }
          await validateMarketplacePaymentHeader(
            value,
            paymentId,
            payer,
            policy,
            true,
            this.#now(),
          )
          let claimed = { name, value, paymentId, refreshCount: 0 }
          if (this.#identityPath) {
            const persisted = await persistPendingPayment(this.#identityPath, publicKey, attemptKey, {
              version: 2,
              state: 'pending',
              paymentId,
              publicKey,
              handle,
              baseUrl: this.#identityValue.baseUrl,
              chainId: this.#identityValue.chainId,
              wallet: this.#identityValue.wallet,
              pathWithQuery,
              bodyHash: sha256Hex(rawBody),
              expectedAmountAtomic: expectedAmountAtomic.toString(),
              headerName: name,
              headerValue: value,
              createdAt: this.#now(),
              refreshCount: 0,
            })
            if (persisted.headerName !== 'payment-signature') {
              throw new Error('stored payment authorization is not an x402 v2 header')
            }
            claimed = {
              name: persisted.headerName,
              value: persisted.headerValue,
              paymentId: persisted.paymentId,
              refreshCount: persisted.version === 1 ? 0 : persisted.refreshCount,
            }
            await validateMarketplacePaymentHeader(
              claimed.value,
              claimed.paymentId,
              payer,
              policy,
              false,
              this.#now(),
            )
            request.headers.delete('payment-signature')
            request.headers.delete('x-payment')
            request.headers.set(claimed.name, claimed.value)
          }
          paymentHeader = claimed
        }
        if (carriesPayment && stagingCrashToken) {
          request.headers.set(STAGING_CRASH_HEADER, stagingCrashToken)
        }
        const response = await signingFetch(request as unknown as RequestInfo)
        if (response.status === 402) {
          try {
            validateMarketplaceChallenge(response, policy)
          } catch (error) {
            await cancelResponseBody(response)
            throw error
          }
          if (!carriesPayment) return bodylessPaymentChallenge(response)
        }
        return response
      }
      const paidFetch = wrapFetchWithPayment(
        capturePaymentFetch,
        this.paymentClient(paymentId, policy, jobPaymentNonce(paymentId, sha256Hex(rawBody))),
      )
      const initialRequest = () =>
        paidFetch(target, {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: rawBody,
        })

      let response: Response
      let wasExactRetry = false
      try {
        response = await initialRequest()
      } catch (firstError) {
        // An interrupted settle response is ambiguous. The durable server-side
        // payment-attempt row needs the exact same EIP-3009 authorization, not
        // merely the same extension identifier, to prove recovery charge-free.
        if (!paymentHeader) throw firstError
        try {
          response = await exactRetry()
          wasExactRetry = true
        } catch {
          throw firstError
        }
      }
      return await finish(await retryAmbiguous(response, wasExactRetry))
    } catch (error) {
      const durableEvidence = paymentHeader !== undefined || durablePaymentEvidenceMayExist
      const classification = paymentMayHaveOccurred(error)
      if (durableEvidence && classification !== true) {
        throw paymentFailure(error, true)
      }
      if (classification !== undefined) throw error
      throw paymentFailure(
        error,
        durableEvidence,
      )
    }
  }

  async register(handle: string, options: RegisterOptions): Promise<RegisterResult> {
    if (
      !options ||
      typeof options.acceptedTermsVersion !== 'string' ||
      options.acceptedTermsVersion !== CURRENT_TERMS_VERSION
    ) {
      throw new Error(`registration requires explicit acceptance of Terms ${CURRENT_TERMS_VERSION}`)
    }
    if (!/^[a-z0-9-]{3,32}$/.test(handle)) throw new Error('invalid agent handle')
    const ts = Math.floor(this.#now() / 1_000)
    const { publicKey: pubkey, wallet } = this.#identityValue
    const identityMessage = registrationMessage(
      this.#identityValue.baseUrl,
      this.#identityValue.chainId,
      handle,
      pubkey,
      wallet,
      ts,
    )
    const sig = await ed.signAsync(
      new TextEncoder().encode(identityMessage),
      fromBase64(this.#identityValue.privateKey),
    )
    const terms = await this.createTermsAcceptanceProof(handle, ts)
    const account = privateKeyToAccount(this.#identityValue.walletPrivateKey)
    const walletSig = await account.signMessage({
      message: walletOwnershipMessage(
        this.#identityValue.baseUrl,
        this.#identityValue.chainId,
        handle,
        pubkey,
      ),
    })
    const response = await marketplaceFetch(this.#fetcher, this.url('/register'), {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        handle,
        pubkey,
        wallet,
        walletSig,
        sig: toBase64(sig),
        ts,
        terms,
      }),
    })
    let result: unknown
    let recoveredConflict = false
    try {
      result = await readResponse(response)
    } catch (error) {
      if (!(error instanceof MarketplaceHttpError) || error.status !== 409) throw error

      let existing: unknown
      try {
        existing = await readResponse(
          await marketplaceFetch(this.#fetcher, this.url(`/agents/${encodeURIComponent(handle)}`), {
            method: 'GET',
            headers: { Accept: 'application/json' },
          }),
        )
      } catch {
        // Preserve the registration conflict when public recovery itself is
        // unavailable; the local identity must remain unregistered.
        throw error
      }
      if (
        !isRecord(existing) ||
        existing.handle !== handle ||
        existing.pubkey !== pubkey ||
        existing.wallet !== wallet
      ) {
        throw new Error(
          `agent handle ${handle} is already registered to an identity that does not match the local identity`,
        )
      }
      // A matching public identity can be a recovered response from the
      // original registration or a pre-Terms preview identity. Before treating
      // the conflict as success, record a fresh, idempotent current acceptance
      // with the exact recovered handle. Keep the unregistered/local handle
      // unchanged until this authoritative write succeeds.
      const unresolvedIdentity = this.#identityValue
      try {
        this.#identityValue = { ...unresolvedIdentity, handle }
        const termsStatus = await this.termsStatus()
        if (!termsStatus.accepted) await this.acceptTerms(CURRENT_TERMS_VERSION)
      } finally {
        this.#identityValue = unresolvedIdentity
      }
      recoveredConflict = true
      result = { handle }
    }
    if (!isRecord(result) || result.handle !== handle) {
      throw new Error('registration returned an invalid response')
    }
    if (recoveredConflict && this.#identityPath) {
      const identityPath = this.#identityPath
      const publicKey = this.#identityValue.publicKey
      await withFileLock(paymentPrincipalLockFile(identityPath, publicKey), async () => {
        const persisted = await loadIdentity(identityPath)
        if (!sameLocalPrincipal(persisted, this.#identityValue)) {
          throw new Error('local identity principal changed during registration recovery')
        }
        const existingMarker = await loadPaymentHandleRebind(identityPath, publicKey)
        const existingStep = await loadPaymentHandleRebindStep(identityPath, publicKey)
        if (!existingMarker && existingStep) {
          throw new Error('payment-journal handle-rebind step exists without its marker')
        }
        const oldHandle = existingMarker?.oldHandle ?? this.#identityValue.handle
        if (existingMarker) {
          if (
            existingMarker.publicKey !== publicKey ||
            existingMarker.wallet !== this.#identityValue.wallet ||
            existingMarker.newHandle !== handle ||
            (this.#identityValue.handle !== existingMarker.oldHandle &&
              this.#identityValue.handle !== handle) ||
            (persisted.handle !== existingMarker.oldHandle && persisted.handle !== handle)
          ) {
            throw new Error('incomplete payment-journal handle rebind does not match this recovery')
          }
        } else if (persisted.handle !== this.#identityValue.handle) {
          throw new Error('agent handle changed on disk during registration recovery')
        }

        let marker: PaymentHandleRebind | undefined
        if (oldHandle && oldHandle !== handle) {
          marker = await rebindV2PaymentAttempts(
            identityPath,
            this.#identityValue,
            oldHandle,
            handle,
            this.#now(),
          )
        } else if (existingMarker) {
          marker = await rebindV2PaymentAttempts(
            identityPath,
            this.#identityValue,
            existingMarker.oldHandle,
            handle,
            this.#now(),
          )
        }
        if (await loadPaymentHandleRebindStep(identityPath, publicKey)) {
          throw new Error('payment-journal handle rebind did not complete')
        }

        const updated = { ...this.#identityValue, handle }
        await saveIdentity(identityPath, updated, { overwrite: true })
        this.#identityValue = updated
        if (marker) {
          await removeAndSync(paymentHandleRebindFile(identityPath, publicKey))
        }
      })
    } else {
      this.#identityValue = { ...this.#identityValue, handle }
      if (this.#identityPath) {
        await saveIdentity(this.#identityPath, this.#identityValue, { overwrite: true })
      }
    }
    return { handle }
  }

  async termsStatus(): Promise<TermsStatusResult> {
    const result = parseTermsStatusResponse(
      await this.signedRequest('GET', '/terms/status'),
      'status',
    )
    assertPinnedCurrentTerms(result.current, 'status')
    return result
  }

  async acceptTerms(version: string): Promise<TermsAcceptResult> {
    if (version !== CURRENT_TERMS_VERSION) {
      throw new Error(`Terms acceptance requires version ${CURRENT_TERMS_VERSION}`)
    }
    const handle = this.#identityValue.handle
    if (!handle) {
      throw new Error(
        `identity is not registered; run 1f4bc register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`,
      )
    }
    const acceptedAt = Math.floor(this.#now() / 1_000)
    const terms = await this.createTermsAcceptanceProof(handle, acceptedAt)
    const result = parseTermsAcceptResponse(
      await this.signedRequest('POST', '/terms/accept', { terms }),
    )
    assertPinnedCurrentTerms(result.current, 'acceptance')
    const acceptance = result.acceptance
    if (
      acceptance.signatureOrigin !== this.#identityValue.baseUrl ||
      acceptance.signatureChainId !== this.#identityValue.chainId ||
      acceptance.signatureVersion !== TERMS_ACCEPTANCE_SIGNATURE_VERSION ||
      (result.created && (
        acceptance.acceptedAt !== acceptedAt ||
        acceptance.acceptanceSource !== 'cli' ||
        acceptance.acceptedPubkey !== this.#identityValue.publicKey ||
        acceptance.acceptedWallet.toLowerCase() !== this.#identityValue.wallet.toLowerCase()
      ))
    ) {
      throw new Error('Terms acceptance returned evidence for a different subject or proof')
    }
    return result
  }

  setProfile(profile: unknown): Promise<unknown> {
    if (!this.#identityValue.handle) throw new Error('identity is not registered')
    return this.signedRequest('PUT', `/agents/${encodeURIComponent(this.#identityValue.handle)}`, profile)
  }

  async postJob(job: unknown, options: PaymentRequestOptions): Promise<unknown> {
    const claimed = claimAuthorizedPaymentControl(
      options?.control,
      'post_job',
      { job },
      POST_FEE_ATOMIC,
      spendPolicyScope(this.#identityValue.chainId, this.#identityValue.wallet),
    )
    return this.paidRequest('/jobs', claimed.job, POST_FEE_ATOMIC, options)
  }

  private async recoverPostJobLocked(rawBody: string): Promise<{
    result: JobPaymentRecoveryResult
    attemptKey: string
    attempt: PaymentAttempt
    archived: boolean
  }> {
    if (!this.#identityPath) {
      throw new Error('job payment recovery requires a durable payment-recovery journal')
    }
    const handle = this.#identityValue.handle
    if (!handle) {
      throw new Error(
        `identity is not registered; run 1f4bc register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`,
      )
    }
    assertNoIdentitySecrets(rawBody, this.#identityValue, 'marketplace payment body')
    const publicKey = this.#identityValue.publicKey
    let attemptKey = paymentAttemptKey(
      this.#identityValue,
      '/jobs',
      rawBody,
      POST_FEE_ATOMIC,
    )
    const legacyKey = legacyPaymentAttemptKey(
      this.#identityValue,
      '/jobs',
      rawBody,
      POST_FEE_ATOMIC,
    )
    await assertNoUnnamespacedPaymentAttempts(this.#identityPath)
    const current = await loadPaymentAttempt(this.#identityPath, publicKey, attemptKey)
    const legacy = legacyKey === attemptKey
      ? undefined
      : await loadPaymentAttempt(this.#identityPath, publicKey, legacyKey)
    if (current && legacy) {
      throw new Error('both principal-bound and legacy payment attempts exist for this operation')
    }
    let attempt = current ?? legacy
    let archived = false
    if (!current && legacy) attemptKey = legacyKey
    if (!attempt) {
      attempt = await loadArchivedTerminalPaymentAttempt(
        this.#identityPath,
        publicKey,
        attemptKey,
      )
      archived = attempt !== undefined
    }
    if (!attempt && legacyKey !== attemptKey) {
      attempt = await loadArchivedTerminalPaymentAttempt(
        this.#identityPath,
        publicKey,
        legacyKey,
      )
      if (attempt) {
        attemptKey = legacyKey
        archived = true
      }
    }
    if (!attempt) throw new Error('no retained payment authorization exists for this exact job body')
    const bodyHash = sha256Hex(rawBody)
    const matches =
      (attempt.version === 1 || (
        attempt.publicKey === publicKey &&
        attempt.handle === handle
      )) &&
      attempt.baseUrl === this.#identityValue.baseUrl &&
      attempt.chainId === this.#identityValue.chainId &&
      attempt.wallet.toLowerCase() === this.#identityValue.wallet.toLowerCase() &&
      attempt.pathWithQuery === '/jobs' &&
      attempt.bodyHash === bodyHash &&
      attempt.expectedAmountAtomic === POST_FEE_ATOMIC.toString() &&
      paymentAttemptKeyFor({
        ...attempt,
        publicKey,
        handle,
        refreshCount: attempt.version === 1 ? 0 : attempt.refreshCount,
      }) === paymentAttemptKey(this.#identityValue, '/jobs', rawBody, POST_FEE_ATOMIC)
    if (!matches) throw new Error('payment-attempt journal entry does not match this recovery')
    if (attempt.version === 2 && attempt.state === 'settled') {
      return {
        result: {
          operation: 'POST /jobs',
          paymentId: attempt.paymentId,
          bodyHash,
          state: 'committed',
          result: { id: String(attempt.result.id) },
          cleared: archived,
          ...(archived ? { archived: true } : {}),
        },
        attemptKey,
        attempt,
        archived,
      }
    }

    const target = this.url('/jobs')
    assertOfficialPaidMarketplace(target, this.#identityValue.chainId)
    const policy = marketplacePaymentPolicy(target, this.#identityValue.chainId, POST_FEE_ATOMIC)
    const payer = privateKeyToAccount(this.#identityValue.walletPrivateKey).address
    await validateMarketplacePaymentHeader(
      attempt.headerValue,
      attempt.paymentId,
      payer,
      policy,
      false,
      this.#now(),
    )
    const decoded = decodePaymentSignatureHeader(attempt.headerValue)
    const authorization = decoded.payload.authorization
    if (
      !isRecord(authorization) ||
      typeof authorization.from !== 'string' ||
      typeof authorization.nonce !== 'string' ||
      typeof authorization.validBefore !== 'string' ||
      !/^[1-9][0-9]{0,15}$/.test(authorization.validBefore)
    ) {
      throw new Error('retained payment authorization is invalid')
    }
    const validBefore = Number(authorization.validBefore)
    if (!Number.isSafeInteger(validBefore)) {
      throw new Error('retained payment authorization is invalid')
    }
    const recoveryPath = `/payment-attempts/jobs/${encodeURIComponent(attempt.paymentId)}` +
      `?bodyHash=${encodeURIComponent(bodyHash)}`
    const headers = await signEnvelope(
      this.#identityValue,
      'GET',
      recoveryPath,
      '',
      this.nextTimestamp(),
    )
    headers.set('Accept', 'application/json')
    headers.set('PAYMENT-SIGNATURE', attempt.headerValue)
    headers.set('X-1F4BC-Recovery-Signature', await privateKeyToAccount(
      this.#identityValue.walletPrivateKey,
    ).signMessage({
      message: jobPaymentRecoveryMessage(
        target.origin,
        this.#identityValue.chainId,
        attempt.paymentId,
        bodyHash,
        authorization.from,
        authorization.nonce,
        validBefore,
      ),
    }))
    const response = await marketplaceFetch(
      this.#fetcher,
      this.url(recoveryPath),
      { method: 'GET', headers },
    )
    const recovered = await readResponse(response)
    if (
      !isRecord(recovered) ||
      recovered.operation !== 'POST /jobs' ||
      recovered.paymentId !== attempt.paymentId ||
      recovered.bodyHash !== bodyHash ||
      !['pending', 'settled', 'committed', 'terminal'].includes(String(recovered.state))
    ) {
      throw new Error('payment recovery returned a conflicting result')
    }
    const state = recovered.state as JobPaymentRecoveryResult['state']
    if (attempt.version === 2 && attempt.state === 'terminal' && state !== 'terminal') {
      throw new Error('payment recovery contradicted a terminal local payment record')
    }
    if (archived && state !== 'terminal') {
      throw new Error('payment recovery contradicted a terminal archive')
    }
    if (state === 'committed') {
      if (!isRecord(recovered.result) || typeof recovered.result.id !== 'string' || !recovered.result.id) {
        throw new Error('payment recovery returned an invalid committed result')
      }
      const result = await settlePaymentAttempt(
        this.#identityPath,
        { publicKey, handle },
        attemptKey,
        {
          paymentId: attempt.paymentId,
          headerName: attempt.headerName,
          headerValue: attempt.headerValue,
        },
        { id: recovered.result.id },
        this.#now(),
      )
      return {
        result: {
          operation: 'POST /jobs',
          paymentId: attempt.paymentId,
          bodyHash,
          state,
          result: { id: String(result.id) },
          cleared: false,
        },
        attemptKey,
        attempt,
        archived,
      }
    }
    if (recovered.result !== null) throw new Error('payment recovery returned an invalid result')
    let resolvedAttempt = attempt
    if (state === 'terminal' && !archived) {
      resolvedAttempt = await markTerminalPaymentAttempt(
        this.#identityPath,
        { publicKey, handle },
        attemptKey,
        {
          paymentId: attempt.paymentId,
          headerName: attempt.headerName,
          headerValue: attempt.headerValue,
        },
        this.#now(),
      )
    }
    return {
      result: {
        operation: 'POST /jobs',
        paymentId: attempt.paymentId,
        bodyHash,
        state,
        result: null,
        cleared: archived,
        ...(archived ? { archived: true } : {}),
      },
      attemptKey,
      attempt: resolvedAttempt,
      archived,
    }
  }

  async recoverPostJob(job: unknown): Promise<JobPaymentRecoveryResult> {
    if (!this.#identityPath) {
      throw new Error('job payment recovery requires a durable payment-recovery journal')
    }
    const rawBody = JSON.stringify(job)
    return withFileLock(
      paymentPrincipalLockFile(this.#identityPath, this.#identityValue.publicKey),
      async () => {
        await assertPaymentPrincipalReady(this.#identityPath!, this.#identityValue)
        return (await this.recoverPostJobLocked(rawBody)).result
      },
    )
  }

  /** @internal Two-phase capability boundary; use clearTerminalPostJob(). */
  async stageTerminalPostJobClear(job: unknown, control: SpendControl): Promise<never> {
    const claimed = claimAuthorizedPaymentControl(
      control,
      'post_job',
      { job },
      POST_FEE_ATOMIC,
      spendPolicyScope(this.#identityValue.chainId, this.#identityValue.wallet),
    )
    if (!this.#identityPath) {
      throw paymentFailure(
        new Error('job payment recovery requires a durable payment-recovery journal'),
        true,
      )
    }
    const rawBody = JSON.stringify(claimed.job)
    return withFileLock(
      paymentPrincipalLockFile(this.#identityPath, this.#identityValue.publicKey),
      async () => {
        await assertPaymentPrincipalReady(this.#identityPath!, this.#identityValue)
        const recovered = await this.recoverPostJobLocked(rawBody)
        if (recovered.result.state !== 'terminal') {
          throw paymentFailure(
            new Error('payment authorization is not server-confirmed terminal'),
            true,
          )
        }
        if (!recovered.archived) {
          await stageTerminalPaymentArchive(
            this.#identityPath!,
            this.#identityValue.publicKey,
            recovered.attemptKey,
            {
              paymentId: recovered.attempt.paymentId,
              headerName: recovered.attempt.headerName,
              headerValue: recovered.attempt.headerValue,
            },
          )
        }
        throw terminalPaymentCleared({
          publicKey: this.#identityValue.publicKey,
          attemptKey: recovered.attemptKey,
          paymentId: recovered.attempt.paymentId,
          bodyHash: recovered.result.bodyHash,
        })
      },
    )
  }

  /** @internal Two-phase capability boundary; use clearTerminalPostJob(). */
  async finalizeTerminalPostJobClear(
    job: unknown,
    completion: TerminalPaymentCleared,
  ): Promise<void> {
    if (!this.#identityPath) {
      throw new Error('job payment recovery requires a durable payment-recovery journal')
    }
    const rawBody = JSON.stringify(job)
    await withFileLock(
      paymentPrincipalLockFile(this.#identityPath, this.#identityValue.publicKey),
      async () => {
        await assertPaymentPrincipalReady(this.#identityPath!, this.#identityValue)
        const currentKey = paymentAttemptKey(
          this.#identityValue,
          '/jobs',
          rawBody,
          POST_FEE_ATOMIC,
        )
        const legacyKey = legacyPaymentAttemptKey(
          this.#identityValue,
          '/jobs',
          rawBody,
          POST_FEE_ATOMIC,
        )
        const binding = consumeTerminalPaymentClear(completion, {
          publicKey: this.#identityValue.publicKey,
          bodyHash: sha256Hex(rawBody),
          attemptKeys: currentKey === legacyKey ? [currentKey] : [currentKey, legacyKey],
        })
        let attempt = await loadPaymentAttempt(
          this.#identityPath!,
          this.#identityValue.publicKey,
          binding.attemptKey,
        )
        const key = binding.attemptKey
        let archived = await loadArchivedTerminalPaymentAttempt(
          this.#identityPath!,
          this.#identityValue.publicKey,
          key,
        )
        const exact = attempt ?? archived
        if (
          !exact ||
          exact.version !== 2 ||
          exact.state !== 'terminal' ||
          exact.paymentId !== binding.paymentId
        ) {
          throw new Error('server-confirmed terminal payment attempt is missing')
        }
        await finalizeTerminalPaymentArchive(
          this.#identityPath!,
          this.#identityValue.publicKey,
          key,
          {
            paymentId: exact.paymentId,
            headerName: exact.headerName,
            headerValue: exact.headerValue,
          },
        )
      },
    )
  }

  /**
   * Explicitly clear one server-confirmed terminal job authorization. The
   * concrete shared spend guard durably releases the ambiguous reservation
   * before the active tombstone is removed; every other error is rethrown.
   */
  async clearTerminalPostJob(
    job: unknown,
    guard: McpSpendGuard,
  ): Promise<TerminalPostClearResult> {
    if (!(guard instanceof McpSpendGuard)) {
      throw new Error('terminal payment clear requires the official spend-policy guard')
    }
    try {
      await guard.execute(
        'post_job',
        { job },
        POST_FEE_ATOMIC,
        (control) => this.stageTerminalPostJobClear(job, control),
      )
      throw new Error('terminal payment clear returned unexpectedly')
    } catch (error) {
      if (!(error instanceof TerminalPaymentCleared)) throw error
      await this.finalizeTerminalPostJobClear(job, error)
      return error.result
    }
  }

  async bidPaymentAmount(jobId: string): Promise<bigint> {
    if (!this.#identityValue.handle) throw new Error('identity is not registered')
    await this.getJob(jobId)
    return BID_FEE_ATOMIC
  }

  async bid(
    jobId: string,
    bid: unknown,
    options: PaymentRequestOptions,
  ): Promise<unknown> {
    const claimed = claimAuthorizedPaymentControl(
      options?.control,
      'bid_job',
      { jobId, bid },
      BID_FEE_ATOMIC,
      spendPolicyScope(this.#identityValue.chainId, this.#identityValue.wallet),
    )
    if (!this.#identityPath) {
      throw paymentFailure(
        new Error('paid marketplace calls require a durable payment-recovery journal'),
        false,
      )
    }
    let amount: bigint
    try {
      amount = await this.bidPaymentAmount(claimed.jobId)
      if (
        options.expectedAmountAtomic !== undefined &&
        options.expectedAmountAtomic !== amount
      ) {
        throw new Error('bid payment amount changed after the local spend reservation')
      }
    } catch (error) {
      throw paymentFailure(error, false)
    }
    return this.paidRequest(
      `/jobs/${encodeURIComponent(claimed.jobId)}/bids`,
      claimed.bid,
      amount,
      options,
    )
  }

  award(jobId: string, bidId: string): Promise<unknown> {
    return this.signedRequest('POST', `/jobs/${encodeURIComponent(jobId)}/award`, { bidId })
  }

  message(jobId: string, bidId: string, body: string): Promise<unknown> {
    return this.signedRequest(
      'POST',
      `/jobs/${encodeURIComponent(jobId)}/threads/${encodeURIComponent(bidId)}/messages`,
      { body },
    )
  }

  thread(jobId: string, bidId: string, after?: number, limit = 100): Promise<unknown> {
    if (after !== undefined && (!Number.isSafeInteger(after) || after < 0)) {
      throw new Error('thread cursor must be a non-negative integer')
    }
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error('thread limit must be an integer from 1 to 100')
    }
    const params = new URLSearchParams()
    if (after !== undefined) params.set('after', String(after))
    if (limit !== 100) params.set('limit', String(limit))
    const query = params.size === 0 ? '' : `?${params}`
    return this.signedRequest(
      'GET',
      `/jobs/${encodeURIComponent(jobId)}/threads/${encodeURIComponent(bidId)}${query}`,
    )
  }

  inbox(after?: number): Promise<unknown> {
    const query = after === undefined ? '' : `?after=${after}`
    return this.signedRequest('GET', `/inbox${query}`)
  }

  proof(input: {
    jobId: string
    worker: string
    txHash: string
    logIndex: number
    amountAtomic: string
    chainId?: number
  }): Promise<unknown> {
    return this.signedRequest('POST', '/proofs', {
      ...input,
      chainId: input.chainId ?? this.#identityValue.chainId,
    })
  }

  search(type: 'profiles' | 'jobs' | 'listings', tag?: string, q?: string): Promise<unknown> {
    const params = new URLSearchParams({ type })
    if (tag) params.set('tag', tag)
    if (q) params.set('q', q)
    return this.publicGet(`/search?${params}`)
  }

  getJob(id: string): Promise<unknown> {
    return this.publicGet(`/jobs/${encodeURIComponent(id)}`)
  }

  getAgent(handle: string): Promise<unknown> {
    return this.publicGet(`/agents/${encodeURIComponent(handle)}`)
  }

  ledger(after?: number, limit = 100): Promise<unknown> {
    const params = new URLSearchParams({ limit: String(limit) })
    if (after !== undefined) params.set('after', String(after))
    return this.publicGet(`/ledger?${params}`)
  }

  marketplaceRules(): Promise<unknown> {
    return this.publicGet('/llms.txt')
  }

  private async findProof(proofId: number): Promise<JsonRecord> {
    const proof = await this.publicGet(`/proofs/${proofId}`)
    if (!isRecord(proof) || Number(proof.proofId ?? proof.id) !== proofId) {
      throw new Error(`proof ${proofId} returned invalid public detail`)
    }
    return proof
  }

  async signAttestation(proofId: number): Promise<AttestationSignature> {
    if (!this.#identityValue.handle) throw new Error('identity is not registered')
    const proof = await this.findProof(proofId)
    const jobIdValue = proof.job_id ?? proof.jobId
    const workerValue = proof.worker
    if (typeof jobIdValue !== 'string' || typeof workerValue !== 'string') {
      throw new Error(`proof ${proofId} has incomplete ledger detail`)
    }
    const job = await this.getJob(jobIdValue)
    if (!isRecord(job) || typeof job.poster !== 'string') {
      throw new Error(`job ${jobIdValue} has incomplete detail`)
    }
    let role: 'poster' | 'worker'
    if (this.#identityValue.handle === workerValue) role = 'worker'
    else if (this.#identityValue.handle === job.poster) role = 'poster'
    else throw new Error('only the job poster or worker can attest this proof')

    const message = attestationMessage(
      this.#identityValue.baseUrl,
      this.#identityValue.chainId,
      proofId,
      jobIdValue,
    )
    const signature = await ed.signAsync(
      new TextEncoder().encode(message),
      fromBase64(this.#identityValue.privateKey),
    )
    return {
      proofId,
      jobId: jobIdValue,
      handle: this.#identityValue.handle,
      role,
      signature: toBase64(signature),
      message,
    }
  }

  async submitAttestation(proofId: number, otherSignature: string): Promise<unknown> {
    const own = await this.signAttestation(proofId)
    return this.signedRequest('POST', '/attestations', {
      proofId,
      posterSig: own.role === 'poster' ? own.signature : otherSignature,
      workerSig: own.role === 'worker' ? own.signature : otherSignature,
    })
  }
}
