import { constants, type Stats } from 'node:fs'
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
} from 'node:fs/promises'
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto'
import { homedir } from 'node:os'
import { dirname, resolve } from 'node:path'
import * as ed from '@noble/ed25519'
import { getAddress, isAddress } from 'viem'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

const IDENTITY_VERSION = 1 as const
const PRIVATE_FILE_MODE = 0o600
const PRIVATE_DIRECTORY_MODE = 0o700
const IDENTITY_FILE_MAX_BYTES = 64 * 1024
const IS_UNIX = process.platform !== 'win32'
const ORIGIN_ONLY = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]+\/?$/
type Hex = `0x${string}`

export const DEFAULT_IDENTITY_PATH = resolve(homedir(), '.1f4bc', 'identity.json')
export const LEGACY_IDENTITY_PATH = resolve(homedir(), '.agent-bazaar', 'identity.json')
export const DEFAULT_MARKETPLACE_URL = 'https://1f4bc.ai'
export const DEFAULT_CHAIN_ID = 8453

export type AgentIdentity = {
  version: typeof IDENTITY_VERSION
  handle?: string
  privateKey: string
  publicKey: string
  walletPrivateKey: Hex
  wallet: `0x${string}`
  baseUrl: string
  chainId: number
  createdAt: number
}

export type InitIdentityOptions = {
  walletPrivateKey: string
  baseUrl?: string
  chainId?: number
  now?: () => number
}

function assertSecureSecretPlatform(): void {
  if (!IS_UNIX) {
    throw new Error(
      '1f4bc identity storage is disabled on Windows until native ACL enforcement is implemented',
    )
  }
}

export function identityPath(path?: string, homeDirectory = homedir()): string {
  if (!path) return resolve(homeDirectory, '.1f4bc', 'identity.json')
  if (path === '~') return homeDirectory
  if (path.startsWith('~/')) return resolve(homeDirectory, path.slice(2))
  return resolve(path)
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

export function fromBase64(value: string): Uint8Array {
  if (
    typeof value !== 'string' ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new Error('value must use canonical base64')
  }
  const decoded = Buffer.from(value, 'base64')
  if (decoded.toString('base64') !== value) {
    throw new Error('value must use canonical base64')
  }
  return new Uint8Array(decoded)
}

// Noble deliberately leaves the synchronous SHA-512 primitive unconfigured.
// The CLI is Node-only, so bind it to Node's audited crypto implementation and
// use one synchronous derivation path in every public client constructor.
ed.hashes.sha512 = (message: Uint8Array) =>
  Uint8Array.from(createHash('sha512').update(message).digest())

export function deriveEd25519PublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.byteLength !== 32) throw new Error('Ed25519 private key must be 32 bytes')
  return ed.getPublicKey(privateKey)
}

export function normalizeBaseUrl(value: string): string {
  if (typeof value !== 'string' || value.trim() !== value || !ORIGIN_ONLY.test(value)) {
    throw new Error('marketplace URL must be an origin without a path, query, or fragment')
  }
  const url = new URL(value)
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('marketplace URL must use http or https')
  }
  if (url.username || url.password) throw new Error('marketplace URL must not contain credentials')
  if (
    url.protocol === 'http:' &&
    url.hostname !== 'localhost' &&
    url.hostname !== '127.0.0.1' &&
    url.hostname !== '[::1]'
  ) {
    throw new Error('marketplace URL must use HTTPS unless it is a loopback development URL')
  }
  return url.origin
}

function walletAccount(value: string): {
  privateKey: Hex
  address: `0x${string}`
} {
  const normalized = typeof value === 'string'
    ? (value.startsWith('0x') ? value : `0x${value}`)
    : ''
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error('wallet private key is invalid')
  }
  const privateKey = normalized.toLowerCase() as Hex
  try {
    return { privateKey, address: privateKeyToAccount(privateKey).address }
  } catch {
    // viem's scalar validation includes the invalid scalar in its exception.
    // Keep local key-validation errors deliberately generic.
    throw new Error('wallet private key is invalid')
  }
}

export function normalizeWalletPrivateKey(value: string): Hex {
  return walletAccount(value).privateKey
}

export function generateWalletPrivateKey(): Hex {
  return generatePrivateKey()
}

function isSafeChainId(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

function identityKey(value: unknown, kind: 'private' | 'public'): Uint8Array {
  if (typeof value !== 'string') {
    throw new Error(`identity file has an invalid Ed25519 ${kind} key`)
  }
  let decoded: Uint8Array
  try {
    decoded = fromBase64(value)
  } catch {
    throw new Error(`identity file has an invalid Ed25519 ${kind} key`)
  }
  if (decoded.byteLength !== 32) {
    throw new Error(`identity file has an invalid Ed25519 ${kind} key`)
  }
  return decoded
}

async function validateIdentity(value: unknown): Promise<AgentIdentity> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('identity file is not an object')
  }
  const row = value as Partial<AgentIdentity>
  if (row.version !== IDENTITY_VERSION) throw new Error('unsupported identity file version')
  if (row.handle !== undefined && !/^[a-z0-9-]{3,32}$/.test(row.handle)) {
    throw new Error('identity file has an invalid handle')
  }

  const privateKeyBytes = identityKey(row.privateKey, 'private')
  const publicKeyBytes = identityKey(row.publicKey, 'public')
  const derivedPublicKey = deriveEd25519PublicKey(privateKeyBytes)
  if (!timingSafeEqual(Buffer.from(publicKeyBytes), Buffer.from(derivedPublicKey))) {
    throw new Error('identity public key does not match its private key')
  }

  if (typeof row.walletPrivateKey !== 'string') {
    throw new Error('identity file has no wallet private key')
  }
  const derivedWallet = walletAccount(row.walletPrivateKey)
  if (typeof row.wallet !== 'string' || !isAddress(row.wallet)) {
    throw new Error('identity file has an invalid wallet address')
  }
  if (getAddress(row.wallet) !== derivedWallet.address) {
    throw new Error('identity wallet address does not match its private key')
  }
  if (typeof row.baseUrl !== 'string') throw new Error('identity file has no marketplace URL')
  if (!isSafeChainId(row.chainId)) throw new Error('identity file has an invalid chain id')
  if (
    typeof row.createdAt !== 'number' ||
    !Number.isSafeInteger(row.createdAt) ||
    row.createdAt < 0
  ) {
    throw new Error('identity file has an invalid creation timestamp')
  }

  return {
    version: IDENTITY_VERSION,
    ...(row.handle ? { handle: row.handle } : {}),
    privateKey: toBase64(privateKeyBytes),
    publicKey: toBase64(derivedPublicKey),
    walletPrivateKey: derivedWallet.privateKey,
    wallet: derivedWallet.address,
    baseUrl: normalizeBaseUrl(row.baseUrl),
    chainId: row.chainId,
    createdAt: row.createdAt,
  }
}

function currentUserId(): number | undefined {
  if (!IS_UNIX) return undefined
  if (typeof process.geteuid === 'function') return process.geteuid()
  if (typeof process.getuid === 'function') return process.getuid()
  return undefined
}

function assertIdentityFileStats(info: Stats, path: string): void {
  if (info.isSymbolicLink()) {
    throw new Error(`identity file must not be a symbolic link: ${path}`)
  }
  if (!info.isFile()) throw new Error(`identity path must be a regular file: ${path}`)
  if (info.nlink !== 1) throw new Error(`identity file has an unsafe link count: ${path}`)
  if (!IS_UNIX) return

  const userId = currentUserId()
  if (userId !== undefined && info.uid !== userId) {
    throw new Error(`identity file is not owned by the current user: ${path}`)
  }
  if ((info.mode & 0o077) !== 0) {
    throw new Error(`identity file has unsafe permissions: ${path}`)
  }
}

function assertIdentityDirectoryStats(info: Stats, path: string): void {
  if (info.isSymbolicLink()) {
    throw new Error(`identity directory must not be a symbolic link: ${path}`)
  }
  if (!info.isDirectory()) throw new Error(`identity parent is not a directory: ${path}`)
  if (!IS_UNIX) return

  const userId = currentUserId()
  if (userId !== undefined && info.uid !== userId) {
    throw new Error(`identity directory is not owned by the current user: ${path}`)
  }
  if ((info.mode & 0o022) !== 0) {
    throw new Error(`identity directory has unsafe write permissions: ${path}`)
  }
}

async function lstatIfExists(path: string): Promise<Stats | null> {
  try {
    return await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

async function assertExistingIdentityPath(path: string): Promise<void> {
  const info = await lstatIfExists(path)
  if (info) {
    assertIdentityDirectoryStats(await lstat(dirname(path)), dirname(path))
    assertIdentityFileStats(info, path)
  }
}

async function syncDirectory(path: string): Promise<void> {
  let handle
  try {
    handle = await open(path, constants.O_RDONLY)
    await handle.sync()
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    // Windows does not consistently support opening/fsyncing directory
    // handles. File fsync remains mandatory on every platform.
    if (
      process.platform === 'win32' &&
      ['EACCES', 'EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(code ?? '')
    ) {
      return
    }
    throw error
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

async function hardenSecretTree(path: string): Promise<void> {
  const info = await lstat(path)
  if (info.isSymbolicLink()) {
    throw new Error(`legacy secret tree contains a symbolic link: ${path}`)
  }
  if (info.isDirectory()) {
    if (IS_UNIX) await chmod(path, PRIVATE_DIRECTORY_MODE)
    for (const entry of await readdir(path)) {
      await hardenSecretTree(resolve(path, entry))
    }
    await syncDirectory(path)
    return
  }
  if (!info.isFile()) {
    throw new Error(`legacy secret tree contains a non-regular file: ${path}`)
  }
  if (info.nlink !== 1) {
    throw new Error(`legacy secret tree contains a hard-linked file: ${path}`)
  }

  // chmod is never invoked on a symlink. Re-open without following links on
  // Unix, then fsync the secret file after its permissions are hardened.
  const noFollow = IS_UNIX ? constants.O_NOFOLLOW : 0
  const handle = await open(path, constants.O_RDONLY | noFollow)
  try {
    const opened = await handle.stat()
    if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino) {
      throw new Error(`legacy secret tree changed while it was hardened: ${path}`)
    }
    if (IS_UNIX) await handle.chmod(PRIVATE_FILE_MODE)
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function readIdentityFile(path: string): Promise<string> {
  assertIdentityDirectoryStats(await lstat(dirname(path)), dirname(path))
  let initial: Stats
  try {
    initial = await lstat(path)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`no agent identity at ${path}; run 1f4bc init first`)
    }
    throw error
  }
  assertIdentityFileStats(initial, path)
  if (initial.size > IDENTITY_FILE_MAX_BYTES) throw new Error('identity file is too large')

  const noFollow = IS_UNIX ? constants.O_NOFOLLOW : 0
  const handle = await open(path, constants.O_RDONLY | noFollow)
  try {
    const opened = await handle.stat()
    assertIdentityFileStats(opened, path)
    if (opened.dev !== initial.dev || opened.ino !== initial.ino) {
      throw new Error('identity file changed while it was opened')
    }
    const raw = await handle.readFile({ encoding: 'utf8' })
    if (Buffer.byteLength(raw) > IDENTITY_FILE_MAX_BYTES) {
      throw new Error('identity file is too large')
    }
    const final = await lstat(path)
    assertIdentityFileStats(final, path)
    if (final.dev !== opened.dev || final.ino !== opened.ino) {
      throw new Error('identity file changed while it was read')
    }
    return raw
  } finally {
    await handle.close()
  }
}

/**
 * Resolves the default 1f4bc identity and, when only the pre-release
 * directory exists, hardens and validates that tree before atomically moving
 * it to the current namespace. Both directories share the same home
 * filesystem, so a successful rename never leaves a second plaintext key.
 */
export async function resolveIdentityPath(
  path?: string,
  homeDirectory = homedir(),
  env: Record<string, string | undefined> = process.env,
): Promise<string> {
  assertSecureSecretPlatform()
  const configured = path ?? env.F4BC_IDENTITY
  if (configured) {
    const target = identityPath(configured, homeDirectory)
    await assertExistingIdentityPath(target)
    return target
  }

  const currentIdentity = identityPath(undefined, homeDirectory)
  const currentInfo = await lstatIfExists(currentIdentity)
  if (currentInfo) {
    await assertExistingIdentityPath(currentIdentity)
    return currentIdentity
  }

  const legacyIdentity = resolve(homeDirectory, '.agent-bazaar', 'identity.json')
  const legacyInfo = await lstatIfExists(legacyIdentity)
  if (!legacyInfo) return currentIdentity
  if (legacyInfo.isSymbolicLink() || !legacyInfo.isFile()) {
    assertIdentityFileStats(legacyInfo, legacyIdentity)
  }
  const legacyDirectory = dirname(legacyIdentity)
  const legacyDirectoryInfo = await lstat(legacyDirectory)
  if (legacyDirectoryInfo.isSymbolicLink() || !legacyDirectoryInfo.isDirectory()) {
    throw new Error(`legacy identity directory must be a regular directory: ${legacyDirectory}`)
  }
  if (IS_UNIX) {
    const userId = currentUserId()
    if (userId !== undefined && legacyDirectoryInfo.uid !== userId) {
      throw new Error(`legacy identity directory is not owned by the current user: ${legacyDirectory}`)
    }
    if (userId !== undefined && legacyInfo.uid !== userId) {
      throw new Error(`legacy identity file is not owned by the current user: ${legacyIdentity}`)
    }
  }

  const currentDirectory = dirname(currentIdentity)
  let readyToMove = false
  let moved = false
  try {
    await hardenSecretTree(legacyDirectory)
    const legacyRaw = await readIdentityFile(legacyIdentity)
    let canonicalLegacy: AgentIdentity
    try {
      canonicalLegacy = await validateIdentity(JSON.parse(legacyRaw) as unknown)
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error('legacy identity file contains invalid JSON')
      throw error
    }
    await saveIdentity(legacyIdentity, canonicalLegacy, { overwrite: true })
    readyToMove = true
    await rename(legacyDirectory, currentDirectory)
    moved = true
    await syncDirectory(homeDirectory)
    return currentIdentity
  } catch (error) {
    if (moved) throw error
    const winner = await lstatIfExists(currentIdentity)
    const legacyStillExists = await lstatIfExists(legacyDirectory)
    // Another process may have completed the same move first. Accept it only
    // when the legacy directory is gone, so successful resolution can never
    // silently leave two key-bearing trees.
    if (winner && !legacyStillExists) {
      await assertExistingIdentityPath(currentIdentity)
      return currentIdentity
    }
    if (winner && legacyStillExists) {
      throw new Error(
        `both ${currentDirectory} and ${legacyDirectory} exist; inspect them and remove the obsolete key-bearing directory manually`,
        { cause: error },
      )
    }
    if (readyToMove && legacyStillExists) {
      throw new Error(
        `automatic identity migration could not move ${legacyDirectory} to ${currentDirectory}; complete the move manually before continuing`,
        { cause: error },
      )
    }
    throw error
  }
}

async function ensureIdentityParent(path: string): Promise<void> {
  const existing = await lstatIfExists(path)
  if (!existing) {
    await mkdir(path, { recursive: true, mode: PRIVATE_DIRECTORY_MODE })
  }
  const info = await lstat(path)
  assertIdentityDirectoryStats(info, path)
}

export async function saveIdentity(
  path: string,
  identity: AgentIdentity,
  options: { overwrite?: boolean } = {},
): Promise<AgentIdentity> {
  assertSecureSecretPlatform()
  const canonical = await validateIdentity(identity)
  const target = identityPath(path)
  const existing = await lstatIfExists(target)
  if (existing) {
    assertIdentityFileStats(existing, target)
    if (!options.overwrite) {
      throw new Error(`identity already exists at ${target}; refusing to replace key material`)
    }
  }

  const parent = dirname(target)
  await ensureIdentityParent(parent)
  const temporary = `${target}.tmp-${process.pid}-${randomUUID()}`
  let temporaryExists = false
  try {
    const handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      PRIVATE_FILE_MODE,
    )
    temporaryExists = true
    try {
      if (IS_UNIX) await handle.chmod(PRIVATE_FILE_MODE)
      await handle.writeFile(`${JSON.stringify(canonical, null, 2)}\n`, { encoding: 'utf8' })
      await handle.sync()
    } finally {
      await handle.close()
    }

    if (options.overwrite) {
      // rename is atomic and replaces the directory entry itself; it never
      // follows a target symlink. Existing unsafe targets were rejected above.
      await rename(temporary, target)
    } else {
      // A hard-link installation is the portable Node primitive that is both
      // atomic and no-clobber. The temporary and target are on the same volume.
      try {
        await link(temporary, target)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new Error(`identity already exists at ${target}; refusing to replace key material`)
        }
        throw error
      }
      await rm(temporary, { force: true })
    }
    temporaryExists = false
    await syncDirectory(parent)
    return canonical
  } finally {
    if (temporaryExists) {
      await rm(temporary, { force: true }).catch(() => undefined)
    }
  }
}

export async function initIdentity(path: string, options: InitIdentityOptions): Promise<AgentIdentity> {
  const derivedWallet = walletAccount(options.walletPrivateKey)
  const privateKey = ed.utils.randomSecretKey()
  const publicKey = await ed.getPublicKeyAsync(privateKey)
  const identity: AgentIdentity = {
    version: IDENTITY_VERSION,
    privateKey: toBase64(privateKey),
    publicKey: toBase64(publicKey),
    walletPrivateKey: derivedWallet.privateKey,
    wallet: derivedWallet.address,
    baseUrl: normalizeBaseUrl(
      options.baseUrl ?? process.env.F4BC_API_URL ?? DEFAULT_MARKETPLACE_URL,
    ),
    chainId: options.chainId ?? DEFAULT_CHAIN_ID,
    createdAt: (options.now ?? Date.now)(),
  }
  return saveIdentity(path, identity)
}

export async function loadIdentity(path?: string): Promise<AgentIdentity> {
  const target = await resolveIdentityPath(path)
  const raw = await readIdentityFile(target)
  try {
    return await validateIdentity(JSON.parse(raw) as unknown)
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error('identity file contains invalid JSON')
    throw error
  }
}

export async function setIdentityHandle(path: string, handle: string): Promise<AgentIdentity> {
  if (!/^[a-z0-9-]{3,32}$/.test(handle)) throw new Error('invalid agent handle')
  const current = await loadIdentity(path)
  return saveIdentity(path, { ...current, handle }, { overwrite: true })
}
