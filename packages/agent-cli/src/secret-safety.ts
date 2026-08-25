import { Buffer } from 'node:buffer'
import type { AgentIdentity } from './keys.js'

function textEncodings(bytes: Uint8Array): string[] {
  const base64 = Buffer.from(bytes).toString('base64')
  const base64Url = base64.replaceAll('+', '-').replaceAll('/', '_')
  const hex = Buffer.from(bytes).toString('hex')
  return [
    base64,
    base64.replace(/=+$/, ''),
    base64Url,
    base64Url.replace(/=+$/, ''),
    hex,
    hex.toUpperCase(),
    `0x${hex}`,
    `0x${hex.toUpperCase()}`,
  ]
}

function secretTextNeedles(identity: AgentIdentity): string[] {
  const ed25519 = Buffer.from(identity.privateKey, 'base64')
  const wallet = Buffer.from(identity.walletPrivateKey.slice(2), 'hex')
  return [...new Set([
    identity.privateKey,
    identity.walletPrivateKey,
    ...textEncodings(ed25519),
    ...textEncodings(wallet),
  ])]
}

function secretHexNeedles(identity: AgentIdentity): string[] {
  return [
    Buffer.from(identity.privateKey, 'base64').toString('hex'),
    identity.walletPrivateKey.slice(2).toLowerCase(),
  ]
}

function secretNeedles(identity: AgentIdentity): Uint8Array[] {
  const ed25519 = Buffer.from(identity.privateKey, 'base64')
  const wallet = Buffer.from(identity.walletPrivateKey.slice(2), 'hex')
  return [
    ed25519,
    wallet,
    ...secretTextNeedles(identity).map((value) => Buffer.from(value, 'utf8')),
  ]
}

function decodedTextVariants(value: string): string[] {
  const variants = [value]
  let decoded = value
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      const next = decodeURIComponent(decoded)
      if (next === decoded) break
      variants.push(next)
      decoded = next
    } catch {
      break
    }
  }
  return variants
}

/** Refuse to place either local signing secret in any outbound payload. */
export function assertNoIdentitySecrets(
  contents: Uint8Array | string,
  identity: AgentIdentity,
  label = 'outbound payload',
): void {
  const haystack = typeof contents === 'string'
    ? Buffer.from(contents, 'utf8')
    : Buffer.from(contents)
  const rawMatch = secretNeedles(identity)
    .some((needle) => needle.byteLength > 0 && haystack.indexOf(needle) >= 0)
  const textNeedles = secretTextNeedles(identity)
  const textMatch = decodedTextVariants(
    typeof contents === 'string' ? contents : haystack.toString('utf8'),
  ).some((value) =>
    textNeedles.some((needle) => value.includes(needle)) ||
    secretHexNeedles(identity).some((needle) => value.toLowerCase().includes(needle)),
  )
  if (rawMatch || textMatch) {
    throw new Error(`${label} contains local private key material; refusing to send it`)
  }
}
