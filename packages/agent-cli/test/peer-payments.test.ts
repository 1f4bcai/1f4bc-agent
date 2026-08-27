import { createHash } from 'node:crypto'
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from '@x402/core/http'
import type { PaymentRequired } from '@x402/core/types'
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
} from '@x402/extensions/payment-identifier'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import { runCli } from '../src/index.js'
import { loadIdentity } from '../src/keys.js'
import { claimAuthorizedPaymentControl, McpSpendGuard } from '../src/mcp-payments.js'
import { spendPolicyScope } from '../src/spend-scope.js'
import {
  PeerPaymentClient,
  inspectUsdcReceipt,
  peerPaymentSpendInput,
  readUsdcBalance,
} from '../src/peer-payments.js'

const walletPrivateKey = `0x${'11'.repeat(32)}` as `0x${string}`
const payTo = `0x${'22'.repeat(20)}` as `0x${string}`
const usdc = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
const txHash = `0x${'ab'.repeat(32)}`
const receiptBlockHash = `0x${'cd'.repeat(32)}`
const payer = privateKeyToAccount(walletPrivateKey).address
const rpcUrl = 'https://rpc.example/'
const terminalRpcUrls = [
  'https://rpc-a.example/private-primary',
  'https://rpc-b.example/private-witness',
  'https://rpc-c.example/private-witness',
] as const
const cleanup: string[] = []
const authorizationUsedTopic =
  '0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5'
let latestAuthorizationNonce = `0x${'00'.repeat(32)}`

function cancellableResponse(
  body: string,
  init: ResponseInit,
): { response: Response; cancelled: () => boolean } {
  let wasCancelled = false
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(body))
    },
    cancel() {
      wasCancelled = true
    },
  })
  return {
    response: new Response(stream, init),
    cancelled: () => wasCancelled,
  }
}

function finalizedTransferRpc(overrides: {
  from?: string
  to?: string
  amountAtomic?: bigint
  transaction?: string
  nonce?: string
} = {}): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    expect(request.redirect).toBe('manual')
    const rpc = JSON.parse(await request.text()) as { method: string }
    if (rpc.method === 'eth_chainId') {
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
    }
    if (rpc.method === 'eth_getBlockByNumber') {
      const params = (rpc as { method: string; params?: unknown[] }).params ?? []
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: params[0] === 'finalized'
          ? { number: '0x64', hash: `0x${'ef'.repeat(32)}` }
          : { number: '0x63', hash: receiptBlockHash, timestamp: '0x65' },
      })
    }
    if (rpc.method !== 'eth_getTransactionReceipt') {
      throw new Error(`unexpected RPC method ${rpc.method}`)
    }
    const from = overrides.from ?? payer
    const to = overrides.to ?? payTo
    const amountAtomic = overrides.amountAtomic ?? 25_000n
    return Response.json({
      jsonrpc: '2.0',
      id: 1,
      result: {
        transactionHash: overrides.transaction ?? txHash,
        status: '0x1',
        blockNumber: '0x63',
        blockHash: receiptBlockHash,
        logs: [{
          address: usdc,
          logIndex: '0x29',
          topics: [
            authorizationUsedTopic,
            `0x${from.slice(2).padStart(64, '0')}`,
            overrides.nonce ?? latestAuthorizationNonce,
          ],
          data: '0x',
        }, {
          address: usdc,
          logIndex: '0x2a',
          topics: [
            '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
            `0x${from.slice(2).padStart(64, '0')}`,
            `0x${to.slice(2).padStart(64, '0')}`,
          ],
          data: `0x${amountAtomic.toString(16).padStart(64, '0')}`,
        }],
      },
    })
  }) as typeof fetch
}

function expiredUnusedQuorumRpc(
  validBefore: bigint,
  nonce: `0x${string}`,
  overrides: { laggingOrigin?: string; usedOrigin?: string } = {},
): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    const rpc = JSON.parse(await request.text()) as { method: string; params?: unknown[] }
    const origin = new URL(request.url).origin
    const index = terminalRpcUrls.findIndex((value) => new URL(value).origin === origin)
    if (index < 0) throw new Error('unexpected terminal RPC origin')
    if (rpc.method === 'eth_chainId') {
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
    }
    const blockHash = `0x${String(index + 1).repeat(64)}`
    if (rpc.method === 'eth_getBlockByNumber') {
      expect(rpc.params).toEqual(['finalized', false])
      const timestamp = origin === overrides.laggingOrigin ? validBefore - 1n : validBefore
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          number: `0x${(100 + index).toString(16)}`,
          hash: blockHash,
          timestamp: `0x${timestamp.toString(16)}`,
        },
      })
    }
    if (rpc.method !== 'eth_call') throw new Error(`unexpected RPC method ${rpc.method}`)
    expect(rpc.params).toEqual([{
      to: usdc,
      data: `0xe94a0102${payer.slice(2).toLowerCase().padStart(64, '0')}${nonce.slice(2)}`,
    }, {
      blockHash,
      requireCanonical: true,
    }])
    return Response.json({
      jsonrpc: '2.0',
      id: 1,
      result: origin === overrides.usedOrigin
        ? `0x${'0'.repeat(63)}1`
        : `0x${'0'.repeat(64)}`,
    })
  }) as typeof fetch
}

async function identityPath(key: `0x${string}` = walletPrivateKey): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), '1f4bc-peer-payment-'))
  cleanup.push(directory)
  const path = join(directory, 'identity.json')
  await runCli(['--identity', path, 'init'], {
    env: {},
    generateWalletPrivateKey: () => key,
    stdout: { write: () => undefined },
  })
  return path
}

async function guardedPay(
  path: string,
  client: PeerPaymentClient,
  input: Parameters<PeerPaymentClient['pay']>[0],
): Promise<Awaited<ReturnType<PeerPaymentClient['pay']>>> {
  const body = input.body ?? new Uint8Array()
  const identity = await loadIdentity(path)
  const guard = new McpSpendGuard({
    journalPath: join(dirname(path), 'test-global-spend.json'),
    maxPaymentAtomic: input.amountAtomic,
    dailyPaymentLimitAtomic: input.amountAtomic * 10n,
    scope: spendPolicyScope(identity.chainId, identity.wallet),
  })
  return guard.execute(
    'peer_pay',
    peerPaymentSpendInput(input),
    input.amountAtomic,
    (control) => client.pay(input, control),
  )
}

async function createAmbiguousCliPeerPayment(
  path: string,
  target: string,
  dailyPaymentLimitAtomic = '25000',
): Promise<string> {
  let header = ''
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    const payment = request.headers.get('PAYMENT-SIGNATURE')
    if (!payment) {
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
      })
    }
    header = payment
    throw new Error('connection lost after peer authorization')
  }) as typeof fetch
  await expect(runCli([
    '--identity', path,
    'pay', target,
    '--amount-atomic', '25000',
    '--pay-to', payTo,
  ], {
    env: {
      F4BC_RPC_URL: terminalRpcUrls[0],
      F4BC_MAX_PAYMENT_ATOMIC: '25000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: dailyPaymentLimitAtomic,
    },
    fetch: fetcher,
    stdout: { write: () => undefined },
  })).rejects.toThrow(/connection lost after peer authorization/i)
  expect(header.length).toBeGreaterThan(20)
  return header
}

function challenge(
  url: string,
  overrides: {
    amount?: string
    payTo?: `0x${string}`
    maxTimeoutSeconds?: number
  } = {},
): PaymentRequired {
  return {
    x402Version: 2,
    resource: { url, description: 'worker deliverable', mimeType: 'text/plain' },
    accepts: [{
      scheme: 'exact',
      network: 'eip155:8453',
      asset: usdc,
      amount: overrides.amount ?? '25000',
      payTo: overrides.payTo ?? payTo,
      maxTimeoutSeconds: overrides.maxTimeoutSeconds ?? 300,
      extra: { name: 'USD Coin', version: '2' },
    }],
    extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
  }
}

function paidResponse(body = 'private worker result'): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'PAYMENT-RESPONSE': encodePaymentResponseHeader({
        success: true,
        payer,
        transaction: txHash,
        network: 'eip155:8453',
        amount: '25000',
      }),
    },
  })
}

function paidResponseFor(request: Request, body?: string): Response {
  const header = request.headers.get('PAYMENT-SIGNATURE')
  if (header) {
    const decoded = decodePaymentSignatureHeader(header)
    const authorization = decoded.payload.authorization as { nonce?: unknown }
    if (typeof authorization.nonce !== 'string') throw new Error('test authorization has no nonce')
    latestAuthorizationNonce = authorization.nonce
  }
  return paidResponse(body)
}

afterEach(async () => {
  latestAuthorizationNonce = `0x${'00'.repeat(32)}`
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('arbitrary worker x402 payments', () => {
  it('rejects peer request mutation between cap reservation and authorization', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async () => {
      throw new Error('must not send')
    })
    const client = await PeerPaymentClient.fromIdentityFile(path, {
      rpcUrl,
      fetch: fetcher as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    })
    const input = {
      url: 'https://worker.example/task',
      method: 'POST' as const,
      body: new Uint8Array([1, 2, 3]),
      amountAtomic: 25_000n,
      payTo,
    }
    const approved = peerPaymentSpendInput(input)
    const guard = new McpSpendGuard({
      journalPath: join(dirname(path), 'mutation-spend.json'),
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      maxPaymentAtomic: 25_000n,
      dailyPaymentLimitAtomic: 25_000n,
    })

    const pending = guard.execute(
      'peer_pay',
      approved,
      25_000n,
      (control) => client.pay(input, control),
    )
    input.body[0] = 9
    await expect(pending).rejects.toThrow(/does not match/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects a peer request getter that changes the payment recipient', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async () => {
      throw new Error('must not send')
    })
    const client = await PeerPaymentClient.fromIdentityFile(path, {
      rpcUrl,
      fetch: fetcher as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    })
    const redirected = `0x${'33'.repeat(20)}`
    let recipientReads = 0
    const input = {
      url: 'https://worker.example/task',
      amountAtomic: 25_000n,
      get payTo() {
        recipientReads += 1
        return recipientReads === 1 ? payTo : redirected
      },
    }
    const approved = peerPaymentSpendInput(input)
    const guard = new McpSpendGuard({
      journalPath: join(dirname(path), 'getter-spend.json'),
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      maxPaymentAtomic: 25_000n,
      dailyPaymentLimitAtomic: 25_000n,
    })

    await expect(guard.execute(
      'peer_pay',
      approved,
      25_000n,
      (control) => client.pay(input, control),
    )).rejects.toThrow(/does not match/i)
    expect(recipientReads).toBe(2)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects local private key material in binary peer request bodies', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async () => {
      throw new Error('must not send')
    })
    const client = await PeerPaymentClient.fromIdentityFile(path, {
      rpcUrl,
      fetch: fetcher as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect(guardedPay(path, client, {
      url: 'https://worker.example/task',
      method: 'POST',
      body: Buffer.from(identity.walletPrivateKey.slice(2), 'hex'),
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/local private key material/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects mixed-case, URL-encoded, URL, header, and RPC secret egress', async () => {
    const letteredKey = `0x${'abcdef0123456789'.repeat(4)}` as `0x${string}`
    const path = await identityPath(letteredKey)
    const identity = await loadIdentity(path)
    const mixedHex = identity.walletPrivateKey.slice(2)
      .split('')
      .map((character, index) => index % 2 === 0 ? character.toUpperCase() : character.toLowerCase())
      .join('')
    const fetcher = vi.fn(async () => {
      throw new Error('must not send')
    })
    const options = {
      rpcUrl,
      fetch: fetcher as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    }

    const bodyClient = await PeerPaymentClient.fromIdentityFile(path, options)
    await expect(guardedPay(path, bodyClient, {
      url: 'https://worker.example/task',
      method: 'POST',
      body: Buffer.from(mixedHex, 'utf8'),
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/local private key material/i)

    const urlClient = await PeerPaymentClient.fromIdentityFile(path, options)
    await expect(guardedPay(path, urlClient, {
      url: `https://worker.example/task?k=${encodeURIComponent(identity.privateKey)}`,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/local private key material/i)

    const headerClient = await PeerPaymentClient.fromIdentityFile(path, options)
    await expect(guardedPay(path, headerClient, {
      url: 'https://worker.example/task',
      method: 'POST',
      contentType: `application/x-${mixedHex}`,
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/local private key material/i)

    expect(() => new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: `https://rpc.example/?token=${encodeURIComponent(identity.privateKey)}`,
    })).toThrow(/local private key material/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('freezes token policy and keeps wallet/RPC secrets non-enumerable', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const client = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: 'https://rpc.example/private-credential',
    })
    expect(Object.isFrozen((await import('../src/peer-payments.js')).USDC_BY_CHAIN_ID)).toBe(true)
    const serialized = JSON.stringify(client)
    expect(serialized).not.toContain(identity.privateKey)
    expect(serialized).not.toContain(identity.walletPrivateKey)
    expect(serialized).not.toContain('private-credential')
    expect(Object.keys(client)).toEqual([])
  })

  it('rejects a mismatched Ed25519 pair before binding a peer-payment client', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    expect(() => new PeerPaymentClient(
      { ...identity, publicKey: Buffer.alloc(32, 9).toString('base64') },
      { identityPath: path, rpcUrl },
    )).toThrow(/public key does not match its private key/i)
  })

  it('rejects a symlinked identity before constructing from an identity file', async () => {
    const path = await identityPath()
    const link = join(dirname(path), 'identity-link.json')
    await symlink(path, link)
    await expect(PeerPaymentClient.fromIdentityFile(link, {
      rpcUrl,
      fetch: vi.fn(async () => paidResponse()) as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    })).rejects.toThrow(/symbolic link/i)
  })

  it('revalidates identity permissions before consuming a peer-payment authorization', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const input = {
      url: 'https://worker.example/deliverable',
      amountAtomic: 25_000n,
      payTo,
    }
    const guard = new McpSpendGuard({
      journalPath: join(dirname(path), 'permissions-spend.json'),
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      maxPaymentAtomic: input.amountAtomic,
      dailyPaymentLimitAtomic: input.amountAtomic,
    })
    const fetcher = vi.fn(async () => paidResponse()) as typeof fetch
    const client = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })
    await chmod(path, 0o644)

    await expect(guard.execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      (control) => client.pay(input, control),
    )).rejects.toThrow(/identity file has unsafe permissions/i)
    expect(fetcher).not.toHaveBeenCalled()
    await expect(stat(join(dirname(path), 'peer-payment-attempts')))
      .rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('revalidates the payment principal and chain before peer-payment signing', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const input = {
      url: 'https://worker.example/deliverable',
      amountAtomic: 25_000n,
      payTo,
    }
    const guard = new McpSpendGuard({
      journalPath: join(dirname(path), 'principal-spend.json'),
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      maxPaymentAtomic: input.amountAtomic,
      dailyPaymentLimitAtomic: input.amountAtomic,
    })
    const fetcher = vi.fn(async () => paidResponse()) as typeof fetch
    const client = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })
    await writeFile(path, `${JSON.stringify({ ...identity, chainId: 84532 })}\n`, {
      mode: 0o600,
    })

    await expect(guard.execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      (control) => client.pay(input, control),
    )).rejects.toThrow(/identity principal changed/i)
    expect(fetcher).not.toHaveBeenCalled()
    await expect(stat(join(dirname(path), 'peer-payment-attempts')))
      .rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('rejects an in-memory chain that does not match the bound identity file', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async () => paidResponse()) as typeof fetch

    expect(() => new PeerPaymentClient({ ...identity, chainId: 84532 }, {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })).toThrow(/identity does not match the bound identity file/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('refuses programmatic payments without an active global spend reservation', async () => {
    const path = await identityPath()
    const fetcher = vi.fn(async () => paidResponse()) as typeof fetch
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect((client.pay as unknown as (
      input: Parameters<PeerPaymentClient['pay']>[0],
      control?: undefined,
    ) => Promise<unknown>)({
      url: 'https://worker.example/deliverable',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/spend-policy reservation/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('exposes a log-safe pay command without requiring marketplace registration', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/deliverable?access=do-not-log'
    let output = ''
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      return request.headers.has('PAYMENT-SIGNATURE')
        ? paidResponseFor(request, 'do-not-log-this-deliverable')
        : new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
    }) as typeof fetch

    const result = await runCli([
      '--identity', path,
      'pay', target,
      '--amount-atomic', '25000',
      '--pay-to', payTo,
      '--rpc-url', rpcUrl,
      '--max-payment-atomic', '25000',
      '--daily-payment-limit-atomic', '100000',
    ], {
      env: {},
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
      stdout: { write: (chunk) => (output += chunk) },
    })

    expect(result).toEqual(expect.objectContaining({ transaction: txHash }))
    expect(output).toContain('https://worker.example/deliverable')
    expect(output).not.toContain('access=do-not-log')
    expect(output).not.toContain('do-not-log-this-deliverable')
    expect(output).not.toContain('PAYMENT-SIGNATURE')
  })

  it('terminal-clears only after three private RPC origins prove exact finalized expiry and non-use', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/private-terminal?capability=do-not-log'
    const header = await createAmbiguousCliPeerPayment(path, target)
    const decoded = decodePaymentSignatureHeader(header)
    const authorization = decoded.payload.authorization as {
      nonce: `0x${string}`
      validBefore: string
    }
    const rpcFetch = expiredUnusedQuorumRpc(BigInt(authorization.validBefore), authorization.nonce)
    let output = ''
    const env = {
      F4BC_RPC_URL: terminalRpcUrls[0],
      F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
      F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
      F4BC_MAX_PAYMENT_ATOMIC: '25000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
    }
    const argv = [
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ]

    await expect(runCli(argv, {
      env,
      rpcFetch,
      stdout: { write: (chunk) => (output += chunk) },
    })).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    expect(rpcFetch).toHaveBeenCalledTimes(9)
    expect(output).not.toContain(header)
    expect(output).not.toContain(authorization.nonce)
    expect(output).not.toContain('private-primary')
    expect(output).not.toContain('private-witness')
    expect(output).not.toContain('capability=do-not-log')

    const root = join(dirname(path), 'peer-payment-attempts')
    const [principal] = await readdir(root)
    const principalDirectory = join(root, principal!)
    expect((await readdir(principalDirectory)).filter((name) => /^[0-9a-f]{64}\.json$/.test(name)))
      .toEqual([])
    const archiveDirectory = join(principalDirectory, 'terminal-archive')
    const archiveNames = (await readdir(archiveDirectory)).filter((name) => name.endsWith('.json'))
    expect(archiveNames).toHaveLength(1)
    const archivePath = join(archiveDirectory, archiveNames[0]!)
    expect((await stat(archivePath)).mode & 0o777).toBe(0o600)
    expect(await readFile(archivePath, 'utf8')).toContain(header)
    const spendName = (await readdir(dirname(path))).find((name) =>
      /^spend-[0-9a-f]{64}\.json$/.test(name))!
    const spend = JSON.parse(await readFile(join(dirname(path), spendName), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'released' })])

    // A crash after active-tombstone removal remains idempotently recoverable
    // from the immutable archive, but must repeat the three-provider proof.
    await expect(runCli(argv, {
      env,
      rpcFetch,
      stdout: { write: () => undefined },
    })).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    expect(rpcFetch).toHaveBeenCalledTimes(18)
  })

  it('replays an archive-only terminal clear after its released spend row crosses UTC', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const target = 'https://worker.example/cross-utc-terminal-clear'
    const input = {
      url: target,
      method: 'GET' as const,
      amountAtomic: 25_000n,
      payTo,
    }
    let header = ''
    const firstClient = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      fetch: vi.fn(async (requestInput: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(requestInput, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (!payment) {
          return new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
        }
        header = payment
        throw new Error('ambiguous before terminal clear')
      }) as typeof fetch,
    })
    let spendNow = Date.UTC(2026, 7, 22, 23, 59)
    const journalPath = join(dirname(path), 'cross-utc-spend.json')
    const spendOptions = {
      journalPath,
      maxPaymentAtomic: input.amountAtomic,
      dailyPaymentLimitAtomic: input.amountAtomic,
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      now: () => spendNow,
    }
    await expect(new McpSpendGuard(spendOptions).execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      (control) => firstClient.pay(input, control),
    )).rejects.toThrow(/ambiguous before terminal clear/i)

    const authorization = decodePaymentSignatureHeader(header).payload.authorization as {
      nonce: `0x${string}`
      validBefore: string
    }
    const rpcFetch = expiredUnusedQuorumRpc(
      BigInt(authorization.validBefore),
      authorization.nonce,
    )
    const terminalClient = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      quorumRpcUrls: terminalRpcUrls.slice(1),
      rpcFetch,
    })
    await expect(terminalClient.clearTerminalPayment(
      input,
      new McpSpendGuard(spendOptions),
    )).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })

    spendNow = Date.UTC(2026, 7, 23, 0, 1)
    await expect(terminalClient.clearTerminalPayment(
      input,
      new McpSpendGuard(spendOptions),
    )).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    expect(rpcFetch).toHaveBeenCalledTimes(18)

    const spend = JSON.parse(await readFile(journalPath, 'utf8')) as {
      entries: Array<{ state: string; day: string }>
    }
    expect(spend.entries).toEqual([
      expect.objectContaining({ state: 'released', day: '2026-08-23' }),
    ])
    const [principal] = await readdir(join(dirname(path), 'peer-payment-attempts'))
    const archives = (await readdir(join(
      dirname(path),
      'peer-payment-attempts',
      principal!,
      'terminal-archive',
    ))).filter((name) => name.endsWith('.json'))
    expect(archives).toHaveLength(1)

    let newerHeader = ''
    const newerClient = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      fetch: vi.fn(async (requestInput: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(requestInput, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (!payment) {
          return new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
        }
        newerHeader = payment
        throw new Error('newer ambiguous generation')
      }) as typeof fetch,
    })
    await expect(new McpSpendGuard(spendOptions).execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      (control) => newerClient.pay(input, control),
    )).rejects.toThrow(/newer ambiguous generation/i)
    expect(newerHeader).not.toBe(header)

    const principalDirectory = join(dirname(path), 'peer-payment-attempts', principal!)
    const [newerActive] = (await readdir(principalDirectory)).filter((name) =>
      /^[0-9a-f]{64}\.json$/.test(name))
    await rm(join(principalDirectory, newerActive!))
    vi.mocked(rpcFetch).mockClear()
    await expect(terminalClient.clearTerminalPayment(
      input,
      new McpSpendGuard(spendOptions),
    )).rejects.toThrow(/missing.*ambiguous spend generation/i)
    expect(rpcFetch).not.toHaveBeenCalled()

    const finalSpend = JSON.parse(await readFile(journalPath, 'utf8')) as {
      entries: Array<{ state: string; day: string }>
    }
    expect(finalSpend.entries).toEqual([
      expect.objectContaining({ state: 'ambiguous', day: '2026-08-23' }),
    ])
  })

  it.each(['symlink', 'hardlink'] as const)(
    'rejects an archived peer-payment %s before RPC proof',
    async (kind) => {
      const path = await identityPath()
      const target = `https://worker.example/${kind}-archive-file`
      const header = await createAmbiguousCliPeerPayment(path, target)
      const authorization = decodePaymentSignatureHeader(header).payload.authorization as {
        nonce: `0x${string}`
        validBefore: string
      }
      const env = {
        F4BC_RPC_URL: terminalRpcUrls[0],
        F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
        F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      }
      const argv = [
        '--identity', path,
        'recover', 'pay', target,
        '--clear-terminal',
        '--amount-atomic', '25000',
        '--pay-to', payTo,
      ]
      await runCli(argv, {
        env,
        rpcFetch: expiredUnusedQuorumRpc(
          BigInt(authorization.validBefore),
          authorization.nonce,
        ),
        stdout: { write: () => undefined },
      })
      const [principal] = await readdir(join(dirname(path), 'peer-payment-attempts'))
      const archiveDirectory = join(
        dirname(path), 'peer-payment-attempts', principal!, 'terminal-archive',
      )
      const [archiveName] = (await readdir(archiveDirectory)).filter((name) => name.endsWith('.json'))
      const archivePath = join(archiveDirectory, archiveName!)
      await rm(archivePath)
      if (kind === 'symlink') {
        await symlink(path, archivePath)
      } else {
        const decoy = join(dirname(path), 'archive-hardlink-decoy.json')
        await writeFile(decoy, '{}\n', { mode: 0o600 })
        await link(decoy, archivePath)
      }
      const rpcFetch = vi.fn(async () => {
        throw new Error('RPC must not be reached for an unsafe archive file')
      }) as typeof fetch

      await expect(runCli(argv, {
        env,
        rpcFetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/single-link regular file/i)
      expect(rpcFetch).not.toHaveBeenCalled()
    },
  )

  it.each([
    ['one finalized head is before validBefore', { laggingOrigin: new URL(terminalRpcUrls[1]).origin }],
    ['one provider reports authorizationState=true', { usedOrigin: new URL(terminalRpcUrls[2]).origin }],
  ] as const)('keeps the exact spend ambiguous when %s', async (_label, override) => {
    const path = await identityPath()
    const target = 'https://worker.example/terminal-fail-closed'
    const header = await createAmbiguousCliPeerPayment(path, target)
    const authorization = decodePaymentSignatureHeader(header).payload.authorization as {
      nonce: `0x${string}`
      validBefore: string
    }
    const rpcFetch = expiredUnusedQuorumRpc(
      BigInt(authorization.validBefore),
      authorization.nonce,
      override,
    )

    await expect(runCli([
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ], {
      env: {
        F4BC_RPC_URL: terminalRpcUrls[0],
        F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
        F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      },
      rpcFetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/not expired|already used/i)

    const spendName = (await readdir(dirname(path))).find((name) =>
      /^spend-[0-9a-f]{64}\.json$/.test(name))!
    const spend = JSON.parse(await readFile(join(dirname(path), spendName), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
    const [principal] = await readdir(join(dirname(path), 'peer-payment-attempts'))
    const entries = await readdir(join(dirname(path), 'peer-payment-attempts', principal!))
    expect(entries.filter((name) => /^[0-9a-f]{64}\.json$/.test(name))).toHaveLength(1)
    expect((await readdir(join(
      dirname(path),
      'peer-payment-attempts',
      principal!,
      'terminal-archive',
    ))).filter((name) => name.endsWith('.json'))).toEqual([])
  })

  it.each(['missing', 'corrupt'] as const)(
    'fails closed without RPC or spend release when the active peer journal is %s',
    async (kind) => {
      const path = await identityPath()
      const target = 'https://worker.example/missing-generation'
      await createAmbiguousCliPeerPayment(path, target)
      const root = join(dirname(path), 'peer-payment-attempts')
      const [principal] = await readdir(root)
      const directory = join(root, principal!)
      const [entry] = (await readdir(directory)).filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
      const active = join(directory, entry!)
      if (kind === 'missing') await rm(active)
      else await writeFile(active, '{', { mode: 0o600 })
      const rpcFetch = vi.fn(async () => {
        throw new Error('RPC must not be reached')
      }) as typeof fetch

      await expect(runCli([
        '--identity', path,
        'recover', 'pay', target,
        '--clear-terminal',
        '--amount-atomic', '25000',
        '--pay-to', payTo,
      ], {
        env: {
          F4BC_RPC_URL: terminalRpcUrls[0],
          F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
          F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
          F4BC_MAX_PAYMENT_ATOMIC: '25000',
          F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
        },
        rpcFetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/missing.*ambiguous spend generation|invalid JSON/i)
      expect(rpcFetch).not.toHaveBeenCalled()
      const spendName = (await readdir(dirname(path))).find((name) =>
        /^spend-[0-9a-f]{64}\.json$/.test(name))!
      const spend = JSON.parse(await readFile(join(dirname(path), spendName), 'utf8')) as {
        entries: Array<{ state: string }>
      }
      expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
    },
  )

  it('rejects a symlinked terminal archive directory before RPC or journal mutation', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/symlinked-archive'
    await createAmbiguousCliPeerPayment(path, target)
    const root = join(dirname(path), 'peer-payment-attempts')
    const [principal] = await readdir(root)
    await symlink(path, join(root, principal!, 'terminal-archive'))
    const rpcFetch = vi.fn(async () => {
      throw new Error('RPC must not be reached')
    }) as typeof fetch

    await expect(runCli([
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ], {
      env: {
        F4BC_RPC_URL: terminalRpcUrls[0],
        F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
        F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      },
      rpcFetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/journal directory must be a real directory/i)
    expect(rpcFetch).not.toHaveBeenCalled()
    const [activeName] = (await readdir(join(root, principal!))).filter((name) =>
      /^[0-9a-f]{64}\.json$/.test(name))
    const active = JSON.parse(await readFile(join(root, principal!, activeName!), 'utf8')) as {
      state: string
    }
    expect(active.state).toBe('pending')
  })

  it('does not let an old archive clear a newer missing authorization generation', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/repeated-exact-request'
    const firstHeader = await createAmbiguousCliPeerPayment(path, target)
    const firstAuthorization = decodePaymentSignatureHeader(firstHeader).payload.authorization as {
      nonce: `0x${string}`
      validBefore: string
    }
    const argv = [
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ]
    const env = {
      F4BC_RPC_URL: terminalRpcUrls[0],
      F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
      F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
      F4BC_MAX_PAYMENT_ATOMIC: '25000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
    }
    await runCli(argv, {
      env,
      rpcFetch: expiredUnusedQuorumRpc(
        BigInt(firstAuthorization.validBefore),
        firstAuthorization.nonce,
      ),
      stdout: { write: () => undefined },
    })

    const secondHeader = await createAmbiguousCliPeerPayment(path, target)
    expect(secondHeader).not.toBe(firstHeader)
    const root = join(dirname(path), 'peer-payment-attempts')
    const [principal] = await readdir(root)
    const directory = join(root, principal!)
    const [activeName] = (await readdir(directory)).filter((name) =>
      /^[0-9a-f]{64}\.json$/.test(name))
    await rm(join(directory, activeName!))
    const rpcFetch = vi.fn(async () => {
      throw new Error('old archive must not reach RPC proof')
    }) as typeof fetch

    await expect(runCli(argv, {
      env,
      rpcFetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/missing.*ambiguous spend generation/i)
    expect(rpcFetch).not.toHaveBeenCalled()
    const archiveNames = (await readdir(join(directory, 'terminal-archive')))
      .filter((name) => name.endsWith('.json'))
    expect(archiveNames).toHaveLength(1)
    const spendName = (await readdir(dirname(path))).find((name) =>
      /^spend-[0-9a-f]{64}\.json$/.test(name))!
    const spend = JSON.parse(await readFile(join(dirname(path), spendName), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
  })

  it('keeps distinct immutable archives for repeated exact requests', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/multiple-generations'
    const env = {
      F4BC_RPC_URL: terminalRpcUrls[0],
      F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
      F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
      F4BC_MAX_PAYMENT_ATOMIC: '25000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
    }
    const argv = [
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ]
    const headers: string[] = []
    for (let generation = 0; generation < 2; generation += 1) {
      const header = await createAmbiguousCliPeerPayment(path, target)
      headers.push(header)
      const authorization = decodePaymentSignatureHeader(header).payload.authorization as {
        nonce: `0x${string}`
        validBefore: string
      }
      await runCli(argv, {
        env,
        rpcFetch: expiredUnusedQuorumRpc(
          BigInt(authorization.validBefore),
          authorization.nonce,
        ),
        stdout: { write: () => undefined },
      })
    }
    expect(headers[1]).not.toBe(headers[0])
    const [principal] = await readdir(join(dirname(path), 'peer-payment-attempts'))
    const archiveDirectory = join(
      dirname(path),
      'peer-payment-attempts',
      principal!,
      'terminal-archive',
    )
    const archives = (await readdir(archiveDirectory)).filter((name) => name.endsWith('.json'))
    expect(archives).toHaveLength(2)
    const contents = await Promise.all(archives.map((name) =>
      readFile(join(archiveDirectory, name), 'utf8')))
    expect(contents.some((value) => value.includes(headers[0]!))).toBe(true)
    expect(contents.some((value) => value.includes(headers[1]!))).toBe(true)
  })

  it('serializes concurrent distinct-key archives at the global entry ceiling', async () => {
    const path = await identityPath()
    const targets = [
      'https://worker.example/archive-cap-a',
      'https://worker.example/archive-cap-b',
    ] as const
    const headers = await Promise.all(targets.map((target) =>
      createAmbiguousCliPeerPayment(path, target, '50000')))
    const authorizations = headers.map((header) =>
      decodePaymentSignatureHeader(header).payload.authorization as {
        nonce: `0x${string}`
        validBefore: string
      })
    const root = join(dirname(path), 'peer-payment-attempts')
    const [principal] = await readdir(root)
    const archiveDirectory = join(root, principal!, 'terminal-archive')
    await mkdir(archiveDirectory, { mode: 0o700 })
    const dummyNames = Array.from({ length: 4_095 }, (_, index) =>
      join(archiveDirectory, `dummy-${index.toString().padStart(4, '0')}.json`))
    for (let offset = 0; offset < dummyNames.length; offset += 128) {
      await Promise.all(dummyNames.slice(offset, offset + 128).map((name) =>
        writeFile(name, '{}\n', { mode: 0o600 })))
    }
    const env = {
      F4BC_RPC_URL: terminalRpcUrls[0],
      F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
      F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
      F4BC_MAX_PAYMENT_ATOMIC: '25000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '50000',
    }
    const outcomes = await Promise.allSettled(targets.map((target, index) => runCli([
      '--identity', path,
      'recover', 'pay', target,
      '--clear-terminal',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ], {
      env,
      rpcFetch: expiredUnusedQuorumRpc(
        BigInt(authorizations[index]!.validBefore),
        authorizations[index]!.nonce,
      ),
      stdout: { write: () => undefined },
    })))

    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1)
    const rejected = outcomes.find((outcome) => outcome.status === 'rejected') as PromiseRejectedResult
    expect(String(rejected.reason)).toMatch(/archive reached its entry safety limit/i)
    expect((await readdir(archiveDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(4_096)
    const spendName = (await readdir(dirname(path))).find((name) =>
      /^spend-[0-9a-f]{64}\.json$/.test(name))!
    const spend = JSON.parse(await readFile(join(dirname(path), spendName), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries.map((entry) => entry.state).sort()).toEqual(['ambiguous', 'released'])
  })

  it('requires explicit terminal-clear intent, caps, and three RPC origins', async () => {
    const path = await identityPath()
    const base = [
      '--identity', path,
      'recover', 'pay', 'https://worker.example/intent',
      '--amount-atomic', '25000',
      '--pay-to', payTo,
    ]
    await expect(runCli(base, { env: {}, stdout: { write: () => undefined } }))
      .rejects.toThrow(/requires.*--clear-terminal/i)
    await expect(runCli([...base, '--clear-terminal'], {
      env: {
        F4BC_RPC_URL: terminalRpcUrls[0],
        F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
        F4BC_QUORUM_RPC_URL_2: terminalRpcUrls[2],
      },
      stdout: { write: () => undefined },
    })).rejects.toThrow(/max-payment-atomic/i)
    await expect(runCli([...base, '--clear-terminal'], {
      env: {
        F4BC_RPC_URL: terminalRpcUrls[0],
        F4BC_QUORUM_RPC_URL_1: terminalRpcUrls[1],
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      },
      stdout: { write: () => undefined },
    })).rejects.toThrow(/exactly two.*RPC/i)
  })

  it('applies a global chain override to both peer authorization and its spend namespace', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const target = 'https://worker.example/sepolia-deliverable'
    const sepoliaUsdc = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'
    const required: PaymentRequired = {
      x402Version: 2,
      resource: { url: target, description: 'testnet deliverable', mimeType: 'text/plain' },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:84532',
        asset: sepoliaUsdc,
        amount: '25000',
        payTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USDC', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const paidHeaders: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (!payment) {
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        })
      }
      paidHeaders.push(payment)
      throw new Error('test connection lost after testnet authorization')
    }) as typeof fetch

    await expect(runCli([
      '--identity', path,
      '--chain-id', '84532',
      'pay', target,
      '--amount-atomic', '25000',
      '--pay-to', payTo,
      '--rpc-url', rpcUrl,
    ], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      },
      fetch: fetcher,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/connection lost/i)

    expect(paidHeaders).toHaveLength(1)
    const payload = decodePaymentSignatureHeader(paidHeaders[0]!)
    expect(payload.accepted).toMatchObject({
      network: 'eip155:84532',
      asset: sepoliaUsdc,
      amount: '25000',
    })
    const scope = spendPolicyScope(84532, identity.wallet)
    const expectedJournal = join(
      dirname(path),
      `spend-${createHash('sha256').update(scope, 'utf8').digest('hex')}.json`,
    )
    const journal = JSON.parse(await readFile(expectedJournal, 'utf8')) as {
      scope: string
      entries: Array<{ state: string }>
    }
    expect(journal.scope).toBe(scope)
    expect(journal.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
  })

  it('rejects the mainnet token domain in a Base Sepolia peer challenge', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/sepolia-wrong-domain'
    const sepoliaUsdc = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'
    const required: PaymentRequired = {
      x402Version: 2,
      resource: { url: target, description: 'testnet deliverable', mimeType: 'text/plain' },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:84532',
        asset: sepoliaUsdc,
        amount: '25000',
        payTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    let paidAttemptSent = false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      if (!request.headers.has('PAYMENT-SIGNATURE')) {
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        })
      }
      paidAttemptSent = true
      return new Response('must not be paid', { status: 500 })
    }) as typeof fetch

    await expect(runCli([
      '--identity', path,
      '--chain-id', '84532',
      'pay', target,
      '--amount-atomic', '25000',
      '--pay-to', payTo,
      '--rpc-url', rpcUrl,
    ], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '25000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '25000',
      },
      fetch: fetcher,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/challenge does not match the exact x402 policy/i)
    expect(paidAttemptSent).toBe(false)
  })

  it('enforces the exact policy, includes an x402 v2 identifier, and caches log-safe evidence', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const target = 'https://worker.example/deliverable?job=private'
    const requests: Request[] = []
    let challengeCancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      expect(request.redirect).toBe('manual')
      if (!request.headers.has('PAYMENT-SIGNATURE')) {
        const tracked = cancellableResponse('unbounded challenge body', {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
        })
        challengeCancelled = tracked.cancelled
        return tracked.response
      }
      return paidResponseFor(request)
    }) as typeof fetch
    const client = new PeerPaymentClient(identity, {
      identityPath: await realpath(path),
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
      now: () => Date.now(),
    })

    const result = await guardedPay(path, client, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })

    expect(result).toEqual(expect.objectContaining({
      state: 'settled',
      url: 'https://worker.example/deliverable',
      queryPresent: true,
      chainId: 8453,
      network: 'eip155:8453',
      asset: usdc,
      amountAtomic: '25000',
      payTo,
      payer: identity.wallet,
      transaction: txHash,
      logIndex: 42,
      responseStatus: 200,
      responseBytes: Buffer.byteLength('private worker result'),
      responseSha256: createHash('sha256').update('private worker result').digest('hex'),
    }))
    expect(JSON.stringify(result)).not.toContain('private worker result')
    expect(JSON.stringify(result)).not.toContain('PAYMENT-SIGNATURE')
    expect(result.paymentId).toMatch(/^1f4bc_peer_[A-Za-z0-9_-]{16,}$/)
    expect(challengeCancelled()).toBe(true)

    const payment = requests[1]!.headers.get('PAYMENT-SIGNATURE')!
    const decoded = decodePaymentSignatureHeader(payment)
    expect(decoded.x402Version).toBe(2)
    expect((decoded.extensions?.[PAYMENT_IDENTIFIER] as { info?: { id?: string } }).info?.id)
      .toBe(result.paymentId)

    await expect(guardedPay(path, client, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).resolves.toEqual(result)
    expect(requests).toHaveLength(2)

    const journalRoot = join(dirname(path), 'peer-payment-attempts')
    const principalDirectories = await readdir(journalRoot)
    const entries = await readdir(join(journalRoot, principalDirectories[0]!))
    const journalFile = join(journalRoot, principalDirectories[0]!, entries[0]!)
    expect((await stat(journalRoot)).mode & 0o077).toBe(0)
    expect((await stat(journalFile)).mode & 0o777).toBe(0o600)
    expect(await readFile(journalFile, 'utf8')).not.toContain('private worker result')
  })

  it.each<[
    string,
    { amount?: string; payTo?: `0x${string}`; maxTimeoutSeconds?: number },
  ]>([
    ['amount', { amount: '25001' }],
    ['recipient', { payTo: `0x${'33'.repeat(20)}` as `0x${string}` }],
    ['authorization timeout', { maxTimeoutSeconds: 3_600 }],
  ])('never creates a paid request for a mismatched %s', async (_label, overrides) => {
    const path = await identityPath()
    const target = 'https://worker.example/deliverable'
    const requests: Request[] = []
    let cancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const tracked = cancellableResponse('invalid challenge body must not be exposed', {
        status: 402,
        headers: {
          'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target, overrides)),
        },
      })
      cancelled = tracked.cancelled
      return tracked.response
    }) as typeof fetch
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect(guardedPay(path, client, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/exact x402 policy/i)
    expect(requests).toHaveLength(1)
    expect(requests[0]!.headers.has('PAYMENT-SIGNATURE')).toBe(false)
    expect(cancelled()).toBe(true)
    const spend = JSON.parse(
      await readFile(join(dirname(path), 'test-global-spend.json'), 'utf8'),
    ) as { entries: Array<{ state: string }> }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'released' })])
  })

  it('refuses redirects without following a downgrade or alternate target', async () => {
    const path = await identityPath()
    const requests: Request[] = []
    let cancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const tracked = cancellableResponse('redirect body must not be exposed', {
        status: 302,
        headers: { location: 'http://attacker.test/' },
      })
      cancelled = tracked.cancelled
      return tracked.response
    }) as typeof fetch
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect(guardedPay(path, client, {
      url: 'https://worker.example/deliverable',
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/redirect/i)
    expect(requests).toHaveLength(1)
    expect(requests[0]!.url).toBe('https://worker.example/deliverable')
    expect(cancelled()).toBe(true)
  })

  it('cancels a worker success body when no x402 payment completed', async () => {
    const path = await identityPath()
    const tracked = cancellableResponse('unpaid worker body must not be exposed', { status: 200 })
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: vi.fn(async () => tracked.response) as typeof fetch,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect(guardedPay(path, client, {
      url: 'https://worker.example/deliverable',
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/did not complete an x402 payment/i)
    expect(tracked.cancelled()).toBe(true)
  })

  it('reuses one durable authorization after an ambiguous process failure', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/deliverable'
    let firstHeader = ''
    const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (!payment) {
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
        })
      }
      firstHeader = payment
      throw new Error('connection lost after settlement')
    }) as typeof fetch
    const first = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: firstFetcher,
      rpcFetch: finalizedTransferRpc(),
    })

    await expect(guardedPay(path, first, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/connection lost after settlement/i)
    const spend = JSON.parse(
      await readFile(join(dirname(path), 'test-global-spend.json'), 'utf8'),
    ) as { entries: Array<{ state: string }> }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])

    const secondRequests: Request[] = []
    const secondFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      secondRequests.push(request)
      return paidResponseFor(request)
    }) as typeof fetch
    const second = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: secondFetcher,
      rpcFetch: finalizedTransferRpc(),
    })
    const result = await guardedPay(path, second, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })

    expect(secondRequests).toHaveLength(1)
    expect(secondRequests[0]!.headers.get('PAYMENT-SIGNATURE')).toBe(firstHeader)
    expect(result.transaction).toBe(txHash)
  })

  it('keeps terminal retry classification generation-aware across the clear boundary', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const target = 'https://worker.example/terminal-clear-race'
    const input = {
      url: target,
      method: 'GET' as const,
      amountAtomic: 25_000n,
      payTo,
    }
    let header = ''
    const first = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      fetch: vi.fn(async (requestInput: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(requestInput, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (!payment) {
          return new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
        }
        header = payment
        throw new Error('ambiguous first generation')
      }) as typeof fetch,
    })
    await expect(guardedPay(path, first, input)).rejects.toThrow(/ambiguous first generation/i)
    const authorization = decodePaymentSignatureHeader(header).payload.authorization as {
      nonce: `0x${string}`
      validBefore: string
    }
    const terminalClient = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      quorumRpcUrls: terminalRpcUrls.slice(1),
      rpcFetch: expiredUnusedQuorumRpc(
        BigInt(authorization.validBefore),
        authorization.nonce,
      ),
    })
    const journalPath = join(dirname(path), 'test-global-spend.json')
    const guard = new McpSpendGuard({
      journalPath,
      maxPaymentAtomic: input.amountAtomic,
      dailyPaymentLimitAtomic: input.amountAtomic * 10n,
      scope: spendPolicyScope(identity.chainId, identity.wallet),
    })
    await expect(guard.execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      (control) => terminalClient.stageTerminalPaymentClear(input, control),
    )).rejects.toMatchObject({ name: 'TerminalPaymentCleared' })
    let spend = JSON.parse(await readFile(journalPath, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'released' })])

    const workerFetch = vi.fn(async () => {
      throw new Error('terminal authorization must not be sent')
    }) as typeof fetch
    const blocked = new PeerPaymentClient(identity, {
      identityPath: path,
      rpcUrl: terminalRpcUrls[0],
      fetch: workerFetch,
    })
    await expect(guardedPay(path, blocked, input)).rejects.toThrow(/authorization is terminal/i)
    expect(workerFetch).not.toHaveBeenCalled()
    spend = JSON.parse(await readFile(journalPath, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'released' })])

    await expect(guard.execute(
      'peer_pay',
      peerPaymentSpendInput(input),
      input.amountAtomic,
      async (control) => {
        claimAuthorizedPaymentControl(
          control,
          'peer_pay',
          peerPaymentSpendInput(input),
          input.amountAtomic,
          spendPolicyScope(identity.chainId, identity.wallet),
        )
        throw new Error('new ambiguity while tombstone is retained')
      },
    )).rejects.toThrow(/new ambiguity/i)
    await expect(guardedPay(path, blocked, input)).rejects.toThrow(/authorization is terminal/i)
    spend = JSON.parse(await readFile(journalPath, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
  })

  it.each(['corrupt', 'oversized', 'symlink'] as const)(
    'keeps the spend reservation ambiguous when an existing peer journal is %s',
    async (kind) => {
      const path = await identityPath()
      const target = 'https://worker.example/durable-journal'
      const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (!request.headers.has('PAYMENT-SIGNATURE')) {
          return new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
        }
        throw new Error('connection lost after authorization')
      }) as typeof fetch
      const first = await PeerPaymentClient.fromIdentityFile(path, {
        rpcUrl,
        fetch: firstFetcher,
        rpcFetch: finalizedTransferRpc(),
      })
      const input = {
        url: target,
        method: 'GET' as const,
        amountAtomic: 25_000n,
        payTo,
      }

      await expect(guardedPay(path, first, input)).rejects.toThrow(/connection lost/i)
      const journalRoot = join(dirname(path), 'peer-payment-attempts')
      const [principal] = await readdir(journalRoot)
      const journalDirectory = join(journalRoot, principal!)
      const [journalName] = (await readdir(journalDirectory)).filter((name) => name.endsWith('.json'))
      const journalFile = join(journalDirectory, journalName!)
      await rm(join(dirname(path), 'test-global-spend.json'))
      if (kind === 'corrupt') {
        await writeFile(journalFile, '{')
      } else if (kind === 'oversized') {
        await writeFile(journalFile, 'x'.repeat(256 * 1_024 + 1))
      } else {
        await rm(journalFile)
        await symlink(path, journalFile)
      }

      const secondFetcher = vi.fn(async () => {
        throw new Error('must not send')
      })
      const second = await PeerPaymentClient.fromIdentityFile(path, {
        rpcUrl,
        fetch: secondFetcher as typeof fetch,
        rpcFetch: finalizedTransferRpc(),
      })
      await expect(guardedPay(path, second, input)).rejects.toThrow()
      expect(secondFetcher).not.toHaveBeenCalled()
      const spend = JSON.parse(
        await readFile(join(dirname(path), 'test-global-spend.json'), 'utf8'),
      ) as { entries: Array<{ state: string }> }
      expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
    },
  )

  it('keeps settlement pending when the claimed transaction lacks the exact finalized transfer', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/deliverable'
    let paidResponseCancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      if (request.headers.has('PAYMENT-SIGNATURE')) {
        const response = paidResponseFor(request)
        const tracked = cancellableResponse('private worker result must not be exposed', {
          status: response.status,
          headers: response.headers,
        })
        paidResponseCancelled = tracked.cancelled
        return tracked.response
      }
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
      })
    }) as typeof fetch
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc({ to: `0x${'33'.repeat(20)}` }),
    })

    await expect(guardedPay(path, client, {
      url: target,
      method: 'GET',
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/exact expected USDC transfer/i)
    expect(paidResponseCancelled()).toBe(true)

    const journalRoot = join(dirname(path), 'peer-payment-attempts')
    const [principal] = await readdir(journalRoot)
    const entryNames = (await readdir(join(journalRoot, principal!)))
      .filter((name) => name.endsWith('.json'))
    const persisted = JSON.parse(
      await readFile(join(journalRoot, principal!, entryNames[0]!), 'utf8'),
    ) as { state: string }
    expect(persisted.state).toBe('pending')
  })

  it('rejects an old identical transfer whose receipt consumed another authorization nonce', async () => {
    const path = await identityPath()
    const target = 'https://worker.example/nonce-bound'
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      return request.headers.has('PAYMENT-SIGNATURE')
        ? paidResponseFor(request)
        : new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(target)) },
          })
    }) as typeof fetch
    const client = new PeerPaymentClient(await loadIdentity(path), {
      identityPath: path,
      rpcUrl,
      fetch: fetcher,
      rpcFetch: finalizedTransferRpc({ nonce: `0x${'ff'.repeat(32)}` }),
    })

    await expect(guardedPay(path, client, {
      url: target,
      amountAtomic: 25_000n,
      payTo,
    })).rejects.toThrow(/exact expected EIP-3009 authorization/i)

    const [principal] = await readdir(join(dirname(path), 'peer-payment-attempts'))
    const [entry] = (await readdir(join(dirname(path), 'peer-payment-attempts', principal!)))
      .filter((name) => name.endsWith('.json'))
    const persisted = JSON.parse(await readFile(
      join(dirname(path), 'peer-payment-attempts', principal!, entry!),
      'utf8',
    )) as { state: string }
    expect(persisted.state).toBe('pending')
  })
})

describe('Base USDC evidence helpers', () => {
  it('wires the finalized balance command to an explicitly configured RPC', async () => {
    const path = await identityPath()
    let output = ''
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string; params?: unknown[] }
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: rpc.method === 'eth_chainId' ? '0x2105' : '0x00',
      })
    }) as typeof fetch

    const result = await runCli([
      '--identity', path,
      'balance',
      '--rpc-url', 'https://rpc.example/secret-token',
    ], {
      env: {},
      fetch: fetcher,
      stdout: { write: (chunk) => (output += chunk) },
    })

    expect(result).toEqual(expect.objectContaining({ balanceAtomic: '0', blockTag: 'finalized' }))
    expect(output).not.toContain('secret-token')
  })

  it('reads an exact integer balance without exposing the RPC URL', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string; params: unknown[] }
      expect(request.redirect).toBe('manual')
      if (rpc.method === 'eth_chainId') {
        expect(rpc.params).toEqual([])
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
      }
      expect(rpc.method).toBe('eth_call')
      expect(rpc.params).toEqual([
        { to: usdc, data: `0x70a08231${identity.wallet.slice(2).toLowerCase().padStart(64, '0')}` },
        'finalized',
      ])
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x0186a0' })
    }) as typeof fetch

    await expect(readUsdcBalance({
      rpcUrl: 'https://rpc.example/private-token',
      chainId: 8453,
      wallet: identity.wallet,
      fetch: fetcher,
    })).resolves.toEqual({
      chainId: 8453,
      network: 'eip155:8453',
      asset: usdc,
      wallet: identity.wallet,
      balanceAtomic: '100000',
      blockTag: 'finalized',
    })
  })

  it('extracts exact finalized USDC transfers by their receipt logIndex field', async () => {
    const from = `0x${'44'.repeat(20)}`
    const to = `0x${'55'.repeat(20)}`
    const transferTopic =
      '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string; params?: unknown[] }
      if (rpc.method === 'eth_chainId') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
      }
      if (rpc.method === 'eth_getBlockByNumber') {
        return Response.json({
          jsonrpc: '2.0',
          id: 1,
          result: rpc.params?.[0] === 'finalized'
            ? { number: '0x64', hash: `0x${'ef'.repeat(32)}` }
            : { number: '0x63', hash: receiptBlockHash, timestamp: '0x65' },
        })
      }
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: {
          transactionHash: txHash,
          status: '0x1',
          blockNumber: '0x63',
          blockHash: receiptBlockHash,
          logs: [
            { address: `0x${'99'.repeat(20)}`, logIndex: '0x7', topics: [], data: '0x' },
            {
              address: usdc,
              logIndex: '0x2a',
              topics: [
                transferTopic,
                `0x${from.slice(2).padStart(64, '0')}`,
                `0x${to.slice(2).padStart(64, '0')}`,
              ],
              data: `0x${25_000n.toString(16).padStart(64, '0')}`,
            },
          ],
        },
      })
    }) as typeof fetch

    await expect(inspectUsdcReceipt({
      rpcUrl: 'https://rpc.example/private-token',
      chainId: 8453,
      txHash,
      fetch: fetcher,
    })).resolves.toEqual({
      chainId: 8453,
      network: 'eip155:8453',
      asset: usdc,
      transaction: txHash,
      blockNumber: '99',
      blockTimestamp: '101',
      finalizedBlockNumber: '100',
      transfers: [{ logIndex: 42, from, to, amountAtomic: '25000' }],
      authorizations: [],
    })
  })

  it('rejects finalized receipt evidence without a canonical block timestamp', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string; params?: unknown[] }
      if (rpc.method === 'eth_chainId') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
      }
      if (rpc.method === 'eth_getTransactionReceipt') {
        return Response.json({
          jsonrpc: '2.0', id: 1, result: {
            transactionHash: txHash,
            status: '0x1',
            blockNumber: '0x63',
            blockHash: receiptBlockHash,
            logs: [],
          },
        })
      }
      return Response.json({
        jsonrpc: '2.0', id: 1,
        result: rpc.params?.[0] === 'finalized'
          ? { number: '0x64', hash: `0x${'ef'.repeat(32)}` }
          : { number: '0x63', hash: receiptBlockHash },
      })
    }) as typeof fetch

    await expect(inspectUsdcReceipt({ rpcUrl, chainId: 8453, txHash, fetch: fetcher }))
      .rejects.toThrow(/receipt block timestamp/i)
  })

  it('rejects an orphan receipt whose block hash disagrees with the canonical block', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string; params?: unknown[] }
      if (rpc.method === 'eth_chainId') {
        return Response.json({ jsonrpc: '2.0', id: 1, result: '0x2105' })
      }
      if (rpc.method === 'eth_getTransactionReceipt') {
        return Response.json({
          jsonrpc: '2.0', id: 1, result: {
            transactionHash: txHash,
            status: '0x1',
            blockNumber: '0x63',
            blockHash: receiptBlockHash,
            logs: [],
          },
        })
      }
      return Response.json({
        jsonrpc: '2.0', id: 1,
        result: rpc.params?.[0] === 'finalized'
          ? { number: '0x64', hash: `0x${'ef'.repeat(32)}` }
          : { number: '0x63', hash: `0x${'00'.repeat(32)}`, timestamp: '0x65' },
      })
    }) as typeof fetch

    await expect(inspectUsdcReceipt({ rpcUrl, chainId: 8453, txHash, fetch: fetcher }))
      .rejects.toThrow(/canonical block/i)
  })

  it('rejects an RPC connected to a different chain', async () => {
    const path = await identityPath()
    const identity = await loadIdentity(path)
    const methods: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string }
      methods.push(rpc.method)
      return Response.json({
        jsonrpc: '2.0',
        id: 1,
        result: rpc.method === 'eth_chainId' ? '0x14a34' : '0x00',
      })
    }) as typeof fetch

    await expect(readUsdcBalance({
      rpcUrl: 'https://rpc.example/',
      chainId: 8453,
      wallet: identity.wallet,
      fetch: fetcher,
    })).rejects.toThrow(/chain id does not match/i)
    expect(methods).toEqual(['eth_chainId'])
  })

  it('rejects a wrong-chain RPC before requesting a transaction receipt or finalized block', async () => {
    const methods: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const rpc = JSON.parse(await request.text()) as { method: string }
      methods.push(rpc.method)
      return Response.json({ jsonrpc: '2.0', id: 1, result: '0x14a34' })
    }) as typeof fetch

    await expect(inspectUsdcReceipt({
      rpcUrl: 'https://rpc.example/',
      chainId: 8453,
      txHash,
      fetch: fetcher,
    })).rejects.toThrow(/chain id does not match/i)
    expect(methods).toEqual(['eth_chainId'])
  })

  it('rejects oversized RPC responses without logging their contents', async () => {
    const fetcher = vi.fn(async () => new Response(`{"padding":"${'x'.repeat(1_100_000)}"}`, {
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch

    await expect(inspectUsdcReceipt({
      rpcUrl,
      chainId: 8453,
      txHash,
      fetch: fetcher,
    })).rejects.toThrow(/response-size safety limit/i)
  })

  it('cancels an RPC error response body before failing closed', async () => {
    let cancelled = () => false
    const fetcher = vi.fn(async () => {
      const tracked = cancellableResponse('upstream RPC secret must not be exposed', { status: 503 })
      cancelled = tracked.cancelled
      return tracked.response
    }) as typeof fetch

    await expect(inspectUsdcReceipt({
      rpcUrl,
      chainId: 8453,
      txHash,
      fetch: fetcher,
    })).rejects.toThrow(/RPC returned HTTP 503/i)
    expect(cancelled()).toBe(true)
  })
})
