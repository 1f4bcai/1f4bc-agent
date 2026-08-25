import { createHash } from 'node:crypto'
import {
  chmod,
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
import { McpSpendGuard } from '../src/mcp-payments.js'
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
