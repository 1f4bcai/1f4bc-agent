import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as ed from '@noble/ed25519'
import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
} from '@x402/core/http'
import type { PaymentRequired } from '@x402/core/types'
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
} from '@x402/extensions/payment-identifier'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import {
  AgentApi,
  MARKETPLACE_PAY_TO_BY_CHAIN_ID,
  type PaymentRequestOptions,
  paymentMayHaveOccurred,
} from '../src/api.js'
import type { AgentIdentity } from '../src/keys.js'
import { SpendGuard, type SpendControl } from '../src/mcp-payments.js'
import { spendPolicyScope } from '../src/spend-scope.js'

const walletPrivateKey = `0x${'11'.repeat(32)}` as const
const cleanup: string[] = []

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

async function fixture(options: { durable?: boolean } = {}): Promise<{
  api: (fetcher: typeof fetch) => AgentApi
  identity: AgentIdentity
  identityPath?: string
}> {
  const privateKey = new Uint8Array(32).fill(7)
  const identity: AgentIdentity = {
    version: 1,
    publicKey: Buffer.from(await ed.getPublicKeyAsync(privateKey)).toString('base64'),
    privateKey: Buffer.from(privateKey).toString('base64'),
    wallet: privateKeyToAccount(walletPrivateKey).address,
    walletPrivateKey,
    baseUrl: 'https://1f4bc.ai',
    chainId: 8453,
    handle: 'alice',
    createdAt: 0,
  }
  let identityPath: string | undefined
  if (options.durable) {
    const directory = await mkdtemp(join(tmpdir(), '1f4bc-api-security-'))
    cleanup.push(directory)
    identityPath = join(directory, 'identity.json')
    await writeFile(identityPath, `${JSON.stringify(identity)}\n`, { mode: 0o600 })
  }
  return {
    identity,
    identityPath,
    api: (fetcher) => new AgentApi(identity, { fetch: fetcher, identityPath }),
  }
}

async function withSpendControl<T>(
  input: unknown,
  scope: string,
  action: (control: SpendControl) => Promise<T>,
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), '1f4bc-api-spend-'))
  cleanup.push(directory)
  const guard = new SpendGuard({
    journalPath: join(directory, 'spend.json'),
    maxPaymentAtomic: 10_000n,
    dailyPaymentLimitAtomic: 10_000n,
    scope,
  })
  return guard.execute('post_job', input, 10_000n, action)
}

function guardedPost(
  api: AgentApi,
  body: unknown,
  options: Omit<PaymentRequestOptions, 'control'> = {},
): Promise<unknown> {
  return withSpendControl(
    { job: body },
    spendPolicyScope(api.identity.chainId, api.identity.wallet),
    (control) => api.postJob(body, { ...options, control }),
  )
}

function challenge(overrides: {
  x402Version?: number
  resource?: string
  payTo?: string
  maxTimeoutSeconds?: number
  paymentIdentifier?: boolean
} = {}): PaymentRequired {
  return {
    x402Version: overrides.x402Version ?? 2,
    resource: {
      url: overrides.resource ?? 'https://1f4bc.ai/jobs',
      description: 'posting toll',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amount: '10000',
      payTo: overrides.payTo ?? MARKETPLACE_PAY_TO_BY_CHAIN_ID[8453]!,
      maxTimeoutSeconds: overrides.maxTimeoutSeconds ?? 300,
      extra: { name: 'USD Coin', version: '2' },
    }],
    ...(overrides.paymentIdentifier === false
      ? {}
      : { extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) } }),
  }
}

afterEach(async () => {
  vi.restoreAllMocks()
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('marketplace network and payment boundaries', () => {
  it('freezes official payment policy and keeps client secrets non-enumerable', async () => {
    const { api, identity } = await fixture({ durable: true })
    expect(Object.isFrozen(MARKETPLACE_PAY_TO_BY_CHAIN_ID)).toBe(true)
    const client = api(vi.fn(async () => Response.json({ ok: true })) as typeof fetch)
    const serialized = JSON.stringify(client)
    expect(serialized).not.toContain(identity.privateKey)
    expect(serialized).not.toContain(identity.walletPrivateKey)
    expect(Object.keys(client)).toEqual([])
  })

  it('refuses private key material in marketplace URLs before any request', async () => {
    const { api, identity } = await fixture()
    const fetcher = vi.fn(async () => Response.json({ results: [] })) as typeof fetch
    const client = api(fetcher)
    await expect(client.search('jobs', undefined, identity.privateKey))
      .rejects.toThrow(/local private key material/i)
    await expect(client.getJob(identity.walletPrivateKey.slice(2)))
      .rejects.toThrow(/local private key material/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('refuses common cross-encodings of either private key in outbound JSON', async () => {
    const { api, identity } = await fixture()
    const fetcher = vi.fn(async () => Response.json({ ok: true })) as typeof fetch
    const client = api(fetcher)
    const edBytes = Buffer.from(identity.privateKey, 'base64')
    const walletBytes = Buffer.from(identity.walletPrivateKey.slice(2), 'hex')
    const encodings = [
      edBytes.toString('hex'),
      edBytes.toString('hex').toUpperCase(),
      edBytes.toString('base64url'),
      `${edBytes.toString('base64url')}==`,
      walletBytes.toString('base64'),
      walletBytes.toString('base64').replace(/=+$/, ''),
      walletBytes.toString('base64url'),
      encodeURIComponent(walletBytes.toString('base64')),
      encodeURIComponent(edBytes.toString('hex')),
    ]

    for (const encoded of encodings) {
      await expect(client.setProfile({ description: encoded }))
        .rejects.toThrow(/local private key material/i)
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects a mismatched Ed25519 pair before binding a durable API client', async () => {
    const { identity, identityPath } = await fixture({ durable: true })
    expect(() => new AgentApi(
      { ...identity, publicKey: Buffer.alloc(32, 9).toString('base64') },
      { identityPath },
    )).toThrow(/public key does not match its private key/i)
  })

  it('refuses to create official-payee authorizations for an unapproved marketplace origin', async () => {
    const { identity, identityPath } = await fixture({ durable: true })
    const fetcher = vi.fn(async () => Response.json({ id: 'fake-job' })) as typeof fetch
    const hostile = new AgentApi(
      { ...identity, baseUrl: 'https://evil.example' },
      { fetch: fetcher, identityPath },
    )
    await expect(guardedPost(hostile, { title: 'captured' }))
      .rejects.toThrow(/restricted to https:\/\/1f4bc\.ai/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('exposes only an immutable public identity projection', async () => {
    const { api, identity } = await fixture()
    const client = api(vi.fn() as unknown as typeof fetch)
    expect(client.identity).toEqual({
      version: 1,
      handle: 'alice',
      publicKey: identity.publicKey,
      wallet: identity.wallet,
      baseUrl: 'https://1f4bc.ai',
      chainId: 8453,
      createdAt: 0,
    })
    expect(client.identity).not.toHaveProperty('privateKey')
    expect(client.identity).not.toHaveProperty('walletPrivateKey')
    expect(Object.isFrozen(client.identity)).toBe(true)
  })

  it('rejects direct paid API calls without an active spend reservation', async () => {
    const { api } = await fixture({ durable: true })
    const fetcher = vi.fn(async () => Response.json({ id: 'must-not-run' })) as typeof fetch
    await expect(api(fetcher).postJob(
      { title: 'unguarded' },
      { control: undefined as never },
    )).rejects.toThrow(
      /active local spend-policy reservation/i,
    )
    expect(fetcher).not.toHaveBeenCalled()
  })
  it.each([301, 302, 307, 308])('uses manual redirect mode and rejects HTTP %s', async (status) => {
    const { api } = await fixture()
    const requests: Request[] = []
    let cancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(new Request(input, init))
      const tracked = cancellableResponse('redirect body must not be exposed', {
        status,
        headers: { Location: 'https://attacker.example/collect' },
      })
      cancelled = tracked.cancelled
      return tracked.response
    }) as typeof fetch

    await expect(api(fetcher).getJob('secret-job')).rejects.toThrow(/redirect/i)
    expect(requests).toHaveLength(1)
    expect(requests[0]?.redirect).toBe('manual')
    expect(cancelled()).toBe(true)
  })

  it('rejects a response whose effective URL differs from the requested URL', async () => {
    const { api } = await fixture()
    let cancelled = () => false
    const fetcher = vi.fn(async () => {
      const tracked = cancellableResponse('wrong-origin body must not be exposed', { status: 200 })
      cancelled = tracked.cancelled
      Object.defineProperty(tracked.response, 'url', {
        value: 'https://attacker.example/jobs/secret-job',
      })
      return tracked.response
    }) as typeof fetch

    await expect(api(fetcher).getJob('secret-job')).rejects.toThrow(/URL.*requested/i)
    expect(cancelled()).toBe(true)
  })

  it('applies a bounded deadline to marketplace requests', async () => {
    const { api } = await fixture()
    const deadline = new Error('test marketplace deadline')
    const timeout = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(AbortSignal.abort(deadline))
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      expect(request.signal.aborted).toBe(true)
      throw request.signal.reason
    }) as typeof fetch

    await expect(api(fetcher).getJob('secret-job')).rejects.toThrow(deadline.message)
    expect(timeout).toHaveBeenCalledWith(30_000)
    timeout.mockRestore()
  })

  it('does not expose an untrusted error body and bounds response reads', async () => {
    const { api } = await fixture()
    const secret = ['PAYMENT-SIGNATURE', 'do-not-log-this'].join('=')
    const errorApi = api(vi.fn(async () => new Response(secret, { status: 400 })) as typeof fetch)
    let failure: unknown
    try {
      await errorApi.getJob('job-1')
    } catch (error) {
      failure = error
    }
    expect(failure).toBeInstanceOf(Error)
    expect((failure as Error).message).toMatch(/HTTP 400/)
    expect((failure as Error).message).not.toContain(secret)

    const oversized = 'x'.repeat(1_048_577)
    const tracked = cancellableResponse(oversized, { status: 200 })
    const oversizedApi = api(vi.fn(async () => tracked.response) as typeof fetch)
    await expect(oversizedApi.getJob('job-1')).rejects.toThrow(/safety limit/i)
    expect(tracked.cancelled()).toBe(true)

    const declared = cancellableResponse('x', {
      status: 200,
      headers: { 'Content-Length': '1048577' },
    })
    const declaredApi = api(vi.fn(async () => declared.response) as typeof fetch)
    await expect(declaredApi.getJob('job-1')).rejects.toThrow(/safety limit/i)
    expect(declared.cancelled()).toBe(true)
  })

  it('refuses paid calls without a durable recovery journal before any request', async () => {
    const { api } = await fixture()
    const fetcher = vi.fn(async () => Response.json({ id: 'must-not-run' })) as typeof fetch

    await expect(guardedPost(api(fetcher), { title: 'no journal' })).rejects.toThrow(/durable.*journal/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it.each([
    ['x402 v1', { x402Version: 1 }],
    ['another resource', { resource: 'https://attacker.example/jobs' }],
    ['another recipient', { payTo: `0x${'22'.repeat(20)}` }],
    ['a zero timeout', { maxTimeoutSeconds: 0 }],
    ['an excessive timeout', { maxTimeoutSeconds: 301 }],
    ['no required payment identifier', { paymentIdentifier: false }],
  ] as const)('rejects a challenge advertising %s before creating an authorization', async (_case, overrides) => {
    const { api } = await fixture({ durable: true })
    const requests: Request[] = []
    let cancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const tracked = cancellableResponse('invalid challenge body must not be exposed', {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge(overrides)) },
      })
      cancelled = tracked.cancelled
      return tracked.response
    }) as typeof fetch

    await expect(guardedPost(api(fetcher), { title: 'do not authorize' })).rejects.toThrow(/x402|challenge/i)
    expect(requests).toHaveLength(1)
    expect(requests[0]?.redirect).toBe('manual')
    expect(requests[0]?.headers.has('PAYMENT-SIGNATURE')).toBe(false)
    expect(cancelled()).toBe(true)
  })

  it('accepts only the pinned policy and transmits a validated EIP-3009 payload', async () => {
    const { api, identity } = await fixture({ durable: true })
    const requests: Request[] = []
    let challengeCancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (!payment) {
        const tracked = cancellableResponse('unbounded challenge body', {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge()) },
        })
        challengeCancelled = tracked.cancelled
        return tracked.response
      }
      return Response.json({ id: 'job-1' }, { status: 201 })
    }) as typeof fetch

    await expect(guardedPost(api(fetcher), { title: 'safe' })).resolves.toEqual({ id: 'job-1' })
    expect(requests).toHaveLength(2)
    expect(challengeCancelled()).toBe(true)
    expect(requests.every((request) => request.redirect === 'manual')).toBe(true)
    const payment = decodePaymentSignatureHeader(requests[1]!.headers.get('PAYMENT-SIGNATURE')!)
    const authorization = payment.payload.authorization as Record<string, unknown>
    expect(payment.x402Version).toBe(2)
    expect(payment.resource?.url).toBe('https://1f4bc.ai/jobs')
    expect(payment.accepted.payTo.toLowerCase())
      .toBe(MARKETPLACE_PAY_TO_BY_CHAIN_ID[8453]!.toLowerCase())
    expect(authorization.from).toBe(identity.wallet)
    expect(authorization.to).toBe(MARKETPLACE_PAY_TO_BY_CHAIN_ID[8453])
    expect(authorization.value).toBe('10000')
  })

  it('never lets a downstream false marker release spend after authorization evidence exists', async () => {
    const { api } = await fixture({ durable: true })
    const dependencyFailure = Object.assign(new Error('dependency misclassified payment'), {
      paymentMayHaveOccurred: false as const,
    })
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      if (request.headers.has('PAYMENT-SIGNATURE')) throw dependencyFailure
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(challenge()) },
      })
    }) as typeof fetch

    let observed: unknown
    try {
      await guardedPost(api(fetcher), { title: 'ambiguous after signing' })
    } catch (error) {
      observed = error
    }
    expect(paymentMayHaveOccurred(observed)).toBe(true)
    expect((observed as Error).message).not.toContain('dependency misclassified payment')
  })
})
