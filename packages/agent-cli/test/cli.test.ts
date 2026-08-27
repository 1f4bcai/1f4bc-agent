import { createHash } from 'node:crypto'
import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import * as ed from '@noble/ed25519'
import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
} from '@x402/core/http'
import type { PaymentRequired } from '@x402/core/types'
import { authorizationTypes } from '@x402/evm'
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
} from '@x402/extensions/payment-identifier'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { verifyMessage, verifyTypedData, type Address, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import {
  AgentApi,
  CURRENT_ACCEPTABLE_USE_URL,
  CURRENT_ACCEPTABLE_USE_VERSION,
  CURRENT_PRIVACY_URL,
  CURRENT_PRIVACY_VERSION,
  CURRENT_TERMS_SHA256,
  CURRENT_TERMS_URL,
  CURRENT_TERMS_VERSION,
  MARKETPLACE_PAY_TO_BY_CHAIN_ID,
  MAX_PAYMENT_ATTEMPT_ENTRIES,
  MarketplaceHttpError,
  STAGING_CRASH_HEADER,
  TERMS_ACCEPTANCE_SIGNATURE_VERSION,
  TERMS_ACCEPTANCE_STATEMENT,
  attestationMessage,
  createSigningFetch,
  paymentMayHaveOccurred,
  registrationMessage,
  requestEnvelopeMessage,
  sha256Hex,
  termsAcceptanceMessage,
  walletOwnershipMessage,
  type PaymentRequestOptions,
} from '../src/api.js'
import {
  TerminalPaymentCleared,
  consumeTerminalPaymentClear,
  markTerminalPaymentClearReleased,
  terminalPaymentCleared,
} from '../src/terminal-clear.js'
import { runCli } from '../src/index.js'
import {
  loadIdentity,
  normalizeBaseUrl,
  resolveIdentityPath,
  saveIdentity,
} from '../src/keys.js'
import {
  SpendGuard,
  claimAuthorizedPaymentControl,
  type SpendControl,
} from '../src/mcp-payments.js'
import { spendPolicyScope } from '../src/spend-scope.js'

const walletPrivateKey = `0x${'11'.repeat(32)}`
const legacyEnvironmentWalletPrivateKey = `0x${'22'.repeat(32)}`
const marketplacePayTo = MARKETPLACE_PAY_TO_BY_CHAIN_ID[8453]!
const acceptCurrentTerms = ['--accept-terms', CURRENT_TERMS_VERSION] as const
const cleanup: string[] = []

function currentTermsDescriptorForTest() {
  return {
    version: CURRENT_TERMS_VERSION,
    sha256: CURRENT_TERMS_SHA256,
    url: CURRENT_TERMS_URL,
    acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
    acceptableUseUrl: CURRENT_ACCEPTABLE_USE_URL,
    privacyVersion: CURRENT_PRIVACY_VERSION,
    privacyUrl: CURRENT_PRIVACY_URL,
    signatureVersion: TERMS_ACCEPTANCE_SIGNATURE_VERSION,
    statement: TERMS_ACCEPTANCE_STATEMENT,
  }
}

function termsAcceptanceEvidenceForTest(
  identity: { publicKey: string; wallet: string },
  acceptedAt: number,
  signatureOrigin = 'https://1f4bc.ai',
  signatureChainId = 8453,
) {
  return {
    acceptedAt,
    recordedAt: acceptedAt * 1_000,
    acceptanceSource: 'cli',
    acceptedPubkey: identity.publicKey,
    acceptedWallet: identity.wallet,
    signatureOrigin,
    signatureChainId,
    signatureVersion: TERMS_ACCEPTANCE_SIGNATURE_VERSION,
  }
}

async function acceptedTermsResponse(
  request: Request,
  identity: { publicKey: string; wallet: string },
  signatureOrigin = 'https://1f4bc.ai',
  signatureChainId = 8453,
): Promise<Response> {
  const body = await request.clone().json() as { terms: { acceptedAt: number } }
  return Response.json({
    accepted: true,
    created: true,
    current: currentTermsDescriptorForTest(),
    acceptance: termsAcceptanceEvidenceForTest(
      identity,
      body.terms.acceptedAt,
      signatureOrigin,
      signatureChainId,
    ),
  }, { status: 201 })
}

function acceptedTermsStatusResponse(
  identity: { publicKey: string; wallet: string },
  signatureOrigin = 'https://1f4bc.ai',
  signatureChainId = 8453,
): Response {
  return Response.json({
    accepted: true,
    current: currentTermsDescriptorForTest(),
    acceptance: termsAcceptanceEvidenceForTest(
      identity,
      1_800_000_000,
      signatureOrigin,
      signatureChainId,
    ),
  })
}

async function expectValidAgentEnvelope(
  request: Request,
  identity: { handle?: string; publicKey: string },
  method: string,
  pathWithQuery: string,
  rawBody: string,
): Promise<void> {
  expect(request.method).toBe(method)
  expect(new URL(request.url).pathname + new URL(request.url).search).toBe(pathWithQuery)
  expect(request.headers.get('X-Agent')).toBe(identity.handle)
  const timestamp = request.headers.get('X-Timestamp')
  const signature = request.headers.get('X-Signature')
  expect(timestamp).toMatch(/^[1-9][0-9]*$/)
  expect(signature).toMatch(/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/)
  await expect(ed.verifyAsync(
    Buffer.from(signature!, 'base64'),
    new TextEncoder().encode(requestEnvelopeMessage(
      new URL(request.url).origin,
      method,
      pathWithQuery,
      timestamp!,
      sha256Hex(rawBody),
    )),
    Buffer.from(identity.publicKey, 'base64'),
  )).resolves.toBe(true)
}

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

async function temporaryIdentity(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), '1f4bc-agent-cli-'))
  cleanup.push(directory)
  return join(directory, 'identity.json')
}

function termsReceiptPath(identityFile: string, acceptedPublicKey: string): string {
  const principal = createHash('sha256').update(acceptedPublicKey, 'utf8').digest('hex').slice(0, 24)
  return `${identityFile}.terms-${CURRENT_TERMS_VERSION}-${principal}.json`
}

async function withSpendControl<T>(
  tool: 'post_job' | 'bid_job',
  input: unknown,
  scope: string,
  action: (control: SpendControl) => Promise<T>,
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), '1f4bc-test-spend-'))
  cleanup.push(directory)
  const guard = new SpendGuard({
    journalPath: join(directory, 'spend.json'),
    maxPaymentAtomic: 10_000n,
    dailyPaymentLimitAtomic: 10_000n,
    scope,
  })
  return guard.execute(tool, input, 10_000n, action)
}

function guardedPost(
  api: AgentApi,
  body: unknown,
  options: Omit<PaymentRequestOptions, 'control'> = {},
): Promise<unknown> {
  return withSpendControl(
    'post_job',
    { job: body },
    spendPolicyScope(api.identity.chainId, api.identity.wallet),
    (control) => api.postJob(body, { ...options, control }),
  )
}

function guardedBid(
  api: AgentApi,
  jobId: string,
  bid: unknown,
  options: Omit<PaymentRequestOptions, 'control'> = {},
): Promise<unknown> {
  return withSpendControl(
    'bid_job',
    { jobId, bid },
    spendPolicyScope(api.identity.chainId, api.identity.wallet),
    (control) => api.bid(jobId, bid, { ...options, control }),
  )
}

function paymentAttemptDirectory(path: string, publicKey: string): string {
  return join(dirname(path), 'payment-attempts', sha256Hex(publicKey))
}

function legacyPaymentAttemptKeyForTest(
  identity: { baseUrl: string; chainId: number; wallet: string },
  pathWithQuery: string,
  rawBody: string,
  expectedAmountAtomic: bigint,
): string {
  return sha256Hex([
    identity.baseUrl,
    String(identity.chainId),
    identity.wallet.toLowerCase(),
    'POST',
    pathWithQuery,
    sha256Hex(rawBody),
    expectedAmountAtomic.toString(),
  ].join('\n'))
}

function postingPaymentRequired(): PaymentRequired {
  return {
    x402Version: 2,
    resource: {
      url: 'https://1f4bc.ai/jobs',
      description: '1f4bc posting toll',
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      },
    ],
    extensions: {
      [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
    },
  }
}

const SECP256K1_ORDER =
  115792089237316195423570985008687907852837564279074904382605163141518161494337n

function replaceSignatureParts(
  signature: string,
  transform: (parts: { r: bigint; s: bigint; v: number }) => {
    r: bigint
    s: bigint
    v: number
  },
): `0x${string}` {
  const raw = signature.slice(2)
  const changed = transform({
    r: BigInt(`0x${raw.slice(0, 64)}`),
    s: BigInt(`0x${raw.slice(64, 128)}`),
    v: Number.parseInt(raw.slice(128, 130), 16),
  })
  const word = (value: bigint) => value.toString(16).padStart(64, '0')
  return `0x${word(changed.r)}${word(changed.s)}${changed.v.toString(16).padStart(2, '0')}`
}

function authorizationValidBefore(header: string): number {
  const decoded = decodePaymentSignatureHeader(header)
  const payload = decoded.payload as { authorization?: { validBefore?: unknown } }
  if (typeof payload.authorization?.validBefore !== 'string') {
    throw new Error('test payment header has no validBefore')
  }
  return Number(payload.authorization.validBefore)
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('agent identity', () => {
  it('binds terminal-clear capabilities to one operation and a durable spend release', () => {
    const binding = {
      publicKey: 'public-key',
      attemptKey: 'a'.repeat(64),
      paymentId: '1f4bc_abcdefghijklmnop',
      bodyHash: 'b'.repeat(64),
    }
    const completion = terminalPaymentCleared(binding)
    expect(() => consumeTerminalPaymentClear(completion, {
      publicKey: binding.publicKey,
      bodyHash: binding.bodyHash,
      attemptKeys: [binding.attemptKey],
    })).toThrow(/not durably released/i)
    expect(markTerminalPaymentClearReleased(completion)).toBe(true)
    expect(() => consumeTerminalPaymentClear(completion, {
      publicKey: binding.publicKey,
      bodyHash: 'c'.repeat(64),
      attemptKeys: [binding.attemptKey],
    })).toThrow(/another operation/i)
    expect(consumeTerminalPaymentClear(completion, {
      publicKey: binding.publicKey,
      bodyHash: binding.bodyHash,
      attemptKeys: [binding.attemptKey],
    })).toEqual(binding)
    expect(() => consumeTerminalPaymentClear(completion, {
      publicKey: binding.publicKey,
      bodyHash: binding.bodyHash,
      attemptKeys: [binding.attemptKey],
    })).toThrow(/invalid or was already used/i)
  })

  it('uses exact versioned protocol message namespaces', () => {
    expect(
      requestEnvelopeMessage('https://1f4bc.ai', 'POST', '/jobs', 1, 'a'.repeat(64)),
    ).toBe(`1f4bc-request/1\nhttps://1f4bc.ai\nPOST\n/jobs\n1\n${'a'.repeat(64)}`)
    expect(
      registrationMessage(
        'https://1f4bc.ai',
        8453,
        'alice',
        'public-key',
        '0x1111111111111111111111111111111111111111',
        1,
      ),
    ).toBe(
      '1f4bc-register/1\nhttps://1f4bc.ai\n8453\nalice\npublic-key\n' +
        '0x1111111111111111111111111111111111111111\n1',
    )
    expect(walletOwnershipMessage('https://1f4bc.ai', 8453, 'alice', 'public-key')).toBe(
      '1f4bc-wallet/1\nhttps://1f4bc.ai\n8453\nalice\npublic-key',
    )
    expect(termsAcceptanceMessage(
      'https://1f4bc.ai',
      8453,
      'alice',
      'public-key',
      '0x1111111111111111111111111111111111111111',
      CURRENT_TERMS_VERSION,
      CURRENT_TERMS_SHA256,
      CURRENT_ACCEPTABLE_USE_VERSION,
      CURRENT_PRIVACY_VERSION,
      'cli',
      1,
    )).toBe([
      '1f4bc-terms/1',
      'https://1f4bc.ai',
      '8453',
      'alice',
      'public-key',
      '0x1111111111111111111111111111111111111111',
      CURRENT_TERMS_VERSION,
      CURRENT_TERMS_SHA256,
      CURRENT_ACCEPTABLE_USE_VERSION,
      CURRENT_PRIVACY_VERSION,
      'cli',
      '1',
      'I am authorized to bind the operator, agree to the Terms and Acceptable Use Policy, and acknowledge the Privacy Notice.',
    ].join('\n'))
    expect(attestationMessage('https://1f4bc.ai', 8453, 42, 'job-1')).toBe(
      '1f4bc-attest/1\nhttps://1f4bc.ai\n8453\n42\njob-1',
    )
  })

  it('advertises only profile terminology', async () => {
    let output = ''
    await runCli(['help'], { env: {}, stdout: { write: (chunk) => (output += chunk) } })
    expect(output).toContain('profile set <profile.json>')
    expect(output).not.toMatch(/\bstall\b/)
    expect(output).toContain('F4BC_IDENTITY')
    expect(output).not.toContain('AGENT_BAZAAR_IDENTITY')
    expect(output).toContain('mcp [--allow-write-tools] [--allow-paid-tools')
    expect(output).toContain('--max-payment-atomic')
    expect(output).toContain('--daily-payment-limit-atomic')
    expect(output).toContain('MCP starts read-only')
    expect(output).toContain('--allow-write-tools')
    expect(output).toContain('Paid tools additionally require --allow-paid-tools')
    expect(output).toContain('atomic USDC')
    expect(output).toContain('ambiguous attempts consume the daily cap')
    expect(output).toContain('purpose-funded')
    expect(output).toContain('starts unfunded')
    expect(output).toContain(`terms accept --version ${CURRENT_TERMS_VERSION}`)
    expect(output).toContain(`register <handle> --accept-terms ${CURRENT_TERMS_VERSION}`)
    expect(output).not.toContain('F4BC_WALLET_PRIVATE_KEY')
    expect(output).not.toContain('--wallet-key-file')
  })

  it('shows help without migrating legacy identity state', async () => {
    const home = await mkdtemp(join(tmpdir(), '1f4bc-help-home-'))
    cleanup.push(home)
    const legacyIdentity = join(home, '.agent-bazaar', 'identity.json')
    await runCli(['--identity', legacyIdentity, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const before = await readFile(legacyIdentity, 'utf8')
    let output = ''

    await runCli(['help'], {
      env: {},
      homeDirectory: home,
      stdout: { write: (chunk) => (output += chunk) },
    })

    expect(output).toContain('1f4bc agent CLI')
    expect(await readFile(legacyIdentity, 'utf8')).toBe(before)
    await expect(stat(join(home, '.1f4bc'))).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('never reinterprets post-command text as identity, URL, or chain authority', async () => {
    const first = await temporaryIdentity()
    const second = await temporaryIdentity()
    for (const path of [first, second]) {
      await runCli(['--identity', path, 'init'], {
        env: {},
        generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
    }
    await runCli(['--identity', first, 'register', 'argv-owner', ...acceptCurrentTerms], {
      env: {},
      fetch: vi.fn(async () => Response.json({ handle: 'argv-owner' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const fetcher = vi.fn(async () => Response.json({ ok: true }, { status: 201 })) as typeof fetch

    await expect(runCli([
      '--identity', first,
      'msg', 'job-1', 'bid-1', 'hello', '--url', 'https://attacker.example',
    ], { env: {}, fetch: fetcher, stdout: { write: () => undefined } }))
      .rejects.toThrow(/global option.*precede the command/i)
    await expect(runCli([
      '--identity', first,
      'msg', 'job-1', 'bid-1', 'hello', '--identity', second,
    ], { env: {}, fetch: fetcher, stdout: { write: () => undefined } }))
      .rejects.toThrow(/global option.*precede the command/i)
    await expect(runCli([
      '--identity', first,
      'msg', 'job-1', 'bid-1', 'hello', '--chain-id', '1',
    ], { env: {}, fetch: fetcher, stdout: { write: () => undefined } }))
      .rejects.toThrow(/global option.*precede the command/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('never echoes secret-shaped unknown argv in command or option errors', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const secret = `0x${'de'.repeat(32)}`

    for (const invocation of [
      ['--identity', path, secret],
      [`--${secret}`, 'help'],
    ]) {
      let observed: unknown
      try {
        await runCli(invocation, { env: {}, stdout: { write: () => undefined } })
      } catch (error) {
        observed = error
      }
      expect(observed).toBeInstanceOf(Error)
      expect((observed as Error).message).toMatch(/unknown (?:command|global option)/i)
      expect((observed as Error).message).not.toContain(secret)
    }
  })

  it('starts MCP read-only and passes an explicit write capability only after opt-in', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const runMcp = vi.fn()

    await runCli(
      ['--identity', path, 'mcp'],
      { env: {}, stdout: { write: () => undefined }, runMcp },
    )
    await runCli(
      ['--identity', path, 'mcp', '--allow-write-tools'],
      { env: {}, stdout: { write: () => undefined }, runMcp },
    )

    expect(runMcp.mock.calls).toEqual([
      [expect.any(AgentApi), {}],
      [expect.any(AgentApi), { writeTools: true }],
    ])
  })

  it('requires write opt-in and both explicit MCP spend caps before enabling paid tools', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const runMcp = vi.fn()

    await expect(runCli(
      [
        '--identity', path, 'mcp', '--allow-paid-tools',
        '--max-payment-atomic', '100000', '--daily-payment-limit-atomic', '200000',
      ],
      { env: {}, stdout: { write: () => undefined }, runMcp },
    )).rejects.toThrow(/allow-write-tools/i)
    await expect(runCli(
      [
        '--identity', path, 'mcp', '--allow-write-tools', '--allow-paid-tools',
        '--max-payment-atomic', '100000',
      ],
      { env: {}, stdout: { write: () => undefined }, runMcp },
    )).rejects.toThrow(/daily-payment-limit-atomic.*required/i)
    await expect(runCli(
      ['--identity', path, 'mcp', '--max-payment-atomic', '100000', '--daily-payment-limit-atomic', '200000'],
      { env: {}, stdout: { write: () => undefined }, runMcp },
    )).rejects.toThrow(/allow-paid-tools/i)
    expect(runMcp).not.toHaveBeenCalled()
  })

  it('passes an explicit MCP payment policy with bigint caps and a local journal', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const canonicalPath = await realpath(path)
    const runMcp = vi.fn()

    await runCli([
      '--identity', path,
      'mcp',
      '--allow-write-tools',
      '--allow-paid-tools',
      '--max-payment-atomic', '100000',
      '--daily-payment-limit-atomic', '250000',
    ], { env: {}, stdout: { write: () => undefined }, runMcp })

    expect(runMcp).toHaveBeenCalledOnce()
    expect(runMcp.mock.calls[0]?.[1]).toEqual({
      writeTools: true,
      payments: {
        journalPath: join(dirname(canonicalPath), `spend-${sha256Hex([
          '1f4bc-spend/1',
          identity.chainId,
          identity.wallet.toLowerCase(),
        ].join('\n'))}.json`),
        maxPaymentAtomic: 100_000n,
        dailyPaymentLimitAtomic: 250_000n,
      },
    })
  })

  it('rejects an identity symlink before locating MCP spend state', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const aliasDirectory = await mkdtemp(join(tmpdir(), '1f4bc-identity-alias-'))
    cleanup.push(aliasDirectory)
    const aliasPath = join(aliasDirectory, 'identity.json')
    await symlink(path, aliasPath)
    const runMcp = vi.fn()

    await expect(runCli([
      '--identity', aliasPath,
      'mcp',
      '--allow-write-tools',
      '--allow-paid-tools',
      '--max-payment-atomic', '100000',
      '--daily-payment-limit-atomic', '250000',
    ], { env: {}, stdout: { write: () => undefined }, runMcp }))
      .rejects.toThrow(/symbolic link/i)
    expect(runMcp).not.toHaveBeenCalled()
  })

  it('does not silently bypass an unnamespaced pre-release MCP spend journal', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const legacyPath = join(dirname(path), 'mcp-spend-journal.json')
    await writeFile(legacyPath, '{"version":1,"entries":[]}\n', { mode: 0o600 })
    const runMcp = vi.fn()

    await expect(runCli([
      '--identity', path,
      'mcp',
      '--allow-write-tools',
      '--allow-paid-tools',
      '--max-payment-atomic', '100000',
      '--daily-payment-limit-atomic', '250000',
    ], { env: {}, stdout: { write: () => undefined }, runMcp }))
      .rejects.toThrow(/unnamespaced pre-release MCP spend journal.*recover or archive/i)
    expect(runMcp).not.toHaveBeenCalled()
    await expect(readFile(legacyPath, 'utf8')).resolves.toContain('"version":1')
  })

  it('defaults zero-flag identities to the deployed 1f4bc API', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    expect((await loadIdentity(path)).baseUrl).toBe('https://1f4bc.ai')
  })

  it('atomically moves a hardened legacy identity and payment journals', async () => {
    const home = await mkdtemp(join(tmpdir(), '1f4bc-legacy-home-'))
    cleanup.push(home)
    const legacyIdentity = join(home, '.agent-bazaar', 'identity.json')
    await runCli(['--identity', legacyIdentity, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const legacyJournalDirectory = join(home, '.agent-bazaar', 'payment-attempts')
    const legacyJournal = join(legacyJournalDirectory, 'pending.json')
    await mkdir(legacyJournalDirectory, { recursive: true, mode: 0o700 })
    await writeFile(legacyJournal, '{"paymentId":"preserve-me"}\n', { mode: 0o600 })
    const identityContents = await readFile(legacyIdentity, 'utf8')
    const journalContents = await readFile(legacyJournal, 'utf8')

    const resolved = await resolveIdentityPath(undefined, home, {})
    expect(resolved).toBe(join(home, '.1f4bc', 'identity.json'))
    expect(await readFile(resolved, 'utf8')).toBe(identityContents)
    expect(await readFile(join(home, '.1f4bc', 'payment-attempts', 'pending.json'), 'utf8'))
      .toBe(journalContents)
    await expect(stat(legacyIdentity)).rejects.toMatchObject({ code: 'ENOENT' })
    await expect(stat(legacyJournal)).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('allows HTTP only for loopback development URLs', () => {
    expect(normalizeBaseUrl('http://localhost:8787')).toBe('http://localhost:8787')
    expect(normalizeBaseUrl('http://127.0.0.1:8787')).toBe('http://127.0.0.1:8787')
    expect(() => normalizeBaseUrl('http://bazaar.example')).toThrow(/HTTPS/)
  })

  it.each(['--wallet-private-key', '--wallet-key-file'])(
    'does not accept the wallet import option %s',
    async (walletOption) => {
      const path = await temporaryIdentity()
      let output = ''
      const generateWalletPrivateKey = vi.fn(() => walletPrivateKey)
      await expect(
        runCli(
          ['--identity', path, 'init', walletOption, walletPrivateKey],
          {
            env: {},
            stdout: { write: (chunk) => (output += chunk) },
            generateWalletPrivateKey,
          },
        ),
      ).rejects.toThrow(/usage/)
      expect(generateWalletPrivateKey).not.toHaveBeenCalled()
      expect(output).not.toContain(walletPrivateKey)
    },
  )

  it('generates a distinct local wallet for each default init', async () => {
    const firstPath = await temporaryIdentity()
    const secondPath = join(dirname(firstPath), 'second-identity.json')

    await runCli(['--identity', firstPath, 'init'], {
      env: {},
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', secondPath, 'init'], {
      env: {},
      stdout: { write: () => undefined },
    })

    const first = await loadIdentity(firstPath)
    const second = await loadIdentity(secondPath)
    expect(first.walletPrivateKey).not.toBe(second.walletPrivateKey)
    expect(first.wallet).not.toBe(second.wallet)
  })

  it('never overwrites an existing identity or accepts a force flag', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const original = await readFile(path, 'utf8')

    await expect(runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => legacyEnvironmentWalletPrivateKey,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/refusing to replace key material/i)
    await expect(runCli(['--identity', path, 'init', '--force'], {
      env: {},
      stdout: { write: () => undefined },
    })).rejects.toThrow(/usage: 1f4bc init/i)
    expect(await readFile(path, 'utf8')).toBe(original)
  })

  it('init ignores the legacy key environment variable, creates a purpose-funded wallet, and never prints secrets', async () => {
    const path = await temporaryIdentity()
    let output = ''
    await runCli(['--identity', path, '--url', 'https://bazaar.example', 'init'], {
      env: { F4BC_WALLET_PRIVATE_KEY: legacyEnvironmentWalletPrivateKey },
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: (chunk) => (output += chunk) },
    })

    const identity = await loadIdentity(path)
    const result = JSON.parse(output) as Record<string, unknown>
    expect(identity.publicKey).toBeTruthy()
    expect(identity.wallet).toMatch(/^0x[0-9A-Fa-f]{40}$/)
    expect(identity.walletPrivateKey).toBe(walletPrivateKey)
    expect(identity.walletPrivateKey).not.toBe(legacyEnvironmentWalletPrivateKey)
    expect(identity.baseUrl).toBe('https://bazaar.example')
    expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect(result.walletPurpose).toBe('purpose-funded isolated wallet')
    expect(result.fundingStatus).toBe('unfunded')
    expect(result.warning).toMatch(/starts unfunded/i)
    expect(output).not.toContain(identity.privateKey)
    expect(output).not.toContain(identity.walletPrivateKey)
    expect(output).not.toContain(legacyEnvironmentWalletPrivateKey)
  })

  it('rejects oversized JSON command input before any network request', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const jobFile = join(dirname(path), 'oversized-job.json')
    await writeFile(jobFile, `{"spec":"${'x'.repeat(65 * 1_024)}"}`)
    const fetcher = vi.fn()
    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
      },
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/exceeds 65536 bytes/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects symlinked command input before any network request', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const alias = join(dirname(path), 'profile-link.json')
    await symlink(path, alias)
    const fetcher = vi.fn(async () => Response.json({ ok: true }))

    await expect(runCli(['--identity', path, 'profile', 'set', alias], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/symbolic link/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('rejects local private key material in marketplace request bodies', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const fetcher = vi.fn(async () => Response.json({ ok: true }))
    const api = new AgentApi({ ...identity, handle: 'alice' }, {
      identityPath: path,
      fetch: fetcher as typeof fetch,
    })

    await expect(api.setProfile({
      description: identity.privateKey,
      services: [],
    })).rejects.toThrow(/local private key material/i)
    await expect(api.message('job-1', 'bid-1', identity.walletPrivateKey.slice(2)))
      .rejects.toThrow(/local private key material/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('requires the exact current Terms flag before registration can use the network', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const fetcher = vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 }))

    for (const invocation of [
      ['--identity', path, 'register', 'alice'],
      ['--identity', path, 'register', 'alice', '--accept-terms', '2026-08-24'],
      ['--identity', path, 'register', 'alice', '--accept-terms'],
    ]) {
      let observed: unknown
      try {
        await runCli(invocation, {
          fetch: fetcher as typeof fetch,
          stdout: { write: () => undefined },
        })
      } catch (error) {
        observed = error
      }
      expect(observed).toBeInstanceOf(Error)
      const message = (observed as Error).message
      expect(message).toContain(CURRENT_TERMS_URL)
      expect(message).toContain(CURRENT_TERMS_SHA256)
      expect(message).toContain(CURRENT_ACCEPTABLE_USE_URL)
      expect(message).toContain(CURRENT_PRIVACY_URL)
    }

    expect(fetcher).not.toHaveBeenCalled()
    await expect(stat(termsReceiptPath(path, (await loadIdentity(path)).publicKey)))
      .rejects.toMatchObject({ code: 'ENOENT' })

    const api = new AgentApi(await loadIdentity(path), { fetch: fetcher as typeof fetch })
    await expect(api.register('alice', { acceptedTermsVersion: '2026-08-24' }))
      .rejects.toThrow(/requires explicit acceptance/i)
    await expect(api.acceptTerms('2026-08-24'))
      .rejects.toThrow(/requires version 2026-08-25-r2/i)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('does not claim or cache Terms acceptance before an identity is registered', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const fetcher = vi.fn(async () => {
      throw new Error('pre-registration Terms commands must not use the network')
    })

    await expect(runCli(['--identity', path, 'terms', 'status'], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/identity is not registered/i)

    await expect(runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/identity is not registered/i)
    expect(fetcher).not.toHaveBeenCalled()
    await expect(stat(termsReceiptPath(path, (await loadIdentity(path)).publicKey)))
      .rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('uses signed server status and acceptance while treating the local receipt as a cache', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    const identity = await loadIdentity(path)
    const legacyReceiptPath = join(dirname(path), 'terms-acceptance.json')
    await writeFile(legacyReceiptPath, '{', { mode: 0o600 })
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const pathname = new URL(request.url).pathname
      if (pathname === '/terms/status') {
        return Response.json({
          accepted: false,
          current: currentTermsDescriptorForTest(),
          acceptance: null,
        })
      }
      if (pathname === '/terms/accept') {
        const body = await request.clone().json() as {
          terms: { acceptedAt: number }
        }
        return Response.json({
          accepted: true,
          created: true,
          current: currentTermsDescriptorForTest(),
          acceptance: termsAcceptanceEvidenceForTest(identity, body.terms.acceptedAt),
        }, { status: 201 })
      }
      throw new Error(`unexpected test request ${request.method} ${pathname}`)
    })

    const initial = await runCli(['--identity', path, 'terms', 'status'], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    }) as {
      authority: string
      accepted: boolean
      current: { version: string; sha256: string; url: string }
      acceptance: unknown
      localCache: { present: boolean; error?: string }
    }
    expect(initial).toMatchObject({
      authority: 'server',
      accepted: false,
      current: {
        version: CURRENT_TERMS_VERSION,
        sha256: CURRENT_TERMS_SHA256,
        url: CURRENT_TERMS_URL,
      },
      acceptance: null,
      localCache: {
        present: false,
      },
    })
    await expectValidAgentEnvelope(requests[0]!, identity, 'GET', '/terms/status', '')
    expect(requests[0]!.headers.get('Accept')).toBe('application/json')
    expect(requests[0]!.headers.has('Content-Type')).toBe(false)

    const accepted = await runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    }) as {
      authority: string
      accepted: boolean
      acceptance: { acceptanceSource: string; acceptedAt: number }
      localCache: {
        present: boolean
        matchesServerCurrentDocuments: boolean
        acceptanceSource: string
        acceptedAt: number
      }
    }
    expect(accepted).toMatchObject({
      authority: 'server',
      accepted: true,
      acceptance: {
        acceptanceSource: 'cli',
        acceptedAt: expect.any(Number),
      },
      localCache: {
        present: true,
        matchesServerCurrentDocuments: true,
        acceptanceSource: 'cli',
        acceptedAt: expect.any(Number),
      },
    })
    expect(accepted.localCache.acceptedAt).toBe(accepted.acceptance.acceptedAt)

    const acceptRequest = requests[1]!
    const rawBody = await acceptRequest.clone().text()
    await expectValidAgentEnvelope(acceptRequest, identity, 'POST', '/terms/accept', rawBody)
    expect(acceptRequest.headers.get('Accept')).toBe('application/json')
    expect(acceptRequest.headers.get('Content-Type')).toBe('application/json')
    const body = JSON.parse(rawBody) as {
      terms: {
        version: string
        sha256: string
        acceptableUseVersion: string
        privacyVersion: string
        acceptanceSource: string
        acceptedAt: number
        signature: string
      }
    }
    expect(body).toEqual({
      terms: {
        version: CURRENT_TERMS_VERSION,
        sha256: CURRENT_TERMS_SHA256,
        acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
        privacyVersion: CURRENT_PRIVACY_VERSION,
        acceptanceSource: 'cli',
        acceptedAt: expect.any(Number),
        signature: expect.stringMatching(/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/),
      },
    })
    const innerMessage = termsAcceptanceMessage(
      'https://1f4bc.ai',
      8453,
      'alice',
      identity.publicKey,
      identity.wallet,
      CURRENT_TERMS_VERSION,
      CURRENT_TERMS_SHA256,
      CURRENT_ACCEPTABLE_USE_VERSION,
      CURRENT_PRIVACY_VERSION,
      'cli',
      body.terms.acceptedAt,
    )
    await expect(ed.verifyAsync(
      Buffer.from(body.terms.signature, 'base64'),
      new TextEncoder().encode(innerMessage),
      Buffer.from(identity.publicKey, 'base64'),
    )).resolves.toBe(true)

    const receiptPath = termsReceiptPath(path, identity.publicKey)
    const receiptInfo = await stat(receiptPath)
    expect(receiptInfo.mode & 0o077).toBe(0)
    expect(JSON.parse(await readFile(receiptPath, 'utf8'))).toMatchObject({
      receiptVersion: 1,
      publicKey: (await loadIdentity(path)).publicKey,
      termsVersion: CURRENT_TERMS_VERSION,
      termsSha256: CURRENT_TERMS_SHA256,
      acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
      privacyVersion: CURRENT_PRIVACY_VERSION,
      acceptanceSource: 'cli',
      acceptedAt: body.terms.acceptedAt,
    })
    await expect(readFile(legacyReceiptPath, 'utf8')).resolves.toBe('{')
  })

  it('never overwrites a custom identity literally named terms-acceptance.json', async () => {
    const placeholder = await temporaryIdentity()
    const path = join(dirname(placeholder), 'terms-acceptance.json')
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    const identity = await loadIdentity(path)
    const identityBefore = await readFile(path, 'utf8')
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
      acceptedTermsResponse(new Request(input, init), identity))

    await runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })

    expect(await readFile(path, 'utf8')).toBe(identityBefore)
    await expect(loadIdentity(path)).resolves.toMatchObject({
      privateKey: identity.privateKey,
      walletPrivateKey: identity.walletPrivateKey,
    })
    expect(termsReceiptPath(path, identity.publicKey)).not.toBe(path)
    await expect(stat(termsReceiptPath(path, identity.publicKey)))
      .resolves.toMatchObject({ size: expect.any(Number) })
  })

  it('refuses to replace another identity placed at the computed receipt path', async () => {
    const placeholder = await temporaryIdentity()
    const firstPath = join(dirname(placeholder), 'alice.json')
    await runCli(['--identity', firstPath, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const firstInitialized = await loadIdentity(firstPath)
    await saveIdentity(firstPath, { ...firstInitialized, handle: 'alice' }, { overwrite: true })
    const firstIdentity = await loadIdentity(firstPath)
    const collisionPath = termsReceiptPath(firstPath, firstIdentity.publicKey)
    await runCli(['--identity', collisionPath, 'init'], {
      env: {},
      generateWalletPrivateKey: () => `0x${'44'.repeat(32)}`,
      stdout: { write: () => undefined },
    })
    const collisionBefore = await readFile(collisionPath, 'utf8')
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
      acceptedTermsResponse(new Request(input, init), firstIdentity))

    const result = await runCli([
      '--identity', firstPath,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    }) as { accepted: boolean; localCache: { present: boolean; error?: string } }

    expect(result).toMatchObject({
      accepted: true,
      localCache: {
        present: false,
        error: expect.stringMatching(/refusing to replace.*Terms acceptance receipt/i),
      },
    })
    expect(await readFile(collisionPath, 'utf8')).toBe(collisionBefore)
    await expect(loadIdentity(collisionPath)).resolves.toMatchObject({
      walletPrivateKey: `0x${'44'.repeat(32)}`,
    })
  })

  it('keeps Terms receipts separate for multiple identities in one directory', async () => {
    const placeholder = await temporaryIdentity()
    const firstPath = join(dirname(placeholder), 'first.json')
    const secondPath = join(dirname(placeholder), 'second.json')
    await runCli(['--identity', firstPath, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', secondPath, 'init'], {
      env: {},
      generateWalletPrivateKey: () => `0x${'33'.repeat(32)}`,
      stdout: { write: () => undefined },
    })
    const firstInitialized = await loadIdentity(firstPath)
    const secondInitialized = await loadIdentity(secondPath)
    await saveIdentity(firstPath, { ...firstInitialized, handle: 'alice' }, { overwrite: true })
    await saveIdentity(secondPath, { ...secondInitialized, handle: 'bob' }, { overwrite: true })
    const identities = new Map([
      ['alice', await loadIdentity(firstPath)],
      ['bob', await loadIdentity(secondPath)],
    ])
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const identity = identities.get(request.headers.get('X-Agent') ?? '')
      if (!identity) throw new Error('unexpected Terms identity')
      return acceptedTermsResponse(request, identity)
    })

    for (const path of [firstPath, secondPath]) {
      await runCli([
        '--identity', path,
        'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
      ], {
        env: {},
        fetch: fetcher as typeof fetch,
        stdout: { write: () => undefined },
      })
    }

    const firstIdentity = identities.get('alice')!
    const secondIdentity = identities.get('bob')!
    const firstReceiptPath = termsReceiptPath(firstPath, firstIdentity.publicKey)
    const secondReceiptPath = termsReceiptPath(secondPath, secondIdentity.publicKey)
    const firstReceipt = JSON.parse(await readFile(firstReceiptPath, 'utf8'))
    const secondReceipt = JSON.parse(await readFile(secondReceiptPath, 'utf8'))
    expect(firstReceiptPath).not.toBe(secondReceiptPath)
    expect(firstReceipt.publicKey).toBe(identities.get('alice')!.publicKey)
    expect(secondReceipt.publicKey).toBe(identities.get('bob')!.publicKey)
    expect(firstReceipt.publicKey).not.toBe(secondReceipt.publicKey)
    await expect(loadIdentity(firstPath)).resolves.toMatchObject({ handle: 'alice' })
    await expect(loadIdentity(secondPath)).resolves.toMatchObject({ handle: 'bob' })
  })

  it('rejects contradictory Terms descriptors and acceptance evidence before caching', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    const identity = await loadIdentity(path)
    const fixedNow = 1_800_000_000_000

    const statusApi = new AgentApi(identity, {
      now: () => fixedNow,
      fetch: async () => Response.json({
        accepted: false,
        current: { ...currentTermsDescriptorForTest(), sha256: '0'.repeat(64) },
        acceptance: null,
      }),
    })
    await expect(statusApi.termsStatus()).rejects.toThrow(/does not match this client/i)

    const contradictions: Array<[
      string,
      (current: ReturnType<typeof currentTermsDescriptorForTest>, evidence: ReturnType<typeof termsAcceptanceEvidenceForTest>) => void,
    ]> = [
      ['descriptor', (current) => { current.statement = 'different statement' }],
      ['timestamp', (_current, evidence) => { evidence.acceptedAt += 1 }],
      ['source', (_current, evidence) => { evidence.acceptanceSource = 'browser' }],
      ['public key', (_current, evidence) => { evidence.acceptedPubkey = `${'A'.repeat(43)}=` }],
      ['wallet', (_current, evidence) => { evidence.acceptedWallet = `0x${'22'.repeat(20)}` }],
      ['origin', (_current, evidence) => { evidence.signatureOrigin = 'https://evil.example' }],
      ['chain', (_current, evidence) => { evidence.signatureChainId = 84532 }],
      ['signature version', (_current, evidence) => { evidence.signatureVersion = 'wrong-version' }],
    ]

    for (const [label, contradict] of contradictions) {
      const api = new AgentApi(identity, {
        now: () => fixedNow,
        fetch: async (input, init) => {
          const request = new Request(input, init)
          const body = await request.clone().json() as { terms: { acceptedAt: number } }
          const current = currentTermsDescriptorForTest()
          const evidence = termsAcceptanceEvidenceForTest(identity, body.terms.acceptedAt)
          contradict(current, evidence)
          return Response.json({ accepted: true, created: true, current, acceptance: evidence })
        },
      })
      await expect(api.acceptTerms(CURRENT_TERMS_VERSION), label)
        .rejects.toThrow(/does not match this client|different subject or proof/i)
    }

    await expect(stat(termsReceiptPath(path, identity.publicKey)))
      .rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('does not report or cache Terms acceptance when the server rejects or contradicts it', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    let responseNumber = 0
    const fetcher = vi.fn(async () => {
      responseNumber += 1
      return responseNumber === 1
        ? Response.json({ error: 'unavailable' }, { status: 503 })
        : Response.json({
            accepted: false,
            current: currentTermsDescriptorForTest(),
            acceptance: null,
          })
    })
    let output = ''

    await expect(runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: (chunk) => (output += chunk) },
    })).rejects.toMatchObject({ status: 503 })
    await expect(stat(termsReceiptPath(path, (await loadIdentity(path)).publicKey)))
      .rejects.toMatchObject({ code: 'ENOENT' })
    expect(output).toBe('')

    await expect(runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: (chunk) => (output += chunk) },
    })).rejects.toThrow(/invalid response/i)
    await expect(stat(termsReceiptPath(path, (await loadIdentity(path)).publicKey)))
      .rejects.toMatchObject({ code: 'ENOENT' })
    expect(output).toBe('')
  })

  it('treats the server\'s immutable existing Terms evidence as an idempotent success', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    const identity = await loadIdentity(path)
    const originalEvidence = {
      ...termsAcceptanceEvidenceForTest(
        {
          publicKey: `${'A'.repeat(43)}=`,
          wallet: `0x${'22'.repeat(20)}`,
        },
        1_799_999_000,
      ),
      acceptanceSource: 'browser' as const,
    }
    const fetcher = vi.fn(async () => Response.json({
      accepted: true,
      created: false,
      current: currentTermsDescriptorForTest(),
      acceptance: originalEvidence,
    }))

    const result = await runCli([
      '--identity', path,
      'terms', 'accept', '--version', CURRENT_TERMS_VERSION,
    ], {
      env: {},
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    }) as {
      accepted: boolean
      acceptance: { acceptedAt: number; acceptanceSource: string; acceptedPubkey: string }
      localCache: {
        matchesServerCurrentDocuments: boolean
        acceptanceSource: string
        acceptedAt: number
      }
    }

    expect(result).toMatchObject({
      accepted: true,
      acceptance: originalEvidence,
      localCache: {
        matchesServerCurrentDocuments: false,
        acceptanceSource: 'browser',
        acceptedAt: originalEvidence.acceptedAt,
      },
    })
    expect(JSON.parse(await readFile(
      termsReceiptPath(path, originalEvidence.acceptedPubkey),
      'utf8',
    ))).toMatchObject({
      publicKey: originalEvidence.acceptedPubkey,
      wallet: originalEvidence.acceptedWallet,
      acceptanceSource: 'browser',
      acceptedAt: originalEvidence.acceptedAt,
    })
    expect(identity.publicKey).not.toBe(originalEvidence.acceptedPubkey)
  })

  it('does not couple the inner Terms timestamp to the signed request timestamp', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const initialized = await loadIdentity(path)
    await saveIdentity(path, { ...initialized, handle: 'alice' }, { overwrite: true })
    const identity = await loadIdentity(path)
    const clock = [1_800_000_000_000, 1_800_000_001_000]
    let request: Request | undefined
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      request = new Request(input, init)
      const body = await request.clone().json() as { terms: { acceptedAt: number } }
      return Response.json({
        accepted: true,
        created: true,
        current: currentTermsDescriptorForTest(),
        acceptance: termsAcceptanceEvidenceForTest(identity, body.terms.acceptedAt),
      }, { status: 201 })
    })
    const api = new AgentApi(identity, {
      fetch: fetcher as typeof fetch,
      now: () => clock.shift() ?? 1_800_000_001_000,
    })

    await expect(api.acceptTerms(CURRENT_TERMS_VERSION)).resolves.toMatchObject({
      accepted: true,
      acceptance: { acceptedAt: 1_800_000_000 },
    })
    expect(request).toBeDefined()
    expect(request!.headers.get('X-Timestamp')).toBe('1800000001')
    expect((await request!.clone().json() as { terms: { acceptedAt: number } }).terms.acceptedAt)
      .toBe(1_800_000_000)
  })

  it('register emits the exact key-possession and EIP-191 wallet proofs', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })

    let request: Request | undefined
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      request = new Request(input, init)
      return Response.json({ handle: 'alice' }, { status: 201 })
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })

    expect(fetcher).toHaveBeenCalledOnce()
    expect(request).toBeDefined()
    const body = (await request!.json()) as {
      handle: string
      pubkey: string
      wallet: `0x${string}`
      walletSig: `0x${string}`
      sig: string
      ts: number
      terms: {
        version: string
        sha256: string
        acceptableUseVersion: string
        privacyVersion: string
        acceptanceSource: string
        acceptedAt: number
        signature: string
      }
    }
    const identityMessage = registrationMessage(
      'https://1f4bc.ai',
      8453,
      'alice',
      body.pubkey,
      body.wallet,
      body.ts,
    )
    expect(body.wallet).not.toBe(body.wallet.toLowerCase())
    expect(identityMessage.split('\n')[5]).toBe(body.wallet)
    await expect(
      ed.verifyAsync(
        Buffer.from(body.sig, 'base64'),
        new TextEncoder().encode(identityMessage),
        Buffer.from(body.pubkey, 'base64'),
      ),
    ).resolves.toBe(true)
    await expect(
      ed.verifyAsync(
        Buffer.from(body.sig, 'base64'),
        new TextEncoder().encode(
          registrationMessage(
            'https://other.example',
            8453,
            'alice',
            body.pubkey,
            body.wallet,
            body.ts,
          ),
        ),
        Buffer.from(body.pubkey, 'base64'),
      ),
    ).resolves.toBe(false)
    await expect(
      verifyMessage({
        address: body.wallet,
        message: walletOwnershipMessage('https://1f4bc.ai', 8453, 'alice', body.pubkey),
        signature: body.walletSig,
      }),
    ).resolves.toBe(true)
    await expect(
      verifyMessage({
        address: body.wallet,
        message: walletOwnershipMessage('https://1f4bc.ai', 84532, 'alice', body.pubkey),
        signature: body.walletSig,
      }),
    ).resolves.toBe(false)
    expect(body.terms).toMatchObject({
      version: CURRENT_TERMS_VERSION,
      sha256: CURRENT_TERMS_SHA256,
      acceptableUseVersion: CURRENT_ACCEPTABLE_USE_VERSION,
      privacyVersion: CURRENT_PRIVACY_VERSION,
      acceptanceSource: 'cli',
      acceptedAt: body.ts,
      signature: expect.stringMatching(/^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/),
    })
    const acceptanceMessage = termsAcceptanceMessage(
      'https://1f4bc.ai',
      8453,
      'alice',
      body.pubkey,
      body.wallet,
      CURRENT_TERMS_VERSION,
      CURRENT_TERMS_SHA256,
      CURRENT_ACCEPTABLE_USE_VERSION,
      CURRENT_PRIVACY_VERSION,
      'cli',
      body.ts,
    )
    expect(acceptanceMessage.split('\n')[5]).toBe(body.wallet.toLowerCase())
    expect(acceptanceMessage.endsWith('\n')).toBe(false)
    await expect(
      ed.verifyAsync(
        Buffer.from(body.terms.signature, 'base64'),
        new TextEncoder().encode(acceptanceMessage),
        Buffer.from(body.pubkey, 'base64'),
      ),
    ).resolves.toBe(true)
    await expect(
      ed.verifyAsync(
        Buffer.from(body.terms.signature, 'base64'),
        new TextEncoder().encode([
          '1f4bc-terms/1',
          'https://1f4bc.ai',
          '8453',
          'alice',
          body.pubkey,
          body.wallet,
          CURRENT_TERMS_VERSION,
          CURRENT_TERMS_SHA256,
          CURRENT_ACCEPTABLE_USE_VERSION,
          CURRENT_PRIVACY_VERSION,
          'cli',
          String(body.ts),
          'I am authorized to bind the operator, agree to the Terms and Acceptable Use Policy, and acknowledge the Privacy Notice.',
        ].join('\n')),
        Buffer.from(body.pubkey, 'base64'),
      ),
    ).resolves.toBe(false)
    await expect(
      ed.verifyAsync(
        Buffer.from(body.terms.signature, 'base64'),
        new TextEncoder().encode(termsAcceptanceMessage(
          'https://1f4bc.ai',
          8453,
          'alice',
          body.pubkey,
          body.wallet,
          CURRENT_TERMS_VERSION,
          CURRENT_TERMS_SHA256,
          CURRENT_ACCEPTABLE_USE_VERSION,
          CURRENT_PRIVACY_VERSION,
          'api',
          body.ts,
        )),
        Buffer.from(body.pubkey, 'base64'),
      ),
    ).resolves.toBe(false)
    expect((await loadIdentity(path)).handle).toBe('alice')
  })

  it('sets the public profile with profile terminology', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      return request.url.endsWith('/register')
        ? Response.json({ handle: 'alice' }, { status: 201 })
        : Response.json({ ok: true })
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })
    const profileFile = join(dirname(path), 'profile.json')
    await writeFile(profileFile, JSON.stringify({ description: 'agent profile', services: [] }))

    await runCli(['--identity', path, 'profile', 'set', profileFile], {
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })
    const profileRequest = requests.at(-1)!
    expect(profileRequest.method).toBe('PUT')
    expect(new URL(profileRequest.url).pathname).toBe('/agents/alice')
    expect(await profileRequest.json()).toEqual({ description: 'agent profile', services: [] })
  })

  it('recovers a lost successful registration response from the public agent identity', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://bazaar.example', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const pathname = new URL(request.url).pathname
      if (request.method === 'POST' && pathname === '/register') {
        return Response.json({ error: 'handle taken' }, { status: 409 })
      }
      if (pathname === '/terms/status') {
        return acceptedTermsStatusResponse(identity, 'https://bazaar.example')
      }
      return Response.json({
        handle: 'alice',
        pubkey: identity.publicKey,
        wallet: identity.wallet,
        manifest: {},
        rotations: [],
        facts: null,
      })
    })

    await expect(
      runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
        fetch: fetcher as typeof fetch,
        stdout: { write: () => undefined },
      }),
    ).resolves.toEqual({ handle: 'alice' })
    expect(requests.map((request) => [request.method, new URL(request.url).pathname])).toEqual([
      ['POST', '/register'],
      ['GET', '/agents/alice'],
      ['GET', '/terms/status'],
    ])
    expect((await loadIdentity(path)).handle).toBe('alice')
  })

  it('records current Terms before recovering a matching pre-Terms identity', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://bazaar.example', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      const pathname = new URL(request.url).pathname
      if (request.method === 'POST' && pathname === '/register') {
        return Response.json({ error: 'handle taken' }, { status: 409 })
      }
      if (pathname === '/agents/alice') {
        return Response.json({
          handle: 'alice',
          pubkey: identity.publicKey,
          wallet: identity.wallet,
          manifest: {},
          rotations: [],
          facts: null,
        })
      }
      if (pathname === '/terms/status') {
        return Response.json({
          accepted: false,
          current: currentTermsDescriptorForTest(),
          acceptance: null,
        })
      }
      if (request.method === 'POST' && pathname === '/terms/accept') {
        return acceptedTermsResponse(request, identity, 'https://bazaar.example')
      }
      throw new Error(`unexpected recovery request ${request.method} ${pathname}`)
    })

    await expect(runCli(
      ['--identity', path, 'register', 'alice', ...acceptCurrentTerms],
      { fetch: fetcher as typeof fetch, stdout: { write: () => undefined } },
    )).resolves.toEqual({ handle: 'alice' })
    expect(requests.map((request) => [request.method, new URL(request.url).pathname])).toEqual([
      ['POST', '/register'],
      ['GET', '/agents/alice'],
      ['GET', '/terms/status'],
      ['POST', '/terms/accept'],
    ])
    expect((await loadIdentity(path)).handle).toBe('alice')
  })

  it('recovers a reviewed server-side handle rename without replacing local keys', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://bazaar.example', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const original = await loadIdentity(path)
    await saveIdentity(path, { ...original, handle: '1f4bc-seed-poster' }, { overwrite: true })
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const pathname = new URL(request.url).pathname
      if (request.method === 'POST' && pathname === '/register') {
        return Response.json({ error: 'handle taken' }, { status: 409 })
      }
      if (pathname === '/terms/status') {
        return acceptedTermsStatusResponse(original, 'https://bazaar.example')
      }
      return Response.json({
        handle: 'seed-poster-84bc',
        pubkey: original.publicKey,
        wallet: original.wallet,
        manifest: {},
        rotations: [],
        facts: null,
      })
    })

    await expect(
      runCli(['--identity', path, 'register', 'seed-poster-84bc', ...acceptCurrentTerms], {
        fetch: fetcher as typeof fetch,
        stdout: { write: () => undefined },
      }),
    ).resolves.toEqual({ handle: 'seed-poster-84bc' })
    const recovered = await loadIdentity(path)
    expect(recovered.handle).toBe('seed-poster-84bc')
    expect(recovered.privateKey).toBe(original.privateKey)
    expect(recovered.walletPrivateKey).toBe(original.walletPrivateKey)
  })

  it('rebinds a pending payment journal on reviewed rename and retries the exact authorization', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const original = await loadIdentity(path)
    const oldHandle = '1f4bc-seed-poster'
    const newHandle = 'seed-poster-84bc'
    await saveIdentity(path, { ...original, handle: oldHandle }, { overwrite: true })
    const oldIdentity = await loadIdentity(path)
    const body = { title: 'one authorization survives a handle rename' }
    const oldPaymentHeaders: string[] = []
    const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        oldPaymentHeaders.push(payment)
        throw new Error('connection lost after settlement')
      }
      return Response.json(
        { error: 'payment required' },
        {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
        },
      )
    })
    const firstApi = new AgentApi(oldIdentity, {
      fetch: firstFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_000_000,
    })

    let firstError: unknown
    try {
      await guardedPost(firstApi, body)
    } catch (error) {
      firstError = error
    }
    expect(paymentMayHaveOccurred(firstError)).toBe(true)
    expect(oldPaymentHeaders.length).toBeGreaterThan(0)
    expect(new Set(oldPaymentHeaders)).toEqual(new Set([oldPaymentHeaders[0]!]))

    const journalDirectory = paymentAttemptDirectory(path, original.publicKey)
    const oldJournalFiles = (await readdir(journalDirectory))
      .filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    expect(oldJournalFiles).toHaveLength(1)
    const staleFetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const staleApi = new AgentApi(oldIdentity, {
      fetch: staleFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_005_000,
    })
    const recoveryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const pathname = new URL(request.url).pathname
      if (request.method === 'POST' && pathname === '/register') {
        return Response.json({ error: 'handle taken' }, { status: 409 })
      }
      if (pathname === '/terms/status') return acceptedTermsStatusResponse(original)
      return Response.json({
        handle: newHandle,
        pubkey: original.publicKey,
        wallet: original.wallet,
        manifest: {},
        rotations: [],
        facts: null,
      })
    })
    const recoveryApi = new AgentApi(oldIdentity, {
      fetch: recoveryFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_006_000,
    })

    await expect(recoveryApi.register(newHandle, {
      acceptedTermsVersion: CURRENT_TERMS_VERSION,
    })).resolves.toEqual({ handle: newHandle })
    expect((await loadIdentity(path)).handle).toBe(newHandle)
    const reboundFiles = (await readdir(journalDirectory))
      .filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    expect(reboundFiles).toHaveLength(1)
    expect(reboundFiles[0]).not.toBe(oldJournalFiles[0])
    expect(JSON.parse(await readFile(join(journalDirectory, reboundFiles[0]!), 'utf8')))
      .toMatchObject({ state: 'pending', handle: newHandle, headerValue: oldPaymentHeaders[0] })

    let staleError: unknown
    try {
      await guardedPost(staleApi, body)
    } catch (error) {
      staleError = error
    }
    expect(staleError).toBeInstanceOf(Error)
    expect((staleError as Error).message).toMatch(/handle changed on disk/i)
    expect(paymentMayHaveOccurred(staleError)).toBe(false)
    expect(staleFetcher).not.toHaveBeenCalled()

    const retriedRequests: Request[] = []
    const retryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      retriedRequests.push(request)
      if (!request.headers.get('PAYMENT-SIGNATURE')) {
        return Response.json(
          { error: 'payment required' },
          {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
          },
        )
      }
      return Response.json({ id: 'job-recovered-after-rename' }, { status: 201 })
    })
    const retryApi = await AgentApi.fromIdentityFile(path, {
      fetch: retryFetcher as typeof fetch,
      now: () => 1_800_000_010_000,
    })

    await expect(guardedPost(retryApi, body))
      .resolves.toEqual({ id: 'job-recovered-after-rename' })
    expect(retriedRequests).toHaveLength(1)
    expect(retriedRequests[0]!.headers.get('X-Agent')).toBe(newHandle)
    expect(retriedRequests[0]!.headers.get('PAYMENT-SIGNATURE')).toBe(oldPaymentHeaders[0])
    const settled = JSON.parse(await readFile(join(journalDirectory, reboundFiles[0]!), 'utf8'))
    expect(settled).toMatchObject({
      state: 'settled',
      handle: newHandle,
      headerValue: oldPaymentHeaders[0],
      result: { id: 'job-recovered-after-rename' },
    })
  })

  it('rebinds a settled payment journal on reviewed rename without another marketplace request', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const original = await loadIdentity(path)
    const oldHandle = '1f4bc-seed-poster'
    const newHandle = 'seed-poster-84bc'
    await saveIdentity(path, { ...original, handle: oldHandle }, { overwrite: true })
    const oldIdentity = await loadIdentity(path)
    const body = { title: 'settled staging job survives the reviewed rename' }
    const paidHeaders: string[] = []
    const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        paidHeaders.push(payment)
        return Response.json({ id: 'staging-job-before-rename' }, { status: 201 })
      }
      return Response.json(
        { error: 'payment required' },
        {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
        },
      )
    })
    const firstApi = new AgentApi(oldIdentity, {
      fetch: firstFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_000_000,
    })
    await expect(guardedPost(firstApi, body))
      .resolves.toEqual({ id: 'staging-job-before-rename' })
    expect(paidHeaders).toHaveLength(1)

    const journalDirectory = paymentAttemptDirectory(path, original.publicKey)
    const oldFiles = (await readdir(journalDirectory))
      .filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    expect(oldFiles).toHaveLength(1)
    const before = JSON.parse(await readFile(join(journalDirectory, oldFiles[0]!), 'utf8')) as {
      paymentId: string
      headerValue: string
      result: unknown
    }
    expect(before).toMatchObject({
      paymentId: expect.stringMatching(/^1f4bc_/),
      headerValue: paidHeaders[0],
      result: { id: 'staging-job-before-rename' },
    })

    const recoveryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const pathname = new URL(request.url).pathname
      if (request.method === 'POST' && pathname === '/register') {
        return Response.json({ error: 'handle taken' }, { status: 409 })
      }
      if (pathname === '/terms/status') return acceptedTermsStatusResponse(original)
      return Response.json({
        handle: newHandle,
        pubkey: original.publicKey,
        wallet: original.wallet,
        manifest: {},
        rotations: [],
        facts: null,
      })
    })
    const recoveryApi = new AgentApi(oldIdentity, {
      fetch: recoveryFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_005_000,
    })
    await expect(recoveryApi.register(newHandle, {
      acceptedTermsVersion: CURRENT_TERMS_VERSION,
    })).resolves.toEqual({ handle: newHandle })

    const reboundFiles = (await readdir(journalDirectory))
      .filter((name) => /^[0-9a-f]{64}\.json$/.test(name))
    expect(reboundFiles).toHaveLength(1)
    expect(reboundFiles[0]).not.toBe(oldFiles[0])
    const noNetworkFetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const retryApi = await AgentApi.fromIdentityFile(path, {
      fetch: noNetworkFetcher as typeof fetch,
      now: () => 1_800_000_010_000,
    })

    await expect(guardedPost(retryApi, body))
      .resolves.toEqual({ id: 'staging-job-before-rename' })
    expect(noNetworkFetcher).not.toHaveBeenCalled()
    expect(JSON.parse(await readFile(join(journalDirectory, reboundFiles[0]!), 'utf8')))
      .toMatchObject({
        state: 'settled',
        handle: newHandle,
        paymentId: before.paymentId,
        headerValue: before.headerValue,
        result: before.result,
      })
  })

  it.each(['pubkey', 'wallet'] as const)(
    'rejects registration recovery when the existing %s does not match',
    async (field) => {
      const path = await temporaryIdentity()
      await runCli(['--identity', path, '--url', 'https://bazaar.example', 'init'], {
        env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
      const identity = await loadIdentity(path)
      const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (request.method === 'POST') {
          return Response.json({ error: 'handle taken' }, { status: 409 })
        }
        return Response.json({
          handle: 'alice',
          pubkey: field === 'pubkey' ? 'different-public-key' : identity.publicKey,
          wallet: field === 'wallet' ? `0x${'22'.repeat(20)}` : identity.wallet,
        })
      })

      await expect(
        runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
          fetch: fetcher as typeof fetch,
          stdout: { write: () => undefined },
        }),
      ).rejects.toThrow(/does not match the local identity/)
      expect((await loadIdentity(path)).handle).toBeUndefined()
    },
  )

  it('re-signs every network attempt with a fresh envelope timestamp', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const base = await loadIdentity(path)
    const identity = { ...base, handle: 'alice' }
    const seen: Request[] = []
    const rawFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(new Request(input, init))
      return Response.json({ ok: true })
    })
    const signedFetch = createSigningFetch(identity, rawFetch as typeof fetch, () => 1_800_000_000_000)
    const body = '{"a":1}'
    await signedFetch(`${identity.baseUrl}/jobs?draft=1`, { method: 'POST', body })
    await signedFetch(`${identity.baseUrl}/jobs?draft=1`, { method: 'POST', body })

    expect(seen).toHaveLength(2)
    const timestamps = seen.map((request) => request.headers.get('X-Timestamp'))
    expect(timestamps).toEqual(['1800000000', '1800000001'])
    for (const request of seen) {
      expect(request.headers.get('X-Agent')).toBe('alice')
      expect(request.headers.has('X-Citizen')).toBe(false)
      const timestamp = request.headers.get('X-Timestamp')!
      const signature = Buffer.from(request.headers.get('X-Signature')!, 'base64')
      const message = requestEnvelopeMessage(
        identity.baseUrl,
        'POST',
        '/jobs?draft=1',
        timestamp,
        sha256Hex(body),
      )
      await expect(
        ed.verifyAsync(signature, new TextEncoder().encode(message), Buffer.from(identity.publicKey, 'base64')),
      ).resolves.toBe(true)
      await expect(
        ed.verifyAsync(
          signature,
          new TextEncoder().encode(
            requestEnvelopeMessage(
              'https://other.example',
              'POST',
              '/jobs?draft=1',
              timestamp,
              sha256Hex(body),
            ),
          ),
          Buffer.from(identity.publicKey, 'base64'),
        ),
      ).resolves.toBe(false)
    }
  })

  it.each([502, 409, 428])(
    'surfaces an unpaid HTTP %i without attempting an exact paid retry',
    async (status) => {
      const path = await temporaryIdentity()
      await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
        env: {},
        generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
      const identity = { ...(await loadIdentity(path)), handle: 'alice' }
      const requests: Request[] = []
      const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        requests.push(request)
        return new Response('unpaid request rejected before an x402 challenge', { status })
      })
      const api = new AgentApi(identity, {
        identityPath: path,
        fetch: fetcher as typeof fetch,
      })

      let observed: unknown
      try {
        await guardedPost(api, { title: 'must remain unpaid' })
      } catch (error) {
        observed = error
      }

      expect(observed).toBeInstanceOf(MarketplaceHttpError)
      expect((observed as MarketplaceHttpError).status).toBe(status)
      expect(requests).toHaveLength(1)
      expect(requests[0]!.headers.has('PAYMENT-SIGNATURE')).toBe(false)
      expect(
        (await readdir(paymentAttemptDirectory(path, identity.publicKey)))
          .filter((name) => name.endsWith('.json')),
      ).toEqual([])
      expect(paymentMayHaveOccurred(observed)).toBe(false)
    },
  )

  it('releases the spend reservation when a fresh unpaid request returns 428', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const api = new AgentApi(identity, {
      identityPath: path,
      fetch: vi.fn(async () => Response.json(
        { error: 'current terms acceptance required' },
        { status: 428 },
      )) as typeof fetch,
    })
    const guard = new SpendGuard({
      journalPath: join(dirname(path), 'terms-spend.json'),
      maxPaymentAtomic: 10_000n,
      dailyPaymentLimitAtomic: 10_000n,
      scope: spendPolicyScope(identity.chainId, identity.wallet),
    })
    const firstInput = { job: { title: 'blocked before payment' } }
    let observed: unknown
    try {
      await guard.execute(
        'post_job',
        firstInput,
        10_000n,
        (control) => api.postJob(firstInput.job, { control }),
      )
    } catch (error) {
      observed = error
    }
    expect(paymentMayHaveOccurred(observed)).toBe(false)
    await expect(guard.execute(
      'post_job',
      { job: { title: 'capacity was released' } },
      10_000n,
      async (control) => {
        claimAuthorizedPaymentControl(
          control,
          'post_job',
          { job: { title: 'capacity was released' } },
          10_000n,
          spendPolicyScope(identity.chainId, identity.wallet),
        )
        return 'released'
      },
    )).resolves.toBe('released')
  })

  it.each(['post', 'bid'] as const)(
    'retains and reuses one durable %s authorization across a 428 Terms gate',
    async (operation) => {
      const path = await temporaryIdentity()
      await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
        env: {},
        generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
      const identity = { ...(await loadIdentity(path)), handle: 'alice' }
      const requestPath = operation === 'post' ? '/jobs' : '/jobs/job-terms/bids'
      const required = postingPaymentRequired()
      required.resource.url = `https://1f4bc.ai${requestPath}`
      const body = operation === 'post'
        ? { title: 'one post authorization' }
        : { message: 'one bid authorization', priceAtomic: '10000', etaHours: 1 }
      const paidHeaders: string[] = []
      let phase: 'disconnect' | 'terms' | 'accepted' = 'disconnect'
      const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (
          operation === 'bid' &&
          request.method === 'GET' &&
          new URL(request.url).pathname === '/jobs/job-terms'
        ) {
          return Response.json({ id: 'job-terms' })
        }
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (!payment) {
          return Response.json(
            { error: 'payment required' },
            {
              status: 402,
              headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
            },
          )
        }
        paidHeaders.push(payment)
        if (phase === 'disconnect') throw new Error('connection lost after authorization')
        if (phase === 'terms') {
          return Response.json(
            { error: 'current terms acceptance required' },
            { status: 428 },
          )
        }
        return Response.json(
          { id: operation === 'post' ? 'job-after-terms' : 'bid-after-terms' },
          { status: 201 },
        )
      })
      const invoke = (api: AgentApi) => operation === 'post'
        ? guardedPost(api, body)
        : guardedBid(api, 'job-terms', body)

      let disconnected: unknown
      try {
        await invoke(new AgentApi(identity, {
          identityPath: path,
          fetch: fetcher as typeof fetch,
          now: () => 1_800_000_000_000,
        }))
      } catch (error) {
        disconnected = error
      }
      expect(paymentMayHaveOccurred(disconnected)).toBe(true)

      phase = 'terms'
      let gated: unknown
      try {
        await invoke(new AgentApi(identity, {
          identityPath: path,
          fetch: fetcher as typeof fetch,
          now: () => 1_800_000_001_000,
        }))
      } catch (error) {
        gated = error
      }
      expect(gated).toBeInstanceOf(Error)
      expect(paymentMayHaveOccurred(gated)).toBe(true)
      const attemptNames = (
        await readdir(paymentAttemptDirectory(path, identity.publicKey))
      ).filter((name) => name.endsWith('.json'))
      expect(attemptNames).toHaveLength(1)

      phase = 'accepted'
      await expect(invoke(new AgentApi(identity, {
        identityPath: path,
        fetch: fetcher as typeof fetch,
        now: () => 1_800_000_002_000,
      }))).resolves.toEqual({
        id: operation === 'post' ? 'job-after-terms' : 'bid-after-terms',
      })
      // The first interrupted response can trigger an internal exact retry.
      // Regardless of retry count, every request must reuse one byte-identical
      // authorization and the durable journal must never duplicate it.
      expect(paidHeaders.length).toBeGreaterThanOrEqual(3)
      expect(new Set(paidHeaders)).toEqual(new Set([paidHeaders[0]!]))
      expect(
        (await readdir(paymentAttemptDirectory(path, identity.publicKey)))
          .filter((name) => name.endsWith('.json')),
      ).toEqual(attemptNames)
      const settledAttempt = JSON.parse(await readFile(
        join(paymentAttemptDirectory(path, identity.publicKey), attemptNames[0]!),
        'utf8',
      )) as unknown
      expect(settledAttempt).toMatchObject({
        version: 2,
        state: 'settled',
        headerName: 'payment-signature',
        headerValue: paidHeaders[0],
        result: {
          id: operation === 'post' ? 'job-after-terms' : 'bid-after-terms',
        },
      })
    },
  )

  it('retains one payment identifier while re-signing a settle-recovery retry', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount: '10000',
          payTo: marketplacePayTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const requests: Request[] = []
    let paidAttempts = 0
    let failedAttemptCancelled = () => false
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      if (!request.headers.has('PAYMENT-SIGNATURE')) {
        return Response.json(
          { error: 'payment required' },
          {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          },
        )
      }
      paidAttempts += 1
      if (paidAttempts === 1) {
        const tracked = cancellableResponse('injected crash body must not be exposed', { status: 500 })
        failedAttemptCancelled = tracked.cancelled
        return tracked.response
      }
      return Response.json({ id: 'job-1' }, { status: 201 })
    })
    const api = new AgentApi(identity, {
      identityPath: path,
      fetch: fetcher as typeof fetch,
      now: () => 1_800_000_000_000,
    })

    await expect(guardedPost(api, { title: 'test' })).resolves.toEqual({ id: 'job-1' })
    expect(requests.length).toBeGreaterThanOrEqual(3)
    const paymentIds = requests
      .filter((request) => request.headers.has('PAYMENT-SIGNATURE'))
      .map((request) => {
        const payload = decodePaymentSignatureHeader(request.headers.get('PAYMENT-SIGNATURE')!)
        const extension = payload.extensions?.[PAYMENT_IDENTIFIER] as
          | { info?: { id?: string } }
          | undefined
        return extension?.info?.id
      })
    expect(paymentIds[0]).toMatch(/^1f4bc_[A-Za-z0-9_-]{16,}$/)
    expect(paymentIds).toEqual([paymentIds[0], paymentIds[0]])
    const firstPayment = decodePaymentSignatureHeader(
      requests.find((request) => request.headers.has('PAYMENT-SIGNATURE'))!
        .headers.get('PAYMENT-SIGNATURE')!,
    )
    const firstAuthorization = firstPayment.payload.authorization as {
      from: Address
      to: Address
      value: string
      validAfter: string
      validBefore: string
      nonce: Hex
    }
    expect(firstAuthorization.nonce).toBe(`0x${sha256Hex(
      `1f4bc:post-job:v1\n${paymentIds[0]}\n${sha256Hex(JSON.stringify({ title: 'test' }))}`,
    )}`)
    await expect(verifyTypedData({
      address: identity.wallet,
      domain: {
        name: 'USD Coin',
        version: '2',
        chainId: 8453,
        verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      },
      types: authorizationTypes,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: firstAuthorization.from,
        to: firstAuthorization.to,
        value: BigInt(firstAuthorization.value),
        validAfter: BigInt(firstAuthorization.validAfter),
        validBefore: BigInt(firstAuthorization.validBefore),
        nonce: firstAuthorization.nonce,
      },
      signature: firstPayment.payload.signature as Hex,
    })).resolves.toBe(true)
    const paymentHeaders = requests
      .map((request) => request.headers.get('PAYMENT-SIGNATURE'))
      .filter((value): value is string => value !== null)
    expect(paymentHeaders).toEqual([paymentHeaders[0], paymentHeaders[0]])
    const timestamps = requests.map((request) => Number(request.headers.get('X-Timestamp')))
    expect(new Set(timestamps).size).toBe(timestamps.length)
    expect(failedAttemptCancelled()).toBe(true)
  })

  it('carries the settle-crash token only on paid Base Sepolia staging attempts', async () => {
    const path = await temporaryIdentity()
    const stagingUrl = 'https://1f4bc-staging.1f4bc.workers.dev'
    const token = ['staging-crash', 'token-with-at-least-32-characters'].join('-')
    await runCli([
      '--identity', path,
      '--url', stagingUrl,
      '--chain-id', '84532',
      'init',
    ], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const jobFile = join(dirname(path), 'job.json')
    await writeFile(jobFile, JSON.stringify({ title: 'staging crash' }))
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: `${stagingUrl}/jobs`,
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:84532',
          asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
          amount: '10000',
          payTo: marketplacePayTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USDC', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const requests: Request[] = []
    let paidAttempts = 0
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      if (!request.headers.has('PAYMENT-SIGNATURE')) {
        return Response.json(
          { error: 'payment required' },
          {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          },
        )
      }
      paidAttempts += 1
      return paidAttempts === 1
        ? Response.json({ error: 'injected crash' }, { status: 500 })
        : Response.json({ id: 'staging-job-1' }, { status: 201 })
    })

    await expect(runCli([
      '--identity', path,
      'post', jobFile,
      '--staging-settle-crash',
    ], {
      env: {
        F4BC_STAGING_CRASH_TOKEN: token,
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '100000',
      },
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).resolves.toEqual({ id: 'staging-job-1' })

    expect(requests).toHaveLength(3)
    expect(requests[0]!.headers.has(STAGING_CRASH_HEADER)).toBe(false)
    expect(requests.slice(1).map((request) => request.headers.get(STAGING_CRASH_HEADER)))
      .toEqual([token, token])
    const paidHeaders = requests.slice(1)
      .map((request) => request.headers.get('PAYMENT-SIGNATURE'))
    expect(paidHeaders[1]).toBe(paidHeaders[0])
  })

  it('rejects the mainnet token domain in a Base Sepolia marketplace challenge', async () => {
    const path = await temporaryIdentity()
    const stagingUrl = 'https://1f4bc-staging.1f4bc.workers.dev'
    await runCli([
      '--identity', path,
      '--url', stagingUrl,
      '--chain-id', '84532',
      'init',
    ], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const jobFile = join(dirname(path), 'wrong-domain-job.json')
    await writeFile(jobFile, JSON.stringify({ title: 'wrong token domain' }))
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: `${stagingUrl}/jobs`,
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:84532',
        asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
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
      return Response.json({ id: 'must-not-be-created' }, { status: 201 })
    })

    await expect(runCli([
      '--identity', path,
      'post', jobFile,
    ], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
      },
      fetch: fetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/challenge does not match the pinned payment policy/i)
    expect(paidAttemptSent).toBe(false)
  })

  it.each([
    ['shorter timeout', (required: PaymentRequired) => {
      required.accepts[0]!.maxTimeoutSeconds = 299
    }],
    ['additional accepted key', (required: PaymentRequired) => {
      Object.assign(required.accepts[0]!, { unexpected: true })
    }],
    ['additional token-domain key', (required: PaymentRequired) => {
      Object.assign(required.accepts[0]!.extra!, { assetTransferMethod: 'eip3009' })
    }],
  ] as const)(
    'rejects a marketplace challenge the Worker would reject: %s',
    async (_label, mutate) => {
      const path = await temporaryIdentity()
      await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
        env: {},
        generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
      const identity = { ...(await loadIdentity(path)), handle: 'alice' }
      const required = structuredClone(postingPaymentRequired())
      mutate(required)
      let paidAttemptSent = false
      const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (request.headers.has('PAYMENT-SIGNATURE')) {
          paidAttemptSent = true
          return Response.json({ id: 'must-not-be-created' }, { status: 201 })
        }
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        })
      })
      const api = new AgentApi(identity, {
        identityPath: path,
        fetch: fetcher as typeof fetch,
      })

      await expect(guardedPost(api, { title: 'strict challenge contract' }))
        .rejects.toThrow(/challenge does not match the pinned payment policy/i)
      expect(paidAttemptSent).toBe(false)
    },
  )

  it('validates retained authorizations against the Worker exact-schema and ECDSA contract', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const job = { title: 'strict retained authorization contract' }
    let retainedHeader = ''
    const ambiguousFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        retainedHeader = payment
        throw new Error('ambiguous transport failure')
      }
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
      })
    })
    await expect(guardedPost(new AgentApi(identity, {
      identityPath: path,
      fetch: ambiguousFetcher as typeof fetch,
    }), job)).rejects.toThrow('ambiguous transport failure')

    const directory = paymentAttemptDirectory(path, identity.publicKey)
    const [attemptName] = (await readdir(directory)).filter((name) => name.endsWith('.json'))
    const attemptPath = join(directory, attemptName!)
    const originalAttempt = JSON.parse(await readFile(attemptPath, 'utf8')) as Record<string, unknown>
    const originalPayload = decodePaymentSignatureHeader(retainedHeader)
    const originalSignature = originalPayload.payload.signature as string
    const mutations: Array<[string, (payload: ReturnType<typeof decodePaymentSignatureHeader>) => void]> = [
      ['timeout', (payload) => { payload.accepted.maxTimeoutSeconds = 299 }],
      ['accepted keys', (payload) => { Object.assign(payload.accepted, { unexpected: true }) }],
      ['token-domain keys', (payload) => {
        Object.assign(payload.accepted.extra, { assetTransferMethod: 'eip3009' })
      }],
      ['payload keys', (payload) => { Object.assign(payload.payload, { unexpected: true }) }],
      ['authorization keys', (payload) => {
        Object.assign(payload.payload.authorization as object, { unexpected: true })
      }],
      ['non-contract recovery byte', (payload) => {
        payload.payload.signature = replaceSignatureParts(
          originalSignature,
          ({ r, s, v }) => ({ r, s, v: v - 27 }),
        )
      }],
      ['high-s signature', (payload) => {
        payload.payload.signature = replaceSignatureParts(
          originalSignature,
          ({ r, s, v }) => ({ r, s: SECP256K1_ORDER - s, v: v === 27 ? 28 : 27 }),
        )
      }],
    ]

    for (const [label, mutate] of mutations) {
      const changed = structuredClone(originalPayload)
      mutate(changed)
      await writeFile(attemptPath, `${JSON.stringify({
        ...originalAttempt,
        headerValue: btoa(JSON.stringify(changed)),
      })}\n`, { mode: 0o600 })
      const network = vi.fn(async () => {
        throw new Error('recovery network must not be reached')
      })
      await expect(new AgentApi(identity, {
        identityPath: path,
        fetch: network as typeof fetch,
      }).recoverPostJob(job), label).rejects.toThrow(/pinned payment policy|invalid EIP-3009/i)
      expect(network, label).not.toHaveBeenCalled()
    }
  })

  it('refuses to send a settle-crash token to mainnet, HTTP, or a non-staging host', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const fetcher = vi.fn()
    const token = ['staging-crash', 'token-with-at-least-32-characters'].join('-')
    const cases = [
      new AgentApi(identity, { fetch: fetcher as typeof fetch }),
      new AgentApi(identity, {
        fetch: fetcher as typeof fetch,
        baseUrl: 'http://localhost:8787',
        chainId: 84532,
      }),
      new AgentApi(identity, {
        fetch: fetcher as typeof fetch,
        baseUrl: 'https://1f4bc-staging.attacker.example',
        chainId: 84532,
      }),
    ]

    for (const api of cases) {
      await expect(guardedPost(api, { title: 'must not send' }, { stagingCrashToken: token }))
        .rejects.toThrow(/Base Sepolia HTTPS staging/i)
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('refuses private keys configured as a staging crash token before any request', async () => {
    const path = await temporaryIdentity()
    await runCli([
      '--identity', path,
      '--url', 'https://1f4bc-staging.1f4bc.workers.dev',
      '--chain-id', '84532',
      'init',
    ], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const fetcher = vi.fn()
    const api = new AgentApi(identity, {
      identityPath: path,
      fetch: fetcher as typeof fetch,
    })

    for (const stagingCrashToken of [identity.privateKey, identity.walletPrivateKey]) {
      await expect(guardedPost(api, { title: 'must not send' }, { stagingCrashToken }))
        .rejects.toThrow(/staging crash token contains local private key material/i)
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('refuses private keys embedded in balance and receipt RPC URLs before any request', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const fetcher = vi.fn()
    const calls = [
      ['balance', '--rpc-url', `https://rpc.example/?token=${identity.privateKey}`],
      [
        'receipt',
        `0x${'12'.repeat(32)}`,
        '--rpc-url',
        `https://rpc.example/?token=${identity.walletPrivateKey}`,
      ],
    ]
    for (const args of calls) {
      await expect(runCli(['--identity', path, ...args], {
        env: {},
        fetch: fetcher as typeof fetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/RPC URL contains local private key material/i)
    }
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('recovers an ambiguous paid request across CLI processes without a new authorization', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount: '10000',
          payTo: marketplacePayTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const firstProcessHeaders: string[] = []
    const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        firstProcessHeaders.push(payment)
        throw new Error('connection lost after settlement')
      }
      return Response.json(
        { error: 'payment required' },
        {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        },
      )
    })
    const body = { title: 'survives process crash' }
    const firstApi = new AgentApi(identity, {
      fetch: firstFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_000_000,
    })

    await expect(guardedPost(firstApi, body)).rejects.toThrow('connection lost after settlement')
    expect(firstProcessHeaders).toHaveLength(2)
    expect(firstProcessHeaders[1]).toBe(firstProcessHeaders[0])
    const journalDirectory = paymentAttemptDirectory(path, identity.publicKey)
    const journalFiles = await readdir(journalDirectory)
    expect(journalFiles).toHaveLength(1)
    expect((await stat(journalDirectory)).mode & 0o777).toBe(0o700)
    expect((await stat(join(journalDirectory, journalFiles[0]!))).mode & 0o777).toBe(0o600)

    const secondProcessRequests: Request[] = []
    const secondFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      secondProcessRequests.push(request)
      return Response.json({ id: 'job-recovered' }, { status: 201 })
    })
    const secondApi = new AgentApi(identity, {
      fetch: secondFetcher as typeof fetch,
      identityPath: path,
      now: () => 1_800_000_010_000,
    })

    await expect(guardedPost(secondApi, body)).resolves.toEqual({ id: 'job-recovered' })
    expect(secondProcessRequests).toHaveLength(1)
    expect(secondProcessRequests[0]!.headers.get('PAYMENT-SIGNATURE')).toBe(firstProcessHeaders[0])
    const settledFiles = await readdir(journalDirectory)
    expect(settledFiles).toHaveLength(1)
    const settled = JSON.parse(await readFile(join(journalDirectory, settledFiles[0]!), 'utf8')) as {
      state: string
      result: unknown
    }
    expect(settled).toMatchObject({ state: 'settled', result: { id: 'job-recovered' } })

    const thirdFetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const thirdApi = new AgentApi(identity, {
      fetch: thirdFetcher as typeof fetch,
      identityPath: path,
    })
    await expect(guardedPost(thirdApi, body)).resolves.toEqual({ id: 'job-recovered' })
    expect(thirdFetcher).not.toHaveBeenCalled()
  })

  it('isolates paid result journals for two principals in the same directory', async () => {
    const firstPath = await temporaryIdentity()
    const secondPath = join(dirname(firstPath), 'second-identity.json')
    await runCli(['--identity', firstPath, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', secondPath, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const firstIdentity = { ...(await loadIdentity(firstPath)), handle: 'alice' }
    const secondIdentity = { ...(await loadIdentity(secondPath)), handle: 'bob' }
    expect(firstIdentity.wallet).toBe(secondIdentity.wallet)
    expect(firstIdentity.publicKey).not.toBe(secondIdentity.publicKey)
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const fetcherFor = (id: string) => vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      return request.headers.has('PAYMENT-SIGNATURE')
        ? Response.json({ id }, { status: 201 })
        : new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          })
    })
    const firstFetcher = fetcherFor('first-principal-job')
    const secondFetcher = fetcherFor('second-principal-job')
    const body = { title: 'same wire body' }

    const firstApi = new AgentApi(firstIdentity, {
      identityPath: firstPath,
      fetch: firstFetcher as typeof fetch,
    })
    const secondApi = new AgentApi(secondIdentity, {
      identityPath: secondPath,
      fetch: secondFetcher as typeof fetch,
    })
    await expect(guardedPost(firstApi, body)).resolves.toEqual({ id: 'first-principal-job' })
    await expect(guardedPost(secondApi, body)).resolves.toEqual({ id: 'second-principal-job' })

    expect(firstFetcher).toHaveBeenCalledTimes(2)
    expect(secondFetcher).toHaveBeenCalledTimes(2)
    expect(await readdir(join(dirname(firstPath), 'payment-attempts'))).toHaveLength(2)
  })

  it('serializes unique payment-attempt claims and fails closed at the entry ceiling', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const journalDirectory = paymentAttemptDirectory(path, identity.publicKey)
    await mkdir(journalDirectory, { recursive: true, mode: 0o700 })
    for (let start = 0; start < MAX_PAYMENT_ATTEMPT_ENTRIES - 1; start += 256) {
      await Promise.all(Array.from(
        { length: Math.min(256, MAX_PAYMENT_ATTEMPT_ENTRIES - 1 - start) },
        (_, offset) => writeFile(
          join(journalDirectory, `${(start + offset).toString(16).padStart(64, '0')}.json`),
          '{}\n',
          { mode: 0o600 },
        ),
      ))
    }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const paidRequests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      if (!request.headers.has('PAYMENT-SIGNATURE')) {
        return Response.json(
          { error: 'payment required' },
          { status: 402, headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) } },
        )
      }
      paidRequests.push(request)
      const body = JSON.parse(await request.text()) as { title: string }
      return Response.json({ id: `job-${body.title}` }, { status: 201 })
    })
    const first = new AgentApi(identity, { fetch: fetcher as typeof fetch, identityPath: path })
    const second = new AgentApi(identity, { fetch: fetcher as typeof fetch, identityPath: path })

    const outcomes = await Promise.allSettled([
      guardedPost(first, { title: 'first-ceiling-claim' }),
      guardedPost(second, { title: 'second-ceiling-claim' }),
    ])

    expect(outcomes.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    const rejected = outcomes.find(({ status }) => status === 'rejected')
    expect(rejected).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({ message: expect.stringMatching(/entry safety limit/i) }),
    })
    expect(paidRequests).toHaveLength(1)
    expect((await readdir(journalDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(MAX_PAYMENT_ATTEMPT_ENTRIES)
  })

  it('recovers a cached paid result through the spend guard without another request', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const body = { title: 'already settled' }
    const firstApi = new AgentApi(identity, {
      identityPath: path,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        return request.headers.has('PAYMENT-SIGNATURE')
          ? Response.json({ id: 'settled-job' }, { status: 201 })
          : Response.json(
              { error: 'payment required' },
              { status: 402, headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) } },
            )
      }) as typeof fetch,
    })
    await expect(guardedPost(firstApi, body)).resolves.toEqual({ id: 'settled-job' })

    const secondFetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const secondApi = new AgentApi(identity, {
      identityPath: path,
      fetch: secondFetcher as typeof fetch,
    })
    await expect(guardedPost(secondApi, body)).resolves.toEqual({ id: 'settled-job' })
    expect(secondFetcher).not.toHaveBeenCalled()
  })

  it('treats an unreadable exact payment-attempt record as ambiguous', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const body = { title: 'corrupt evidence must fail closed' }
    const rawBody = JSON.stringify(body)
    const key = sha256Hex([
      identity.publicKey,
      identity.handle ?? '',
      identity.baseUrl,
      String(identity.chainId),
      identity.wallet.toLowerCase(),
      'POST',
      '/jobs',
      sha256Hex(rawBody),
      '10000',
    ].join('\n'))
    const journalDirectory = paymentAttemptDirectory(path, identity.publicKey)
    await mkdir(journalDirectory, { recursive: true, mode: 0o700 })
    await writeFile(join(journalDirectory, `${key}.json`), '{not-json', { mode: 0o600 })
    const fetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const api = new AgentApi(identity, { identityPath: path, fetch: fetcher as typeof fetch })
    let observed: unknown

    try {
      await guardedPost(api, body)
    } catch (error) {
      observed = error
    }

    expect(observed).toBeInstanceOf(Error)
    expect(paymentMayHaveOccurred(observed)).toBe(true)
    expect(fetcher).not.toHaveBeenCalled()
  })

  it('fails closed on an unnamespaced pre-release payment journal without deleting it', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const legacyDirectory = join(dirname(path), 'payment-attempts')
    const legacyFile = join(legacyDirectory, 'pre-release-pending.json')
    await mkdir(legacyDirectory, { recursive: true, mode: 0o700 })
    await writeFile(legacyFile, '{"version":1}\n', { mode: 0o600 })
    const fetcher = vi.fn(async () => Response.json({ id: 'must-not-run' }))
    const api = new AgentApi(identity, { identityPath: path, fetch: fetcher as typeof fetch })
    let observed: unknown

    try {
      await guardedPost(api, { title: 'do not bypass legacy evidence' })
    } catch (error) {
      observed = error
    }

    expect(observed).toBeInstanceOf(Error)
    expect((observed as Error).message).toMatch(/unnamespaced pre-release.*recover or archive/i)
    expect(paymentMayHaveOccurred(observed)).toBe(true)
    expect(fetcher).not.toHaveBeenCalled()
    await expect(readFile(legacyFile, 'utf8')).resolves.toContain('"version":1')
  })

  it('returns a cached paid result when the direct CLI crashes while displaying success', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const jobFile = join(dirname(path), 'durable-job.json')
    await writeFile(jobFile, JSON.stringify({ title: 'display may fail' }))
    const paidRequests: Request[] = []
    const firstFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      paidRequests.push(request)
      return request.headers.has('PAYMENT-SIGNATURE')
        ? Response.json({ id: 'durable-job-id' }, { status: 201 })
        : new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          })
    })

    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '100000',
      },
      fetch: firstFetcher as typeof fetch,
      stdout: { write: () => { throw new Error('stdout disappeared') } },
    })).rejects.toThrow('stdout disappeared')
    expect(paidRequests.some((request) => request.headers.has('PAYMENT-SIGNATURE'))).toBe(true)

    let replayOutput = ''
    const replayFetcher = vi.fn(async () => Response.json({ id: 'duplicate' }))
    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '100000',
      },
      fetch: replayFetcher as typeof fetch,
      stdout: { write: (chunk) => (replayOutput += chunk) },
    })).resolves.toEqual({ id: 'durable-job-id' })
    expect(replayFetcher).not.toHaveBeenCalled()
    expect(replayOutput).toContain('durable-job-id')
  })

  it('never replaces an expired authorization whose nonce may already be charged', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount: '10000',
          payTo: marketplacePayTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const body = { title: 'refresh only when proven expired' }
    const oldHeaders: string[] = []
    const firstApi = new AgentApi(identity, {
      identityPath: path,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (payment) {
          oldHeaders.push(payment)
          throw new Error('connection lost after settlement')
        }
        return Response.json(
          { error: 'payment required' },
          {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          },
        )
      }) as typeof fetch,
    })
    await expect(guardedPost(firstApi, body)).rejects.toThrow('connection lost after settlement')
    expect(new Set(oldHeaders).size).toBe(1)
    const legacyDirectory = paymentAttemptDirectory(path, identity.publicKey)
    const [legacyName] = await readdir(legacyDirectory)
    const legacy = JSON.parse(await readFile(join(legacyDirectory, legacyName!), 'utf8')) as
      Record<string, unknown>
    legacy.version = 1
    delete legacy.state
    delete legacy.publicKey
    delete legacy.handle
    delete legacy.refreshCount
    await writeFile(join(legacyDirectory, legacyName!), `${JSON.stringify(legacy)}\n`, { mode: 0o600 })
    const legacyKey = sha256Hex([
      identity.baseUrl,
      String(identity.chainId),
      identity.wallet.toLowerCase(),
      'POST',
      '/jobs',
      sha256Hex(JSON.stringify(body)),
      '10000',
    ].join('\n'))
    await rename(join(legacyDirectory, legacyName!), join(legacyDirectory, `${legacyKey}.json`))

    const prematureRequests: Request[] = []
    const prematureApi = new AgentApi(identity, {
      identityPath: path,
      now: () => (authorizationValidBefore(oldHeaders[0]!) - 1) * 1_000,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        prematureRequests.push(new Request(input, init))
        return Response.json(
          { error: 'server marker alone is insufficient' },
          { status: 410, headers: { 'X-1F4BC-Payment-Expired': '1' } },
        )
      }) as typeof fetch,
    })
    await expect(guardedPost(prematureApi, body)).rejects.toThrow(/HTTP 410/)
    expect(prematureRequests).toHaveLength(1)
    expect(prematureRequests[0]?.headers.get('PAYMENT-SIGNATURE')).toBe(oldHeaders[0])

    const secondHeaders: string[] = []
    let expiredResponseCancelled = () => false
    const secondApi = new AgentApi(identity, {
      identityPath: path,
      now: () => (authorizationValidBefore(oldHeaders[0]!) + 1) * 1_000,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (payment) {
          secondHeaders.push(payment)
          if (payment === oldHeaders[0]) {
            const tracked = cancellableResponse(
              'expired authorization body must not be exposed',
              {
                status: 410,
                headers: { 'X-1F4BC-Payment-Expired': '1' },
              },
            )
            expiredResponseCancelled = tracked.cancelled
            return tracked.response
          }
          return Response.json({ id: 'job-refreshed' }, { status: 201 })
        }
        return Response.json(
          { error: 'payment required' },
          {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          },
        )
      }) as typeof fetch,
    })

    await expect(guardedPost(secondApi, body)).rejects.toThrow(
      /automatic replacement is disabled.*old nonce may already have been charged/i,
    )
    expect(secondHeaders).toHaveLength(1)
    expect(secondHeaders[0]).toBe(oldHeaders[0])
    expect(expiredResponseCancelled()).toBe(true)
    const retainedFiles = await readdir(paymentAttemptDirectory(path, identity.publicKey))
    expect(retainedFiles).toHaveLength(1)
    const retained = JSON.parse(await readFile(
      join(paymentAttemptDirectory(path, identity.publicKey), retainedFiles[0]!),
      'utf8',
    )) as { headerValue: string; result?: unknown }
    expect(retained.headerValue).toBe(oldHeaders[0])
    expect(retained).not.toHaveProperty('result')
  })

  it('never clears a refreshed authorization even if its replacement looks expired and unused', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      env: {},
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const job = { title: 'old authorization may still be live' }
    const jobFile = join(dirname(path), 'refreshed-recovery-job.json')
    await writeFile(jobFile, JSON.stringify(job))
    const retainedHeaders: string[] = []
    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
      },
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')
        if (payment) {
          retainedHeaders.push(payment)
          throw new Error('old authorization outcome is ambiguous')
        }
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
        })
      }) as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow('old authorization outcome is ambiguous')

    const attemptDirectory = paymentAttemptDirectory(path, identity.publicKey)
    const [attemptName] = (await readdir(attemptDirectory)).filter((name) => name.endsWith('.json'))
    const attemptPath = join(attemptDirectory, attemptName!)
    const stored = JSON.parse(await readFile(attemptPath, 'utf8')) as Record<string, unknown>
    const oldHeader = retainedHeaders[0]!
    const decoded = decodePaymentSignatureHeader(oldHeader)
    const oldAuthorization = decoded.payload.authorization as {
      from: `0x${string}`
      to: `0x${string}`
      value: string
      validAfter: string
      validBefore: string
      nonce: `0x${string}`
    }
    const replacementAuthorization = {
      ...oldAuthorization,
      validBefore: '1',
      nonce: `0x${'7a'.repeat(32)}`,
    }
    const replacementSignature = await privateKeyToAccount(walletPrivateKey as `0x${string}`)
      .signTypedData({
        domain: {
          name: 'USD Coin',
          version: '2',
          chainId: 8453,
          verifyingContract: decoded.accepted.asset as `0x${string}`,
        },
        types: authorizationTypes,
        primaryType: 'TransferWithAuthorization',
        message: {
          from: replacementAuthorization.from as `0x${string}`,
          to: replacementAuthorization.to as `0x${string}`,
          value: BigInt(replacementAuthorization.value),
          validAfter: BigInt(replacementAuthorization.validAfter),
          validBefore: 1n,
          nonce: replacementAuthorization.nonce as `0x${string}`,
        },
      })
    const replacementHeader = btoa(JSON.stringify({
      ...decoded,
      payload: {
        ...decoded.payload,
        authorization: replacementAuthorization,
        signature: replacementSignature,
      },
    }))
    stored.headerValue = replacementHeader
    stored.refreshCount = 1
    await writeFile(attemptPath, `${JSON.stringify(stored)}\n`, { mode: 0o600 })
    expect(Number(oldAuthorization.validBefore)).toBeGreaterThan(1)
    expect(replacementHeader).not.toBe(oldHeader)

    const identifier = decoded.extensions?.[PAYMENT_IDENTIFIER] as { info?: { id?: string } }
    const paymentId = identifier.info!.id!
    const bodyHash = sha256Hex(JSON.stringify(job))
    let recoveryState: 'terminal' | 'committed' = 'terminal'
    const recoveryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      expect(request.method).toBe('GET')
      expect(request.headers.get('PAYMENT-SIGNATURE')).toBe(replacementHeader)
      return Response.json({
        operation: 'POST /jobs',
        paymentId,
        bodyHash,
        state: recoveryState,
        result: recoveryState === 'committed' ? { id: 'durably-committed-job' } : null,
        ...(recoveryState === 'terminal' ? { terminalBasis: 'durable-attempt' } : {}),
      })
    })

    await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/refreshed payment authorization.*cannot be terminal/i)
    await expect(runCli([
      '--identity', path,
      'recover', 'post', jobFile,
      '--clear-terminal',
    ], {
      env: {
        F4BC_MAX_PAYMENT_ATOMIC: '10000',
        F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
      },
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/refreshed payment authorization.*cannot be terminal/i)

    const stillPending = JSON.parse(await readFile(attemptPath, 'utf8')) as {
      state: string
      refreshCount: number
      headerValue: string
    }
    expect(stillPending).toMatchObject({
      state: 'pending',
      refreshCount: 1,
      headerValue: replacementHeader,
    })
    const archiveDirectory = join(
      dirname(path),
      'payment-attempt-archive',
      sha256Hex(identity.publicKey),
    )
    await expect(readdir(archiveDirectory)).rejects.toMatchObject({ code: 'ENOENT' })
    const spendFiles = (await readdir(dirname(path)))
      .filter((name) => /^spend-[0-9a-f]{64}\.json$/.test(name))
    expect(spendFiles).toHaveLength(1)
    const spend = JSON.parse(await readFile(join(dirname(path), spendFiles[0]!), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])

    const locallyTerminal = {
      ...stillPending,
      ...stored,
      state: 'terminal',
      refreshCount: 1,
      headerValue: replacementHeader,
      terminalAt: Date.now(),
      terminalProofVersion: 1,
    }
    await writeFile(attemptPath, `${JSON.stringify(locallyTerminal)}\n`, { mode: 0o600 })
    for (const args of [
      ['--identity', path, 'recover', 'post', jobFile],
      ['--identity', path, 'recover', 'post', jobFile, '--clear-terminal'],
    ]) {
      await expect(runCli(args, {
        env: args.includes('--clear-terminal') ? {
          F4BC_MAX_PAYMENT_ATOMIC: '10000',
          F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
        } : {},
        fetch: recoveryFetcher as typeof fetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/refreshed payment authorization.*cannot be terminal/i)
    }

    const attemptKey = attemptName!.replace(/\.json$/, '')
    const terminalContents = `${JSON.stringify(locallyTerminal)}\n`
    await mkdir(archiveDirectory, { recursive: true, mode: 0o700 })
    const archivePath = join(
      archiveDirectory,
      `${attemptKey}.${locallyTerminal.terminalAt}.${sha256Hex(terminalContents).slice(0, 16)}.json`,
    )
    await writeFile(archivePath, terminalContents, { mode: 0o600 })
    await rm(attemptPath)
    for (const args of [
      ['--identity', path, 'recover', 'post', jobFile],
      ['--identity', path, 'recover', 'post', jobFile, '--clear-terminal'],
    ]) {
      await expect(runCli(args, {
        env: args.includes('--clear-terminal') ? {
          F4BC_MAX_PAYMENT_ATOMIC: '10000',
          F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
        } : {},
        fetch: recoveryFetcher as typeof fetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/refreshed payment authorization.*cannot be terminal/i)
    }
    expect((JSON.parse(await readFile(archivePath, 'utf8')) as { refreshCount: number }).refreshCount)
      .toBe(1)

    await rm(archiveDirectory, { recursive: true })
    await writeFile(attemptPath, `${JSON.stringify({
      ...stored,
      state: 'pending',
      refreshCount: 1,
      headerValue: replacementHeader,
    })}\n`, { mode: 0o600 })

    recoveryState = 'committed'
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).resolves.toMatchObject({
      state: 'committed',
      result: { id: 'durably-committed-job' },
    })
  })

  it('recovers, tombstones, and explicitly archives one terminal post authorization', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      env: {},
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const job = { title: 'recover one exact terminal authorization' }
    const jobFile = join(dirname(path), 'recovery-job.json')
    await writeFile(jobFile, JSON.stringify(job))
    const paymentHeaders: string[] = []
    const failedFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        paymentHeaders.push(payment)
        throw new Error('ambiguous transport failure')
      }
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(postingPaymentRequired()) },
      })
    })
    const caps = {
      F4BC_MAX_PAYMENT_ATOMIC: '10000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
    }
    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: caps,
      fetch: failedFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow('ambiguous transport failure')
    expect(new Set(paymentHeaders).size).toBe(1)
    let expectedRecoveryHeader = paymentHeaders[0]!

    type RecoveryMode =
      | 'terminal'
      | 'pending'
      | 'settled'
      | 'committed'
      | 'wrong-operation'
      | 'wrong-payment-id'
      | 'wrong-body-hash'
      | 'non-null-pending'
      | 'malformed-committed'
      | 404
      | 409
      | 429
      | 503
    let recoveryMode: RecoveryMode = 'terminal'
    const recoveryRequests: Request[] = []
    const recoveryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      recoveryRequests.push(request)
      expect(request.method).toBe('GET')
      expect(request.headers.get('PAYMENT-SIGNATURE')).toBe(expectedRecoveryHeader)
      expect(request.headers.has('X-1F4BC-Recovery-Signature')).toBe(false)
      const decoded = decodePaymentSignatureHeader(expectedRecoveryHeader)
      const authorization = decoded.payload.authorization as {
        nonce: string
      }
      const identifier = decoded.extensions?.[PAYMENT_IDENTIFIER] as { info?: { id?: string } }
      const paymentId = identifier.info!.id!
      const bodyHash = new URL(request.url).searchParams.get('bodyHash')!
      if (typeof recoveryMode === 'number') {
        return new Response(
          `${expectedRecoveryHeader} ${authorization.nonce}`,
          {
            status: recoveryMode,
            headers: recoveryMode === 409 || recoveryMode === 429 || recoveryMode === 503
              ? { 'Retry-After': '30' }
              : undefined,
          },
        )
      }
      const recovered: Record<string, unknown> = {
        operation: 'POST /jobs',
        paymentId,
        bodyHash,
        state: recoveryMode,
        result: null,
      }
      if (recoveryMode === 'terminal') recovered.terminalBasis = 'durable-attempt'
      if (recoveryMode === 'committed') recovered.result = { id: 'recovered-job-id' }
      if (recoveryMode === 'wrong-operation') recovered.operation = 'POST /jobs/other'
      if (recoveryMode === 'wrong-payment-id') recovered.paymentId = `${paymentId}-other`
      if (recoveryMode === 'wrong-body-hash') recovered.bodyHash = 'f'.repeat(64)
      if (recoveryMode === 'non-null-pending') {
        recovered.state = 'pending'
        recovered.result = { id: 'must-not-exist' }
      }
      if (recoveryMode === 'malformed-committed') {
        recovered.state = 'committed'
        recovered.result = { id: '' }
      }
      return Response.json(recovered)
    })

    const activeDirectory = paymentAttemptDirectory(path, identity.publicKey)
    const [activeName] = (await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))
    expect(activeName).toBeDefined()
    const spendFilesBeforeClear = (await readdir(dirname(path)))
      .filter((name) => /^spend-[0-9a-f]{64}\.json$/.test(name))
    expect(spendFilesBeforeClear).toHaveLength(1)
    const spendPath = join(dirname(path), spendFilesBeforeClear[0]!)
    const assertStillAmbiguousAndPending = async () => {
      const active = JSON.parse(await readFile(join(activeDirectory, activeName!), 'utf8')) as {
        state: string
      }
      expect(active.state).toBe('pending')
      const spend = JSON.parse(await readFile(spendPath, 'utf8')) as {
        entries: Array<{ state: string }>
      }
      expect(spend.entries).toHaveLength(1)
      expect(spend.entries[0]?.state).toBe('ambiguous')
      const archiveDirectory = join(
        dirname(path),
        'payment-attempt-archive',
        sha256Hex(identity.publicKey),
      )
      await expect(readdir(archiveDirectory)).rejects.toMatchObject({ code: 'ENOENT' })
    }
    for (const mode of [
      'pending',
      'settled',
      404,
      409,
      429,
      503,
      'wrong-operation',
      'wrong-payment-id',
      'wrong-body-hash',
      'non-null-pending',
      'malformed-committed',
    ] satisfies RecoveryMode[]) {
      recoveryMode = mode
      let output = ''
      let observed: unknown
      try {
        await runCli([
          '--identity', path,
          'recover', 'post', jobFile,
          '--clear-terminal',
        ], {
          env: caps,
          fetch: recoveryFetcher as typeof fetch,
          stdout: { write: (chunk) => (output += chunk) },
        })
      } catch (error) {
        observed = error
      }
      expect(observed).toBeInstanceOf(Error)
      const diagnostic = `${String(observed)}\n${output}`
      expect(diagnostic).not.toContain(paymentHeaders[0]!)
      const decoded = decodePaymentSignatureHeader(paymentHeaders[0]!)
      expect(diagnostic).not.toContain(
        (decoded.payload.authorization as { nonce: string }).nonce,
      )
      expect(recoveryRequests.at(-1)!.headers.has('X-1F4BC-Recovery-Signature')).toBe(false)
      await assertStillAmbiguousAndPending()
    }

    recoveryMode = 'terminal'
    let recoveryOutput = ''
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: (chunk) => (recoveryOutput += chunk) },
    })).resolves.toMatchObject({ state: 'terminal', cleared: false })
    expect(recoveryOutput).toContain('"state": "terminal"')
    const activeNames = (await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))
    expect(activeNames).toHaveLength(1)
    const terminalAttempt = JSON.parse(await readFile(
      join(activeDirectory, activeNames[0]!),
      'utf8',
    )) as { state: string; headerValue: string }
    expect(terminalAttempt).toMatchObject({ state: 'terminal', headerValue: paymentHeaders[0] })
    for (const mode of ['pending', 'settled', 'committed'] satisfies RecoveryMode[]) {
      recoveryMode = mode
      await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
        env: {},
        fetch: recoveryFetcher as typeof fetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow(/contradicted a terminal local payment record/i)
      const unchanged = JSON.parse(await readFile(
        join(activeDirectory, activeNames[0]!),
        'utf8',
      )) as { state: string; headerValue: string }
      expect(unchanged).toMatchObject({ state: 'terminal', headerValue: paymentHeaders[0] })
    }
    recoveryMode = 'terminal'
    const spendBeforeClear = JSON.parse(await readFile(
      spendPath,
      'utf8',
    )) as { entries: Array<{ state: string }> }
    expect(spendBeforeClear.entries[0]?.state).toBe('ambiguous')
    const forbiddenRetryFetch = vi.fn(async () => {
      throw new Error('terminal attempt must not be sent')
    })
    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: caps,
      fetch: forbiddenRetryFetch as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/server-confirmed terminal.*--clear-terminal/i)
    expect(forbiddenRetryFetch).not.toHaveBeenCalled()

    const ambiguousSpendContents = await readFile(spendPath, 'utf8')
    const crashApi = new AgentApi(identity, {
      identityPath: path,
      fetch: recoveryFetcher as typeof fetch,
    })
    const crashGuard = new SpendGuard({
      journalPath: spendPath,
      scope: spendPolicyScope(identity.chainId, identity.wallet),
      maxPaymentAtomic: 10_000n,
      dailyPaymentLimitAtomic: 10_000n,
    })
    let earlyFinalizeFailure: unknown
    await expect(crashGuard.execute(
      'post_job',
      { job },
      10_000n,
      async (control) => {
        try {
          return await crashApi.stageTerminalPostJobClear(job, control)
        } catch (error) {
          expect(error).toBeInstanceOf(TerminalPaymentCleared)
          try {
            await crashApi.finalizeTerminalPostJobClear(job, error as TerminalPaymentCleared)
          } catch (finalizeError) {
            earlyFinalizeFailure = finalizeError
          }
          throw error
        }
      },
    )).rejects.toBeInstanceOf(TerminalPaymentCleared)
    expect(String(earlyFinalizeFailure)).toMatch(/not durably released/i)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    await writeFile(spendPath, ambiguousSpendContents, { mode: 0o600 })

    await expect(crashGuard.execute(
      'post_job',
      { job },
      10_000n,
      async (control) => {
        try {
          return await crashApi.stageTerminalPostJobClear(job, control)
        } catch (error) {
          expect(error).toBeInstanceOf(TerminalPaymentCleared)
          await writeFile(spendPath, '{"injected":"crash-before-release"', { mode: 0o600 })
          throw error
        }
      },
    )).rejects.toThrow(/spend journal contains invalid JSON/i)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    const stagedArchiveDirectory = join(
      dirname(path),
      'payment-attempt-archive',
      sha256Hex(identity.publicKey),
    )
    expect((await readdir(stagedArchiveDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    await writeFile(spendPath, ambiguousSpendContents, { mode: 0o600 })

    const [stagedArchiveName] = (await readdir(stagedArchiveDirectory))
      .filter((name) => name.endsWith('.json'))
    const stagedArchivePath = join(stagedArchiveDirectory, stagedArchiveName!)
    const archiveDirectoryBackup = `${stagedArchiveDirectory}.real`
    await rename(stagedArchiveDirectory, archiveDirectoryBackup)
    await symlink(archiveDirectoryBackup, stagedArchiveDirectory)
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile, '--clear-terminal'], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/directory.*real directory/i)
    await rm(stagedArchiveDirectory)
    await rename(archiveDirectoryBackup, stagedArchiveDirectory)

    const archiveFileBackup = `${stagedArchivePath}.real`
    await rename(stagedArchivePath, archiveFileBackup)
    await symlink(archiveFileBackup, stagedArchivePath)
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile, '--clear-terminal'], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/single-link regular file/i)
    await rm(stagedArchivePath)
    await rename(archiveFileBackup, stagedArchivePath)

    await rename(stagedArchivePath, archiveFileBackup)
    await link(archiveFileBackup, stagedArchivePath)
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile, '--clear-terminal'], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/single-link regular file/i)
    await rm(stagedArchivePath)
    await rename(archiveFileBackup, stagedArchivePath)

    let crashAfterRelease: unknown
    try {
      await crashGuard.execute(
        'post_job',
        { job },
        10_000n,
        (control) => crashApi.stageTerminalPostJobClear(job, control),
      )
    } catch (error) {
      crashAfterRelease = error
    }
    expect(crashAfterRelease).toBeInstanceOf(TerminalPaymentCleared)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    const releasedBeforeFinalize = JSON.parse(await readFile(spendPath, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(releasedBeforeFinalize.entries[0]?.state).toBe('released')

    await expect(runCli([
      '--identity', path,
      'recover', 'post', jobFile,
      '--clear-terminal',
    ], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => { throw new Error('recovery output disappeared') } },
    })).rejects.toThrow('recovery output disappeared')
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))).toEqual([])

    let clearOutput = ''
    await expect(runCli([
      '--identity', path,
      'recover', 'post', jobFile,
      '--clear-terminal',
    ], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: (chunk) => (clearOutput += chunk) },
    })).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    expect(clearOutput).toContain('"cleared": true')
    expect(recoveryRequests.length).toBeGreaterThanOrEqual(19)

    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))).toEqual([])
    const archiveDirectory = join(dirname(path), 'payment-attempt-archive', sha256Hex(identity.publicKey))
    const archived = (await readdir(archiveDirectory)).filter((name) => name.endsWith('.json'))
    expect(archived).toHaveLength(1)
    expect((await stat(archiveDirectory)).mode & 0o777).toBe(0o700)
    expect((await stat(join(archiveDirectory, archived[0]!))).mode & 0o777).toBe(0o600)

    const spendFiles = (await readdir(dirname(path))).filter((name) => /^spend-[0-9a-f]{64}\.json$/.test(name))
    expect(spendFiles).toHaveLength(1)
    const spend = JSON.parse(await readFile(join(dirname(path), spendFiles[0]!), 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(spend.entries).toHaveLength(1)
    expect(spend.entries[0]?.state).toBe('released')

    const concurrent = await Promise.allSettled([
      runCli([
        '--identity', path,
        'recover', 'post', jobFile,
        '--clear-terminal',
      ], {
        env: caps,
        fetch: recoveryFetcher as typeof fetch,
        stdout: { write: () => undefined },
      }),
      runCli([
        '--identity', path,
        'recover', 'post', jobFile,
        '--clear-terminal',
      ], {
        env: caps,
        fetch: recoveryFetcher as typeof fetch,
        stdout: { write: () => undefined },
      }),
    ])
    expect(concurrent.some((outcome) => outcome.status === 'fulfilled')).toBe(true)
    for (const outcome of concurrent) {
      if (outcome.status === 'rejected') {
        expect(String(outcome.reason)).toMatch(/already in progress|local journal is locked/i)
      } else {
        expect(outcome.value).toEqual({ state: 'terminal', cleared: true, archived: true })
      }
    }
    expect((await readdir(archiveDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))).toEqual([])
    const decodedRetained = decodePaymentSignatureHeader(paymentHeaders[0]!)
    const retainedNonce = (decodedRetained.payload.authorization as { nonce: string }).nonce
    for (const output of [recoveryOutput, clearOutput]) {
      expect(output).not.toContain(paymentHeaders[0]!)
      expect(output).not.toContain(retainedNonce)
      expect(recoveryRequests.every((request) =>
        !request.headers.has('X-1F4BC-Recovery-Signature'))).toBe(true)
    }

    await expect(runCli(['--identity', path, 'post', jobFile], {
      env: caps,
      fetch: failedFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow('ambiguous transport failure')
    const distinctPaymentHeaders = [...new Set(paymentHeaders)]
    expect(distinctPaymentHeaders).toHaveLength(2)
    expect(distinctPaymentHeaders[1]).not.toBe(distinctPaymentHeaders[0])
    expectedRecoveryHeader = distinctPaymentHeaders[1]!
    recoveryMode = 'terminal'
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).resolves.toMatchObject({ state: 'terminal', cleared: false })
    const fillerNames = Array.from(
      { length: MAX_PAYMENT_ATTEMPT_ENTRIES - 1 },
      (_, index) => `filler-${String(index).padStart(4, '0')}.json`,
    )
    for (let offset = 0; offset < fillerNames.length; offset += 100) {
      await Promise.all(fillerNames.slice(offset, offset + 100).map((name) =>
        writeFile(join(archiveDirectory, name), '{}\n', { mode: 0o600 })))
    }
    await expect(runCli([
      '--identity', path,
      'recover', 'post', jobFile,
      '--clear-terminal',
    ], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/archive reached its entry safety limit/i)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    for (let offset = 0; offset < fillerNames.length; offset += 100) {
      await Promise.all(fillerNames.slice(offset, offset + 100).map((name) =>
        rm(join(archiveDirectory, name))))
    }
    await expect(runCli([
      '--identity', path,
      'recover', 'post', jobFile,
      '--clear-terminal',
    ], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    const twoArchives = (await readdir(archiveDirectory)).filter((name) => name.endsWith('.json'))
    expect(twoArchives).toHaveLength(2)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))).toEqual([])

    const archiveKey = twoArchives[0]!.slice(0, 64)
    await writeFile(
      join(archiveDirectory, `${archiveKey}.9999999999999.${'0'.repeat(16)}.json`),
      '{}\n',
      { mode: 0o600 },
    )
    const requestsBeforeCorruptionCheck = recoveryRequests.length
    await expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/payment-attempt journal entry is invalid|archive.*inconsistent/i)
    expect(recoveryRequests).toHaveLength(requestsBeforeCorruptionCheck)
  })

  it.each(['v1', 'v2'] as const)(
    'handles a terminal post retained under the legacy key safely (%s journal)',
    async (journalVersion) => {
      const path = await temporaryIdentity()
      await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
        env: {},
        generateWalletPrivateKey: () => walletPrivateKey,
        stdout: { write: () => undefined },
      })
      await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
        env: {},
        fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
        stdout: { write: () => undefined },
      })
      const identity = await loadIdentity(path)
      const job = { title: `recover legacy ${journalVersion} terminal authorization` }
      const rawBody = JSON.stringify(job)
      const jobFile = join(dirname(path), `legacy-${journalVersion}-recovery-job.json`)
      await writeFile(jobFile, rawBody)
      const required = postingPaymentRequired()
      await expect(runCli(['--identity', path, 'post', jobFile], {
        env: {
          F4BC_MAX_PAYMENT_ATOMIC: '10000',
          F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
        },
        fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
          const request = new Request(input, init)
          if (request.headers.has('PAYMENT-SIGNATURE')) {
            throw new Error('ambiguous legacy transport failure')
          }
          return new Response(null, {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
          })
        }) as typeof fetch,
        stdout: { write: () => undefined },
      })).rejects.toThrow('ambiguous legacy transport failure')

      const directory = paymentAttemptDirectory(path, identity.publicKey)
      const [canonicalName] = (await readdir(directory)).filter((name) => name.endsWith('.json'))
      expect(canonicalName).toBeDefined()
      const canonicalPath = join(directory, canonicalName!)
      const stored = JSON.parse(await readFile(canonicalPath, 'utf8')) as Record<string, unknown>
      if (journalVersion === 'v1') {
        stored.version = 1
        delete stored.state
        delete stored.publicKey
        delete stored.handle
        delete stored.refreshCount
        await writeFile(canonicalPath, `${JSON.stringify(stored)}\n`, { mode: 0o600 })
      }
      const legacyKey = legacyPaymentAttemptKeyForTest(identity, '/jobs', rawBody, 10_000n)
      await rename(canonicalPath, join(directory, `${legacyKey}.json`))

      const recoveryFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        const payment = request.headers.get('PAYMENT-SIGNATURE')!
        const decoded = decodePaymentSignatureHeader(payment)
        const identifier = decoded.extensions?.[PAYMENT_IDENTIFIER] as { info?: { id?: string } }
        return Response.json({
          operation: 'POST /jobs',
          paymentId: identifier.info!.id!,
          bodyHash: new URL(request.url).searchParams.get('bodyHash'),
          state: 'terminal',
          result: null,
          terminalBasis: 'durable-attempt',
        })
      })
      const recovery = expect(runCli(['--identity', path, 'recover', 'post', jobFile], {
        env: {},
        fetch: recoveryFetch as typeof fetch,
        stdout: { write: () => undefined },
      }))
      if (journalVersion === 'v1') {
        await recovery.rejects.toThrow(/legacy payment authorization cannot be terminal or cleared/i)
      } else {
        await recovery.resolves.toMatchObject({ state: 'terminal', cleared: false })
      }
      const clear = expect(runCli([
        '--identity', path,
        'recover', 'post', jobFile,
        '--clear-terminal',
      ], {
        env: {
          F4BC_MAX_PAYMENT_ATOMIC: '10000',
          F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
        },
        fetch: recoveryFetch as typeof fetch,
        stdout: { write: () => undefined },
      }))
      if (journalVersion === 'v1') {
        await clear.rejects.toThrow(/legacy payment authorization cannot be terminal or cleared/i)
        expect((await readdir(directory)).filter((name) => name.endsWith('.json')))
          .toEqual([`${legacyKey}.json`])
      } else {
        await clear.resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
        expect((await readdir(directory)).filter((name) => name.endsWith('.json'))).toEqual([])
      }
      const archiveDirectory = join(
        dirname(path),
        'payment-attempt-archive',
        sha256Hex(identity.publicKey),
      )
      if (journalVersion === 'v1') {
        await expect(readdir(archiveDirectory)).rejects.toMatchObject({ code: 'ENOENT' })
        const spendFiles = (await readdir(dirname(path)))
          .filter((name) => /^spend-[0-9a-f]{64}\.json$/.test(name))
        const spend = JSON.parse(await readFile(
          join(dirname(path), spendFiles[0]!),
          'utf8',
        )) as { entries: Array<{ state: string }> }
        expect(spend.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
      } else {
        expect((await readdir(archiveDirectory)).filter((name) =>
          name.startsWith(`${legacyKey}.`) && name.endsWith('.json'))).toHaveLength(1)
      }
    },
  )

  it('does not refresh a pending authorization for an unmarked 410 response', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: '1f4bc posting toll',
        mimeType: 'application/json',
      },
      accepts: [{
        scheme: 'exact',
        network: 'eip155:8453',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        amount: '10000',
        payTo: marketplacePayTo,
        maxTimeoutSeconds: 300,
        extra: { name: 'USD Coin', version: '2' },
      }],
      extensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    }
    const body = { title: 'generic gone is ambiguous' }
    const firstApi = new AgentApi(identity, {
      identityPath: path,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (request.headers.has('PAYMENT-SIGNATURE')) throw new Error('lost')
        return new Response(null, {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        })
      }) as typeof fetch,
    })
    await expect(guardedPost(firstApi, body)).rejects.toThrow('lost')

    const requests: Request[] = []
    const secondApi = new AgentApi(identity, {
      identityPath: path,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        requests.push(request)
        return Response.json({ error: 'gone' }, { status: 410 })
      }) as typeof fetch,
    })
    await expect(guardedPost(secondApi, body)).rejects.toThrow(/HTTP 410/)
    expect(requests).toHaveLength(1)
    expect(requests[0]?.headers.has('PAYMENT-SIGNATURE')).toBe(true)
    expect(await readdir(paymentAttemptDirectory(path, identity.publicKey))).toHaveLength(1)
  })

  it.each([
    ['an inflated posting toll', '1000000', `0x${'22'.repeat(20)}`],
    ['the zero-address recipient', '10000', `0x${'00'.repeat(20)}`],
  ])('rejects a malicious 402 advertising %s', async (_case, amount, payTo) => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs',
        description: 'malicious posting toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount,
          payTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      if (request.headers.has('PAYMENT-SIGNATURE')) {
        return Response.json({ id: 'charged-job' }, { status: 201 })
      }
      return Response.json(
        { error: 'payment required' },
        {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        },
      )
    })
    const api = new AgentApi(identity, { identityPath: path, fetch: fetcher as typeof fetch })

    await expect(guardedPost(api, { title: 'do not overcharge' })).rejects.toThrow()
    expect(requests.some((request) => request.headers.has('PAYMENT-SIGNATURE'))).toBe(false)
  })

  it('recovers and explicitly clears only one exact terminal bid authorization', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    await runCli(['--identity', path, 'register', 'alice', ...acceptCurrentTerms], {
      env: {},
      fetch: vi.fn(async () => Response.json({ handle: 'alice' }, { status: 201 })) as typeof fetch,
      stdout: { write: () => undefined },
    })
    const identity = await loadIdentity(path)
    const jobId = 'job-terminal-bid'
    const bid = { message: 'recover this exact bid', priceAtomic: '10000', etaHours: 2 }
    const bidFile = join(dirname(path), 'recovery-bid.json')
    await writeFile(bidFile, JSON.stringify(bid))
    const required = postingPaymentRequired()
    required.resource.url = `https://1f4bc.ai/jobs/${jobId}/bids`
    required.resource.description = '1f4bc bid toll'
    const paymentHeaders: string[] = []
    const failedFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      const requestUrl = new URL(request.url)
      if (request.method === 'GET' && requestUrl.pathname === `/jobs/${jobId}`) {
        return Response.json({ id: jobId, budgetAtomic: '1000000' })
      }
      const payment = request.headers.get('PAYMENT-SIGNATURE')
      if (payment) {
        paymentHeaders.push(payment)
        throw new Error('ambiguous bid transport failure')
      }
      return new Response(null, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
      })
    })
    const caps = {
      F4BC_MAX_PAYMENT_ATOMIC: '10000',
      F4BC_DAILY_PAYMENT_LIMIT_ATOMIC: '10000',
    }
    await expect(runCli(['--identity', path, 'bid', jobId, bidFile], {
      env: caps,
      fetch: failedFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow('ambiguous bid transport failure')
    expect(new Set(paymentHeaders)).toHaveLength(1)
    const retainedPayment = paymentHeaders[0]!
    const decoded = decodePaymentSignatureHeader(retainedPayment)
    const authorization = decoded.payload.authorization as {
      from: `0x${string}`
      nonce: string
      validBefore: string
    }
    const identifier = decoded.extensions?.[PAYMENT_IDENTIFIER] as { info?: { id?: string } }
    const paymentId = identifier.info!.id!
    const rawBody = JSON.stringify(bid)
    const bodyHash = sha256Hex(rawBody)
    const recoveryRequests: Request[] = []
    const recoveryFetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      recoveryRequests.push(request)
      const recoveryPath = `/payment-attempts/jobs/${jobId}/bids/${paymentId}` +
        `?bodyHash=${bodyHash}`
      await expectValidAgentEnvelope(request, identity, 'GET', recoveryPath, '')
      expect(request.headers.get('PAYMENT-SIGNATURE')).toBe(retainedPayment)
      expect(request.headers.has('X-1F4BC-Recovery-Signature')).toBe(false)
      return Response.json({
        operation: `POST /jobs/${jobId}/bids`,
        paymentId,
        bodyHash,
        state: 'terminal',
        result: null,
        terminalBasis: 'durable-attempt',
      })
    })

    const requestsBeforeMismatch = recoveryRequests.length
    const changedBidFile = join(dirname(path), 'changed-recovery-bid.json')
    await writeFile(changedBidFile, JSON.stringify({ ...bid, etaHours: 3 }))
    await expect(runCli(['--identity', path, 'recover', 'bid', jobId, changedBidFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/no retained payment authorization exists for this exact bid body/i)
    await expect(runCli(['--identity', path, 'recover', 'bid', 'another-job', bidFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/no retained payment authorization exists for this exact bid body/i)
    expect(recoveryRequests).toHaveLength(requestsBeforeMismatch)

    let recoveryOutput = ''
    await expect(runCli(['--identity', path, 'recover', 'bid', jobId, bidFile], {
      env: {},
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: (chunk) => (recoveryOutput += chunk) },
    })).resolves.toEqual({
      operation: `POST /jobs/${jobId}/bids`,
      paymentId,
      bodyHash,
      state: 'terminal',
      result: null,
      cleared: false,
      terminalBasis: 'durable-attempt',
    })

    const activeDirectory = paymentAttemptDirectory(path, identity.publicKey)
    const [activeName] = (await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))
    const terminalAttempt = JSON.parse(await readFile(
      join(activeDirectory, activeName!),
      'utf8',
    )) as { state: string; pathWithQuery: string; headerValue: string }
    expect(terminalAttempt).toMatchObject({
      state: 'terminal',
      pathWithQuery: `/jobs/${jobId}/bids`,
      headerValue: retainedPayment,
    })

    const forbiddenPaidRequests: Request[] = []
    await expect(runCli(['--identity', path, 'bid', jobId, bidFile], {
      env: caps,
      fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init)
        if (request.method === 'GET' && new URL(request.url).pathname === `/jobs/${jobId}`) {
          return Response.json({ id: jobId })
        }
        forbiddenPaidRequests.push(request)
        throw new Error('terminal bid must not be retried')
      }) as typeof fetch,
      stdout: { write: () => undefined },
    })).rejects.toThrow(/recover bid <jobId> <bid\.json> --clear-terminal/i)
    expect(forbiddenPaidRequests).toEqual([])

    let clearOutput = ''
    await expect(runCli([
      '--identity', path,
      'recover', 'bid', jobId, bidFile,
      '--clear-terminal',
    ], {
      env: caps,
      fetch: recoveryFetcher as typeof fetch,
      stdout: { write: (chunk) => (clearOutput += chunk) },
    })).resolves.toEqual({ state: 'terminal', cleared: true, archived: true })
    expect(recoveryRequests.every((request) => request.method === 'GET')).toBe(true)
    expect((await readdir(activeDirectory)).filter((name) => name.endsWith('.json'))).toEqual([])
    const archiveDirectory = join(
      dirname(path),
      'payment-attempt-archive',
      sha256Hex(identity.publicKey),
    )
    expect((await readdir(archiveDirectory)).filter((name) => name.endsWith('.json')))
      .toHaveLength(1)
    const spendFiles = (await readdir(dirname(path)))
      .filter((name) => /^spend-[0-9a-f]{64}\.json$/.test(name))
    expect(spendFiles).toHaveLength(1)
    const spend = JSON.parse(await readFile(join(dirname(path), spendFiles[0]!), 'utf8')) as {
      entries: Array<{ tool: string; state: string }>
    }
    expect(spend.entries).toEqual([
      expect.objectContaining({ tool: 'bid_job', state: 'released' }),
    ])
    const retainedNonce = authorization.nonce
    for (const output of [recoveryOutput, clearOutput]) {
      expect(output).not.toContain(retainedPayment)
      expect(output).not.toContain(retainedNonce)
      expect(recoveryRequests.every((request) =>
        !request.headers.has('X-1F4BC-Recovery-Signature'))).toBe(true)
    }
  })

  it('enforces the flat one-cent bid toll regardless of job budget', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, '--url', 'https://1f4bc.ai', 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'alice' }
    const required: PaymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://1f4bc.ai/jobs/job-1/bids',
        description: 'inflated bid toll',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          amount: '15000',
          payTo: marketplacePayTo,
          maxTimeoutSeconds: 300,
          extra: { name: 'USD Coin', version: '2' },
        },
      ],
      extensions: {
        [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
      },
    }
    const requests: Request[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      requests.push(request)
      if (request.method === 'GET') return Response.json({ budgetAtomic: '15000000' })
      if (request.headers.has('PAYMENT-SIGNATURE')) {
        return Response.json({ id: 'charged-bid' }, { status: 201 })
      }
      return Response.json(
        { error: 'payment required' },
        {
          status: 402,
          headers: { 'PAYMENT-REQUIRED': encodePaymentRequiredHeader(required) },
        },
      )
    })
    const api = new AgentApi(identity, { identityPath: path, fetch: fetcher as typeof fetch })

    await expect(guardedBid(api, 'job-1', { message: 'work', priceAtomic: '1', etaHours: 1 }))
      .rejects.toThrow()
    expect(requests[0]?.method).toBe('GET')
    expect(requests.some((request) => request.headers.has('PAYMENT-SIGNATURE'))).toBe(false)

    // Every application costs exactly 10,000 atomic USDC ($0.01).
    required.accepts[0]!.amount = '10000'
    requests.length = 0
    await expect(guardedBid(api, 'job-1', { message: 'work', priceAtomic: '1', etaHours: 1 }))
      .resolves.toEqual({ id: 'charged-bid' })
    expect(requests.map((request) => request.method)).toEqual(['GET', 'POST', 'POST'])
    expect(requests.at(-1)?.headers.has('PAYMENT-SIGNATURE')).toBe(true)
  })

  it('signs attestations from canonical camelCase ledger proof detail', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const identity = { ...(await loadIdentity(path)), handle: 'ledger-worker' }
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init)
      if (new URL(request.url).pathname === '/proofs/42') {
        return Response.json({
          standard: 'awc/0.1',
          proofId: 42,
          jobId: 'canonical-job',
          worker: 'ledger-worker',
        })
      }
      if (new URL(request.url).pathname === '/jobs/canonical-job') {
        return Response.json({ poster: 'ledger-poster' })
      }
      return new Response('not found', { status: 404 })
    })
    const api = new AgentApi(identity, { fetch: fetcher as typeof fetch })

    const signed = await api.signAttestation(42)
    expect(signed).toMatchObject({
      proofId: 42,
      jobId: 'canonical-job',
      handle: 'ledger-worker',
      role: 'worker',
      message: attestationMessage(identity.baseUrl, identity.chainId, 42, 'canonical-job'),
      signature: expect.any(String),
    })
    await expect(
      ed.verifyAsync(
        Buffer.from(signed.signature, 'base64'),
        new TextEncoder().encode(
          attestationMessage(identity.baseUrl, 84532, 42, 'canonical-job'),
        ),
        Buffer.from(identity.publicKey, 'base64'),
      ),
    ).resolves.toBe(false)
  })
})

describe('public marketplace reads', () => {
  it('sends the public profile search type without a legacy translation', async () => {
    const path = await temporaryIdentity()
    await runCli(['--identity', path, 'init'], {
      env: {},
      generateWalletPrivateKey: () => walletPrivateKey,
      stdout: { write: () => undefined },
    })
    const seen: URL[] = []
    const api = new AgentApi(await loadIdentity(path), {
      fetch: vi.fn(async (input: RequestInfo | URL) => {
        seen.push(new URL(input instanceof Request ? input.url : input))
        return Response.json({ results: [] })
      }) as typeof fetch,
    })

    await api.search('profiles', 'testing')
    expect(seen[0]?.pathname).toBe('/search')
    expect(seen[0]?.searchParams.get('type')).toBe('profiles')
    expect(seen[0]?.searchParams.get('tag')).toBe('testing')
  })
})
