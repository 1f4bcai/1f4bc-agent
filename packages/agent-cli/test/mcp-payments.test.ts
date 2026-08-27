import { mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  MAX_MCP_SPEND_JOURNAL_ENTRIES,
  MAX_MCP_SPEND_JOURNAL_BYTES,
  MAX_MCP_SPEND_RESULT_BYTES,
  McpSpendGuard,
  assertAuthorizedPaymentControl,
  claimAuthorizedPaymentControl,
} from '../src/mcp-payments.js'
import {
  claimedSpendControlMetadata,
  terminalPaymentCleared,
} from '../src/terminal-clear.js'

const cleanup: string[] = []

async function journalPath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), '1f4bc-mcp-spend-'))
  cleanup.push(directory)
  return join(directory, 'mcp-spend-journal.json')
}

function consume(
  control: Parameters<typeof claimAuthorizedPaymentControl>[0],
  tool: string,
  input: unknown,
  amountAtomic: bigint,
  scope = 'test-wallet',
): void {
  claimAuthorizedPaymentControl(control, tool, input, amountAtomic, scope)
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('MCP spend guard', () => {
  it('retains prior ambiguity until the exact current-control terminal capability releases it', async () => {
    const path = await journalPath()
    const scope = 'test-wallet'
    const tool = 'peer_pay'
    const input = { url: 'https://worker.example/exact', bodySha256: 'a'.repeat(64) }
    const amount = 25_000n
    const guard = new McpSpendGuard({
      journalPath: path,
      scope,
      maxPaymentAtomic: amount,
      dailyPaymentLimitAtomic: amount,
    })

    await expect(guard.execute(tool, input, amount, async (control) => {
      consume(control, tool, input, amount, scope)
      throw new Error('authorization outcome is ambiguous')
    })).rejects.toThrow(/ambiguous/i)

    await expect(guard.execute(tool, input, amount, async () => {
      throw Object.assign(new Error('pre-claim mismatch'), { paymentMayHaveOccurred: false })
    })).rejects.toThrow(/pre-claim mismatch/i)
    await expect(guard.execute(tool, input, amount, async (control) => {
      consume(control, tool, input, amount, scope)
      throw Object.assign(new Error('downstream false marker'), {
        paymentMayHaveOccurred: false,
      })
    })).rejects.toThrow(/downstream false marker/i)
    let journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(journal.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
    await expect(guard.execute(tool, { url: 'https://worker.example/other' }, amount, async () => {
      throw new Error('must not run')
    })).rejects.toThrow(/daily cap/i)

    let completion: ReturnType<typeof terminalPaymentCleared> | undefined
    let observed: unknown
    try {
      await guard.execute(tool, input, amount, async (control) => {
        consume(control, tool, input, amount, scope)
        completion = terminalPaymentCleared({
          spendControl: control,
          spendReservationId: claimedSpendControlMetadata(control).reservationId,
          spendAmountAtomic: amount.toString(),
          publicKey: 'test-public-key',
          attemptKey: 'b'.repeat(64),
          paymentId: '1f4bc_peer_test',
          bodyHash: 'a'.repeat(64),
        })
        throw completion
      })
    } catch (error) {
      observed = error
    }
    expect(observed).toBe(completion)
    journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(journal.entries).toEqual([expect.objectContaining({ state: 'released' })])

    await expect(guard.execute(tool, input, amount, async (control) => {
      consume(control, tool, input, amount, scope)
      throw new Error('new authorization B is ambiguous')
    })).rejects.toThrow(/authorization B/i)
    await expect(guard.execute(tool, input, amount, async () => {
      throw completion
    })).rejects.toBe(completion)
    journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(journal.entries).toEqual([expect.objectContaining({ state: 'ambiguous' })])
  })

  it('refuses symlinked and oversized spend journals before executing a paid action', async () => {
    const linkedPath = await journalPath()
    const linkedTarget = `${linkedPath}.target`
    await writeFile(
      linkedTarget,
      `${JSON.stringify({ version: 1, scope: 'secure', entries: [] })}\n`,
      { mode: 0o600 },
    )
    await symlink(linkedTarget, linkedPath)
    const linkedAction = vi.fn(async () => ({ id: 'must-not-run' }))
    await expect(new McpSpendGuard({
      journalPath: linkedPath,
      scope: 'secure',
      maxPaymentAtomic: 1n,
      dailyPaymentLimitAtomic: 1n,
    }).execute('post_job', {}, 1n, linkedAction)).rejects.toThrow(/single-link regular file/i)
    expect(linkedAction).not.toHaveBeenCalled()

    const oversizedPath = await journalPath()
    await writeFile(oversizedPath, 'x'.repeat(MAX_MCP_SPEND_JOURNAL_BYTES + 1), { mode: 0o600 })
    const oversizedAction = vi.fn(async () => ({ id: 'must-not-run' }))
    await expect(new McpSpendGuard({
      journalPath: oversizedPath,
      scope: 'secure',
      maxPaymentAtomic: 1n,
      dailyPaymentLimitAtomic: 1n,
    }).execute('post_job', {}, 1n, oversizedAction)).rejects.toThrow(/byte-size safety limit/i)
    expect(oversizedAction).not.toHaveBeenCalled()
  })

  it('binds each control to one exact tool, input, and amount', async () => {
    const cases: Array<[string, unknown, bigint]> = [
      ['bid_job', { job: { title: 'bound' } }, 100n],
      ['post_job', { job: { title: 'different' } }, 100n],
      ['post_job', { job: { title: 'bound' } }, 101n],
    ]
    for (const [tool, input, amount] of cases) {
      const scope = `binding-${tool}-${amount}`
      const guard = new McpSpendGuard({
        journalPath: await journalPath(),
        scope,
        maxPaymentAtomic: 1_000n,
        dailyPaymentLimitAtomic: 1_000n,
      })
      await expect(guard.execute(
        'post_job',
        { job: { title: 'bound' } },
        100n,
        async (control) => {
          claimAuthorizedPaymentControl(control, tool, input, amount, scope)
          return { id: 'must-not-run' }
        },
      )).rejects.toThrow(/does not match.*already used/i)
    }
  })

  it('rejects caller mutation between reservation and the paid action', async () => {
    const path = await journalPath()
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'mutation-boundary',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
    })
    const input = { job: { title: 'approved-a' } }
    const action = vi.fn(async (control) => {
      claimAuthorizedPaymentControl(
        control,
        'post_job',
        input,
        100n,
        'mutation-boundary',
      )
      return { id: input.job.title }
    })

    const pending = guard.execute('post_job', input, 100n, action)
    input.job.title = 'mutated-b'
    await expect(pending).rejects.toThrow(/does not match/i)
    expect(action).toHaveBeenCalledOnce()

    input.job.title = 'approved-a'
    await expect(guard.execute('post_job', input, 100n, action))
      .resolves.toEqual({ id: 'approved-a' })
    expect(action).toHaveBeenCalledTimes(2)
  })

  it('rejects non-plain JSON semantics before reserving or running paid code', async () => {
    const cases: unknown[] = [
      { job: { title: 'hook', toJSON: () => ({ title: 'changed' }) } },
      { job: new Date('2026-08-22T00:00:00Z') },
      { job: Object.assign(Object.create({ inherited: true }), { title: 'prototype' }) },
      { job: Array(2) },
      { job: [1, 2, Object.assign(() => undefined, { value: 3 })] },
    ]
    const accessor = { job: {} as { title?: string } }
    Object.defineProperty(accessor.job, 'title', {
      get: () => 'side-effect',
      enumerable: true,
    })
    cases.push(accessor)
    const cyclic: { self?: unknown } = {}
    cyclic.self = cyclic
    cases.push(cyclic)

    for (const [index, input] of cases.entries()) {
      const action = vi.fn(async () => ({ id: 'must-not-run' }))
      const path = await journalPath()
      await expect(new McpSpendGuard({
        journalPath: path,
        scope: `strict-json-${index}`,
        maxPaymentAtomic: 1n,
        dailyPaymentLimitAtomic: 1n,
      }).execute('post_job', input, 1n, action)).rejects.toThrow(/strict JSON data/i)
      expect(action).not.toHaveBeenCalled()
      await expect(stat(path)).rejects.toMatchObject({ code: 'ENOENT' })
    }
  })

  it('binds a control to the exact wallet-and-chain spend namespace', async () => {
    const guard = new McpSpendGuard({
      journalPath: await journalPath(),
      scope: 'wallet-a-on-chain-8453',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
    })
    await expect(guard.execute('post_job', { title: 'bound' }, 100n, async (control) => {
      claimAuthorizedPaymentControl(
        control,
        'post_job',
        { title: 'bound' },
        100n,
        'wallet-b-on-chain-8453',
      )
      return { id: 'must-not-run' }
    })).rejects.toThrow(/does not match.*already used/i)
  })

  it('atomically consumes a control once across sequential and concurrent callers', async () => {
    const guard = new McpSpendGuard({
      journalPath: await journalPath(),
      scope: 'one-shot',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
    })
    await guard.execute('post_job', { job: { title: 'once' } }, 100n, async (control) => {
      const concurrent = await Promise.allSettled([
        Promise.resolve().then(() => claimAuthorizedPaymentControl(
          control,
          'post_job',
          { job: { title: 'once' } },
          100n,
          'one-shot',
        )),
        Promise.resolve().then(() => claimAuthorizedPaymentControl(
          control,
          'post_job',
          { job: { title: 'once' } },
          100n,
          'one-shot',
        )),
      ])
      expect(concurrent.map((result) => result.status).sort()).toEqual(['fulfilled', 'rejected'])
      expect(() => claimAuthorizedPaymentControl(
        control,
        'post_job',
        { job: { title: 'once' } },
        100n,
        'one-shot',
      )).toThrow(/already used/i)
      return { id: 'one' }
    })
  })

  it('issues an unforgeable control only while the guarded action is active', async () => {
    expect(() => assertAuthorizedPaymentControl(undefined)).toThrow(/spend-policy reservation/i)
    expect(() => assertAuthorizedPaymentControl({} as never))
      .toThrow(/spend-policy reservation/i)

    const guard = new McpSpendGuard({
      journalPath: await journalPath(),
      scope: 'test-wallet',
      maxPaymentAtomic: 1n,
      dailyPaymentLimitAtomic: 1n,
    })
    let issued: Parameters<typeof assertAuthorizedPaymentControl>[0] = undefined
    await guard.execute('post_job', { title: 'authorized' }, 1n, async (control) => {
      issued = control
      expect(() => assertAuthorizedPaymentControl(control)).not.toThrow()
      consume(control, 'post_job', { title: 'authorized' }, 1n)
      return { id: 'job-1' }
    })
    expect(() => assertAuthorizedPaymentControl(issued)).toThrow(/spend-policy reservation/i)
  })

  it('enforces the per-transaction cap before invoking a paid operation', async () => {
    const action = vi.fn(async () => ({ id: 'never' }))
    const guard = new McpSpendGuard({
      journalPath: await journalPath(),
      scope: 'test-wallet',
      maxPaymentAtomic: 99n,
      dailyPaymentLimitAtomic: 1_000n,
    })

    await expect(guard.execute('post_job', { title: 'too much' }, 100n, action))
      .rejects.toThrow(/per-transaction cap/i)
    expect(action).not.toHaveBeenCalled()
  })

  it('reserves the daily cap atomically across guard instances', async () => {
    const path = await journalPath()
    const options = {
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => Date.UTC(2026, 7, 22, 12),
    }
    const first = new McpSpendGuard(options)
    const second = new McpSpendGuard(options)
    let releaseActions!: () => void
    const actionsMayFinish = new Promise<void>((resolve) => {
      releaseActions = resolve
    })
    const action = vi.fn(async (id: string) => {
      await actionsMayFinish
      return { id }
    })

    const outcomesPromise = Promise.allSettled([
      first.execute('post_job', { title: 'first' }, 100n, (control) => {
        consume(control, 'post_job', { title: 'first' }, 100n)
        return action('first')
      }),
      second.execute('post_job', { title: 'second' }, 100n, (control) => {
        consume(control, 'post_job', { title: 'second' }, 100n)
        return action('second')
      }),
    ])
    await vi.waitFor(() => expect(action).toHaveBeenCalledTimes(1))
    releaseActions()
    const outcomes = await outcomesPromise

    expect(outcomes.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(outcomes.filter(({ status }) => status === 'rejected')).toHaveLength(1)
    expect(action).toHaveBeenCalledTimes(1)
  })

  it('returns a durable settled result for an exact repeated tool call without paying twice', async () => {
    const path = await journalPath()
    const options = {
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => Date.UTC(2026, 7, 22, 12),
    }
    const input = { job: { title: 'same logical call' } }
    const action = vi.fn(async (control) => {
      consume(control, 'post_job', input, 100n)
      return { id: 'job-1' }
    })

    await expect(new McpSpendGuard(options).execute(
      'post_job',
      input,
      100n,
      action,
    )).resolves.toEqual({ id: 'job-1' })
    await expect(new McpSpendGuard(options).execute(
      'post_job',
      input,
      100n,
      action,
    )).resolves.toEqual({ id: 'job-1' })

    expect(action).toHaveBeenCalledOnce()
    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string; amountAtomic: string }>
    }
    expect(journal.entries).toEqual([
      expect.objectContaining({ state: 'settled', amountAtomic: '100' }),
    ])
    expect((await stat(path)).mode & 0o777).toBe(0o600)
    expect((await stat(join(path, '..'))).mode & 0o077).toBe(0)
  })

  it('does not run the same logical paid call concurrently', async () => {
    const path = await journalPath()
    let now = Date.UTC(2026, 7, 22, 12)
    const options = {
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => now,
    }
    let finish!: () => void
    const mayFinish = new Promise<void>((resolve) => {
      finish = resolve
    })
    const input = { job: { title: 'same' } }
    const action = vi.fn(async (control) => {
      consume(control, 'post_job', input, 100n)
      await mayFinish
      return { id: 'job-1' }
    })
    const first = new McpSpendGuard(options).execute(
      'post_job',
      input,
      100n,
      action,
    )
    await vi.waitFor(() => expect(action).toHaveBeenCalledOnce())
    // A paused or hung owner must not become stealable merely because an
    // arbitrary lease duration elapsed; it may still submit its payment.
    now += 60 * 60_000

    await expect(new McpSpendGuard(options).execute(
      'post_job',
      input,
      100n,
      action,
    )).rejects.toThrow(/already in progress/i)
    finish()
    await expect(first).resolves.toEqual({ id: 'job-1' })
    expect(action).toHaveBeenCalledOnce()
  })

  it('counts a live prior-day reservation against the new UTC day', async () => {
    const path = await journalPath()
    let now = Date.UTC(2026, 7, 22, 23, 59)
    const options = {
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => now,
    }
    let finishFirst!: () => void
    const firstMayFinish = new Promise<void>((resolve) => {
      finishFirst = resolve
    })
    const firstInput = { title: 'started before midnight' }
    const firstAction = vi.fn(async (control) => {
      consume(control, 'post_job', firstInput, 100n)
      await firstMayFinish
      return { id: 'first' }
    })
    const first = new McpSpendGuard(options).execute(
      'post_job',
      firstInput,
      100n,
      firstAction,
    )
    await vi.waitFor(() => expect(firstAction).toHaveBeenCalledOnce())

    now = Date.UTC(2026, 7, 23, 0, 1)
    const secondAction = vi.fn(async () => ({ id: 'must-not-run' }))
    await expect(new McpSpendGuard(options).execute(
      'post_job',
      { title: 'new day call' },
      100n,
      secondAction,
    )).rejects.toThrow(/daily cap/i)
    expect(secondAction).not.toHaveBeenCalled()

    finishFirst()
    await expect(first).resolves.toEqual({ id: 'first' })
    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string; day: string }>
    }
    expect(journal.entries[0]).toMatchObject({ state: 'settled', day: '2026-08-23' })
  })

  it('moves an ambiguous exact retry into the current UTC day before running it', async () => {
    const path = await journalPath()
    let now = Date.UTC(2026, 7, 22, 23, 59)
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => now,
    })
    const input = { title: 'cross-midnight retry' }

    await expect(guard.execute('post_job', input, 100n, async (control) => {
      consume(control, 'post_job', input, 100n)
      throw new Error('response lost')
    })).rejects.toThrow('response lost')
    now = Date.UTC(2026, 7, 23, 0, 1)
    await expect(guard.execute('post_job', input, 100n, async (control) => {
      consume(control, 'post_job', input, 100n)
      throw new Error('still ambiguous')
    })).rejects.toThrow('still ambiguous')
    await expect(guard.execute('bid_job', { jobId: 'new' }, 1n, async () => ({ id: 'no' })))
      .rejects.toThrow(/daily cap/i)

    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string; day: string }>
    }
    expect(journal.entries[0]).toMatchObject({ state: 'ambiguous', day: '2026-08-23' })
  })

  it('fails closed when a cross-day retry does not fit under the current UTC-day cap', async () => {
    const path = await journalPath()
    let now = Date.UTC(2026, 7, 22, 23, 59)
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => now,
    })
    const priorInput = { title: 'prior-day authorization' }
    await expect(guard.execute('post_job', priorInput, 100n, async (control) => {
      consume(control, 'post_job', priorInput, 100n)
      throw new Error('response lost')
    })).rejects.toThrow('response lost')

    now = Date.UTC(2026, 7, 23, 0, 1)
    const lowerCurrentDayCap = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 99n,
      now: () => now,
    })
    const retry = vi.fn(async () => ({ id: 'must-not-run' }))
    await expect(lowerCurrentDayCap.execute('post_job', priorInput, 100n, retry))
      .rejects.toThrow(/daily cap/i)
    expect(retry).not.toHaveBeenCalled()
  })

  it('does not let an action self-report a fake paid result through its capability', async () => {
    const path = await journalPath()
    const options = {
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
    }
    const action = vi.fn(async (control) => {
      expect(Object.keys(control)).toEqual([])
      expect((control as { recordPaidSuccess?: unknown }).recordPaidSuccess).toBeUndefined()
      claimAuthorizedPaymentControl(
        control,
        'post_job',
        { job: { title: 'durable result first' } },
        100n,
        'test-wallet',
      )
      return { id: 'paid-client-result' }
    })

    await expect(new McpSpendGuard(options).execute(
      'post_job',
      { job: { title: 'durable result first' } },
      100n,
      action,
    )).resolves.toEqual({ id: 'paid-client-result' })
    await expect(new McpSpendGuard(options).execute(
      'post_job',
      { job: { title: 'durable result first' } },
      100n,
      action,
    )).resolves.toEqual({ id: 'paid-client-result' })
    expect(action).toHaveBeenCalledOnce()
  })

  it('releases only a failure explicitly classified as definitive nonpayment', async () => {
    const path = await journalPath()
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => Date.UTC(2026, 7, 22, 12),
    })
    const noPayment = Object.assign(new Error('challenge rejected'), {
      paymentMayHaveOccurred: false,
    })

    const releasedInput = { title: 'released' }
    await expect(guard.execute('post_job', releasedInput, 100n, async (control) => {
      consume(control, 'post_job', releasedInput, 100n)
      throw noPayment
    })).rejects.toThrow('challenge rejected')
    const replacementInput = { title: 'replacement' }
    await expect(guard.execute('post_job', replacementInput, 100n, async (control) => {
      consume(control, 'post_job', replacementInput, 100n)
      return { id: 'replacement' }
    })).resolves.toEqual({ id: 'replacement' })
  })

  it('counts ambiguous failures against the daily cap', async () => {
    const path = await journalPath()
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => Date.UTC(2026, 7, 22, 12),
    })

    const ambiguousInput = { title: 'ambiguous' }
    await expect(guard.execute('post_job', ambiguousInput, 100n, async (control) => {
      consume(control, 'post_job', ambiguousInput, 100n)
      throw new Error('connection lost')
    })).rejects.toThrow('connection lost')
    await expect(guard.execute('post_job', { title: 'new call' }, 1n, async () => ({ id: 'no' })))
      .rejects.toThrow(/daily cap/i)

    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string }>
    }
    expect(journal.entries[0]?.state).toBe('ambiguous')
  })

  it('does not share one reservation across differently ordered JSON request bodies', async () => {
    const path = await journalPath()
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => Date.UTC(2026, 7, 22, 12),
    })
    await expect(guard.execute(
      'post_job',
      { job: { alpha: 1, beta: 2 } },
      100n,
      async (control) => {
        consume(control, 'post_job', { job: { alpha: 1, beta: 2 } }, 100n)
        throw new Error('first body is ambiguous')
      },
    )).rejects.toThrow('first body is ambiguous')
    const reorderedAction = vi.fn(async () => ({ id: 'must-not-run' }))

    await expect(guard.execute(
      'post_job',
      { job: { beta: 2, alpha: 1 } },
      100n,
      reorderedAction,
    )).rejects.toThrow(/daily cap/i)
    expect(reorderedAction).not.toHaveBeenCalled()
  })

  it('prunes released rows after their UTC day ends', async () => {
    const path = await journalPath()
    let now = Date.UTC(2026, 7, 22, 12)
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 100n,
      dailyPaymentLimitAtomic: 100n,
      now: () => now,
    })

    const unpaidInput = { title: 'not paid' }
    await expect(guard.execute('post_job', unpaidInput, 100n, async (control) => {
      consume(control, 'post_job', unpaidInput, 100n)
      throw Object.assign(new Error('rejected before signing'), { paymentMayHaveOccurred: false })
    })).rejects.toThrow('rejected before signing')
    now = Date.UTC(2026, 7, 23, 12)
    const nextInput = { title: 'paid next day' }
    await expect(guard.execute('post_job', nextInput, 100n, async (control) => {
      consume(control, 'post_job', nextInput, 100n)
      return { id: 'job-next-day' }
    })).resolves.toEqual({ id: 'job-next-day' })

    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string; day: string }>
    }
    expect(journal.entries).toEqual([
      expect.objectContaining({ state: 'settled', day: '2026-08-23' }),
    ])
  })

  it('fails closed at a fixed entry ceiling without evicting settled records', async () => {
    const path = await journalPath()
    const timestamp = Date.UTC(2026, 7, 22, 12)
    const entries = Array.from({ length: MAX_MCP_SPEND_JOURNAL_ENTRIES }, (_, index) => ({
      id: index.toString(16).padStart(64, '0'),
      tool: 'bid_job',
      amountAtomic: '1',
      day: '2026-08-22',
      state: 'settled',
      createdAt: timestamp,
      updatedAt: timestamp,
      attempts: 1,
      result: { id: `bid-${index}` },
    }))
    await writeFile(path, `${JSON.stringify({ version: 1, scope: 'test-wallet', entries })}\n`, {
      mode: 0o600,
    })
    const action = vi.fn(async () => ({ id: 'must-not-run' }))
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 1n,
      dailyPaymentLimitAtomic: BigInt(MAX_MCP_SPEND_JOURNAL_ENTRIES + 1),
      now: () => timestamp,
    })

    await expect(guard.execute('bid_job', { jobId: 'new' }, 1n, action))
      .rejects.toThrow(/entry safety limit/i)
    expect(action).not.toHaveBeenCalled()
    const retained = JSON.parse(await readFile(path, 'utf8')) as { entries: unknown[] }
    expect(retained.entries).toHaveLength(MAX_MCP_SPEND_JOURNAL_ENTRIES)
  })

  it('does not persist an unbounded paid-tool result', async () => {
    const path = await journalPath()
    const guard = new McpSpendGuard({
      journalPath: path,
      scope: 'test-wallet',
      maxPaymentAtomic: 1n,
      dailyPaymentLimitAtomic: 1n,
    })

    const largeInput = { jobId: 'large-result' }
    await expect(guard.execute('bid_job', largeInput, 1n, async (control) => {
      consume(control, 'bid_job', largeInput, 1n)
      return {
        id: 'bid-1',
        untrusted: 'x'.repeat(MAX_MCP_SPEND_RESULT_BYTES + 1),
      }
    })).rejects.toThrow(/result exceeds.*safety limit/i)
    const journal = JSON.parse(await readFile(path, 'utf8')) as {
      entries: Array<{ state: string; result?: unknown }>
    }
    expect(journal.entries).toEqual([
      expect.objectContaining({ state: 'ambiguous' }),
    ])
    expect(journal.entries[0]).not.toHaveProperty('result')
    expect((await stat(path)).size).toBeLessThan(MAX_MCP_SPEND_RESULT_BYTES)
  })
})
