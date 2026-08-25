import { createHash, randomUUID } from 'node:crypto'
import { atomicWritePrivate, readPrivateFile, withFileLock } from './local-journal.js'
import { markTerminalPaymentClearReleased } from './terminal-clear.js'

export const MAX_MCP_SPEND_JOURNAL_ENTRIES = 4_096
export const MAX_MCP_SPEND_JOURNAL_BYTES = 8 * 1_024 * 1_024
export const MAX_MCP_SPEND_RESULT_BYTES = 64 * 1_024

export type McpPaymentOptions = {
  journalPath: string
  maxPaymentAtomic: bigint
  dailyPaymentLimitAtomic: bigint
  now?: () => number
}

export type McpSpendGuardOptions = McpPaymentOptions & {
  scope?: string
}

const spendControlBrand: unique symbol = Symbol('1f4bc-spend-control')

export type McpPaymentControl = {
  readonly [spendControlBrand]: true
}
export type SpendControl = McpPaymentControl

type IssuedPaymentControl = {
  tool: string
  input: string
  snapshot: unknown
  amountAtomic: bigint
  scope: string
  state: 'issued' | 'claimed'
}

// Payment controls are process-local, operation-bound, one-shot capabilities.
// A paid API entry point must atomically claim the exact tool/input/amount that
// SpendGuard reserved before it can create or submit an authorization.
const issuedPaymentControls = new WeakMap<McpPaymentControl, IssuedPaymentControl>()

export function assertAuthorizedPaymentControl(
  control: McpPaymentControl | undefined,
): asserts control is McpPaymentControl {
  if (!control || !issuedPaymentControls.has(control)) {
    throw Object.assign(
      new Error('paid operation requires an active local spend-policy reservation'),
      { paymentMayHaveOccurred: false as const },
    )
  }
}

type SpendState = 'reserved' | 'ambiguous' | 'settled' | 'released'

type SpendEntry = {
  id: string
  tool: string
  amountAtomic: string
  day: string
  state: SpendState
  createdAt: number
  updatedAt: number
  attempts: number
  ownerPid?: number
  ownerToken?: string
  leaseAt?: number
  result?: unknown
}

type SpendJournal = {
  version: 1
  scope: string
  entries: SpendEntry[]
}

type Reservation =
  | { cached: true; result: unknown }
  | { cached: false; id: string; ownerToken: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function validEntry(value: unknown): value is SpendEntry {
  if (!(isRecord(value) &&
    typeof value.id === 'string' && /^[0-9a-f]{64}$/.test(value.id) &&
    typeof value.tool === 'string' && value.tool.length > 0 &&
    typeof value.amountAtomic === 'string' && /^[1-9][0-9]*$/.test(value.amountAtomic) &&
    typeof value.day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value.day) &&
    (value.state === 'reserved' || value.state === 'ambiguous' ||
      value.state === 'settled' || value.state === 'released') &&
    typeof value.createdAt === 'number' && Number.isFinite(value.createdAt) &&
    typeof value.updatedAt === 'number' && Number.isFinite(value.updatedAt) &&
    typeof value.attempts === 'number' && Number.isSafeInteger(value.attempts) &&
    value.attempts > 0 &&
    (value.state !== 'settled' || Object.prototype.hasOwnProperty.call(value, 'result'))
  )) return false
  if (value.state === 'reserved') {
    return typeof value.ownerPid === 'number' && Number.isSafeInteger(value.ownerPid) &&
      value.ownerPid > 0 && typeof value.ownerToken === 'string' && value.ownerToken.length > 0 &&
      typeof value.leaseAt === 'number' && Number.isFinite(value.leaseAt)
  }
  return value.ownerPid === undefined && value.ownerToken === undefined && value.leaseAt === undefined
}

function parseJournal(value: unknown, scope: string): SpendJournal {
  if (
    !isRecord(value) ||
    value.version !== 1 ||
    value.scope !== scope ||
    !Array.isArray(value.entries) ||
    !value.entries.every(validEntry)
  ) {
    throw new Error('MCP spend journal is invalid or belongs to a different identity')
  }
  const ids = new Set(value.entries.map((entry) => entry.id))
  if (ids.size !== value.entries.length) throw new Error('MCP spend journal contains duplicate entries')
  return value as SpendJournal
}

const MAX_PAID_INPUT_BYTES = 64 * 1_024
const MAX_PAID_INPUT_DEPTH = 100
const MAX_PAID_INPUT_NODES = 20_000

type PreparedPaidInput = {
  snapshot: unknown
  serialized: string
}

type SnapshotState = {
  ancestors: WeakSet<object>
  nodes: number
}

function paidInputError(detail: string): Error {
  return definitiveNonpaymentError(`MCP paid tool input must be strict JSON data: ${detail}`)
}

function snapshotStrictJson(
  value: unknown,
  state: SnapshotState,
  depth: number,
): unknown {
  state.nodes += 1
  if (state.nodes > MAX_PAID_INPUT_NODES) throw paidInputError('too many values')
  if (depth > MAX_PAID_INPUT_DEPTH) throw paidInputError('nesting is too deep')
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw paidInputError('numbers must be finite')
    return value
  }
  if (typeof value !== 'object') {
    throw paidInputError('undefined, bigint, symbols, and functions are not allowed')
  }

  const object = value as object
  if (state.ancestors.has(object)) throw paidInputError('cyclic values are not allowed')
  state.ancestors.add(object)
  try {
    const symbols = Object.getOwnPropertySymbols(object)
    if (symbols.length > 0) throw paidInputError('symbol properties are not allowed')
    const descriptors = Object.getOwnPropertyDescriptors(object)

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw paidInputError('array subclasses and custom array prototypes are not allowed')
      }
      const keys = Object.keys(descriptors).filter((key) => key !== 'length')
      if (keys.length !== value.length) {
        throw paidInputError('arrays must be dense and cannot have extra properties')
      }
      const snapshot: unknown[] = []
      for (let index = 0; index < value.length; index += 1) {
        const key = String(index)
        const descriptor = descriptors[key]
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
          throw paidInputError('array items must be enumerable data properties')
        }
        snapshot.push(snapshotStrictJson(descriptor.value, state, depth + 1))
      }
      return Object.freeze(snapshot)
    }

    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      throw paidInputError('dates, boxed values, class instances, and custom prototypes are not allowed')
    }
    const snapshot = Object.create(null) as Record<string, unknown>
    // Preserve JSON.stringify's object key order. Sorting here would allow two
    // differently ordered wire bodies to share one cap reservation.
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]
      if (!descriptor.enumerable || !('value' in descriptor)) {
        throw paidInputError('object properties must be enumerable data properties')
      }
      if (key === 'toJSON') throw paidInputError('toJSON hooks are not allowed')
      Object.defineProperty(snapshot, key, {
        value: snapshotStrictJson(descriptor.value, state, depth + 1),
        enumerable: true,
        configurable: false,
        writable: false,
      })
    }
    return Object.freeze(snapshot)
  } finally {
    state.ancestors.delete(object)
  }
}

function preparePaidInput(value: unknown): PreparedPaidInput {
  const snapshot = snapshotStrictJson(value, { ancestors: new WeakSet(), nodes: 0 }, 0)
  const serialized = JSON.stringify(snapshot)
  if (serialized === undefined) throw paidInputError('the top-level value is missing')
  if (Buffer.byteLength(serialized, 'utf8') > MAX_PAID_INPUT_BYTES) {
    throw paidInputError(`serialized input exceeds ${MAX_PAID_INPUT_BYTES} bytes`)
  }
  return { snapshot, serialized }
}

/** Atomically consume a SpendGuard capability for one exact paid operation. */
export function claimAuthorizedPaymentControl<T>(
  control: McpPaymentControl | undefined,
  tool: string,
  input: T,
  amountAtomic: bigint,
  scope: string,
): T {
  assertAuthorizedPaymentControl(control)
  const issued = issuedPaymentControls.get(control)
  const serialized = preparePaidInput(input).serialized
  if (
    !issued ||
    issued.state !== 'issued' ||
    issued.tool !== tool ||
    issued.input !== serialized ||
    issued.amountAtomic !== amountAtomic ||
    issued.scope !== scope
  ) {
    throw definitiveNonpaymentError(
      'spend-policy control does not match this paid operation or was already used',
    )
  }
  // JavaScript executes this transition synchronously, so concurrent callers
  // cannot both consume the same control before either reaches its first await.
  issued.state = 'claimed'
  return issued.snapshot as T
}

function operationId(scope: string, tool: string, serialized: string): string {
  return createHash('sha256').update(`${scope}\n${tool}\n${serialized}`, 'utf8').digest('hex')
}

function utcDay(timestamp: number): string {
  const date = new Date(timestamp)
  if (!Number.isFinite(date.getTime())) throw new Error('MCP spend clock returned an invalid time')
  return date.toISOString().slice(0, 10)
}

function countsAgainstCap(entry: SpendEntry): boolean {
  return entry.state === 'reserved' || entry.state === 'ambiguous' || entry.state === 'settled'
}

function paymentMayHaveOccurred(error: unknown): boolean | undefined {
  if (!isRecord(error)) return undefined
  return typeof error.paymentMayHaveOccurred === 'boolean'
    ? error.paymentMayHaveOccurred
    : undefined
}

function definitiveNonpaymentError(message: string): Error {
  return Object.assign(new Error(message), { paymentMayHaveOccurred: false as const })
}

export class McpSpendGuard {
  private readonly path: string
  private readonly scope: string
  private readonly maxPaymentAtomic: bigint
  private readonly dailyPaymentLimitAtomic: bigint
  private readonly now: () => number

  constructor(options: McpSpendGuardOptions) {
    if (!options.journalPath) throw new Error('MCP spend journal path is required')
    if (options.maxPaymentAtomic <= 0n) throw new Error('MCP per-transaction cap must be positive')
    if (options.dailyPaymentLimitAtomic <= 0n) throw new Error('MCP daily cap must be positive')
    this.path = options.journalPath
    this.scope = options.scope ?? '1f4bc-mcp'
    this.maxPaymentAtomic = options.maxPaymentAtomic
    this.dailyPaymentLimitAtomic = options.dailyPaymentLimitAtomic
    this.now = options.now ?? Date.now
  }

  async execute<T>(
    tool: string,
    input: unknown,
    amountAtomic: bigint,
    action: (control: McpPaymentControl) => Promise<T>,
  ): Promise<T> {
    if (amountAtomic <= 0n) throw new Error('MCP payment amount must be positive')
    if (amountAtomic > this.maxPaymentAtomic) {
      throw new Error(
        `MCP payment ${amountAtomic} atomic USDC exceeds the per-transaction cap ${this.maxPaymentAtomic}`,
      )
    }
    // Snapshot and serialize synchronously before the first await. The same
    // immutable value is bound to the reservation and later returned by the
    // one-shot claim, so caller mutation cannot turn an approved A into paid B.
    const preparedInput = preparePaidInput(input)
    const id = operationId(this.scope, tool, preparedInput.serialized)
    const reservation = await this.reserve(id, tool, amountAtomic)
    if (reservation.cached) return structuredClone(reservation.result) as T

    const control = Object.freeze({
      [spendControlBrand]: true as const,
    }) as McpPaymentControl
    issuedPaymentControls.set(control, {
      tool,
      input: preparedInput.serialized,
      snapshot: preparedInput.snapshot,
      amountAtomic,
      scope: this.scope,
      state: 'issued',
    })
    let result: T
    let finalControl: IssuedPaymentControl | undefined
    try {
      result = await action(control)
      finalControl = issuedPaymentControls.get(control)
      if (finalControl?.state !== 'claimed') {
        throw definitiveNonpaymentError(
          'paid action returned without consuming its exact spend-policy control',
        )
      }
    } catch (error) {
      const issued = issuedPaymentControls.get(control)
      const targetState = issued?.state !== 'claimed' || paymentMayHaveOccurred(error) === false
          ? 'released'
          : 'ambiguous'
      const transitioned = await this.transition(
        id,
        targetState,
        undefined,
        reservation.ownerToken,
      )
      if (targetState === 'released' && transitioned) {
        markTerminalPaymentClearReleased(error)
      }
      throw error
    } finally {
      issuedPaymentControls.delete(control)
    }

    try {
      await this.recordSettlement(id, result, reservation.ownerToken)
    } catch (error) {
      await this.transition(id, 'ambiguous', undefined, reservation.ownerToken).catch(() => undefined)
      throw error
    }
    return result
  }

  private emptyJournal(): SpendJournal {
    return { version: 1, scope: this.scope, entries: [] }
  }

  private async load(): Promise<SpendJournal> {
    try {
      return parseJournal(JSON.parse(await readPrivateFile(
        this.path,
        MAX_MCP_SPEND_JOURNAL_BYTES,
        'MCP spend journal',
      )), this.scope)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return this.emptyJournal()
      if (error instanceof SyntaxError) throw new Error('MCP spend journal contains invalid JSON')
      throw error
    }
  }

  private save(journal: SpendJournal): Promise<void> {
    const contents = `${JSON.stringify(journal)}\n`
    if (Buffer.byteLength(contents, 'utf8') > MAX_MCP_SPEND_JOURNAL_BYTES) {
      throw new Error('MCP spend journal reached its byte-size safety limit')
    }
    return atomicWritePrivate(this.path, contents)
  }

  private async reserve(id: string, tool: string, amountAtomic: bigint): Promise<Reservation> {
    return withFileLock(this.path, async () => {
      const journal = await this.load()
      const timestamp = this.now()
      const day = utcDay(timestamp)
      const beforePrune = journal.entries.length
      // A definitive nonpayment has no authorization or result to recover.
      // Keep today's rows for auditability, then discard them at the UTC boundary.
      journal.entries = journal.entries.filter(
        (entry) => entry.state !== 'released' || entry.day === day,
      )
      let journalChanged = journal.entries.length !== beforePrune
      // Outstanding authorizations may still be submitted after midnight.
      // Carry all of that uncertainty into the current UTC bucket before
      // considering any new reservation, including a different operation.
      for (const entry of journal.entries) {
        if (
          (entry.state === 'reserved' || entry.state === 'ambiguous') &&
          entry.day !== day
        ) {
          entry.day = day
          entry.updatedAt = timestamp
          journalChanged = true
        }
      }
      const existing = journal.entries.find((entry) => entry.id === id)
      const ownerToken = randomUUID()
      if (existing && existing.tool !== tool) {
        if (journalChanged) await this.save(journal)
        throw new Error('MCP spend reservation tool mismatch')
      }
      if (existing && existing.amountAtomic !== amountAtomic.toString()) {
        if (journalChanged) await this.save(journal)
        throw new Error('MCP spend reservation amount changed for the same logical call')
      }
      if (existing?.state === 'settled') {
        if (journalChanged) await this.save(journal)
        return { cached: true, result: existing.result }
      }
      if (existing?.state === 'reserved' && this.reservationOwnerIsLive(existing)) {
        if (journalChanged) await this.save(journal)
        throw new Error('the same paid MCP tool call is already in progress')
      }
      if (existing && (existing.state === 'reserved' || existing.state === 'ambiguous')) {
        // A retry after UTC rollover can still submit the old authorization.
        // Move that uncertainty into today's bucket before doing any work so
        // an authorization created yesterday cannot bypass today's cap.
        const used = journal.entries
          .filter((entry) => entry.id !== id && entry.day === day && countsAgainstCap(entry))
          .reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n)
        if (used + amountAtomic > this.dailyPaymentLimitAtomic) {
          if (journalChanged) await this.save(journal)
          throw new Error(
            `MCP daily cap ${this.dailyPaymentLimitAtomic} atomic USDC would be exceeded`,
          )
        }
        existing.attempts += 1
        existing.day = day
        existing.state = 'reserved'
        existing.updatedAt = timestamp
        existing.ownerPid = process.pid
        existing.ownerToken = ownerToken
        existing.leaseAt = timestamp
        await this.save(journal)
        return { cached: false, id, ownerToken }
      }

      const used = journal.entries
        .filter((entry) => entry.day === day && countsAgainstCap(entry))
        .reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n)
      if (used + amountAtomic > this.dailyPaymentLimitAtomic) {
        if (journalChanged) await this.save(journal)
        throw new Error(
          `MCP daily cap ${this.dailyPaymentLimitAtomic} atomic USDC would be exceeded`,
        )
      }
      if (!existing && journal.entries.length >= MAX_MCP_SPEND_JOURNAL_ENTRIES) {
        if (journalChanged) await this.save(journal)
        throw new Error(
          `MCP spend journal reached its ${MAX_MCP_SPEND_JOURNAL_ENTRIES}-entry safety limit`,
        )
      }
      if (existing) {
        Object.assign(existing, {
          amountAtomic: amountAtomic.toString(),
          day,
          state: 'reserved' as const,
          updatedAt: timestamp,
          attempts: existing.attempts + 1,
          ownerPid: process.pid,
          ownerToken,
          leaseAt: timestamp,
        })
        delete existing.result
      } else {
        journal.entries.push({
          id,
          tool,
          amountAtomic: amountAtomic.toString(),
          day,
          state: 'reserved',
          createdAt: timestamp,
          updatedAt: timestamp,
          attempts: 1,
          ownerPid: process.pid,
          ownerToken,
          leaseAt: timestamp,
        })
      }
      await this.save(journal)
      return { cached: false, id, ownerToken }
    })
  }

  private reservationOwnerIsLive(entry: SpendEntry): boolean {
    if (!entry.ownerPid || entry.leaseAt === undefined) return false
    try {
      process.kill(entry.ownerPid, 0)
      return true
    } catch (error) {
      return (error as NodeJS.ErrnoException).code !== 'ESRCH'
    }
  }

  private async transition(
    id: string,
    state: SpendState,
    result: unknown,
    ownerToken: string,
  ): Promise<boolean> {
    return withFileLock(this.path, async () => {
      const journal = await this.load()
      const entry = journal.entries.find((candidate) => candidate.id === id)
      if (!entry) throw new Error('MCP spend reservation disappeared')
      if (entry.ownerToken !== ownerToken) return false
      if (entry.state === 'settled' && state !== 'settled') return false
      if (entry.state === 'released' && state === 'ambiguous') return false
      const timestamp = this.now()
      entry.state = state
      entry.updatedAt = timestamp
      if (state === 'settled' || state === 'ambiguous') entry.day = utcDay(timestamp)
      delete entry.ownerPid
      delete entry.ownerToken
      delete entry.leaseAt
      if (state === 'settled') entry.result = result
      else delete entry.result
      await this.save(journal)
      return true
    })
  }

  private async recordSettlement(id: string, result: unknown, ownerToken: string): Promise<void> {
    const serialized = JSON.stringify(result)
    if (serialized === undefined) throw new Error('paid MCP tool returned no durable result')
    if (Buffer.byteLength(serialized, 'utf8') > MAX_MCP_SPEND_RESULT_BYTES) {
      throw new Error('paid MCP tool result exceeds the spend-journal safety limit')
    }
    await this.transition(id, 'settled', JSON.parse(serialized) as unknown, ownerToken)
  }
}

// Public neutral name; the legacy class name remains internal-source
// compatible while CLI, MCP, and peer payments share one policy engine.
export { McpSpendGuard as SpendGuard }
