export type SpendReservationHistory = 'none' | 'released' | 'uncertain'

type SpendControlMetadata = Readonly<{
  reservationId: string
  reservationHistory: SpendReservationHistory
  claimed: boolean
}>

const spendControlMetadata = new WeakMap<object, SpendControlMetadata>()

/** Package-internal metadata; terminal-clear.ts is not a published subpath. */
export function registerSpendControl(
  control: object,
  metadata: Omit<SpendControlMetadata, 'claimed'>,
): void {
  spendControlMetadata.set(control, Object.freeze({ ...metadata, claimed: false }))
}

/** Mark only after the public control has claimed its exact paid operation. */
export function markSpendControlClaimed(control: object): void {
  const metadata = spendControlMetadata.get(control)
  if (!metadata || metadata.claimed) {
    throw Object.assign(new Error('spend-policy control metadata is invalid'), {
      paymentMayHaveOccurred: false as const,
    })
  }
  spendControlMetadata.set(control, Object.freeze({ ...metadata, claimed: true }))
}

export function claimedSpendControlMetadata(
  control: object,
): Pick<SpendControlMetadata, 'reservationId' | 'reservationHistory'> {
  const metadata = spendControlMetadata.get(control)
  if (!metadata?.claimed) {
    throw Object.assign(new Error('spend-policy control has not been claimed'), {
      paymentMayHaveOccurred: false as const,
    })
  }
  return metadata
}

export function forgetSpendControl(control: object): void {
  spendControlMetadata.delete(control)
}

const terminalPaymentClearSecret = Object.freeze({})
export type TerminalPaymentClearBinding = Readonly<{
  spendControl: object
  spendReservationId: string
  spendAmountAtomic: string
  publicKey: string
  attemptKey: string
  paymentId: string
  bodyHash: string
  /** Optional hash of the exact authorization header carried by this capability. */
  authorizationHash?: string
}>

const terminalPaymentClearTokens = new WeakMap<TerminalPaymentCleared, {
  binding: TerminalPaymentClearBinding
  released: boolean
}>()

/** Internal completion token carried across the spend-policy release boundary. */
export class TerminalPaymentCleared extends Error {
  readonly result = { state: 'terminal' as const, cleared: true as const, archived: true as const }

  constructor(secret: typeof terminalPaymentClearSecret, binding: TerminalPaymentClearBinding) {
    if (secret !== terminalPaymentClearSecret) throw new Error('invalid terminal-payment completion')
    super('terminal payment authorization was durably archived')
    this.name = 'TerminalPaymentCleared'
    terminalPaymentClearTokens.set(this, { binding: Object.freeze({ ...binding }), released: false })
    Object.defineProperty(this, 'paymentMayHaveOccurred', {
      value: false,
      enumerable: true,
      configurable: false,
    })
  }
}

export function terminalPaymentCleared(
  binding: TerminalPaymentClearBinding,
): TerminalPaymentCleared {
  return new TerminalPaymentCleared(terminalPaymentClearSecret, binding)
}

/** Mark only after the spend journal has durably transitioned to released. */
export function markTerminalPaymentClearReleased(value: unknown): boolean {
  if (!(value instanceof TerminalPaymentCleared)) return false
  const state = terminalPaymentClearTokens.get(value)
  if (!state || state.released) return false
  state.released = true
  return true
}

/** Recognize only a live process-local capability issued by this module. */
export function isTerminalPaymentClear(value: unknown): value is TerminalPaymentCleared {
  return value instanceof TerminalPaymentCleared && terminalPaymentClearTokens.has(value)
}

export function isTerminalPaymentClearFor(
  value: unknown,
  expected: {
    spendControl: object
    spendReservationId: string
    spendAmountAtomic: string
  },
): value is TerminalPaymentCleared {
  if (!isTerminalPaymentClear(value)) return false
  const state = terminalPaymentClearTokens.get(value)
  return state?.released === false &&
    state.binding.spendControl === expected.spendControl &&
    state.binding.spendReservationId === expected.spendReservationId &&
    state.binding.spendAmountAtomic === expected.spendAmountAtomic
}

export function consumeTerminalPaymentClear(
  value: TerminalPaymentCleared,
  expected: {
    publicKey: string
    bodyHash: string
    attemptKeys: readonly string[]
    authorizationHashes?: readonly string[]
  },
): TerminalPaymentClearBinding {
  const state = terminalPaymentClearTokens.get(value)
  if (!state) {
    throw new Error('terminal-payment completion is invalid or was already used')
  }
  if (!state.released) {
    throw new Error('terminal-payment completion is not durably released')
  }
  if (
    state.binding.publicKey !== expected.publicKey ||
    state.binding.bodyHash !== expected.bodyHash ||
    !expected.attemptKeys.includes(state.binding.attemptKey) ||
    (
      state.binding.authorizationHash !== undefined ||
      expected.authorizationHashes !== undefined
    ) && (
      state.binding.authorizationHash === undefined ||
      expected.authorizationHashes === undefined ||
      !expected.authorizationHashes.includes(state.binding.authorizationHash)
    )
  ) {
    throw new Error('terminal-payment completion belongs to another operation')
  }
  terminalPaymentClearTokens.delete(value)
  return state.binding
}
