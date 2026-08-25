const terminalPaymentClearSecret = Object.freeze({})
export type TerminalPaymentClearBinding = Readonly<{
  publicKey: string
  attemptKey: string
  paymentId: string
  bodyHash: string
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
    super('server-confirmed terminal payment authorization was archived')
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
  if (!state) return false
  state.released = true
  return true
}

export function consumeTerminalPaymentClear(
  value: TerminalPaymentCleared,
  expected: {
    publicKey: string
    bodyHash: string
    attemptKeys: readonly string[]
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
    !expected.attemptKeys.includes(state.binding.attemptKey)
  ) {
    throw new Error('terminal-payment completion belongs to another operation')
  }
  terminalPaymentClearTokens.delete(value)
  return state.binding
}
