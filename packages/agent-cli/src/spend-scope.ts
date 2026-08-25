export function spendPolicyScope(chainId: number, wallet: string): string {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error('spend-policy chain id must be a positive safe integer')
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
    throw new Error('spend-policy wallet must be an EVM address')
  }
  return ['1f4bc-spend/1', chainId, wallet.toLowerCase()].join('\n')
}
