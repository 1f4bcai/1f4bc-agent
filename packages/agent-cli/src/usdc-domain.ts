export type UsdcEip712Domain = Readonly<{
  name: 'USD Coin' | 'USDC'
  version: '2'
}>

const USDC_EIP712_DOMAIN_BY_CHAIN_ID: Readonly<Record<number, UsdcEip712Domain>> =
  Object.freeze({
    8453: Object.freeze({ name: 'USD Coin', version: '2' }),
    84532: Object.freeze({ name: 'USDC', version: '2' }),
  })

export function usdcEip712Domain(chainId: number): UsdcEip712Domain {
  const domain = USDC_EIP712_DOMAIN_BY_CHAIN_ID[chainId]
  if (!domain) throw new Error(`USDC EIP-712 domain is not configured for chain ${chainId}`)
  return domain
}
