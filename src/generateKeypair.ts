import bsv from 'babbage-bsv'

/**
 * Generates a public/private keypair for the sending and receiving of invoices.
 *
 * @param params All parameters are given in an object
 * @param params.returnType='hex' Return type, either "hex" or "babbage-bsv"
 *
 * @returns The generated keypair, with `privateKey` and `publicKey` properties.
 */
export function generateKeypair (params?: { returnType?: 'hex' | 'babbage-bsv' }
): {
    privateKey: string | bsv.PrivateKey
    publicKey: string | bsv.PublicKey
  } {
  params ||= {}
  params.returnType ||= 'hex'

  const privateKey = bsv.PrivateKey.fromRandom()

  if (params.returnType === 'babbage-bsv') {
    return {
      privateKey,
      publicKey: privateKey.publicKey
    }
  } else {
    return {
      privateKey: privateKey.bn.toHex({ size: 32 }),
      publicKey: privateKey.publicKey.toString()
    }
  }
}
