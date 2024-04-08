/* eslint-disable @typescript-eslint/no-explicit-any */
import { BigNumber, PrivateKey, PublicKey, Hash, Curve } from '@bsv/sdk'
import bsvJs from 'babbage-bsv'
const BN = bsvJs.crypto.BN
const HashJs = bsvJs.crypto.Hash
const G = bsvJs.crypto.Point.getG()
import sharedSecretCache from './sharedSecretCache'
import { asArray } from '.'

/**
 * Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.
 *
 * @param params All parameters are provided in an object
 * @param params.senderPrivateKey The private key of the sender in WIF format
 * @param params.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param params.invoiceNumber The invoice number to use
 * @param params.revealCounterpartyLinkage=false When true, reveals the root shared secret between the two counterparties rather than performing key derivation, returning it as a hex string
 * @param params.revealPaymentLinkage=false When true, reveals the secret between the two counterparties used for this specific invoice number, rather than performing key derivation. Returns the linkage as a hex string
 * @param params.returnType=address] The destination key return type, either `address` or `publicKey`
 *
 * @returns The destination address or public key
 */
export function getPaymentAddress(params: {
  senderPrivateKey: string | bsvJs.crypto.BN | bsvJs.PrivateKey
  recipientPublicKey: string | bsvJs.PublicKey
  invoiceNumber: string
  revealCounterpartyLinkage?: boolean
  revealPaymentLinkage?: boolean
  returnType?: 'address' | 'publicKey' | 'babbage-bsv'
}): string | bsvJs.PublicKey {
  // First, a shared secret is calculated based on the public and private keys.
  let publicKey: bsvJs.PublicKey, privateKey: bsvJs.BN
  let cacheKey: string
  if (typeof params.recipientPublicKey === 'string') {
    cacheKey = `-${params.recipientPublicKey}`
    publicKey = bsvJs.PublicKey.fromString(params.recipientPublicKey)
  } else if (params.recipientPublicKey instanceof bsvJs.PublicKey) {
    cacheKey = `-${params.recipientPublicKey.toString()}`
    publicKey = params.recipientPublicKey
  } else {
    throw new Error('Unrecognized format for recipientPublicKey')
  }
  if (typeof params.senderPrivateKey === 'string') {
    cacheKey = params.senderPrivateKey + cacheKey
    privateKey = BN.fromHex(params.senderPrivateKey)
  } else if (params.senderPrivateKey instanceof BN) {
    cacheKey = params.senderPrivateKey.toHex({ size: 32 }) + cacheKey
    privateKey = params.senderPrivateKey
  } else if (params.senderPrivateKey instanceof bsvJs.PrivateKey) {
    cacheKey = params.senderPrivateKey.bn.toHex({ size: 32 }) + cacheKey
    privateKey = params.senderPrivateKey.bn
  } else {
    throw new Error('Unrecognized format for senderPrivateKey')
  }
  let sharedSecret
  if (sharedSecretCache[cacheKey]) {
    sharedSecret = sharedSecretCache[cacheKey]
  } else {
    sharedSecret = publicKey.point.mul(privateKey).toBuffer()
    sharedSecretCache[cacheKey] = sharedSecret
  }
  if (params.revealCounterpartyLinkage === true) {
    return sharedSecret.toString('hex')
  }

  // The invoice number is turned into a buffer.
  const invoiceNumber = Buffer.from(String(params.invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = HashJs.sha256hmac(invoiceNumber, sharedSecret)
  if (params.revealPaymentLinkage === true) {
    return hmac.toString('hex')
  }

  // The HMAC is multiplied by the generator point.
  const point = G.mul(BN.fromBuffer(hmac))

  // The resulting point is added to the recipient public key.
  const finalPublicKey = bsvJs.PublicKey.fromPoint(
    publicKey.point.add(point)
  )

  // Finally, an address is calculated with the new public key.
  if (params.returnType === undefined || params.returnType === 'address') {
    return bsvJs.Address.fromPublicKey(finalPublicKey).toString()
  } else if (params.returnType === 'publicKey') {
    return finalPublicKey.toString()
  } else if (params.returnType === 'babbage-bsv') {
    return finalPublicKey
  } else {
    throw new Error('The return type must either be "address" or "publicKey"')
  }
}

export function computePaymentContext(params: {
  senderPrivateKey: string | BigNumber | PrivateKey
  recipientPublicKey: string | PublicKey
  invoiceNumber: string
}): { publicKey: PublicKey, sharedSecret: number[], hmac: number[] } {
  // First, a shared secret is calculated based on the public and private keys.
  let publicKey: PublicKey
  if (typeof params.recipientPublicKey === 'string') {
    publicKey = PublicKey.fromString(params.recipientPublicKey)
  } else if (params.recipientPublicKey instanceof PublicKey) {
    publicKey = params.recipientPublicKey
  } else {
    throw new Error('Unrecognized format for recipientPublicKey')
  }
  let privateKey: BigNumber
  if (typeof params.senderPrivateKey === 'string') {
    privateKey = PrivateKey.fromString(params.senderPrivateKey, 'hex')
  } else if (params.senderPrivateKey instanceof PrivateKey) {
    privateKey = params.senderPrivateKey
  } else if (params.senderPrivateKey instanceof BigNumber) {
    privateKey = params.senderPrivateKey
  } else {
    throw new Error('Unrecognized format for senderPrivateKey')
  }
  const sharedSecret = publicKey.mul(privateKey).encode(true) as number[]

  // The invoice number is turned into a buffer.
  const invoiceBuffer = asArray(String(params.invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceBuffer)

  const curve = new Curve()

  // The HMAC is multiplied by the generator point.
  const point = curve.g.mul(new BigNumber(hmac))

  // The resulting point is added to the recipient public key.
  const resultPublicKey = new PublicKey(publicKey.add(point))

  return { publicKey: resultPublicKey, sharedSecret, hmac }
}

/**
 * @param params All parameters are provided in an object
 * @param params.senderPrivateKey The private key of the sender in WIF format
 * @param params.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param params.invoiceNumber The invoice number to use
 *
 * @returns The destination public key
 */
export function getPaymentPubKey(params: {
  senderPrivateKey: string | BigNumber | PrivateKey
  recipientPublicKey: string | PublicKey
  invoiceNumber: string
}): PublicKey {
  const { publicKey } = computePaymentContext(params)

  return publicKey
}

/**
 * @param params All parameters are provided in an object
 * @param params.senderPrivateKey The private key of the sender in WIF format
 * @param params.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param params.invoiceNumber The invoice number to use
 *
 * @returns The destination public key Base58 string
 */
export function getPaymentPubKeyString(params: {
  senderPrivateKey: string | BigNumber | PrivateKey
  recipientPublicKey: string | PublicKey
  invoiceNumber: string
}): string {
  return getPaymentPubKey(params).toString()
}

/**
 * @param params All parameters are provided in an object
 * @param params.senderPrivateKey The private key of the sender in WIF format
 * @param params.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param params.invoiceNumber The invoice number to use
 *
 * @returns The destination address as Base58 string
 */
export function getPaymentAddressString(params: {
  senderPrivateKey: string | BigNumber | PrivateKey
  recipientPublicKey: string | PublicKey
  invoiceNumber: string
}): string {
  const pubKey = getPaymentPubKey(params)
  return pubKey.toAddress()
}
