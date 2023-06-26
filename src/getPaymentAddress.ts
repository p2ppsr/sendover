/* eslint-disable @typescript-eslint/no-explicit-any */
import bsv from 'babbage-bsv';

const BN = bsv.crypto.BN
const Hash = bsv.crypto.Hash
const G = bsv.crypto.Point.getG()

/**
 * Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.
 *
 * @param params All parameters are provided in an object
 * @param params.senderPrivateKey The private key of the sender in WIF format
 * @param params.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param params.invoiceNumber The invoice number to use
 * @param params.returnType=address] The destination key return type, either `address` or `publicKey`
 *
 * @returns The destination address or public key
 */
export function getPaymentAddress(params: {
  senderPrivateKey: string | bsv.crypto.BN | bsv.PrivateKey,
  recipientPublicKey: string | bsv.PublicKey,
  invoiceNumber: string,
  returnType?: 'address' | 'publicKey' | 'babbage-bsv'
}): string | bsv.PublicKey {

  // First, a shared secret is calculated based on the public and private keys.
  let publicKey: bsv.PublicKey, privateKey: bsv.PrivateKey
  if (typeof params.recipientPublicKey === 'string') {
    publicKey = bsv.PublicKey.fromString(params.recipientPublicKey)
  } else if (params.recipientPublicKey instanceof bsv.PublicKey) {
    publicKey = params.recipientPublicKey
  } else {
    throw new Error('Unrecognized format for recipientPublicKey')
  }
  if (typeof params.senderPrivateKey === 'string') {
    privateKey = BN.fromHex(params.senderPrivateKey)
  } else if (params.senderPrivateKey instanceof BN) {
    privateKey = params.senderPrivateKey
  } else if (params.senderPrivateKey instanceof bsv.PrivateKey) {
    privateKey = params.senderPrivateKey.bn
  } else {
    throw new Error('Unrecognized format for senderPrivateKey')
  }
  const sharedSecret = publicKey.point.mul(privateKey).toBuffer()

  // The invoice number is turned into a buffer.
  const invoiceNumber = Buffer.from(String(params.invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber)

  // The HMAC is multiplied by the generator point.
  const point = G.mul(BN.fromBuffer(hmac))

  // The resulting point is added to the recipient public key.
  const finalPublicKey = bsv.PublicKey.fromPoint(
    publicKey.point.add(point)
  )

  // Finally, an address is calculated with the new public key.
  if (!params.returnType || params.returnType === 'address') {
    return bsv.Address.fromPublicKey(finalPublicKey).toString()
  } else if (params.returnType === 'publicKey') {
    return finalPublicKey.toString()
  } else if (params.returnType === 'babbage-bsv') {
    return finalPublicKey
  } else {
    throw new Error('The return type must either be "address" or "publicKey"')
  }
}
