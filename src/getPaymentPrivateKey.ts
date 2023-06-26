/* eslint-disable @typescript-eslint/no-explicit-any */
import bsv from 'babbage-bsv';
const BN = bsv.crypto.BN
const Hash = bsv.crypto.Hash
const N = bsv.crypto.Point.getN()

/**
 * Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.
 *
 * @param params All parametera ere provided in an object
 * @param params.recipientPrivateKey The private key of the recipient in WIF format
 * @param params.senderPublicKey The public key of the sender in hexadecimal DER format
 * @param params.invoiceNumber The invoice number that was used
 * @param params.returnType=wif The incoming payment key return type, either `wif` or `hex`
 *
 * @returns The incoming payment key that can unlock the money.
 */
export function getPaymentPrivateKey(params: {
  recipientPrivateKey: string | bsv.crypto.BN | bsv.PrivateKey,
  senderPublicKey: string | bsv.PublicKey,
  invoiceNumber: string,
  returnType?: 'wif' | 'hex' | 'buffer' | 'babbage-bsv'
}) : string | Buffer | bsv.PrivateKey {
  if (!params.returnType) params.returnType = 'wif'

  // First, a shared secret is calculated based on the public and private keys.
  let publicKey: bsv.PublicKey, privateKey: bsv.PrivateKey

  if (typeof params.senderPublicKey === 'string') {
    publicKey = bsv.PublicKey.fromString(params.senderPublicKey)
  } else if (params.senderPublicKey instanceof bsv.PublicKey) {
    publicKey = params.senderPublicKey
  } else {
    throw new Error('Unrecognized format for senderPublicKey')
  }

  if (typeof params.recipientPrivateKey === 'string') {
    privateKey = BN.fromHex(params.recipientPrivateKey)
  } else if (params.recipientPrivateKey instanceof BN) {
    privateKey = params.recipientPrivateKey
  } else if (params.recipientPrivateKey instanceof bsv.PrivateKey) {
    privateKey = params.recipientPrivateKey.bn
  } else {
    throw new Error('Unrecognized format for recipientPrivateKey')
  }

  const sharedSecret = publicKey.point.mul(privateKey).toBuffer()

  // The invoice number is turned into a buffer.
  const invoiceNumber = Buffer.from(String(params.invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber)

  // Finally, the hmac is added to the private key, and the result is modulo N.
  const finalPrivateKey = privateKey.add(BN.fromBuffer(hmac)).mod(N)

  switch (params.returnType) {
    case 'wif':
      return new bsv.PrivateKey(finalPrivateKey).toWIF()
    case 'hex':
      return finalPrivateKey.toHex({ size: 32 })
    case 'buffer':
      return finalPrivateKey.toBuffer({ size: 32 })
    case 'babbage-bsv':
      return finalPrivateKey
    default:
      throw new Error('The return type must either be "wif" or "hex"')
  }
}
