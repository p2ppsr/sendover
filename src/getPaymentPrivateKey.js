const bsv = require('bsv')
const BN = bsv.crypto.BN
const Hash = bsv.crypto.Hash
const N = bsv.crypto.Point.getN()

/**
 * Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.
 *
 * @param {Object} obj All parametera ere provided in an object
 * @param {String} obj.recipientPrivateKey The private key of the recipient in WIF format
 * @param {String} obj.senderPublicKey The public key of the sender in hexadecimal DER format
 * @param {String} obj.invoiceNumber The invoice number that was used
 * @param {String} [obj.returnType=wif] The incoming payment key return type, either `wif` or `hex`
 *
 * @returns {String} The incoming payment key that can unlock the money.
 */
module.exports = ({
  recipientPrivateKey,
  senderPublicKey,
  invoiceNumber,
  returnType = 'wif'
}) => {
  // First, a shared secret is calculated based on the public and private keys.
  let publicKey, privateKey
  if (typeof senderPublicKey === 'string') {
    publicKey = bsv.PublicKey.fromString(senderPublicKey)
  } else if (senderPublicKey instanceof bsv.PublicKey) {
    publicKey = senderPublicKey
  } else {
    throw new Error('Unrecognized format for senderPublicKey')
  }
  if (typeof recipientPrivateKey === 'string') {
    privateKey = BN.fromHex(recipientPrivateKey)
  } else if (recipientPrivateKey instanceof BN) {
    privateKey = recipientPrivateKey
  } else if (recipientPrivateKey instanceof bsv.PrivateKey) {
    privateKey = recipientPrivateKey.bn
  } else {
    throw new Error('Unrecognized format for recipientPrivateKey')
  }
  const sharedSecret = publicKey.point.mul(privateKey).toBuffer()

  // The invoice number is turned into a buffer.
  invoiceNumber = Buffer.from(String(invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber)

  // Finally, the hmac is added to the private key, and the result is modulo N.
  const finalPrivateKey = privateKey.add(BN.fromBuffer(hmac)).mod(N)

  switch (returnType) {
    case 'wif':
      return new bsv.PrivateKey(finalPrivateKey).toWIF()
    case 'hex':
      return finalPrivateKey.toHex({ size: 32 })
    case 'buffer':
      return finalPrivateKey.toBuffer({ size: 32 })
    case 'bsv':
      return finalPrivateKey
    default:
      throw new Error('The return type must either be "wif" or "hex"')
  }
}
