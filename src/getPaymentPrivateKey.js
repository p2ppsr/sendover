const bsv = require('bsv')
const BN = bsv.crypto.BN
const Hash = bsv.crypto.Hash
const N = bsv.crypto.Point.getN()

/**
 * Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.
 *
 * @returns {String} The base58 Bitcoin private key that can unlock the money.
 */
module.exports = ({ recipientPrivateKey, senderPublicKey, invoiceNumber }) => {
  // First, a shared secret is calculated based on the public and private keys.
  const publicKey = bsv.PublicKey.fromString(senderPublicKey)
  const privateKey = BN.fromHex(recipientPrivateKey)
  const sharedSecret = publicKey.point.mul(privateKey).toBuffer()

  // The invoice number is turned into a buffer.
  invoiceNumber = Buffer.from(String(invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber)

  // Finally, the hmac is added to the private key, and the result is modulo N.
  const finalPrivateKey = privateKey.add(BN.fromBuffer(hmac)).mod(N)
  return new bsv.PrivateKey(finalPrivateKey).toWIF()
}
