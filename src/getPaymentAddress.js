const bsv = require('bsv')
const BN = bsv.crypto.BN
const Hash = bsv.crypto.Hash
const G = bsv.crypto.Point.getG()

/**
 * Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.
 *
 * @returns {String} The base58 Bitcoin address where the payment is to be sent.
 */
module.exports = ({ senderPrivateKey, recipientPublicKey, invoiceNumber }) => {
  // First, a shared secret is calculated based on the public and private keys.
  const publicKey = bsv.PublicKey.fromString(recipientPublicKey)
  const privateKey = BN.fromHex(senderPrivateKey)
  const sharedSecret = publicKey.point.mul(privateKey).toBuffer()

  // The invoice number is turned into a buffer.
  invoiceNumber = Buffer.from(String(invoiceNumber), 'utf8')

  // An HMAC is calculated with the shared secret and the invoice number.
  const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber)

  // The HMAC is multiplied by the generator point.
  const point = G.mul(BN.fromBuffer(hmac))

  // The resulting point is added to the recipient public key.
  const finalPublicKey = bsv.PublicKey.fromPoint(
    publicKey.point.add(point)
  )

  // Finally, an address is calculated with the new public key.
  return bsv.Address.fromPublicKey(finalPublicKey).toString()
}
