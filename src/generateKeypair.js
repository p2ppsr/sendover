const bsv = require('bsv')

/**
 * Generates a public/private keypair for the sending and receiving of invoices.
 *
 * @returns {Object} The generated keypair, with `privateKey` and `publicKey` properties.
 */
module.exports = () => {
  const privateKey = bsv.PrivateKey.fromRandom()
  return {
    privateKey: privateKey.bn.toHex(),
    publicKey: privateKey.publicKey.toString()
  }
}
