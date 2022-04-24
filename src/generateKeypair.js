const bsv = require('bsv')

/**
 * Generates a public/private keypair for the sending and receiving of invoices.
 *
 * @param {Object} obj All parameters are given in an object
 * @param {String} [obj.returnType='hex'] Return type, either "hex" or "bsv"
 *
 * @returns {Object} The generated keypair, with `privateKey` and `publicKey` properties.
 */
module.exports = ({ returnType = 'hex' } = {}) => {
  const privateKey = bsv.PrivateKey.fromRandom()
  if (returnType === 'bsv') {
    return {
      privateKey,
      publicKey: privateKey.publicKey
    }
  } else {
    return {
      privateKey: privateKey.bn.toHex(),
      publicKey: privateKey.publicKey.toString()
    }
  }
}
