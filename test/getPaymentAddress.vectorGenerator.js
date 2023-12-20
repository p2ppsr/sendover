const { getPaymentAddress } = require('../out/src/getPaymentAddress')
const { generateKeypair } = require('../out/src/generateKeypair')

const vectors = []
for (let i = 0; i < 5; i++) {
  const senderKeypair = generateKeypair()
  const recipientKeypair = generateKeypair()
  const invoiceNumber = require('crypto')
    .randomBytes(8)
    .toString('base64')
  const result = getPaymentAddress({
    senderPrivateKey: senderKeypair.privateKey,
    recipientPublicKey: recipientKeypair.publicKey,
    invoiceNumber: invoiceNumber,
    returnType: 'publicKey'
  })
  vectors.push({
    senderPrivateKey: senderKeypair.privateKey,
    recipientPublicKey: recipientKeypair.publicKey,
    invoiceNumber: invoiceNumber,
    publicKey: result
  })
}

console.log(JSON.stringify(vectors, null, 2))
