const getPaymentPrivateKey = require('../getPaymentPrivateKey')
const generateKeypair = require('../generateKeypair')

const vectors = []
for (let i = 0; i < 5; i++) {
  const senderKeypair = generateKeypair()
  const recipientKeypair = generateKeypair()
  const invoiceNumber = require('crypto')
    .randomBytes(8)
    .toString('base64')
  const result = getPaymentPrivateKey({
    senderPublicKey: senderKeypair.publicKey,
    recipientPrivateKey: recipientKeypair.privateKey,
    invoiceNumber: invoiceNumber
  })
  vectors.push({
    senderPublicKey: senderKeypair.publicKey,
    recipientPrivateKey: recipientKeypair.privateKey,
    invoiceNumber: invoiceNumber,
    privateKey: result
  })
}

console.log(JSON.stringify(vectors, null, 2))
