const getPaymentAddress = require('../getPaymentAddress')
const generateKeypair = require('../generateKeypair')

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
    invoiceNumber: invoiceNumber
  })
  vectors.push({
    senderPrivateKey: senderKeypair.privateKey,
    recipientPublicKey: recipientKeypair.publicKey,
    invoiceNumber: invoiceNumber,
    address: result
  })
}

console.log(JSON.stringify(vectors, null, 2))
