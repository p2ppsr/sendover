const getPaymentAddress = require('../getPaymentAddress')
const generateKeypair = require('../generateKeypair')
const bsv = require('bsv')
const testVectors = require('./getPaymentAddress.vectors')

describe('getPaymentAddress', () => {
  it('Returns a valid Bitcoin SV address', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const result = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: testInvoiceNumber
    })
    expect(() => {
      bsv.Address.fromString(result)
    }).not.toThrow()
  })
  it('Returns a different address with a different invoice number', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const firstInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const firstResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: firstInvoiceNumber
    })
    const secondInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const secondResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: secondInvoiceNumber
    })
    expect(firstResult).not.toEqual(secondResult)
  })
  testVectors.forEach((vector, index) => {
    it(`Passes test vector #${index + 1}`, () => {
      expect(getPaymentAddress({
        senderPrivateKey: vector.senderPrivateKey,
        recipientPublicKey: vector.recipientPublicKey,
        invoiceNumber: vector.invoiceNumber
      })).toEqual(vector.address)
    })
  })
})
