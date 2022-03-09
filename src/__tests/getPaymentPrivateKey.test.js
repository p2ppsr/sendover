/* eslint-env jest */
const getPaymentPrivateKey = require('../getPaymentPrivateKey')
const generateKeypair = require('../generateKeypair')
const bsv = require('bsv')
const testVectors = require('./getPaymentPrivateKey.vectors')

describe('getPaymentPrivateKey', () => {
  it('Returns a valid Bitcoin SV private key', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const result = getPaymentPrivateKey({
      senderPublicKey: senderKeypair.publicKey,
      recipientPrivateKey: recipientKeypair.privateKey,
      invoiceNumber: testInvoiceNumber
    })
    expect(() => {
      bsv.PrivateKey.fromWIF(result)
    }).not.toThrow()
  })
  it('Returns a valid hex string', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const result = getPaymentPrivateKey({
      senderPublicKey: senderKeypair.publicKey,
      recipientPrivateKey: recipientKeypair.privateKey,
      invoiceNumber: testInvoiceNumber,
      returnType: 'hex'
    })
    expect(() => {
      bsv.PrivateKey.fromHex(result)
    }).not.toThrow()
  })
  it('Throws an error if an invalid return type is given', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    expect(() => {
      getPaymentPrivateKey({
        senderPublicKey: senderKeypair.publicKey,
        recipientPrivateKey: recipientKeypair.privateKey,
        invoiceNumber: testInvoiceNumber,
        returnType: 'publicKey'
      })
    }).toThrow(new Error(
      'The return type must either be "wif" or "hex"'
    ))
  })
  it('Returns a different private key with a different invoice number', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const firstInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const firstResult = getPaymentPrivateKey({
      senderPublicKey: senderKeypair.publicKey,
      recipientPrivateKey: recipientKeypair.privateKey,
      invoiceNumber: firstInvoiceNumber
    })
    const secondInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const secondResult = getPaymentPrivateKey({
      senderPublicKey: senderKeypair.publicKey,
      recipientPrivateKey: recipientKeypair.privateKey,
      invoiceNumber: secondInvoiceNumber
    })
    expect(firstResult).not.toEqual(secondResult)
  })
  testVectors.forEach((vector, index) => {
    it(`Passes test vector #${index + 1}`, () => {
      expect(getPaymentPrivateKey({
        senderPublicKey: vector.senderPublicKey,
        recipientPrivateKey: vector.recipientPrivateKey,
        invoiceNumber: vector.invoiceNumber
      })).toEqual(vector.privateKey)
    })
  })
})
