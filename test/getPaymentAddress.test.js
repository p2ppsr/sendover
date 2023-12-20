/* eslint-env jest */
const { getPaymentAddress } = require('../out/src/getPaymentAddress')
const { generateKeypair } = require('../out/src/generateKeypair')
const bsv = require('babbage-bsv')
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
  it('Returns a valid public key', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const result = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: testInvoiceNumber,
      returnType: 'publicKey'
    })
    expect(() => {
      bsv.PublicKey.fromString(result)
    }).not.toThrow()
  })
  it('Throws an error if an invalid return type is given', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    expect(() => {
      getPaymentAddress({
        senderPrivateKey: senderKeypair.privateKey,
        recipientPublicKey: recipientKeypair.publicKey,
        invoiceNumber: testInvoiceNumber,
        returnType: 'privateKey'
      })
    }).toThrow(new Error(
      'The return type must either be "address" or "publicKey"'
    ))
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
  it('Reveals the same counterparty linkage information across two invoice numbers', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const firstInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const firstResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: firstInvoiceNumber,
      revealCounterpartyLinkage: true
    })
    const secondInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const secondResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: secondInvoiceNumber,
      revealCounterpartyLinkage: true
    })
    expect(firstResult).toEqual(secondResult)
  })
  it('Reveals different payment linkage information across two invoice numbers', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const firstInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const firstResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: firstInvoiceNumber,
      revealPaymentLinkage: true
    })
    const secondInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const secondResult = getPaymentAddress({
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: secondInvoiceNumber,
      revealPaymentLinkage: true
    })
    expect(firstResult).not.toEqual(secondResult)
  })
  testVectors.forEach((vector, index) => {
    it(`Passes test vector #${index + 1}`, () => {
      expect(getPaymentAddress({
        senderPrivateKey: vector.senderPrivateKey,
        recipientPublicKey: vector.recipientPublicKey,
        invoiceNumber: vector.invoiceNumber,
        returnType: 'publicKey'
      })).toEqual(vector.publicKey)
    })
  })
})
