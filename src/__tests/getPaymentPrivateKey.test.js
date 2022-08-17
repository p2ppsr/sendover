/* eslint-env jest */
//const getPaymentPrivateKey = require('../../lib/getPaymentPrivateKey')
//const generateKeypair = require('../../lib/generateKeypair')
const { getPaymentPrivateKey } = require('../../lib/getPaymentPrivateKey2')
const { generateKeypair } = require('../../lib/generateKeypair2')
const bsv = require('bsv')
// const testVectors = require('./getPaymentPrivateKey.vectors')
const { generateTestVectors } = require('./getPaymentPrivateKey.vectorGenerator')

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
  it('Returns a valid buffer array', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = require('crypto')
      .randomBytes(8)
      .toString('base64')
    const result = getPaymentPrivateKey({
      senderPublicKey: senderKeypair.publicKey,
      recipientPrivateKey: recipientKeypair.privateKey,
      invoiceNumber: testInvoiceNumber,
      returnType: 'buffer'
    })
    expect(() => {
      bsv.PrivateKey.fromBuffer(result)
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
  it('Pads private keys with zeros if their size is less than 32 bytes', () => {
    // Generates a private key that meets the criteria described above
    const result = getPaymentPrivateKey({
      senderPublicKey: '040c2cb7c02421257c7cc01e95288e0167bb4982f6ed7f06843ca908a7ee987bcc5e79df21aee01631cca74ba10b92c3053016514c79434f49e952304717df9f87',
      recipientPrivateKey: 'a4f4ad15349c25ed3d8bf69a713a2c3099f76adeb11cf3d1c5d9abb15e00f4a0',
      invoiceNumber: 1,
      returnType: 'hex'
    })
    expect(result.length).toEqual(64)
  })
  it('Returns a bsv BN object that can be used to retrieve a 32 byte hex string', () => {
    // Generates a private key that meets the criteria described above
    const result = getPaymentPrivateKey({
      senderPublicKey: '040c2cb7c02421257c7cc01e95288e0167bb4982f6ed7f06843ca908a7ee987bcc5e79df21aee01631cca74ba10b92c3053016514c79434f49e952304717df9f87',
      recipientPrivateKey: 'a4f4ad15349c25ed3d8bf69a713a2c3099f76adeb11cf3d1c5d9abb15e00f4a0',
      invoiceNumber: 1,
      returnType: 'bsv'
    })
    expect(result.toHex({ size: 32 }).length).toEqual(64)
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
  const testVectors = generateTestVectors()
  testVectors.forEach((vector, index) => {
    it(`Passes test vector #${index + 1}`, () => {
      const privateKey = getPaymentPrivateKey({
        senderPublicKey: vector.senderPublicKey,
        recipientPrivateKey: vector.recipientPrivateKey,
        invoiceNumber: vector.invoiceNumber,
        returnType: 'hex'
      })
      expect(privateKey.length).toEqual(64)
      expect(privateKey).toEqual(vector.privateKey)
    })
  })
})
