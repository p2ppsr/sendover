import { computePaymentContext, getPaymentAddress, getPaymentAddressString, getPaymentPubKey } from '../out/src/getPaymentAddress'
import { generateKeypair } from '../out/src/generateKeypair'
import bsv from 'babbage-bsv'
import testVectors from './getPaymentAddress.vectors'
import { asString, randomBytesBase64 } from 'cwi-base'

describe('getPaymentAddress', () => {
  it('Returns a valid Bitcoin SV address', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = randomBytesBase64(8)
    const params = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: testInvoiceNumber
    }
    const result = getPaymentAddress(params)
    expect(() => {
      bsv.Address.fromString(result)
    }).not.toThrow()

    const r2 = getPaymentAddressString(params)
    expect(r2).toBe(result)
  })
  it('Returns a valid public key', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = randomBytesBase64(8)
    const params = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: testInvoiceNumber
    }
    const result = getPaymentAddress({
      ...params,
      returnType: 'publicKey'
    })
    expect(() => {
      bsv.PublicKey.fromString(result)
    }).not.toThrow()
    const r2 = getPaymentPubKey(params)
    expect(r2.toString()).toBe(result)
  })
  it('Throws an error if an invalid return type is given', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const testInvoiceNumber = randomBytesBase64(8)
    const params = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: testInvoiceNumber
    }
    expect(() => {
      getPaymentAddress({
        ...params,
        returnType: <'publicKey'>'privateKey'
      })
    }).toThrow(new Error(
      'The return type must either be "address" or "publicKey"'
    ))
  })
  it('Returns a different address with a different invoice number', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const params1 = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: randomBytesBase64(8)
    }
    const params2 = {
      ...params1,
      invoiceNumber: randomBytesBase64(8)
    }
    const firstResult = getPaymentAddress(params1)
    const secondResult = getPaymentAddress(params2)
    expect(firstResult).not.toEqual(secondResult)
    const r1 = getPaymentAddressString(params1)
    const r2 = getPaymentAddressString(params2)
    expect(r1).toBe(firstResult)
    expect(r2).toBe(secondResult)
    expect(r1).not.toEqual(r2)
  })
  it('Reveals the same counterparty linkage information across two invoice numbers', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const params1 = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: randomBytesBase64(8)
    }
    const params2 = {
      ...params1,
      invoiceNumber: randomBytesBase64(8)
    }
    const firstResult = getPaymentAddress({
      ...params1,
      revealCounterpartyLinkage: true
    })
    const secondResult = getPaymentAddress({
      ...params2,
      revealCounterpartyLinkage: true
    })
    expect(firstResult).toEqual(secondResult)
    const r1 = computePaymentContext(params1)
    const r2 = computePaymentContext(params2)
    expect(asString(r1.sharedSecret)).toBe(firstResult)
    expect(asString(r2.sharedSecret)).toBe(secondResult)
    expect(asString(r1.sharedSecret)).toEqual(asString(r2.sharedSecret))
  })
  it('Reveals different payment linkage information across two invoice numbers', () => {
    const senderKeypair = generateKeypair()
    const recipientKeypair = generateKeypair()
    const params1 = {
      senderPrivateKey: senderKeypair.privateKey,
      recipientPublicKey: recipientKeypair.publicKey,
      invoiceNumber: randomBytesBase64(8)
    }
    const params2 = {
      ...params1,
      invoiceNumber: randomBytesBase64(8)
    }
    const firstResult = getPaymentAddress({
      ...params1,
      revealPaymentLinkage: true
    })
    const secondResult = getPaymentAddress({
      ...params2,
      revealPaymentLinkage: true
    })
    expect(firstResult).not.toEqual(secondResult)
    const r1 = computePaymentContext(params1)
    const r2 = computePaymentContext(params2)
    expect(asString(r1.hmac)).toBe(firstResult)
    expect(asString(r2.hmac)).toBe(secondResult)
    expect(asString(r1.hmac)).not.toEqual(asString(r2.hmac))
  })
  testVectors.forEach((vector, index) => {
    it(`Passes test vector #${index + 1}`, () => {
      const params = {
        senderPrivateKey: vector.senderPrivateKey,
        recipientPublicKey: vector.recipientPublicKey,
        invoiceNumber: vector.invoiceNumber
      }
      const rJs = getPaymentAddress(params)
      expect(rJs).toEqual(vector.address)
      const rTs = getPaymentAddressString(params)
      expect(rTs).toEqual(vector.address)
    })
  })
})
