import { deriveKey } from '../out/src/deriveKey'
import { getPaymentAddress } from '../out/src/getPaymentAddress'
import { getPaymentPrivateKey } from '../out/src/getPaymentPrivateKey'
import bsvJs from 'babbage-bsv'
import { getProtocolInvoiceNumber } from 'cwi-base'

// A value for the key on which derivation is to be performed
const key = Uint8Array.from([
  219, 3, 2, 54, 111, 133, 169, 46,
  104, 185, 102, 75, 252, 62, 30, 240,
  131, 248, 10, 62, 102, 44, 184, 35,
  207, 194, 4, 109, 153, 59, 23, 18
])

// A value for the counterparty's key
const counterpartyPriv = '1e8226e9f542196333aa2c5da061a8f1c3e189f60493930d26be4b1d1704c27f'
const counterparty = bsvJs.PrivateKey.fromHex(counterpartyPriv)
  .publicKey.toString()
// Anyone can know this key
const anyone = '0000000000000000000000000000000000000000000000000000000000000001'
let params

describe('deriveKey', () => {
  beforeEach(() => {
    params = {
      key,
      counterparty: 'self',
      protocolID: 'Hello World',
      keyID: '1',
      deriveFromRoot: false
    }
  })
  it('Returns the correct root private key', () => {
    const returnValue = deriveKey({ ...params, rootKey: true })
    expect(returnValue).toEqual(Buffer.from(key).toString('hex'))
  })
  it('Returns the correct root public key', () => {
    const returnValue = deriveKey({ ...params, rootKey: true, publicKey: true })
    expect(returnValue).toEqual(
      bsvJs.PrivateKey.fromHex(Buffer.from(key).toString('hex'))
        .publicKey.toString()
    )
  })
  it('Returns the correct identity private key deriving from root', () => {
    const returnValue = deriveKey({
      ...params,
      identityKey: true,
      deriveFromRoot: true
    })
    expect(returnValue).toEqual(Buffer.from(key).toString('hex'))
  })
  it('Returns the correct identity public key deriving from root', () => {
    const returnValue = deriveKey({
      ...params,
      identityKey: true,
      publicKey: true,
      deriveFromRoot: true
    })
    expect(returnValue).toEqual(
      bsvJs.PrivateKey.fromHex(Buffer.from(key).toString('hex'))
        .publicKey.toString()
    )
  })
  it('Returns the correct identity private key', () => {
    const returnValue = deriveKey({
      ...params,
      identityKey: true,
      deriveFromRoot: false
    })
    const identity = getPaymentPrivateKey({
      recipientPrivateKey: Buffer.from(key).toString('hex'),
      senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
        .publicKey.toString(),
      invoiceNumber: '1',
      returnType: 'hex'
    })
    expect(returnValue).toEqual(identity)
  })
  it('Returns the correct identity public key', () => {
    const returnValue = deriveKey({
      ...params,
      identityKey: true,
      publicKey: true,
      deriveFromRoot: false
    })
    const identity = getPaymentPrivateKey({
      recipientPrivateKey: Buffer.from(key).toString('hex'),
      senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
        .publicKey.toString(),
      invoiceNumber: '1',
      returnType: 'hex'
    })
    expect(returnValue).toEqual(
      bsvJs.PrivateKey.fromHex(identity)
        .publicKey.toString()
    )
  })
  it('Throws Error if counterparty is not specified', () => {
    expect(() => {
      deriveKey({ ...params, counterparty: undefined })
    }).toThrow(new Error(
      'counterparty must be self, anyone or a public key!'
    ))
  })
  it('Throws Error if public key is requested for a symmetric key', () => {
    expect(() => {
      deriveKey({ ...params, publicKey: true, sharedSymmetricKey: true })
    }).toThrow(new Error(
      'Cannot return a public key for a symmetric key!'
    ))
  })
  it('Throws Error if counterparty = anyone for a symmetric key', () => {
    expect(() => {
      deriveKey({ ...params, counterparty: 'anyone', sharedSymmetricKey: true })
    }).toThrow(new Error(
      'Symmetric keys (such as encryption keys or HMAC keys) should not be derivable by everyone, because messages would be decryptable by anyone who knows the identity public key of the user, and HMACs would be similarly forgeable.'
    ))
  })
  describe('When counterparty = self', () => {
    beforeEach(() => {
      params = { ...params, counterparty: 'self' }
    })
    it('Returns a properly-derived asymmetric public key', () => {
      const returnValue = deriveKey({
        ...params,
        publicKey: true,
        deriveFromRoot: false
      })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive the private key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: identity,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber,
        returnType: 'hex'
      })
      // The public key from the key derived by the counterparty should be identical to the one that was returned by our derivation.
      expect(returnValue).toEqual(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(correspondingPrivateKey).publicKey.point
      ).toString())
    })
    it('Returns a properly-derived asymmetric private key', () => {
      const returnValue = deriveKey(params)
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber,
        returnType: 'publicKey'
      })
      // The public key derived by the counterparty should be identical to the one from the private key that was returned by our derivation.
      expect(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(returnValue).publicKey.point
      ).toString()).toEqual(correspondingPublicKey)
    })
    it('Returns a properly-derived shared symmetric key', () => {
      const returnValue = deriveKey({ ...params, sharedSymmetricKey: true })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber,
        returnType: 'publicKey'
      })
      // Derive the private key from the point-of-view of the counterparty
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: identity,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber,
        returnType: 'hex'
      })
      const sharedSecret = bsvJs.PublicKey.fromString(correspondingPublicKey).point.mul(
        bsvJs.crypto.BN.fromHex(correspondingPrivateKey, { size: 32 })
      ).toBuffer().slice(1).toString('hex')
      // The symmetric shared secret calculated by the counterparty should be identical to the one that was returned.
      expect(returnValue).toEqual(sharedSecret)
    })
    it('Throws Error if counterparty secret revelation requested', () => {
      expect(() => {
        deriveKey({ ...params, revealCounterpartyLinkage: true })
      }).toThrow(new Error(
        'Counterparty secrets cannot be revealed for counterparty=self as specified by BRC-69'
      ))
    })
    it('Throws Error if counterparty secret revelation requested, even if self public key is provided manually', () => {
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      const identityPublicKey = bsvJs.PrivateKey.fromHex(identity)
        .publicKey.toString()
      expect(() => {
        deriveKey({
          ...params,
          counterparty: identityPublicKey,
          revealCounterpartyLinkage: true
        })
      }).toThrow(new Error(
        'Counterparty secrets cannot be revealed for counterparty=self as specified by BRC-69'
      ))
    })
    it('Reveals BRC-69 linkage for a specific key', () => {
      const returnValue = deriveKey({
        ...params,
        revealPaymentLinkage: true
      })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const linkage = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber,
        revealPaymentLinkage: true
      })
      // The linkage should match that derived
      expect(returnValue).toEqual(linkage)
    })
  })
  describe('When counterparty = anyone', () => {
    beforeEach(() => {
      params = { ...params, counterparty: 'anyone' }
    })
    it('Returns a properly-derived asymmetric public key', () => {
      const returnValue = deriveKey({
        ...params,
        publicKey: true,
        deriveFromRoot: false
      })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive the private key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: anyone,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber,
        returnType: 'hex'
      })
      // The public key from the key derived by the counterparty should be identical to the one that was returned by our derivation.
      expect(returnValue).toEqual(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(correspondingPrivateKey).publicKey.point
      ).toString())
    })
    it('Returns a properly-derived asymmetric private key', () => {
      const returnValue = deriveKey(params)
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: anyone,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber,
        returnType: 'publicKey'
      })
      // The public key derived by the counterparty should be identical to the one from the private key that was returned by our derivation.
      expect(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(returnValue).publicKey.point
      ).toString()).toEqual(correspondingPublicKey)
    })
  })
  describe('When counterparty = a foreign public key', () => {
    beforeEach(() => {
      params = { ...params, counterparty }
    })
    it('Returns a properly-derived asymmetric public key', () => {
      const returnValue = deriveKey({
        ...params,
        publicKey: true,
        deriveFromRoot: false
      })
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: [2, 'hello world'], keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive the private key from the point-of-view of the counterparty
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: counterpartyPriv,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'hex'
      })
      // The public key from the key derived by the counterparty should be identical to the one that was returned by our derivation.
      expect(returnValue).toEqual(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(correspondingPrivateKey).publicKey.point
      ).toString())
    })
    it('Returns a properly-derived asymmetric public key of our own', () => {
      const returnValue = deriveKey({
        ...params,
        publicKey: true,
        forSelf: true,
        deriveFromRoot: false
      })
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: [2, 'hello world'], keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: counterpartyPriv,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'publicKey'
      })
      // The public key that the counterparty derived should be identical to the one that was returned by our derivation.
      expect(returnValue).toEqual(correspondingPublicKey)
    })
    it('Returns a properly-derived asymmetric private key', () => {
      const returnValue = deriveKey(params)
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: [2, 'hello world'], keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: counterpartyPriv,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber, // : 'hello world-1',
        returnType: 'publicKey'
      })
      // The public key derived by the counterparty should be identical to the one from the private key that was returned by our derivation.
      expect(bsvJs.PublicKey.fromPoint(
        bsvJs.PrivateKey.fromHex(returnValue).publicKey.point
      ).toString()).toEqual(correspondingPublicKey)
    })
    it('Returns a properly-derived shared symmetric key', () => {
      const returnValue = deriveKey({ ...params, sharedSymmetricKey: true })
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: [2, 'hello world'], keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: counterpartyPriv,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'publicKey'
      })
      // Derive the private key from the point-of-view of the counterparty
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: counterpartyPriv,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'hex'
      })
      const sharedSecret = bsvJs.PublicKey.fromString(correspondingPublicKey).point.mul(
        bsvJs.crypto.BN.fromHex(correspondingPrivateKey, { size: 32 })
      ).toBuffer().slice(1).toString('hex')
      // The symmetric shared secret calculated by the counterparty should be identical to the one that was returned.
      expect(returnValue).toEqual(sharedSecret)
    })
    it('Returns a properly-derived shared symmetric key for a custom identity', () => {
      const returnValue = deriveKey({ ...params, sharedSymmetricKey: true, derivationIdentity: 'custom' })
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: [2, 'hello world'], keyID: 1 })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: 'custom',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const correspondingPublicKey = getPaymentAddress({
        senderPrivateKey: counterpartyPriv,
        recipientPublicKey: bsvJs.PrivateKey.fromHex(identity)
          .publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'publicKey'
      })
      // Derive the private key from the point-of-view of the counterparty
      const correspondingPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: counterpartyPriv,
        senderPublicKey: bsvJs.PrivateKey.fromHex(identity).publicKey.toString(),
        invoiceNumber, // 'hello world-1',
        returnType: 'hex'
      })
      const sharedSecret = bsvJs.PublicKey.fromString(correspondingPublicKey).point.mul(
        bsvJs.crypto.BN.fromHex(correspondingPrivateKey, { size: 32 })
      ).toBuffer().slice(1).toString('hex')
      // The symmetric shared secret calculated by the counterparty should be identical to the one that was returned.
      expect(returnValue).toEqual(sharedSecret)
    })
    it('Reveals BRC-69 linkage for the counterparty', () => {
      const returnValue = deriveKey({
        ...params,
        revealCounterpartyLinkage: true
      })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const linkage = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: counterparty,
        invoiceNumber,
        revealCounterpartyLinkage: true
      })
      // The linkage should match that derived
      expect(returnValue).toEqual(linkage)
    })
    it('Reveals BRC-69 linkage for the specific key', () => {
      const returnValue = deriveKey({
        ...params,
        revealPaymentLinkage: true
      })
      const identity = getPaymentPrivateKey({
        recipientPrivateKey: Buffer.from(key).toString('hex'),
        senderPublicKey: bsvJs.PrivateKey.fromBuffer(Buffer.from(key))
          .publicKey.toString(),
        invoiceNumber: '1',
        returnType: 'hex'
      })
      // Derive our public key from the point-of-view of the counterparty
      const invoiceNumber = getProtocolInvoiceNumber({ protocolID: params.protocolID, keyID: params.keyID })
      const linkage = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: counterparty,
        invoiceNumber,
        revealPaymentLinkage: true
      })
      // The linkage should match that derived
      expect(returnValue).toEqual(linkage)
    })
  })
})
