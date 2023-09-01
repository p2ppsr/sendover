import { getPaymentPrivateKey, getPaymentAddress } from '.'
import { getProtocolInvoiceNumber, normalizeProtocol } from 'cwi-base'
import bsv from 'babbage-bsv'

/**
 * This function derives the child key given the root key. The rootKey,
 * identityKey, publicKey, and sharedSymmetricKey flags can be combined with
 * counterparty, protocolID and keyID to derive the needed keys.
 *
 * @param {Object} obj All parameters are given in an object
 * @param {Uint8Array} obj.key The root key for derivation
 * @param {Boolean} [obj.rootKey=false] Whether the root key should be returned
 * @param {Boolean} [obj.publicKey=false] Whether a public key should be derived
 * @param {Boolean} [obj.forSelf=false] Whether the derived key corresponds to
 * a private key held by the current user.
 * @param {Boolean} [obj.identityKey=false] Whether the identity key should be
 * returned, only works if rootKey = false
 * @param {Boolean} [obj.sharedSymmetricKey=false] Whether a shared symmetric key should be returned. Cannot be used when publicKey = true
 * @param {String} [obj.counterparty] The counterparty to use for derivation. Can be "self", "anyone", or the public key of a counterparty. Only the counterparty can derive the corresponding private keys for asymmetric operations, or the corresponding shared symmetric key in symmetric operations.
 * @param {String} [obj.protocolID] The protocol under which this key is used.
 * @param {String} [obj.keyID] The specific key to derive under this protocol.
 * @param {Boolean} [obj.deriveFromRoot] Whether to derive from the root key, rather than the provided identity (default true)
 * @param {String} [obj.derivationIdentity=1] The identity under which key derivation should occur (default 1)
 * @return {String} Hex string of key to return
 * @private
 */
export function deriveKey ({
  key,
  rootKey,
  identityKey,
  publicKey,
  forSelf = false,
  sharedSymmetricKey,
  counterparty,
  protocolID,
  keyID,
  deriveFromRoot = true,
  derivationIdentity = '1'
}) {
  if (rootKey) {
    if (publicKey) {
      return bsv.PrivateKey.fromBuffer(Buffer.from(key))
        .publicKey.toString()
    } else {
      return Buffer.from(key).toString('hex')
    }
  }
  const rootPrivate = bsv.PrivateKey.fromBuffer(Buffer.from(key))
  let identity
  if (deriveFromRoot) {
    identity = rootPrivate
  } else {
    identity = getPaymentPrivateKey({
      recipientPrivateKey: rootPrivate,
      senderPublicKey: rootPrivate.publicKey,
      invoiceNumber: derivationIdentity,
      returnType: 'babbage-bsv'
    })
  }
  if (identityKey) {
    if (publicKey) {
      return bsv.PrivateKey.fromBuffer(identity.toBuffer({ size: 32 })).publicKey.toString()
    } else {
      return identity.toHex({ size: 32 })
    }
  }

  if (!counterparty) {
    throw new Error('counterparty must be self, anyone or a public key!')
  } else if (counterparty === 'self') {
    counterparty = bsv.PrivateKey.fromBuffer(identity.toBuffer({ size: 32 })).publicKey
  } else if (counterparty === 'anyone') {
    if (sharedSymmetricKey) {
      throw new Error(
        'Symmetric keys (such as encryption keys or HMAC keys) should not be derivable by everyone, because messages would be decryptable by anyone who knows the identity public key of the user, and HMACs would be similarly forgeable.'
      )
    }
    counterparty = bsv.PrivateKey.fromHex(
      '0000000000000000000000000000000000000000000000000000000000000001'
    ).publicKey
  }

  protocolID = normalizeProtocol(protocolID)
  const invoiceNumber = getProtocolInvoiceNumber({ protocolID, keyID })

  let derivedPublicKey
  if (sharedSymmetricKey || publicKey) {
    if (forSelf) {
      const ourPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: identity,
        senderPublicKey: counterparty,
        invoiceNumber,
        returnType: 'babbage-bsv'
      })
      return bsv.PrivateKey.fromBuffer(ourPrivateKey.toBuffer({ size: 32 })).publicKey.toString()
    } else {
      derivedPublicKey = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: counterparty,
        invoiceNumber,
        returnType: 'babbage-bsv'
      })
    }
  }
  if (publicKey) {
    if (sharedSymmetricKey) {
      throw new Error('Cannot return a public key for a symmetric key!')
    }
    return derivedPublicKey.toString()
  }
  const derivedPrivateKey = getPaymentPrivateKey({
    recipientPrivateKey: identity,
    senderPublicKey: counterparty,
    invoiceNumber,
    returnType: 'babbage-bsv'
  })
  if (!sharedSymmetricKey) {
    return derivedPrivateKey.toHex({ size: 32 })
  }
  const sharedSecret = derivedPublicKey.point.mul(
    derivedPrivateKey
  ).toBuffer().slice(1)
  return sharedSecret.toString('hex')
}
