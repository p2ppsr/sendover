import { getPaymentPrivateKey, getPaymentAddress, normalizeProtocol, getProtocolInvoiceNumber } from '.'
import bsv from 'babbage-bsv'

/**
 * Input params to the `deriveKey` function.
 *
 * This function derives the child key given the root key.
 *
 * The flags:
 *
 *   rootKey, identityKey, publicKey, and sharedSymmetricKey flags
 *
 * can be combined with:
 *
 *    counterparty, protocolID and keyID
 *
 * to derive the required key.
 */
export interface SendOverDeriveKeyParams {
  /*
   * The root key for derivation
   */
  key: Uint8Array
  /*
   * The counterparty to use for derivation. Can be "self", "anyone", or the public key of a counterparty.
   *
   * public key must be a babbage-bsv PublicKey object.
   *
   * Only the counterparty can derive the corresponding private keys for asymmetric operations,
   * or the corresponding shared symmetric key in symmetric operations.
   */
  counterparty: string | 'self' | 'anyone' | bsv.PublicKey
  /*
   * The protocol under which this key is used.
   */
  protocolID: string | [number, string]
  /*
   * The specific key to derive under this protocol.
   */
  keyID: string
  /*
   * Optional, defaults to '1'. The identity under which key derivation should occur (default 1)
   */
  derivationIdentity: string
  /*
   * Optional, defaults to false. Whether the root key should be returned
   */
  rootKey?: boolean
  /*
   * Optional, defaults to false. Whether the identity key should be returned, only works if rootKey = false
   */
  identityKey?: boolean
  /*
   * Optional, defaults to false. Whether a public key should be derived
   */
  publicKey?: boolean
  /*
   * Optional, defaults to false. Whether the derived key corresponds to a private key held by the current user.
   */
  forSelf?: boolean
  /*
   * Optional, defaults to false. Whether a shared symmetric key should be returned. Cannot be used when publicKey = true
   */
  sharedSymmetricKey?: boolean
  /*
   * Whether to derive from the root key, rather than the provided identity (default true)
   */
  deriveFromRoot?: boolean
  /**
   *
   */
  revealCounterpartyLinkage?: boolean
  /**
   * Optional, defaults to false.
   */
  revealPaymentLinkage?: boolean
}

/**
 * This function derives the child key given the root key.
 *
 * The rootKey, identityKey, publicKey, and sharedSymmetricKey flags can be combined with
 * counterparty, protocolID and keyID to derive the needed keys.
 *
 * @return Hex string of key to return
 */
export function deriveKey(params: SendOverDeriveKeyParams): string {
  let counterparty = params.counterparty
  const {
    key,
    protocolID,
    keyID,
    derivationIdentity = '1',
    rootKey = false,
    identityKey = false,
    publicKey = false,
    forSelf = false,
    sharedSymmetricKey = false,
    deriveFromRoot = true,
    revealCounterpartyLinkage = false,
    revealPaymentLinkage = false
  } = params

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
    if (revealCounterpartyLinkage) {
      throw new Error('Counterparty secrets cannot be revealed for counterparty=self as specified by BRC-69')
    }
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

  // If the counterparty secret is requested, it's worth making absolutely certain this is not counterparty=self, even if passed in manually
  // This process ensures that whatever formats the keys are in, if the derivations produce the same child keys, the counterparty secret is not evealed
  if (revealCounterpartyLinkage) {
    const self = bsv.PrivateKey.fromBuffer(identity.toBuffer({ size: 32 })).publicKey
    const keyDerivedBySelf = getPaymentPrivateKey({
      recipientPrivateKey: identity,
      senderPublicKey: self,
      invoiceNumber: 'test',
      returnType: 'hex'
    })
    const keyDerivedByCounterparty = getPaymentPrivateKey({
      recipientPrivateKey: identity,
      senderPublicKey: counterparty,
      invoiceNumber: 'test',
      returnType: 'hex'
    })
    if (keyDerivedBySelf === keyDerivedByCounterparty) {
      throw new Error('Counterparty secrets cannot be revealed for counterparty=self as specified by BRC-69')
    }
  }

  const normalizedProtocolID = normalizeProtocol(protocolID)
  const invoiceNumber = getProtocolInvoiceNumber({ protocolID: normalizedProtocolID, keyID })

  let derivedPublicKey
  if (sharedSymmetricKey || publicKey) {
    if (forSelf) {
      const ourPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: identity,
        senderPublicKey: counterparty,
        invoiceNumber,
        returnType: 'babbage-bsv',
        revealCounterpartyLinkage,
        revealPaymentLinkage
      })
      if (revealCounterpartyLinkage || revealPaymentLinkage) {
        return ourPrivateKey
      }
      return bsv.PrivateKey.fromBuffer(ourPrivateKey.toBuffer({ size: 32 })).publicKey.toString()
    } else {
      derivedPublicKey = getPaymentAddress({
        senderPrivateKey: identity,
        recipientPublicKey: counterparty,
        invoiceNumber,
        returnType: 'babbage-bsv',
        revealCounterpartyLinkage,
        revealPaymentLinkage
      })
      if (revealCounterpartyLinkage || revealPaymentLinkage) {
        return derivedPublicKey
      }
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
    returnType: 'babbage-bsv',
    revealCounterpartyLinkage,
    revealPaymentLinkage
  })
  if (revealCounterpartyLinkage || revealPaymentLinkage) {
    return derivedPrivateKey
  }
  if (!sharedSymmetricKey) {
    return derivedPrivateKey.toHex({ size: 32 })
  }
  const sharedSecret = derivedPublicKey.point.mul(
    derivedPrivateKey
  ).toBuffer().slice(1)
  return sharedSecret.toString('hex')
}
