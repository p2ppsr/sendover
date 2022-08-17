import { PrivKey, PubKey, Bn as BN } from '@ts-bitcoin/core';
/**
 * Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.
 *
 * @param {Object} obj All parameters are provided in an object
 * @param {String} obj.senderPrivateKey The private key of the sender in WIF format
 * @param {String} obj.recipientPublicKey The public key of the recipient in hexadecimal DER format
 * @param {String} obj.invoiceNumber The invoice number to use
 * @param {String} [obj.returnType=address] The destination key return type, either `address` or `publicKey`
 *
 * @returns {String} The destination address or public key
 */
export declare function getPaymentAddress(opts: {
    senderPrivateKey: string | BN | PrivKey;
    recipientPublicKey: string | PubKey;
    invoiceNumber: any;
    returnType: 'address' | 'publicKey' | 'bsv' | undefined;
}): string | PubKey;
