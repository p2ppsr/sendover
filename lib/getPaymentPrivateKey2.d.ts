/// <reference types="node" />
import { PrivKey, PubKey, Bn as BN } from '@ts-bitcoin/core';
/**
 * Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.
 *
 * @param {Object} obj All parametera ere provided in an object
 * @param {String} obj.recipientPrivateKey The private key of the recipient in WIF format
 * @param {String} obj.senderPublicKey The public key of the sender in hexadecimal DER format
 * @param {String} obj.invoiceNumber The invoice number that was used
 * @param {String} [obj.returnType=wif] The incoming payment key return type, either `wif` or `hex`
 *
 * @returns {String} The incoming payment key that can unlock the money.
 */
export declare function getPaymentPrivateKey(opts: {
    recipientPrivateKey: string | BN | PrivKey;
    senderPublicKey: string | PubKey;
    invoiceNumber: any;
    returnType: 'wif' | 'hex' | 'buffer' | 'bsv' | undefined;
}): String | Buffer | BN;
