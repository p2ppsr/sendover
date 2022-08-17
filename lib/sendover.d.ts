import bsv from '@ts-bitcoin/core';
export declare function generateKeypair(opts?: {
    returnType: "hex" | "bsv";
}): {
    privateKey: bsv.PrivKey | string;
    publicKey: bsv.PubKey | string;
};
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
export declare function getPaymentAddress({ senderPrivateKey, recipientPublicKey, invoiceNumber, returnType }: any): string | bsv.PubKey;
