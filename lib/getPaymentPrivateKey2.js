"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPaymentPrivateKey = void 0;
const core_1 = require("@ts-bitcoin/core");
const N = core_1.Point.getN();
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
function getPaymentPrivateKey(opts) {
    // First, a shared secret is calculated based on the public and private keys.
    let publicKey, privateKey;
    if (typeof opts.senderPublicKey === 'string') {
        publicKey = core_1.PubKey.fromString(opts.senderPublicKey);
    }
    else if (opts.senderPublicKey instanceof core_1.PubKey) {
        publicKey = opts.senderPublicKey;
    }
    else {
        throw new Error('Unrecognized format for senderPublicKey');
    }
    if (typeof opts.recipientPrivateKey === 'string') {
        privateKey = new core_1.Bn().fromHex(opts.recipientPrivateKey);
    }
    else if (opts.recipientPrivateKey instanceof core_1.Bn) {
        privateKey = opts.recipientPrivateKey;
    }
    else if (opts.recipientPrivateKey instanceof core_1.PrivKey) {
        privateKey = opts.recipientPrivateKey.bn;
    }
    else {
        throw new Error('Unrecognized format for recipientPrivateKey');
    }
    const sharedSecret = new core_1.PubKey(publicKey.point.mul(privateKey)).toDer(true);
    // The invoice number is turned into a buffer.
    let invoiceNumber = Buffer.from(String(opts.invoiceNumber), 'utf8');
    // An HMAC is calculated with the shared secret and the invoice number.
    const hmac = core_1.Hash.sha256Hmac(sharedSecret, invoiceNumber);
    // Finally, the hmac is added to the private key, and the result is modulo N.
    const finalPrivateKey = privateKey.add(core_1.Bn.fromBuffer(hmac)).mod(N);
    switch (opts.returnType) {
        case undefined:
        case 'wif':
            return new core_1.PrivKey(finalPrivateKey).toWif();
        case 'hex':
            return finalPrivateKey.toHex({ size: 32 });
        case 'buffer':
            return finalPrivateKey.toBuffer({ size: 32 });
        case 'bsv':
            return finalPrivateKey;
        default:
            throw new Error('The return type must either be "wif" or "hex"');
    }
}
exports.getPaymentPrivateKey = getPaymentPrivateKey;
