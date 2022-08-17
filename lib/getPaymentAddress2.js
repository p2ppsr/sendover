"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPaymentAddress = void 0;
const core_1 = require("@ts-bitcoin/core");
const G = core_1.Point.getG();
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
function getPaymentAddress(opts) {
    // First, a shared secret is calculated based on the public and private keys.
    let publicKey, privateKey;
    if (typeof opts.recipientPublicKey === 'string') {
        publicKey = core_1.PubKey.fromString(opts.recipientPublicKey);
    }
    else if (opts.recipientPublicKey instanceof core_1.PubKey) {
        publicKey = opts.recipientPublicKey;
    }
    else {
        throw new Error('Unrecognized format for recipientPublicKey');
    }
    if (typeof opts.senderPrivateKey === 'string') {
        privateKey = new core_1.Bn().fromHex(opts.senderPrivateKey);
    }
    else if (opts.senderPrivateKey instanceof core_1.Bn) {
        privateKey = opts.senderPrivateKey;
    }
    else if (opts.senderPrivateKey instanceof core_1.PrivKey) {
        privateKey = opts.senderPrivateKey.bn;
    }
    else {
        throw new Error('Unrecognized format for senderPrivateKey');
    }
    const sharedSecret = new core_1.PubKey(publicKey.point.mul(privateKey)).toDer(true);
    // The invoice number is turned into a buffer.
    let invoiceNumber = Buffer.from(String(opts.invoiceNumber), 'utf8');
    // An HMAC is calculated with the shared secret and the invoice number.
    const hmac = core_1.Hash.sha256Hmac(sharedSecret, invoiceNumber);
    // The HMAC is multiplied by the generator point.
    const point = G.mul(core_1.Bn.fromBuffer(hmac));
    // The resulting point is added to the recipient public key.
    const finalPublicKey = new core_1.PubKey(publicKey.point.add(point));
    // Finally, an address is calculated with the new public key.
    switch (opts.returnType) {
        case undefined:
        case 'address':
            return core_1.Address.fromPubKey(finalPublicKey).toString();
        case 'publicKey':
            return finalPublicKey.toString();
        case 'bsv':
            return finalPublicKey;
        default:
            throw new Error('The return type must either be "address" or "publicKey"');
    }
}
exports.getPaymentAddress = getPaymentAddress;
