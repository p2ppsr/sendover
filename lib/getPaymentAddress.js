"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bsv_1 = __importDefault(require("bsv"));
const BN = bsv_1.default.crypto.BN;
const Hash = bsv_1.default.crypto.Hash;
const G = bsv_1.default.crypto.Point.getG();
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
module.exports = ({ senderPrivateKey, recipientPublicKey, invoiceNumber, returnType = 'address' }) => {
    // First, a shared secret is calculated based on the public and private keys.
    let publicKey, privateKey;
    if (typeof recipientPublicKey === 'string') {
        publicKey = bsv_1.default.PublicKey.fromString(recipientPublicKey);
    }
    else if (recipientPublicKey instanceof bsv_1.default.PublicKey) {
        publicKey = recipientPublicKey;
    }
    else {
        throw new Error('Unrecognized format for recipientPublicKey');
    }
    if (typeof senderPrivateKey === 'string') {
        privateKey = BN.fromHex(senderPrivateKey);
    }
    else if (senderPrivateKey instanceof BN) {
        privateKey = senderPrivateKey;
    }
    else if (senderPrivateKey instanceof bsv_1.default.PrivateKey) {
        privateKey = senderPrivateKey.bn;
    }
    else {
        throw new Error('Unrecognized format for senderPrivateKey');
    }
    const sharedSecret = publicKey.point.mul(privateKey).toBuffer();
    // The invoice number is turned into a buffer.
    invoiceNumber = Buffer.from(String(invoiceNumber), 'utf8');
    // An HMAC is calculated with the shared secret and the invoice number.
    const hmac = Hash.sha256hmac(sharedSecret, invoiceNumber);
    // The HMAC is multiplied by the generator point.
    const point = G.mul(BN.fromBuffer(hmac));
    // The resulting point is added to the recipient public key.
    const finalPublicKey = bsv_1.default.PublicKey.fromPoint(publicKey.point.add(point));
    // Finally, an address is calculated with the new public key.
    if (returnType === 'address') {
        return bsv_1.default.Address.fromPublicKey(finalPublicKey).toString();
    }
    else if (returnType === 'publicKey') {
        return finalPublicKey.toString();
    }
    else if (returnType === 'bsv') {
        return finalPublicKey;
    }
    else {
        throw new Error('The return type must either be "address" or "publicKey"');
    }
};
