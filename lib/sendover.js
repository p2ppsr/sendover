"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPaymentAddress = exports.generateKeypair = void 0;
const core_1 = __importDefault(require("@ts-bitcoin/core"));
const BN = core_1.default.Bn;
const Hash = core_1.default.Hash;
const G = core_1.default.Point.getG();
function generateKeypair(opts = { returnType: "hex" }) {
    const privateKey = core_1.default.PrivKey.fromRandom();
    const publicKey = core_1.default.PubKey.fromPrivKey(privateKey);
    if (opts.returnType === 'bsv') {
        return {
            privateKey,
            publicKey
        };
    }
    else {
        return {
            privateKey: privateKey.bn.toHex({ size: 32 }),
            publicKey: publicKey.toString()
        };
    }
}
exports.generateKeypair = generateKeypair;
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
function getPaymentAddress({ senderPrivateKey, recipientPublicKey, invoiceNumber, returnType = 'address' }) {
    // First, a shared secret is calculated based on the public and private keys.
    let publicKey, privateKey;
    if (typeof recipientPublicKey === 'string') {
        publicKey = core_1.default.PubKey.fromString(recipientPublicKey);
    }
    else if (recipientPublicKey instanceof core_1.default.PubKey) {
        publicKey = recipientPublicKey;
    }
    else {
        throw new Error('Unrecognized format for recipientPublicKey');
    }
    if (typeof senderPrivateKey === 'string') {
        privateKey = new BN().fromHex(senderPrivateKey);
    }
    else if (senderPrivateKey instanceof BN) {
        privateKey = senderPrivateKey;
    }
    else if (senderPrivateKey instanceof core_1.default.PrivKey) {
        privateKey = senderPrivateKey.bn;
    }
    else {
        throw new Error('Unrecognized format for senderPrivateKey');
    }
    const sharedSecret = new core_1.default.PubKey(publicKey.point.mul(privateKey)).toDer(true);
    // The invoice number is turned into a buffer.
    invoiceNumber = Buffer.from(String(invoiceNumber), 'utf8');
    // An HMAC is calculated with the shared secret and the invoice number.
    const hmac = Hash.sha256Hmac(sharedSecret, invoiceNumber);
    // The HMAC is multiplied by the generator point.
    const point = G.mul(BN.fromBuffer(hmac));
    // The resulting point is added to the recipient public key.
    const finalPublicKey = new core_1.default.PubKey(publicKey.point.add(point));
    // Finally, an address is calculated with the new public key.
    if (returnType === 'address') {
        return core_1.default.Address.fromPubKey(finalPublicKey).toString();
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
}
exports.getPaymentAddress = getPaymentAddress;
