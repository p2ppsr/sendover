"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeypair = void 0;
const core_1 = require("@ts-bitcoin/core");
function generateKeypair(opts = { returnType: "hex" }) {
    const privateKey = core_1.PrivKey.fromRandom();
    const publicKey = core_1.PubKey.fromPrivKey(privateKey);
    switch (opts.returnType) {
        case undefined:
        case 'hex':
            return {
                privateKey: privateKey.bn.toHex({ size: 32 }),
                publicKey: publicKey.toString()
            };
        case 'bsv':
            return {
                privateKey,
                publicKey
            };
        default:
            throw new Error('The return type must either be "bsv" or "hex"');
    }
}
exports.generateKeypair = generateKeypair;
