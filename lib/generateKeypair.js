"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const babbage_bsv_1 = __importDefault(require("babbage-bsv"));
/**
 * Generates a public/private keypair for the sending and receiving of invoices.
 *
 * @param {Object} obj All parameters are given in an object
 * @param {String} [obj.returnType='hex'] Return type, either "hex" or "bsv"
 *
 * @returns {Object} The generated keypair, with `privateKey` and `publicKey` properties.
 */
module.exports = ({ returnType = 'hex' } = {}) => {
    const privateKey = babbage_bsv_1.default.PrivateKey.fromRandom();
    if (returnType === 'babbage-bsv') {
        return {
            privateKey,
            publicKey: privateKey.publicKey
        };
    }
    else {
        return {
            privateKey: privateKey.bn.toHex({ size: 32 }),
            publicKey: privateKey.publicKey.toString()
        };
    }
};
