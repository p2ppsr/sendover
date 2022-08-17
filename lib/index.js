"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const generateKeypair2_1 = require("./generateKeypair2");
const getPaymentAddress2_1 = require("./getPaymentAddress2");
const getPaymentPrivateKey2_1 = require("./getPaymentPrivateKey2");
//const generateKeypair = require('./generateKeypair')
//const getPaymentAddress = require('./getPaymentAddress')
//const getPaymentPrivateKey = require('./getPaymentPrivateKey')
exports.default = {
    generateKeypair: generateKeypair2_1.generateKeypair,
    getPaymentAddress: getPaymentAddress2_1.getPaymentAddress,
    getPaymentPrivateKey: getPaymentPrivateKey2_1.getPaymentPrivateKey
};
