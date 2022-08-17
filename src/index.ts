import  { generateKeypair } from "./generateKeypair2"
import  { getPaymentAddress } from "./getPaymentAddress2"
import  { getPaymentPrivateKey } from "./getPaymentPrivateKey2"

//const generateKeypair = require('./generateKeypair')
//const getPaymentAddress = require('./getPaymentAddress')
//const getPaymentPrivateKey = require('./getPaymentPrivateKey')

export default {
  generateKeypair: generateKeypair,
  getPaymentAddress,
  getPaymentPrivateKey
}
