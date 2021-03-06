# sendover

Tools for creating and paying invoices privately on Bitcoin SV

The code is hosted [on GitHub](https://github.com/p2ppsr/sendover) and the package is available [through NPM](https://www.npmjs.com/package/sendover).

## Installation

    npm i sendover

## Example Usage

```js
const sendover = require('sendover')

// The merchant generates a keypair.
// They put the public key on their website, and keep the private key secret.
const merchantKeypair = sendover.generateKeypair()

// The customer also generates a keypair.
const customerKeypair = sendover.generateKeypair()

// The customer and the merchant agree on an invoice number.
// The customer knows the invoice number.
const purchaseInvoiceNumber = '341-9945319'

// The customer can now generate a Bitcoin addres for the payment.
// After generating the address, the customer sends the payment.
const paymentAddress = sendover.getPaymentAddress({
  senderPrivateKey: customerKeypair.privateKey,
  recipientPublicKey: merchantKeypair.publicKey,
  invoiceNumber: purchaseInvoiceNumber
})

// After making the payment, the customer sends a few things to the merchant.
// - The Bitcoin transaction that contains the payment
// - The invoice number they have agreed upon
// - The customer's public key
// - Any SPV proofs needed for the merchant to validate and accept the transaction
const dataSentToMerchant = {
  customerPublicKey: customerKeypair.publicKey,
  paymentTransaction: '...', // transaction that pays money to the address
  invoiceNumber: purchaseInvoiceNumber,
  transactionSPVProofs: ['...'] // Any needed SPV proofs
}

// The merchant can now calculate the private key that unlocks the money.
const privateKey = sendover.getPaymentPrivateKey({
  senderPublicKey: dataSentToMerchant.customerPublicKey,
  recipientPrivateKey: merchantKeypair.privateKey,
  invoiceNumber: dataSentToMerchant.invoiceNumber
})
```

## API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

#### Table of Contents

*   [generateKeypair](#generatekeypair)
    *   [Parameters](#parameters)
*   [getPaymentAddress](#getpaymentaddress)
    *   [Parameters](#parameters-1)
*   [getPaymentPrivateKey](#getpaymentprivatekey)
    *   [Parameters](#parameters-2)

### generateKeypair

Generates a public/private keypair for the sending and receiving of invoices.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parameters are given in an object (optional, default `{}`)

    *   `obj.returnType` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Return type, either "hex" or "bsv" (optional, default `'hex'`)

Returns **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** The generated keypair, with `privateKey` and `publicKey` properties.

### getPaymentAddress

Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parametera ere provided in an object

    *   `obj.senderPrivateKey` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The private key of the sender in WIF format
    *   `obj.recipientPublicKey` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The public key of the recipient in hexadecimal DER format
    *   `obj.invoiceNumber` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The invoice number to use
    *   `obj.returnType` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The destination key return type, either `address` or `publicKey` (optional, default `address`)

Returns **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The destination address or public key

### getPaymentPrivateKey

Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.

#### Parameters

*   `obj` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** All parametera ere provided in an object

    *   `obj.recipientPrivateKey` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The private key of the recipient in WIF format
    *   `obj.senderPublicKey` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The public key of the sender in hexadecimal DER format
    *   `obj.invoiceNumber` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The invoice number that was used
    *   `obj.returnType` **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** The incoming payment key return type, `wif`, `hex`, `buffer`, or `bsv` (optional, default `wif`) - Note: specifying a return type of `bsv` will require you to use an argument of `{ size: 32 }` when calling `.toHex()` or `.toBuffer()` on the BN object.

Returns **[String](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** | **[Buffer](https://nodejs.org/api/buffer.html)** | **[BN](https://github.com/moneybutton/bsv/blob/bsv-legacy/lib/crypto/bn.js)** The incoming payment key that can unlock the money.

## Credits

Credit is given to the people who have worked on making these ideas into reality. In particular, we thank Xiaohui Liu for creating the [first known implementation](https://gist.github.com/xhliu/9e267e23dd7c799039befda3ae6fa244) of private addresses using this scheme, and Dr. Craig Wright for first [describing it](https://craigwright.net/blog/bitcoin-blockchain-tech/offline-addressing).

## License

The license for the code in this repository is the Open BSV License.
