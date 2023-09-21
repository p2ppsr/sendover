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

<!--#region ts2md-api-merged-here-->
Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

### Interfaces

#### Interface: SendOverDeriveKeyParams

##### Description

Input params to the `deriveKey` function.

This function derives the child key given the root key.

The flags:

  rootKey, identityKey, publicKey, and sharedSymmetricKey flags

can be combined with:

   counterparty, protocolID and keyID

to derive the required key.

```ts
export interface SendOverDeriveKeyParams {
    key: Uint8Array;
    counterparty: "self" | "anyone" | bsv.PublicKey;
    protocolID: string | [
        number,
        string
    ];
    keyID: string;
    derivationIdentity: string;
    rootKey?: boolean;
    identityKey?: boolean;
    publicKey?: boolean;
    forSelf?: boolean;
    sharedSymmetricKey?: boolean;
    deriveFromRoot?: boolean;
    revealCounterpartyLinkage?: boolean;
    revealPaymentLinkage?: boolean;
}
```

<details>

<summary>Interface SendOverDeriveKeyParams Member Details</summary>

###### revealCounterpartyLinkage

###### revealPaymentLinkage

Optional, defaults to false.

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
### Functions

| |
| --- |
| [deriveKey](#function-derivekey) |
| [generateKeypair](#function-generatekeypair) |
| [getPaymentAddress](#function-getpaymentaddress) |
| [getPaymentPrivateKey](#function-getpaymentprivatekey) |

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---

#### Function: generateKeypair

##### Description

Generates a public/private keypair for the sending and receiving of invoices.

```ts
export function generateKeypair(params?: {
    returnType?: "hex" | "babbage-bsv";
}): {
    privateKey: string | bsv.PrivateKey;
    publicKey: string | bsv.PublicKey;
} 
```

##### Returns

The generated keypair, with `privateKey` and `publicKey` properties.

<details>

<summary>Function generateKeypair Argument Details</summary>

###### params

All parameters are given in an object###### params.returnType

='hex' Return type, either "hex" or "babbage-bsv"</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentAddress

##### Description

Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.

```ts
export function getPaymentAddress(params: {
    senderPrivateKey: string | bsv.crypto.BN | bsv.PrivateKey;
    recipientPublicKey: string | bsv.PublicKey;
    invoiceNumber: string;
    revealCounterpartyLinkage?: boolean;
    revealPaymentLinkage?: boolean;
    returnType?: "address" | "publicKey" | "babbage-bsv";
}): string | bsv.PublicKey 
```

##### Returns

The destination address or public key

<details>

<summary>Function getPaymentAddress Argument Details</summary>

###### params

All parameters are provided in an object###### params.senderPrivateKey

The private key of the sender in WIF format###### params.recipientPublicKey

The public key of the recipient in hexadecimal DER format###### params.invoiceNumber

The invoice number to use###### params.revealCounterpartyLinkage

=false When true, reveals the root shared secret between the two counterparties rather than performing key derivation, returning it as a hex string###### params.revealPaymentLinkage

=false When true, reveals the secret between the two counterparties used for this specific invoice number, rather than performing key derivation. Returns the linkage as a hex string###### params.returnType

=address] The destination key return type, either `address` or `publicKey`</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentPrivateKey

##### Description

Returns a private key for use by the recipient, given the sender's public key, the recipient's private key and the invoice number.

```ts
export function getPaymentPrivateKey(params: {
    recipientPrivateKey: string | bsv.crypto.BN | bsv.PrivateKey;
    senderPublicKey: string | bsv.PublicKey;
    invoiceNumber: string;
    revealCounterpartyLinkage?: boolean;
    revealPaymentLinkage?: boolean;
    returnType?: "wif" | "hex" | "buffer" | "babbage-bsv";
}): string | Buffer | bsv.PrivateKey 
```

##### Returns

The incoming payment key that can unlock the money.

<details>

<summary>Function getPaymentPrivateKey Argument Details</summary>

###### params

All parametera ere provided in an object###### params.recipientPrivateKey

The private key of the recipient in WIF format###### params.senderPublicKey

The public key of the sender in hexadecimal DER format###### params.invoiceNumber

The invoice number that was used###### params.revealCounterpartyLinkage

=false When true, reveals the root shared secret between the two counterparties rather than performing key derivation, returning it as a hex string###### params.revealPaymentLinkage

=false When true, reveals the secret between the two counterparties used for this specific invoice number, rather than performing key derivation. Returns the linkage as a hex string###### params.returnType

=wif The incoming payment key return type, either `wif` or `hex`</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: deriveKey

##### Description

This function derives the child key given the root key.

The rootKey, identityKey, publicKey, and sharedSymmetricKey flags can be combined with
counterparty, protocolID and keyID to derive the needed keys.

```ts
export function deriveKey(params: SendOverDeriveKeyParams): string 
```

##### Returns

Hex string of key to return

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---

<!--#endregion ts2md-api-merged-here-->

## Credits

Credit is given to the people who have worked on making these ideas into reality. In particular, we thank Xiaohui Liu for creating the [first known implementation](https://gist.github.com/xhliu/9e267e23dd7c799039befda3ae6fa244) of private addresses using this scheme, and Dr. Craig Wright for first [describing it](https://craigwright.net/blog/bitcoin-blockchain-tech/offline-addressing).

## License

The license for the code in this repository is the Open BSV License.
