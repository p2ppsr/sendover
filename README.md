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
    counterparty: string | "self" | "anyone" | bsv.PublicKey;
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

<summary>Interface SendOverDeriveKeyParams Details</summary>

##### Property revealPaymentLinkage

Optional, defaults to false.

```ts
revealPaymentLinkage?: boolean
```

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
### Functions

| |
| --- |
| [asArray](#function-asarray) |
| [computePaymentContext](#function-computepaymentcontext) |
| [deriveKey](#function-derivekey) |
| [deriveKeyWithCache](#function-derivekeywithcache) |
| [generateKeypair](#function-generatekeypair) |
| [getPaymentAddress](#function-getpaymentaddress) |
| [getPaymentAddressString](#function-getpaymentaddressstring) |
| [getPaymentPrivateKey](#function-getpaymentprivatekey) |
| [getPaymentPubKey](#function-getpaymentpubkey) |
| [getPaymentPubKeyString](#function-getpaymentpubkeystring) |
| [getProtocolInvoiceNumber](#function-getprotocolinvoicenumber) |

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---

#### Function: generateKeypair

Generates a public/private keypair for the sending and receiving of invoices.

```ts
export function generateKeypair(params?: {
    returnType?: "hex" | "babbage-bsv";
}): {
    privateKey: string | bsv.PrivateKey;
    publicKey: string | bsv.PublicKey;
} 
```

<details>

<summary>Function generateKeypair Details</summary>

Returns

The generated keypair, with `privateKey` and `publicKey` properties.

Argument Details

+ **params**
  + All parameters are given in an object
+ **params.returnType**
  + ='hex' Return type, either "hex" or "babbage-bsv"

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentAddress

Returns a payment address for use by the sender, given the recipient's public key, the sender's private key and the invoice number.

```ts
export function getPaymentAddress(params: {
    senderPrivateKey: string | bsvJs.crypto.BN | bsvJs.PrivateKey;
    recipientPublicKey: string | bsvJs.PublicKey;
    invoiceNumber: string;
    revealCounterpartyLinkage?: boolean;
    revealPaymentLinkage?: boolean;
    returnType?: "address" | "publicKey" | "babbage-bsv";
}): string | bsvJs.PublicKey 
```

<details>

<summary>Function getPaymentAddress Details</summary>

Returns

The destination address or public key

Argument Details

+ **params**
  + All parameters are provided in an object
+ **params.senderPrivateKey**
  + The private key of the sender in WIF format
+ **params.recipientPublicKey**
  + The public key of the recipient in hexadecimal DER format
+ **params.invoiceNumber**
  + The invoice number to use
+ **params.revealCounterpartyLinkage**
  + =false When true, reveals the root shared secret between the two counterparties rather than performing key derivation, returning it as a hex string
+ **params.revealPaymentLinkage**
  + =false When true, reveals the secret between the two counterparties used for this specific invoice number, rather than performing key derivation. Returns the linkage as a hex string
+ **params.returnType**
  + =address] The destination key return type, either `address` or `publicKey`

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: computePaymentContext

```ts
export function computePaymentContext(params: {
    senderPrivateKey: string | BigNumber | PrivateKey;
    recipientPublicKey: string | PublicKey;
    invoiceNumber: string;
}): {
    publicKey: PublicKey;
    sharedSecret: number[];
    hmac: number[];
} 
```

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentPubKey

```ts
export function getPaymentPubKey(params: {
    senderPrivateKey: string | BigNumber | PrivateKey;
    recipientPublicKey: string | PublicKey;
    invoiceNumber: string;
}): PublicKey 
```

<details>

<summary>Function getPaymentPubKey Details</summary>

Returns

The destination public key

Argument Details

+ **params**
  + All parameters are provided in an object
+ **params.senderPrivateKey**
  + The private key of the sender in WIF format
+ **params.recipientPublicKey**
  + The public key of the recipient in hexadecimal DER format
+ **params.invoiceNumber**
  + The invoice number to use

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentPubKeyString

```ts
export function getPaymentPubKeyString(params: {
    senderPrivateKey: string | BigNumber | PrivateKey;
    recipientPublicKey: string | PublicKey;
    invoiceNumber: string;
}): string 
```

<details>

<summary>Function getPaymentPubKeyString Details</summary>

Returns

The destination public key Base58 string

Argument Details

+ **params**
  + All parameters are provided in an object
+ **params.senderPrivateKey**
  + The private key of the sender in WIF format
+ **params.recipientPublicKey**
  + The public key of the recipient in hexadecimal DER format
+ **params.invoiceNumber**
  + The invoice number to use

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentAddressString

```ts
export function getPaymentAddressString(params: {
    senderPrivateKey: string | BigNumber | PrivateKey;
    recipientPublicKey: string | PublicKey;
    invoiceNumber: string;
}): string 
```

<details>

<summary>Function getPaymentAddressString Details</summary>

Returns

The destination address as Base58 string

Argument Details

+ **params**
  + All parameters are provided in an object
+ **params.senderPrivateKey**
  + The private key of the sender in WIF format
+ **params.recipientPublicKey**
  + The public key of the recipient in hexadecimal DER format
+ **params.invoiceNumber**
  + The invoice number to use

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getPaymentPrivateKey

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

<details>

<summary>Function getPaymentPrivateKey Details</summary>

Returns

The incoming payment key that can unlock the money.

Argument Details

+ **params**
  + All parametera ere provided in an object
+ **params.recipientPrivateKey**
  + The private key of the recipient in WIF format
+ **params.senderPublicKey**
  + The public key of the sender in hexadecimal DER format
+ **params.invoiceNumber**
  + The invoice number that was used
+ **params.revealCounterpartyLinkage**
  + =false When true, reveals the root shared secret between the two counterparties rather than performing key derivation, returning it as a hex string
+ **params.revealPaymentLinkage**
  + =false When true, reveals the secret between the two counterparties used for this specific invoice number, rather than performing key derivation. Returns the linkage as a hex string
+ **params.returnType**
  + =wif The incoming payment key return type, either `wif` or `hex`

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: deriveKey

This function derives the child key given the root key.

The rootKey, identityKey, publicKey, and sharedSymmetricKey flags can be combined with
counterparty, protocolID and keyID to derive the needed keys.

```ts
export function deriveKey(params: SendOverDeriveKeyParams): string 
```

<details>

<summary>Function deriveKey Details</summary>

Returns

Hex string of key to return

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: deriveKeyWithCache

Modified deriveKey function that utilizes a caching mechanism.
This function first checks if the result for the given parameters is already in the cache.
If so, it returns the cached result. Otherwise, it proceeds with the derivation and stores the result in the cache.

```ts
export function deriveKeyWithCache(params: SendOverDeriveKeyParams): string 
```

<details>

<summary>Function deriveKeyWithCache Details</summary>

Returns

Hex string of the derived key.

Argument Details

+ **params**
  + The input parameters for the key derivation.

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: getProtocolInvoiceNumber

```ts
export function getProtocolInvoiceNumber(params: {
    protocolID: string | [
        number,
        string
    ];
    keyID: number | string;
}): string 
```

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---
#### Function: asArray

Coerce a value to number[]

```ts
export function asArray(val: Buffer | string | number[], encoding?: BufferEncoding): number[] {
    let a: number[];
    if (Array.isArray(val))
        a = val;
    else if (Buffer.isBuffer(val))
        a = Array.from(val);
    else
        a = Array.from(Buffer.from(val, encoding || "hex"));
    return a;
}
```

<details>

<summary>Function asArray Details</summary>

Returns

input val if it is a number[]; if string converts to Buffer using encoding; uses Array.from to convert buffer to number[]

Argument Details

+ **val**
  + Buffer or string or number[]. If string, encoding param applies.
+ **encoding**
  + defaults to 'hex'

</details>

Links: [API](#api), [Interfaces](#interfaces), [Functions](#functions)

---

<!--#endregion ts2md-api-merged-here-->

## Credits

Credit is given to the people who have worked on making these ideas into reality. In particular, we thank Xiaohui Liu for creating the [first known implementation](https://gist.github.com/xhliu/9e267e23dd7c799039befda3ae6fa244) of private addresses using this scheme, and Dr. Craig Wright for first [describing it](https://craigwright.net/blog/bitcoin-blockchain-tech/offline-addressing).

## License

The license for the code in this repository is the Open BSV License.
