/* eslint-env jest */
const sendover = require('../index')
const bsv = require('bsv')

describe('sendover', () => {
  it('Works as described in README.md', () => {
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

    // At the end, the merchant's private key should be the one that the customer sent the payment to.
    const merchantDerivedAddress = bsv.PrivateKey.fromWIF(privateKey)
      .toAddress().toString()
    expect(merchantDerivedAddress).toEqual(paymentAddress)
  })
})
