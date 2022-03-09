/* eslint-env jest */
const generateKeypair = require('../generateKeypair')
const bsv = require('bsv')

describe('generateKeypair', () => {
  it('Returns object with publicKey / privateKey string properties', () => {
    const result = generateKeypair()
    expect(result.constructor).toEqual(Object)
    expect(result).toEqual({
      publicKey: expect.any(String),
      privateKey: expect.any(String)
    })
  })
  it('Produces a 33-byte public key', () => {
    const { publicKey } = generateKeypair()
    expect(publicKey.length).toBe(66)
    const regex = /[0-9a-f]{66}/
    expect(regex.test(publicKey)).toEqual(true)
  })
  it('Produces a 32-byte private key', () => {
    const { privateKey } = generateKeypair()
    expect(privateKey.length).toBe(64)
    const regex = /[0-9a-f]{64}/
    expect(regex.test(privateKey)).toEqual(true)
  })
  it('Produces the correct public key for the private key', () => {
    const { privateKey, publicKey } = generateKeypair()
    const testPrivateKey = bsv.PrivateKey.fromString(privateKey)
    const testPublicKeyString = testPrivateKey.publicKey.toString()
    expect(testPublicKeyString).toEqual(publicKey)
  })
})
