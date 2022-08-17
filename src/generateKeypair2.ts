import { PrivKey, PubKey } from '@ts-bitcoin/core';

export function generateKeypair(opts: { returnType : "hex" | "bsv" | undefined } = { returnType: "hex"})
: {privateKey: PrivKey | string, publicKey: PubKey | string}
{
    const privateKey = PrivKey.fromRandom()
    const publicKey = PubKey.fromPrivKey(privateKey)

    switch (opts.returnType) {
        case undefined:
        case 'hex':
            return {
                privateKey: privateKey.bn.toHex({ size: 32 }),
                publicKey: publicKey.toString()
            }
        case 'bsv':
            return {
                privateKey,
                publicKey
            }
        default:
            throw new Error('The return type must either be "bsv" or "hex"')
    }
}
