import { PrivKey, PubKey } from '@ts-bitcoin/core';
export declare function generateKeypair(opts?: {
    returnType: "hex" | "bsv" | undefined;
}): {
    privateKey: PrivKey | string;
    publicKey: PubKey | string;
};
