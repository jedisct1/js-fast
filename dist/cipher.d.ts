import type { FastParams } from "./types.ts";
export declare class FastCipher {
    readonly params: FastParams;
    private readonly masterKey;
    private readonly sboxPool;
    private cachedTweak;
    private cachedSeq;
    private constructor();
    static create(params: FastParams, key: Uint8Array): FastCipher;
    private static validateParams;
    private hasCachedSequenceFor;
    private ensureSequence;
    private validateInput;
    /**
     * Encrypt plaintext using the FAST cipher.
     * Each value in plaintext must be in [0, radix).
     */
    encrypt(plaintext: Uint8Array, tweak?: Uint8Array): Uint8Array;
    /**
     * Decrypt ciphertext using the FAST cipher.
     * Each value in ciphertext must be in [0, radix).
     */
    decrypt(ciphertext: Uint8Array, tweak?: Uint8Array): Uint8Array;
    /**
     * Zero out sensitive key material.
     */
    destroy(): void;
}
