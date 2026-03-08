import type { FastParams } from "./types.ts";
export declare class FastCipher {
    readonly params: FastParams;
    private masterKey;
    private sboxPool;
    private cachedTweak;
    private cachedSeq;
    private constructor();
    /**
     * Create a new FAST cipher context.
     * Validates parameters and generates the S-box pool from the master key.
     */
    static create(params: FastParams, key: Uint8Array): FastCipher;
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
