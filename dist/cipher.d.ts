import type { SBoxPool } from "./sbox.ts";
import type { FastParams } from "./types.ts";
/**
 * Derive the S-box pool for `key`.
 *
 * The pool depends only on the key, radix, and S-box count, so ciphers with
 * other word lengths or tweaks can share it.
 */
export declare function deriveSBoxPool(params: Pick<FastParams, "radix" | "sboxCount">, key: Uint8Array): SBoxPool;
export declare class FastCipher {
    readonly params: FastParams;
    private readonly masterKey;
    private readonly sboxPool;
    private readonly ownsPool;
    private destroyed;
    private cachedTweak;
    private cachedSeq;
    private constructor();
    static create(params: FastParams, key: Uint8Array): FastCipher;
    private static validateParams;
    private hasCachedSequenceFor;
    private ensureSequence;
    private validateInput;
    private assertNotDestroyed;
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
