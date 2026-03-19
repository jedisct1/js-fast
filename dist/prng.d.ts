/**
 * Deterministic PRNG state using AES-128 ECB encryption of an incrementing counter.
 * Matches the C and Zig reference implementations exactly.
 */
export declare class PrngState {
    private readonly key;
    private readonly counter;
    private readonly buffer;
    private bufferPos;
    constructor(key: Uint8Array, nonce: Uint8Array);
    private incrementCounter;
    private encryptBlock;
    getBytes(output: Uint8Array): void;
    nextU32(): number;
    /**
     * Generate a uniform random number in [0, bound) with no modulo bias.
     * Uses Lemire's nearly-divisionless method with BigInt for 64-bit precision.
     */
    uniform(bound: number): number;
    cleanup(): void;
}
/**
 * Split 32-byte key material into AES key (first 16 bytes) and IV (last 16 bytes).
 * For sequence generation, the last 2 IV bytes are zeroed.
 */
export declare function splitKeyMaterial(keyMaterial: Uint8Array, zeroizeIvSuffix: boolean): {
    key: Uint8Array;
    iv: Uint8Array;
};
/**
 * Generate a sequence of S-box indices using PRF-derived key material.
 * Indices are in [0, poolSize).
 */
export declare function generateSequence(numLayers: number, poolSize: number, keyMaterial: Uint8Array): Uint32Array;
