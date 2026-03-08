import { PrngState } from "./prng.ts";
export interface SBox {
    perm: Uint8Array;
    inv: Uint8Array;
}
/**
 * Generate a single S-box permutation using Fisher-Yates shuffle.
 */
export declare function generateSBox(radix: number, prng: PrngState): SBox;
export interface SBoxPool {
    sboxes: SBox[];
    radix: number;
}
/**
 * Generate a pool of S-boxes from PRF-derived key material.
 * Uses Fisher-Yates shuffle driven by AES-ECB PRNG.
 */
export declare function generateSBoxPool(radix: number, count: number, keyMaterial: Uint8Array): SBoxPool;
