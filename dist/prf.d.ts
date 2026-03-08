/**
 * Derive key material using AES-CMAC in counter mode.
 * Matches the C and Zig reference implementations exactly.
 *
 * buffer = counter_be32 || encoded_input
 * CMAC is computed for counter 0, 1, 2, ... until enough bytes are produced.
 */
export declare function deriveKey(masterKey: Uint8Array, input: Uint8Array, outputLength: number): Uint8Array;
