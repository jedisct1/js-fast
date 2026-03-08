import type { FastParams } from "./types.ts";
/**
 * Encode an array of parts into the PRF input format.
 * Format: 4-byte BE part count, then for each part: 4-byte BE length + raw bytes.
 */
export declare function encodeParts(parts: Uint8Array[]): Uint8Array;
/**
 * Build the setup1 input for S-box pool key derivation.
 * Parts: [LABEL_INSTANCE1, radix_be32, sboxCount_be32, LABEL_FPE_POOL]
 */
export declare function buildSetup1Input(params: FastParams): Uint8Array;
/**
 * Build the setup2 input for sequence key derivation.
 * Parts: [LABEL_INSTANCE1, radix, sboxCount, LABEL_INSTANCE2,
 *         wordLength, numLayers, branchDist1, branchDist2,
 *         LABEL_FPE_SEQ, LABEL_TWEAK, tweak]
 */
export declare function buildSetup2Input(params: FastParams, tweak: Uint8Array): Uint8Array;
