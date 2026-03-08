import type { FastParams } from "./types.ts";
/**
 * Calculate recommended parameters for the FAST cipher.
 */
export declare function calculateRecommendedParams(radix: number, wordLength: number, securityLevel?: number): FastParams;
