import type { TokenPattern, TokenSpan } from "./types.ts";
/**
 * Find non-overlapping tokens in `text`.
 *
 * `allPatterns` lets a filtered scan recognize boundaries created by patterns
 * that are not returned.
 */
export declare function scan(text: string, patterns: readonly TokenPattern[], allPatterns?: readonly TokenPattern[]): TokenSpan[];
export declare function shannonEntropy(s: string): number;
