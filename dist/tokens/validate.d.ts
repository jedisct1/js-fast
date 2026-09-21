import type { Alphabet, SimpleTokenPattern, StructuredTokenPattern, TokenPattern } from "./types.ts";
export interface ParsedSegments {
    segments: string[];
    alphabets: Alphabet[];
}
export declare function getBodyValidator(pattern: SimpleTokenPattern): RegExp;
export declare function heuristicMarker(patternName: string): string;
export declare function isInAlphabet(s: string, alphabet: Alphabet): boolean;
/**
 * Validate one complete token and return its body.
 * Heuristic ciphertext must include its marker.
 */
export declare function tokenBody(pattern: TokenPattern, token: string, form: "plain" | "encrypted"): string;
/**
 * Parse a body and check that rebuilding it keeps its segments and alphabets.
 */
export declare function parseStructured(pattern: StructuredTokenPattern, body: string): ParsedSegments;
/**
 * Format segments and reject output that would be read differently.
 */
export declare function formatStructured(pattern: StructuredTokenPattern, segments: string[], alphabets: Alphabet[]): string;
/**
 * Check whether a changed segment keeps its parsed value and alphabet.
 */
export declare function segmentClass(pattern: StructuredTokenPattern, parsed: ParsedSegments, index: number): (candidate: string) => boolean;
