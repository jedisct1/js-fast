import { ALPHANUMERIC, ALPHANUMERIC_LOWER, ALPHANUMERIC_UPPER, BASE64, BASE64URL, DIGITS, HEX_LOWER } from "./alphabets.ts";
import type { TokenPattern } from "./types.ts";
export type { CycleWalkResult } from "./cyclewalk.ts";
export { cycleWalk, MAX_CYCLE_STEPS } from "./cyclewalk.ts";
export { CycleWalkError, TokenError, TokenFormatError, UnknownPatternError, } from "./errors.ts";
export { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
export { scan } from "./scanner.ts";
export type { Alphabet, HeuristicTokenPattern, SimpleTokenPattern, StructuredTokenPattern, TokenPattern, TokenSpan, } from "./types.ts";
export { ALPHANUMERIC, ALPHANUMERIC_LOWER, ALPHANUMERIC_UPPER, BASE64, BASE64URL, DIGITS, HEX_LOWER, };
export interface TokenEncryptorOptions {
    types?: string[];
    tweak?: Uint8Array;
}
export interface TokenOptions {
    /** Use the same tweak for encryption and decryption. */
    tweak?: Uint8Array;
}
export interface EncryptedSpan {
    /** Zero-based start offset in the original text. */
    start: number;
    /** Exclusive end offset in the original text. */
    end: number;
    original: string;
    /** Includes the marker for heuristic patterns. */
    encrypted: string;
    patternName: string;
}
export interface EncryptResult {
    text: string;
    spans: EncryptedSpan[];
}
export declare class TokenEncryptor {
    private readonly key;
    private readonly cache;
    private readonly patterns;
    private destroyed;
    constructor(key: Uint8Array);
    private assertAlive;
    private getCipher;
    private makeTweak;
    private activePatterns;
    encrypt(text: string, options?: TokenEncryptorOptions): string;
    encryptWithSpans(text: string, options?: TokenEncryptorOptions): EncryptResult;
    /**
     * Decrypt the tokens found by scanning `text`.
     *
     * Encrypted text can contain another pattern's prefix by chance.
     * Use saved encrypted values and pattern names with `decryptToken()` when
     * recovery must be reliable.
     */
    decrypt(text: string, options?: TokenEncryptorOptions): string;
    /**
     * Encrypt one complete token with a named pattern.
     *
     * The result matches the encrypted value returned by `encryptWithSpans()`.
     *
     * @throws UnknownPatternError if no registered pattern has that name.
     * @throws TokenFormatError if `plaintext` is not a complete token of the pattern.
     */
    encryptToken(plaintext: string, patternName: string, options?: TokenOptions): string;
    /**
     * Decrypt one complete token with a named pattern.
     *
     * Use this with the encrypted value and pattern name from `encryptWithSpans()`
     * when recovery must be reliable.
     * Heuristic tokens must include their `[ENCRYPTED:<name>]` marker.
     *
     * @throws UnknownPatternError if no registered pattern has that name.
     * @throws TokenFormatError if `ciphertext` is not a complete token of the pattern.
     */
    decryptToken(ciphertext: string, patternName: string, options?: TokenOptions): string;
    private patternByName;
    private encryptedLead;
    private encryptSpan;
    private transform;
    private transformStructured;
    private findHeuristicMarkerHits;
    register(pattern: TokenPattern): void;
    destroy(): void;
}
