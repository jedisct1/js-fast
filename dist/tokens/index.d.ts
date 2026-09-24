import { ALPHANUMERIC, ALPHANUMERIC_LOWER, ALPHANUMERIC_UPPER, BASE64, BASE64URL, DIGITS, HEX_LOWER, TOKEN67 } from "./alphabets.ts";
import type { TokenPattern } from "./types.ts";
import { type WrappedDecryptResult } from "./wrapped.ts";
export type { CycleWalkResult } from "./cyclewalk.ts";
export { cycleWalk, MAX_CYCLE_STEPS } from "./cyclewalk.ts";
export { CycleWalkError, TokenError, TokenFormatError, UnknownPatternError, WrappedTokenFormatError, WrappedTokenIntegrityError, } from "./errors.ts";
export { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
export { scan } from "./scanner.ts";
export type { Alphabet, HeuristicTokenPattern, SimpleTokenPattern, StructuredTokenPattern, TokenPattern, TokenSpan, } from "./types.ts";
export type { WrappedDecryptResult } from "./wrapped.ts";
export { ALPHANUMERIC, ALPHANUMERIC_LOWER, ALPHANUMERIC_UPPER, BASE64, BASE64URL, DIGITS, HEX_LOWER, TOKEN67, };
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
export interface WrappedEncryptOptions {
    /** Names of the patterns to detect; all registered patterns by default. */
    types?: string[];
    /** Pass the same tweak to `decryptWrapped()`. */
    tweak?: Uint8Array;
    /** Longest token to wrap, an integer from 2 to 4096; 512 by default. */
    maxTokenLength?: number;
}
export interface WrappedDecryptOptions {
    /** The tweak given to `encryptWrapped()`. */
    tweak?: Uint8Array;
    /** Longest token to accept, an integer from 2 to 4096; 512 by default. */
    maxTokenLength?: number;
    /**
     * `"throw"`, the default, rejects the whole text if any candidate is
     * invalid.
     * `"preserve"` leaves invalid candidates unchanged and counts them.
     */
    onInvalid?: "throw" | "preserve";
}
export declare class TokenEncryptor {
    private readonly key;
    private readonly cache;
    private readonly patterns;
    private wrapped;
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
    /**
     * Replace every detected token with `{ENCRYPTED:<payload>}`.
     *
     * Each complete token, prefix and separators included, is encrypted with
     * eight check symbols, so the replacement is 20 characters longer.
     * `decryptWrapped()` recovers the text without the pattern registry.
     * Encrypt only new plaintext: text that already contains `{ENCRYPTED:`
     * is rejected.
     *
     * @throws WrappedTokenFormatError if the text contains `{ENCRYPTED:`, or
     * a detected token is too short, longer than `maxTokenLength`, or uses a
     * symbol outside `TOKEN67`.
     */
    encryptWrapped(text: string, options?: WrappedEncryptOptions): string;
    /**
     * Replace every `{ENCRYPTED:<payload>}` wrapper with its token.
     *
     * Only wrappers are recognized, so registered patterns do not matter.
     * Each wrapper must decrypt with its check symbols intact.
     * In the default `"throw"` mode, any invalid candidate throws and no text
     * is returned.
     *
     * @throws WrappedTokenFormatError for a candidate without a closing brace,
     * with a symbol outside `TOKEN67`, or with a bad payload length.
     * @throws WrappedTokenIntegrityError for a wrapper that fails its check.
     */
    decryptWrapped(text: string, options: WrappedDecryptOptions & {
        onInvalid: "preserve";
    }): WrappedDecryptResult;
    decryptWrapped(text: string, options?: WrappedDecryptOptions & {
        onInvalid?: "throw";
    }): string;
    decryptWrapped(text: string, options?: WrappedDecryptOptions): string | WrappedDecryptResult;
    private wrappedCipher;
    register(pattern: TokenPattern): void;
    destroy(): void;
}
