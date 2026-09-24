import type { FastParams } from "../types.ts";
export declare const WRAPPED_OPENER = "{ENCRYPTED:";
/** FAST parameters for a wrapped word of `n` symbols, token plus check. */
export declare function wrappedParams(n: number): FastParams;
export declare function deriveWrapperKey(masterKey: Uint8Array): Uint8Array;
/**
 * Build the FAST tweak for wrapped tokens.
 * An omitted tweak and an empty one give the same result.
 */
export declare function wrapperTweak(tweak?: Uint8Array): Uint8Array;
export declare function resolveMaxTokenLength(value: number | undefined): number;
export declare function isPreserveMode(value: string | undefined): boolean;
export declare function assertWrappable(token: string, maxTokenLength: number): void;
/**
 * Encrypts and decrypts wrapped tokens for one master key.
 *
 * The derived key and S-box pool are kept until `destroy()`.
 * Every token gets a transient FAST context that borrows the pool and is
 * destroyed before the call returns, so no sequence outlives its token.
 */
export declare class WrappedTokenCipher {
    private readonly key;
    private readonly pool;
    private destroyed;
    private constructor();
    static create(masterKey: Uint8Array): WrappedTokenCipher;
    /** Return the complete wrapper for a token accepted by `assertWrappable()`. */
    wrap(token: string, tweak: Uint8Array): string;
    /**
     * Return the token encrypted in `payload`, or `null` if its check symbols
     * are not all zero after decryption.
     */
    unwrap(payload: string, tweak: Uint8Array): string | null;
    private transform;
    destroy(): void;
}
export type WrappedFraming = "valid" | "unterminated" | "too-short" | "too-long";
export interface WrappedCandidate {
    /** Offset of the opener. */
    start: number;
    /** Exclusive end, including the closing brace when there is one. */
    end: number;
    /** The payload starts right after the opener. */
    payloadEnd: number;
    framing: WrappedFraming;
}
/**
 * Yield every `{ENCRYPTED:` opener and the candidate that follows it.
 *
 * The payload is the longest run of `TOKEN67` symbols after the opener.
 * The first other character ends it, and is part of the candidate only if it
 * is `}`.
 * The next search starts at that character, so a stray opener cannot hide
 * the wrappers after it.
 */
export declare function wrappedCandidates(text: string, maxTokenLength: number): Generator<WrappedCandidate>;
export interface WrappedDecryptResult {
    text: string;
    /** Invalid candidates left unchanged in `text`. */
    preservedCandidates: number;
}
/**
 * Replace every verified wrapper in `text` with its token.
 *
 * `open` returns the token for a well-framed payload, or `null` if its check
 * fails.
 * Without `preserve`, a framing error throws before any payload is opened,
 * and the first failed check throws too.
 * With `preserve`, invalid candidates stay unchanged and are counted.
 */
export declare function unwrapText(text: string, maxTokenLength: number, preserve: boolean, open: (payload: string) => string | null): WrappedDecryptResult;
