/**
 * Base class for token errors.
 *
 * Messages never include token values, encrypted text, or key material.
 */
export declare class TokenError extends Error {
}
export declare class UnknownPatternError extends TokenError {
    name: string;
    constructor();
}
export declare class TokenFormatError extends TokenError {
    name: string;
    constructor(patternName: string);
}
export declare class CycleWalkError extends TokenError {
    name: string;
    constructor();
}
/**
 * Text or a token does not fit the wrapped format.
 *
 * Decryption throws it for a malformed `{ENCRYPTED:...}` candidate.
 * Encryption throws it when the input already contains the opener, or when a
 * detected token is too short, too long, or uses symbols outside `TOKEN67`.
 */
export declare class WrappedTokenFormatError extends TokenError {
    name: string;
}
/** A wrapped token failed its check after decryption. */
export declare class WrappedTokenIntegrityError extends TokenError {
    name: string;
    constructor();
}
