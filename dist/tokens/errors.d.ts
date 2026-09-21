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
