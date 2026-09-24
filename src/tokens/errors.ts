/**
 * Base class for token errors.
 *
 * Messages never include token values, encrypted text, or key material.
 */
export class TokenError extends Error {}

export class UnknownPatternError extends TokenError {
	override name = "UnknownPatternError";

	constructor() {
		super("Unknown token pattern");
	}
}

export class TokenFormatError extends TokenError {
	override name = "TokenFormatError";

	constructor(patternName: string) {
		super(`Malformed ${patternName} token`);
	}
}

export class CycleWalkError extends TokenError {
	override name = "CycleWalkError";

	constructor() {
		super("Cycle walk did not converge");
	}
}

/**
 * Text or a token does not fit the wrapped format.
 *
 * Decryption throws it for a malformed `{ENCRYPTED:...}` candidate.
 * Encryption throws it when the input already contains the opener, or when a
 * detected token is too short, too long, or uses symbols outside `TOKEN67`.
 */
export class WrappedTokenFormatError extends TokenError {
	override name = "WrappedTokenFormatError";
}

/** A wrapped token failed its check after decryption. */
export class WrappedTokenIntegrityError extends TokenError {
	override name = "WrappedTokenIntegrityError";

	constructor() {
		super("Encrypted token failed verification");
	}
}
