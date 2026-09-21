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
