export class FastError extends Error {}

export class InvalidRadixError extends FastError {
	override name = "InvalidRadixError";

	constructor() {
		super("Radix must be between 4 and 256");
	}
}

export class InvalidWordLengthError extends FastError {
	override name = "InvalidWordLengthError";

	constructor(message = "Word length must be >= 2") {
		super(message);
	}
}

export class InvalidSBoxCountError extends FastError {
	override name = "InvalidSBoxCountError";

	constructor() {
		super("S-box count must be > 0");
	}
}

export class InvalidBranchDistError extends FastError {
	override name = "InvalidBranchDistError";
}

export class InvalidLengthError extends FastError {
	override name = "InvalidLengthError";

	constructor() {
		super("Input length does not match word length");
	}
}

export class InvalidValueError extends FastError {
	override name = "InvalidValueError";

	constructor() {
		super("Input value exceeds radix");
	}
}

export class InvalidParametersError extends FastError {
	override name = "InvalidParametersError";

	constructor(message = "Invalid parameters") {
		super(message);
	}
}
