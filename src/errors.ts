export class FastError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "FastError";
	}
}

export class InvalidRadixError extends FastError {
	constructor() {
		super("Radix must be between 4 and 256");
		this.name = "InvalidRadixError";
	}
}

export class InvalidWordLengthError extends FastError {
	constructor(message = "Word length must be >= 2") {
		super(message);
		this.name = "InvalidWordLengthError";
	}
}

export class InvalidSBoxCountError extends FastError {
	constructor() {
		super("S-box count must be > 0");
		this.name = "InvalidSBoxCountError";
	}
}

export class InvalidBranchDistError extends FastError {
	constructor(message: string) {
		super(message);
		this.name = "InvalidBranchDistError";
	}
}

export class InvalidLengthError extends FastError {
	constructor() {
		super("Input length does not match word length");
		this.name = "InvalidLengthError";
	}
}

export class InvalidValueError extends FastError {
	constructor() {
		super("Input value exceeds radix");
		this.name = "InvalidValueError";
	}
}

export class InvalidParametersError extends FastError {
	constructor(message = "Invalid parameters") {
		super(message);
		this.name = "InvalidParametersError";
	}
}
