export interface Alphabet {
	readonly name: string;
	readonly chars: string;
	readonly radix: number;
	readonly charToIndex: ReadonlyMap<string, number>;
}

export interface SimpleTokenPattern {
	readonly kind: "simple";
	readonly name: string;
	readonly prefix: string;
	readonly bodyRegex: string;
	readonly bodyAlphabet: Alphabet;
	readonly minBodyLength: number;
}

export interface StructuredTokenPattern {
	readonly kind: "structured";
	readonly name: string;
	readonly prefix: string;
	readonly fullRegex: string;
	readonly trailingAlphabet: Alphabet;
	/**
	 * Split a valid body into segments and choose an alphabet for each one.
	 *
	 * Return `null` when the body is invalid.
	 * Calling `parse(format(segments))` must return the same segments and alphabets.
	 * Each alphabet must depend only on its own segment.
	 */
	parse(body: string): { segments: string[]; alphabets: Alphabet[] } | null;
	/** Rebuild a body from parsed segments of the same lengths. */
	format(segments: string[]): string;
}

export interface HeuristicTokenPattern {
	readonly kind: "heuristic";
	readonly name: string;
	readonly prefix: "";
	readonly bodyAlphabet: Alphabet;
	readonly minLength: number;
	readonly maxLength: number;
	readonly minEntropy: number;
	readonly minCharClasses: number;
}

export type TokenPattern =
	| SimpleTokenPattern
	| StructuredTokenPattern
	| HeuristicTokenPattern;

export interface TokenSpan {
	start: number;
	end: number;
	pattern: TokenPattern;
	body: string;
}
