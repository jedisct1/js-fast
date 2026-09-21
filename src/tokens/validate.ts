import { TokenFormatError } from "./errors.ts";
import { MIN_SEGMENT_LENGTH } from "./registry.ts";
import type {
	Alphabet,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
} from "./types.ts";

export interface ParsedSegments {
	segments: string[];
	alphabets: Alphabet[];
}

const bodyValidatorCache = new WeakMap<SimpleTokenPattern, RegExp>();
export function getBodyValidator(pattern: SimpleTokenPattern): RegExp {
	let re = bodyValidatorCache.get(pattern);
	if (!re) {
		re = new RegExp(`^(?:${pattern.bodyRegex})$`);
		bodyValidatorCache.set(pattern, re);
	}
	return re;
}

const fullValidatorCache = new WeakMap<StructuredTokenPattern, RegExp>();
function getFullValidator(pattern: StructuredTokenPattern): RegExp {
	let re = fullValidatorCache.get(pattern);
	if (!re) {
		re = new RegExp(`^(?:${pattern.fullRegex})$`);
		fullValidatorCache.set(pattern, re);
	}
	return re;
}

export function heuristicMarker(patternName: string): string {
	return `[ENCRYPTED:${patternName}]`;
}

export function isInAlphabet(s: string, alphabet: Alphabet): boolean {
	for (let i = 0; i < s.length; i++) {
		if (!alphabet.charToIndex.has(s[i]!)) return false;
	}
	return true;
}

function sameAlphabet(a: Alphabet | undefined, b: Alphabet): boolean {
	return a === b || a?.chars === b.chars;
}

/**
 * Validate one complete token and return its body.
 * Heuristic ciphertext must include its marker.
 */
export function tokenBody(
	pattern: TokenPattern,
	token: string,
	form: "plain" | "encrypted",
): string {
	const lead =
		pattern.kind === "heuristic" && form === "encrypted"
			? heuristicMarker(pattern.name)
			: pattern.prefix;
	if (!token.startsWith(lead)) throw new TokenFormatError(pattern.name);
	const body = token.slice(lead.length);

	let valid: boolean;
	if (pattern.kind === "simple") {
		valid =
			body.length >= pattern.minBodyLength &&
			isInAlphabet(body, pattern.bodyAlphabet) &&
			getBodyValidator(pattern).test(body);
	} else if (pattern.kind === "heuristic") {
		valid =
			body.length >= pattern.minLength &&
			body.length <= pattern.maxLength &&
			isInAlphabet(body, pattern.bodyAlphabet);
	} else {
		valid = getFullValidator(pattern).test(token);
	}
	if (!valid) throw new TokenFormatError(pattern.name);
	return body;
}

function readsBack(
	pattern: StructuredTokenPattern,
	body: string,
	expected: ParsedSegments,
): boolean {
	const reparsed = pattern.parse(body);
	if (!reparsed || reparsed.segments.length !== expected.segments.length) {
		return false;
	}
	for (let i = 0; i < expected.segments.length; i++) {
		if (
			reparsed.segments[i] !== expected.segments[i] ||
			!sameAlphabet(reparsed.alphabets[i], expected.alphabets[i]!)
		) {
			return false;
		}
	}
	return true;
}

/**
 * Parse a body and check that rebuilding it keeps its segments and alphabets.
 */
export function parseStructured(
	pattern: StructuredTokenPattern,
	body: string,
): ParsedSegments {
	const parsed = pattern.parse(body);
	if (
		!parsed ||
		parsed.alphabets.length !== parsed.segments.length ||
		!readsBack(pattern, pattern.format(parsed.segments), parsed)
	) {
		throw new TokenFormatError(pattern.name);
	}
	for (let i = 0; i < parsed.segments.length; i++) {
		const segment = parsed.segments[i]!;
		if (
			segment.length >= MIN_SEGMENT_LENGTH &&
			!isInAlphabet(segment, parsed.alphabets[i]!)
		) {
			throw new TokenFormatError(pattern.name);
		}
	}
	return parsed;
}

/**
 * Format segments and reject output that would be read differently.
 */
export function formatStructured(
	pattern: StructuredTokenPattern,
	segments: string[],
	alphabets: Alphabet[],
): string {
	const body = pattern.format(segments);
	if (!readsBack(pattern, body, { segments, alphabets })) {
		throw new TokenFormatError(pattern.name);
	}
	return body;
}

/**
 * Check whether a changed segment keeps its parsed value and alphabet.
 */
export function segmentClass(
	pattern: StructuredTokenPattern,
	parsed: ParsedSegments,
	index: number,
): (candidate: string) => boolean {
	const probe = [...parsed.segments];
	const alphabet = parsed.alphabets[index]!;
	return (candidate) => {
		probe[index] = candidate;
		const reparsed = pattern.parse(pattern.format(probe));
		return (
			reparsed !== null &&
			reparsed.segments.length === probe.length &&
			reparsed.segments[index] === candidate &&
			sameAlphabet(reparsed.alphabets[index], alphabet)
		);
	};
}
