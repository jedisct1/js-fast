import type {
	Alphabet,
	HeuristicTokenPattern,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
	TokenSpan,
} from "./types.ts";
import { getBodyValidator } from "./validate.ts";

const NO_POSITIONS: readonly number[] = [];
const NO_OFFSETS = new Int32Array(0);

function findAllPositions(text: string, needle: string): readonly number[] {
	let positions: number[] | undefined;
	let idx = 0;
	while (idx <= text.length - needle.length) {
		const pos = text.indexOf(needle, idx);
		if (pos === -1) break;
		positions ??= [];
		positions.push(pos);
		idx = pos + 1;
	}
	return positions ?? NO_POSITIONS;
}

const stickyRegexCache = new WeakMap<StructuredTokenPattern, RegExp>();
function getStickyRegex(pattern: StructuredTokenPattern): RegExp {
	let re = stickyRegexCache.get(pattern);
	if (!re) {
		re = new RegExp(pattern.fullRegex, "y");
		stickyRegexCache.set(pattern, re);
	}
	return re;
}

interface LengthBounds {
	readonly min: number;
	readonly max: number;
}

const CHARACTER_CLASS_WITH_LENGTH =
	/^(\[(?:[^\\[\]]|\\.)+\])\{(\d{1,9})(?:(,)(\d{0,9}))?\}$/;
const lengthBoundsCache = new WeakMap<
	SimpleTokenPattern,
	LengthBounds | null
>();

/**
 * Return the body length bounds when they are all that `bodyRegex` checks.
 *
 * That is the case for one character class followed by `{n}`, `{n,}` or `{n,m}`, when the class accepts every character of the body alphabet.
 * Bodies never extend past a run of alphabet characters, so the regex then accepts a body exactly when its length is within bounds.
 * Any other regex returns `null` and keeps being tested on each candidate body.
 */
function lengthBounds(pattern: SimpleTokenPattern): LengthBounds | null {
	const cached = lengthBoundsCache.get(pattern);
	if (cached !== undefined) return cached;

	getBodyValidator(pattern);
	let bounds: LengthBounds | null = null;
	const m = CHARACTER_CLASS_WITH_LENGTH.exec(pattern.bodyRegex);
	if (m) {
		const charClass = new RegExp(`^${m[1]}$`);
		let coversAlphabet = true;
		for (const ch of pattern.bodyAlphabet.charToIndex.keys()) {
			if (!charClass.test(ch)) {
				coversAlphabet = false;
				break;
			}
		}
		if (coversAlphabet) {
			const min = Number(m[2]);
			let max = min;
			if (m[3] !== undefined) max = m[4] === "" ? Infinity : Number(m[4]);
			bounds = { min: Math.max(min, pattern.minBodyLength), max };
		}
	}
	lengthBoundsCache.set(pattern, bounds);
	return bounds;
}

/** Index of the last value at most `limit` in `values[from..]`, or `from - 1`. */
function lastIndexAtMost(
	values: Int32Array,
	from: number,
	limit: number,
): number {
	let lo = from;
	let hi = values.length;
	while (lo < hi) {
		const mid = (lo + hi) >>> 1;
		if (values[mid]! <= limit) lo = mid + 1;
		else hi = mid;
	}
	return lo - 1;
}

/**
 * Find where the run of alphabet characters starting at a position ends.
 *
 * The last run found is remembered, so a series of positions that only goes up, or only goes down, reads each character once.
 */
class RunEnds {
	private start = -1;
	private end = -2;

	constructor(
		private readonly text: string,
		private readonly alphabet: Alphabet,
	) {}

	from(pos: number): number {
		if (pos >= this.start && pos <= this.end) return this.end;
		const { text, alphabet } = this;
		let end = pos;
		while (end < text.length && alphabet.charToIndex.has(text[end]!)) {
			if (end === this.start) {
				end = this.end;
				break;
			}
			end++;
		}
		this.start = pos;
		this.end = end;
		return end;
	}
}

function sortedUnique(positions: number[]): Int32Array {
	if (positions.length === 0) return NO_OFFSETS;
	const sorted = Int32Array.from(positions).sort();
	let count = 0;
	for (const pos of sorted) {
		if (count === 0 || sorted[count - 1] !== pos) sorted[count++] = pos;
	}
	return sorted.subarray(0, count);
}

type PrefixedPattern = SimpleTokenPattern | StructuredTokenPattern;

/**
 * Token boundaries for one text.
 *
 * A body can end early where another prefixed token starts, and whether a token starts at a position only depends on the text from there on.
 * So every prefix position is checked once, from the end of the text backward, and the ones where a token starts are kept in order.
 * Each check can then look up the token starts to its right instead of searching again.
 */
class Boundaries {
	private readonly occurrences = new Map<string, readonly number[]>();
	private readonly positions: Int32Array;
	private readonly starts: Int32Array;
	private first: number;

	constructor(
		private readonly text: string,
		allPatterns: readonly TokenPattern[],
	) {
		const found: number[] = [];
		for (const { prefix } of allPatterns) {
			if (prefix.length === 0 || this.occurrences.has(prefix)) continue;
			const positions = findAllPositions(text, prefix);
			this.occurrences.set(prefix, positions);
			for (const pos of positions) found.push(pos);
		}
		this.positions = sortedUnique(found);
		if (this.positions.length === 0) {
			this.starts = NO_OFFSETS;
			this.first = 0;
			return;
		}
		this.starts = new Int32Array(this.positions.length);
		this.first = this.starts.length;
		this.findStarts(allPatterns);
	}

	/** Check every prefix position from right to left, and keep the ones where a token starts. */
	private findStarts(allPatterns: readonly TokenPattern[]): void {
		const { text } = this;
		const byFirstChar = new Map<string, PrefixedPattern[]>();
		const unprefixed: PrefixedPattern[] = [];
		const runs = new Map<SimpleTokenPattern, RunEnds>();
		for (const pattern of allPatterns) {
			if (pattern.kind === "heuristic") continue;
			const { prefix } = pattern;
			if (prefix.length === 0) {
				unprefixed.push(pattern);
				continue;
			}
			let group = byFirstChar.get(prefix[0]!);
			if (!group) {
				group = [];
				byFirstChar.set(prefix[0]!, group);
			}
			group.push(pattern);
		}

		for (let k = this.positions.length - 1; k >= 0; k--) {
			const pos = this.positions[k]!;
			const group = byFirstChar.get(text[pos]!);
			if (
				(group !== undefined && this.tokenStartsAt(pos, group, runs)) ||
				this.tokenStartsAt(pos, unprefixed, runs)
			) {
				this.starts[--this.first] = pos;
			}
		}
	}

	private tokenStartsAt(
		pos: number,
		patterns: readonly PrefixedPattern[],
		runs: Map<SimpleTokenPattern, RunEnds>,
	): boolean {
		for (const pattern of patterns) {
			if (!this.text.startsWith(pattern.prefix, pos)) continue;
			let end: number;
			if (pattern.kind === "simple") {
				let patternRuns = runs.get(pattern);
				if (!patternRuns) {
					patternRuns = new RunEnds(this.text, pattern.bodyAlphabet);
					runs.set(pattern, patternRuns);
				}
				end = this.simpleEnd(pattern, pos, patternRuns);
			} else {
				end = this.structuredEndAt(pattern, pos);
			}
			if (end !== -1) return true;
		}
		return false;
	}

	/** Positions of `prefix` in the text, including overlapping ones. */
	occurrencesOf(prefix: string): readonly number[] {
		return this.occurrences.get(prefix) ?? findAllPositions(this.text, prefix);
	}

	/**
	 * Return where a simple token starting at `pos` ends, or -1.
	 *
	 * The body runs to the end of its alphabet run, unless it can end at a later token start.
	 * The last such start with a valid body before it wins.
	 */
	simpleEnd(pattern: SimpleTokenPattern, pos: number, runs: RunEnds): number {
		const bodyStart = pos + pattern.prefix.length;
		const bodyEnd = runs.from(bodyStart);
		if (bodyEnd - bodyStart < pattern.minBodyLength) return -1;

		const bounds = lengthBounds(pattern);
		if (bounds) {
			const k = lastIndexAtMost(
				this.starts,
				this.first,
				Math.min(bodyEnd - 1, bodyStart + bounds.max),
			);
			if (
				k >= this.first &&
				this.starts[k]! >= bodyStart + Math.max(bounds.min, 1)
			) {
				return this.starts[k]!;
			}
			const length = bodyEnd - bodyStart;
			return length >= bounds.min && length <= bounds.max ? bodyEnd : -1;
		}

		const bodyValidator = getBodyValidator(pattern);
		const validate = (body: string): boolean =>
			body.length >= pattern.minBodyLength && bodyValidator.test(body);
		const split = this.split(bodyStart, bodyEnd, validate);
		if (split !== -1) return split;
		return validate(this.text.slice(bodyStart, bodyEnd)) ? bodyEnd : -1;
	}

	/** Return where a structured token matched from `start` to `matchEnd` ends, or -1. */
	structuredEnd(
		pattern: StructuredTokenPattern,
		start: number,
		matchEnd: number,
	): number {
		const { text } = this;
		const bodyStart = start + pattern.prefix.length;
		const validate = (body: string): boolean => pattern.parse(body) !== null;
		const split = this.split(bodyStart, matchEnd, validate);
		if (split !== -1) return split;
		if (!validate(text.slice(bodyStart, matchEnd))) return -1;
		if (
			matchEnd < text.length &&
			pattern.trailingAlphabet.charToIndex.has(text[matchEnd]!) &&
			!this.isPrefixPosition(matchEnd)
		) {
			return -1;
		}
		return matchEnd;
	}

	private structuredEndAt(
		pattern: StructuredTokenPattern,
		pos: number,
	): number {
		const regex = getStickyRegex(pattern);
		regex.lastIndex = pos;
		const match = regex.exec(this.text);
		if (!match) return -1;
		return this.structuredEnd(pattern, pos, pos + match[0].length);
	}

	/** Return the last token start inside the body with a valid body before it, or -1. */
	private split(
		bodyStart: number,
		bodyEnd: number,
		validateLeft: (body: string) => boolean,
	): number {
		const { starts, first } = this;
		for (let k = lastIndexAtMost(starts, first, bodyEnd - 1); k >= first; k--) {
			const splitPos = starts[k]!;
			if (splitPos <= bodyStart) break;
			if (validateLeft(this.text.slice(bodyStart, splitPos))) return splitPos;
		}
		return -1;
	}

	private isPrefixPosition(pos: number): boolean {
		const k = lastIndexAtMost(this.positions, 0, pos);
		return k >= 0 && this.positions[k] === pos;
	}
}

/**
 * Find non-overlapping tokens in `text`.
 *
 * `allPatterns` lets a filtered scan recognize boundaries created by patterns
 * that are not returned.
 */
export function scan(
	text: string,
	patterns: readonly TokenPattern[],
	allPatterns?: readonly TokenPattern[],
): TokenSpan[] {
	const boundaries = new Boundaries(text, allPatterns ?? patterns);
	const candidates: TokenSpan[] = [];

	for (const pattern of patterns) {
		if (pattern.kind === "structured") {
			scanStructured(text, pattern, boundaries, candidates);
		} else if (pattern.kind === "heuristic") {
			scanHeuristic(text, pattern, candidates);
		} else {
			scanSimple(text, pattern, boundaries, candidates);
		}
	}

	// Prefer earlier matches, then longer prefixes and longer matches.
	candidates.sort((a, b) => {
		if (a.start !== b.start) return a.start - b.start;
		if (a.pattern.prefix.length !== b.pattern.prefix.length)
			return b.pattern.prefix.length - a.pattern.prefix.length;
		return b.end - b.start - (a.end - a.start);
	});

	const result: TokenSpan[] = [];
	let lastEnd = 0;
	for (const span of candidates) {
		if (span.start >= lastEnd) {
			result.push(span);
			lastEnd = span.end;
		}
	}

	return result;
}

function scanSimple(
	text: string,
	pattern: SimpleTokenPattern,
	boundaries: Boundaries,
	candidates: TokenSpan[],
): void {
	lengthBounds(pattern);
	const positions = boundaries.occurrencesOf(pattern.prefix);
	if (positions.length === 0) return;
	const runs = new RunEnds(text, pattern.bodyAlphabet);
	for (const pos of positions) {
		const end = boundaries.simpleEnd(pattern, pos, runs);
		if (end === -1) continue;
		candidates.push({
			start: pos,
			end,
			pattern,
			body: text.slice(pos + pattern.prefix.length, end),
		});
	}
}

export function shannonEntropy(s: string): number {
	if (s.length === 0) return 0;
	const freq = new Map<string, number>();
	for (const ch of s) {
		freq.set(ch, (freq.get(ch) ?? 0) + 1);
	}
	let entropy = 0;
	const len = s.length;
	for (const count of freq.values()) {
		const p = count / len;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

function countCharClasses(s: string): number {
	let hasUpper = false;
	let hasLower = false;
	let hasDigit = false;
	let hasOther = false;
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c >= 65 && c <= 90) hasUpper = true;
		else if (c >= 97 && c <= 122) hasLower = true;
		else if (c >= 48 && c <= 57) hasDigit = true;
		else hasOther = true;
	}
	return +hasUpper + +hasLower + +hasDigit + +hasOther;
}

const WORD_BOUNDARY_RE = /[^A-Za-z0-9_-]/;

function isWordBoundary(text: string, pos: number): boolean {
	if (pos === 0) return true;
	return WORD_BOUNDARY_RE.test(text[pos - 1]!);
}

function isWordBoundaryEnd(text: string, pos: number): boolean {
	if (pos >= text.length) return true;
	return WORD_BOUNDARY_RE.test(text[pos]!);
}

function scanHeuristic(
	text: string,
	pattern: HeuristicTokenPattern,
	candidates: TokenSpan[],
): void {
	const { bodyAlphabet, minLength, maxLength, minEntropy, minCharClasses } =
		pattern;
	let i = 0;
	while (i < text.length) {
		if (!bodyAlphabet.charToIndex.has(text[i]!)) {
			i++;
			continue;
		}

		if (!isWordBoundary(text, i)) {
			while (i < text.length && bodyAlphabet.charToIndex.has(text[i]!)) i++;
			continue;
		}

		let end = i;
		while (end < text.length && bodyAlphabet.charToIndex.has(text[end]!)) end++;

		const len = end - i;
		if (len >= minLength && len <= maxLength && isWordBoundaryEnd(text, end)) {
			const body = text.slice(i, end);
			if (
				countCharClasses(body) >= minCharClasses &&
				shannonEntropy(body) >= minEntropy
			) {
				candidates.push({
					start: i,
					end,
					pattern,
					body,
				});
			}
		}

		i = end;
	}
}

function scanStructured(
	text: string,
	pattern: StructuredTokenPattern,
	boundaries: Boundaries,
	candidates: TokenSpan[],
): void {
	const regex = new RegExp(pattern.fullRegex, "g");
	for (let match = regex.exec(text); match !== null; match = regex.exec(text)) {
		const start = match.index;
		if (match[0].length === 0) {
			regex.lastIndex = start + 1;
			continue;
		}
		const end = boundaries.structuredEnd(
			pattern,
			start,
			start + match[0].length,
		);
		if (end === -1) continue;
		candidates.push({
			start,
			end,
			pattern,
			body: text.slice(start + pattern.prefix.length, end),
		});
	}
}
