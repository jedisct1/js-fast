// The 0.3.0 scanner, kept verbatim as the reference for differential tests.
// It needs cubic time on some texts, and exponential time with some custom patterns, so only run it on short texts.
// Bun can't interrupt a synchronous test, so a long input would hang the run instead of failing.
import type {
	HeuristicTokenPattern,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
	TokenSpan,
} from "../src/tokens/types.ts";
import { getBodyValidator } from "../src/tokens/validate.ts";

function findAllPositions(text: string, needle: string): number[] {
	const positions: number[] = [];
	let idx = 0;
	while (idx <= text.length - needle.length) {
		const pos = text.indexOf(needle, idx);
		if (pos === -1) break;
		positions.push(pos);
		idx = pos + 1;
	}
	return positions;
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

/**
 * Check whether a prefixed token starts at `pos`.
 * Each nested check starts later in the text, so recursion always ends.
 */
function wouldMatchAt(
	text: string,
	pos: number,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
): boolean {
	for (const pattern of allPatterns) {
		if (pattern.kind === "heuristic") continue;
		if (!text.startsWith(pattern.prefix, pos)) continue;

		if (pattern.kind === "simple") {
			if (
				wouldMatchSimpleAt(text, pos, pattern, prefixPositions, allPatterns)
			) {
				return true;
			}
		} else {
			if (
				wouldMatchStructuredAt(text, pos, pattern, prefixPositions, allPatterns)
			) {
				return true;
			}
		}
	}
	return false;
}

function wouldMatchSimpleAt(
	text: string,
	pos: number,
	pattern: SimpleTokenPattern,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
): boolean {
	const bodyStart = pos + pattern.prefix.length;

	let bodyEnd = bodyStart;
	while (bodyEnd < text.length) {
		if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!)) break;
		bodyEnd++;
	}

	if (bodyEnd - bodyStart < pattern.minBodyLength) return false;

	const bodyValidator = getBodyValidator(pattern);
	const validate = (body: string): boolean =>
		body.length >= pattern.minBodyLength && bodyValidator.test(body);

	const truncEnd = findTruncatedEnd(
		text,
		bodyStart,
		bodyEnd,
		prefixPositions,
		allPatterns,
		validate,
	);
	if (truncEnd !== -1) return true;

	return validate(text.slice(bodyStart, bodyEnd));
}

function wouldMatchStructuredAt(
	text: string,
	pos: number,
	pattern: StructuredTokenPattern,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
): boolean {
	const regex = getStickyRegex(pattern);
	regex.lastIndex = pos;
	const match = regex.exec(text);
	if (!match) return false;

	const matchEnd = pos + match[0].length;
	const bodyStart = pos + pattern.prefix.length;

	const truncEnd = findTruncatedEnd(
		text,
		bodyStart,
		matchEnd,
		prefixPositions,
		allPatterns,
		(body) => pattern.parse(body) !== null,
	);
	if (truncEnd !== -1) return true;

	const body = text.slice(bodyStart, matchEnd);
	if (pattern.parse(body) !== null) {
		if (matchEnd < text.length) {
			const nextCh = text[matchEnd]!;
			if (pattern.trailingAlphabet.charToIndex.has(nextCh)) {
				if (!prefixPositions.has(matchEnd)) return false;
			}
		}
		return true;
	}

	return false;
}

/**
 * Find non-overlapping tokens in `text`.
 *
 * `allPatterns` lets a filtered scan recognize boundaries created by patterns
 * that are not returned.
 */
export function referenceScan(
	text: string,
	patterns: readonly TokenPattern[],
	allPatterns?: readonly TokenPattern[],
): TokenSpan[] {
	const allPats = allPatterns ?? patterns;
	const uniquePrefixes = new Set(
		allPats.map((p) => p.prefix).filter((p) => p.length > 0),
	);

	const prefixPositions = new Set<number>();
	for (const pfx of uniquePrefixes) {
		for (const pos of findAllPositions(text, pfx)) {
			prefixPositions.add(pos);
		}
	}

	const candidates: TokenSpan[] = [];

	for (const pattern of patterns) {
		if (pattern.kind === "structured") {
			scanStructured(text, pattern, prefixPositions, allPats, candidates);
		} else if (pattern.kind === "heuristic") {
			scanHeuristic(text, pattern, candidates);
		} else {
			scanSimple(text, pattern, prefixPositions, allPats, candidates);
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

/**
 * Split a body only when both sides are valid tokens.
 * Prefer the longest valid left side.
 */
function findTruncatedEnd(
	text: string,
	bodyStart: number,
	bodyEnd: number,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
	validateLeft: (body: string) => boolean,
): number {
	const prefixesInBody: number[] = [];
	for (let i = bodyStart + 1; i < bodyEnd; i++) {
		if (prefixPositions.has(i)) prefixesInBody.push(i);
	}
	if (prefixesInBody.length === 0) return -1;

	for (let j = prefixesInBody.length - 1; j >= 0; j--) {
		const splitPos = prefixesInBody[j]!;
		const leftBody = text.slice(bodyStart, splitPos);
		if (!validateLeft(leftBody)) continue;
		if (!wouldMatchAt(text, splitPos, prefixPositions, allPatterns)) continue;
		return splitPos;
	}

	return -1;
}

function scanSimple(
	text: string,
	pattern: SimpleTokenPattern,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
	candidates: TokenSpan[],
): void {
	const bodyValidator = getBodyValidator(pattern);
	const validate = (body: string): boolean =>
		body.length >= pattern.minBodyLength && bodyValidator.test(body);

	for (const pos of findAllPositions(text, pattern.prefix)) {
		const bodyStart = pos + pattern.prefix.length;

		let bodyEnd = bodyStart;
		while (bodyEnd < text.length) {
			if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!)) break;
			bodyEnd++;
		}

		if (bodyEnd - bodyStart < pattern.minBodyLength) continue;

		const truncEnd = findTruncatedEnd(
			text,
			bodyStart,
			bodyEnd,
			prefixPositions,
			allPatterns,
			validate,
		);

		let finalEnd: number;
		if (truncEnd !== -1) {
			finalEnd = truncEnd;
		} else {
			const fullBody = text.slice(bodyStart, bodyEnd);
			if (!validate(fullBody)) continue;
			finalEnd = bodyEnd;
		}

		candidates.push({
			start: pos,
			end: finalEnd,
			pattern,
			body: text.slice(bodyStart, finalEnd),
		});
	}
}

function shannonEntropy(s: string): number {
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
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
	candidates: TokenSpan[],
): void {
	const regex = new RegExp(pattern.fullRegex, "g");
	for (let match = regex.exec(text); match !== null; match = regex.exec(text)) {
		const matchStart = match.index;
		if (match[0].length === 0) {
			regex.lastIndex = matchStart + 1;
			continue;
		}
		const matchEnd = matchStart + match[0].length;
		const bodyStart = matchStart + pattern.prefix.length;

		const truncEnd = findTruncatedEnd(
			text,
			bodyStart,
			matchEnd,
			prefixPositions,
			allPatterns,
			(body) => pattern.parse(body) !== null,
		);

		if (truncEnd !== -1) {
			candidates.push({
				start: matchStart,
				end: truncEnd,
				pattern,
				body: text.slice(bodyStart, truncEnd),
			});
			continue;
		}

		const body = text.slice(bodyStart, matchEnd);
		if (pattern.parse(body) === null) continue;

		if (matchEnd < text.length) {
			const nextCh = text[matchEnd]!;
			if (pattern.trailingAlphabet.charToIndex.has(nextCh)) {
				if (!prefixPositions.has(matchEnd)) continue;
			}
		}

		candidates.push({
			start: matchStart,
			end: matchEnd,
			pattern,
			body,
		});
	}
}
