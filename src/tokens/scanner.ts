import type {
	HeuristicTokenPattern,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
	TokenSpan,
} from "./types.ts";

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

// Cached compiled regexes to avoid recompilation in hot paths.
const bodyValidatorCache = new WeakMap<SimpleTokenPattern, RegExp>();
function getBodyValidator(pattern: SimpleTokenPattern): RegExp {
	let re = bodyValidatorCache.get(pattern);
	if (!re) {
		re = new RegExp(`^(?:${pattern.bodyRegex})$`);
		bodyValidatorCache.set(pattern, re);
	}
	return re;
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
 * Check whether a valid token would be produced starting at `pos`.
 * Runs the same greedy-consume + validate + recursive RHS logic the
 * real scanner uses. Recursion terminates because each nested call
 * starts at a strictly later text position.
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

	// Greedily consume body-alphabet chars (same as scanSimple).
	let bodyEnd = bodyStart;
	while (bodyEnd < text.length) {
		if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!)) break;
		bodyEnd++;
	}

	if (bodyEnd - bodyStart < pattern.minBodyLength) return false;

	const bodyValidator = getBodyValidator(pattern);
	const validate = (body: string): boolean =>
		body.length >= pattern.minBodyLength && bodyValidator.test(body);

	// Try truncating at prefix boundaries with valid right-hand side.
	// Recursion terminates because split positions are strictly increasing.
	const truncEnd = findTruncatedEnd(
		text,
		bodyStart,
		bodyEnd,
		prefixPositions,
		allPatterns,
		validate,
	);
	if (truncEnd !== -1) return true;

	// Try full greedy body.
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

	// Try truncations at prefix boundaries within the match.
	const truncEnd = findTruncatedEnd(
		text,
		bodyStart,
		matchEnd,
		prefixPositions,
		allPatterns,
		(body) => pattern.parse(body) !== null,
	);
	if (truncEnd !== -1) return true;

	// Try full match body.
	const body = text.slice(bodyStart, matchEnd);
	if (pattern.parse(body) !== null) {
		// Also check trailing boundary.
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
 * Scan text for token matches.
 *
 * Simple patterns use prefix-first scanning: find the prefix, greedily
 * consume body-alphabet chars, then try to split at prefix boundaries
 * where a valid token exists on the right-hand side.
 *
 * Structured patterns use fullRegex for initial matching, then try
 * truncating at prefix boundaries where a valid right-hand token exists.
 *
 * A truncation is only accepted when BOTH the left-side body validates
 * AND a real token match would be produced at the split point. This
 * prevents false splits when a variable-length body happens to contain
 * a prefix substring that doesn't lead to a valid token (too short,
 * too long, wrong characters, boundary-invalid, etc.).
 *
 * @param allPatterns - The full set of known patterns, used for boundary
 *   detection and right-hand-side validation. When using a types filter,
 *   this should include ALL patterns. Defaults to the provided patterns.
 */
export function scan(
	text: string,
	patterns: readonly TokenPattern[],
	allPatterns?: readonly TokenPattern[],
): TokenSpan[] {
	const allPats = allPatterns ?? patterns;
	const uniquePrefixes = new Set(
		allPats.map((p) => p.prefix).filter((p) => p.length > 0),
	);

	// Precompute all positions where any known prefix starts.
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

	// Sort by start position, then by longest prefix (most specific),
	// then by longest total match.
	candidates.sort((a, b) => {
		if (a.start !== b.start) return a.start - b.start;
		if (a.pattern.prefix.length !== b.pattern.prefix.length)
			return b.pattern.prefix.length - a.pattern.prefix.length;
		return b.end - b.start - (a.end - a.start);
	});

	// Remove overlaps: first match wins (after sorting by specificity).
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
 * Try to find the best body end by truncating at prefix boundaries.
 * Only accepts a truncation if the left-side body validates AND a
 * real token match would be produced at the split point.
 * Tries rightmost prefix position first (longest body).
 * Returns the split position, or -1 if no valid split found.
 */
function findTruncatedEnd(
	text: string,
	bodyStart: number,
	bodyEnd: number,
	prefixPositions: Set<number>,
	allPatterns: readonly TokenPattern[],
	validateLeft: (body: string) => boolean,
): number {
	// Collect prefix positions within the consumed body, excluding bodyStart.
	const prefixesInBody: number[] = [];
	for (let i = bodyStart + 1; i < bodyEnd; i++) {
		if (prefixPositions.has(i)) prefixesInBody.push(i);
	}
	if (prefixesInBody.length === 0) return -1;

	// Try rightmost first (longest valid left-side body).
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

		// Greedily consume all body-alphabet chars.
		let bodyEnd = bodyStart;
		while (bodyEnd < text.length) {
			if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!)) break;
			bodyEnd++;
		}

		if (bodyEnd - bodyStart < pattern.minBodyLength) continue;

		// Try truncating at prefix boundaries where a valid
		// right-hand-side token exists.
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
			// No valid truncation. Validate the full greedy body.
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

/**
 * Shannon entropy in bits per character.
 */
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

/**
 * Count character classes present in a string:
 * uppercase, lowercase, digits, and symbols (anything else).
 */
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
		// Skip non-alphabet characters.
		if (!bodyAlphabet.charToIndex.has(text[i]!)) {
			i++;
			continue;
		}

		// Check word boundary at start.
		if (!isWordBoundary(text, i)) {
			// Advance past this run of alphabet characters.
			while (i < text.length && bodyAlphabet.charToIndex.has(text[i]!)) i++;
			continue;
		}

		// Greedily consume alphabet characters.
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

		// Try truncating at prefix boundaries where a valid
		// right-hand-side token exists.
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

		// No truncation. Require the full body to satisfy the parser contract.
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
