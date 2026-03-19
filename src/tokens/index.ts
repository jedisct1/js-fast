import { FastCipher } from "../cipher.ts";
import { calculateRecommendedParams } from "../params.ts";
import {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	ALPHANUMERIC_UPPER,
	BASE64,
	BASE64URL,
	DIGITS,
	HEX_LOWER,
} from "./alphabets.ts";
import { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
import { scan } from "./scanner.ts";
import { transformBody } from "./transformer.ts";
import type { TokenPattern, TokenSpan } from "./types.ts";

export { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
export { scan } from "./scanner.ts";
export type {
	Alphabet,
	TokenPattern,
	TokenSpan,
} from "./types.ts";
export {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	ALPHANUMERIC_UPPER,
	BASE64,
	BASE64URL,
	DIGITS,
	HEX_LOWER,
};

export interface TokenEncryptorOptions {
	types?: string[];
	tweak?: Uint8Array;
}

export interface EncryptedSpan {
	/** Start position of the token in the original text. */
	start: number;
	/** End position of the token in the original text. */
	end: number;
	/** The full original token (prefix + body). */
	original: string;
	/** The full encrypted token (prefix + encrypted body, or marker + body for heuristic). */
	encrypted: string;
	/** Name of the pattern that matched (e.g., "github-pat", "sendgrid"). */
	patternName: string;
}

export interface EncryptResult {
	/** The full encrypted text. */
	text: string;
	/** One entry per token that was encrypted. */
	spans: EncryptedSpan[];
}

const AES_KEY_SIZE = 16;
const textEncoder = new TextEncoder();

function heuristicMarker(patternName: string): string {
	return `[ENCRYPTED:${patternName}]`;
}

export class TokenEncryptor {
	private readonly key: Uint8Array;
	private readonly cache = new Map<string, FastCipher>();
	private readonly patterns: TokenPattern[];
	private destroyed = false;

	constructor(key: Uint8Array) {
		if (key.length !== AES_KEY_SIZE) {
			throw new Error("Key must be 16 bytes");
		}
		this.key = new Uint8Array(key);
		this.patterns = [...BUILTIN_PATTERNS];
	}

	private assertAlive(): void {
		if (this.destroyed) {
			throw new Error("TokenEncryptor has been destroyed");
		}
	}

	private getCipher(radix: number, wordLength: number): FastCipher {
		const k = `${radix}:${wordLength}`;
		let cipher = this.cache.get(k);
		if (!cipher) {
			const params = calculateRecommendedParams(radix, wordLength);
			cipher = FastCipher.create(params, this.key);
			this.cache.set(k, cipher);
		}
		return cipher;
	}

	private makeTweak(patternName: string, extra?: Uint8Array): Uint8Array {
		const nameBytes = textEncoder.encode(patternName);
		if (!extra || extra.length === 0) return nameBytes;
		const combined = new Uint8Array(nameBytes.length + 1 + extra.length);
		combined.set(nameBytes, 0);
		combined[nameBytes.length] = 0x00; // separator
		combined.set(extra, nameBytes.length + 1);
		return combined;
	}

	private activePatterns(
		options?: TokenEncryptorOptions,
	): readonly TokenPattern[] {
		if (!options?.types) return this.patterns;
		const allowed = new Set(options.types);
		return this.patterns.filter((p) => allowed.has(p.name));
	}

	encrypt(text: string, options?: TokenEncryptorOptions): string {
		return this.encryptWithSpans(text, options).text;
	}

	encryptWithSpans(
		text: string,
		options?: TokenEncryptorOptions,
	): EncryptResult {
		this.assertAlive();
		const patterns = this.activePatterns(options);
		const scanned = scan(text, patterns, this.patterns);
		if (scanned.length === 0) return { text, spans: [] };

		const parts: string[] = [];
		const spans: EncryptedSpan[] = [];
		let cursor = 0;

		for (const span of scanned) {
			parts.push(text.slice(cursor, span.start));
			const original = text.slice(span.start, span.end);
			const encrypted = this.encryptSpan(span, options?.tweak);
			parts.push(encrypted);
			spans.push({
				start: span.start,
				end: span.end,
				original,
				encrypted,
				patternName: span.pattern.name,
			});
			cursor = span.end;
		}

		parts.push(text.slice(cursor));
		return { text: parts.join(""), spans };
	}

	decrypt(text: string, options?: TokenEncryptorOptions): string {
		this.assertAlive();
		const patterns = this.activePatterns(options);

		// First pass: decrypt heuristic markers ([ENCRYPTED:<name>]<body>).
		// These are unambiguous prefixes, so they don't need entropy checks.
		const heuristicPatterns = patterns.filter((p) => p.kind === "heuristic");
		let result = text;
		if (heuristicPatterns.length > 0) {
			result = this.decryptHeuristicMarkers(
				result,
				heuristicPatterns,
				options?.tweak,
			);
		}

		// Second pass: decrypt prefix-based tokens (simple + structured).
		const prefixPatterns = patterns.filter((p) => p.kind !== "heuristic");
		if (prefixPatterns.length === 0) return result;

		const spans = scan(result, prefixPatterns, this.patterns);
		if (spans.length === 0) return result;

		const parts: string[] = [];
		let cursor = 0;

		for (const span of spans) {
			parts.push(result.slice(cursor, span.start));
			parts.push(this.decryptSpan(span, options?.tweak));
			cursor = span.end;
		}

		parts.push(result.slice(cursor));
		return parts.join("");
	}

	private encryptSpan(span: TokenSpan, extraTweak?: Uint8Array): string {
		const { pattern, body } = span;
		const tweak = this.makeTweak(pattern.name, extraTweak);

		if (pattern.kind === "heuristic") {
			const cipher = this.getCipher(pattern.bodyAlphabet.radix, body.length);
			const encrypted = transformBody(
				body,
				pattern.bodyAlphabet,
				cipher,
				"encrypt",
				tweak,
			);
			return heuristicMarker(pattern.name) + encrypted;
		}

		if (pattern.kind === "simple") {
			const cipher = this.getCipher(pattern.bodyAlphabet.radix, body.length);
			const encrypted = transformBody(
				body,
				pattern.bodyAlphabet,
				cipher,
				"encrypt",
				tweak,
			);
			return pattern.prefix + encrypted;
		}

		// Structured token
		const parsed = pattern.parse(body);
		if (!parsed) return pattern.prefix + body;

		const transformedSegments: string[] = [];
		for (let i = 0; i < parsed.segments.length; i++) {
			const seg = parsed.segments[i]!;
			const alphabet = parsed.alphabets[i]!;

			if (seg.length < MIN_SEGMENT_LENGTH) {
				transformedSegments.push(seg);
				continue;
			}

			const cipher = this.getCipher(alphabet.radix, seg.length);
			transformedSegments.push(
				transformBody(seg, alphabet, cipher, "encrypt", tweak),
			);
		}

		return pattern.prefix + pattern.format(transformedSegments);
	}

	private decryptSpan(span: TokenSpan, extraTweak?: Uint8Array): string {
		const { pattern, body } = span;
		const tweak = this.makeTweak(pattern.name, extraTweak);

		if (pattern.kind === "simple") {
			const cipher = this.getCipher(pattern.bodyAlphabet.radix, body.length);
			const decrypted = transformBody(
				body,
				pattern.bodyAlphabet,
				cipher,
				"decrypt",
				tweak,
			);
			return pattern.prefix + decrypted;
		}

		// Structured token
		if (pattern.kind !== "structured") return pattern.prefix + body;
		const parsed = pattern.parse(body);
		if (!parsed) return pattern.prefix + body;

		const transformedSegments: string[] = [];
		for (let i = 0; i < parsed.segments.length; i++) {
			const seg = parsed.segments[i]!;
			const alphabet = parsed.alphabets[i]!;

			if (seg.length < MIN_SEGMENT_LENGTH) {
				transformedSegments.push(seg);
				continue;
			}

			const cipher = this.getCipher(alphabet.radix, seg.length);
			transformedSegments.push(
				transformBody(seg, alphabet, cipher, "decrypt", tweak),
			);
		}

		return pattern.prefix + pattern.format(transformedSegments);
	}

	private decryptHeuristicMarkers(
		text: string,
		patterns: readonly TokenPattern[],
		extraTweak?: Uint8Array,
	): string {
		// Find all marker spans across all heuristic patterns, then process
		// in text order. This avoids order-dependence on pattern iteration.
		interface MarkerHit {
			start: number;
			end: number;
			body: string;
			patternName: string;
			alphabet: import("./types.ts").Alphabet;
		}

		const hits: MarkerHit[] = [];

		for (const pattern of patterns) {
			if (pattern.kind !== "heuristic") continue;
			const marker = heuristicMarker(pattern.name);

			let searchFrom = 0;
			while (searchFrom < text.length) {
				const idx = text.indexOf(marker, searchFrom);
				if (idx === -1) break;

				const bodyStart = idx + marker.length;
				let bodyEnd = bodyStart;
				while (
					bodyEnd < text.length &&
					bodyEnd - bodyStart < pattern.maxLength &&
					pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!)
				) {
					bodyEnd++;
				}

				const bodyLen = bodyEnd - bodyStart;
				// Reject if more alphabet chars follow — the body is overlong/malformed.
				const trailingAlphaChar =
					bodyEnd < text.length &&
					pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]!);
				if (
					bodyLen >= pattern.minLength &&
					bodyLen <= pattern.maxLength &&
					!trailingAlphaChar
				) {
					hits.push({
						start: idx,
						end: bodyEnd,
						body: text.slice(bodyStart, bodyEnd),
						patternName: pattern.name,
						alphabet: pattern.bodyAlphabet,
					});
					searchFrom = bodyEnd;
				} else {
					searchFrom = idx + 1;
				}
			}
		}

		if (hits.length === 0) return text;

		// Sort by text position and remove overlaps.
		hits.sort((a, b) => a.start - b.start);

		const parts: string[] = [];
		let cursor = 0;

		for (const hit of hits) {
			if (hit.start < cursor) continue; // skip overlap
			parts.push(text.slice(cursor, hit.start));
			const tweak = this.makeTweak(hit.patternName, extraTweak);
			const cipher = this.getCipher(hit.alphabet.radix, hit.body.length);
			parts.push(
				transformBody(hit.body, hit.alphabet, cipher, "decrypt", tweak),
			);
			cursor = hit.end;
		}

		parts.push(text.slice(cursor));
		return parts.join("");
	}

	register(pattern: TokenPattern): void {
		this.assertAlive();
		this.patterns.unshift(pattern);
	}

	destroy(): void {
		this.destroyed = true;
		this.key.fill(0);
		for (const cipher of this.cache.values()) cipher.destroy();
		this.cache.clear();
	}
}
