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
	TOKEN67,
} from "./alphabets.ts";
import { cycleWalk } from "./cyclewalk.ts";
import {
	TokenError,
	TokenFormatError,
	UnknownPatternError,
	WrappedTokenFormatError,
} from "./errors.ts";
import { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
import { scan } from "./scanner.ts";
import { transformBody } from "./transformer.ts";
import type {
	HeuristicTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
	TokenSpan,
} from "./types.ts";
import {
	formatStructured,
	heuristicMarker,
	parseStructured,
	segmentClass,
	tokenBody,
} from "./validate.ts";
import {
	assertWrappable,
	isPreserveMode,
	resolveMaxTokenLength,
	unwrapText,
	WRAPPED_OPENER,
	type WrappedDecryptResult,
	WrappedTokenCipher,
	wrapperTweak,
} from "./wrapped.ts";

export type { CycleWalkResult } from "./cyclewalk.ts";
export { cycleWalk, MAX_CYCLE_STEPS } from "./cyclewalk.ts";
export {
	CycleWalkError,
	TokenError,
	TokenFormatError,
	UnknownPatternError,
	WrappedTokenFormatError,
	WrappedTokenIntegrityError,
} from "./errors.ts";
export { BUILTIN_PATTERNS, MIN_SEGMENT_LENGTH } from "./registry.ts";
export { scan } from "./scanner.ts";
export type {
	Alphabet,
	HeuristicTokenPattern,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
	TokenSpan,
} from "./types.ts";
export type { WrappedDecryptResult } from "./wrapped.ts";
export {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	ALPHANUMERIC_UPPER,
	BASE64,
	BASE64URL,
	DIGITS,
	HEX_LOWER,
	TOKEN67,
};

export interface TokenEncryptorOptions {
	types?: string[];
	tweak?: Uint8Array;
}

export interface TokenOptions {
	/** Use the same tweak for encryption and decryption. */
	tweak?: Uint8Array;
}

export interface EncryptedSpan {
	/** Zero-based start offset in the original text. */
	start: number;
	/** Exclusive end offset in the original text. */
	end: number;
	original: string;
	/** Includes the marker for heuristic patterns. */
	encrypted: string;
	patternName: string;
}

export interface EncryptResult {
	text: string;
	spans: EncryptedSpan[];
}

export interface WrappedEncryptOptions {
	/** Names of the patterns to detect; all registered patterns by default. */
	types?: string[];
	/** Pass the same tweak to `decryptWrapped()`. */
	tweak?: Uint8Array;
	/** Longest token to wrap, an integer from 2 to 4096; 512 by default. */
	maxTokenLength?: number;
}

export interface WrappedDecryptOptions {
	/** The tweak given to `encryptWrapped()`. */
	tweak?: Uint8Array;
	/** Longest token to accept, an integer from 2 to 4096; 512 by default. */
	maxTokenLength?: number;
	/**
	 * `"throw"`, the default, rejects the whole text if any candidate is
	 * invalid.
	 * `"preserve"` leaves invalid candidates unchanged and counts them.
	 */
	onInvalid?: "throw" | "preserve";
}

type Mode = "encrypt" | "decrypt";

interface MarkerHit {
	start: number;
	end: number;
	body: string;
	pattern: HeuristicTokenPattern;
}

const AES_KEY_SIZE = 16;
const textEncoder = new TextEncoder();

export class TokenEncryptor {
	private readonly key: Uint8Array;
	private readonly cache = new Map<string, FastCipher>();
	private readonly patterns: TokenPattern[];
	private wrapped: WrappedTokenCipher | null = null;
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

	private getCipher(
		pattern: TokenPattern,
		radix: number,
		wordLength: number,
	): FastCipher {
		if (!Number.isInteger(radix) || radix < 4 || radix > 256) {
			throw new TokenError(
				`Unsupported alphabet radix for ${pattern.name} pattern`,
			);
		}
		if (wordLength < 2) {
			throw new TokenFormatError(pattern.name);
		}
		this.assertAlive();
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

	/**
	 * Decrypt the tokens found by scanning `text`.
	 *
	 * Encrypted text can contain another pattern's prefix by chance.
	 * Use saved encrypted values and pattern names with `decryptToken()` when
	 * recovery must be reliable.
	 */
	decrypt(text: string, options?: TokenEncryptorOptions): string {
		this.assertAlive();
		const patterns = this.activePatterns(options);
		const prefixPatterns = patterns.filter((p) => p.kind !== "heuristic");
		const heuristicPatterns = patterns.filter((p) => p.kind === "heuristic");

		const spans =
			prefixPatterns.length === 0
				? []
				: scan(text, prefixPatterns, this.patterns);
		const heuristicHits =
			heuristicPatterns.length === 0
				? []
				: this.findHeuristicMarkerHits(text, heuristicPatterns);
		if (spans.length === 0 && heuristicHits.length === 0) return text;

		const parts: string[] = [];
		let cursor = 0;
		let spanIndex = 0;
		let hitIndex = 0;

		while (spanIndex < spans.length || hitIndex < heuristicHits.length) {
			const span = spanIndex < spans.length ? spans[spanIndex]! : undefined;
			const hit =
				hitIndex < heuristicHits.length ? heuristicHits[hitIndex]! : undefined;

			if (hit && (!span || hit.start < span.start)) {
				if (hit.start >= cursor) {
					parts.push(text.slice(cursor, hit.start));
					parts.push(
						this.transform(hit.pattern, hit.body, "decrypt", options?.tweak),
					);
					cursor = hit.end;
				}
				hitIndex++;
				continue;
			}

			const nextSpan = spans[spanIndex]!;
			if (nextSpan.start >= cursor) {
				parts.push(text.slice(cursor, nextSpan.start));
				parts.push(
					nextSpan.pattern.prefix +
						this.transform(
							nextSpan.pattern,
							nextSpan.body,
							"decrypt",
							options?.tweak,
						),
				);
				cursor = nextSpan.end;
			}
			spanIndex++;
		}

		parts.push(text.slice(cursor));
		return parts.join("");
	}

	/**
	 * Encrypt one complete token with a named pattern.
	 *
	 * The result matches the encrypted value returned by `encryptWithSpans()`.
	 *
	 * @throws UnknownPatternError if no registered pattern has that name.
	 * @throws TokenFormatError if `plaintext` is not a complete token of the pattern.
	 */
	encryptToken(
		plaintext: string,
		patternName: string,
		options?: TokenOptions,
	): string {
		this.assertAlive();
		const pattern = this.patternByName(patternName);
		const body = tokenBody(pattern, plaintext, "plain");
		return (
			this.encryptedLead(pattern) +
			this.transform(pattern, body, "encrypt", options?.tweak)
		);
	}

	/**
	 * Decrypt one complete token with a named pattern.
	 *
	 * Use this with the encrypted value and pattern name from `encryptWithSpans()`
	 * when recovery must be reliable.
	 * Heuristic tokens must include their `[ENCRYPTED:<name>]` marker.
	 *
	 * @throws UnknownPatternError if no registered pattern has that name.
	 * @throws TokenFormatError if `ciphertext` is not a complete token of the pattern.
	 */
	decryptToken(
		ciphertext: string,
		patternName: string,
		options?: TokenOptions,
	): string {
		this.assertAlive();
		const pattern = this.patternByName(patternName);
		const body = tokenBody(pattern, ciphertext, "encrypted");
		return (
			pattern.prefix + this.transform(pattern, body, "decrypt", options?.tweak)
		);
	}

	private patternByName(patternName: string): TokenPattern {
		const pattern = this.patterns.find((p) => p.name === patternName);
		if (!pattern) throw new UnknownPatternError();
		return pattern;
	}

	private encryptedLead(pattern: TokenPattern): string {
		return pattern.kind === "heuristic"
			? heuristicMarker(pattern.name)
			: pattern.prefix;
	}

	private encryptSpan(span: TokenSpan, extraTweak?: Uint8Array): string {
		const { pattern, body } = span;
		return (
			this.encryptedLead(pattern) +
			this.transform(pattern, body, "encrypt", extraTweak)
		);
	}

	private transform(
		pattern: TokenPattern,
		body: string,
		mode: Mode,
		extraTweak?: Uint8Array,
	): string {
		const tweak = this.makeTweak(pattern.name, extraTweak);
		if (pattern.kind === "structured") {
			return this.transformStructured(pattern, body, mode, tweak);
		}
		const cipher = this.getCipher(
			pattern,
			pattern.bodyAlphabet.radix,
			body.length,
		);
		return transformBody(body, pattern.bodyAlphabet, cipher, mode, tweak);
	}

	private transformStructured(
		pattern: StructuredTokenPattern,
		body: string,
		mode: Mode,
		tweak: Uint8Array,
	): string {
		const parsed = parseStructured(pattern, body);
		const transformed = [...parsed.segments];

		for (let i = 0; i < parsed.segments.length; i++) {
			const segment = parsed.segments[i]!;
			if (segment.length < MIN_SEGMENT_LENGTH) continue;

			const alphabet = parsed.alphabets[i]!;
			const cipher = this.getCipher(pattern, alphabet.radix, segment.length);
			transformed[i] = cycleWalk(
				segment,
				(value) => transformBody(value, alphabet, cipher, mode, tweak),
				segmentClass(pattern, parsed, i),
			).output;
		}

		return formatStructured(pattern, transformed, parsed.alphabets);
	}

	private findHeuristicMarkerHits(
		text: string,
		patterns: readonly TokenPattern[],
	): MarkerHit[] {
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
						pattern,
					});
					searchFrom = bodyEnd;
				} else {
					searchFrom = idx + 1;
				}
			}
		}

		hits.sort((a, b) => a.start - b.start);
		return hits;
	}

	/**
	 * Replace every detected token with `{ENCRYPTED:<payload>}`.
	 *
	 * Each complete token, prefix and separators included, is encrypted with
	 * eight check symbols, so the replacement is 20 characters longer.
	 * `decryptWrapped()` recovers the text without the pattern registry.
	 * Encrypt only new plaintext: text that already contains `{ENCRYPTED:`
	 * is rejected.
	 *
	 * @throws WrappedTokenFormatError if the text contains `{ENCRYPTED:`, or
	 * a detected token is too short, longer than `maxTokenLength`, or uses a
	 * symbol outside `TOKEN67`.
	 */
	encryptWrapped(text: string, options?: WrappedEncryptOptions): string {
		this.assertAlive();
		const maxTokenLength = resolveMaxTokenLength(options?.maxTokenLength);
		if (options?.types !== undefined && !Array.isArray(options.types)) {
			throw new TypeError("types must be an array of pattern names");
		}
		const tweak = wrapperTweak(options?.tweak);
		try {
			if (text.includes(WRAPPED_OPENER)) {
				throw new WrappedTokenFormatError(
					"Text already contains an encrypted token opener",
				);
			}

			const spans = scan(text, this.activePatterns(options), this.patterns);
			for (const span of spans) {
				assertWrappable(text.slice(span.start, span.end), maxTokenLength);
			}

			const parts: string[] = [];
			let cursor = 0;
			for (const span of spans) {
				const token = text.slice(span.start, span.end);
				parts.push(
					text.slice(cursor, span.start),
					this.wrappedCipher().wrap(token, tweak),
				);
				cursor = span.end;
			}
			parts.push(text.slice(cursor));
			return parts.join("");
		} finally {
			tweak.fill(0);
		}
	}

	/**
	 * Replace every `{ENCRYPTED:<payload>}` wrapper with its token.
	 *
	 * Only wrappers are recognized, so registered patterns do not matter.
	 * Each wrapper must decrypt with its check symbols intact.
	 * In the default `"throw"` mode, any invalid candidate throws and no text
	 * is returned.
	 *
	 * @throws WrappedTokenFormatError for a candidate without a closing brace,
	 * with a symbol outside `TOKEN67`, or with a bad payload length.
	 * @throws WrappedTokenIntegrityError for a wrapper that fails its check.
	 */
	decryptWrapped(
		text: string,
		options: WrappedDecryptOptions & { onInvalid: "preserve" },
	): WrappedDecryptResult;
	decryptWrapped(
		text: string,
		options?: WrappedDecryptOptions & { onInvalid?: "throw" },
	): string;
	decryptWrapped(
		text: string,
		options?: WrappedDecryptOptions,
	): string | WrappedDecryptResult;
	decryptWrapped(
		text: string,
		options?: WrappedDecryptOptions,
	): string | WrappedDecryptResult {
		this.assertAlive();
		const maxTokenLength = resolveMaxTokenLength(options?.maxTokenLength);
		const preserve = isPreserveMode(options?.onInvalid);
		const tweak = wrapperTweak(options?.tweak);
		try {
			const result = unwrapText(text, maxTokenLength, preserve, (payload) =>
				this.wrappedCipher().unwrap(payload, tweak),
			);
			return preserve ? result : result.text;
		} finally {
			tweak.fill(0);
		}
	}

	private wrappedCipher(): WrappedTokenCipher {
		this.assertAlive();
		this.wrapped ??= WrappedTokenCipher.create(this.key);
		return this.wrapped;
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
		this.wrapped?.destroy();
		this.wrapped = null;
	}
}
