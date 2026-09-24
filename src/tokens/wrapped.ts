import { deriveSBoxPool, FastCipher } from "../cipher.ts";
import { encodeParts } from "../encoding.ts";
import { deriveKey } from "../prf.ts";
import { type SBoxPool, wipeSBoxPool } from "../sbox.ts";
import type { FastParams } from "../types.ts";
import { TOKEN67 } from "./alphabets.ts";
import {
	WrappedTokenFormatError,
	WrappedTokenIntegrityError,
} from "./errors.ts";
import { charsToIndices, indicesToChars } from "./transformer.ts";
import { isInAlphabet } from "./validate.ts";

export const WRAPPED_OPENER = "{ENCRYPTED:";
const WRAPPED_CLOSER = "}";

/**
 * Eight zero indices appended to every token before encryption.
 * Decryption must find them again before releasing the token.
 */
const CHECK_SUFFIX = "00000000";
const CHECK_SYMBOLS = CHECK_SUFFIX.length;

const MIN_WRAPPED_TOKEN_LENGTH = 2;
const DEFAULT_MAX_WRAPPED_TOKEN_LENGTH = 512;
const MAX_WRAPPED_TOKEN_LENGTH = 4096;
const MIN_PAYLOAD_LENGTH = MIN_WRAPPED_TOKEN_LENGTH + CHECK_SYMBOLS;

const RADIX = 67;
const SBOX_COUNT = 256;
const SECURITY_LEVEL = 128;
const WRAPPER_KEY_SIZE = 16;

const textEncoder = new TextEncoder();
const WRAPPER_KEY_INPUT = encodeParts([
	textEncoder.encode("fast-cipher/tokens/wrapped/v1/key"),
]);
const WRAPPER_TWEAK_LABEL = textEncoder.encode(
	"fast-cipher/tokens/wrapped/v1/tweak",
);

// Version 1 freezes these rows of the FAST round table instead of following
// later changes to calculateRecommendedParams().
const ROUND_WORD_LENGTHS = [
	2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100,
];
const ROUNDS_RADIX_16 = [
	67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47,
];
const ROUNDS_RADIX_100 = [
	40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44,
];
const RADIX_67_WEIGHT =
	(Math.log(67) - Math.log(16)) / (Math.log(100) - Math.log(16));

function interpolateRounds(row: readonly number[], n: number): number {
	const last = ROUND_WORD_LENGTHS.length - 1;
	if (n <= ROUND_WORD_LENGTHS[0]!) return row[0]!;
	if (n >= ROUND_WORD_LENGTHS[last]!) {
		return row[last]! * Math.sqrt(n / ROUND_WORD_LENGTHS[last]!);
	}

	let i = 1;
	while (n > ROUND_WORD_LENGTHS[i]!) i++;
	const x0 = ROUND_WORD_LENGTHS[i - 1]!;
	const x1 = ROUND_WORD_LENGTHS[i]!;
	const y0 = row[i - 1]!;
	return y0 + ((n - x0) / (x1 - x0)) * (row[i]! - y0);
}

/** FAST parameters for a wrapped word of `n` symbols, token plus check. */
export function wrappedParams(n: number): FastParams {
	const r16 = interpolateRounds(ROUNDS_RADIX_16, n);
	const r100 = interpolateRounds(ROUNDS_RADIX_100, n);
	const rawRounds = r16 + RADIX_67_WEIGHT * (r100 - r16);
	const branchDist1 = n <= 2 ? 0 : Math.min(Math.ceil(Math.sqrt(n)), n - 2);
	const branchDist2 = Math.min(
		branchDist1 > 1 ? branchDist1 - 1 : 1,
		n - branchDist1 - 1,
	);

	return {
		radix: RADIX,
		wordLength: n,
		sboxCount: SBOX_COUNT,
		numLayers: Math.ceil(Math.max(1, rawRounds)) * n,
		branchDist1,
		branchDist2,
		securityLevel: SECURITY_LEVEL,
	};
}

export function deriveWrapperKey(masterKey: Uint8Array): Uint8Array {
	return deriveKey(masterKey, WRAPPER_KEY_INPUT, WRAPPER_KEY_SIZE);
}

/**
 * Build the FAST tweak for wrapped tokens.
 * An omitted tweak and an empty one give the same result.
 */
export function wrapperTweak(tweak?: Uint8Array): Uint8Array {
	if (tweak !== undefined && !(tweak instanceof Uint8Array)) {
		throw new TypeError("tweak must be a Uint8Array");
	}
	return encodeParts([WRAPPER_TWEAK_LABEL, tweak ?? new Uint8Array(0)]);
}

export function resolveMaxTokenLength(value: number | undefined): number {
	if (value === undefined) return DEFAULT_MAX_WRAPPED_TOKEN_LENGTH;
	if (
		!Number.isSafeInteger(value) ||
		value < MIN_WRAPPED_TOKEN_LENGTH ||
		value > MAX_WRAPPED_TOKEN_LENGTH
	) {
		throw new RangeError(
			`maxTokenLength must be an integer from ${MIN_WRAPPED_TOKEN_LENGTH} to ${MAX_WRAPPED_TOKEN_LENGTH}`,
		);
	}
	return value;
}

export function isPreserveMode(value: string | undefined): boolean {
	if (value === undefined || value === "throw") return false;
	if (value === "preserve") return true;
	throw new RangeError('onInvalid must be "throw" or "preserve"');
}

export function assertWrappable(token: string, maxTokenLength: number): void {
	if (token.length < MIN_WRAPPED_TOKEN_LENGTH) {
		throw new WrappedTokenFormatError("Token is too short to wrap");
	}
	if (token.length > maxTokenLength) {
		throw new WrappedTokenFormatError(
			"Token is longer than maxTokenLength allows",
		);
	}
	if (!isInAlphabet(token, TOKEN67)) {
		throw new WrappedTokenFormatError(
			"Token contains a symbol outside TOKEN67",
		);
	}
}

/**
 * Encrypts and decrypts wrapped tokens for one master key.
 *
 * The derived key and S-box pool are kept until `destroy()`.
 * Every token gets a transient FAST context that borrows the pool and is
 * destroyed before the call returns, so no sequence outlives its token.
 */
export class WrappedTokenCipher {
	private destroyed = false;

	private constructor(
		private readonly key: Uint8Array,
		private readonly pool: SBoxPool,
	) {}

	static create(masterKey: Uint8Array): WrappedTokenCipher {
		const key = deriveWrapperKey(masterKey);
		try {
			const pool = deriveSBoxPool({ radix: RADIX, sboxCount: SBOX_COUNT }, key);
			return new WrappedTokenCipher(key, pool);
		} catch (error) {
			key.fill(0);
			throw error;
		}
	}

	/** Return the complete wrapper for a token accepted by `assertWrappable()`. */
	wrap(token: string, tweak: Uint8Array): string {
		const word = charsToIndices(token + CHECK_SUFFIX, TOKEN67);
		try {
			const ciphertext = this.transform(word, "encrypt", tweak);
			return (
				WRAPPED_OPENER + indicesToChars(ciphertext, TOKEN67) + WRAPPED_CLOSER
			);
		} finally {
			word.fill(0);
		}
	}

	/**
	 * Return the token encrypted in `payload`, or `null` if its check symbols
	 * are not all zero after decryption.
	 */
	unwrap(payload: string, tweak: Uint8Array): string | null {
		const word = this.transform(
			charsToIndices(payload, TOKEN67),
			"decrypt",
			tweak,
		);
		try {
			const tokenLength = word.length - CHECK_SYMBOLS;
			let check = 0;
			for (let i = tokenLength; i < word.length; i++) {
				check |= word[i]!;
			}
			if (check !== 0) return null;
			return indicesToChars(word.subarray(0, tokenLength), TOKEN67);
		} finally {
			word.fill(0);
		}
	}

	private transform(
		word: Uint8Array,
		mode: "encrypt" | "decrypt",
		tweak: Uint8Array,
	): Uint8Array {
		if (this.destroyed) {
			throw new Error("Wrapped token cipher has been destroyed");
		}
		const cipher = FastCipher.withSharedPool(
			wrappedParams(word.length),
			this.key,
			this.pool,
		);
		try {
			return mode === "encrypt"
				? cipher.encrypt(word, tweak)
				: cipher.decrypt(word, tweak);
		} finally {
			cipher.destroy();
		}
	}

	destroy(): void {
		this.destroyed = true;
		this.key.fill(0);
		wipeSBoxPool(this.pool);
	}
}

export type WrappedFraming =
	| "valid"
	| "unterminated"
	| "too-short"
	| "too-long";

export interface WrappedCandidate {
	/** Offset of the opener. */
	start: number;
	/** Exclusive end, including the closing brace when there is one. */
	end: number;
	/** The payload starts right after the opener. */
	payloadEnd: number;
	framing: WrappedFraming;
}

const FRAMING_MESSAGES: Record<Exclude<WrappedFraming, "valid">, string> = {
	unterminated: "Encrypted token has an invalid symbol or no closing brace",
	"too-short": "Encrypted token is too short",
	"too-long": "Encrypted token is longer than maxTokenLength allows",
};

/**
 * Yield every `{ENCRYPTED:` opener and the candidate that follows it.
 *
 * The payload is the longest run of `TOKEN67` symbols after the opener.
 * The first other character ends it, and is part of the candidate only if it
 * is `}`.
 * The next search starts at that character, so a stray opener cannot hide
 * the wrappers after it.
 */
export function* wrappedCandidates(
	text: string,
	maxTokenLength: number,
): Generator<WrappedCandidate> {
	const maxPayloadLength = maxTokenLength + CHECK_SYMBOLS;

	let start = text.indexOf(WRAPPED_OPENER);
	while (start !== -1) {
		const payloadStart = start + WRAPPED_OPENER.length;
		let payloadEnd = payloadStart;
		while (TOKEN67.charToIndex.has(text[payloadEnd]!)) payloadEnd++;

		const closed = text[payloadEnd] === WRAPPED_CLOSER;
		const length = payloadEnd - payloadStart;
		let framing: WrappedFraming = "valid";
		if (!closed) framing = "unterminated";
		else if (length < MIN_PAYLOAD_LENGTH) framing = "too-short";
		else if (length > maxPayloadLength) framing = "too-long";

		const end = closed ? payloadEnd + 1 : payloadEnd;
		yield { start, end, payloadEnd, framing };
		start = text.indexOf(WRAPPED_OPENER, end);
	}
}

export interface WrappedDecryptResult {
	text: string;
	/** Invalid candidates left unchanged in `text`. */
	preservedCandidates: number;
}

/**
 * Replace every verified wrapper in `text` with its token.
 *
 * `open` returns the token for a well-framed payload, or `null` if its check
 * fails.
 * Without `preserve`, a framing error throws before any payload is opened,
 * and the first failed check throws too.
 * With `preserve`, invalid candidates stay unchanged and are counted.
 */
export function unwrapText(
	text: string,
	maxTokenLength: number,
	preserve: boolean,
	open: (payload: string) => string | null,
): WrappedDecryptResult {
	if (!preserve) {
		for (const candidate of wrappedCandidates(text, maxTokenLength)) {
			if (candidate.framing !== "valid") {
				throw new WrappedTokenFormatError(FRAMING_MESSAGES[candidate.framing]);
			}
		}
	}

	const parts: string[] = [];
	let cursor = 0;
	let preservedCandidates = 0;
	for (const candidate of wrappedCandidates(text, maxTokenLength)) {
		const token =
			candidate.framing === "valid"
				? open(
						text.slice(
							candidate.start + WRAPPED_OPENER.length,
							candidate.payloadEnd,
						),
					)
				: null;
		if (token === null) {
			if (!preserve) throw new WrappedTokenIntegrityError();
			// Left in place; the next slice copies it unchanged.
			preservedCandidates++;
			continue;
		}
		parts.push(text.slice(cursor, candidate.start), token);
		cursor = candidate.end;
	}
	parts.push(text.slice(cursor));

	return { text: parts.join(""), preservedCandidates };
}
