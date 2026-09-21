import { afterAll, describe, expect, test } from "bun:test";
import { FastCipher } from "../src/cipher.ts";
import { calculateRecommendedParams } from "../src/params.ts";
import {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	type Alphabet,
	BASE64URL,
	BUILTIN_PATTERNS,
	CycleWalkError,
	cycleWalk,
	DIGITS,
	HEX_LOWER,
	MAX_CYCLE_STEPS,
	MIN_SEGMENT_LENGTH,
	type StructuredTokenPattern,
	TokenEncryptor,
	TokenError,
	TokenFormatError,
	type TokenOptions,
	type TokenPattern,
	UnknownPatternError,
} from "../src/tokens/index.ts";
import { transformBody } from "../src/tokens/transformer.ts";

const KEY_07 = new Uint8Array(16).fill(0x07);

const SLACK_PLAIN = "xoxb-12345678-12345678-siXA";
const SLACK_ENCRYPTED = "xoxb-19234138-19234138-v20D";
const SLACK_3_STEPS_PLAIN = "xoxb-12345678-12345678-NxKQ";
const SLACK_3_STEPS_ENCRYPTED = "xoxb-19234138-19234138-LvrX";
const STRIPE_PLAIN = "sk_live_F9ZJz11XNvB3i0RhazAEAbGJdznewI9VguEStDdFtyHK";
const STRIPE_ENCRYPTED = "sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAKIAAAAAAAAAAAAAAAAA";
const FASTLY_PLAIN = "XhnOcYIP3GkYYKrJTKOrVLu6mQbbwF0t";
const FASTLY_ENCRYPTED = `[ENCRYPTED:fastly]${"A".repeat(32)}`;

const PROPERTY_KEYS = Number(process.env.TOKEN_PROPERTY_KEYS ?? 8);
const PROPERTY_SEED = 0x2026_0922;
const PROPERTY_TIMEOUT_MS = 600_000;

function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

function fnv1a(s: string): number {
	let h = 0x811c9dc5;
	for (let i = 0; i < s.length; i++) {
		h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
	}
	return h >>> 0;
}

class Rng {
	private readonly next: () => number;

	constructor(seed: number) {
		this.next = mulberry32(seed);
	}

	int(bound: number): number {
		return Math.floor(this.next() * bound);
	}

	between(min: number, max: number): number {
		return min + this.int(max - min + 1);
	}

	pick<T>(items: readonly T[]): T {
		return items[this.int(items.length)]!;
	}

	bytes(length: number): Uint8Array {
		const out = new Uint8Array(length);
		for (let i = 0; i < length; i++) out[i] = this.int(256);
		return out;
	}

	chars(alphabet: Alphabet, length: number): string {
		let out = "";
		for (let i = 0; i < length; i++)
			out += alphabet.chars[this.int(alphabet.radix)];
		return out;
	}

	withLetter(length: number): string {
		const s = this.chars(ALPHANUMERIC, length);
		if (!isDigits(s)) return s;
		const at = this.int(length);
		const letter = ALPHANUMERIC.chars[this.between(10, 61)]!;
		return s.slice(0, at) + letter + s.slice(at + 1);
	}
}

function isDigits(s: string): boolean {
	return /^\d+$/.test(s);
}

// These strings test nearby text without extending a token span.
const SURROUNDINGS: ReadonlyArray<readonly [string, string]> = [
	["", ""],
	["(", ")"],
	['"', '",'],
	["\u{1F511}", "\u{1F642}"],
	["clé secrète «", "», à ne pas partager."],
	["トークン「", "」を使う"],
	["密钥：", "。"],
	["señal \u{1F680} token='", "'; \u{1F9EA} fin\n"],
	["Authorization: Bearer ", "\r\nnaïve: üß"],
	["x=", ";y=é"],
];

function buildTweak(patternName: string, extra?: Uint8Array): Uint8Array {
	const name = new TextEncoder().encode(patternName);
	if (!extra || extra.length === 0) return name;
	const tweak = new Uint8Array(name.length + 1 + extra.length);
	tweak.set(name, 0);
	tweak.set(extra, name.length + 1);
	return tweak;
}

/** Calculates expected walks without using TokenEncryptor. */
class ReferenceWalker {
	private readonly ciphers = new Map<string, FastCipher>();

	constructor(private readonly key: Uint8Array) {}

	private cipher(radix: number, length: number): FastCipher {
		const id = `${radix}:${length}`;
		let cipher = this.ciphers.get(id);
		if (!cipher) {
			cipher = FastCipher.create(
				calculateRecommendedParams(radix, length),
				this.key,
			);
			this.ciphers.set(id, cipher);
		}
		return cipher;
	}

	permute(
		mode: "encrypt" | "decrypt",
		patternName: string,
		alphabet: Alphabet,
		value: string,
		extraTweak?: Uint8Array,
	): string {
		return transformBody(
			value,
			alphabet,
			this.cipher(alphabet.radix, value.length),
			mode,
			buildTweak(patternName, extraTweak),
		);
	}

	walk(
		mode: "encrypt" | "decrypt",
		patternName: string,
		alphabet: Alphabet,
		segment: string,
		inClass: (candidate: string) => boolean,
		extraTweak?: Uint8Array,
	): { output: string; steps: number; trail: string[] } {
		const trail = [segment];
		const { output, steps } = cycleWalk(
			segment,
			(value) => {
				const next = this.permute(
					mode,
					patternName,
					alphabet,
					value,
					extraTweak,
				);
				trail.push(next);
				return next;
			},
			inClass,
		);
		return { output, steps, trail };
	}
}

function readsBackAs(
	pattern: StructuredTokenPattern,
	segments: readonly string[],
	index: number,
	alphabet: Alphabet,
): (candidate: string) => boolean {
	return (candidate) => {
		const probe = [...segments];
		probe[index] = candidate;
		const again = pattern.parse(pattern.format(probe));
		return (
			again !== null &&
			again.segments[index] === candidate &&
			again.alphabets[index] === alphabet
		);
	};
}

const stats = {
	tokens: 0,
	heuristicSkipped: 0,
	walkedSegments: 0,
	histogram: new Map<number, number>(),
	maxSteps: 0,
	coldEncryptMs: 0,
	coldDecryptMs: 0,
	warmEncryptMs: 0,
	warmDecryptMs: 0,
	scanningDecryptMisses: 0,
};

function recordSteps(steps: number): void {
	stats.walkedSegments++;
	stats.histogram.set(steps, (stats.histogram.get(steps) ?? 0) + 1);
	stats.maxSteps = Math.max(stats.maxSteps, steps);
}

afterAll(() => {
	if (stats.tokens === 0) return;
	expect(stats.scanningDecryptMisses).toBe(0);
	const histogram = [...stats.histogram.entries()]
		.sort((a, b) => a[0] - b[0])
		.map(([steps, count]) => `${steps}:${count}`)
		.join(" ");
	const perToken = (ms: number) => (ms / stats.tokens).toFixed(3);
	console.log(
		[
			`[tokens-inverse] ${stats.tokens} tokens over ${PROPERTY_KEYS} keys per pattern`,
			`heuristic candidates skipped: ${stats.heuristicSkipped}`,
			`cycle-walked segments: ${stats.walkedSegments}, max steps: ${stats.maxSteps}, histogram (steps:count): ${histogram}`,
			`ms per token, fresh encryptor: encryptWithSpans ${perToken(stats.coldEncryptMs)}, decryptToken ${perToken(stats.coldDecryptMs)}`,
			`ms per token, warm encryptor: encryptToken ${perToken(stats.warmEncryptMs)}, decryptToken ${perToken(stats.warmDecryptMs)}`,
			`tokens that scanning decrypt() failed to restore: ${stats.scanningDecryptMisses}`,
		].join("\n"),
	);
});

function checkStructuredSpan(
	pattern: StructuredTokenPattern,
	original: string,
	encrypted: string,
	walker: ReferenceWalker,
	extraTweak?: Uint8Array,
): number {
	const plainBody = original.slice(pattern.prefix.length);
	const encryptedBody = encrypted.slice(pattern.prefix.length);
	const plain = pattern.parse(plainBody);
	const enc = pattern.parse(encryptedBody);
	if (!plain || !enc) throw new Error(`${pattern.name} did not parse`);

	expect(pattern.format(enc.segments)).toBe(encryptedBody);
	expect(enc.segments.map((s) => s.length)).toEqual(
		plain.segments.map((s) => s.length),
	);
	const mask = (segments: string[]) =>
		pattern.format(segments.map((s) => "#".repeat(s.length)));
	expect(mask(enc.segments)).toBe(mask(plain.segments));

	let maxSteps = 0;
	for (let i = 0; i < plain.segments.length; i++) {
		const plainSegment = plain.segments[i]!;
		const encryptedSegment = enc.segments[i]!;
		const alphabet = plain.alphabets[i]!;

		expect(enc.alphabets[i]).toBe(alphabet);
		if (pattern.name.startsWith("slack-")) {
			expect(isDigits(encryptedSegment)).toBe(isDigits(plainSegment));
		}

		if (plainSegment.length < MIN_SEGMENT_LENGTH) {
			expect(encryptedSegment).toBe(plainSegment);
			continue;
		}

		const forward = walker.walk(
			"encrypt",
			pattern.name,
			alphabet,
			plainSegment,
			readsBackAs(pattern, plain.segments, i, alphabet),
			extraTweak,
		);
		const backward = walker.walk(
			"decrypt",
			pattern.name,
			alphabet,
			encryptedSegment,
			readsBackAs(pattern, enc.segments, i, alphabet),
			extraTweak,
		);
		expect(forward.output).toBe(encryptedSegment);
		expect(backward.output).toBe(plainSegment);
		expect(backward.steps).toBe(forward.steps);
		expect(backward.trail).toEqual([...forward.trail].reverse());
		if (alphabet === DIGITS || pattern.name === "sendgrid") {
			expect(forward.steps).toBe(1);
		}
		recordSteps(forward.steps);
		maxSteps = Math.max(maxSteps, forward.steps);
	}
	return maxSteps;
}

/** Checks a token in surrounding text and returns its largest step count. */
function checkToken(
	pattern: TokenPattern,
	token: string,
	key: Uint8Array,
	rng: Rng,
	walker: ReferenceWalker,
	extraTweak?: Uint8Array,
): number | undefined {
	const [before, after] = rng.pick(SURROUNDINGS);
	const text = before + token + after;
	const options: TokenOptions | undefined = extraTweak
		? { tweak: extraTweak }
		: undefined;

	let t0 = performance.now();
	const encryptor = new TokenEncryptor(key);
	const result = encryptor.encryptWithSpans(text, options);
	const coldEncryptMs = performance.now() - t0;

	const twin = new TokenEncryptor(key);
	expect(twin.encryptWithSpans(text, options)).toEqual(result);
	twin.destroy();

	let rebuilt = "";
	let cursor = 0;
	let coldDecryptMs = 0;
	for (const span of result.spans) {
		expect(text.slice(span.start, span.end)).toBe(span.original);
		rebuilt += text.slice(cursor, span.start) + span.encrypted;
		cursor = span.end;

		t0 = performance.now();
		const fresh = new TokenEncryptor(key);
		const recovered = fresh.decryptToken(
			span.encrypted,
			span.patternName,
			options,
		);
		coldDecryptMs += performance.now() - t0;
		expect(recovered).toBe(span.original);
		fresh.destroy();
	}
	expect(rebuilt + text.slice(cursor)).toBe(result.text);

	const span = result.spans.find(
		(s) => s.patternName === pattern.name && s.original === token,
	);
	if (!span) {
		encryptor.destroy();
		return undefined;
	}
	expect(result.spans).toHaveLength(1);
	expect(span.start).toBe(before.length);
	expect(result.text).toBe(before + span.encrypted + after);

	if (pattern.kind === "heuristic") {
		const marker = `[ENCRYPTED:${pattern.name}]`;
		expect(span.encrypted.startsWith(marker)).toBe(true);
		const body = span.encrypted.slice(marker.length);
		expect(body).toHaveLength(token.length);
		for (const ch of body) {
			expect(pattern.bodyAlphabet.charToIndex.has(ch)).toBe(true);
		}
	} else {
		expect(span.encrypted.startsWith(pattern.prefix)).toBe(true);
		expect(span.encrypted).toHaveLength(token.length);
	}
	if (pattern.kind === "simple") {
		const body = span.encrypted.slice(pattern.prefix.length);
		expect(body).toMatch(new RegExp(`^(?:${pattern.bodyRegex})$`));
	}
	const maxSteps =
		pattern.kind === "structured"
			? checkStructuredSpan(pattern, token, span.encrypted, walker, extraTweak)
			: 1;

	t0 = performance.now();
	const mirrored = encryptor.encryptToken(token, pattern.name, options);
	const warmEncryptMs = performance.now() - t0;
	expect(mirrored).toBe(span.encrypted);

	t0 = performance.now();
	const warmRecovered = encryptor.decryptToken(mirrored, pattern.name, options);
	const warmDecryptMs = performance.now() - t0;
	expect(warmRecovered).toBe(token);

	if (encryptor.decrypt(result.text, options) !== text) {
		stats.scanningDecryptMisses++;
	}
	encryptor.destroy();

	stats.tokens++;
	stats.coldEncryptMs += coldEncryptMs;
	stats.coldDecryptMs += coldDecryptMs;
	stats.warmEncryptMs += warmEncryptMs;
	stats.warmDecryptMs += warmDecryptMs;
	return maxSteps;
}

function simpleBodyLengths(bodyRegex: string, minBodyLength: number): number[] {
	const quantifier = /\{(\d+)(,)?(\d*)\}$/.exec(bodyRegex);
	if (!quantifier) {
		throw new Error(`Teach the generator about the body regex ${bodyRegex}`);
	}
	const min = Math.max(Number(quantifier[1]), minBodyLength);
	if (!quantifier[2]) return [min];
	const max = quantifier[3] ? Number(quantifier[3]) : min + 40;
	return [...new Set([min, Math.min(min + 1, max), max])];
}

function slackBodies(
	pattern: StructuredTokenPattern,
	rng: Rng,
	walker: ReferenceWalker,
	extraTweak?: Uint8Array,
): string[] {
	const digits = () => rng.chars(DIGITS, rng.between(10, 13));

	const walkLength = rng.between(MIN_SEGMENT_LENGTH, MIN_SEGMENT_LENGTH + 2);
	let forcesWalk = rng.chars(DIGITS, walkLength);
	while (isDigits(forcesWalk)) {
		forcesWalk = walker.permute(
			"decrypt",
			pattern.name,
			ALPHANUMERIC,
			forcesWalk,
			extraTweak,
		);
	}

	const bodies = [
		`${digits()}-${digits()}-${rng.withLetter(24)}`,
		`${digits()}-${digits()}-${rng.withLetter(MIN_SEGMENT_LENGTH)}`,
		`${digits()}-${digits()}-${rng.chars(DIGITS, rng.between(MIN_SEGMENT_LENGTH, 12))}`,
		`${digits()}-${digits()}-${rng.withLetter(rng.between(1, MIN_SEGMENT_LENGTH - 1))}`,
		`${digits()}-${digits()}-${rng.chars(DIGITS, MIN_SEGMENT_LENGTH - 1)}`,
		`${rng.chars(DIGITS, 2)}-${rng.chars(DIGITS, 13)}-${rng.withLetter(rng.between(8, 32))}`,
		`${digits()}-${digits()}-${forcesWalk}`,
		`${rng.chars(DIGITS, 5)}-${digits()}-${rng.withLetter(5)}`,
	];
	if (pattern.name === "slack-user") {
		return [...bodies, ...bodies.map((body) => `${digits()}-${body}`)];
	}
	return bodies;
}

const STRUCTURED_BODIES: Record<
	string,
	(
		pattern: StructuredTokenPattern,
		rng: Rng,
		walker: ReferenceWalker,
		extraTweak?: Uint8Array,
	) => string[]
> = {
	"slack-bot": slackBodies,
	"slack-user": slackBodies,
	sendgrid: (_pattern, rng) => [
		`${rng.chars(BASE64URL, 22)}.${rng.chars(BASE64URL, 43)}`,
	],
};

function candidateTokens(
	pattern: TokenPattern,
	rng: Rng,
	walker: ReferenceWalker,
	extraTweak?: Uint8Array,
): string[] {
	if (pattern.kind === "simple") {
		const validator = new RegExp(`^(?:${pattern.bodyRegex})$`);
		return simpleBodyLengths(pattern.bodyRegex, pattern.minBodyLength).map(
			(length) => {
				const body = rng.chars(pattern.bodyAlphabet, length);
				expect(body).toMatch(validator);
				return pattern.prefix + body;
			},
		);
	}
	if (pattern.kind === "heuristic") {
		const lengths = new Set([
			pattern.minLength,
			pattern.maxLength,
			rng.between(pattern.minLength, pattern.maxLength),
		]);
		return [...lengths].map((length) =>
			rng.chars(pattern.bodyAlphabet, length),
		);
	}
	const bodies = STRUCTURED_BODIES[pattern.name];
	if (!bodies) {
		throw new Error(`Add a body generator for ${pattern.name}`);
	}
	return bodies(pattern, rng, walker, extraTweak).map(
		(body) => pattern.prefix + body,
	);
}

describe("regression vectors, key = 16 x 0x07", () => {
	test("slack: five-character segments round trip through every API", () => {
		const enc = new TokenEncryptor(KEY_07);
		for (const [prefix, name, count] of [
			["xoxb-", "slack-bot", 3],
			["xoxp-", "slack-user", 3],
			["xoxp-", "slack-user", 4],
		] as const) {
			for (let index = 0; index < count; index++) {
				const segments = Array<string>(count).fill("12345678");
				segments[count - 1] = "abcdefghi";
				segments[index] = index === count - 1 ? "abcde" : "12345";
				const token = prefix + segments.join("-");
				const text = `token=(${token})`;
				const encrypted = enc.encryptToken(token, name);
				expect(encrypted).not.toBe(token);
				expect(encrypted).toHaveLength(token.length);
				expect(enc.encrypt(text)).toBe(`token=(${encrypted})`);
				expect(enc.decryptToken(encrypted, name)).toBe(token);
				expect(enc.decrypt(`token=(${encrypted})`)).toBe(text);
			}
		}
		enc.destroy();
	});

	test("slack: four-segment user tokens encrypt the whole secret", () => {
		const enc = new TokenEncryptor(KEY_07);
		for (const secret of ["abcdefghij", "0123456789abcdef0123456789abcdef"]) {
			const token = `xoxp-12345678-12345678-12345678-${secret}`;
			const text = `before (${token}) after`;
			const result = enc.encryptWithSpans(text);
			expect(result.spans).toHaveLength(1);
			const span = result.spans[0]!;
			expect(span.original).toBe(token);
			expect(span.start).toBe("before (".length);
			expect(span.end).toBe("before (".length + token.length);
			expect(span.patternName).toBe("slack-user");
			expect(span.encrypted).toMatch(/^xoxp-\d{8}-\d{8}-\d{8}-[A-Za-z0-9]+$/);
			expect(span.encrypted).toHaveLength(token.length);
			expect(span.encrypted.split("-")[4]).not.toBe(secret);
			expect(result.text).not.toContain(secret);
			expect(enc.encrypt(text)).toBe(result.text);
			expect(enc.encryptToken(token, "slack-user")).toBe(span.encrypted);
			expect(enc.decryptToken(span.encrypted, "slack-user")).toBe(token);
			expect(enc.decrypt(result.text)).toBe(text);
		}
		enc.destroy();
	});

	test("slack: a final segment that encrypts to digits is cycle walked", () => {
		const result = new TokenEncryptor(KEY_07).encryptWithSpans(SLACK_PLAIN);
		expect(result.text).toBe(SLACK_ENCRYPTED);
		expect(result.spans).toEqual([
			{
				start: 0,
				end: SLACK_PLAIN.length,
				original: SLACK_PLAIN,
				encrypted: SLACK_ENCRYPTED,
				patternName: "slack-bot",
			},
		]);

		const fresh = new TokenEncryptor(KEY_07);
		expect(fresh.decryptToken(SLACK_ENCRYPTED, "slack-bot")).toBe(SLACK_PLAIN);
		expect(fresh.decrypt(SLACK_ENCRYPTED)).toBe(SLACK_PLAIN);
		expect(fresh.encryptToken(SLACK_PLAIN, "slack-bot")).toBe(SLACK_ENCRYPTED);
	});

	test("slack: intermediate walk values", () => {
		const walker = new ReferenceWalker(KEY_07);
		const hasLetter = (s: string) => !isDigits(s);

		const forward = walker.walk(
			"encrypt",
			"slack-bot",
			ALPHANUMERIC,
			"siXA",
			hasLetter,
		);
		expect(forward.trail).toEqual(["siXA", "1234", "v20D"]);
		expect(forward.steps).toBe(2);

		const backward = walker.walk(
			"decrypt",
			"slack-bot",
			ALPHANUMERIC,
			"v20D",
			hasLetter,
		);
		expect(backward.trail).toEqual(["v20D", "1234", "siXA"]);
		expect(backward.steps).toBe(2);
	});

	test("slack: a three step walk", () => {
		const walker = new ReferenceWalker(KEY_07);
		const forward = walker.walk(
			"encrypt",
			"slack-bot",
			ALPHANUMERIC,
			"NxKQ",
			(s) => !isDigits(s),
		);
		expect(forward.trail).toEqual(["NxKQ", "8271", "3894", "LvrX"]);

		const enc = new TokenEncryptor(KEY_07);
		expect(enc.encrypt(SLACK_3_STEPS_PLAIN)).toBe(SLACK_3_STEPS_ENCRYPTED);
		expect(enc.decryptToken(SLACK_3_STEPS_ENCRYPTED, "slack-bot")).toBe(
			SLACK_3_STEPS_PLAIN,
		);
		expect(enc.decrypt(SLACK_3_STEPS_ENCRYPTED)).toBe(SLACK_3_STEPS_PLAIN);
	});

	test("slack: the digits-only intermediate value is a token of its own", () => {
		// A numeric input must stay in the ten-digit alphabet.
		const enc = new TokenEncryptor(KEY_07);
		const token = "xoxb-12345678-12345678-1234";
		const encrypted = enc.encryptToken(token, "slack-bot");
		expect(encrypted).toMatch(/^xoxb-\d{8}-\d{8}-\d{4}$/);
		expect(encrypted).not.toBe(SLACK_ENCRYPTED);
		expect(enc.decryptToken(encrypted, "slack-bot")).toBe(token);
	});

	test("stripe: ciphertext containing AKIA is recovered by decryptToken", () => {
		const result = new TokenEncryptor(KEY_07).encryptWithSpans(STRIPE_PLAIN);
		expect(result.spans).toHaveLength(1);
		const span = result.spans[0]!;
		expect(span.patternName).toBe("stripe-secret-live");
		expect(span.encrypted).toBe(STRIPE_ENCRYPTED);
		expect(span.encrypted).toContain("AKIA");

		const fresh = new TokenEncryptor(KEY_07);
		expect(fresh.decryptToken(span.encrypted, span.patternName)).toBe(
			STRIPE_PLAIN,
		);
	});

	test("stripe: scanning decrypt() is not the inverse to rely on", () => {
		// The embedded AKIA prefix records a known scanner limitation.
		const enc = new TokenEncryptor(KEY_07);
		expect(enc.decrypt(STRIPE_ENCRYPTED)).not.toBe(STRIPE_PLAIN);
	});

	test("decryptToken ignores prefixes of patterns registered later", () => {
		const ciphertext = `sk_live_${"A".repeat(24)}ZZTOP${"B".repeat(21)}`;
		const enc = new TokenEncryptor(KEY_07);
		const plain = enc.decryptToken(ciphertext, "stripe-secret-live");
		expect(enc.decrypt(ciphertext)).toBe(plain);

		enc.register({
			kind: "simple",
			name: "later",
			prefix: "ZZTOP",
			bodyRegex: "[A-Za-z0-9]{21}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 21,
		});
		expect(enc.decrypt(ciphertext)).not.toBe(plain);
		expect(enc.decryptToken(ciphertext, "stripe-secret-live")).toBe(plain);
		expect(enc.encryptToken(plain, "stripe-secret-live")).toBe(ciphertext);
	});

	test("heuristic: low entropy ciphertext is decrypted", () => {
		const result = new TokenEncryptor(KEY_07).encryptWithSpans(FASTLY_PLAIN);
		expect(result.spans).toHaveLength(1);
		expect(result.spans[0]!.patternName).toBe("fastly");
		expect(result.spans[0]!.encrypted).toBe(FASTLY_ENCRYPTED);

		const fresh = new TokenEncryptor(KEY_07);
		expect(fresh.decryptToken(FASTLY_ENCRYPTED, "fastly")).toBe(FASTLY_PLAIN);
		expect(fresh.encryptToken(FASTLY_PLAIN, "fastly")).toBe(FASTLY_ENCRYPTED);
	});
});

describe("cycleWalk", () => {
	const next = (v: string) => String((Number(v) + 1) % 10);
	const previous = (v: string) => String((Number(v) + 9) % 10);
	const inClass = (v: string) => v === "0" || v === "5";

	test("walks until the class is reached, same count both ways", () => {
		const visited: string[] = [];
		const forward = cycleWalk(
			"0",
			(v) => {
				const out = next(v);
				visited.push(out);
				return out;
			},
			inClass,
		);
		expect(forward).toEqual({ output: "5", steps: 5 });
		expect(visited).toEqual(["1", "2", "3", "4", "5"]);

		const backward = cycleWalk(forward.output, previous, inClass);
		expect(backward).toEqual({ output: "0", steps: 5 });
	});

	test("is a permutation of the class", () => {
		const images = ["0", "5"].map((v) => cycleWalk(v, next, inClass).output);
		expect(images.sort()).toEqual(["0", "5"]);
	});

	test("a single step when the first output is already in the class", () => {
		expect(cycleWalk("4", next, inClass)).toEqual({ output: "5", steps: 1 });
	});

	test("the cap is inclusive and shared by both directions", () => {
		expect(cycleWalk("0", next, inClass, 5).steps).toBe(5);
		expect(cycleWalk("5", previous, inClass, 5).steps).toBe(5);
		expect(MAX_CYCLE_STEPS).toBe(32);
	});

	test("throws on exhaustion instead of returning a partial value", () => {
		let calls = 0;
		let result: unknown = "untouched";
		let caught: unknown;
		try {
			result = cycleWalk(
				"0",
				(v) => {
					calls++;
					return next(v);
				},
				inClass,
				4,
			);
		} catch (error) {
			caught = error;
		}
		expect(calls).toBe(4);
		expect(result).toBe("untouched");
		expect(caught).toBeInstanceOf(CycleWalkError);
		expect((caught as Error).message).toBe("Cycle walk did not converge");
		expect(() => cycleWalk("5", previous, inClass, 4)).toThrow(CycleWalkError);
	});

	test("the default cap applies to a class that is never reached", () => {
		let calls = 0;
		const step = (v: string) => {
			calls++;
			return next(v);
		};
		expect(() => cycleWalk("0", step, () => false)).toThrow(CycleWalkError);
		expect(calls).toBe(MAX_CYCLE_STEPS);
	});
});

// This pattern defines its alphabet rules only through parse() and format().
const ACME: StructuredTokenPattern = {
	kind: "structured",
	name: "acme",
	prefix: "acme_",
	trailingAlphabet: ALPHANUMERIC_LOWER,
	fullRegex: "acme_[a-z0-9]+(?:\\.[a-z0-9]+)+",
	parse(body) {
		const segments = body.split(".");
		if (segments.length < 2) return null;
		const alphabets: Alphabet[] = [];
		for (const segment of segments) {
			if (/^[0-9a-f]+$/.test(segment)) alphabets.push(HEX_LOWER);
			else if (/^[0-9a-z]+$/.test(segment)) alphabets.push(ALPHANUMERIC_LOWER);
			else return null;
		}
		return { segments, alphabets };
	},
	format(segments) {
		return segments.join(".");
	},
};

describe("custom structured pattern with only parse and format", () => {
	test("hex-looking outputs of a wider segment are walked past", () => {
		const rng = new Rng(PROPERTY_SEED ^ fnv1a(ACME.name));
		const key = rng.bytes(16);
		const enc = new TokenEncryptor(key);
		enc.register(ACME);
		const dec = new TokenEncryptor(key);
		dec.register(ACME);
		const walker = new ReferenceWalker(key);

		const histogram = new Map<number, number>();
		for (let n = 0; n < 1500; n++) {
			let wide = rng.chars(ALPHANUMERIC_LOWER, rng.between(4, 6));
			if (/^[0-9a-f]+$/.test(wide)) wide = `${wide.slice(1)}z`;
			const token = `acme_${rng.chars(HEX_LOWER, 8)}.${wide}.${rng.chars(ALPHANUMERIC_LOWER, 3)}`;
			const text = `\u{1F512} ${token} é`;

			const result = enc.encryptWithSpans(text);
			expect(result.spans).toHaveLength(1);
			const span = result.spans[0]!;
			expect(span.original).toBe(token);
			expect(dec.decryptToken(span.encrypted, "acme")).toBe(token);
			expect(dec.decrypt(result.text)).toBe(text);

			const plain = ACME.parse(token.slice(ACME.prefix.length))!;
			const encrypted = ACME.parse(span.encrypted.slice(ACME.prefix.length))!;
			expect(encrypted.alphabets).toEqual(plain.alphabets);
			expect(encrypted.segments[2]).toBe(plain.segments[2]);

			const forward = walker.walk(
				"encrypt",
				"acme",
				ALPHANUMERIC_LOWER,
				wide,
				readsBackAs(ACME, plain.segments, 1, ALPHANUMERIC_LOWER),
			);
			expect(forward.output).toBe(encrypted.segments[1]!);
			for (const skipped of forward.trail.slice(1, -1)) {
				expect(skipped).toMatch(/^[0-9a-f]+$/);
			}
			histogram.set(forward.steps, (histogram.get(forward.steps) ?? 0) + 1);
		}

		expect(histogram.get(1)).toBeGreaterThan(0);
		expect(histogram.get(2)).toBeGreaterThan(0);
		console.log(
			`[tokens-inverse] acme walk histogram (steps:count): ${[
				...histogram.entries(),
			]
				.sort((a, b) => a[0] - b[0])
				.map(([steps, count]) => `${steps}:${count}`)
				.join(" ")}`,
		);
		enc.destroy();
		dec.destroy();
	});

	test("a fresh encryptor inverts a walked token", () => {
		const rng = new Rng(PROPERTY_SEED ^ fnv1a("acme-fresh"));
		const key = rng.bytes(16);
		const walker = new ReferenceWalker(key);

		let wide = "0abc";
		while (/^[0-9a-f]+$/.test(wide)) {
			wide = walker.permute("decrypt", "acme", ALPHANUMERIC_LOWER, wide);
		}
		const token = `acme_0123abcd.${wide}`;

		const enc = new TokenEncryptor(key);
		enc.register(ACME);
		const encrypted = enc.encryptToken(token, "acme");
		expect(ACME.parse(encrypted.slice(5))!.alphabets[1]).toBe(
			ALPHANUMERIC_LOWER,
		);

		const fresh = new TokenEncryptor(key);
		fresh.register(ACME);
		expect(fresh.decryptToken(encrypted, "acme")).toBe(token);
	});

	test("an unreachable class fails closed", () => {
		// Only results starting with "zz" keep the wider alphabet.
		// Therefore, this fixture reaches the 32-step cap.
		const picky: StructuredTokenPattern = {
			...ACME,
			name: "picky",
			prefix: "picky_",
			fullRegex: "picky_[a-z0-9]+\\.[a-z0-9]+",
			parse(body) {
				const segments = body.split(".");
				if (segments.length !== 2) return null;
				return {
					segments,
					alphabets: segments.map((s) =>
						s.startsWith("zz") ? ALPHANUMERIC_LOWER : DIGITS,
					),
				};
			},
		};
		const enc = new TokenEncryptor(KEY_07);
		enc.register(picky);
		const text = "before picky_zzsecret.zzhidden after";

		expect(() => enc.encrypt(text)).toThrow(CycleWalkError);
		expect(() => enc.encryptWithSpans(text)).toThrow(CycleWalkError);
		expect(() => enc.encryptToken("picky_zzsecret.zzhidden", "picky")).toThrow(
			CycleWalkError,
		);
		expect(() => enc.decryptToken("picky_zzsecret.zzhidden", "picky")).toThrow(
			CycleWalkError,
		);
		try {
			enc.encrypt(text);
		} catch (error) {
			expect((error as Error).message).not.toContain("zz");
		}
	});

	test("an alphabet tied to another segment is refused, not mis-encrypted", () => {
		// The second segment's alphabet depends on the first.
		// Therefore, changing the first could make decryption ambiguous.
		const linked: StructuredTokenPattern = {
			...ACME,
			name: "linked",
			prefix: "linked_",
			trailingAlphabet: ALPHANUMERIC,
			fullRegex: "linked_[A-Za-z0-9]+\\.[A-Za-z0-9]+",
			parse(body) {
				const segments = body.split(".");
				if (segments.length !== 2) return null;
				const second = segments[0]!.startsWith("A") ? DIGITS : ALPHANUMERIC;
				return { segments, alphabets: [ALPHANUMERIC, second] };
			},
		};
		const enc = new TokenEncryptor(KEY_07);
		enc.register(linked);
		expect(() =>
			enc.encryptToken("linked_Abcdefgh.12345678", "linked"),
		).toThrow(TokenFormatError);
		expect(() => enc.encrypt("see linked_Abcdefgh.12345678.")).toThrow(
			TokenFormatError,
		);

		const independent = enc.encryptToken("linked_Bbcdefgh.12345678", "linked");
		expect(enc.decryptToken(independent, "linked")).toBe(
			"linked_Bbcdefgh.12345678",
		);
	});

	test("a pattern that cannot read its own segments back is rejected", () => {
		const lossy: StructuredTokenPattern = {
			...ACME,
			name: "lossy",
			prefix: "lossy_",
			fullRegex: "lossy_[a-z0-9]+\\.[a-z0-9]+",
			format(segments) {
				return segments.join("");
			},
		};
		const enc = new TokenEncryptor(KEY_07);
		enc.register(lossy);
		expect(() => enc.encryptToken("lossy_abcdef.ghijkl", "lossy")).toThrow(
			TokenFormatError,
		);
	});
});

describe("custom patterns with unsupported radices", () => {
	for (const radix of [2, 3, 257, 2.5, Number.NaN]) {
		const chars = Number.isInteger(radix)
			? Array.from({ length: radix }, (_, i) =>
					String.fromCharCode(48 + i),
				).join("")
			: "01";
		const alphabet: Alphabet = {
			name: "unsupported",
			chars,
			radix,
			charToIndex: new Map([...chars].map((char, index) => [char, index])),
		};
		const patterns: TokenPattern[] = [
			{
				kind: "simple",
				name: "custom-simple",
				prefix: "custom_",
				bodyRegex: "[01]{8}",
				bodyAlphabet: alphabet,
				minBodyLength: 8,
			},
			{
				kind: "heuristic",
				name: "custom-heuristic",
				prefix: "",
				bodyAlphabet: alphabet,
				minLength: 8,
				maxLength: 8,
				minEntropy: 0,
				minCharClasses: 0,
			},
			{
				kind: "structured",
				name: "custom-structured",
				prefix: "custom_",
				fullRegex: "custom_[01]{8}",
				trailingAlphabet: alphabet,
				parse(body) {
					return /^[01]{8}$/.test(body)
						? { segments: [body], alphabets: [alphabet] }
						: null;
				},
				format(segments) {
					return segments.join("");
				},
			},
		];
		for (const pattern of patterns) {
			test(`${pattern.kind}: radix ${radix} yields a token error without the input`, () => {
				const enc = new TokenEncryptor(KEY_07);
				enc.register(pattern);
				const body = "01011001";
				const plain = pattern.prefix + body;
				const encrypted =
					pattern.kind === "heuristic"
						? `[ENCRYPTED:${pattern.name}]${body}`
						: plain;
				const operations = [
					() => enc.encrypt(plain),
					() => enc.encryptWithSpans(plain),
					() => enc.encryptToken(plain, pattern.name),
					() => enc.decrypt(encrypted),
					() => enc.decryptToken(encrypted, pattern.name),
				];
				for (const operation of operations) {
					let caught: unknown;
					try {
						operation();
					} catch (error) {
						caught = error;
					}
					expect(caught).toBeInstanceOf(TokenError);
					expect(caught).not.toBeInstanceOf(TokenFormatError);
					expect((caught as Error).message).toBe(
						`Unsupported alphabet radix for ${pattern.name} pattern`,
					);
					expect(String(caught)).not.toContain(body);
				}
				enc.destroy();
			});
		}
	}
});

describe("decryptToken rejections", () => {
	const GITHUB = `ghp_${"aB3".repeat(12)}`;
	const SENDGRID = `SG.${"a".repeat(22)}.${"b".repeat(43)}`;

	function rejection(
		token: string,
		patternName: string,
		direction: "decryptToken" | "encryptToken" = "decryptToken",
	): Error {
		const enc = new TokenEncryptor(KEY_07);
		try {
			enc[direction](token, patternName);
		} catch (error) {
			return error as Error;
		} finally {
			enc.destroy();
		}
		throw new Error("expected a rejection");
	}

	const BOTH = ["decryptToken", "encryptToken"] as const;

	function expectMalformed(
		token: string,
		patternName: string,
		directions: ReadonlyArray<"decryptToken" | "encryptToken"> = BOTH,
	): void {
		for (const direction of directions) {
			const error = rejection(token, patternName, direction);
			expect(error).toBeInstanceOf(TokenFormatError);
			expect(error.message).toBe(`Malformed ${patternName} token`);
		}
	}

	test("well-formed tokens are accepted", () => {
		const enc = new TokenEncryptor(KEY_07);
		expect(enc.decryptToken(GITHUB, "github-pat")).toMatch(
			/^ghp_[A-Za-z0-9]{36}$/,
		);
		expect(enc.decryptToken(SENDGRID, "sendgrid")).toMatch(
			/^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/,
		);
	});

	test("unknown pattern", () => {
		const error = rejection(GITHUB, "github-pats");
		expect(error).toBeInstanceOf(UnknownPatternError);
		expect(error.message).toBe("Unknown token pattern");
	});

	test("swapped arguments do not leak the token", () => {
		const error = rejection("github-pat", GITHUB);
		expect(error).toBeInstanceOf(UnknownPatternError);
		expect(error.message).not.toContain(GITHUB);
		expect(error.message).not.toContain(GITHUB.slice(4, 12));
	});

	test("wrong prefix", () => {
		expectMalformed(`gho_${GITHUB.slice(4)}`, "github-pat");
		expectMalformed(GITHUB.slice(1), "github-pat");
		expectMalformed(` ${GITHUB}`, "github-pat");
		expectMalformed(`token=${GITHUB}`, "github-pat");
		expectMalformed("", "github-pat");
		expectMalformed("ghp_", "github-pat");
	});

	test("character outside the alphabet", () => {
		expectMalformed(`${GITHUB.slice(0, -1)}!`, "github-pat");
		expectMalformed(`${GITHUB.slice(0, -1)}_`, "github-pat");
		expectMalformed(`${GITHUB.slice(0, -1)}é`, "github-pat");
		expectMalformed(`sbp_${"a".repeat(39)}g`, "supabase");
		expectMalformed(`AKIA${"a".repeat(16)}`, "aws-access-key");
	});

	test("too short", () => {
		expectMalformed(GITHUB.slice(0, -1), "github-pat");
		expectMalformed(`sk_live_${"a".repeat(23)}`, "stripe-secret-live");
	});

	test("trailing garbage", () => {
		expectMalformed(`${GITHUB}x`, "github-pat");
		expectMalformed(`${GITHUB}\n`, "github-pat");
		expectMalformed(`${GITHUB} `, "github-pat");
		expectMalformed(`sk_live_${"a".repeat(30)}.`, "stripe-secret-live");
		expectMalformed(`sk_live_${"a".repeat(30)}\n`, "stripe-secret-live");
	});

	test("structured tokens", () => {
		expectMalformed(`${SENDGRID}c`, "sendgrid");
		expectMalformed(SENDGRID.slice(0, -1), "sendgrid");
		expectMalformed(SENDGRID.replace(".a", ".!"), "sendgrid");
		expectMalformed(`SG_${SENDGRID.slice(3)}`, "sendgrid");
		expectMalformed("xoxb-1-2-abc", "slack-bot");
		expectMalformed(`${SLACK_ENCRYPTED}-extra`, "slack-bot");
		expectMalformed(`${SLACK_ENCRYPTED}.`, "slack-bot");
		expectMalformed(SLACK_ENCRYPTED.replace("xoxb-", "xoxp-"), "slack-bot");
		expectMalformed("xoxb-1234567a-12345678-siXA", "slack-bot");
	});

	test("heuristic tokens need their exact marker", () => {
		const body = "A".repeat(32);
		expectMalformed(body, "fastly", ["decryptToken"]);
		expectMalformed(`[ENCRYPTED:aws-secret-key]${body}`, "fastly", [
			"decryptToken",
		]);
		expectMalformed(`[encrypted:fastly]${body}`, "fastly", ["decryptToken"]);
		expectMalformed(` [ENCRYPTED:fastly]${body}`, "fastly", ["decryptToken"]);
		expectMalformed(`[ENCRYPTED:fastly]${body.slice(1)}`, "fastly", [
			"decryptToken",
		]);
		expectMalformed(`[ENCRYPTED:fastly]${body}A`, "fastly", ["decryptToken"]);
		expectMalformed(`[ENCRYPTED:fastly]${body.slice(1)}+`, "fastly", [
			"decryptToken",
		]);
		expectMalformed(`[ENCRYPTED:fastly]${body} `, "fastly", ["decryptToken"]);
	});

	test("encryptToken takes the bare heuristic token, not the marked one", () => {
		const error = rejection(FASTLY_ENCRYPTED, "fastly", "encryptToken");
		expect(error).toBeInstanceOf(TokenFormatError);
		expect(rejection("A".repeat(31), "fastly", "encryptToken")).toBeInstanceOf(
			TokenFormatError,
		);
	});

	test("encryptToken does not apply the plaintext heuristics", () => {
		const enc = new TokenEncryptor(KEY_07);
		const dull = "A".repeat(32);
		expect(enc.encrypt(dull)).toBe(dull);
		const encrypted = enc.encryptToken(dull, "fastly");
		expect(encrypted.startsWith("[ENCRYPTED:fastly]")).toBe(true);
		expect(enc.decryptToken(encrypted, "fastly")).toBe(dull);
	});

	test("messages never contain the input", () => {
		const secret = "Zq9Xw7Vu5Ts3";
		const inputs: Array<[string, string]> = [
			[`ghp_${secret}`, "github-pat"],
			[`ghp_${secret.repeat(3)}!`, "github-pat"],
			[`nope_${secret.repeat(3)}`, "github-pat"],
			[`[ENCRYPTED:fastly]${secret}`, "fastly"],
			[`xoxb-${secret}`, "slack-bot"],
			[`SG.${secret}.${secret}`, "sendgrid"],
			[`ghp_${secret.repeat(3)}`, secret],
		];
		for (const [token, patternName] of inputs) {
			for (const direction of ["decryptToken", "encryptToken"] as const) {
				const error = rejection(token, patternName, direction);
				expect(error.message).not.toContain(secret);
				expect(error.message).not.toContain(secret.slice(0, 4));
				expect(String(error.stack).split("\n")[0]).not.toContain(secret);
			}
		}
	});

	test("the tweak is part of the inverse", () => {
		const enc = new TokenEncryptor(KEY_07);
		const tweak = new Uint8Array([1, 2, 3]);
		const span = enc.encryptWithSpans(GITHUB, { tweak }).spans[0]!;
		expect(enc.decryptToken(span.encrypted, "github-pat", { tweak })).toBe(
			GITHUB,
		);
		expect(enc.decryptToken(span.encrypted, "github-pat")).not.toBe(GITHUB);
		expect(
			enc.decryptToken(span.encrypted, "github-pat", {
				tweak: new Uint8Array(0),
			}),
		).toBe(enc.decryptToken(span.encrypted, "github-pat"));
	});

	test("registered patterns shadow built-in ones of the same name", () => {
		const enc = new TokenEncryptor(KEY_07);
		enc.register({
			kind: "simple",
			name: "github-pat",
			prefix: "mine_",
			bodyRegex: "[0-9]{12}",
			bodyAlphabet: DIGITS,
			minBodyLength: 12,
		});
		const encrypted = enc.encryptToken("mine_123456789012", "github-pat");
		expect(encrypted).toMatch(/^mine_\d{12}$/);
		expect(enc.decryptToken(encrypted, "github-pat")).toBe("mine_123456789012");
		expect(() => enc.decryptToken(GITHUB, "github-pat")).toThrow(
			TokenFormatError,
		);
	});

	test("destroyed encryptor", () => {
		const enc = new TokenEncryptor(KEY_07);
		enc.destroy();
		expect(() => enc.decryptToken(GITHUB, "github-pat")).toThrow("destroyed");
		expect(() => enc.encryptToken(GITHUB, "github-pat")).toThrow("destroyed");
	});
});

describe("property: a fresh encryptor inverts every emitted span", () => {
	for (const pattern of BUILTIN_PATTERNS) {
		test(
			pattern.name,
			() => {
				const rng = new Rng(PROPERTY_SEED ^ fnv1a(pattern.name));
				let verified = 0;
				let skipped = 0;
				let maxSteps = 0;

				for (let k = 0; k < PROPERTY_KEYS; k++) {
					const key = rng.bytes(16);
					const extraTweak =
						k % 2 === 1 ? rng.bytes(rng.between(1, 12)) : undefined;
					const walker = new ReferenceWalker(key);

					for (const token of candidateTokens(
						pattern,
						rng,
						walker,
						extraTweak,
					)) {
						const steps = checkToken(
							pattern,
							token,
							key,
							rng,
							walker,
							extraTweak,
						);
						if (steps === undefined) {
							skipped++;
						} else {
							verified++;
							maxSteps = Math.max(maxSteps, steps);
						}
					}
				}

				if (pattern.kind === "heuristic") {
					stats.heuristicSkipped += skipped;
					expect(verified).toBeGreaterThan(skipped);
				} else {
					expect(skipped).toBe(0);
				}
				expect(verified).toBeGreaterThan(0);
				if (pattern.name.startsWith("slack-")) {
					expect(maxSteps).toBeGreaterThanOrEqual(2);
				}
			},
			PROPERTY_TIMEOUT_MS,
		);
	}
});
