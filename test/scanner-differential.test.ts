import { describe, expect, test } from "bun:test";
import {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	ALPHANUMERIC_UPPER,
	type Alphabet,
	BASE64,
	BASE64URL,
	BUILTIN_PATTERNS,
	DIGITS,
	HEX_LOWER,
	scan,
	TokenEncryptor,
	type TokenPattern,
	type TokenSpan,
	WrappedTokenFormatError,
} from "../src/tokens/index.ts";
import { ADVERSARIAL_TEXTS, AWS_KEY, SAMPLE_TOKENS } from "./helpers.ts";
import { referenceScan } from "./reference-scanner.ts";

const KEY = new Uint8Array(16).map((_, i) => i);

function mulberry32(seed: number): () => number {
	let state = seed;
	return () => {
		state = (state + 0x6d2b79f5) | 0;
		let t = Math.imul(state ^ (state >>> 15), 1 | state);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

function simple(
	name: string,
	prefix: string,
	bodyRegex: string,
	bodyAlphabet: Alphabet,
	minBodyLength: number,
): TokenPattern {
	return {
		kind: "simple",
		name,
		prefix,
		bodyRegex,
		bodyAlphabet,
		minBodyLength,
	};
}

// Only the first six can be checked by length alone; the others need their regex.
const CUSTOM_PATTERNS: TokenPattern[] = [
	simple("bounded", "tok_", "[A-Za-z0-9]{8,12}", ALPHANUMERIC, 8),
	simple("hex-open", "zz", "[0-9a-f]{0,}", HEX_LOWER, 4),
	simple("negated", "neg:", "[^\\s]{10,}", BASE64, 10),
	simple("fixed-escaped", "esc.", "[\\w\\-]{12}", BASE64URL, 12),
	simple("longer-minimum", "lm_", "[A-Za-z0-9]{2,}", ALPHANUMERIC, 10),
	simple("maybe-empty", "up:", "[A-Z0-9]{0,}", ALPHANUMERIC_UPPER, 0),
	simple("strict-upper", "foo_", "[A-Z]{8}", ALPHANUMERIC, 8),
	simple("fixed-char", "key-", "X[A-Z0-9]{7}", ALPHANUMERIC_UPPER, 8),
	simple("alternation", "alt_", "[a-z]{8}|[0-9]{8}", ALPHANUMERIC_LOWER, 8),
	simple("stricter-open", "sk-x", "[A-Z0-9]{6,}", BASE64URL, 6),
	simple("strict-longer-minimum", "slm_", "[A-Z]{2,}", ALPHANUMERIC, 10),
	simple("strict-maybe-empty", "me_", "(?:[A-Z]{4})*", ALPHANUMERIC_UPPER, 0),
	{
		kind: "structured",
		name: "dotted",
		prefix: "ab-",
		fullRegex: "ab-[0-9]+\\.[A-Za-z0-9]+",
		trailingAlphabet: ALPHANUMERIC,
		parse(body) {
			const parts = body.split(".");
			if (parts.length !== 2 || !/^[0-9]+$/.test(parts[0]!)) return null;
			if (!/^[A-Za-z0-9]+$/.test(parts[1]!) || body.length < 8) return null;
			return { segments: parts, alphabets: [DIGITS, ALPHANUMERIC] };
		},
		format(segments) {
			return segments.join(".");
		},
	},
];

const WITH_CUSTOM = [...CUSTOM_PATTERNS, ...BUILTIN_PATTERNS];

function pick(names: string[], from: readonly TokenPattern[]): TokenPattern[] {
	return from.filter((p) => names.includes(p.name));
}

const PATTERN_SETS: {
	name: string;
	patterns: readonly TokenPattern[];
	all?: readonly TokenPattern[];
}[] = [
	{ name: "built-in", patterns: BUILTIN_PATTERNS },
	{ name: "custom", patterns: WITH_CUSTOM },
	{
		name: "filtered built-in",
		patterns: pick(
			["aws-access-key", "openai", "slack-bot", "vercel", "twilio"],
			BUILTIN_PATTERNS,
		),
		all: BUILTIN_PATTERNS,
	},
	{
		name: "filtered custom",
		patterns: pick(
			["strict-upper", "bounded", "dotted", "google-api", "grafana"],
			WITH_CUSTOM,
		),
		all: WITH_CUSTOM,
	},
	{
		name: "empty prefix",
		patterns: [
			simple("bare-upper", "", "[A-Z0-9]{16}", ALPHANUMERIC_UPPER, 16),
			simple("bare-digits", "", "[0-9]{6,}", DIGITS, 6),
			...BUILTIN_PATTERNS,
		],
	},
];

function describeSpans(spans: TokenSpan[]): string[] {
	return spans.map((s) => `${s.pattern.name}@${s.start}-${s.end}:${s.body}`);
}

function expectSameAsReference(
	text: string,
	patterns: readonly TokenPattern[],
	all?: readonly TokenPattern[],
): void {
	const actual = describeSpans(scan(text, patterns, all));
	const expected = describeSpans(referenceScan(text, patterns, all));
	if (actual.join("\n") !== expected.join("\n")) {
		expect({ text, actual }).toEqual({ text, actual: expected });
	}
}

const PREFIXES = [
	...new Set(WITH_CUSTOM.map((p) => p.prefix).filter((p) => p.length > 0)),
];
const RUN_ALPHABETS = [
	ALPHANUMERIC_UPPER,
	BASE64URL,
	ALPHANUMERIC,
	HEX_LOWER,
	DIGITS,
	ALPHANUMERIC_LOWER,
	BASE64,
];
const SEPARATORS = [" ", "-", "_", ".", "\n", "=", "/", "+", ":", '"'];
const SLACK_PARTS = ["1-2-", "123-4567-", "1-2-3-", "12-", "-"];
const WHOLE_TOKENS = [
	...Object.values(SAMPLE_TOKENS),
	AWS_KEY,
	`AIza${"C".repeat(35)}`,
];

function randomText(random: () => number, maxLength: number): string {
	const choose = <T>(items: readonly T[]): T =>
		items[Math.floor(random() * items.length)]!;
	const target = 1 + Math.floor(random() * maxLength);
	let text = "";
	while (text.length < target) {
		const r = random();
		if (r < 0.35) {
			text += choose(PREFIXES);
		} else if (r < 0.7) {
			const { chars } = choose(RUN_ALPHABETS);
			const length = 1 + Math.floor(random() * 40);
			const uniform = random() < 0.3 ? choose([...chars]) : "";
			for (let i = 0; i < length; i++) text += uniform || choose([...chars]);
		} else if (r < 0.8) {
			text += choose(SEPARATORS);
		} else if (r < 0.9) {
			text += choose(SLACK_PARTS);
		} else {
			text += choose(WHOLE_TOKENS);
		}
	}
	return text;
}

describe("scanner matches the 0.3.0 reference", () => {
	for (const set of PATTERN_SETS) {
		test(`random texts, ${set.name} patterns`, () => {
			const random = mulberry32(0x5eed + set.name.length);
			for (let i = 0; i < 1500; i++) {
				expectSameAsReference(randomText(random, 240), set.patterns, set.all);
			}
		});
	}

	test("every prefix, then a short run, then a whole token", () => {
		const tokens = [
			AWS_KEY,
			`AIza${"C".repeat(35)}`,
			SAMPLE_TOKENS["github-pat"]!,
			SAMPLE_TOKENS["slack-bot"]!,
			SAMPLE_TOKENS.sendgrid!,
			SAMPLE_TOKENS.twilio!,
			SAMPLE_TOKENS.openai!,
			"ab-12.CDEFGH",
		];
		for (const prefix of PREFIXES) {
			for (const fill of ["A", "a", "7"]) {
				for (let length = 0; length <= 12; length++) {
					for (const token of tokens) {
						for (const tail of ["", "Z", " "]) {
							const text = prefix + fill.repeat(length) + token + tail;
							expectSameAsReference(text, WITH_CUSTOM);
						}
					}
				}
			}
		}
	});

	test("a prefix given to a heuristic pattern still ends a structured token", () => {
		const heuristic = BUILTIN_PATTERNS.find((p) => p.kind === "heuristic")!;
		const prefixed = { ...heuristic, name: "prefixed", prefix: "Zq" };
		const patterns = [prefixed as TokenPattern, ...BUILTIN_PATTERNS];
		const text = `${SAMPLE_TOKENS.sendgrid}Zq`;
		expectSameAsReference(text, patterns);
		expect(scan(text, patterns).map((s) => s.pattern.name)).toEqual([
			"sendgrid",
		]);
	});

	test("adversarial families up to 600 characters", () => {
		for (const make of Object.values(ADVERSARIAL_TEXTS)) {
			for (let size = 20; size <= 600; size += 29) {
				const text = make(size);
				expectSameAsReference(text, BUILTIN_PATTERNS);
				expectSameAsReference(text, WITH_CUSTOM);
			}
		}
	});

	test("adversarial families cut at every length up to 120", () => {
		for (const make of Object.values(ADVERSARIAL_TEXTS)) {
			for (let size = 12; size <= 120; size++) {
				expectSameAsReference(make(size), BUILTIN_PATTERNS);
			}
		}
	});
});

describe("a split never moves to shorten an overlong token", () => {
	const vercelThenKeys = (keys: number): string =>
		`vercel_${"A".repeat(20)}${AWS_KEY.repeat(keys)}`;

	test("the body of the Vercel token is split at the last AWS key", () => {
		const text = vercelThenKeys(40);
		expect(describeSpans(scan(text, BUILTIN_PATTERNS))).toEqual([
			`vercel@0-807:${text.slice(7, 807)}`,
			`aws-access-key@807-827:${"B".repeat(16)}`,
		]);
	});

	test("wrapping rejects the 807-character Vercel token", () => {
		const encryptor = new TokenEncryptor(KEY);
		try {
			expect(() => encryptor.encryptWrapped(vercelThenKeys(40))).toThrow(
				WrappedTokenFormatError,
			);
		} finally {
			encryptor.destroy();
		}
	});

	test("around the 512-character limit, only the length decides", () => {
		const encryptor = new TokenEncryptor(KEY);
		try {
			for (let keys = 20; keys <= 30; keys++) {
				const text = vercelThenKeys(keys);
				expectSameAsReference(text, BUILTIN_PATTERNS);
				const vercelLength = 7 + 20 * keys;
				if (vercelLength > 512) {
					expect(() => encryptor.encryptWrapped(text)).toThrow(
						WrappedTokenFormatError,
					);
				} else {
					const wrapped = encryptor.encryptWrapped(text);
					expect(wrapped.match(/\{ENCRYPTED:/g)?.length).toBe(2);
					expect(encryptor.decryptWrapped(wrapped)).toBe(text);
				}
			}
		} finally {
			encryptor.destroy();
		}
	});
});

describe("custom body regexes", () => {
	const find = (text: string, pattern: TokenPattern) =>
		describeSpans(scan(text, [pattern, ...BUILTIN_PATTERNS]));

	test("a class narrower than the alphabet is still checked", () => {
		const pattern = CUSTOM_PATTERNS.find((p) => p.name === "strict-upper")!;
		expect(find("foo_ABCDEFGH", pattern)).toEqual([
			"strict-upper@0-12:ABCDEFGH",
		]);
		expect(find("foo_ABCDEFgH", pattern)).toEqual([]);
		expect(find(`foo_ABCDEFGH${AWS_KEY}`, pattern)).toEqual([
			"strict-upper@0-12:ABCDEFGH",
			`aws-access-key@12-32:${"B".repeat(16)}`,
		]);
		expect(find(`foo_ABCDEFgH${AWS_KEY}`, pattern)).toEqual([
			`aws-access-key@12-32:${"B".repeat(16)}`,
		]);
	});

	test("a fixed character in the body is still checked", () => {
		const pattern = CUSTOM_PATTERNS.find((p) => p.name === "fixed-char")!;
		expect(find("key-XABC1234", pattern)).toEqual(["fixed-char@0-12:XABC1234"]);
		expect(find("key-YABC1234", pattern)).toEqual([]);
		expect(find(`key-XABC1234${AWS_KEY}`, pattern)).toEqual([
			"fixed-char@0-12:XABC1234",
			`aws-access-key@12-32:${"B".repeat(16)}`,
		]);
		expect(find(`key-YABC1234${AWS_KEY}`, pattern)).toEqual([
			`aws-access-key@12-32:${"B".repeat(16)}`,
		]);
	});

	test("an upper length bound limits where a body can be split", () => {
		const pattern = CUSTOM_PATTERNS.find((p) => p.name === "bounded")!;
		const within = `tok_${"a".repeat(12)}${AWS_KEY}`;
		const beyond = `tok_${"a".repeat(13)}${AWS_KEY}`;
		expect(find(within, pattern)).toEqual([
			`bounded@0-16:${"a".repeat(12)}`,
			`aws-access-key@16-36:${"B".repeat(16)}`,
		]);
		expect(find(beyond, pattern)).toEqual([
			`aws-access-key@17-37:${"B".repeat(16)}`,
		]);
	});

	test("a token can start at the last character of a body", () => {
		const inner = simple("inner", "a-", "[0-9]{2}", DIGITS, 2);
		const text = `x${"b".repeat(3)}a-12`;
		for (const bodyRegex of ["[a-z]{3,}", "[a-z0-9]{3,}"]) {
			const outer = simple("outer", "x", bodyRegex, ALPHANUMERIC_LOWER, 3);
			expectSameAsReference(text, [outer, inner]);
			expect(describeSpans(scan(text, [outer, inner]))).toEqual([
				"outer@0-4:bbb",
				"inner@4-8:12",
			]);
		}
	});

	test("a class missing any one alphabet character is still checked", () => {
		for (const [bodyRegex, rejected] of [
			["[1-9]{4}", "0000"],
			["[02-9]{4}", "1111"],
			["[0-8]{4}", "9999"],
		] as const) {
			const pattern = simple("partial", "n:", bodyRegex, DIGITS, 4);
			expect(describeSpans(scan("n:2345", [pattern]))).toEqual([
				"partial@0-6:2345",
			]);
			expect(describeSpans(scan(`n:${rejected}`, [pattern]))).toEqual([]);
		}
	});

	test("an invalid body regex still throws", () => {
		const broken = simple("broken", "brk_", "[A-Z{8}", ALPHANUMERIC, 8);
		expect(() => scan("brk_ABCDEFGH", [broken])).toThrow(SyntaxError);
	});
});
