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
	WrappedTokenFormatError,
} from "../src/tokens/index.ts";
import { AWS_KEY, describeSpans, KEY, wrappersIn } from "./helpers.ts";

const awsAt = (start: number): string =>
	`aws-access-key@${start}-${start + AWS_KEY.length}:${AWS_KEY.slice(4)}`;

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

test("a structured pattern that can match nothing finds no empty tokens", () => {
	const caps: TokenPattern = {
		kind: "structured",
		name: "caps",
		prefix: "",
		fullRegex: "[A-Z]*",
		trailingAlphabet: ALPHANUMERIC_UPPER,
		parse: (body) => ({ segments: [body], alphabets: [ALPHANUMERIC_UPPER] }),
		format: (segments) => segments.join(""),
	};
	expect(describeSpans(scan("", [caps]))).toEqual([]);
	expect(describeSpans(scan("ab CD", [caps]))).toEqual(["caps@3-5:CD"]);
});

describe("a split never moves to shorten an overlong token", () => {
	const vercelThenKeys = (keys: number): string =>
		`vercel_${"A".repeat(20)}${AWS_KEY.repeat(keys)}`;

	test("the body of the Vercel token is split at the last AWS key", () => {
		const text = vercelThenKeys(40);
		expect(describeSpans(scan(text, BUILTIN_PATTERNS))).toEqual([
			`vercel@0-807:${text.slice(7, 807)}`,
			awsAt(807),
		]);
	});

	test("around the 512-character limit, only the length decides", () => {
		const encryptor = new TokenEncryptor(KEY);
		try {
			for (let keys = 20; keys <= 30; keys++) {
				const text = vercelThenKeys(keys);
				const vercelLength = 7 + 20 * keys;
				if (vercelLength > 512) {
					expect(() => encryptor.encryptWrapped(text)).toThrow(
						WrappedTokenFormatError,
					);
				} else {
					const wrapped = encryptor.encryptWrapped(text);
					expect(wrappersIn(wrapped)).toHaveLength(2);
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

	for (const [title, pattern, valid, invalid] of [
		[
			"a class narrower than the alphabet",
			simple("strict-upper", "foo_", "[A-Z]{8}", ALPHANUMERIC, 8),
			"ABCDEFGH",
			"ABCDEFgH",
		],
		[
			"a fixed character in the body",
			simple("fixed-char", "key-", "X[A-Z0-9]{7}", ALPHANUMERIC_UPPER, 8),
			"XABC1234",
			"YABC1234",
		],
	] as const) {
		test(`${title} is still checked`, () => {
			const span = `${pattern.name}@0-12:${valid}`;
			const aws = awsAt(12);
			expect(find(pattern.prefix + valid, pattern)).toEqual([span]);
			expect(find(pattern.prefix + invalid, pattern)).toEqual([]);
			expect(find(pattern.prefix + valid + AWS_KEY, pattern)).toEqual([
				span,
				aws,
			]);
			expect(find(pattern.prefix + invalid + AWS_KEY, pattern)).toEqual([aws]);

			const outer = `sk-proj-${"A".repeat(48)}${pattern.prefix}${invalid}`;
			expect(find(outer, pattern)).toEqual([
				`openai@0-${outer.length}:${outer.slice(8)}`,
			]);
		});
	}

	test("an upper length bound limits where a body can be split", () => {
		const pattern = simple(
			"bounded",
			"tok_",
			"[A-Za-z0-9]{8,12}",
			ALPHANUMERIC,
			8,
		);
		expect(find(`tok_${"a".repeat(12)}${AWS_KEY}`, pattern)).toEqual([
			`bounded@0-16:${"a".repeat(12)}`,
			awsAt(16),
		]);
		expect(find(`tok_${"a".repeat(13)}${AWS_KEY}`, pattern)).toEqual([
			awsAt(17),
		]);
	});

	for (const bodyRegex of ["[A-Za-z0-9_-]{8}", "X[A-Za-z0-9_-]{7}"]) {
		test(`a body matching ${bodyRegex} keeps its own trailing dashes`, () => {
			const pattern = simple("punctuated", "tok:", bodyRegex, BASE64URL, 8);
			const token = "tok:XAAA___-";
			expect(find(`${token}__--${AWS_KEY}`, pattern)).toEqual([
				"punctuated@0-12:XAAA___-",
				awsAt(16),
			]);
			for (const suffix of ["-", "__--AKIAshort", `A-${AWS_KEY}`]) {
				const names = scan(token + suffix, [pattern, ...BUILTIN_PATTERNS]).map(
					(s) => s.pattern.name,
				);
				expect(names).not.toContain("punctuated");
			}
		});
	}

	test("a token can start at the last character of a body", () => {
		const inner = simple("inner", "a-", "[0-9]{2}", DIGITS, 2);
		const text = `x${"b".repeat(3)}a-12`;
		for (const bodyRegex of ["[a-z]{3,}", "[a-z0-9]{3,}"]) {
			const outer = simple("outer", "x", bodyRegex, ALPHANUMERIC_LOWER, 3);
			expect(describeSpans(scan(text, [outer, inner]))).toEqual([
				"outer@0-4:bbb",
				"inner@4-8:12",
			]);
		}
	});

	test("length limits and minBodyLength are both enforced", () => {
		for (const [pattern, body] of [
			[simple("hex-open", "zz", "[0-9a-f]{0,}", HEX_LOWER, 4), "0a1b"],
			[simple("negated", "neg:", "[^\\s]{10,}", BASE64, 10), "ab+/cd+/ef"],
			[
				simple("escaped", "esc.", "[\\w\\-]{12}", BASE64URL, 12),
				"ab_-cd_-ef_-",
			],
			[
				simple("minimum", "lm_", "[A-Za-z0-9]{2,}", ALPHANUMERIC, 10),
				"abcdefghij",
			],
			[
				simple("strict-minimum", "slm_", "[A-Z]{2,}", ALPHANUMERIC, 10),
				"ABCDEFGHIJ",
			],
			[
				simple(
					"alternation",
					"alt_",
					"[a-z]{8}|[0-9]{8}",
					ALPHANUMERIC_LOWER,
					8,
				),
				"abcdefgh",
			],
		] as const) {
			const token = pattern.prefix + body;
			const span = `${pattern.name}@0-${token.length}:${body}`;
			expect(find(token, pattern)).toEqual([span]);
			expect(find(token.slice(0, -1), pattern)).toEqual([]);
			expect(find(token + AWS_KEY, pattern)).toEqual([
				span,
				awsAt(token.length),
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
