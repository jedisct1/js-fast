import { describe, expect, expectTypeOf, spyOn, test } from "bun:test";
import { FastCipher } from "../src/cipher.ts";
import { calculateRecommendedParams } from "../src/params.ts";
import { generateSBoxPool, type SBoxPool } from "../src/sbox.ts";
import {
	ALPHANUMERIC,
	BUILTIN_PATTERNS,
	type HeuristicTokenPattern,
	TOKEN67,
	TokenEncryptor,
	TokenError,
	type TokenPattern,
	type WrappedDecryptOptions,
	type WrappedDecryptResult,
	WrappedTokenFormatError,
	WrappedTokenIntegrityError,
} from "../src/tokens/index.ts";
import { escapeRegex } from "../src/tokens/registry.ts";
import {
	deriveWrapperKey,
	unwrapText,
	WrappedTokenCipher,
	wrappedCandidates,
	wrappedParams,
	wrapperTweak,
} from "../src/tokens/wrapped.ts";
import shared from "./fixtures/wrapped-tokens-v1.json";
import { decodeSecret, hex, SAMPLE_TOKENS } from "./helpers.ts";

const KEY = Uint8Array.from({ length: 16 }, (_, i) => i);
const OTHER_KEY = Uint8Array.from({ length: 16 }, (_, i) => 0x10 + i);
const OPENER = "{ENCRYPTED:";

function toHex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

/** Matches whole runs of TOKEN67 symbols, so any string of them can be wrapped. */
function anyToken(name = "any"): HeuristicTokenPattern {
	return {
		kind: "heuristic",
		name,
		prefix: "",
		bodyAlphabet: TOKEN67,
		minLength: 1,
		maxLength: 5000,
		minEntropy: 0,
		minCharClasses: 0,
	};
}

function wrapperFor(
	token: string,
	options: {
		key?: Uint8Array;
		tweak?: Uint8Array;
		maxTokenLength?: number;
	} = {},
): string {
	const enc = new TokenEncryptor(options.key ?? KEY);
	enc.register(anyToken());
	const wrapped = enc.encryptWrapped(token, {
		types: ["any"],
		tweak: options.tweak,
		maxTokenLength: options.maxTokenLength,
	});
	enc.destroy();
	return wrapped;
}

function wrappersIn(text: string): string[] {
	return text.match(/\{ENCRYPTED:[^}]*\}/g) ?? [];
}

function thrown(run: () => unknown): Error {
	try {
		run();
	} catch (error) {
		return error as Error;
	}
	throw new Error("expected an exception");
}

function payloadOfLength(length: number): string {
	return Array.from(
		{ length },
		(_, i) => TOKEN67.chars[(i * 31 + 7) % 67],
	).join("");
}

function countSetups(run: () => void): number {
	const create = spyOn(WrappedTokenCipher, "create");
	try {
		run();
		return create.mock.calls.length;
	} finally {
		create.mockRestore();
	}
}

/** Record the transient contexts created while `run` executes. */
function withContextSpy<T>(run: () => T): {
	result: T;
	contexts: FastCipher[];
	calls: unknown[][];
} {
	const spy = spyOn(FastCipher, "withSharedPool");
	try {
		const result = run();
		return {
			result,
			contexts: spy.mock.results.map((r) => r.value as FastCipher),
			calls: spy.mock.calls,
		};
	} finally {
		spy.mockRestore();
	}
}

function isDestroyed(cipher: FastCipher): boolean {
	try {
		cipher.encrypt(new Uint8Array(cipher.params.wordLength));
		return false;
	} catch (error) {
		return (error as Error).message === "Cipher has been destroyed";
	}
}

describe("wire format", () => {
	test("TOKEN67 uses the documented symbols in order", () => {
		expect(TOKEN67.chars).toBe(
			"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/-_.",
		);
		expect(TOKEN67.radix).toBe(67);
		expect(new Set(TOKEN67.chars).size).toBe(67);
		expect(TOKEN67.chars.slice(62)).toBe("+/-_.");
		for (const excluded of ["{", "}", ":", "="]) {
			expect(TOKEN67.charToIndex.has(excluded)).toBe(false);
		}
		expect(shared.alphabet).toBe(TOKEN67.chars);
	});

	test("the frozen parameters match the integer fixtures", () => {
		for (const row of shared.parameters) {
			expect(wrappedParams(row.wordLength)).toMatchObject({
				...row,
				radix: 67,
				sboxCount: 256,
				securityLevel: 128,
			});
		}
	});

	test("the frozen recipe still equals calculateRecommendedParams(67, n)", () => {
		for (let n = 10; n <= 4104; n++) {
			expect(wrappedParams(n)).toEqual(calculateRecommendedParams(67, n));
		}
	});

	for (const vector of shared.vectors) {
		test(`shared vector: ${vector.description}`, () => {
			const tweak = vector.tweak === null ? undefined : hex(vector.tweak);
			const maxTokenLength =
				"maxTokenLength" in vector ? vector.maxTokenLength : undefined;
			const masterKey = hex(vector.masterKey);

			expect(toHex(deriveWrapperKey(masterKey))).toBe(vector.wrapperKey);
			expect(toHex(wrapperTweak(tweak))).toBe(vector.wrapperTweak);
			expect(wrappedParams(vector.plaintext.length + 8)).toMatchObject(
				vector.params,
			);

			expect(vector.wrapped).toBe(`${OPENER}${vector.payload}}`);
			expect(vector.wrapped).toHaveLength(vector.plaintext.length + 20);
			expect(
				wrapperFor(vector.plaintext, { key: masterKey, tweak, maxTokenLength }),
			).toBe(vector.wrapped);

			const fresh = new TokenEncryptor(masterKey);
			expect(
				fresh.decryptWrapped(vector.wrapped, { tweak, maxTokenLength }),
			).toBe(vector.plaintext);
			fresh.destroy();
		});
	}

	test("shared invalid wrappers fail their check", () => {
		for (const vector of shared.invalid) {
			const enc = new TokenEncryptor(hex(vector.masterKey));
			const tweak = vector.tweak === null ? undefined : hex(vector.tweak);
			expect(
				thrown(() => enc.decryptWrapped(vector.wrapped, { tweak })),
			).toBeInstanceOf(WrappedTokenIntegrityError);
			expect(
				enc.decryptWrapped(vector.wrapped, { tweak, onInvalid: "preserve" }),
			).toEqual({ text: vector.wrapped, preservedCandidates: 1 });
			enc.destroy();
		}
	});

	test("shared documents decrypt as recorded", () => {
		const enc = new TokenEncryptor(KEY);
		for (const doc of shared.documents) {
			const strict: { text?: string; error?: string } = doc.strict;
			if (strict.error !== undefined) {
				expect(thrown(() => enc.decryptWrapped(doc.text)).name).toBe(
					strict.error,
				);
			} else {
				expect(enc.decryptWrapped(doc.text)).toBe(strict.text!);
			}
			expect(enc.decryptWrapped(doc.text, { onInvalid: "preserve" })).toEqual(
				doc.preserve,
			);
		}
		enc.destroy();
	});

	test("the check suffix is eight zero symbols inside the encryption", () => {
		const cipher = WrappedTokenCipher.create(KEY);
		const tweak = wrapperTweak();
		const payload = cipher.wrap("ab", tweak).slice(OPENER.length, -1);
		const params = wrappedParams(payload.length);
		const fast = FastCipher.create(params, deriveWrapperKey(KEY));
		const word = fast.decrypt(
			Uint8Array.from(payload, (ch) => TOKEN67.charToIndex.get(ch)!),
			tweak,
		);
		expect([...word]).toEqual([36, 37, 0, 0, 0, 0, 0, 0, 0, 0]);
		fast.destroy();
		cipher.destroy();
	});
});

describe("framing parser", () => {
	const valid = `${OPENER}${"a".repeat(10)}}`;

	test("classifies candidates without decrypting them", () => {
		const text = `x${valid}${OPENER}abc=${OPENER}}${OPENER}${"b".repeat(521)}}${OPENER}tail`;
		expect(
			[...wrappedCandidates(text, 512)].map((c) => [
				c.start,
				c.end,
				c.payloadEnd,
				c.framing,
			]),
		).toEqual([
			[1, 23, 22, "valid"],
			[23, 37, 37, "unterminated"],
			[38, 50, 49, "too-short"],
			[50, 583, 582, "too-long"],
			[583, 598, 598, "unterminated"],
		]);
	});

	test("a candidate ends at the first symbol outside TOKEN67", () => {
		const alphabet = new Set(TOKEN67.chars);
		const boundaries = [
			...Array.from({ length: 128 }, (_, code) => String.fromCharCode(code)),
			"é",
			"\u{1F600}",
			"\uD800",
		].filter((ch) => !alphabet.has(ch));
		expect(boundaries.length).toBe(128 - 67 + 3);

		const open = (payload: string) =>
			payload === "a".repeat(10) ? "ok" : null;
		for (const boundary of boundaries) {
			const text = `${OPENER}abc${boundary}${valid}`;
			const [first] = [...wrappedCandidates(text, 512)];
			expect(first!.payloadEnd).toBe(OPENER.length + 3);
			const consumed = boundary === "}";
			expect(first!.end).toBe(OPENER.length + 3 + (consumed ? 1 : 0));
			expect(unwrapText(text, 512, true, open)).toEqual({
				text: `${OPENER}abc${boundary}ok`,
				preservedCandidates: 1,
			});
		}

		expect(unwrapText(`${OPENER}abc${valid}`, 512, true, open)).toEqual({
			text: `${OPENER}abcok`,
			preservedCandidates: 1,
		});
	});

	test("every opener starts a candidate, even an empty one", () => {
		const text = `${OPENER}${OPENER}${OPENER}}`;
		expect([...wrappedCandidates(text, 512)].map((c) => c.framing)).toEqual([
			"unterminated",
			"unterminated",
			"too-short",
		]);
		expect(unwrapText(text, 512, true, () => "never")).toEqual({
			text,
			preservedCandidates: 3,
		});
	});

	test("text without the exact opener has no candidates", () => {
		for (const text of [
			"",
			"{}",
			"{ENCRYPTED}",
			"{ENCRYPTED abc}",
			"{encrypted:abcdefghij}",
			"[ENCRYPTED:fastly]abc",
			"{ ENCRYPTED:abcdefghij}",
		]) {
			expect([...wrappedCandidates(text, 512)]).toEqual([]);
			expect(unwrapText(text, 512, false, () => "never")).toEqual({
				text,
				preservedCandidates: 0,
			});
		}
	});

	test("strict mode reports framing before opening any payload", () => {
		let opened = 0;
		const open = () => {
			opened++;
			return "ok";
		};
		const error = thrown(() =>
			unwrapText(`${valid}${valid}${OPENER}x`, 512, false, open),
		);
		expect(error).toBeInstanceOf(WrappedTokenFormatError);
		expect(opened).toBe(0);
	});

	test("dense openers are found lazily and each counted once", () => {
		const text = OPENER.repeat(100_000);
		const candidates = wrappedCandidates(text, 512);
		expect(candidates.next().value).toEqual({
			start: 0,
			end: OPENER.length,
			payloadEnd: OPENER.length,
			framing: "unterminated",
		});
		expect(unwrapText(text, 512, true, () => "never")).toEqual({
			text,
			preservedCandidates: 100_000,
		});
		expect(() => unwrapText(text, 512, false, () => "never")).toThrow(
			WrappedTokenFormatError,
		);
	});

	test("the payload limit follows maxTokenLength", () => {
		const at = (length: number, max: number) =>
			[...wrappedCandidates(`${OPENER}${"x".repeat(length)}}`, max)][0]!
				.framing;
		expect(at(9, 512)).toBe("too-short");
		expect(at(10, 512)).toBe("valid");
		expect(at(520, 512)).toBe("valid");
		expect(at(521, 512)).toBe("too-long");
		expect(at(521, 513)).toBe("valid");
		expect(at(10, 2)).toBe("valid");
		expect(at(11, 2)).toBe("too-long");
		expect(at(4104, 4096)).toBe("valid");
		expect(at(4105, 4096)).toBe("too-long");
	});
});

describe("encryptWrapped", () => {
	test("the samples cover every built-in pattern", () => {
		expect(Object.keys(SAMPLE_TOKENS).sort()).toEqual(
			BUILTIN_PATTERNS.map((p) => p.name).sort(),
		);
		expect(BUILTIN_PATTERNS).toHaveLength(28);
	});

	for (const [name, token] of Object.entries(SAMPLE_TOKENS)) {
		test(`wraps a complete ${name} token`, () => {
			const enc = new TokenEncryptor(KEY);
			const text = `key: ${token} end`;
			expect(
				enc.encryptWithSpans(text).spans.map((s) => s.patternName),
			).toEqual([name]);

			const wrapped = enc.encryptWrapped(text);
			const [wrapper] = wrappersIn(wrapped);
			expect(wrapped).toBe(`key: ${wrapper} end`);
			expect(wrapper).toHaveLength(token.length + 20);
			expect(wrapper).not.toContain(token.slice(0, 4));

			const fresh = new TokenEncryptor(KEY);
			expect(fresh.decryptWrapped(wrapped)).toBe(text);
			fresh.destroy();
			enc.destroy();
		});
	}

	test("mixed, repeated, and Unicode-surrounded tokens round trip", () => {
		const enc = new TokenEncryptor(KEY);
		const tokens = Object.values(SAMPLE_TOKENS);
		const separators = [
			" ",
			"\n",
			" ¶ ",
			"「",
			"」 ",
			"\u{1F510} ",
			"\uD800 ",
			"\t",
		];
		const text = [...tokens, ...tokens.slice(0, 5)]
			.map((token, i) => `${separators[i % separators.length]}${token}`)
			.join(" | ");
		const spans = enc.encryptWithSpans(text).spans;
		const wrapped = enc.encryptWrapped(text);

		expect(wrappersIn(wrapped)).toHaveLength(spans.length);
		expect(wrapped.length).toBe(text.length + 20 * spans.length);
		for (const separator of separators) expect(wrapped).toContain(separator);
		expect(enc.decryptWrapped(wrapped)).toBe(text);

		const byToken = new Map<string, Set<string>>();
		const all = wrappersIn(wrapped);
		spans.forEach((span, i) => {
			const seen = byToken.get(span.original) ?? new Set<string>();
			seen.add(all[i]!);
			byToken.set(span.original, seen);
		});
		for (const seen of byToken.values()) expect(seen.size).toBe(1);
		enc.destroy();
	});

	test("adjacent tokens become adjacent wrappers", () => {
		const enc = new TokenEncryptor(KEY);
		for (const [left, right] of [
			["github-pat", "npm"],
			["openai", "npm"],
			["slack-bot", "aws-access-key"],
		] as const) {
			const text = `${SAMPLE_TOKENS[left]}${SAMPLE_TOKENS[right]}`;
			const wrapped = enc.encryptWrapped(text);
			const wrappers = wrappersIn(wrapped);
			expect(wrappers).toHaveLength(2);
			expect(wrapped).toBe(wrappers.join(""));
			expect(enc.decryptWrapped(wrapped)).toBe(text);
		}
		enc.destroy();
	});

	test("types selects the patterns to wrap", () => {
		const enc = new TokenEncryptor(KEY);
		const github = SAMPLE_TOKENS["github-pat"]!;
		const aws = SAMPLE_TOKENS["aws-access-key"]!;
		const text = `${github} ${aws}`;
		const wrapped = enc.encryptWrapped(text, { types: ["aws-access-key"] });
		expect(wrapped.startsWith(`${github} ${OPENER}`)).toBe(true);
		expect(wrappersIn(wrapped)).toHaveLength(1);
		expect(enc.decryptWrapped(wrapped)).toBe(text);
		expect(enc.encryptWrapped(text, { types: [] })).toBe(text);
		expect(enc.encryptWrapped(text, { types: ["no-such-pattern"] })).toBe(text);
		enc.destroy();
	});

	test("every TOKEN67 symbol and leading zeros survive", () => {
		for (const token of [
			TOKEN67.chars,
			"00",
			"0000000000000000abc",
			"00000000",
			"+/-_.",
			"..",
			"zz",
		]) {
			const wrapped = wrapperFor(token);
			expect(wrapped).toHaveLength(token.length + 20);
			expect(new TokenEncryptor(KEY).decryptWrapped(wrapped)).toBe(token);
		}
	});

	test("custom prefixes and separators inside TOKEN67 are supported", () => {
		const enc = new TokenEncryptor(KEY);
		enc.register({
			kind: "simple",
			name: "dotted",
			prefix: "my.app+v1/",
			bodyRegex: "[A-Za-z0-9]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		const text = "use my.app+v1/Ab3dEf7h now";
		const wrapped = enc.encryptWrapped(text);
		expect(wrapped).not.toContain("my.app");
		expect(new TokenEncryptor(KEY).decryptWrapped(wrapped)).toBe(text);
		enc.destroy();
	});

	test("custom tokens with symbols outside TOKEN67 are rejected", () => {
		for (const prefix of ["tk:", "tk~", "tk=", "tké"]) {
			const enc = new TokenEncryptor(KEY);
			enc.register({
				kind: "simple",
				name: `custom ${prefix}`,
				prefix,
				bodyRegex: "[A-Za-z0-9]{8}",
				bodyAlphabet: ALPHANUMERIC,
				minBodyLength: 8,
			});
			const text = `${SAMPLE_TOKENS["github-pat"]} ${prefix}Ab3dEf7h`;
			const { contexts } = withContextSpy(() => {
				const error = thrown(() => enc.encryptWrapped(text));
				expect(error).toBeInstanceOf(WrappedTokenFormatError);
				expect(error.message).toBe("Token contains a symbol outside TOKEN67");
				expect(error.message).not.toContain(prefix);
			});
			expect(contexts).toHaveLength(0);
			enc.destroy();
		}
	});

	test("custom separators are supported only inside TOKEN67", () => {
		for (const [separator, supported] of [
			[".", true],
			["+", true],
			["/", true],
			["-", true],
			["_", true],
			[":", false],
			["|", false],
			["~", false],
			["#", false],
		] as const) {
			const enc = new TokenEncryptor(KEY);
			enc.register({
				kind: "structured",
				name: "sep",
				prefix: "ref",
				fullRegex: `ref[0-9]{4}${escapeRegex(separator)}[a-z]{6}`,
				trailingAlphabet: ALPHANUMERIC,
				parse(body) {
					const [left, right, ...rest] = body.split(separator);
					if (rest.length > 0 || left?.length !== 4 || right?.length !== 6) {
						return null;
					}
					return {
						segments: [left, right],
						alphabets: [ALPHANUMERIC, ALPHANUMERIC],
					};
				},
				format(segments) {
					return segments.join(separator);
				},
			});
			const text = `id ref1234${separator}abcdef done`;
			const options = { types: ["sep"] };
			expect(enc.encryptWithSpans(text, options).spans).toHaveLength(1);
			if (supported) {
				const wrapped = enc.encryptWrapped(text, options);
				expect(wrappersIn(wrapped)).toHaveLength(1);
				expect(new TokenEncryptor(KEY).decryptWrapped(wrapped)).toBe(text);
			} else {
				expect(() => enc.encryptWrapped(text, options)).toThrow(
					"Token contains a symbol outside TOKEN67",
				);
			}
			enc.destroy();
		}
	});

	test("short Slack segments and SendGrid periods are encrypted too", () => {
		const enc = new TokenEncryptor(KEY);
		const slack = decodeSecret("kbko-12-345-NOPQRSTUVWXYZABCDEFGHIJKLM");
		expect(enc.encryptWithSpans(slack).spans[0]!.encrypted).toStartWith(
			"xoxb-12-345-",
		);
		const wrappedSlack = enc.encryptWrapped(slack);
		expect(wrappedSlack).not.toContain("xoxb");
		expect(wrappedSlack).not.toContain("-12-345-");
		expect(enc.decryptWrapped(wrappedSlack)).toBe(slack);

		const sendgrid = SAMPLE_TOKENS.sendgrid!;
		const wrappedSendgrid = enc.encryptWrapped(sendgrid);
		expect(wrappedSendgrid).not.toContain("SG.");
		expect(enc.decryptWrapped(wrappedSendgrid)).toBe(sendgrid);
		enc.destroy();
	});

	test("text containing the reserved opener is rejected", () => {
		const enc = new TokenEncryptor(KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const once = enc.encryptWrapped(`a ${token}`);
		for (const text of [
			once,
			`${OPENER}`,
			`no token here, just ${OPENER}`,
			`${token} ${OPENER}broken`,
			`${OPENER}${OPENER}}`,
		]) {
			const error = thrown(() => enc.encryptWrapped(text));
			expect(error).toBeInstanceOf(WrappedTokenFormatError);
			expect(error.message).toBe(
				"Text already contains an encrypted token opener",
			);
		}
		for (const text of ["{ENCRYPTED", "{ENCRYPTED}", "[ENCRYPTED:fastly]x"]) {
			expect(enc.encryptWrapped(text)).toBe(text);
		}
		enc.destroy();
	});

	test("text without tokens is returned unchanged without any setup", () => {
		const enc = new TokenEncryptor(KEY);
		const setups = countSetups(() => {
			for (const text of ["", "plain text", "{braces} and 🎉"]) {
				expect(enc.encryptWrapped(text)).toBe(text);
				expect(enc.decryptWrapped(text)).toBe(text);
			}
		});
		expect(setups).toBe(0);
		enc.destroy();
	});

	test("the default and hard length limits", () => {
		const enc = new TokenEncryptor(KEY);
		enc.register(anyToken());
		const options = { types: ["any"] };

		expect(
			wrappersIn(enc.encryptWrapped(payloadOfLength(512), options)),
		).toHaveLength(1);
		const tooLong = thrown(() =>
			enc.encryptWrapped(payloadOfLength(513), options),
		);
		expect(tooLong).toBeInstanceOf(WrappedTokenFormatError);
		expect(tooLong.message).toBe("Token is longer than maxTokenLength allows");

		const wrapped513 = enc.encryptWrapped(payloadOfLength(513), {
			...options,
			maxTokenLength: 513,
		});
		expect(enc.decryptWrapped(wrapped513, { maxTokenLength: 513 })).toBe(
			payloadOfLength(513),
		);
		expect(thrown(() => enc.decryptWrapped(wrapped513)).message).toBe(
			"Encrypted token is longer than maxTokenLength allows",
		);

		const max = payloadOfLength(4096);
		const wrappedMax = enc.encryptWrapped(max, {
			...options,
			maxTokenLength: 4096,
		});
		expect(wrappedMax).toHaveLength(4116);
		expect(enc.decryptWrapped(wrappedMax, { maxTokenLength: 4096 })).toBe(max);
		expect(() =>
			enc.encryptWrapped(payloadOfLength(4097), {
				...options,
				maxTokenLength: 4096,
			}),
		).toThrow(WrappedTokenFormatError);

		expect(wrapperFor("ab", { maxTokenLength: 2 })).toHaveLength(22);
		expect(() =>
			enc.encryptWrapped("abc", { ...options, maxTokenLength: 2 }),
		).toThrow(WrappedTokenFormatError);
		enc.destroy();
	});

	test("one-character tokens are rejected", () => {
		const enc = new TokenEncryptor(KEY);
		enc.register(anyToken());
		const error = thrown(() => enc.encryptWrapped("a b", { types: ["any"] }));
		expect(error).toBeInstanceOf(WrappedTokenFormatError);
		expect(error.message).toBe("Token is too short to wrap");
		expect(
			wrappersIn(enc.encryptWrapped("ab cd", { types: ["any"] })),
		).toHaveLength(2);
		enc.destroy();
	});

	test("every token is checked before any is encrypted", () => {
		const enc = new TokenEncryptor(KEY);
		enc.register(anyToken());
		const text = `ab ${payloadOfLength(600)}`;
		const { contexts } = withContextSpy(() => {
			expect(() => enc.encryptWrapped(text, { types: ["any"] })).toThrow(
				WrappedTokenFormatError,
			);
		});
		expect(contexts).toHaveLength(0);
		enc.destroy();
	});

	test("legacy methods are unchanged", () => {
		const text = Object.values(SAMPLE_TOKENS).join(" ");
		const before = new TokenEncryptor(KEY).encryptWithSpans(text);
		const enc = new TokenEncryptor(KEY);
		enc.decryptWrapped(enc.encryptWrapped(text));
		expect(enc.encryptWithSpans(text)).toEqual(before);
		expect(enc.decrypt(before.text)).toBe(text);
		enc.destroy();
	});
});

describe("decryptWrapped", () => {
	const token = SAMPLE_TOKENS["github-pat"]!;
	const text = `token ${token} and ${SAMPLE_TOKENS.sendgrid}`;

	test("recovers text with a fresh instance and any registry", () => {
		const custom: TokenPattern = {
			kind: "simple",
			name: "custom",
			prefix: "cust_",
			bodyRegex: "[A-Za-z0-9]{10}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 10,
		};
		const enc = new TokenEncryptor(KEY);
		enc.register(custom);
		const original = `${text} cust_0123456789`;
		const wrapped = enc.encryptWrapped(original);
		expect(wrappersIn(wrapped)).toHaveLength(3);
		enc.destroy();

		const fresh = new TokenEncryptor(KEY);
		expect(fresh.decryptWrapped(wrapped)).toBe(original);
		fresh.destroy();
	});

	test("never scans for tokens", () => {
		const trap: TokenPattern = {
			kind: "structured",
			name: "trap",
			prefix: "",
			fullRegex: "ENCRYPTED|ghp_|[A-Za-z0-9]{4}",
			trailingAlphabet: ALPHANUMERIC,
			parse() {
				throw new Error("scanned");
			},
			format(segments) {
				return segments.join("");
			},
		};
		const wrapped = new TokenEncryptor(KEY).encryptWrapped(text);
		const enc = new TokenEncryptor(KEY);
		enc.register(trap);
		expect(() => enc.encrypt(wrapped)).toThrow("scanned");
		expect(enc.decryptWrapped(wrapped)).toBe(text);
		expect(enc.decryptWrapped(`${token} ${wrapped}`)).toBe(`${token} ${text}`);
		enc.destroy();
	});

	test("leaves bare tokens alone", () => {
		const enc = new TokenEncryptor(KEY);
		expect(enc.decryptWrapped(text)).toBe(text);
		enc.destroy();
	});

	test("recovers wrappers moved into another document", () => {
		const enc = new TokenEncryptor(KEY);
		const [a, b] = wrappersIn(enc.encryptWrapped(text));
		const moved = `«${b}»\n${a}${a}{${b}}`;
		expect(enc.decryptWrapped(moved)).toBe(
			`«${SAMPLE_TOKENS.sendgrid}»\n${token}${token}{${SAMPLE_TOKENS.sendgrid}}`,
		);
		enc.destroy();
	});

	test("an omitted tweak equals an empty one", () => {
		const enc = new TokenEncryptor(KEY);
		const empty = new Uint8Array(0);
		const omitted = enc.encryptWrapped(text);
		expect(enc.encryptWrapped(text, { tweak: empty })).toBe(omitted);
		expect(enc.decryptWrapped(omitted, { tweak: empty })).toBe(text);
		const tweaked = enc.encryptWrapped(text, { tweak: new Uint8Array([0]) });
		expect(tweaked).not.toBe(omitted);
		expect(tweaked).toHaveLength(omitted.length);
		enc.destroy();
	});

	test("the tweak and key must match", () => {
		const tweak = new TextEncoder().encode("conversation-1");
		const wrapped = new TokenEncryptor(KEY).encryptWrapped(text, { tweak });
		expect(new TokenEncryptor(KEY).decryptWrapped(wrapped, { tweak })).toBe(
			text,
		);

		for (const [key, options] of [
			[KEY, {}],
			[KEY, { tweak: new TextEncoder().encode("conversation-2") }],
			[OTHER_KEY, { tweak }],
		] as const) {
			const enc = new TokenEncryptor(key);
			const error = thrown(() => enc.decryptWrapped(wrapped, options));
			expect(error).toBeInstanceOf(WrappedTokenIntegrityError);
			expect(
				enc.decryptWrapped(wrapped, { ...options, onInvalid: "preserve" }),
			).toEqual({ text: wrapped, preservedCandidates: 2 });
		}
	});

	test("recovered text is not processed again", () => {
		const inner = wrapperFor("hidden-token");
		const innerPayload = inner.slice(OPENER.length, -1);
		const outer = wrapperFor(innerPayload);
		const enc = new TokenEncryptor(KEY);
		expect(enc.decryptWrapped(outer)).toBe(innerPayload);
		const nested = `${OPENER}${outer}}`;
		expect(enc.decryptWrapped(nested, { onInvalid: "preserve" })).toEqual({
			text: inner,
			preservedCandidates: 1,
		});
		expect(enc.decryptWrapped(inner)).toBe("hidden-token");
		enc.destroy();
	});

	test("strict mode returns everything or nothing", () => {
		const enc = new TokenEncryptor(KEY);
		const wrapped = enc.encryptWrapped(text);
		const [first] = wrappersIn(wrapped);
		const corrupted = `${first!.slice(0, 11)}${first![11] === "A" ? "B" : "A"}${first!.slice(12)}`;
		for (const [bad, kind] of [
			[`${wrapped} ${OPENER}`, WrappedTokenFormatError],
			[`${wrapped} ${OPENER}abc}`, WrappedTokenFormatError],
			[`${wrapped} ${OPENER}abcdefghij=}`, WrappedTokenFormatError],
			[`${wrapped} ${corrupted}`, WrappedTokenIntegrityError],
			[`${corrupted} ${wrapped}`, WrappedTokenIntegrityError],
		] as const) {
			const error = thrown(() => enc.decryptWrapped(bad));
			expect(error).toBeInstanceOf(kind);
			expect(error).toBeInstanceOf(TokenError);
			expect(error.message).not.toContain(token);
			expect(error.message).not.toContain(first!.slice(OPENER.length, -1));
		}
		enc.destroy();
	});

	test("strict mode rejects bad framing before any setup", () => {
		const wrapped = new TokenEncryptor(KEY).encryptWrapped(text);
		const enc = new TokenEncryptor(KEY);
		const setups = countSetups(() =>
			expect(() => enc.decryptWrapped(`${wrapped}${OPENER}`)).toThrow(
				WrappedTokenFormatError,
			),
		);
		expect(setups).toBe(0);
		enc.destroy();
	});
});

describe("preserve mode", () => {
	const enc = new TokenEncryptor(KEY);
	const token = SAMPLE_TOKENS["aws-access-key"]!;
	const wrapped = enc.encryptWrapped(token);

	test("counts nothing when every wrapper is valid", () => {
		expect(
			enc.decryptWrapped(`x ${wrapped} y`, { onInvalid: "preserve" }),
		).toEqual({ text: `x ${token} y`, preservedCandidates: 0 });
		expect(
			enc.decryptWrapped("no wrappers", { onInvalid: "preserve" }),
		).toEqual({ text: "no wrappers", preservedCandidates: 0 });
	});

	test("a quoted stray opener does not hide later wrappers", () => {
		expect(
			enc.decryptWrapped(`say "${OPENER}" then ${wrapped}`, {
				onInvalid: "preserve",
			}),
		).toEqual({
			text: `say "${OPENER}" then ${token}`,
			preservedCandidates: 1,
		});
	});

	test("a nested wrapper is verified on its own", () => {
		expect(
			enc.decryptWrapped(`${OPENER}${wrapped}}`, { onInvalid: "preserve" }),
		).toEqual({ text: `${OPENER}${token}}`, preservedCandidates: 1 });

		const broken = `${wrapped.slice(0, -2)}${wrapped.at(-2) === "A" ? "B" : "A"}}`;
		const nested = `${OPENER}${broken}}`;
		expect(enc.decryptWrapped(nested, { onInvalid: "preserve" })).toEqual({
			text: nested,
			preservedCandidates: 2,
		});
	});

	test("adjacent invalid candidates are each counted once", () => {
		const text = `${OPENER}}${OPENER}}${OPENER}abc}${wrapped}${OPENER}${"x".repeat(600)}}${OPENER}`;
		expect(enc.decryptWrapped(text, { onInvalid: "preserve" })).toEqual({
			text: text.replace(wrapped, token),
			preservedCandidates: 5,
		});
	});

	test("invalid symbols and missing braces are kept verbatim", () => {
		for (const bad of [
			`${OPENER}abcdefghijk`,
			`${OPENER}abcdefghijk=}`,
			`${OPENER}abcdef ghijk}`,
			`${OPENER}abcdefghijk\n}`,
			`${OPENER}abcdéfghijk}`,
			wrapped.slice(0, -1),
		]) {
			const text = `<${bad}> ${wrapped}`;
			expect(enc.decryptWrapped(text, { onInvalid: "preserve" })).toEqual({
				text: `<${bad}> ${token}`,
				preservedCandidates: 1,
			});
			expect(() => enc.decryptWrapped(text)).toThrow(WrappedTokenFormatError);
		}
	});

	test("oversized and undersized candidates never reach the cipher", () => {
		const text = `${OPENER}${"a".repeat(100_000)}} ${OPENER}abc} ${OPENER}${"b".repeat(521)}}`;
		const { result, contexts } = withContextSpy(() =>
			enc.decryptWrapped(text, { onInvalid: "preserve" }),
		);
		expect(result).toEqual({ text, preservedCandidates: 3 });
		expect(contexts).toHaveLength(0);
	});

	test("option and lifecycle errors still throw", () => {
		const other = new TokenEncryptor(KEY);
		expect(() =>
			other.decryptWrapped(wrapped, {
				onInvalid: "preserve",
				maxTokenLength: 1,
			}),
		).toThrow(RangeError);
		expect(() =>
			other.decryptWrapped(wrapped, {
				onInvalid: "preserve",
				tweak: "abc" as unknown as Uint8Array,
			}),
		).toThrow(TypeError);
		other.destroy();
		expect(() =>
			other.decryptWrapped(wrapped, { onInvalid: "preserve" }),
		).toThrow("TokenEncryptor has been destroyed");
	});
});

describe("options", () => {
	test("maxTokenLength must be an integer from 2 to 4096", () => {
		const enc = new TokenEncryptor(KEY);
		for (const value of [
			1,
			0,
			-1,
			4097,
			2.5,
			512.000001,
			Number.NaN,
			Number.POSITIVE_INFINITY,
			2 ** 53,
			"512",
			null,
		]) {
			const maxTokenLength = value as number;
			for (const run of [
				() => enc.encryptWrapped("x", { maxTokenLength }),
				() => enc.decryptWrapped("x", { maxTokenLength }),
				() =>
					enc.decryptWrapped("x", { maxTokenLength, onInvalid: "preserve" }),
			]) {
				const error = thrown(run);
				expect(error).toBeInstanceOf(RangeError);
				expect(error.message).toBe(
					"maxTokenLength must be an integer from 2 to 4096",
				);
			}
		}
		for (const maxTokenLength of [2, 512, 4096]) {
			expect(enc.decryptWrapped("x", { maxTokenLength })).toBe("x");
		}
		enc.destroy();
	});

	test("onInvalid, tweak, and types are checked", () => {
		const enc = new TokenEncryptor(KEY);
		const onInvalid = "ignore" as unknown as "throw";
		expect(() => enc.decryptWrapped("x", { onInvalid })).toThrow(RangeError);
		const tweak = [1, 2] as unknown as Uint8Array;
		expect(() => enc.encryptWrapped("x", { tweak })).toThrow(TypeError);
		expect(() => enc.decryptWrapped("x", { tweak })).toThrow(TypeError);
		const types = "github-pat" as unknown as string[];
		expect(() => enc.encryptWrapped("x", { types })).toThrow(TypeError);
		expect(enc.decryptWrapped("x", { onInvalid: "throw" })).toBe("x");
		expect(enc.encryptWrapped("x", { tweak: Buffer.from("t") })).toBe("x");
		enc.destroy();
	});

	test("the overloads infer each return type", () => {
		const enc = new TokenEncryptor(KEY);
		const wrapped = enc.encryptWrapped(SAMPLE_TOKENS.npm!);

		const strict = enc.decryptWrapped(wrapped);
		expectTypeOf(strict).toEqualTypeOf<string>();
		expectTypeOf(enc.decryptWrapped(wrapped, {})).toEqualTypeOf<string>();
		expectTypeOf(
			enc.decryptWrapped(wrapped, { onInvalid: "throw" }),
		).toEqualTypeOf<string>();
		const preserved = enc.decryptWrapped(wrapped, { onInvalid: "preserve" });
		expectTypeOf(preserved).toEqualTypeOf<WrappedDecryptResult>();

		const mode = Math.random() < 2 ? ("preserve" as const) : ("throw" as const);
		const options: WrappedDecryptOptions = { onInvalid: mode };
		const either = enc.decryptWrapped(wrapped, options);
		expectTypeOf(either).toEqualTypeOf<string | WrappedDecryptResult>();
		expectTypeOf(
			enc.decryptWrapped(wrapped, { onInvalid: mode }),
		).toEqualTypeOf<string | WrappedDecryptResult>();

		expect(strict).toBe(SAMPLE_TOKENS.npm!);
		expect(preserved).toEqual({
			text: SAMPLE_TOKENS.npm!,
			preservedCandidates: 0,
		});
		expect(either).toEqual(preserved);
		enc.destroy();
	});
});

describe("ownership and cleanup", () => {
	const text = Object.values(SAMPLE_TOKENS).slice(0, 6).join(" ");

	test("each wrapper gets its own context on one shared pool", () => {
		const enc = new TokenEncryptor(KEY);
		const legacy = spyOn(FastCipher, "create");
		try {
			const encrypted = withContextSpy(() => enc.encryptWrapped(text));
			const decrypted = withContextSpy(() =>
				enc.decryptWrapped(encrypted.result),
			);
			expect(decrypted.result).toBe(text);
			expect(legacy).not.toHaveBeenCalled();

			const contexts = [...encrypted.contexts, ...decrypted.contexts];
			const calls = [...encrypted.calls, ...decrypted.calls];
			expect(contexts).toHaveLength(12);
			for (const context of contexts) expect(isDestroyed(context)).toBe(true);

			const [, key, pool] = calls[0] as [
				unknown,
				Uint8Array,
				{ sboxes: { perm: Uint8Array }[] },
			];
			for (const call of calls) {
				expect(call[1]).toBe(key);
				expect(call[2]).toBe(pool);
			}
			expect(pool.sboxes).toHaveLength(256);
			expect(pool.sboxes.every((s) => s.perm.some((v) => v !== 0))).toBe(true);
			expect(key.some((v) => v !== 0)).toBe(true);

			enc.destroy();
			expect(pool.sboxes.every((s) => s.perm.every((v) => v === 0))).toBe(true);
			expect(key.every((v) => v === 0)).toBe(true);
			expect(() => enc.encryptWrapped(text)).toThrow(
				"TokenEncryptor has been destroyed",
			);
			expect(() => enc.decryptWrapped(text)).toThrow(
				"TokenEncryptor has been destroyed",
			);
		} finally {
			legacy.mockRestore();
		}
	});

	test("destroying a context wipes its sequence and tweak copy", () => {
		type Internals = {
			cachedSeq: Uint32Array | null;
			cachedTweak: Uint8Array | null;
		};
		const destroy = FastCipher.prototype.destroy;
		const wiped: Internals[] = [];
		const spy = spyOn(FastCipher.prototype, "destroy").mockImplementation(
			function (this: FastCipher) {
				const internals = this as unknown as Internals;
				const seen = { ...internals };
				destroy.call(this);
				expect(internals.cachedSeq).toBeNull();
				expect(internals.cachedTweak).toBeNull();
				wiped.push(seen);
			},
		);
		try {
			const enc = new TokenEncryptor(KEY);
			const tweak = new Uint8Array([1, 2, 3]);
			const wrapped = enc.encryptWrapped(text, { tweak });
			expect(enc.decryptWrapped(wrapped, { tweak })).toBe(text);
			enc.destroy();
		} finally {
			spy.mockRestore();
		}

		expect(wiped).toHaveLength(12);
		for (const { cachedSeq, cachedTweak } of wiped) {
			expect(cachedSeq!.length).toBeGreaterThan(0);
			expect(cachedSeq!.every((v) => v === 0)).toBe(true);
			expect(cachedTweak!.length).toBeGreaterThan(3);
			expect(cachedTweak!.every((v) => v === 0)).toBe(true);
		}
	});

	test("contexts are destroyed when a check fails", () => {
		const enc = new TokenEncryptor(KEY);
		const wrapped = enc.encryptWrapped(text);
		const { contexts } = withContextSpy(() =>
			expect(() =>
				enc.decryptWrapped(wrapped, { tweak: new Uint8Array([1]) }),
			).toThrow(WrappedTokenIntegrityError),
		);
		expect(contexts).toHaveLength(1);
		expect(isDestroyed(contexts[0]!)).toBe(true);
		enc.destroy();
	});

	test("contexts are destroyed when the cipher throws, in either mode", () => {
		const enc = new TokenEncryptor(KEY);
		const wrapped = enc.encryptWrapped(text);
		for (const method of ["encrypt", "decrypt"] as const) {
			const failing = spyOn(FastCipher.prototype, method).mockImplementation(
				() => {
					throw new Error("operational failure");
				},
			);
			let contexts: FastCipher[];
			try {
				contexts = withContextSpy(() => {
					expect(() =>
						method === "encrypt"
							? enc.encryptWrapped(text)
							: enc.decryptWrapped(wrapped, { onInvalid: "preserve" }),
					).toThrow("operational failure");
				}).contexts;
			} finally {
				failing.mockRestore();
			}
			expect(contexts).toHaveLength(1);
			expect(isDestroyed(contexts[0]!)).toBe(true);
		}
		enc.destroy();
	});

	test("a borrowed pool must match the parameters and survives the context", () => {
		const params = wrappedParams(12);
		const key = new Uint8Array(16).fill(9);
		const pool = generateSBoxPool(67, 256, new Uint8Array(32).fill(1));
		const context = FastCipher.withSharedPool(params, key, pool);
		context.encrypt(new Uint8Array(12));
		context.destroy();
		expect(pool.sboxes[0]!.perm.some((v) => v !== 0)).toBe(true);
		expect(key.some((v) => v !== 0)).toBe(true);

		expect(() =>
			FastCipher.withSharedPool({ ...params, radix: 66 }, key, pool),
		).toThrow("S-box pool does not match the parameters");
		expect(() =>
			FastCipher.withSharedPool(
				params,
				key,
				generateSBoxPool(67, 8, new Uint8Array(32)),
			),
		).toThrow("S-box pool does not match the parameters");

		const owner = FastCipher.create(params, key);
		const ownPool = (owner as unknown as { sboxPool: SBoxPool }).sboxPool;
		owner.destroy();
		expect(ownPool.sboxes.every((s) => s.perm.every((v) => v === 0))).toBe(
			true,
		);
	});

	test("a destroyed wrapped cipher refuses to work", () => {
		const cipher = WrappedTokenCipher.create(KEY);
		const tweak = wrapperTweak();
		const payload = cipher.wrap("ab", tweak).slice(OPENER.length, -1);
		cipher.destroy();
		cipher.destroy();
		expect(() => cipher.wrap("ab", tweak)).toThrow(
			"Wrapped token cipher has been destroyed",
		);
		expect(() => cipher.unwrap(payload, tweak)).toThrow(
			"Wrapped token cipher has been destroyed",
		);
	});

	test("setup is lazy and happens once per instance", () => {
		const enc = new TokenEncryptor(KEY);
		expect(
			countSetups(() =>
				enc.decryptWrapped(`${OPENER}abc} plain`, { onInvalid: "preserve" }),
			),
		).toBe(0);
		expect(
			countSetups(() => {
				enc.decryptWrapped(enc.encryptWrapped(text));
				enc.encryptWrapped(text, { tweak: new Uint8Array([7]) });
			}),
		).toBe(1);
		enc.destroy();
	});

	test("destroying the instance during a call stops it", () => {
		const destroyOnParse = (enc: TokenEncryptor): TokenPattern => ({
			kind: "structured",
			name: "destroying",
			prefix: "zz_",
			fullRegex: "zz_[a-z]{8}",
			trailingAlphabet: ALPHANUMERIC,
			parse(body) {
				enc.destroy();
				return { segments: [body], alphabets: [ALPHANUMERIC] };
			},
			format(segments) {
				return segments.join("");
			},
		});
		for (const run of [
			(enc: TokenEncryptor) => enc.encryptWrapped("x zz_abcdefgh y"),
			(enc: TokenEncryptor) => enc.encrypt("x zz_abcdefgh y"),
		]) {
			const enc = new TokenEncryptor(KEY);
			enc.register(destroyOnParse(enc));
			expect(() => run(enc)).toThrow("TokenEncryptor has been destroyed");
		}
	});
});

function seededRandom(seed: number): (bound: number) => number {
	let state = seed >>> 0;
	return (bound) => {
		state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
		return Math.floor((state / 2 ** 32) * bound);
	};
}

/** A direct reading of the plan's parser rules, one position at a time. */
function referenceUnwrap(
	text: string,
	maxTokenLength: number,
	open: (payload: string) => string | null,
): { text: string; preservedCandidates: number } {
	let out = "";
	let preservedCandidates = 0;
	let i = 0;
	while (i < text.length) {
		if (!text.startsWith(OPENER, i)) {
			out += text[i];
			i++;
			continue;
		}
		let j = i + OPENER.length;
		while (j < text.length && TOKEN67.charToIndex.has(text[j]!)) j++;
		const closed = text[j] === "}";
		const length = j - i - OPENER.length;
		const token =
			closed && length >= 10 && length <= maxTokenLength + 8
				? open(text.slice(i + OPENER.length, j))
				: null;
		const end = closed ? j + 1 : j;
		if (token === null) {
			out += text.slice(i, end);
			preservedCandidates++;
		} else {
			out += token;
		}
		i = end;
	}
	return { text: out, preservedCandidates };
}

describe("properties", () => {
	test("the parser agrees with a direct reading of the rules", () => {
		const random = seededRandom(1);
		const fragments = [
			OPENER,
			OPENER,
			"{",
			"}",
			":",
			"ENCRYPTED",
			"abcde",
			"0",
			"Z.",
			"+/-_",
			"=",
			" ",
			"é",
			"\u{1F600}",
		];
		const open = (payload: string) =>
			payload.length % 3 === 0 ? null : `<${payload.length}>`;
		for (let round = 0; round < 3000; round++) {
			let text = "";
			const parts = random(40);
			for (let i = 0; i < parts; i++) {
				text += fragments[random(fragments.length)]!;
			}
			const max = 2 + random(20);
			expect(unwrapText(text, max, true, open)).toEqual(
				referenceUnwrap(text, max, open),
			);
		}
	});

	test("accepted plaintext round trips", () => {
		const random = seededRandom(2);
		const tokens = Object.values(SAMPLE_TOKENS);
		const fillers = [
			" ",
			"\n",
			"{",
			"}",
			"{ENCRYPTED",
			"ENCRYPTED:",
			"[ENCRYPTED:fastly]",
			"é",
			"\u{1F600}",
			"\uDC00",
			"plain words",
			"=",
			":",
			"__",
		];
		const enc = new TokenEncryptor(KEY);
		const fresh = new TokenEncryptor(KEY);
		let wrappers = 0;
		let rejected = 0;
		for (let round = 0; round < 300; round++) {
			let text = "";
			const parts = random(12);
			for (let i = 0; i < parts; i++) {
				text +=
					random(3) === 0
						? tokens[random(tokens.length)]!
						: fillers[random(fillers.length)]!;
			}
			const tweak = new Uint8Array([random(256)]);
			if (text.includes(OPENER)) {
				expect(() => enc.encryptWrapped(text, { tweak })).toThrow(
					WrappedTokenFormatError,
				);
				rejected++;
				continue;
			}
			const wrapped = enc.encryptWrapped(text, { tweak });
			wrappers += wrappersIn(wrapped).length;
			expect(fresh.decryptWrapped(wrapped, { tweak })).toBe(text);
			expect(
				fresh.decryptWrapped(wrapped, { tweak, onInvalid: "preserve" }),
			).toEqual({ text, preservedCandidates: 0 });
		}
		expect(wrappers).toBeGreaterThan(200);
		expect(rejected).toBeGreaterThan(0);
		enc.destroy();
		fresh.destroy();
	});
});

describe("measurements", () => {
	test("setup time and memory under length and tweak churn", () => {
		const setupRuns = 5;
		let setupMs = 0;
		for (let i = 0; i < setupRuns; i++) {
			const key = new Uint8Array(16).fill(i);
			const start = performance.now();
			WrappedTokenCipher.create(key).destroy();
			setupMs += performance.now() - start;
		}

		const enc = new TokenEncryptor(KEY);
		enc.register(anyToken());
		const lengths = [2, 3, 17, 64, 100, 257, 512, 1024, 2048, 4096];
		const timings: string[] = [];

		Bun.gc(true);
		const before = process.memoryUsage();
		let contexts = 0;
		for (const length of lengths) {
			const token = payloadOfLength(length);
			const rounds = length > 1000 ? 2 : 10;
			const spied = withContextSpy(() => {
				const start = performance.now();
				for (let round = 0; round < rounds; round++) {
					const tweak = new Uint8Array([length & 0xff, length >> 8, round]);
					const options = { types: ["any"], tweak, maxTokenLength: 4096 };
					const wrapped = enc.encryptWrapped(token, options);
					expect(enc.decryptWrapped(wrapped, options)).toBe(token);
				}
				return (performance.now() - start) / (2 * rounds);
			});
			contexts += spied.contexts.length;
			for (const context of spied.contexts) {
				expect(isDestroyed(context)).toBe(true);
			}
			timings.push(`${length}:${spied.result.toFixed(2)}`);
		}
		Bun.gc(true);
		const after = process.memoryUsage();
		enc.destroy();

		const mb = (bytes: number) => (bytes / 2 ** 20).toFixed(1);
		console.log(
			[
				`[tokens-wrapped] key and pool setup: ${(setupMs / setupRuns).toFixed(2)} ms`,
				`ms per wrapper by token length: ${timings.join(" ")}`,
				`${contexts} transient contexts, heap ${mb(before.heapUsed)} -> ${mb(after.heapUsed)} MiB, rss ${mb(before.rss)} -> ${mb(after.rss)} MiB`,
			].join("\n"),
		);
		expect(after.heapUsed - before.heapUsed).toBeLessThan(64 * 2 ** 20);
	});
});
