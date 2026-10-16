import { describe, expect, test } from "bun:test";
import { BUILTIN_PATTERNS, scan, TokenEncryptor } from "../src/tokens/index.ts";
import {
	AWS_KEY,
	decodeSecret,
	describeSpans,
	KEY,
	SAMPLE_TOKENS,
	wrappersIn,
} from "./helpers.ts";

interface Fixture {
	label: string;
	name: string;
	prefix: string;
	token: string;
}

const SENDGRID: Fixture = {
	label: "sendgrid",
	name: "sendgrid",
	prefix: "SG.",
	token: SAMPLE_TOKENS.sendgrid!,
};
const GITLAB: Fixture = {
	label: "gitlab",
	name: "gitlab",
	prefix: "glpat-",
	token: decodeSecret("tycng-No1-_No1-_No1-_No1-_"),
};
const SLACK: Fixture[] = [
	{
		label: "slack-bot",
		name: "slack-bot",
		prefix: "xoxb-",
		token: SAMPLE_TOKENS["slack-bot"]!,
	},
	{
		label: "slack-user",
		name: "slack-user",
		prefix: "xoxp-",
		token: SAMPLE_TOKENS["slack-user"]!,
	},
	{
		label: "slack-user with four segments",
		name: "slack-user",
		prefix: "xoxp-",
		token: decodeSecret(
			"kbkc-1234567890-9876543210-2468013579-NoPqRsTuVwXyZaBcDeFgHiJk",
		),
	},
];

const SEPARATORS = ["", "-", "_", "-_--"];

function spanAt(start: number, { name, prefix, token }: Fixture): string {
	return `${name}@${start}-${start + token.length}:${token.slice(prefix.length)}`;
}

function join(fixtures: Fixture[], separator: string) {
	let start = 0;
	const spans = fixtures.map((fixture) => {
		const span = spanAt(start, fixture);
		start += fixture.token.length + separator.length;
		return span;
	});
	return { text: fixtures.map((f) => f.token).join(separator), spans };
}

function find(text: string, patterns = BUILTIN_PATTERNS): string[] {
	return describeSpans(scan(text, patterns, BUILTIN_PATTERNS));
}

function expectRoundTrips(text: string, count: number): void {
	const enc = new TokenEncryptor(KEY);
	try {
		const encrypted = enc.encryptWithSpans(text);
		expect(encrypted.spans).toHaveLength(count);
		expect(enc.decrypt(encrypted.text)).toBe(text);
		const wrapped = enc.encryptWrapped(text);
		expect(wrappersIn(wrapped)).toHaveLength(count);
		expect(enc.decryptWrapped(wrapped)).toBe(text);
	} finally {
		enc.destroy();
	}
}

describe("tokens next to each other are all found", () => {
	for (const fixture of [SENDGRID, GITLAB, ...SLACK]) {
		test(`four ${fixture.label} tokens`, () => {
			for (const separator of SEPARATORS) {
				const { text, spans } = join(Array(4).fill(fixture), separator);
				expect(find(text)).toEqual(spans);
				expectRoundTrips(text, 4);
			}
		});
	}

	const mixed = [SENDGRID, GITLAB, SLACK[0]!];
	for (const left of mixed) {
		for (const right of mixed) {
			if (left === right) continue;
			test(`${left.label} then ${right.label}`, () => {
				const leftOnly = BUILTIN_PATTERNS.filter((p) => p.name === left.name);
				for (const separator of SEPARATORS) {
					const { text, spans } = join([left, right], separator);
					expect(find(text)).toEqual(spans);
					expect(find(text, leftOnly)).toEqual(spans.slice(0, 1));
					expectRoundTrips(text, 2);
				}
			});
		}
	}
});

describe("a body only stops early before a valid token", () => {
	for (const fixture of [SENDGRID, GITLAB]) {
		test(fixture.label, () => {
			for (const suffix of [
				"Z",
				"-",
				`-${fixture.prefix}short`,
				"AKIA",
				AWS_KEY.slice(0, -1),
				`${AWS_KEY}A`,
			]) {
				expect(find(fixture.token + suffix)).toEqual([]);
			}
			const { text, spans } = join([fixture, fixture], "Z");
			expect(find(text)).toEqual(spans.slice(1));

			const only = BUILTIN_PATTERNS.filter((p) => p.name === fixture.name);
			expect(find(fixture.token + AWS_KEY, only)).toEqual([spanAt(0, fixture)]);
		});
	}

	for (const fixture of SLACK) {
		test(fixture.label, () => {
			const { name, prefix, token } = fixture;
			const incomplete = `${token}${prefix}12`;
			const end = token.length + prefix.length - 1;
			expect(find(incomplete)).toEqual([
				`${name}@0-${end}:${incomplete.slice(prefix.length, end)}`,
			]);
			const invalid = "xoxb-1-1-";
			expect(find(invalid + token)).toEqual([spanAt(invalid.length, fixture)]);
		});
	}
});
