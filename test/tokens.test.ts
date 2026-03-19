import { describe, expect, test } from "bun:test";
import {
	ALPHANUMERIC,
	BUILTIN_PATTERNS,
	scan,
	TokenEncryptor,
	type TokenPattern,
} from "../src/tokens/index.ts";
import { shannonEntropy } from "../src/tokens/scanner.ts";

const TEST_KEY = new Uint8Array([
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f,
]);

const ALT_KEY = new Uint8Array([
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
	0x1d, 0x1e, 0x1f,
]);

// Realistic sample tokens for each provider
const SAMPLE_TOKENS: Record<string, string> = {
	"github-pat": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"github-oauth": "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"github-user": "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"github-server": "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"github-refresh": "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	gitlab: "glpat-ABCDEFGHIJKLMNOPQRST",
	"aws-access-key": "AKIAIOSFODNN7EXAMPLE",
	openai:
		"sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGH",
	"openai-legacy": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
	anthropic:
		"sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZa",
	"stripe-secret-live": "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"stripe-publish-live": "pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"stripe-secret-test": "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"stripe-publish-test": "pk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	"google-api": "AIzaSyA1234567890abcdefghijklmnopqrstuv",
	twilio: "SK0123456789abcdef0123456789abcdef",
	npm: "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
	pypi: "pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01",
	datadog: "ddapi_abcdefghijklmnopqrstuvwxyz0123456789abcd",
	vercel: "vercel_ABCDEFGHIJKLMNOPQRSTUVWXYZab",
	supabase: "sbp_0123456789abcdef0123456789abcdef01234567",
	huggingface: "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
	grafana: "glc_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
	sendgrid:
		"SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
	"slack-bot": "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXab",
	"slack-user": "xoxp-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXab",
	fastly: "5lYCIuNxQuC-WFvIvHNmjO0PvaVqrtos",
	"aws-secret-key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

// Build regex patterns that tokens should match (to verify format is preserved)
const FORMAT_REGEXES: Record<string, RegExp> = {
	"github-pat": /^ghp_[A-Za-z0-9]{36}$/,
	"github-oauth": /^gho_[A-Za-z0-9]{36}$/,
	"github-user": /^ghu_[A-Za-z0-9]{36}$/,
	"github-server": /^ghs_[A-Za-z0-9]{36}$/,
	"github-refresh": /^ghr_[A-Za-z0-9]{36}$/,
	gitlab: /^glpat-[A-Za-z0-9_-]{20}$/,
	"aws-access-key": /^AKIA[A-Z0-9]{16}$/,
	openai: /^sk-proj-[A-Za-z0-9_-]{48,}$/,
	"openai-legacy": /^sk-[A-Za-z0-9]{48}$/,
	anthropic: /^sk-ant-api03-[A-Za-z0-9_-]{80,}$/,
	"stripe-secret-live": /^sk_live_[A-Za-z0-9]{24,}$/,
	"stripe-publish-live": /^pk_live_[A-Za-z0-9]{24,}$/,
	"stripe-secret-test": /^sk_test_[A-Za-z0-9]{24,}$/,
	"stripe-publish-test": /^pk_test_[A-Za-z0-9]{24,}$/,
	"google-api": /^AIza[A-Za-z0-9_-]{35}$/,
	twilio: /^SK[a-f0-9]{32}$/,
	npm: /^npm_[A-Za-z0-9]{36}$/,
	pypi: /^pypi-[A-Za-z0-9_-]{50,}$/,
	datadog: /^ddapi_[a-z0-9]{40}$/,
	vercel: /^vercel_[A-Za-z0-9_-]{20,}$/,
	supabase: /^sbp_[a-f0-9]{40}$/,
	huggingface: /^hf_[A-Za-z0-9]{34}$/,
	grafana: /^glc_[A-Za-z0-9_-]{30,}$/,
	sendgrid: /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/,
	"slack-bot": /^xoxb-\d+-\d+-[A-Za-z0-9]+$/,
	"slack-user": /^xoxp-\d+-\d+-[A-Za-z0-9]+$/,
	// Heuristic patterns get [ENCRYPTED:name] marker prefix
	fastly: /^\[ENCRYPTED:fastly\][A-Za-z0-9_-]{32}$/,
	"aws-secret-key": /^\[ENCRYPTED:aws-secret-key\][A-Za-z0-9+/]{40}$/,
};

describe("contract tests", () => {
	test("roundtrip: decrypt(encrypt(text)) === text", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		for (const [_name, token] of Object.entries(SAMPLE_TOKENS)) {
			const text = `before ${token} after`;
			const encrypted = enc.encrypt(text);
			const decrypted = enc.decrypt(encrypted);
			expect(decrypted).toBe(text);
		}
		enc.destroy();
	});

	test("decrypt undoes one layer: decrypt(encrypt(encrypt(text))) === encrypt(text)", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const text = `token: ${token}`;
		const once = enc.encrypt(text);
		const twice = enc.encrypt(once);
		const back = enc.decrypt(twice);
		expect(back).toBe(once);
		enc.destroy();
	});

	test("no-op on text without tokens", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "Hello, this is plain text with no tokens.";
		expect(enc.encrypt(text)).toBe(text);
		expect(enc.decrypt(text)).toBe(text);
		enc.destroy();
	});

	test("deterministic: same key produces same ciphertext", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `key: ${SAMPLE_TOKENS["github-pat"]}`;
		expect(enc.encrypt(text)).toBe(enc.encrypt(text));
		enc.destroy();
	});

	test("different keys produce different ciphertexts", () => {
		const enc1 = new TokenEncryptor(TEST_KEY);
		const enc2 = new TokenEncryptor(ALT_KEY);
		const text = `key: ${SAMPLE_TOKENS["github-pat"]}`;
		expect(enc1.encrypt(text)).not.toBe(enc2.encrypt(text));
		enc1.destroy();
		enc2.destroy();
	});
});

describe("per-pattern roundtrip and format preservation", () => {
	const enc = new TokenEncryptor(TEST_KEY);

	for (const [name, token] of Object.entries(SAMPLE_TOKENS)) {
		test(`${name}: roundtrip`, () => {
			const text = token;
			const encrypted = enc.encrypt(text);
			expect(encrypted).not.toBe(text);
			const decrypted = enc.decrypt(encrypted);
			expect(decrypted).toBe(text);
		});

		const formatRegex = FORMAT_REGEXES[name];
		if (formatRegex) {
			test(`${name}: format preserved`, () => {
				const encrypted = enc.encrypt(token);
				expect(encrypted).toMatch(formatRegex);
				// Heuristic patterns add a marker prefix, so length won't match.
				if (!encrypted.startsWith("[ENCRYPTED:")) {
					expect(encrypted.length).toBe(token.length);
				}
			});
		}
	}
});

describe("minimum body length enforcement", () => {
	test("ghp_ with short body is not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "ghp_example";
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});

	test("ghp_ with 35 chars (one below min) is not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"; // 35 chars
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});

	test("ghp_ with exactly 36 chars IS matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // 36 chars
		expect(enc.encrypt(text)).not.toBe(text);
		enc.destroy();
	});

	test("sk-proj- with short body is not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "sk-proj-shortbody";
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});
});

describe("scanner tests", () => {
	test("overlapping prefixes: sk-ant-api03- wins over sk-", () => {
		const token = SAMPLE_TOKENS.anthropic!;
		const spans = scan(token, BUILTIN_PATTERNS);
		expect(spans.length).toBe(1);
		expect(spans[0]!.pattern.name).toBe("anthropic");
	});

	test("sk-proj- wins over sk-", () => {
		const token = SAMPLE_TOKENS.openai!;
		const spans = scan(token, BUILTIN_PATTERNS);
		expect(spans.length).toBe(1);
		expect(spans[0]!.pattern.name).toBe("openai");
	});

	test("multiple tokens in one text", () => {
		const text = `github: ${SAMPLE_TOKENS["github-pat"]} and npm: ${SAMPLE_TOKENS.npm}`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(2);
		expect(spans[0]!.pattern.name).toBe("github-pat");
		expect(spans[1]!.pattern.name).toBe("npm");
	});

	test("space-separated tokens both found", () => {
		const t1 = SAMPLE_TOKENS["github-pat"]!;
		const t2 = SAMPLE_TOKENS.npm!;
		const text = `${t1} ${t2}`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(2);
	});

	test("truly adjacent tokens (no delimiter) both found", () => {
		const t1 = SAMPLE_TOKENS["github-pat"]!;
		const t2 = SAMPLE_TOKENS.npm!;
		const text = `${t1}${t2}`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(2);
		expect(spans[0]!.pattern.name).toBe("github-pat");
		expect(spans[1]!.pattern.name).toBe("npm");
	});

	test("truly adjacent tokens roundtrip correctly", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const t1 = SAMPLE_TOKENS["github-pat"]!;
		const t2 = SAMPLE_TOKENS.npm!;
		const text = `${t1}${t2}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("greedy-body pattern adjacent to another token: both found", () => {
		// sk-proj- has a greedy body [A-Za-z0-9_-]{48,} which could swallow
		// the next token's prefix chars if not handled correctly.
		const t1 = SAMPLE_TOKENS.openai!;
		const t2 = SAMPLE_TOKENS.npm!;
		const text = `${t1}${t2}`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(2);
		expect(spans[0]!.pattern.name).toBe("openai");
		expect(spans[1]!.pattern.name).toBe("npm");
	});

	test("greedy-body adjacent roundtrips correctly", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const t1 = SAMPLE_TOKENS.openai!;
		const t2 = SAMPLE_TOKENS.npm!;
		const text = `${t1}${t2}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("greedy body with internal prefix but no valid right-side token: no split", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// OpenAI body contains "npm_" but what follows is too short to be a real npm token.
		const body = `${"A".repeat(48)}npm_SHORT`;
		const token = `sk-proj-${body}`;
		const encrypted = enc.encrypt(token);
		// The entire body should be encrypted as one OpenAI token, not split.
		expect(encrypted.startsWith("sk-proj-")).toBe(true);
		expect(encrypted).not.toContain("npm_SHORT");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("structured slack with internal prefix but no valid right-side: no split", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// Slack last segment contains AKIA but the tail is too short for an AWS key.
		const token = "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTAKIAfoo";
		const encrypted = enc.encrypt(token);
		// Entire thing should be one Slack token, not split at AKIA.
		expect(encrypted.startsWith("xoxb-")).toBe(true);
		expect(encrypted).not.toContain("AKIAfoo");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("structured slack adjacent to AWS key: both found", () => {
		const t1 = SAMPLE_TOKENS["slack-bot"]!;
		const t2 = SAMPLE_TOKENS["aws-access-key"]!;
		const text = `${t1}${t2}`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(2);
		expect(spans[0]!.pattern.name).toBe("slack-bot");
		expect(spans[1]!.pattern.name).toBe("aws-access-key");
	});

	test("structured slack adjacent to AWS key roundtrips", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const t1 = SAMPLE_TOKENS["slack-bot"]!;
		const t2 = SAMPLE_TOKENS["aws-access-key"]!;
		const text = `${t1}${t2}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("overlong RHS prevents truncation: sk-proj- with npm_ + extra char", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// npm_ pattern requires exactly 36 alphanumeric chars. Here we have 37
		// (36 B's + X), so the RHS is overlong and should NOT trigger a split.
		const body = `${"A".repeat(48)}npm_${"B".repeat(36)}X`;
		const token = `sk-proj-${body}`;
		const encrypted = enc.encrypt(token);
		// The entire body should be encrypted as one OpenAI token.
		expect(encrypted.startsWith("sk-proj-")).toBe(true);
		expect(encrypted).not.toContain("npm_");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("nested invalid RHS: sk-proj- with npm_ + AKIA tail does not split", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// npm_ body greedily consumes 36 B's + AKIAfoo (all alphanumeric = 43 chars).
		// wouldMatchSimpleAt tries truncating at AKIA: left body (36 B's) validates,
		// but AKIAfoo is only 3 chars after prefix (needs 16). If wouldMatchSimpleAt
		// doesn't verify the nested RHS, it falsely accepts the npm_ split.
		const body = `${"A".repeat(48)}npm_${"B".repeat(36)}AKIAfoo`;
		const token = `sk-proj-${body}`;
		const encrypted = enc.encrypt(token);
		expect(encrypted.startsWith("sk-proj-")).toBe(true);
		expect(encrypted).not.toContain("npm_");
		expect(encrypted).not.toContain("AKIAfoo");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("strict bodyRegex prevents false truncation on custom pattern", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// Register a pattern where bodyRegex is stricter than bodyAlphabet:
		// alphabet allows all alphanumeric, but regex only allows uppercase.
		enc.register({
			kind: "simple",
			name: "strict-upper",
			prefix: "foo_",
			bodyRegex: "[A-Z]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		// sk-proj- body contains "foo_abcdefgh" -- lowercase body fails regex.
		const body = `${"A".repeat(48)}foo_abcdefgh`;
		const token = `sk-proj-${body}`;
		const encrypted = enc.encrypt(token);
		// Should NOT split at foo_ since "abcdefgh" fails [A-Z]{8}.
		expect(encrypted.startsWith("sk-proj-")).toBe(true);
		expect(encrypted).not.toContain("foo_abcdefgh");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("tokens embedded in text are found", () => {
		const token = SAMPLE_TOKENS["aws-access-key"]!;
		const text = `key=${token}&secret=foo`;
		const spans = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(1);
		expect(spans[0]!.pattern.name).toBe("aws-access-key");
	});

	test("adversarial: many embedded prefixes in one body scans in reasonable time", () => {
		// Body with 50 embedded "npm_" substrings, none leading to a valid RHS.
		// Tests that recursive wouldMatchAt doesn't blow up combinatorially.
		const segment = "npm_"; // 4 chars
		const filler = "AAAA"; // 4 chars, keeps body in alphanumeric alphabet
		const body = (segment + filler).repeat(50) + "A".repeat(8); // 408 chars
		const token = `sk-proj-${body}`;
		const start = performance.now();
		const spans = scan(token, BUILTIN_PATTERNS);
		const elapsed = performance.now() - start;
		// Should complete well under 1 second even with 50 prefix positions.
		expect(elapsed).toBeLessThan(1000);
		// Should produce a single OpenAI span (all npm_ RHS bodies are too short).
		expect(spans.length).toBe(1);
		expect(spans[0]!.pattern.name).toBe("openai");
	});
});

describe("structured token tests", () => {
	test("sendgrid: segments encrypted independently, dots preserved", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.sendgrid!;
		const encrypted = enc.encrypt(token);
		expect(encrypted).toMatch(/^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/);
		expect(encrypted).not.toBe(token);
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("sendgrid: rejects overlong token (trailing body chars)", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = `${SAMPLE_TOKENS.sendgrid!}Z`;
		const encrypted = enc.encrypt(token);
		expect(encrypted).toBe(token);
		enc.destroy();
	});

	test("slack-bot: segments encrypted, dashes preserved", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["slack-bot"]!;
		const encrypted = enc.encrypt(token);
		expect(encrypted.startsWith("xoxb-")).toBe(true);
		const encParts = encrypted.slice(5).split("-");
		const origParts = token.slice(5).split("-");
		expect(encParts.length).toBe(origParts.length);
		// Each segment preserves length
		for (let i = 0; i < origParts.length; i++) {
			expect(encParts[i]!.length).toBe(origParts[i]!.length);
		}
		// Digit segments stay digits
		expect(encParts[0]).toMatch(/^\d+$/);
		expect(encParts[1]).toMatch(/^\d+$/);
		// Last segment stays alphanumeric
		expect(encParts[2]).toMatch(/^[A-Za-z0-9]+$/);
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("slack: token followed by dash punctuation is still matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["slack-bot"]!;
		const text = `${token}- some text`;
		const encrypted = enc.encrypt(text);
		expect(encrypted.endsWith("- some text")).toBe(true);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("slack: short segments left as-is", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// Token with a very short first segment
		const token = "xoxb-12-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXab";
		const encrypted = enc.encrypt(token);
		// The "12" segment (len 2) should be preserved as-is
		const encParts = encrypted.slice(5).split("-");
		expect(encParts[0]).toBe("12");
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});
});

describe("custom pattern tests", () => {
	test("registered pattern is found and roundtrips", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.register({
			kind: "simple",
			name: "my-service",
			prefix: "myapp_",
			bodyRegex: "[A-Za-z0-9]{32}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 32,
		});
		const token = "myapp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
		const encrypted = enc.encrypt(token);
		expect(encrypted).not.toBe(token);
		expect(encrypted).toMatch(/^myapp_[A-Za-z0-9]{32}$/);
		expect(enc.decrypt(encrypted)).toBe(token);
		enc.destroy();
	});

	test("fixed-length body rejects match when followed by more body chars", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.register({
			kind: "simple",
			name: "test-pattern",
			prefix: "test_",
			bodyRegex: "[A-Za-z0-9]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		// 13 alphanumeric chars after prefix -- no known prefix follows, so rejected
		const text = "test_ABCDEFGHextra";
		const encrypted = enc.encrypt(text);
		expect(encrypted).toBe(text);
		enc.destroy();
	});

	test("fixed-length body matches when followed by non-body char", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.register({
			kind: "simple",
			name: "test-pattern",
			prefix: "test_",
			bodyRegex: "[A-Za-z0-9]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		const text = "test_ABCDEFGH.extra";
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(encrypted.endsWith(".extra")).toBe(true);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("fixed-length body matches when followed by a known token prefix", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.register({
			kind: "simple",
			name: "test-a",
			prefix: "aaa_",
			bodyRegex: "[A-Za-z0-9]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		enc.register({
			kind: "simple",
			name: "test-b",
			prefix: "bbb_",
			bodyRegex: "[A-Za-z0-9]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});
		// Two tokens directly adjacent -- body chars overlap with next prefix
		const text = "aaa_ABCDEFGHbbb_IJKLMNOP";
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});
});

describe("types filter", () => {
	test("only encrypts specified types", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const ghToken = SAMPLE_TOKENS["github-pat"]!;
		const npmToken = SAMPLE_TOKENS.npm!;
		const text = `gh: ${ghToken} npm: ${npmToken}`;
		const encrypted = enc.encrypt(text, { types: ["github-pat"] });
		// GitHub token should be encrypted
		expect(encrypted).not.toContain(ghToken);
		// npm token should be untouched
		expect(encrypted).toContain(npmToken);
		enc.destroy();
	});

	test("filtered encrypt roundtrips with same filter on decrypt", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const ghToken = SAMPLE_TOKENS["github-pat"]!;
		const npmToken = SAMPLE_TOKENS.npm!;
		const text = `gh: ${ghToken} npm: ${npmToken}`;
		const opts = { types: ["github-pat"] };
		const encrypted = enc.encrypt(text, opts);
		const decrypted = enc.decrypt(encrypted, opts);
		expect(decrypted).toBe(text);
		enc.destroy();
	});

	test("filtered encrypt still detects adjacent tokens correctly", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const ghToken = SAMPLE_TOKENS["github-pat"]!;
		const npmToken = SAMPLE_TOKENS.npm!;
		// Adjacent with no delimiter -- npm_ prefix must be recognized as boundary
		// even though npm is not in the types filter.
		const text = `${ghToken}${npmToken}`;
		const opts = { types: ["github-pat"] };
		const encrypted = enc.encrypt(text, opts);
		// GitHub token encrypted, npm untouched
		expect(encrypted).not.toBe(text);
		expect(encrypted.endsWith(npmToken)).toBe(true);
		// Roundtrips with same filter
		expect(enc.decrypt(encrypted, opts)).toBe(text);
		enc.destroy();
	});

	test("filtered encrypt then unfiltered decrypt corrupts untouched tokens", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const ghToken = SAMPLE_TOKENS["github-pat"]!;
		const npmToken = SAMPLE_TOKENS.npm!;
		const text = `gh: ${ghToken} npm: ${npmToken}`;
		const encrypted = enc.encrypt(text, { types: ["github-pat"] });
		// Unfiltered decrypt will also "decrypt" the untouched npm token
		const decrypted = enc.decrypt(encrypted);
		expect(decrypted).not.toBe(text);
		expect(decrypted).not.toContain(npmToken);
		enc.destroy();
	});
});

describe("tweak option", () => {
	test("same token with different tweaks produces different ciphertext", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const tweak1 = new TextEncoder().encode("doc-1");
		const tweak2 = new TextEncoder().encode("doc-2");
		const enc1 = enc.encrypt(token, { tweak: tweak1 });
		const enc2 = enc.encrypt(token, { tweak: tweak2 });
		expect(enc1).not.toBe(enc2);
		// Each roundtrips with its own tweak
		expect(enc.decrypt(enc1, { tweak: tweak1 })).toBe(token);
		expect(enc.decrypt(enc2, { tweak: tweak2 })).toBe(token);
		enc.destroy();
	});

	test("tweak mismatch does not roundtrip", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const tweak = new TextEncoder().encode("doc-1");
		const encrypted = enc.encrypt(token, { tweak });
		// Decrypt without tweak does not recover original
		const decrypted = enc.decrypt(encrypted);
		expect(decrypted).not.toBe(token);
		enc.destroy();
	});
});

describe("destroy lifecycle", () => {
	test("encrypt throws after destroy", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.destroy();
		expect(() => enc.encrypt("text")).toThrow("destroyed");
	});

	test("decrypt throws after destroy", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.destroy();
		expect(() => enc.decrypt("text")).toThrow("destroyed");
	});

	test("register throws after destroy", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.destroy();
		expect(() =>
			enc.register({
				kind: "simple",
				name: "x",
				prefix: "x_",
				bodyRegex: "[a-z]{8}",
				bodyAlphabet: ALPHANUMERIC,
				minBodyLength: 8,
			}),
		).toThrow("destroyed");
	});

	test("destroy is idempotent", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		enc.destroy();
		expect(() => enc.destroy()).not.toThrow();
	});

	test("constructor rejects invalid key length", () => {
		expect(() => new TokenEncryptor(new Uint8Array(15))).toThrow("16 bytes");
		expect(() => new TokenEncryptor(new Uint8Array(17))).toThrow("16 bytes");
	});

	test("caller mutating key after construction doesn't affect encryptor", () => {
		const key = new Uint8Array(TEST_KEY);
		const enc = new TokenEncryptor(key);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const encrypted1 = enc.encrypt(token);
		// Mutate the original key
		key.fill(0xff);
		const encrypted2 = enc.encrypt(token);
		expect(encrypted2).toBe(encrypted1);
		enc.destroy();
	});
});

describe("heuristic pattern tests", () => {
	test("heuristic patterns are active by default", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `key: ${token}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		enc.destroy();
	});

	test("encrypt adds [ENCRYPTED:name] marker", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const encrypted = enc.encrypt(token);
		expect(encrypted).toMatch(/^\[ENCRYPTED:fastly\][A-Za-z0-9_-]{32}$/);
		enc.destroy();
	});

	test("decrypt on plaintext is safe: no marker means no transformation", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// A random-looking 32-char string without marker is NOT touched
		const text = "5lYCIuNxQuC-WFvIvHNmjO0PvaVqrtos";
		expect(enc.decrypt(text)).toBe(text);
		enc.destroy();
	});

	test("decrypt on plaintext with AWS-like string is safe", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
		expect(enc.decrypt(text)).toBe(text);
		enc.destroy();
	});

	test("fastly token roundtrips", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `key: ${token}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("fastly encrypted body is format-preserving (within marker)", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const encrypted = enc.encrypt(token);
		// Strip marker and check body format
		const body = encrypted.replace(/^\[ENCRYPTED:fastly\]/, "");
		expect(body).toMatch(/^[A-Za-z0-9_-]{32}$/);
		expect(body.length).toBe(32);
		enc.destroy();
	});

	test("aws secret key with slashes roundtrips", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["aws-secret-key"]!;
		expect(token).toContain("/");
		const text = `secret=${token}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(encrypted).toContain("[ENCRYPTED:aws-secret-key]");
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("aws secret key encrypted body format preserved", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["aws-secret-key"]!;
		const encrypted = enc.encrypt(token);
		const body = encrypted.replace(/^\[ENCRYPTED:aws-secret-key\]/, "");
		expect(body).toMatch(/^[A-Za-z0-9+/]{40}$/);
		expect(body.length).toBe(40);
		enc.destroy();
	});

	test("low-entropy string is not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});

	test("short base64url string is not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = "abc123XYZ";
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});

	test("word boundary required: embedded in longer string not matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `prefix${token}suffix`;
		expect(enc.encrypt(text)).toBe(text);
		enc.destroy();
	});

	test("heuristic with delimiter boundaries is matched", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `key="${token}"`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(encrypted.startsWith('key="[ENCRYPTED:fastly]')).toBe(true);
		expect(encrypted.endsWith('"')).toBe(true);
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("prefix-based pattern takes priority over heuristic in overlap", () => {
		const token = SAMPLE_TOKENS["github-pat"]!;
		const spans = scan(token, BUILTIN_PATTERNS);
		expect(spans.length).toBe(1);
		expect(spans[0]!.pattern.name).toBe("github-pat");
	});

	test("excluding heuristic via types filter leaves it unchanged", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `key: ${token}`;
		const encrypted = enc.encrypt(text, { types: ["github-pat"] });
		expect(encrypted).toBe(text);
		enc.destroy();
	});

	test("multiple heuristic tokens in one document", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const fastly = SAMPLE_TOKENS.fastly!;
		const aws = SAMPLE_TOKENS["aws-secret-key"]!;
		const text = `fastly=${fastly} aws=${aws}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toBe(text);
		expect(encrypted).toContain("[ENCRYPTED:fastly]");
		expect(encrypted).toContain("[ENCRYPTED:aws-secret-key]");
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("heuristic tokens in reverse registry order roundtrip", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const fastly = SAMPLE_TOKENS.fastly!;
		const aws = SAMPLE_TOKENS["aws-secret-key"]!;
		// AWS before Fastly — reversed from registry order
		const text = `aws=${aws} fastly=${fastly}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).toContain("[ENCRYPTED:aws-secret-key]");
		expect(encrypted).toContain("[ENCRYPTED:fastly]");
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});

	test("malformed marker with overlong body is left unchanged", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// 33 base64url chars after marker — one too many for fastly (expects 32)
		const text = "x [ENCRYPTED:fastly]ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg y";
		expect(enc.decrypt(text)).toBe(text);
		enc.destroy();
	});

	test("malformed marker with underlong body is left unchanged", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// 31 chars — one too few
		const text = "[ENCRYPTED:fastly]ABCDEFGHIJKLMNOPQRSTUVWXYZabcde";
		expect(enc.decrypt(text)).toBe(text);
		enc.destroy();
	});

	test("decrypt undoes one layer for heuristic tokens", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const once = enc.encrypt(token);
		const twice = enc.encrypt(once);
		const back = enc.decrypt(twice);
		expect(back).toBe(once);
		enc.destroy();
	});

	test("mixed prefix and heuristic tokens roundtrip", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const gh = SAMPLE_TOKENS["github-pat"]!;
		const fastly = SAMPLE_TOKENS.fastly!;
		const text = `gh=${gh} fastly=${fastly}`;
		const encrypted = enc.encrypt(text);
		expect(encrypted).not.toContain(gh);
		expect(encrypted).toContain("[ENCRYPTED:fastly]");
		expect(enc.decrypt(encrypted)).toBe(text);
		enc.destroy();
	});
});

describe("encryptWithSpans", () => {
	test("returns encrypted text identical to encrypt()", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `gh: ${SAMPLE_TOKENS["github-pat"]} npm: ${SAMPLE_TOKENS.npm}`;
		const { text: withSpans } = enc.encryptWithSpans(text);
		const plain = enc.encrypt(text);
		expect(withSpans).toBe(plain);
		enc.destroy();
	});

	test("span count matches scan count", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `gh: ${SAMPLE_TOKENS["github-pat"]} npm: ${SAMPLE_TOKENS.npm}`;
		const { spans } = enc.encryptWithSpans(text);
		const scanned = scan(text, BUILTIN_PATTERNS);
		expect(spans.length).toBe(scanned.length);
		enc.destroy();
	});

	test("each span.original is the correct substring of input", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `gh: ${SAMPLE_TOKENS["github-pat"]} npm: ${SAMPLE_TOKENS.npm}`;
		const { spans } = enc.encryptWithSpans(text);
		for (const span of spans) {
			expect(span.original).toBe(text.slice(span.start, span.end));
		}
		enc.destroy();
	});

	test("each span.encrypted appears at the correct position in output", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `gh: ${SAMPLE_TOKENS["github-pat"]} npm: ${SAMPLE_TOKENS.npm}`;
		const { text: encrypted, spans } = enc.encryptWithSpans(text);
		// Rebuild the encrypted text from spans and verify it matches
		let rebuilt = "";
		let cursor = 0;
		for (const span of spans) {
			rebuilt += text.slice(cursor, span.start);
			rebuilt += span.encrypted;
			cursor = span.end;
		}
		rebuilt += text.slice(cursor);
		expect(rebuilt).toBe(encrypted);
		enc.destroy();
	});

	test("empty text returns empty spans", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const { text, spans } = enc.encryptWithSpans("");
		expect(text).toBe("");
		expect(spans).toEqual([]);
		enc.destroy();
	});

	test("no tokens returns input text and empty spans", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const input = "Hello, no tokens here.";
		const { text, spans } = enc.encryptWithSpans(input);
		expect(text).toBe(input);
		expect(spans).toEqual([]);
		enc.destroy();
	});

	test("heuristic token: span.encrypted includes marker", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const text = `key: ${token}`;
		const { spans } = enc.encryptWithSpans(text);
		expect(spans.length).toBe(1);
		expect(spans[0]!.original).toBe(token);
		expect(spans[0]!.encrypted).toMatch(/^\[ENCRYPTED:fastly\]/);
		expect(spans[0]!.patternName).toBe("fastly");
		enc.destroy();
	});

	test("heuristic token: span.original is the bare body (no marker)", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.fastly!;
		const { spans } = enc.encryptWithSpans(token);
		expect(spans[0]!.original).toBe(token);
		expect(spans[0]!.original).not.toContain("[ENCRYPTED:");
		enc.destroy();
	});

	test("types filter limits which spans are returned", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const text = `gh: ${SAMPLE_TOKENS["github-pat"]} npm: ${SAMPLE_TOKENS.npm}`;
		const { spans } = enc.encryptWithSpans(text, { types: ["github-pat"] });
		expect(spans.length).toBe(1);
		expect(spans[0]!.patternName).toBe("github-pat");
		enc.destroy();
	});

	test("custom register() pattern appears in spans with correct precedence", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		// Register a custom pattern that also matches ghp_ but with a different name
		enc.register({
			kind: "simple",
			name: "custom-ghp",
			prefix: "ghp_",
			bodyRegex: "[A-Za-z0-9]{36}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 36,
		});
		const token = SAMPLE_TOKENS["github-pat"]!;
		const { spans } = enc.encryptWithSpans(token);
		expect(spans.length).toBe(1);
		// Custom pattern was register()ed (unshift), so it takes precedence
		expect(spans[0]!.patternName).toBe("custom-ghp");
		enc.destroy();
	});

	test("structured token spans are correct", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS.sendgrid!;
		const text = `key: ${token}`;
		const { spans } = enc.encryptWithSpans(text);
		expect(spans.length).toBe(1);
		expect(spans[0]!.original).toBe(token);
		expect(spans[0]!.encrypted).toMatch(/^SG\./);
		expect(spans[0]!.encrypted).not.toBe(token);
		expect(spans[0]!.patternName).toBe("sendgrid");
		enc.destroy();
	});

	test("encrypt() delegates to encryptWithSpans()", () => {
		// Verify encrypt() and encryptWithSpans() produce identical results
		// across all sample tokens
		const enc = new TokenEncryptor(TEST_KEY);
		for (const [_name, token] of Object.entries(SAMPLE_TOKENS)) {
			const text = `before ${token} after`;
			const encrypted = enc.encrypt(text);
			const { text: withSpans } = enc.encryptWithSpans(text);
			expect(withSpans).toBe(encrypted);
		}
		enc.destroy();
	});

	test("mutating returned spans does not affect encryptor", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const { spans } = enc.encryptWithSpans(token);

		// Mutate the returned span
		spans[0]!.patternName = "HACKED";
		spans[0]!.original = "HACKED";

		// Encryptor is unaffected — produces the same result
		const { spans: spans2 } = enc.encryptWithSpans(token);
		expect(spans2[0]!.patternName).toBe("github-pat");
		expect(spans2[0]!.original).toBe(token);
		enc.destroy();
	});

	test("mutating BUILTIN_PATTERNS array does not affect existing encryptors", () => {
		const enc = new TokenEncryptor(TEST_KEY);
		const token = SAMPLE_TOKENS["github-pat"]!;
		const before = enc.encrypt(token);

		// Mutate the exported array (push a dummy)
		const original = BUILTIN_PATTERNS.length;
		(BUILTIN_PATTERNS as TokenPattern[]).push({
			kind: "simple",
			name: "injected",
			prefix: "zzz_",
			bodyRegex: "[a-z]{8}",
			bodyAlphabet: ALPHANUMERIC,
			minBodyLength: 8,
		});

		// Existing encryptor is unaffected (it copied the array at construction)
		const after = enc.encrypt(token);
		expect(after).toBe(before);

		// Cleanup
		(BUILTIN_PATTERNS as TokenPattern[]).pop();
		expect(BUILTIN_PATTERNS.length).toBe(original);
		enc.destroy();
	});
});

describe("shannon entropy", () => {
	test("entropy of uniform distribution", () => {
		// All unique chars -> max entropy
		const s = "abcdefghijklmnop"; // 16 unique chars
		const e = shannonEntropy(s);
		expect(e).toBeCloseTo(4.0, 2); // log2(16) = 4
	});

	test("entropy of single repeated char is 0", () => {
		expect(shannonEntropy("aaaaaaaaaa")).toBe(0);
	});

	test("entropy of empty string is 0", () => {
		expect(shannonEntropy("")).toBe(0);
	});

	test("real fastly token has high entropy", () => {
		const e = shannonEntropy("5lYCIuNxQuC-WFvIvHNmjO0PvaVqrtos");
		expect(e).toBeGreaterThan(4.0);
	});
});
