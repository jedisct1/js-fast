import {
	ALPHANUMERIC,
	ALPHANUMERIC_LOWER,
	ALPHANUMERIC_UPPER,
	BASE64,
	BASE64URL,
	DIGITS,
	HEX_LOWER,
} from "./alphabets.ts";
import type {
	Alphabet,
	HeuristicTokenPattern,
	SimpleTokenPattern,
	StructuredTokenPattern,
	TokenPattern,
} from "./types.ts";

const MIN_SEGMENT_LENGTH = 4;

function simple(
	name: string,
	prefix: string,
	bodyRegex: string,
	bodyAlphabet: Alphabet,
	minBodyLength: number,
): SimpleTokenPattern {
	return {
		kind: "simple",
		name,
		prefix,
		bodyRegex,
		bodyAlphabet,
		minBodyLength,
	};
}

function makeSlackPattern(
	prefix: string,
	name: string,
): StructuredTokenPattern {
	return {
		kind: "structured",
		name,
		prefix,
		trailingAlphabet: ALPHANUMERIC,
		fullRegex: `${escapeRegex(prefix)}\\d+-\\d+-[A-Za-z0-9]+`,
		parse(body: string): { segments: string[]; alphabets: Alphabet[] } | null {
			const parts = body.split("-");
			if (parts.length < 3) return null;
			let totalLen = 0;
			for (const p of parts) totalLen += p.length;
			if (totalLen < 20) return null;
			const alphabets: Alphabet[] = [];
			for (const part of parts) {
				if (/^\d+$/.test(part)) {
					alphabets.push(DIGITS);
				} else if (/^[A-Za-z0-9]+$/.test(part)) {
					alphabets.push(ALPHANUMERIC);
				} else {
					return null;
				}
			}
			return { segments: parts, alphabets };
		},
		format(segments: string[]): string {
			return segments.join("-");
		},
	};
}

function heuristic(
	name: string,
	bodyAlphabet: Alphabet,
	minLength: number,
	maxLength: number,
	minEntropy: number,
	minCharClasses: number,
): HeuristicTokenPattern {
	return {
		kind: "heuristic",
		name,
		prefix: "",
		bodyAlphabet,
		minLength,
		maxLength,
		minEntropy,
		minCharClasses,
	};
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const sendgridPattern: StructuredTokenPattern = {
	kind: "structured",
	name: "sendgrid",
	prefix: "SG.",
	trailingAlphabet: BASE64URL,
	fullRegex: `SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`,
	parse(body: string): { segments: string[]; alphabets: Alphabet[] } | null {
		const dotIdx = body.indexOf(".");
		if (dotIdx === -1) return null;
		const seg1 = body.slice(0, dotIdx);
		const seg2 = body.slice(dotIdx + 1);
		if (seg1.length !== 22 || seg2.length !== 43) return null;
		return {
			segments: [seg1, seg2],
			alphabets: [BASE64URL, BASE64URL],
		};
	},
	format(segments: string[]): string {
		return `${segments[0]}.${segments[1]}`;
	},
};

export const BUILTIN_PATTERNS: readonly TokenPattern[] = [
	// Longest prefixes first for correct overlap resolution.
	// Anthropic must come before generic sk- patterns.
	simple("anthropic", "sk-ant-api03-", "[A-Za-z0-9_-]{80,}", BASE64URL, 80),

	// OpenAI sk-proj- must come before sk-
	simple("openai", "sk-proj-", "[A-Za-z0-9_-]{48,}", BASE64URL, 48),
	simple("openai-legacy", "sk-", "[A-Za-z0-9]{48}", ALPHANUMERIC, 48),

	// Stripe (8-char prefixes)
	simple(
		"stripe-secret-live",
		"sk_live_",
		"[A-Za-z0-9]{24,}",
		ALPHANUMERIC,
		24,
	),
	simple(
		"stripe-publish-live",
		"pk_live_",
		"[A-Za-z0-9]{24,}",
		ALPHANUMERIC,
		24,
	),
	simple(
		"stripe-secret-test",
		"sk_test_",
		"[A-Za-z0-9]{24,}",
		ALPHANUMERIC,
		24,
	),
	simple(
		"stripe-publish-test",
		"pk_test_",
		"[A-Za-z0-9]{24,}",
		ALPHANUMERIC,
		24,
	),

	// Vercel (7-char prefix)
	simple("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", BASE64URL, 20),

	// GitLab (6-char prefix)
	simple("gitlab", "glpat-", "[A-Za-z0-9_-]{20}", BASE64URL, 20),

	// Datadog (6-char prefix)
	simple("datadog", "ddapi_", "[a-z0-9]{40}", ALPHANUMERIC_LOWER, 40),

	// PyPI (5-char prefix)
	simple("pypi", "pypi-", "[A-Za-z0-9_-]{50,}", BASE64URL, 50),

	// Slack (5-char prefix, structured)
	makeSlackPattern("xoxb-", "slack-bot"),
	makeSlackPattern("xoxp-", "slack-user"),

	// GitHub (4-char prefix)
	simple("github-pat", "ghp_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
	simple("github-oauth", "gho_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
	simple("github-user", "ghu_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
	simple("github-server", "ghs_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
	simple("github-refresh", "ghr_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),

	// AWS (4-char prefix)
	simple("aws-access-key", "AKIA", "[A-Z0-9]{16}", ALPHANUMERIC_UPPER, 16),

	// Google (4-char prefix)
	simple("google-api", "AIza", "[A-Za-z0-9_-]{35}", BASE64URL, 35),

	// npm (4-char prefix)
	simple("npm", "npm_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),

	// Supabase (4-char prefix)
	simple("supabase", "sbp_", "[a-f0-9]{40}", HEX_LOWER, 40),

	// Grafana (4-char prefix)
	simple("grafana", "glc_", "[A-Za-z0-9_-]{30,}", BASE64URL, 30),

	// HuggingFace (3-char prefix)
	simple("huggingface", "hf_", "[A-Za-z0-9]{34}", ALPHANUMERIC, 34),

	// SendGrid (3-char prefix, structured)
	sendgridPattern,

	// Twilio (2-char prefix)
	simple("twilio", "SK", "[a-f0-9]{32}", HEX_LOWER, 32),

	// Heuristic patterns (no prefix, entropy-based).
	// These are ordered last so prefix-based patterns take priority.
	heuristic("fastly", BASE64URL, 32, 32, 4.0, 3),
	heuristic("aws-secret-key", BASE64, 40, 40, 4.0, 3),
];

export { MIN_SEGMENT_LENGTH };
