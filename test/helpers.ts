/** Realistic sample tokens for each built-in pattern. */
export const SAMPLE_TOKENS: Record<string, string> = {
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

export function hex(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "hex"));
}
