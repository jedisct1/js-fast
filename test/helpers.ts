/** Fake credentials use ROT13 because GitHub also scans base64-encoded secrets. */
export function decodeSecret(value: string): string {
	return value.replace(/[A-Za-z]/g, (char) => {
		const start = char <= "Z" ? 65 : 97;
		return String.fromCharCode(
			start + ((char.charCodeAt(0) - start + 13) % 26),
		);
	});
}

/** Realistic sample tokens for each built-in pattern. */
export const SAMPLE_TOKENS: Record<string, string> = {
	"github-pat": decodeSecret("tuc_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	"github-oauth": decodeSecret("tub_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	"github-user": decodeSecret("tuh_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	"github-server": decodeSecret("tuf_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	"github-refresh": decodeSecret("tue_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	gitlab: decodeSecret("tycng-NOPQRSTUVWXYZABCDEFG"),
	"aws-access-key": decodeSecret("NXVNVBFSBQAA7RKNZCYR"),
	openai: decodeSecret(
		"fx-cebw-NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789_-NOPQRSTU",
	),
	"openai-legacy": decodeSecret(
		"fx-NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghi",
	),
	anthropic: decodeSecret(
		"fx-nag-ncv03-NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789_-NOPQRSTUVWXYZABCDEFGHIJKLMn",
	),
	"stripe-secret-live": decodeSecret(
		"fx_yvir_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw",
	),
	"stripe-publish-live": decodeSecret(
		"cx_yvir_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw",
	),
	"stripe-secret-test": decodeSecret(
		"fx_grfg_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw",
	),
	"stripe-publish-test": decodeSecret(
		"cx_grfg_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw",
	),
	"google-api": decodeSecret("NVmnFlN1234567890nopqrstuvwxyzabcdefghi"),
	twilio: decodeSecret("FX0123456789nopqrs0123456789nopqrs"),
	npm: decodeSecret("acz_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvw"),
	pypi: decodeSecret(
		"clcv-NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm01",
	),
	datadog: decodeSecret("qqncv_nopqrstuvwxyzabcdefghijklm0123456789nopq"),
	vercel: decodeSecret("irepry_NOPQRSTUVWXYZABCDEFGHIJKLMno"),
	supabase: decodeSecret("foc_0123456789nopqrs0123456789nopqrs01234567"),
	huggingface: decodeSecret("us_NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstu"),
	grafana: decodeSecret("typ_NOPQRSTUVWXYZABCDEFGHIJKLMnopq"),
	sendgrid: decodeSecret(
		"FT.NOPQRSTUVWXYZABCDEFGHI.NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcd",
	),
	"slack-bot": decodeSecret(
		"kbko-123456789012-1234567890123-NOPQRSTUVWXYZABCDEFGHIJKno",
	),
	"slack-user": decodeSecret(
		"kbkc-123456789012-1234567890123-NOPQRSTUVWXYZABCDEFGHIJKno",
	),
	fastly: decodeSecret("5yLPVhAkDhP-JSiViUAzwB0CinIdegbf"),
	"aws-secret-key": decodeSecret("jWnyeKHgaSRZV/X7ZQRAT/oCkEsvPLRKNZCYRXRL"),
};

export function hex(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "hex"));
}

const repeatTo = (unit: string, size: number): string =>
	unit.repeat(Math.ceil(size / unit.length)).slice(0, size);

/** A made-up AWS access key, built at run time so secret scanners ignore it. */
export const AWS_KEY = `AKIA${"B".repeat(16)}`;

/**
 * Texts packed with prefixes, which used to make the scanner quadratic or worse.
 * Each function returns a text of the given length.
 */
export const ADVERSARIAL_TEXTS: Record<string, (size: number) => string> = {
	AKIA: (n) => repeatTo("AKIA", n),
	"AWS keys": (n) => repeatTo(AWS_KEY, n),
	AIza: (n) => repeatTo("AIza", n),
	"pypi-": (n) => repeatTo("pypi-", n),
	glc_: (n) => repeatTo("glc_", n),
	"glpat-": (n) => repeatTo("glpat-", n),
	vercel_: (n) => repeatTo("vercel_", n),
	"sk-proj-": (n) => repeatTo("sk-proj-", n),
	"sk-ant-api03-": (n) => repeatTo("sk-ant-api03-", n),
	"slack + AWS keys": (n) => `xoxb-1-1-${repeatTo(AWS_KEY, n - 9)}`,
	"slack + whole AWS keys": (n) =>
		`xoxb-1-1-${AWS_KEY.repeat(Math.floor((n - 9) / 20))}`.padEnd(n, " "),
	"slack + Twilio keys": (n) =>
		`xoxb-1-1-${repeatTo(`SK${"a".repeat(32)}`, n - 9)}`,
	"slack + AIza": (n) => `xoxb-1-1-${repeatTo("AIza", n - 9)}`,
	"slack user + glc_": (n) => `xoxp-1-1-1-${repeatTo("glc_", n - 11)}`,
	"sendgrid + AIza": (n) => `SG.${repeatTo("AIza", n - 3)}`,
	mixed: (n) =>
		repeatTo("AKIAglc_AIzasbp_pypi-hf_SKnpm_vercel_sk-proj-xoxb-1-1-", n),
};
