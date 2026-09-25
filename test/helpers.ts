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
