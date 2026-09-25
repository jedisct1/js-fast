// Scans each adversarial text once and prints one JSON line per text as soon as it is done.
// scanner-timing.test.ts runs it in a child process, so it can kill a scan that hangs and tell which one it was.
import { BUILTIN_PATTERNS, scan } from "../src/tokens/index.ts";
import { ADVERSARIAL_TEXTS } from "./helpers.ts";

const size = Number(process.argv[2]);

// Short texts first, so the first family measured doesn't pay for compiling the scanner.
for (const make of Object.values(ADVERSARIAL_TEXTS)) {
	scan(make(2_000), BUILTIN_PATTERNS);
}

for (const [name, make] of Object.entries(ADVERSARIAL_TEXTS)) {
	const text = make(size);
	const start = performance.now();
	scan(text, BUILTIN_PATTERNS);
	const ms = performance.now() - start;
	process.stdout.write(`${JSON.stringify({ name, ms })}\n`);
}
