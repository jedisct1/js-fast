import { expect, test } from "bun:test";
import { ADVERSARIAL_TEXTS } from "./helpers.ts";

const SIZE = 200_000;
const LIMIT_MS = 250;
const DEADLINE_MS = 30_000;

// A synchronous scan can't be interrupted from inside the process, so a
// regression back to quadratic time would hang the test run instead of failing.
// The scans run in a child process that this test kills at a deadline.
test(
	"adversarial texts of 200 KB scan in milliseconds",
	async () => {
		const child = Bun.spawn(
			[process.execPath, `${import.meta.dir}/scan-timing-child.ts`, `${SIZE}`],
			{ stdout: "pipe", stderr: "pipe" },
		);
		const timer = setTimeout(() => child.kill("SIGKILL"), DEADLINE_MS);
		const [output, errors, exitCode] = await Promise.all([
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
			child.exited,
		]);
		clearTimeout(timer);

		const results: { name: string; ms: number }[] = output
			.split("\n")
			.filter((line) => line.length > 0)
			.map((line) => JSON.parse(line));
		const done = new Set(results.map((r) => r.name));
		// After a kill, the first unfinished family is the one that hung.
		const unfinished = Object.keys(ADVERSARIAL_TEXTS).filter(
			(name) => !done.has(name),
		);
		expect({ exitCode, signal: child.signalCode, errors, unfinished }).toEqual({
			exitCode: 0,
			signal: null,
			errors: "",
			unfinished: [],
		});
		const slow = results
			.filter((r) => r.ms > LIMIT_MS)
			.map((r) => `${r.name}: ${Math.round(r.ms)} ms`);
		expect(slow).toEqual([]);
	},
	DEADLINE_MS + 5_000,
);
