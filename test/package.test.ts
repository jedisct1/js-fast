import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import * as core from "../src/index.ts";
import * as tokens from "../src/tokens/index.ts";

for (const [specifier, source] of [
	["fast-cipher", core],
	["fast-cipher/tokens", tokens],
] as const) {
	test(`Node loads every export from ${specifier}`, () => {
		const result = spawnSync(
			"node",
			[
				"--input-type=module",
				"--eval",
				`import * as api from ${JSON.stringify(specifier)};
				 console.log(JSON.stringify(Object.keys(api).sort()));`,
			],
			{ cwd: new URL("..", import.meta.url), encoding: "utf8" },
		);
		expect(result.error).toBeUndefined();
		expect(result.stderr).toBe("");
		expect(result.status).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual(Object.keys(source).sort());
	});
}
