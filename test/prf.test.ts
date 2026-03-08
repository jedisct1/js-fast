import { describe, expect, test } from "bun:test";
import { deriveKey } from "../src/prf.ts";

const baseKey = new Uint8Array(16).fill(0x01);
const alternateKey = new Uint8Array(16).fill(0x42);

describe("deriveKey", () => {
	test("returns the same bytes for the same inputs", () => {
		const input = new Uint8Array([1, 2, 3, 4]);
		const output = deriveKey(alternateKey, input, 32);

		expect(deriveKey(alternateKey, input, 32)).toEqual(output);
	});

	test("changes output when the key changes", () => {
		const input = new Uint8Array([1, 2, 3]);

		expect(deriveKey(baseKey, input, 32)).not.toEqual(
			deriveKey(new Uint8Array(16).fill(0x02), input, 32),
		);
	});

	test("changes output when the input changes", () => {
		expect(deriveKey(baseKey, new Uint8Array([1, 2, 3]), 32)).not.toEqual(
			deriveKey(baseKey, new Uint8Array([4, 5, 6]), 32),
		);
	});

	test("returns exactly the requested number of bytes", () => {
		const input = new Uint8Array([1]);

		expect(deriveKey(baseKey, input, 16)).toHaveLength(16);
		expect(deriveKey(baseKey, input, 32)).toHaveLength(32);
		expect(deriveKey(baseKey, input, 48)).toHaveLength(48);
	});

	test("extends shorter outputs by appending more blocks", () => {
		const input = new Uint8Array([1, 2, 3]);
		const shortOutput = deriveKey(baseKey, input, 16);
		const longOutput = deriveKey(baseKey, input, 32);
		const prefix = longOutput.subarray(0, shortOutput.length);

		expect(Array.from(prefix)).toEqual(Array.from(shortOutput));
	});

	test("rejects keys that are not 16 bytes", () => {
		expect(() =>
			deriveKey(new Uint8Array(15), new Uint8Array([1]), 16),
		).toThrow();
	});

	test("rejects zero-length output requests", () => {
		expect(() =>
			deriveKey(new Uint8Array(16), new Uint8Array([1]), 0),
		).toThrow();
	});
});
