import { describe, expect, test } from "bun:test";
import { generateSequence, PrngState } from "../src/prng.ts";

const testKey = new Uint8Array([
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
	0x54, 0x32, 0x10,
]);
const alternateKey = new Uint8Array(16).fill(0xff);
const sequenceKey = new Uint8Array(32).fill(0x01);
const zeroNonce = new Uint8Array(16);

function withPrng<T>(key: Uint8Array, run: (prng: PrngState) => T): T {
	const prng = new PrngState(key, zeroNonce);
	try {
		return run(prng);
	} finally {
		prng.cleanup();
	}
}

function getBytes(key: Uint8Array, length: number): Uint8Array {
	return withPrng(key, (prng) => {
		const bytes = new Uint8Array(length);
		prng.getBytes(bytes);
		return bytes;
	});
}

describe("PrngState", () => {
	test("produces deterministic output for the same key and nonce", () => {
		expect(getBytes(testKey, 32)).toEqual(getBytes(testKey, 32));
	});

	test("fills the destination buffer with keystream bytes", () => {
		expect(getBytes(testKey, 32).some((byte) => byte !== 0)).toBe(true);
	});

	test("returns u32 values", () => {
		const value = withPrng(testKey, (prng) => prng.nextU32());

		expect(typeof value).toBe("number");
		expect(value).toBeGreaterThanOrEqual(0);
		expect(value).toBeLessThanOrEqual(0xffffffff);
	});

	test("samples uniformly within the requested bound", () => {
		withPrng(testKey, (prng) => {
			for (let i = 0; i < 100; i++) {
				const value = prng.uniform(10);
				expect(value).toBeGreaterThanOrEqual(0);
				expect(value).toBeLessThan(10);
			}
		});
	});

	test("returns 0 for a bound of 1", () => {
		withPrng(testKey, (prng) => {
			for (let i = 0; i < 10; i++) {
				expect(prng.uniform(1)).toBe(0);
			}
		});
	});

	test("changes output when the key changes", () => {
		expect(getBytes(testKey, 16)).not.toEqual(getBytes(alternateKey, 16));
	});
});

describe("generateSequence", () => {
	test("returns the requested number of indices", () => {
		expect(generateSequence(100, 256, sequenceKey)).toHaveLength(100);
	});

	test("keeps every index inside the pool", () => {
		for (const index of generateSequence(100, 256, sequenceKey)) {
			expect(index).toBeGreaterThanOrEqual(0);
			expect(index).toBeLessThan(256);
		}
	});

	test("is deterministic for the same key material", () => {
		expect(generateSequence(50, 256, sequenceKey)).toEqual(
			generateSequence(50, 256, sequenceKey),
		);
	});
});
