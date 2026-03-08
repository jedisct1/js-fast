import { describe, expect, test } from "bun:test";
import { PrngState } from "../src/prng.ts";
import { generateSBox, generateSBoxPool } from "../src/sbox.ts";

const baseKey = new Uint8Array([
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
	0x54, 0x32, 0x10,
]);
const alternateKey = new Uint8Array(16).fill(0x42);
const poolKey = new Uint8Array(32).fill(0x01);
const zeroNonce = new Uint8Array(16);

function withPrng<T>(key: Uint8Array, run: (prng: PrngState) => T): T {
	const prng = new PrngState(key, zeroNonce);
	try {
		return run(prng);
	} finally {
		prng.cleanup();
	}
}

function expectPermutation(values: Uint8Array, radix: number): void {
	const seen = new Set<number>();

	for (const value of values) {
		expect(value).toBeGreaterThanOrEqual(0);
		expect(value).toBeLessThan(radix);
		seen.add(value);
	}

	expect(seen.size).toBe(radix);
}

function expectInverseTable(
	radix: number,
	perm: Uint8Array,
	inv: Uint8Array,
): void {
	for (let i = 0; i < radix; i++) {
		expect(inv[perm[i]!]).toBe(i);
	}
}

describe("generateSBox", () => {
	test("produces a valid permutation", () => {
		expectPermutation(
			withPrng(baseKey, (prng) => generateSBox(10, prng)).perm,
			10,
		);
	});

	test("builds a matching inverse table", () => {
		const sbox = withPrng(alternateKey, (prng) => generateSBox(16, prng));

		expectInverseTable(16, sbox.perm, sbox.inv);
	});

	test("still behaves like a permutation at radix 256", () => {
		const sbox = withPrng(new Uint8Array(16).fill(0x01), (prng) =>
			generateSBox(256, prng),
		);

		expectPermutation(sbox.perm, 256);
		expectInverseTable(256, sbox.perm, sbox.inv);
	});
});

describe("generateSBoxPool", () => {
	test("returns the requested pool size", () => {
		const pool = generateSBoxPool(10, 256, poolKey);
		expect(pool.sboxes).toHaveLength(256);
		expect(pool.radix).toBe(10);
	});

	test("is deterministic for the same key material", () => {
		const pool1 = generateSBoxPool(10, 4, poolKey);
		const pool2 = generateSBoxPool(10, 4, poolKey);

		for (let i = 0; i < 4; i++) {
			expect(pool1.sboxes[i]!.perm).toEqual(pool2.sboxes[i]!.perm);
		}
	});

	test("fills the pool with valid permutations", () => {
		for (const sbox of generateSBoxPool(10, 8, new Uint8Array(32).fill(0x42))
			.sboxes) {
			expectPermutation(sbox.perm, 10);
		}
	});
});
