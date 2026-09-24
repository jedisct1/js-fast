import { describe, expect, spyOn, test } from "bun:test";
import * as nodeCrypto from "node:crypto";
import { generateSequence, PrngState, splitKeyMaterial } from "../src/prng.ts";
import { hex } from "./helpers.ts";

const testKey = new Uint8Array([
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
	0x54, 0x32, 0x10,
]);
const alternateKey = new Uint8Array(16).fill(0xff);
const sequenceKey = new Uint8Array(32).fill(0x01);
const zeroNonce = new Uint8Array(16);

function withPrng<T>(
	key: Uint8Array,
	run: (prng: PrngState) => T,
	nonce: Uint8Array = zeroNonce,
): T {
	const prng = new PrngState(key, nonce);
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

/** The reference construction: encrypt each incremented counter with AES-ECB. */
function referenceStream(key: Uint8Array, nonce: Uint8Array, length: number) {
	const counter = new Uint8Array(nonce);
	const out = new Uint8Array(length);
	for (let offset = 0; offset < length; offset += 16) {
		for (let i = 15; i >= 0 && ++counter[i]! === 256; i--) counter[i] = 0;
		const ecb = nodeCrypto.createCipheriv("aes-128-ecb", key, null);
		ecb.setAutoPadding(false);
		out.set(ecb.update(counter).subarray(0, length - offset), offset);
	}
	return out;
}

function sampledSequence(
	numLayers: number,
	poolSize: number,
	keyMaterial: Uint8Array,
): Uint32Array {
	const { key, iv } = splitKeyMaterial(keyMaterial, true);
	return withPrng(
		key,
		(prng) =>
			Uint32Array.from({ length: numLayers }, () => prng.uniform(poolSize)),
		iv,
	);
}

/** Record the AES ciphers created while `run` executes. */
function captureCiphers(run: () => void): nodeCrypto.Cipheriv[] {
	const createCipheriv = nodeCrypto.createCipheriv;
	const ciphers: nodeCrypto.Cipheriv[] = [];
	const spy = spyOn(nodeCrypto, "createCipheriv").mockImplementation(((
		...args: Parameters<typeof createCipheriv>
	) => {
		const cipher = createCipheriv(...args);
		ciphers.push(cipher);
		return cipher;
	}) as typeof createCipheriv);
	try {
		run();
	} finally {
		spy.mockRestore();
	}
	return ciphers;
}

describe("PrngState stream", () => {
	test("is AES of successive counters, across carries and read sizes", () => {
		const readSizes = [1, 3, 16, 4000, 5000];
		for (const nonce of [
			"00000000000000000000000000000000",
			"000000000000000000000000fffffffe",
			"00000000000000000000ffffffffffff",
			"fffffffffffffffffffffffffffffffe",
			"ffffffffffffffffffffffffffffffff",
		]) {
			for (const length of [1, 15, 16, 17, 4095, 4096, 4097, 8193]) {
				const actual = withPrng(
					testKey,
					(prng) => {
						const bytes = new Uint8Array(length);
						for (let offset = 0, i = 0; offset < length; i++) {
							const end = Math.min(length, offset + readSizes[i % 5]!);
							prng.getBytes(bytes.subarray(offset, end));
							offset = end;
						}
						return bytes;
					},
					hex(nonce),
				);
				expect(actual).toEqual(referenceStream(testKey, hex(nonce), length));
			}
		}
	});

	test("cleanup finalizes the cipher and may run twice", () => {
		let prng: PrngState | undefined;
		const ciphers = captureCiphers(() => {
			prng = new PrngState(testKey, zeroNonce);
		});
		prng!.getBytes(new Uint8Array(10));
		prng!.cleanup();
		prng!.cleanup();
		expect(ciphers).toHaveLength(1);
		expect(() => ciphers[0]!.update(new Uint8Array(16))).toThrow();
		expect(() => prng!.getBytes(new Uint8Array(1))).toThrow(
			"PRNG has been cleaned up",
		);
	});
});

describe("batched 256-entry sequences", () => {
	test("match rejection sampling at block and chunk edges", () => {
		for (const numLayers of [
			0,
			1,
			2,
			3,
			4,
			5,
			7,
			8,
			9,
			1023,
			1024,
			1025,
			3 * 1024 + 1,
		]) {
			expect(generateSequence(numLayers, 256, sequenceKey)).toEqual(
				sampledSequence(numLayers, 256, sequenceKey),
			);
		}
	});

	test("match rejection sampling across 32-bit and 128-bit counter carries", () => {
		// Bytes 14 and 15 of the IV are zeroed, so with bytes 12 and 13 set the
		// low 32 bits of the counter wrap after 65,536 blocks.
		const partial = new Uint8Array(32).fill(0x5a);
		partial.fill(0xff, 28, 30);
		const whole = new Uint8Array(32);
		whole.fill(0xff, 16);
		for (const keyMaterial of [partial, whole]) {
			const numLayers = 4 * 65536 + 5;
			expect(generateSequence(numLayers, 256, keyMaterial)).toEqual(
				sampledSequence(numLayers, 256, keyMaterial),
			);
		}
	});

	test("keep rejection sampling for other pool sizes", () => {
		for (const poolSize of [7, 10, 67, 255]) {
			expect(generateSequence(1000, poolSize, sequenceKey)).toEqual(
				sampledSequence(1000, poolSize, sequenceKey),
			);
		}
	});
});
