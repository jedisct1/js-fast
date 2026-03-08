import { describe, expect, test } from "bun:test";
import { FastCipher } from "../src/cipher.ts";
import { cdec, cenc } from "../src/core.ts";
import { calculateRecommendedParams } from "../src/params.ts";
import { generateSBoxPool } from "../src/sbox.ts";
import type { FastParams } from "../src/types.ts";

describe("layer roundtrip", () => {
	test("single ES/DS layer inverts correctly", () => {
		const keyMaterial = new Uint8Array(32).fill(0x01);
		const pool = generateSBoxPool(10, 1, keyMaterial);

		const params: FastParams = {
			radix: 10,
			wordLength: 4,
			sboxCount: 1,
			numLayers: 4,
			branchDist1: 1,
			branchDist2: 1,
			securityLevel: 128,
		};

		const original = new Uint8Array([1, 2, 3, 4]);
		const seq = new Uint32Array([0, 0, 0, 0]);

		const encrypted = new Uint8Array(4);
		cenc(params, pool, seq, original, encrypted);

		// Should differ from original
		let same = true;
		for (let i = 0; i < 4; i++) {
			if (encrypted[i] !== original[i]) same = false;
		}
		expect(same).toBe(false);

		const decrypted = new Uint8Array(4);
		cdec(params, pool, seq, encrypted, decrypted);

		expect(decrypted).toEqual(original);
	});

	test("roundtrip with multiple sboxes", () => {
		const keyMaterial = new Uint8Array(32).fill(0x42);
		const pool = generateSBoxPool(16, 10, keyMaterial);

		const params: FastParams = {
			radix: 16,
			wordLength: 8,
			sboxCount: 10,
			numLayers: 16,
			branchDist1: 2,
			branchDist2: 1,
			securityLevel: 128,
		};

		const seq = new Uint32Array(16);
		for (let i = 0; i < 16; i++) {
			seq[i] = i % 10;
		}

		const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
		const encrypted = new Uint8Array(8);
		const decrypted = new Uint8Array(8);

		cenc(params, pool, seq, original, encrypted);
		cdec(params, pool, seq, encrypted, decrypted);

		expect(decrypted).toEqual(original);
	});

	test("all-zero plaintext roundtrip", () => {
		const keyMaterial = new Uint8Array(32).fill(0x01);
		const pool = generateSBoxPool(10, 4, keyMaterial);

		const params: FastParams = {
			radix: 10,
			wordLength: 4,
			sboxCount: 4,
			numLayers: 8,
			branchDist1: 1,
			branchDist2: 1,
			securityLevel: 128,
		};

		const seq = new Uint32Array([0, 1, 2, 3, 0, 1, 2, 3]);
		const original = new Uint8Array([0, 0, 0, 0]);
		const encrypted = new Uint8Array(4);
		const decrypted = new Uint8Array(4);

		cenc(params, pool, seq, original, encrypted);
		cdec(params, pool, seq, encrypted, decrypted);

		expect(decrypted).toEqual(original);
	});

	test("max-symbol plaintext roundtrip", () => {
		const keyMaterial = new Uint8Array(32).fill(0x01);
		const pool = generateSBoxPool(10, 4, keyMaterial);

		const params: FastParams = {
			radix: 10,
			wordLength: 4,
			sboxCount: 4,
			numLayers: 8,
			branchDist1: 1,
			branchDist2: 1,
			securityLevel: 128,
		};

		const seq = new Uint32Array([0, 1, 2, 3, 0, 1, 2, 3]);
		const original = new Uint8Array([9, 9, 9, 9]);
		const encrypted = new Uint8Array(4);
		const decrypted = new Uint8Array(4);

		cenc(params, pool, seq, original, encrypted);

		// Verify all encrypted values < radix
		for (const v of encrypted) {
			expect(v).toBeLessThan(10);
		}

		cdec(params, pool, seq, encrypted, decrypted);
		expect(decrypted).toEqual(original);
	});

	test("w=0 case (wordLength=2) roundtrip", () => {
		const keyMaterial = new Uint8Array(32).fill(0x01);
		const pool = generateSBoxPool(10, 4, keyMaterial);

		const params: FastParams = {
			radix: 10,
			wordLength: 2,
			sboxCount: 4,
			numLayers: 4,
			branchDist1: 0,
			branchDist2: 1,
			securityLevel: 128,
		};

		const seq = new Uint32Array([0, 1, 2, 3]);
		const original = new Uint8Array([3, 7]);
		const encrypted = new Uint8Array(2);
		const decrypted = new Uint8Array(2);

		cenc(params, pool, seq, original, encrypted);
		cdec(params, pool, seq, encrypted, decrypted);

		expect(decrypted).toEqual(original);
	});
});

describe("FastCipher", () => {
	const testKey = new Uint8Array([
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c,
	]);

	test("encrypt/decrypt roundtrip radix=10", () => {
		const params = calculateRecommendedParams(10, 16);
		const cipher = FastCipher.create(params, testKey);
		const tweak = new Uint8Array([
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		]);
		const plaintext = new Uint8Array([
			1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
		]);

		const ciphertext = cipher.encrypt(plaintext, tweak);
		const recovered = cipher.decrypt(ciphertext, tweak);

		expect(recovered).toEqual(plaintext);

		// All ciphertext values < radix
		for (const v of ciphertext) {
			expect(v).toBeLessThan(10);
		}

		cipher.destroy();
	});

	test("encrypt/decrypt roundtrip radix=4", () => {
		const params = calculateRecommendedParams(4, 8);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([0, 1, 2, 3, 0, 1, 2, 3]);

		const ciphertext = cipher.encrypt(plaintext);
		const recovered = cipher.decrypt(ciphertext);

		expect(recovered).toEqual(plaintext);
		for (const v of ciphertext) {
			expect(v).toBeLessThan(4);
		}

		cipher.destroy();
	});

	test("encrypt/decrypt roundtrip radix=256", () => {
		const params = calculateRecommendedParams(256, 8);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([0, 50, 100, 150, 200, 250, 255, 128]);

		const ciphertext = cipher.encrypt(plaintext);
		const recovered = cipher.decrypt(ciphertext);

		expect(recovered).toEqual(plaintext);
		cipher.destroy();
	});

	test("encrypt/decrypt roundtrip radix=16", () => {
		const params = calculateRecommendedParams(16, 10);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 15]);

		const ciphertext = cipher.encrypt(plaintext);
		const recovered = cipher.decrypt(ciphertext);

		expect(recovered).toEqual(plaintext);
		for (const v of ciphertext) {
			expect(v).toBeLessThan(16);
		}
		cipher.destroy();
	});

	test("different tweaks produce different ciphertexts", () => {
		const params = calculateRecommendedParams(10, 8);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
		const tweak1 = new Uint8Array([1]);
		const tweak2 = new Uint8Array([2]);

		const ct1 = cipher.encrypt(plaintext, tweak1);
		const ct2 = cipher.encrypt(plaintext, tweak2);

		let same = true;
		for (let i = 0; i < ct1.length; i++) {
			if (ct1[i] !== ct2[i]) same = false;
		}
		expect(same).toBe(false);

		cipher.destroy();
	});

	test("tweak caching works", () => {
		const params = calculateRecommendedParams(10, 4);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([1, 2, 3, 4]);
		const tweak = new Uint8Array([0xaa, 0xbb]);

		const ct1 = cipher.encrypt(plaintext, tweak);
		const ct2 = cipher.encrypt(plaintext, tweak);

		expect(ct1).toEqual(ct2);
		cipher.destroy();
	});

	test("empty tweak roundtrip", () => {
		const params = calculateRecommendedParams(10, 4);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([1, 2, 3, 4]);

		const ciphertext = cipher.encrypt(plaintext);
		const recovered = cipher.decrypt(ciphertext);

		expect(recovered).toEqual(plaintext);
		cipher.destroy();
	});

	test("rejects invalid plaintext values", () => {
		const params = calculateRecommendedParams(10, 4);
		const cipher = FastCipher.create(params, testKey);
		const invalid = new Uint8Array([1, 2, 10, 4]); // 10 >= radix

		expect(() => cipher.encrypt(invalid)).toThrow();
		cipher.destroy();
	});

	test("rejects wrong-length plaintext", () => {
		const params = calculateRecommendedParams(10, 4);
		const cipher = FastCipher.create(params, testKey);

		expect(() => cipher.encrypt(new Uint8Array([1, 2, 3]))).toThrow();
		cipher.destroy();
	});

	test("property: decrypt(encrypt(x)) = x for many inputs", () => {
		const params = calculateRecommendedParams(10, 6);
		const cipher = FastCipher.create(params, testKey);
		const tweak = new Uint8Array([1, 2, 3]);

		for (let trial = 0; trial < 50; trial++) {
			const pt = new Uint8Array(6);
			for (let i = 0; i < 6; i++) {
				pt[i] = (trial * 7 + i * 3) % 10;
			}
			const ct = cipher.encrypt(pt, tweak);
			const rt = cipher.decrypt(ct, tweak);
			expect(rt).toEqual(pt);
		}

		cipher.destroy();
	});

	test("wordLength=2 roundtrip", () => {
		const params = calculateRecommendedParams(10, 2);
		const cipher = FastCipher.create(params, testKey);
		const plaintext = new Uint8Array([3, 7]);
		const tweak = new Uint8Array([0x01]);

		const ciphertext = cipher.encrypt(plaintext, tweak);
		const recovered = cipher.decrypt(ciphertext, tweak);

		expect(recovered).toEqual(plaintext);
		cipher.destroy();
	});
});
