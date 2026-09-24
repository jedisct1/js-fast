import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { FastCipher } from "../src/cipher.ts";
import { calculateRecommendedParams } from "../src/params.ts";
import { generateSequence } from "../src/prng.ts";
import { generateSBoxPool } from "../src/sbox.ts";
import { TokenEncryptor } from "../src/tokens/index.ts";
import legacy from "./fixtures/legacy-outputs.json";
import { hex } from "./helpers.ts";

function sha256(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

describe("outputs pinned before the wrapped-token change", () => {
	test("sequences, including counter carries", () => {
		for (const {
			numLayers,
			poolSize,
			keyMaterial,
			sha256: digest,
		} of legacy.sequences) {
			const seq = generateSequence(numLayers, poolSize, hex(keyMaterial));
			expect(sha256(Uint8Array.from(seq))).toBe(digest);
		}
	});

	test("S-box pools", () => {
		for (const { radix, count, keyMaterial, sha256: digest } of legacy.pools) {
			const pool = generateSBoxPool(radix, count, hex(keyMaterial));
			const tables = pool.sboxes.flatMap((sbox) => [...sbox.perm, ...sbox.inv]);
			expect(sha256(Uint8Array.from(tables))).toBe(digest);
		}
	});

	test("FAST ciphertexts", () => {
		for (const vector of legacy.ciphers) {
			const cipher = FastCipher.create(
				calculateRecommendedParams(vector.radix, vector.wordLength),
				hex(legacy.key),
			);
			const tweak = hex(vector.tweak);
			const ciphertext = cipher.encrypt(hex(vector.plaintext), tweak);
			expect(ciphertext).toEqual(hex(vector.ciphertext));
			expect(cipher.decrypt(ciphertext, tweak)).toEqual(hex(vector.plaintext));
			cipher.destroy();
		}
	});

	test("format-preserving token encryption", () => {
		for (const { tweak, encrypted } of legacy.tokens) {
			const enc = new TokenEncryptor(hex(legacy.key));
			const options = tweak ? { tweak: hex(tweak) } : undefined;
			expect(enc.encrypt(legacy.tokenText, options)).toBe(encrypted);
			expect(enc.decrypt(encrypted, options)).toBe(legacy.tokenText);
			enc.destroy();
		}
	});
});
