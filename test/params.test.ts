import { describe, expect, test } from "bun:test";
import { FastCipher } from "../src/cipher.ts";
import {
	InvalidBranchDistError,
	InvalidParametersError,
	InvalidRadixError,
	InvalidSBoxCountError,
	InvalidWordLengthError,
} from "../src/errors.ts";
import { calculateRecommendedParams } from "../src/params.ts";

describe("calculateRecommendedParams", () => {
	test("returns sensible defaults for a decimal alphabet", () => {
		const params = calculateRecommendedParams(10, 16);

		expect(params.radix).toBe(10);
		expect(params.wordLength).toBe(16);
		expect(params.sboxCount).toBe(256);
		expect(params.securityLevel).toBe(128);
		expect(params.numLayers).toBeGreaterThan(0);
		expect(params.numLayers % params.wordLength).toBe(0);
	});

	test("uses the w=0 special case for two-symbol words", () => {
		const params = calculateRecommendedParams(10, 2);

		expect(params.branchDist1).toBe(0);
		expect(params.branchDist2).toBe(1);
	});

	test("keeps the number of layers aligned to the word length", () => {
		for (const [radix, wordLength] of [
			[4, 4],
			[256, 8],
		] as const) {
			expect(
				calculateRecommendedParams(radix, wordLength).numLayers % wordLength,
			).toBe(0);
		}
	});

	test("defaults a zero security level back to 128 bits", () => {
		expect(calculateRecommendedParams(10, 4, 0).securityLevel).toBe(128);
	});

	test("derives branch distances from the word length", () => {
		const fourSymbolWord = calculateRecommendedParams(10, 4);
		const threeSymbolWord = calculateRecommendedParams(10, 3);

		expect(fourSymbolWord.branchDist1).toBe(2);
		expect(fourSymbolWord.branchDist2).toBe(1);
		expect(threeSymbolWord.branchDist1).toBe(1);
		expect(threeSymbolWord.branchDist2).toBe(1);
	});

	test("supports five-symbol words", () => {
		for (const radix of [4, 10, 62, 256]) {
			const params = calculateRecommendedParams(radix, 5);
			expect(params.branchDist1).toBe(3);
			expect(params.branchDist2).toBe(1);

			const cipher = FastCipher.create(params, new Uint8Array(16));
			try {
				const plaintext = new Uint8Array([0, 1, 2, 3, radix - 1]);
				const tweak = new Uint8Array([1, 2, 3]);
				expect(cipher.decrypt(cipher.encrypt(plaintext, tweak), tweak)).toEqual(
					plaintext,
				);
			} finally {
				cipher.destroy();
			}
		}
	});

	test("keeps branch distances within the cipher's bounds", () => {
		for (let wordLength = 2; wordLength <= 256; wordLength++) {
			const params = calculateRecommendedParams(10, wordLength);
			expect(params.branchDist1).toBeLessThanOrEqual(wordLength - 2);
			expect(params.branchDist2).toBeGreaterThan(0);
			expect(params.branchDist2).toBeLessThanOrEqual(
				wordLength - params.branchDist1 - 1,
			);
		}
	});

	test("rejects invalid radix and word length values", () => {
		for (const radix of [3, 10.5, Number.NaN]) {
			expect(() => calculateRecommendedParams(radix, 4)).toThrow(
				InvalidParametersError,
			);
		}
		for (const wordLength of [1, 2.5, Number.NaN]) {
			expect(() => calculateRecommendedParams(10, wordLength)).toThrow(
				InvalidParametersError,
			);
		}
	});
});

describe("FastCipher parameter validation", () => {
	// 240 is also a multiple of 2.5, so only the integer check rejects a word
	// length of 2.5.
	const params = { ...calculateRecommendedParams(10, 4), numLayers: 240 };
	const key = new Uint8Array(16);

	test.each([
		["radix", InvalidRadixError, [3, 257, 10.5, Number.NaN]],
		["wordLength", InvalidWordLengthError, [1, 2.5, Number.NaN]],
		["numLayers", InvalidWordLengthError, [0, -4, 4.5, Number.NaN]],
		["sboxCount", InvalidSBoxCountError, [0, -1, 1.5, Number.NaN]],
		["branchDist1", InvalidBranchDistError, [0.5, 3, Number.NaN]],
		["branchDist2", InvalidBranchDistError, [-1, 0, 0.5, 2, Number.NaN]],
	] as const)("rejects invalid %s", (field, error, values) => {
		for (const value of values) {
			expect(() => {
				FastCipher.create({ ...params, [field]: value }, key).destroy();
			}).toThrow(error);
		}
	});
});
