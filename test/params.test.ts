import { describe, expect, test } from "bun:test";
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

	test("rejects invalid radix and word length values", () => {
		expect(() => calculateRecommendedParams(3, 4)).toThrow();
		expect(() => calculateRecommendedParams(10, 1)).toThrow();
	});
});
