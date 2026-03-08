import { InvalidParametersError } from "./errors.ts";
import type { FastParams } from "./types.ts";

const SBOX_POOL_SIZE = 256;

// Lookup tables for recommended rounds - copied from reference implementations
const ROUND_L_VALUES = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100];
const ROUND_RADICES = [
	4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 100, 128, 256, 1000, 1024,
	10000, 65536,
];

const ROUND_TABLE: number[][] = [
	[165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57], // a = 4
	[131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53], // a = 5
	[113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52], // a = 6
	[102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50], // a = 7
	[94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50], // a = 8
	[88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49], // a = 9
	[83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49], // a = 10
	[79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48], // a = 11
	[76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48], // a = 12
	[73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48], // a = 13
	[71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47], // a = 14
	[69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47], // a = 15
	[67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47], // a = 16
	[40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44], // a = 100
	[38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44], // a = 128
	[33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44], // a = 256
	[32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43], // a = 1000
	[32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43], // a = 1024
	[32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42], // a = 10000
	[32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42], // a = 65536
];

function interpolate(
	x: number,
	x0: number,
	x1: number,
	y0: number,
	y1: number,
): number {
	if (x1 === x0) {
		return y0;
	}

	const ratio = (x - x0) / (x1 - x0);
	if (ratio <= 0) {
		return y0;
	}
	if (ratio >= 1) {
		return y1;
	}

	return y0 + ratio * (y1 - y0);
}

function roundsForRow(rowIndex: number, ell: number): number {
	const row = ROUND_TABLE[rowIndex]!;
	const lastIndex = ROUND_L_VALUES.length - 1;
	const maxWordLength = ROUND_L_VALUES[lastIndex]!;

	if (ell <= ROUND_L_VALUES[0]!) {
		return row[0]!;
	}

	if (ell >= maxWordLength) {
		const baseRounds = row[lastIndex]!;
		return Math.max(baseRounds, baseRounds * Math.sqrt(ell / maxWordLength));
	}

	for (let i = 1; i <= lastIndex; i++) {
		const lowerLength = ROUND_L_VALUES[i - 1]!;
		const upperLength = ROUND_L_VALUES[i]!;
		if (ell <= upperLength) {
			return interpolate(ell, lowerLength, upperLength, row[i - 1]!, row[i]!);
		}
	}

	return row[lastIndex]!;
}

/**
 * Lookup recommended rounds with log-space radix interpolation.
 * Matches the reference implementations exactly.
 */
function lookupRecommendedRounds(radix: number, ell: number): number {
	const lastIndex = ROUND_RADICES.length - 1;

	if (radix <= ROUND_RADICES[0]!) {
		return roundsForRow(0, ell);
	}

	if (radix >= ROUND_RADICES[lastIndex]!) {
		return roundsForRow(lastIndex, ell);
	}

	const logRadix = Math.log(radix);
	for (let i = 1; i <= lastIndex; i++) {
		const lowerRadix = ROUND_RADICES[i - 1]!;
		const upperRadix = ROUND_RADICES[i]!;
		if (radix <= upperRadix) {
			return interpolate(
				logRadix,
				Math.log(lowerRadix),
				Math.log(upperRadix),
				roundsForRow(i - 1, ell),
				roundsForRow(i, ell),
			);
		}
	}

	return roundsForRow(lastIndex, ell);
}

/**
 * Calculate recommended parameters for the FAST cipher.
 */
export function calculateRecommendedParams(
	radix: number,
	wordLength: number,
	securityLevel = 128,
): FastParams {
	if (radix < 4 || wordLength < 2) {
		throw new InvalidParametersError();
	}

	const secLevel = securityLevel === 0 ? 128 : securityLevel;

	// Branch distances per specification
	const wCandidate = Math.ceil(Math.sqrt(wordLength));
	const branchDist1 =
		wordLength <= 2 ? 0 : Math.min(wCandidate, wordLength - 2);
	const branchDist2 = branchDist1 > 1 ? branchDist1 - 1 : 1;

	let rounds = lookupRecommendedRounds(radix, wordLength);
	if (rounds < 1.0) rounds = 1.0;

	const roundsU = Math.ceil(rounds);
	const numLayers = roundsU * wordLength;

	return {
		radix,
		wordLength,
		sboxCount: SBOX_POOL_SIZE,
		numLayers,
		branchDist1,
		branchDist2,
		securityLevel: secLevel,
	};
}
