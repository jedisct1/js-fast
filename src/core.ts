import type { SBoxPool } from "./sbox.ts";
import type { FastParams } from "./types.ts";

/**
 * Modular addition: (a + b) mod radix
 */
function modAdd(a: number, b: number, radix: number): number {
	if (radix === 256) return (a + b) & 0xff;
	return (a + b) % radix;
}

/**
 * Modular subtraction: (a - b) mod radix, always non-negative.
 */
function modSub(a: number, b: number, radix: number): number {
	if (radix === 256) return (a - b) & 0xff;
	return (a + radix - (b % radix)) % radix;
}

/**
 * ES (Expansion-Substitution) forward layer.
 * Matches the reference implementations exactly.
 */
function esLayer(
	params: FastParams,
	pool: SBoxPool,
	data: Uint8Array,
	sboxIndex: number,
): void {
	const w = params.branchDist1;
	const wp = params.branchDist2;
	const ell = params.wordLength;
	const radix = params.radix;
	const box = pool.sboxes[sboxIndex]!;
	const perm = box.perm;

	// sum1 = S[data[0] + data[ell - wp]]
	const sum1 = perm[modAdd(data[0]!, data[ell - wp]!, radix)]!;

	let newLast: number;
	if (w > 0) {
		// S[sum1 - data[w]]
		newLast = perm[modSub(sum1, data[w]!, radix)]!;
	} else {
		// S[sum1] (double application)
		newLast = perm[sum1]!;
	}

	// Shift left by 1
	data.copyWithin(0, 1, ell);
	data[ell - 1] = newLast;
}

/**
 * DS (De-Substitution) backward layer.
 * Matches the reference implementations exactly.
 */
function dsLayer(
	params: FastParams,
	pool: SBoxPool,
	data: Uint8Array,
	sboxIndex: number,
): void {
	const w = params.branchDist1;
	const wp = params.branchDist2;
	const ell = params.wordLength;
	const radix = params.radix;
	const box = pool.sboxes[sboxIndex]!;
	const inv = box.inv;

	// Inverse S-box on last element
	const xLast = inv[data[ell - 1]!]!;

	let intermediate: number;
	if (w > 0) {
		// S^-1[xLast + data[w-1]]
		intermediate = inv[modAdd(xLast, data[w - 1]!, radix)]!;
	} else {
		// S^-1[S^-1[xLast]] (double inverse)
		intermediate = inv[xLast]!;
	}

	const newFirst = modSub(intermediate, data[ell - wp - 1]!, radix);

	// Shift right by 1
	data.copyWithin(1, 0, ell - 1);
	data[0] = newFirst;
}

/**
 * Component encryption: apply all ES layers in forward order.
 */
export function cenc(
	params: FastParams,
	pool: SBoxPool,
	seq: Uint32Array,
	input: Uint8Array,
	output: Uint8Array,
): void {
	// Copy input to output
	output.set(input);

	const hasSeq = seq.length > 0;
	for (let i = 0; i < params.numLayers; i++) {
		const sboxIndex = hasSeq ? seq[i]! : i % params.sboxCount;
		esLayer(params, pool, output, sboxIndex);
	}
}

/**
 * Component decryption: apply all DS layers in reverse order.
 */
export function cdec(
	params: FastParams,
	pool: SBoxPool,
	seq: Uint32Array,
	input: Uint8Array,
	output: Uint8Array,
): void {
	// Copy input to output
	output.set(input);

	const hasSeq = seq.length > 0;
	for (let i = params.numLayers - 1; i >= 0; i--) {
		const sboxIndex = hasSeq ? seq[i]! : i % params.sboxCount;
		dsLayer(params, pool, output, sboxIndex);
	}
}
