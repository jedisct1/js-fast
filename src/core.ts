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
	const { branchDist1, branchDist2, wordLength, radix } = params;
	const perm = pool.sboxes[sboxIndex]!.perm;
	const sum = perm[modAdd(data[0]!, data[wordLength - branchDist2]!, radix)]!;
	const next =
		branchDist1 > 0
			? perm[modSub(sum, data[branchDist1]!, radix)]!
			: perm[sum]!;

	data.copyWithin(0, 1, wordLength);
	data[wordLength - 1] = next;
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
	const { branchDist1, branchDist2, wordLength, radix } = params;
	const inv = pool.sboxes[sboxIndex]!.inv;
	const last = inv[data[wordLength - 1]!]!;
	const intermediate =
		branchDist1 > 0
			? inv[modAdd(last, data[branchDist1 - 1]!, radix)]!
			: inv[last]!;
	const next = modSub(intermediate, data[wordLength - branchDist2 - 1]!, radix);

	data.copyWithin(1, 0, wordLength - 1);
	data[0] = next;
}

function resolveSBoxIndex(
	seq: Uint32Array,
	layer: number,
	sboxCount: number,
): number {
	return seq.length > 0 ? seq[layer]! : layer % sboxCount;
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
	output.set(input);

	for (let layer = 0; layer < params.numLayers; layer++) {
		esLayer(
			params,
			pool,
			output,
			resolveSBoxIndex(seq, layer, params.sboxCount),
		);
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
	output.set(input);

	for (let layer = params.numLayers - 1; layer >= 0; layer--) {
		dsLayer(
			params,
			pool,
			output,
			resolveSBoxIndex(seq, layer, params.sboxCount),
		);
	}
}
