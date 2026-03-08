import { PrngState, splitKeyMaterial } from "./prng.ts";

export interface SBox {
	perm: Uint8Array;
	inv: Uint8Array;
}

/**
 * Generate a single S-box permutation using Fisher-Yates shuffle.
 */
export function generateSBox(radix: number, prng: PrngState): SBox {
	const perm = new Uint8Array(radix);
	const inv = new Uint8Array(radix);

	// Initialize to identity
	for (let i = 0; i < radix; i++) {
		perm[i] = i;
	}

	// Fisher-Yates shuffle (matching reference: iterate from radix down to 2)
	for (let i = radix; i > 1; i--) {
		const j = prng.uniform(i);
		const temp = perm[i - 1]!;
		perm[i - 1] = perm[j]!;
		perm[j] = temp;
	}

	// Compute inverse
	for (let i = 0; i < radix; i++) {
		inv[perm[i]!] = i;
	}

	return { perm, inv };
}

export interface SBoxPool {
	sboxes: SBox[];
	radix: number;
}

/**
 * Generate a pool of S-boxes from PRF-derived key material.
 * Uses Fisher-Yates shuffle driven by AES-ECB PRNG.
 */
export function generateSBoxPool(
	radix: number,
	count: number,
	keyMaterial: Uint8Array,
): SBoxPool {
	// Split key material (don't zeroize IV suffix for S-box generation)
	const { key, iv } = splitKeyMaterial(keyMaterial, false);
	const prng = new PrngState(key, iv);

	const sboxes: SBox[] = [];
	for (let i = 0; i < count; i++) {
		sboxes.push(generateSBox(radix, prng));
	}

	prng.cleanup();
	key.fill(0);
	iv.fill(0);

	return { sboxes, radix };
}
