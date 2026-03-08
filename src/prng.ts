import { createCipheriv } from "node:crypto";

const AES_BLOCK_SIZE = 16;
const AES_KEY_SIZE = 16;

/**
 * Deterministic PRNG state using AES-128 ECB encryption of an incrementing counter.
 * Matches the C and Zig reference implementations exactly.
 */
export class PrngState {
	private readonly key: Uint8Array;
	private readonly counter: Uint8Array;
	private readonly buffer = new Uint8Array(AES_BLOCK_SIZE);
	private bufferPos = AES_BLOCK_SIZE;

	constructor(key: Uint8Array, nonce: Uint8Array) {
		this.key = new Uint8Array(key);
		this.counter = new Uint8Array(nonce);
	}

	private incrementCounter(): void {
		for (let i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
			this.counter[i] = (this.counter[i]! + 1) & 0xff;
			if (this.counter[i] !== 0) break;
		}
	}

	private encryptBlock(): void {
		const cipher = createCipheriv("aes-128-ecb", this.key, null);
		cipher.setAutoPadding(false);
		const encrypted = cipher.update(this.counter);
		cipher.final();
		this.buffer.set(new Uint8Array(encrypted));
	}

	getBytes(output: Uint8Array): void {
		for (let offset = 0; offset < output.length; ) {
			if (this.bufferPos === AES_BLOCK_SIZE) {
				this.incrementCounter();
				this.encryptBlock();
				this.bufferPos = 0;
			}

			const chunkLength = Math.min(
				output.length - offset,
				AES_BLOCK_SIZE - this.bufferPos,
			);
			output.set(
				this.buffer.subarray(this.bufferPos, this.bufferPos + chunkLength),
				offset,
			);
			this.bufferPos += chunkLength;
			offset += chunkLength;
		}
	}

	nextU32(): number {
		const bytes = new Uint8Array(4);
		this.getBytes(bytes);
		return new DataView(
			bytes.buffer,
			bytes.byteOffset,
			bytes.byteLength,
		).getUint32(0, false);
	}

	/**
	 * Generate a uniform random number in [0, bound) with no modulo bias.
	 * Uses Lemire's nearly-divisionless method with BigInt for 64-bit precision.
	 */
	uniform(bound: number): number {
		if (bound <= 1) return 0;

		const bound64 = BigInt(bound);
		// threshold = (2^32 - bound) % bound = (-bound) % bound in u32
		const threshold = Number((0x100000000n - bound64) % bound64);

		for (;;) {
			const r = this.nextU32();
			const product = BigInt(r) * bound64;
			const low = Number(product & 0xffffffffn);
			if (low >= threshold) {
				return Number(product >> 32n);
			}
		}
	}

	cleanup(): void {
		this.counter.fill(0);
		this.buffer.fill(0);
		this.key.fill(0);
		this.bufferPos = 0;
	}
}

/**
 * Split 32-byte key material into AES key (first 16 bytes) and IV (last 16 bytes).
 * For sequence generation, the last 2 IV bytes are zeroed.
 */
export function splitKeyMaterial(
	keyMaterial: Uint8Array,
	zeroizeIvSuffix: boolean,
): { key: Uint8Array; iv: Uint8Array } {
	const key = keyMaterial.slice(0, AES_KEY_SIZE);
	const iv = keyMaterial.slice(AES_KEY_SIZE, AES_KEY_SIZE + AES_BLOCK_SIZE);
	if (zeroizeIvSuffix) {
		iv[AES_BLOCK_SIZE - 1] = 0;
		iv[AES_BLOCK_SIZE - 2] = 0;
	}
	return { key, iv };
}

/**
 * Generate a sequence of S-box indices using PRF-derived key material.
 * Indices are in [0, poolSize).
 */
export function generateSequence(
	numLayers: number,
	poolSize: number,
	keyMaterial: Uint8Array,
): Uint32Array {
	const { key, iv } = splitKeyMaterial(keyMaterial, true);
	const prng = new PrngState(key, iv);

	const seq = new Uint32Array(numLayers);
	for (let i = 0; i < numLayers; i++) {
		seq[i] = prng.uniform(poolSize);
	}

	prng.cleanup();
	key.fill(0);
	iv.fill(0);

	return seq;
}
