import { type Cipheriv, createCipheriv } from "node:crypto";

const AES_BLOCK_SIZE = 16;
const AES_KEY_SIZE = 16;
const ZEROS = new Uint8Array(4096);

function incrementCounter(counter: Uint8Array): void {
	for (let i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
		counter[i] = (counter[i]! + 1) & 0xff;
		if (counter[i] !== 0) break;
	}
}

/**
 * Deterministic PRNG: AES-128 encryption of an incrementing counter.
 * Matches the C and Zig reference implementations exactly.
 *
 * They increment the counter before each block, so the stream is AES-128-CTR
 * starting from `nonce + 1`.
 */
export class PrngState {
	private ctr: Cipheriv | null;
	private buffer = new Uint8Array(0);
	private bufferPos = 0;

	constructor(key: Uint8Array, nonce: Uint8Array) {
		const counter = new Uint8Array(nonce);
		incrementCounter(counter);
		this.ctr = createCipheriv("aes-128-ctr", key, counter);
		counter.fill(0);
	}

	getBytes(output: Uint8Array): void {
		for (let offset = 0; offset < output.length; ) {
			if (this.bufferPos === this.buffer.length) this.refill();

			const chunkLength = Math.min(
				output.length - offset,
				this.buffer.length - this.bufferPos,
			);
			output.set(
				this.buffer.subarray(this.bufferPos, this.bufferPos + chunkLength),
				offset,
			);
			this.bufferPos += chunkLength;
			offset += chunkLength;
		}
	}

	private refill(): void {
		if (this.ctr === null) throw new Error("PRNG has been cleaned up");
		this.buffer.fill(0);
		this.buffer = this.ctr.update(ZEROS);
		this.bufferPos = 0;
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
		this.buffer.fill(0);
		this.bufferPos = this.buffer.length;
		if (this.ctr === null) return;
		try {
			this.ctr.final();
		} catch {
			// Cleanup runs in finally blocks and must not replace their error.
		}
		this.ctr = null;
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
 * With 256 S-boxes, `uniform(256)` never rejects a sample and returns the
 * high byte of each big-endian `nextU32()`.
 * Element `i` is therefore byte `4 * i` of the PRNG stream.
 */
function highByteSequence(numLayers: number, prng: PrngState): Uint32Array {
	const seq = new Uint32Array(numLayers);
	const bytes = new Uint8Array(Math.min(4 * numLayers, ZEROS.length));
	try {
		for (let i = 0; i < numLayers; ) {
			const chunk = bytes.subarray(
				0,
				Math.min(bytes.length, 4 * (numLayers - i)),
			);
			prng.getBytes(chunk);
			for (let offset = 0; offset < chunk.length; offset += 4) {
				seq[i++] = chunk[offset]!;
			}
		}
	} finally {
		bytes.fill(0);
	}
	return seq;
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
	key.fill(0);
	iv.fill(0);

	try {
		if (poolSize === 256) return highByteSequence(numLayers, prng);

		const seq = new Uint32Array(numLayers);
		for (let i = 0; i < numLayers; i++) {
			seq[i] = prng.uniform(poolSize);
		}
		return seq;
	} finally {
		prng.cleanup();
	}
}
