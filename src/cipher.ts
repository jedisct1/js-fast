import { cdec, cenc } from "./core.ts";
import { buildSetup1Input, buildSetup2Input } from "./encoding.ts";
import {
	InvalidBranchDistError,
	InvalidLengthError,
	InvalidRadixError,
	InvalidSBoxCountError,
	InvalidValueError,
	InvalidWordLengthError,
} from "./errors.ts";
import { deriveKey } from "./prf.ts";
import { generateSequence } from "./prng.ts";
import type { SBoxPool } from "./sbox.ts";
import { generateSBoxPool } from "./sbox.ts";
import type { FastParams } from "./types.ts";

const AES_KEY_SIZE = 16;
const DERIVED_KEY_SIZE = 32;

export class FastCipher {
	readonly params: FastParams;
	private readonly masterKey: Uint8Array;
	private readonly sboxPool: SBoxPool;
	private destroyed = false;
	private cachedTweak: Uint8Array | null = null;
	private cachedSeq: Uint32Array | null = null;

	private constructor(
		params: FastParams,
		masterKey: Uint8Array,
		sboxPool: SBoxPool,
	) {
		this.params = params;
		this.masterKey = new Uint8Array(masterKey);
		this.sboxPool = sboxPool;
	}

	static create(params: FastParams, key: Uint8Array): FastCipher {
		FastCipher.validateParams(params, key);

		const poolKeyMaterial = deriveKey(
			key,
			buildSetup1Input(params),
			DERIVED_KEY_SIZE,
		);
		const sboxPool = generateSBoxPool(
			params.radix,
			params.sboxCount,
			poolKeyMaterial,
		);
		poolKeyMaterial.fill(0);

		return new FastCipher(params, key, sboxPool);
	}

	private static validateParams(params: FastParams, key: Uint8Array): void {
		if (params.radix < 4 || params.radix > 256) {
			throw new InvalidRadixError();
		}

		if (
			params.wordLength < 2 ||
			params.numLayers === 0 ||
			params.numLayers % params.wordLength !== 0
		) {
			throw new InvalidWordLengthError(
				"Word length must be >= 2 and numLayers must be a positive multiple of wordLength",
			);
		}

		if (params.sboxCount === 0) {
			throw new InvalidSBoxCountError();
		}

		if (params.branchDist1 > params.wordLength - 2) {
			throw new InvalidBranchDistError("branchDist1 must be <= wordLength - 2");
		}

		if (
			params.branchDist2 === 0 ||
			params.branchDist2 > params.wordLength - 1 ||
			params.branchDist2 > params.wordLength - params.branchDist1 - 1
		) {
			throw new InvalidBranchDistError("branchDist2 is out of valid range");
		}

		if (key.length !== AES_KEY_SIZE) {
			throw new Error("Key must be 16 bytes");
		}
	}

	private hasCachedSequenceFor(tweak: Uint8Array): boolean {
		if (this.cachedSeq === null) {
			return false;
		}

		if (tweak.length === 0) {
			return this.cachedTweak === null;
		}

		const cachedTweak = this.cachedTweak;
		if (cachedTweak === null || tweak.length !== cachedTweak.length) {
			return false;
		}

		return tweak.every((value, index) => value === cachedTweak[index]);
	}

	private ensureSequence(tweak: Uint8Array): Uint32Array {
		if (this.hasCachedSequenceFor(tweak)) {
			return this.cachedSeq!;
		}

		const seqKeyMaterial = deriveKey(
			this.masterKey,
			buildSetup2Input(this.params, tweak),
			DERIVED_KEY_SIZE,
		);
		const seq = generateSequence(
			this.params.numLayers,
			this.params.sboxCount,
			seqKeyMaterial,
		);
		seqKeyMaterial.fill(0);

		this.cachedTweak = tweak.length === 0 ? null : new Uint8Array(tweak);
		this.cachedSeq = seq;

		return seq;
	}

	private validateInput(data: Uint8Array): void {
		if (data.length !== this.params.wordLength) {
			throw new InvalidLengthError();
		}

		for (const value of data) {
			if (value >= this.params.radix) {
				throw new InvalidValueError();
			}
		}
	}

	private assertNotDestroyed(): void {
		if (this.destroyed) {
			throw new Error("Cipher has been destroyed");
		}
	}

	/**
	 * Encrypt plaintext using the FAST cipher.
	 * Each value in plaintext must be in [0, radix).
	 */
	encrypt(
		plaintext: Uint8Array,
		tweak: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		this.assertNotDestroyed();
		this.validateInput(plaintext);
		const seq = this.ensureSequence(tweak);
		const ciphertext = new Uint8Array(this.params.wordLength);
		cenc(this.params, this.sboxPool, seq, plaintext, ciphertext);
		return ciphertext;
	}

	/**
	 * Decrypt ciphertext using the FAST cipher.
	 * Each value in ciphertext must be in [0, radix).
	 */
	decrypt(
		ciphertext: Uint8Array,
		tweak: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		this.assertNotDestroyed();
		this.validateInput(ciphertext);
		const seq = this.ensureSequence(tweak);
		const plaintext = new Uint8Array(this.params.wordLength);
		cdec(this.params, this.sboxPool, seq, ciphertext, plaintext);
		return plaintext;
	}

	/**
	 * Zero out sensitive key material.
	 */
	destroy(): void {
		if (this.destroyed) return;

		this.masterKey.fill(0);
		this.cachedSeq?.fill(0);
		this.cachedSeq = null;
		this.cachedTweak?.fill(0);
		this.cachedTweak = null;
		for (const sbox of this.sboxPool.sboxes) {
			sbox.perm.fill(0);
			sbox.inv.fill(0);
		}
		this.destroyed = true;
	}
}
