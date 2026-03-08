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
	private masterKey: Uint8Array;
	private sboxPool: SBoxPool;
	private cachedTweak: Uint8Array | null;
	private cachedSeq: Uint32Array | null;

	private constructor(
		params: FastParams,
		masterKey: Uint8Array,
		sboxPool: SBoxPool,
	) {
		this.params = params;
		this.masterKey = new Uint8Array(masterKey);
		this.sboxPool = sboxPool;
		this.cachedTweak = null;
		this.cachedSeq = null;
	}

	/**
	 * Create a new FAST cipher context.
	 * Validates parameters and generates the S-box pool from the master key.
	 */
	static create(params: FastParams, key: Uint8Array): FastCipher {
		// Validate parameters
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

		// Derive S-box pool key material
		const setup1Input = buildSetup1Input(params);
		const poolKeyMaterial = deriveKey(key, setup1Input, DERIVED_KEY_SIZE);

		// Generate S-box pool
		const sboxPool = generateSBoxPool(
			params.radix,
			params.sboxCount,
			poolKeyMaterial,
		);

		// Zero key material
		poolKeyMaterial.fill(0);

		return new FastCipher(params, key, sboxPool);
	}

	private ensureSequence(tweak: Uint8Array): Uint32Array {
		// Check cache
		if (this.cachedSeq !== null) {
			if (
				this.cachedTweak !== null &&
				tweak.length === this.cachedTweak.length
			) {
				let match = true;
				for (let i = 0; i < tweak.length; i++) {
					if (tweak[i] !== this.cachedTweak[i]) {
						match = false;
						break;
					}
				}
				if (match) return this.cachedSeq;
			} else if (this.cachedTweak === null && tweak.length === 0) {
				return this.cachedSeq;
			}
		}

		// Derive sequence key material
		const setup2Input = buildSetup2Input(this.params, tweak);
		const seqKeyMaterial = deriveKey(
			this.masterKey,
			setup2Input,
			DERIVED_KEY_SIZE,
		);

		// Generate sequence
		const seq = generateSequence(
			this.params.numLayers,
			this.params.sboxCount,
			seqKeyMaterial,
		);

		seqKeyMaterial.fill(0);

		// Cache
		this.cachedTweak = tweak.length > 0 ? new Uint8Array(tweak) : null;
		this.cachedSeq = seq;

		return seq;
	}

	private validateInput(data: Uint8Array): void {
		if (data.length !== this.params.wordLength) {
			throw new InvalidLengthError();
		}
		for (let i = 0; i < data.length; i++) {
			if (data[i]! >= this.params.radix) {
				throw new InvalidValueError();
			}
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
		this.masterKey.fill(0);
		this.cachedSeq = null;
		this.cachedTweak = null;
	}
}
