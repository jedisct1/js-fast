import type { SBoxPool } from "./sbox.ts";
import type { FastParams } from "./types.ts";
/**
 * Component encryption: apply all ES layers in forward order.
 */
export declare function cenc(params: FastParams, pool: SBoxPool, seq: Uint32Array, input: Uint8Array, output: Uint8Array): void;
/**
 * Component decryption: apply all DS layers in reverse order.
 */
export declare function cdec(params: FastParams, pool: SBoxPool, seq: Uint32Array, input: Uint8Array, output: Uint8Array): void;
