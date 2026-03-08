import type { FastParams } from "./types.ts";

const encoder = new TextEncoder();
const LABEL_INSTANCE1 = encoder.encode("instance1");
const LABEL_INSTANCE2 = encoder.encode("instance2");
const LABEL_FPE_POOL = encoder.encode("FPE Pool");
const LABEL_FPE_SEQ = encoder.encode("FPE SEQ");
const LABEL_TWEAK = encoder.encode("tweak");

function writeU32Be(value: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value, false);
	return bytes;
}

/**
 * Encode an array of parts into the PRF input format.
 * Format: 4-byte BE part count, then for each part: 4-byte BE length + raw bytes.
 */
export function encodeParts(parts: Uint8Array[]): Uint8Array {
	const totalLength = parts.reduce((total, part) => total + 4 + part.length, 4);
	const encoded = new Uint8Array(totalLength);
	const view = new DataView(encoded.buffer);
	let offset = 0;

	view.setUint32(offset, parts.length, false);
	offset += 4;

	for (const part of parts) {
		view.setUint32(offset, part.length, false);
		offset += 4;
		encoded.set(part, offset);
		offset += part.length;
	}

	return encoded;
}

/**
 * Build the setup1 input for S-box pool key derivation.
 * Parts: [LABEL_INSTANCE1, radix_be32, sboxCount_be32, LABEL_FPE_POOL]
 */
export function buildSetup1Input(params: FastParams): Uint8Array {
	return encodeParts([
		LABEL_INSTANCE1,
		writeU32Be(params.radix),
		writeU32Be(params.sboxCount),
		LABEL_FPE_POOL,
	]);
}

/**
 * Build the setup2 input for sequence key derivation.
 * Parts: [LABEL_INSTANCE1, radix, sboxCount, LABEL_INSTANCE2,
 *         wordLength, numLayers, branchDist1, branchDist2,
 *         LABEL_FPE_SEQ, LABEL_TWEAK, tweak]
 */
export function buildSetup2Input(
	params: FastParams,
	tweak: Uint8Array,
): Uint8Array {
	return encodeParts([
		LABEL_INSTANCE1,
		writeU32Be(params.radix),
		writeU32Be(params.sboxCount),
		LABEL_INSTANCE2,
		writeU32Be(params.wordLength),
		writeU32Be(params.numLayers),
		writeU32Be(params.branchDist1),
		writeU32Be(params.branchDist2),
		LABEL_FPE_SEQ,
		LABEL_TWEAK,
		tweak,
	]);
}
