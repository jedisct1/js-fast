import type { FastParams } from "./types.ts";

const LABEL_INSTANCE1 = new TextEncoder().encode("instance1");
const LABEL_INSTANCE2 = new TextEncoder().encode("instance2");
const LABEL_FPE_POOL = new TextEncoder().encode("FPE Pool");
const LABEL_FPE_SEQ = new TextEncoder().encode("FPE SEQ");
const LABEL_TWEAK = new TextEncoder().encode("tweak");

function writeU32Be(value: number): Uint8Array {
	const buf = new Uint8Array(4);
	const view = new DataView(buf.buffer);
	view.setUint32(0, value, false);
	return buf;
}

/**
 * Encode an array of parts into the PRF input format.
 * Format: 4-byte BE part count, then for each part: 4-byte BE length + raw bytes.
 */
export function encodeParts(parts: Uint8Array[]): Uint8Array {
	let total = 4; // part count
	for (const part of parts) {
		total += 4 + part.length;
	}

	const buffer = new Uint8Array(total);
	const view = new DataView(buffer.buffer);
	let pos = 0;

	view.setUint32(pos, parts.length, false);
	pos += 4;

	for (const part of parts) {
		view.setUint32(pos, part.length, false);
		pos += 4;
		buffer.set(part, pos);
		pos += part.length;
	}

	return buffer;
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
