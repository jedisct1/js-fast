import { createCipheriv } from "node:crypto";

const AES_BLOCK_SIZE = 16;
const AES_KEY_SIZE = 16;
const CMAC_RB = 0x87;

/**
 * AES-128 single-block encryption (ECB mode, no padding).
 */
function aesEncryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
	const cipher = createCipheriv("aes-128-ecb", key, null);
	cipher.setAutoPadding(false);
	const encrypted = cipher.update(block);
	cipher.final(); // flush (no additional bytes for ECB with exact block)
	return new Uint8Array(encrypted);
}

/**
 * Generate AES-CMAC subkeys K1 and K2 from the AES key.
 * RFC 4493 Section 2.3.
 */
function generateCmacSubkeys(key: Uint8Array): {
	k1: Uint8Array;
	k2: Uint8Array;
} {
	const block = aesEncryptBlock(key, new Uint8Array(AES_BLOCK_SIZE));
	const k1 = leftShiftAndXor(block, CMAC_RB);
	const k2 = leftShiftAndXor(k1, CMAC_RB);

	return { k1, k2 };
}

function leftShiftAndXor(input: Uint8Array, xorByte: number): Uint8Array {
	const output = new Uint8Array(AES_BLOCK_SIZE);
	let carry = 0;
	for (let i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
		const b = input[i]!;
		output[i] = ((b << 1) | carry) & 0xff;
		carry = (b >> 7) & 1;
	}
	// If MSB of input was 1, XOR last byte with Rb
	if ((input[0]! >> 7) & 1) {
		output[AES_BLOCK_SIZE - 1]! ^= xorByte;
	}
	return output;
}

/**
 * Compute AES-128-CMAC (RFC 4493).
 */
function aesCmac(key: Uint8Array, message: Uint8Array): Uint8Array {
	const { k1, k2 } = generateCmacSubkeys(key);
	const blockCount =
		message.length === 0 ? 1 : Math.ceil(message.length / AES_BLOCK_SIZE);
	const lastBlockOffset = (blockCount - 1) * AES_BLOCK_SIZE;
	const hasFullLastBlock =
		message.length > 0 && message.length % AES_BLOCK_SIZE === 0;
	const lastBlock = new Uint8Array(AES_BLOCK_SIZE);

	if (hasFullLastBlock) {
		for (let i = 0; i < AES_BLOCK_SIZE; i++) {
			lastBlock[i] = message[lastBlockOffset + i]! ^ k1[i]!;
		}
	} else {
		const remaining = message.length - lastBlockOffset;
		lastBlock.set(message.subarray(lastBlockOffset));
		lastBlock[remaining] = 0x80;
		for (let i = 0; i < AES_BLOCK_SIZE; i++) {
			lastBlock[i]! ^= k2[i]!;
		}
	}

	const state = new Uint8Array(AES_BLOCK_SIZE);
	for (let blockIndex = 0; blockIndex < blockCount - 1; blockIndex++) {
		const blockOffset = blockIndex * AES_BLOCK_SIZE;
		for (let i = 0; i < AES_BLOCK_SIZE; i++) {
			state[i]! ^= message[blockOffset + i]!;
		}
		state.set(aesEncryptBlock(key, state));
	}

	for (let i = 0; i < AES_BLOCK_SIZE; i++) {
		state[i]! ^= lastBlock[i]!;
	}

	return aesEncryptBlock(key, state);
}

/**
 * Derive key material using AES-CMAC in counter mode.
 * Matches the C and Zig reference implementations exactly.
 *
 * buffer = counter_be32 || encoded_input
 * CMAC is computed for counter 0, 1, 2, ... until enough bytes are produced.
 */
export function deriveKey(
	masterKey: Uint8Array,
	input: Uint8Array,
	outputLength: number,
): Uint8Array {
	if (masterKey.length !== AES_KEY_SIZE) {
		throw new Error("Master key must be 16 bytes");
	}
	if (outputLength === 0) {
		throw new Error("Output length must be > 0");
	}

	const output = new Uint8Array(outputLength);
	const buffer = new Uint8Array(4 + input.length);
	const bufferView = new DataView(buffer.buffer);

	// Copy input once (counter updated in place)
	buffer.set(input, 4);

	let bytesGenerated = 0;
	let counter = 0;

	while (bytesGenerated < outputLength) {
		bufferView.setUint32(0, counter, false); // big-endian counter
		const cmacOutput = aesCmac(masterKey, buffer);

		const toCopy = Math.min(outputLength - bytesGenerated, AES_BLOCK_SIZE);
		output.set(cmacOutput.subarray(0, toCopy), bytesGenerated);
		bytesGenerated += toCopy;
		counter++;
	}

	return output;
}
