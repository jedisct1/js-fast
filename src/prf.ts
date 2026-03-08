import { createCipheriv } from "node:crypto";

const AES_BLOCK_SIZE = 16;
const AES_KEY_SIZE = 16;

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
	const Rb = 0x87;
	const zero = new Uint8Array(AES_BLOCK_SIZE);
	const L = aesEncryptBlock(key, zero);

	// Left-shift by 1 and conditionally XOR with Rb
	const k1 = leftShiftAndXor(L, Rb);
	const k2 = leftShiftAndXor(k1, Rb);

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

	const n =
		message.length === 0 ? 1 : Math.ceil(message.length / AES_BLOCK_SIZE);
	const lastBlockComplete =
		message.length > 0 && message.length % AES_BLOCK_SIZE === 0;

	// Prepare last block
	const lastBlock = new Uint8Array(AES_BLOCK_SIZE);
	const lastBlockStart = (n - 1) * AES_BLOCK_SIZE;

	if (lastBlockComplete) {
		// XOR last complete block with K1
		for (let i = 0; i < AES_BLOCK_SIZE; i++) {
			lastBlock[i] = message[lastBlockStart + i]! ^ k1[i]!;
		}
	} else {
		// Pad incomplete block: append 1-bit then zeros, XOR with K2
		const remaining = message.length - lastBlockStart;
		for (let i = 0; i < AES_BLOCK_SIZE; i++) {
			if (i < remaining) {
				lastBlock[i] = message[lastBlockStart + i]! ^ k2[i]!;
			} else if (i === remaining) {
				lastBlock[i] = 0x80 ^ k2[i]!;
			} else {
				lastBlock[i] = k2[i]!;
			}
		}
	}

	// CBC-MAC
	const x = new Uint8Array(AES_BLOCK_SIZE);

	for (let i = 0; i < n - 1; i++) {
		const blockStart = i * AES_BLOCK_SIZE;
		for (let j = 0; j < AES_BLOCK_SIZE; j++) {
			x[j]! ^= message[blockStart + j]!;
		}
		const encrypted = aesEncryptBlock(key, x);
		x.set(encrypted);
	}

	// Last block
	for (let j = 0; j < AES_BLOCK_SIZE; j++) {
		x[j]! ^= lastBlock[j]!;
	}

	return aesEncryptBlock(key, x);
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
