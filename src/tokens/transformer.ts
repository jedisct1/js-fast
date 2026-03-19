import type { FastCipher } from "../cipher.ts";
import type { Alphabet } from "./types.ts";

export function charsToIndices(body: string, alphabet: Alphabet): Uint8Array {
	const indices = new Uint8Array(body.length);
	for (let i = 0; i < body.length; i++) {
		const idx = alphabet.charToIndex.get(body[i]!);
		if (idx === undefined) {
			throw new Error(
				`Character '${body[i]}' not in alphabet '${alphabet.name}'`,
			);
		}
		indices[i] = idx;
	}
	return indices;
}

export function indicesToChars(
	indices: Uint8Array,
	alphabet: Alphabet,
): string {
	let result = "";
	for (let i = 0; i < indices.length; i++) {
		result += alphabet.chars[indices[i]!];
	}
	return result;
}

export function transformBody(
	body: string,
	alphabet: Alphabet,
	cipher: FastCipher,
	mode: "encrypt" | "decrypt",
	tweak: Uint8Array,
): string {
	const indices = charsToIndices(body, alphabet);
	const result =
		mode === "encrypt"
			? cipher.encrypt(indices, tweak)
			: cipher.decrypt(indices, tweak);
	return indicesToChars(result, alphabet);
}
