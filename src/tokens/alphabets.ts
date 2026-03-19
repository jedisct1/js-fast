import type { Alphabet } from "./types.ts";

function makeAlphabet(name: string, chars: string): Alphabet {
	const charToIndex = new Map<string, number>();
	for (let i = 0; i < chars.length; i++) {
		charToIndex.set(chars[i]!, i);
	}
	return { name, chars, radix: chars.length, charToIndex };
}

export const DIGITS: Alphabet = makeAlphabet("digits", "0123456789");

export const HEX_LOWER: Alphabet = makeAlphabet(
	"hex-lower",
	"0123456789abcdef",
);

export const ALPHANUMERIC_UPPER: Alphabet = makeAlphabet(
	"alphanumeric-upper",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
);

export const ALPHANUMERIC_LOWER: Alphabet = makeAlphabet(
	"alphanumeric-lower",
	"0123456789abcdefghijklmnopqrstuvwxyz",
);

export const ALPHANUMERIC: Alphabet = makeAlphabet(
	"alphanumeric",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
);

export const BASE64: Alphabet = makeAlphabet(
	"base64",
	"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
);

export const BASE64URL: Alphabet = makeAlphabet(
	"base64url",
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-",
);
