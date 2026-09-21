import type { FastCipher } from "../cipher.ts";
import type { Alphabet } from "./types.ts";
export declare function charsToIndices(body: string, alphabet: Alphabet): Uint8Array;
export declare function indicesToChars(indices: Uint8Array, alphabet: Alphabet): string;
export declare function transformBody(body: string, alphabet: Alphabet, cipher: FastCipher, mode: "encrypt" | "decrypt", tweak: Uint8Array): string;
