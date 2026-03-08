import { describe, expect, test } from "bun:test";
import {
	buildSetup1Input,
	buildSetup2Input,
	encodeParts,
} from "../src/encoding.ts";
import type { FastParams } from "../src/types.ts";

const decoder = new TextDecoder();
const baseParams: FastParams = {
	radix: 10,
	wordLength: 16,
	sboxCount: 256,
	numLayers: 592,
	branchDist1: 2,
	branchDist2: 1,
	securityLevel: 128,
};

function readU32(bytes: Uint8Array, offset: number): number {
	return new DataView(
		bytes.buffer,
		bytes.byteOffset,
		bytes.byteLength,
	).getUint32(offset, false);
}

function readText(bytes: Uint8Array, offset: number, length: number): string {
	return decoder.decode(bytes.slice(offset, offset + length));
}

describe("encodeParts", () => {
	test("encodes an empty parts list", () => {
		const encoded = encodeParts([]);

		expect(encoded).toHaveLength(4);
		expect(readU32(encoded, 0)).toBe(0);
	});

	test("encodes a single part", () => {
		const encoded = encodeParts([new Uint8Array([0x41, 0x42])]);

		expect(readU32(encoded, 0)).toBe(1);
		expect(readU32(encoded, 4)).toBe(2);
		expect(Array.from(encoded.slice(8))).toEqual([0x41, 0x42]);
		expect(encoded).toHaveLength(10);
	});

	test("encodes multiple parts back to back", () => {
		const encoded = encodeParts([
			new Uint8Array([1, 2, 3]),
			new Uint8Array([4, 5]),
			new Uint8Array([]),
		]);

		expect(readU32(encoded, 0)).toBe(3);
		expect(readU32(encoded, 4)).toBe(3);
		expect(Array.from(encoded.slice(8, 11))).toEqual([1, 2, 3]);
		expect(readU32(encoded, 11)).toBe(2);
		expect(Array.from(encoded.slice(15, 17))).toEqual([4, 5]);
		expect(readU32(encoded, 17)).toBe(0);
		expect(encoded).toHaveLength(21);
	});
});

describe("buildSetup1Input", () => {
	test("lays out the pool derivation payload as expected", () => {
		const encoded = buildSetup1Input(baseParams);
		let offset = 4;

		expect(readU32(encoded, 0)).toBe(4);
		expect(readU32(encoded, offset)).toBe(9);
		offset += 4;
		expect(readText(encoded, offset, 9)).toBe("instance1");
		offset += 9;

		expect(readU32(encoded, offset)).toBe(4);
		offset += 4;
		expect(readU32(encoded, offset)).toBe(10);
		offset += 4;

		expect(readU32(encoded, offset)).toBe(4);
		offset += 4;
		expect(readU32(encoded, offset)).toBe(256);
		offset += 4;

		expect(readU32(encoded, offset)).toBe(8);
		offset += 4;
		expect(readText(encoded, offset, 8)).toBe("FPE Pool");
	});
});

describe("buildSetup2Input", () => {
	test("includes the expected number of parts when a tweak is present", () => {
		expect(
			readU32(
				buildSetup2Input(baseParams, new Uint8Array([0x00, 0x11, 0x22, 0x33])),
				0,
			),
		).toBe(11);
	});

	test("keeps the same layout when the tweak is empty", () => {
		expect(readU32(buildSetup2Input(baseParams, new Uint8Array(0)), 0)).toBe(
			11,
		);
	});
});
