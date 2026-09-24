import type { TokenPattern } from "./types.ts";
declare const MIN_SEGMENT_LENGTH = 4;
export declare function escapeRegex(s: string): string;
export declare const BUILTIN_PATTERNS: readonly TokenPattern[];
export { MIN_SEGMENT_LENGTH };
