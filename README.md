# FAST implementation for JavaScript

A TypeScript implementation of the FAST (Format-preserving, Additive, Symmetric Translation) cipher.

FAST is a format-preserving encryption (FPE) scheme for arbitrary radix values and fixed word lengths. This implementation encrypts data while preserving both the input length and the symbol domain, making it suitable for tokenizing or encrypting structured values such as decimal identifiers or byte-oriented records.

This implementation is intended to be fully interoperable with the other existing FAST implementations.

## Installation

Install from npm:

```bash
npm install fast-cipher
```

With Bun:

```bash
bun add fast-cipher
```

This package ships as standard ESM with bundled JavaScript in `dist/` and published TypeScript declarations, so the same package import works in Bun, Node.js, and TypeScript projects.

Node.js consumers should use an ESM project setup (`"type": "module"` in `package.json` or `.mjs` entry files). The published package target is Node.js 20 or newer.

## Usage

### Basic Example

```ts
import { FastCipher, calculateRecommendedParams } from "fast-cipher";

const params = calculateRecommendedParams(10, 16);
const key = new Uint8Array([
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
]);

const cipher = FastCipher.create(params, key);

const tweak = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
]);

const plaintext = new Uint8Array([
  1, 2, 3, 4, 5, 6, 7, 8,
  9, 0, 1, 2, 3, 4, 5, 6,
]);

const ciphertext = cipher.encrypt(plaintext, tweak);
const recovered = cipher.decrypt(ciphertext, tweak);

console.log(ciphertext);
console.log(recovered);

cipher.destroy();
```

### Input Rules

- `key` must be exactly 16 bytes
- `radix` must be between 4 and 256
- `wordLength` must be at least 2
- `numLayers` must be a positive multiple of `wordLength`
- `branchDist1` must be at most `wordLength - 2`
- `branchDist2` must be >= 1, at most `wordLength - 1`, and at most `wordLength - branchDist1 - 1`
- plaintext and ciphertext must have length `wordLength`
- every symbol in the input must be in the range `[0, radix)`

### Tweaks

Tweaks provide domain separation. Encrypting the same plaintext with the same key and different tweaks produces different ciphertexts. The same tweak must be supplied again for decryption.

```ts
const params = calculateRecommendedParams(10, 8);
const cipher = FastCipher.create(params, key);
const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

const tweakA = new Uint8Array([1]);
const tweakB = new Uint8Array([2]);

const ctA = cipher.encrypt(plaintext, tweakA);
const ctB = cipher.encrypt(plaintext, tweakB);

console.log(ctA);
console.log(ctB);
```

## API

### `calculateRecommendedParams(radix, wordLength, securityLevel?)`

Returns a `FastParams` object using the FAST round tables and branch-distance rules. The returned parameters use an S-box pool size of 256 and a security level of 128 bits by default.

### `FastCipher.create(params, key)`

Creates a cipher context, validates parameters, and derives the S-box pool from the master key.

### `cipher.encrypt(plaintext, tweak?)`

Encrypts a `Uint8Array` and returns a new `Uint8Array` with the same length and radix domain. If `tweak` is omitted, the cipher uses an empty tweak.

### `cipher.decrypt(ciphertext, tweak?)`

Decrypts a `Uint8Array` produced by FAST using the same parameters, key, and tweak. If `tweak` is omitted, the cipher uses an empty tweak.

### `cipher.destroy()`

Zeros the stored master key material held by the cipher instance.

### Errors

The package exports `FastError` plus the concrete error classes used for invalid inputs and parameters:
`InvalidBranchDistError`, `InvalidLengthError`, `InvalidParametersError`, `InvalidRadixError`, `InvalidSBoxCountError`, `InvalidValueError`, and `InvalidWordLengthError`.

## Token Encryption

The `fast-cipher/tokens` subpath exports a higher-level `TokenEncryptor` that scans text for known secret token formats (API keys, access tokens, etc.) and encrypts them in place using format-preserving encryption. The encrypted output has the same length, character set, and prefix as the original token.

```ts
import { TokenEncryptor } from "fast-cipher/tokens";

const key = new Uint8Array(16); // 16-byte AES key
crypto.getRandomValues(key);

const enc = new TokenEncryptor(key);

const text = "My GitHub token is ghp_ABCDEFabcdef1234567890abcdef12345678";
const encrypted = enc.encrypt(text);
const decrypted = enc.decrypt(encrypted);
// decrypted === text

enc.destroy();
```

### Supported Token Formats

There are three kinds of built-in patterns:

**Prefix-based** (fully format-preserving) -- The prefix (`ghp_`, `sk-proj-`, `AKIA`, etc.) is preserved as-is and only the body is encrypted. The output has the same length, prefix, and character set as the input. Covers: OpenAI, Anthropic, GitHub, GitLab, AWS access keys, Stripe, Google, Twilio, npm, PyPI, Datadog, Vercel, Supabase, HuggingFace, and Grafana.

**Structured** (fully format-preserving) -- Tokens with internal delimiters like SendGrid (`SG.<seg1>.<seg2>`) and Slack (`xoxb-<seg1>-<seg2>-<seg3>`) encrypt each segment independently while preserving the prefix and delimiters.

**Heuristic** (marker-based) -- Some tokens have no fixed prefix (e.g. Fastly API tokens, AWS secret keys). These are detected using heuristics: exact length constraints, word boundary detection, Shannon entropy thresholds, and character class diversity. On encrypt, a `[ENCRYPTED:<name>]` marker is prepended so that `decrypt()` can safely identify encrypted spans without corrupting plaintext strings that happen to look token-like. The encrypted body itself is format-preserving (same length and alphabet), but the marker makes the overall output longer than the input. Heuristic patterns are active by default and can be excluded via the `types` filter.

### Options

```ts
// Restrict to specific pattern names
const opts = { types: ["github-pat", "openai"] };
const filtered = enc.encrypt(text, opts);
// IMPORTANT: pass the same types filter to decrypt()
const restored = enc.decrypt(filtered, opts);

// Per-document tweak to break deterministic linkage
const tweaked = enc.encrypt(text, { tweak: new Uint8Array([1, 2, 3]) });
const untweaked = enc.decrypt(tweaked, { tweak: new Uint8Array([1, 2, 3]) });
```

### Custom Patterns

```ts
import { TokenEncryptor, ALPHANUMERIC } from "fast-cipher/tokens";

const enc = new TokenEncryptor(key);

enc.register({
  kind: "simple",
  name: "my-service",
  prefix: "myapp_",
  bodyRegex: "[A-Za-z0-9]{32}",
  bodyAlphabet: ALPHANUMERIC,
  minBodyLength: 32,
});
```

The exported alphabets are `ALPHANUMERIC`, `ALPHANUMERIC_LOWER`, `ALPHANUMERIC_UPPER`, `BASE64`, `BASE64URL`, `DIGITS`, and `HEX_LOWER`.

## Development

Run the formatter:

```bash
bunx biome format --write src test
```

Run lint/style checks:

```bash
bunx biome check src test
```

Run the test suite:

```bash
bun test
```

Run type checking:

```bash
bunx tsc --noEmit
```

Build the package:

```bash
bun run build
```

## References

- [FAST Paper](https://eprint.iacr.org/2021/1171.pdf)
- [The Next Generation of Performant Data Protection: a New FPE Algorithm](https://insights.comforte.com/the-next-generation-of-performant-data-protection-a-new-fpe-algorithm)
- [Format-Preserving Encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption)
