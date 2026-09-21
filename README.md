# FAST implementation for JavaScript

A TypeScript implementation of the FAST (Format-preserving, Additive, Symmetric Translation) cipher.

FAST is a format-preserving encryption (FPE) scheme for arbitrary radix values and fixed word lengths.
Because it preserves the input length and allowed symbols, it can encrypt structured values such as decimal identifiers or byte-oriented records.
This package interoperates with other FAST implementations.

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

Node.js consumers should use an ESM project setup with `"type": "module"` in `package.json` or `.mjs` entry files.
The published package target is Node.js 20 or newer.

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

Tweaks provide domain separation: the same plaintext and key produce the same ciphertext when the tweak is reused, while different tweaks break that deterministic link between contexts.
Coincidental ciphertext matches are still possible.
The same tweak must be supplied again for decryption.

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

Returns a `FastParams` object using the FAST round tables and branch-distance rules.
By default, the parameters use an S-box pool size of 256 and a security level of 128 bits.

For five-symbol words, `branchDist2` is capped at `wordLength - branchDist1 - 1`, giving branch distances of 3 and 1.
Other FAST implementations need the same cap to decrypt these ciphertexts.
The current zig-fast implementation still rejects five-symbol words.

### `FastCipher.create(params, key)`

Creates a cipher context, validates parameters, and derives the S-box pool from the master key.

### `cipher.encrypt(plaintext, tweak?)`

Encrypts a `Uint8Array` and returns a new `Uint8Array` with the same length and radix domain.
If `tweak` is omitted, the cipher uses an empty tweak.

### `cipher.decrypt(ciphertext, tweak?)`

Decrypts a `Uint8Array` produced by FAST using the same parameters, key, and tweak.
If `tweak` is omitted, the cipher uses an empty tweak.

### `cipher.destroy()`

Zeros the stored master key material held by the cipher instance.

### Errors

The package exports `FastError` plus the concrete error classes used for invalid inputs and parameters:
`InvalidBranchDistError`, `InvalidLengthError`, `InvalidParametersError`, `InvalidRadixError`, `InvalidSBoxCountError`, `InvalidValueError`, and `InvalidWordLengthError`.

## Token Encryption

The `fast-cipher/tokens` subpath exports `TokenEncryptor`, which finds known API keys and access tokens in text and encrypts them in place.
All fixed-prefix tokens keep their length, prefix, and character set.
Tokens found without a fixed prefix receive the marker described below.

```ts
import { TokenEncryptor } from "fast-cipher/tokens";

const key = new Uint8Array(16);
crypto.getRandomValues(key);

const enc = new TokenEncryptor(key);

const text = "My GitHub token is ghp_ABCDEFabcdef1234567890abcdef12345678";
const encrypted = enc.encrypt(text);
const decrypted = enc.decrypt(encrypted);
console.log(decrypted === text);

const result = enc.encryptWithSpans(text);
console.log(result.text);
for (const span of result.spans) {
  console.log(span.patternName, span.start, span.end);
}

enc.destroy();
```

### Supported Token Formats

There are three kinds of built-in patterns:

**Prefix-based patterns** keep prefixes such as `ghp_`, `sk-proj-`, and `AKIA` unchanged while encrypting the rest of the token.
The encrypted token has the same length, prefix, and allowed characters as the original.
This covers OpenAI, Anthropic, GitHub, GitLab, AWS access keys, Stripe, Google, Twilio, npm, PyPI, Datadog, Vercel, Supabase, Hugging Face, and Grafana.

**Structured patterns** split tokens at separators and encrypt each part.
For example, SendGrid uses `SG.<part1>.<part2>`, while Slack bot tokens use `xoxb-<part1>-<part2>-<part3>`.
Slack user tokens use `xoxp-<id1>-<id2>-<id3>-<secret>`, and the three-part `xoxp-` form is also supported.
The prefix, separators, and character sets stay unchanged.
Slack also keeps digits-only parts numeric, as described in [Segments whose alphabet depends on their contents](#segments-whose-alphabet-depends-on-their-contents).

**Heuristic patterns** cover tokens without a fixed prefix, such as Fastly API tokens and AWS secret keys.
They look for the expected length, token boundaries, randomness, and mix of characters.
Encryption adds an `[ENCRYPTED:<name>]` marker so that `decrypt()` can find these tokens without changing ordinary text that happens to look like a token.
The encrypted body keeps its length and character set, but the marker makes the complete result longer.
These patterns are enabled by default.
You can exclude them with the `types` option.

### Decrypting Recorded Tokens

`decrypt(text)` scans the encrypted text to find tokens again.
This usually works, but encrypted text can contain another pattern's prefix by chance.
For example, a Stripe key can contain `AKIA` followed by 16 uppercase letters or digits after encryption.
The scanner then treats that section as an AWS access key, splits the Stripe key, and cannot recover the original token.
The same problem can appear when an application registers a custom prefix or a later package version adds a built-in one.

If you must always recover the original token, record each span's `encrypted` value and `patternName`, then pass them to `decryptToken()`.
Do not store `original` unless you need the plaintext secret.
You can decrypt the recorded values later or in another process, as long as you use the same key and tweak.

```ts
const encryptedResult = enc.encryptWithSpans(text);
const recordedTokens = encryptedResult.spans.map(({ encrypted, patternName }) => ({
  encrypted,
  patternName,
}));

const dec = new TokenEncryptor(key);
const originals = recordedTokens.map((token) =>
  dec.decryptToken(token.encrypted, token.patternName),
);
```

`decryptToken(ciphertext, patternName, options?)` checks one complete token against the named pattern and decrypts it without scanning for other patterns.
Patterns added with `register()` take priority over built-in patterns with the same name.
For heuristic patterns, the encrypted token must include its `[ENCRYPTED:<name>]` marker.
The method returns the original token without that marker.
If you encrypted the token with a `tweak`, pass the same tweak in `options`.

`encryptToken(plaintext, patternName, options?)` encrypts one complete token in the same way.
Its result is the same as the `encrypted` value reported by `encryptWithSpans()`.

Both methods throw `UnknownPatternError` when the pattern does not exist and `TokenFormatError` when the input does not match it.
These errors extend `TokenError`.
Their messages never include the input, output, or key material.
For example, a format error says `Malformed slack-bot token`.

### Segments whose alphabet depends on their contents

Slack parts can use one of two character sets.
A digits-only part stays within the ten digits, while a part containing a letter is encrypted using the 62 letters and digits.
However, a value such as `siXA` can first encrypt to `1234`.
Without another check, decryption would mistake it for a digits-only part and use the wrong character set.

To prevent this, the value is encrypted again with the original character set until the result contains a letter.
This process is called cycle walking, and decryption follows the same path in reverse.
Digits-only parts always encrypt to digits, while patterns with fixed character sets, such as SendGrid, finish in one step.

Each part is limited to `MAX_CYCLE_STEPS`, which is 32 attempts in either direction.
If no valid result is found, the operation throws `CycleWalkError` without returning partial output.

Custom structured patterns use the same protection.
To support it, `parse(format(segments))` must return the same segments and character sets, and the character set for each part must depend only on that part.

The package also exports `cycleWalk(input, step, inClass, maxSteps?)` for custom uses.
It returns the accepted output and the number of calls to `step`; the input must already pass `inClass`, and `step` must be reversible.

### Options

```ts
const opts = { types: ["github-pat", "openai"] };
const filtered = enc.encrypt(text, opts);
const restored = enc.decrypt(filtered, opts);

const tweak = new Uint8Array([1, 2, 3]);
const tweaked = enc.encrypt(text, { tweak });
const untweaked = enc.decrypt(tweaked, { tweak });
```

Use the same `types` filter and `tweak` when decrypting.
A different tweak for each document provides domain separation, breaking the deterministic link between repeated plaintext tokens in different documents.

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
Custom alphabets used for encryption must have an integer radix from 4 to 256.
An unsupported radix raises `TokenError` with a message identifying the pattern's alphabet configuration.

## Development

Run the formatter:

```bash
bunx biome format --write src test
```

Run lint/style checks:

```bash
bunx biome check src test
```

Build the package before running the test suite, since the package import tests load `dist/`:

```bash
bun run build
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
