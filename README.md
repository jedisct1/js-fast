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

The exported alphabets are `ALPHANUMERIC`, `ALPHANUMERIC_LOWER`, `ALPHANUMERIC_UPPER`, `BASE64`, `BASE64URL`, `DIGITS`, `HEX_LOWER`, and `TOKEN67`, the alphabet of wrapped tokens.
Custom alphabets used for encryption must have an integer radix from 4 to 256.
An unsupported radix raises `TokenError` with a message identifying the pattern's alphabet configuration.

## Wrapped Tokens

Format-preserving output is convenient, but recovering it means finding the tokens again, which can fail as described in [Decrypting Recorded Tokens](#decrypting-recorded-tokens).
`encryptWrapped()` gives up the original format instead.
It replaces every detected token with a self-delimiting `{ENCRYPTED:<payload>}` wrapper, and `decryptWrapped()` finds those wrappers again without stored positions, pattern names, or the pattern registry.

```ts
const enc = new TokenEncryptor(key);

const wrapped = enc.encryptWrapped(
  "Deploy with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij today",
);
// "Deploy with {ENCRYPTED:<48 symbols>} today"

const restored = new TokenEncryptor(key).decryptWrapped(wrapped);
```

The whole token is encrypted, including its prefix and separators, so the wrapper does not reveal the provider.
Its payload is eight symbols longer than the token, and the complete wrapper is exactly 20 characters longer.
Text outside tokens, Unicode included, is copied unchanged.
A fresh instance, a different set of registered patterns, or another document can decrypt a wrapper as long as the key and tweak are the same.

Detection is the same as for `encrypt()`, including the `types` filter, so the scanner's false positives and misses still apply.
Wrapping only makes recovery reliable.

### Options and limits

`encryptWrapped(text, options?)` accepts `types`, `tweak`, and `maxTokenLength`.
`decryptWrapped(text, options?)` accepts `tweak`, `maxTokenLength`, and `onInvalid`; it has no `types` option because it does not look for tokens.

`maxTokenLength` bounds the work done for a single wrapper.
It defaults to 512 characters and must be an integer from 2 to 4,096, so a payload never exceeds 4,104 symbols.
Several built-in patterns, such as OpenAI and Stripe keys, have no maximum length, and a longer match makes encryption throw rather than stay in plaintext.
If you raise the limit for encryption, raise it for decryption as well.

On an Apple M5 Max, the first wrapped call on an instance spends about 3.5 ms deriving its key and S-box pool.
Each wrapper then takes about 1 ms to encrypt or decrypt at 512 characters, 12 ms at 2,048, and 56 ms at 4,096.
The limit bounds the cost of one wrapper, not of a whole document, so services that decrypt untrusted text should also limit document size and request rates.

### Strict and preserve decryption

By default, `decryptWrapped()` returns a string only if every candidate is valid, and otherwise throws without returning partial output.
A candidate is the text after each `{ENCRYPTED:` opener: the longest run of alphabet symbols, which must be followed by `}` and hold between 10 and `maxTokenLength + 8` symbols.
Framing is checked for the whole text before anything is decrypted.

- `WrappedTokenFormatError` reports a candidate with a symbol outside the alphabet, no closing brace, or a bad payload length.
  A payload that only exceeds `maxTokenLength` has its own message, so a configuration mismatch does not look like corruption.
- `WrappedTokenIntegrityError` reports a wrapper whose check symbols do not decrypt to zero.
  A wrong key, a wrong tweak, or a modified payload normally ends here.

Both extend `TokenError`, and their messages never include tokens, payloads, tweaks, keys, or pattern names.

With `{ onInvalid: "preserve" }`, the method returns `{ text, preservedCandidates }` instead.
Valid wrappers are decrypted, and each invalid candidate is left unchanged and counted once.
A candidate ends at the first symbol outside the alphabet, which is consumed only when it is `}`, so a stray or quoted opener does not hide the wrappers after it.

```ts
const result = enc.decryptWrapped(`say "{ENCRYPTED:" then ${wrapped}`, {
  onInvalid: "preserve",
});
// result.text: 'say "{ENCRYPTED:" then Deploy with ghp_... today'
// result.preservedCandidates: 1
```

Nested wrappers are checked independently: in `{ENCRYPTED:{ENCRYPTED:...}}` the outer opener is kept, and the inner wrapper is decrypted only if it passes its own check.
Recovered tokens are never scanned again.
Invalid options, a destroyed instance, and other operational errors still throw in preserve mode.

The TypeScript overloads return `string` in the default mode, `WrappedDecryptResult` for `onInvalid: "preserve"`, and the union when the mode is only known at run time.

### Using wrapped tokens in a pipeline

Encrypt only newly received plaintext, and store the wrapped result.
`encryptWrapped()` rejects any text that already contains `{ENCRYPTED:`, whether or not it is a valid wrapper, because a literal wrapper cannot be told apart from a real one.
Running it again over a history that contains wrappers therefore throws, instead of nesting or skipping them.

Use strict decryption when validating stored text or wherever integrity matters.
Preserve mode suits display of partial streamed or pasted text, where `preservedCandidates` tells you that something could not be recovered.
The count does not say where, and a successful result can mix recovered tokens with text that was never verified.

### Integrity and privacy limits

Eight zero symbols are appended to each token before encryption and checked after decryption, before any plaintext is released.
Assuming FAST behaves as a strong tweakable pseudorandom permutation over the whole word, a forged or damaged wrapper passes with probability about 67^-8, or 2.5e-15, roughly 48.5 bits.
This is a conditional, per-attempt bound that accumulates over attempts.
It is not standard authenticated encryption and does not provide 128-bit integrity.

Encryption is deterministic.
Equal tokens produce equal wrappers under the same key and tweak, and the wrapper reveals the token length.
The check symbols do not add entropy, so short custom tokens can be enumerated by anyone who can encrypt.
A valid wrapper can be replayed, moved, or swapped for another under the same key and tweak, and removing a whole wrapper cannot be detected.
Nothing here authenticates the surrounding text, the order of wrappers, or the completeness of a document; use an authenticated container when you need that.

A tweak, such as a tenant or conversation identifier, keeps wrappers from being reused across contexts.
Keep it yourself: it is not stored in the wrapper.
An omitted tweak and an empty one are the same.

### Wrapped format, version 1

This section defines the format for other implementations.
The shared test vectors in [`test/fixtures/wrapped-tokens-v1.json`](test/fixtures/wrapped-tokens-v1.json) cover the derived key and tweak, parameters, payloads, invalid wrappers, and whole documents.
Check them before treating another implementation as compatible.

The alphabet has 67 symbols, in this order:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/-_.
```

A wrapper is the literal `{ENCRYPTED:`, a payload, and `}`, with no padding, whitespace, escaping, or separator.
To encrypt a token of length `L`, map each character to its alphabet index, append eight zero indices, and encrypt the resulting word of length `n = L + 8` with radix-67 FAST.
The payload is the ciphertext written with the same alphabet.
To decrypt, invert the whole word, check that the last eight indices are zero, and only then strip them.

The FAST key and tweak are derived from the 16-byte master key with the package's existing AES-CMAC derivation and part encoding:

```text
wrapperKey   = deriveKey(masterKey, encodeParts(["fast-cipher/tokens/wrapped/v1/key"]), 16)
wrapperTweak = encodeParts(["fast-cipher/tokens/wrapped/v1/tweak", callerTweak or empty])
```

`encodeParts` writes a four-byte big-endian part count, then each part's four-byte big-endian length and bytes.
`deriveKey` concatenates AES-CMAC outputs over `counter_be32 || input`, starting at counter zero.
FAST then derives its S-box pool and sequence from `wrapperKey` exactly as `FastCipher` does.

The parameters are frozen for version 1, independent of later changes to `calculateRecommendedParams()`.
Radix is 67, the S-box count 256, and the security level 128.
The round counts come from these two rows of the FAST round table:

| Word length | 2   | 3   | 4   | 5   | 6   | 7   | 8   | 9   | 10  | 12  | 16  | 32  | 50  | 64  | 100 |
| ----------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Radix 16    | 67  | 55  | 48  | 43  | 39  | 36  | 35  | 34  | 34  | 33  | 33  | 35  | 38  | 41  | 47  |
| Radix 100   | 40  | 33  | 28  | 27  | 26  | 26  | 25  | 25  | 25  | 26  | 26  | 30  | 34  | 37  | 44  |

For each row, interpolate linearly between the surrounding word lengths with `y0 + ((n - x0) / (x1 - x0)) * (y1 - y0)`.
At 100 or more, use the last entry multiplied by `sqrt(n / 100)`.
With those values `r16` and `r100`, compute in double precision:

```text
f           = (ln(67) - ln(16)) / (ln(100) - ln(16))
rawRounds   = r16 + f * (r100 - r16)
numLayers   = ceil(max(1, rawRounds)) * n
branchDist1 = n <= 2 ? 0 : min(ceil(sqrt(n)), n - 2)
branchDist2 = min(branchDist1 > 1 ? branchDist1 - 1 : 1, n - branchDist1 - 1)
```

For every supported word length, from 10 to 4,104, the raw round count is at least 2e-4 away from an integer.
Floating-point differences between platforms therefore cannot change `numLayers`.

A decoder looks for each exact `{ENCRYPTED:` opener and reads the longest run of alphabet symbols after it.
The candidate is well framed only if that run is followed by `}` and its length is from 10 to `maxTokenLength + 8`.
The next search starts right after the candidate: after the `}` if there is one, or at the character that ended the run otherwise.
An incompatible future format must use a different opener.

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
