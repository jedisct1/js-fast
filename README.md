# FAST implementation for JavaScript

Encrypt data with FAST without changing its length or allowed characters.

A 16-digit number stays a 16-digit number after encryption.
That's useful when you're encrypting values like:

- Numeric IDs
- Records stored as bytes

You choose the input length and the number of allowed symbols, called the radix.

The package implements FAST (Format-preserving, Additive, Symmetric Translation) in TypeScript, and it works with other FAST implementations.

## Installation

```bash
npm install fast-cipher
```

That installs the package from npm.
If you're using Bun instead:

```bash
bun add fast-cipher
```

The package uses JavaScript modules (ESM) and ships with JavaScript files in `dist/` and TypeScript types.
You can use the same import in Bun, Node.js, and TypeScript projects.

For Node.js, you'll need version 20 or newer.
Also, add `"type": "module"` to your `package.json` or use `.mjs` files for your entry points.

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

- `key` must be exactly 16 bytes.
- `radix` is the number of allowed symbols and must be between 4 and 256.
- `wordLength` is the number of symbols in each input and must be at least 2.
- `numLayers` must be a positive multiple of `wordLength`.
- `branchDist1` must be at most `wordLength - 2`.
- `branchDist2` must be at least 1.
  It must also be no greater than either `wordLength - 1` or `wordLength - branchDist1 - 1`.
- Both the original input (plaintext) and the encrypted output (ciphertext) must contain exactly `wordLength` symbols.
- Each input symbol must be a number from 0 to `radix - 1`.

### Tweaks

Want to encrypt the same input differently without changing the key?
That's what a tweak is for: it's an extra value you pass in alongside the input.

For example, you can use a different tweak for each document so repeated values don't always produce the same encrypted output across documents.
Two outputs can still match by chance.

Reuse the same input, key, and tweak, and you'll always get the same encrypted output.
To decrypt it, you'll need the same tweak you used for encryption.

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

Returns a `FastParams` object with recommended settings for your radix and input length.
It follows the FAST rules for choosing rounds and branch distances.
By default, you get a pool of 256 substitution tables (S-boxes) and a security level of 128 bits.

For inputs with five symbols, `branchDist2` is limited to `wordLength - branchDist1 - 1`, giving branch distances of 3 and 1.
Other FAST implementations must use the same limit to decrypt these outputs.
But the current zig-fast implementation still rejects inputs with five symbols.

### `FastCipher.create(params, key)`

Creates a cipher object, checks its settings, and builds the S-box pool from the master key.

### `cipher.encrypt(plaintext, tweak?)`

Encrypts a `Uint8Array` and returns a new `Uint8Array` of the same length.
The output uses the same range of allowed symbol values as the input.
If you leave out `tweak`, the cipher uses an empty tweak.

### `cipher.decrypt(ciphertext, tweak?)`

Decrypts a `Uint8Array` produced by FAST.
Use the same settings, key, and tweak that you used for encryption.
If you leave out `tweak`, the cipher uses an empty tweak.

### `cipher.destroy()`

Overwrites the cipher object's stored master key with zeros.

### Errors

The package exports `FastError` and these error classes for invalid inputs and settings:

- `InvalidBranchDistError`
- `InvalidLengthError`
- `InvalidParametersError`
- `InvalidRadixError`
- `InvalidSBoxCountError`
- `InvalidValueError`
- `InvalidWordLengthError`

## Token Encryption

Need to encrypt API keys or access tokens in text?
Import `TokenEncryptor` from `fast-cipher/tokens`.
It finds known tokens and replaces each one with its encrypted version.

Tokens with a known prefix keep their length, prefix, and allowed characters.
Tokens without a fixed prefix get an extra marker, as described below.

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

There are three kinds of built-in patterns.

**Prefix-based patterns** encrypt the rest of the token but leave prefixes like these alone:

- `ghp_`
- `sk-proj-`
- `AKIA`

The encrypted token has the same length, prefix, and allowed characters as the original.

These patterns cover:

- OpenAI
- Anthropic
- GitHub
- GitLab
- AWS access keys
- Stripe
- Google
- Twilio
- npm
- PyPI
- Datadog
- Vercel
- Supabase
- Hugging Face
- Grafana

**Structured patterns** split tokens at separators and encrypt each part.
The prefix, separators, and allowed characters stay unchanged.
Here are some examples:

- SendGrid: `SG.<part1>.<part2>`
- Slack bot tokens: `xoxb-<part1>-<part2>-<part3>`
- Slack user tokens: `xoxp-<id1>-<id2>-<id3>-<secret>`

The three-part `xoxp-` form works too.
Slack parts made up of digits stay that way after encryption, as explained in [Keeping Slack token parts in the right character set](#keeping-slack-token-parts-in-the-right-character-set).

**Heuristic patterns** look for likely tokens without a fixed prefix, such as:

- Fastly API tokens
- AWS secret keys

They check the length, surrounding characters, how random the value looks, and which kinds of characters it uses.

Encryption adds an `[ENCRYPTED:<name>]` marker so `decrypt()` can find these tokens without changing ordinary text that happens to look like a token.
The encrypted body keeps its length and allowed characters, but the marker makes the full result longer.

These patterns are on by default.
You can leave them out with the `types` option.

### Decrypting Recorded Tokens

`decrypt(text)` scans the encrypted text to find tokens again.
That usually works, but encrypted text can contain another pattern's prefix by chance.

For example, an encrypted Stripe key can contain `AKIA` followed by 16 uppercase letters or digits.
The scanner then treats that section as an AWS access key, splits the Stripe key, and can't recover the original token.
You can hit the same problem if your application adds a custom prefix or a later package version adds a built-in one.

To make sure you can recover the original token, save each span's `encrypted` value and `patternName`, then pass them to `decryptToken()`.
Don't save `original` unless you need to keep the unencrypted secret.

You can decrypt the saved values later or in another process.
Just use the same key and tweak.

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

`decryptToken(ciphertext, patternName, options?)` checks one complete token against the named pattern and decrypts it without looking for other patterns.
If you encrypted the token with a `tweak`, pass the same tweak in `options`.

Patterns added with `register()` take priority over built-in patterns with the same name.
For heuristic patterns, the encrypted token must include its `[ENCRYPTED:<name>]` marker.
The method returns the original token without that marker.

`encryptToken(plaintext, patternName, options?)` encrypts one complete token in the same way.
Its result is the same as the `encrypted` value returned by `encryptWithSpans()`.

Both methods throw `UnknownPatternError` when the pattern does not exist and `TokenFormatError` when the input does not match it.
Both errors extend `TokenError`.

Their messages never include the input, output, or key.
For example, a format error says `Malformed slack-bot token`.

### Keeping Slack token parts in the right character set

Each part of a Slack token uses one of two character sets:

- A part made up of digits uses only the ten digits.
- A part containing a letter uses the 62 uppercase letters, lowercase letters, and digits.

But a value like `siXA` can first encrypt to `1234`.
Without another check, decryption would mistake it for a digits-only part and choose the wrong character set.

So the value is encrypted again with the original character set until the result contains a letter.
That's called cycle walking, and decryption follows the same steps in reverse.

Parts made up of digits always encrypt to digits.
Patterns with fixed character sets, such as SendGrid, finish in one step.

Each part gets at most `MAX_CYCLE_STEPS`, or 32 attempts, when encrypting or decrypting.
If no valid result is found, the operation throws `CycleWalkError` without returning any partial output.

Custom structured patterns use the same protection, but they must follow two rules:

- `parse(format(segments))` must return the same segments and character sets.
- The character set for each part must depend only on that part.

The package also exports `cycleWalk(input, step, inClass, maxSteps?)` for use in your own code.
It returns the accepted output and the number of calls to `step`.
The input must already pass `inClass`, and `step` must be reversible.

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

Use a different tweak for each document so repeated tokens don't always produce the same encrypted output across documents.
Outputs can still match by chance.

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

An alphabet is the set of characters a token can use.
The package exports these alphabets for custom patterns:

- `ALPHANUMERIC`
- `ALPHANUMERIC_LOWER`
- `ALPHANUMERIC_UPPER`
- `BASE64`
- `BASE64URL`
- `DIGITS`
- `HEX_LOWER`
- `TOKEN67`, used for wrapped tokens

Your custom alphabet must have an integer radix from 4 to 256.
If it doesn't, encryption throws `TokenError` with a message that identifies the pattern's alphabet settings.

A token's body runs until the first character that isn't in `bodyAlphabet`.
If another token starts inside that run, the body can end there instead, as long as what comes before is still a valid body.

With the built-in patterns, scanning time grows roughly in proportion to the text's length, even when it's packed with prefixes.
Your custom pattern keeps that property if its `bodyRegex` is a single character class followed by a length, and the class accepts every character of `bodyAlphabet`.
For example:

- `[A-Za-z0-9]{32}`
- `[A-Za-z0-9_-]{20,}`

Any other regex still works, but the scanner has to run it on each possible body, from the start of the body.
A long run of body characters with many other tokens inside, or many copies of the pattern's prefix, can then make scanning much slower.
The same goes for a structured pattern whose `parse()` reads the whole body.

The scanner remembers what it learns from a pattern the first time it uses it.
Once a pattern has been used, don't change it or its alphabet.
Register a new pattern object instead.

A structured pattern's `parse()` can also be called several times on the same body, so it must always return the same answer.

## Wrapped Tokens

Keeping the original token format is useful, but decryption has to find the tokens again.
That can fail, as explained in [Decrypting Recorded Tokens](#decrypting-recorded-tokens).

If you don't need to keep that format, `encryptWrapped()` replaces each token it finds with an `{ENCRYPTED:<payload>}` wrapper.
The wrapper marks where the encrypted value starts and ends.
So `decryptWrapped()` can find it without any of these:

- Saved positions
- Pattern names
- A list of registered patterns

```ts
const enc = new TokenEncryptor(key);

const wrapped = enc.encryptWrapped(
  "Deploy with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij today",
);
// "Deploy with {ENCRYPTED:<48 symbols>} today"

const restored = new TokenEncryptor(key).decryptWrapped(wrapped);
```

The whole token is encrypted, including its prefix and separators, so the wrapper doesn't show which service it belongs to.
The payload inside the braces is eight symbols longer than the token.
With the marker and braces included, the wrapper is exactly 20 characters longer than the token.

Text outside tokens stays unchanged, including Unicode text.
You can decrypt a wrapper with a new `TokenEncryptor`, with different registered patterns, or after moving it to another document.
You just need the same key and tweak.

Token detection works the same way as `encrypt()`, including the `types` filter.
It can still miss tokens or mistake ordinary text for a token.
Wrapping makes detected tokens easier to recover, but it doesn't improve detection.

### Options and limits

`encryptWrapped(text, options?)` accepts:

- `types`
- `tweak`
- `maxTokenLength`

`decryptWrapped(text, options?)` accepts:

- `tweak`
- `maxTokenLength`
- `onInvalid`

There's no `types` option for wrapped decryption because it looks for wrappers, not token patterns.

`maxTokenLength` limits the work needed for a single wrapper.
It defaults to 512 characters and must be a whole number from 2 to 4,096.
With the eight extra symbols, that means a payload can be no longer than 4,104 symbols.

Several built-in patterns, such as OpenAI and Stripe keys, have no maximum length.
If a matched token is longer than the limit, encryption throws an error instead of leaving the token unencrypted.
If you raise the limit for encryption, raise it for decryption too.

On an Apple M5 Max, the first call that encrypts or decrypts wrappers on a `TokenEncryptor` takes about 3.5 ms to set up its key and S-box pool.
After that, each wrapper takes about this long to encrypt or decrypt:

| Token length     | Time per wrapper |
| ---------------- | ---------------- |
| 512 characters   | 1 ms             |
| 2,048 characters | 12 ms            |
| 4,096 characters | 56 ms            |

The limit applies to one wrapper, not a whole document.
So if your service decrypts text from untrusted sources, also limit document size and the number of requests it accepts.

### Handling invalid wrappers

By default, `decryptWrapped()` uses strict mode: you get a string only if every possible wrapper is valid.
Otherwise, it throws an error without returning partial output.

Each `{ENCRYPTED:` marker starts a possible wrapper, called a candidate.
The decoder reads the run of allowed symbols after it.
That run must contain between 10 and `maxTokenLength + 8` symbols and end with `}`.

The decoder checks every candidate's format before decrypting anything.

There are two wrapper errors:

- `WrappedTokenFormatError` means a candidate has an invalid symbol, a missing closing brace, or an invalid payload length.
  A payload that only exceeds the `maxTokenLength` limit gets a separate message, so you can tell a settings mismatch from damaged data.
- `WrappedTokenIntegrityError` means the wrapper's check symbols did not decrypt to zero.
  This usually happens because the key or tweak is wrong, or the payload has changed.

Both errors extend `TokenError`.
Their messages never include tokens, payloads, tweaks, keys, or pattern names.

Want to leave invalid wrappers in the text?
Use `{ onInvalid: "preserve" }`.
The method then returns `{ text, preservedCandidates }` instead of a string.

Valid wrappers are decrypted, while each invalid candidate is left unchanged and counted once.

A candidate ends at the first character outside the wrapper alphabet.
The decoder includes that character in the candidate only if it's `}`.
So a stray or quoted opening marker doesn't hide later wrappers.

```ts
const result = enc.decryptWrapped(`say "{ENCRYPTED:" then ${wrapped}`, {
  onInvalid: "preserve",
});
// result.text: 'say "{ENCRYPTED:" then Deploy with ghp_... today'
// result.preservedCandidates: 1
```

Nested wrappers are checked separately.
For example, in `{ENCRYPTED:{ENCRYPTED:...}}`, preserve mode keeps the outer opening marker.
It decrypts the inner wrapper only if that wrapper passes its own check.
Recovered tokens are never scanned again.

Preserve mode doesn't ignore every error.
It still throws for invalid options, a destroyed `TokenEncryptor`, and other errors unrelated to wrapper validation.

In TypeScript, the return type is `string` in the default mode and `WrappedDecryptResult` for `onInvalid: "preserve"`.
If you only know the mode at run time, the return type allows either result.

### Working with stored or incoming text

Encrypt only newly received, unencrypted text, then store the wrapped result.
`encryptWrapped()` rejects any text that already contains `{ENCRYPTED:`, even if it isn't a valid wrapper.
It can't tell a marker that's just part of the text from one meant for decryption.

So if you run it again on a history that contains wrappers, it throws an error rather than nesting or skipping them.

Use strict decryption to check stored text or whenever you need to know that all wrappers passed validation.

Preserve mode is useful for displaying incomplete text from a stream or pasted text.
The `preservedCandidates` count tells you how many candidates couldn't be recovered, but not where they are.
Just keep in mind that a successful preserve-mode result can mix recovered tokens with text that was never checked.

### Integrity and privacy limits

Eight zero symbols are added to each token before encryption.
After decryption, those symbols are checked before any unencrypted token is returned.

The strength of this check depends on FAST behaving like a strong, random-looking, reversible mapping of the whole input for each tweak.
The cryptographic term is a strong tweakable pseudorandom permutation.
Under that assumption, a forged or damaged wrapper passes the check with a probability of about 67^-8, or 2.5e-15, per attempt.
That is roughly 48.5 bits of protection, and the chance of a successful forgery grows with more attempts.

This isn't standard authenticated encryption, and it doesn't provide 128-bit protection against forgery.

The same token always produces the same wrapper when the key and tweak are the same.
The wrapper also reveals the token's length.
The check symbols don't add randomness, so anyone who can encrypt can try all possible values of a short custom token and compare the results.

A valid wrapper can be reused, moved, or replaced with another valid wrapper under the same key and tweak.
Removing a whole wrapper also goes undetected.

The wrapper checks don't protect:

- The surrounding text
- The order of wrappers
- Whether parts of a document are missing

If you need those guarantees, also protect the whole document with authenticated encryption or another form of authentication.

Use a different tweak for each customer or conversation to keep wrappers from being reused across them.
Keep the tweak yourself, because it isn't stored in the wrapper.
Leaving out the tweak is the same as using an empty one.

### Wrapped format, version 1

Here's the exact format if you want another implementation to read and write the same wrappers.

The shared test cases in [`test/fixtures/wrapped-tokens-v1.json`](test/fixtures/wrapped-tokens-v1.json) include expected keys, tweaks, settings, and payloads.
They also cover invalid wrappers and whole documents.
Check them before you rely on another implementation to produce the same results.

The alphabet has 67 symbols, in this order:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/-_.
```

A wrapper consists of `{ENCRYPTED:`, the payload, and `}`.
There is no padding, whitespace, escaping, or separator.

To encrypt a token of length `L`:

1. Replace each character with its position in the alphabet, starting at zero.
2. Add eight zeros to the end.
3. Encrypt the resulting input of length `n = L + 8` with radix-67 FAST.
4. Write the encrypted values using the same alphabet to form the payload.

For decryption, process the whole payload and check that the last eight decrypted values are zero.
Only remove those values after the check passes.

Use the package's existing AES-CMAC key derivation and `encodeParts` format to build the wrapper key and tweak.
The master key is 16 bytes:

```text
wrapperKey   = deriveKey(masterKey, encodeParts(["fast-cipher/tokens/wrapped/v1/key"]), 16)
wrapperTweak = encodeParts(["fast-cipher/tokens/wrapped/v1/tweak", callerTweak or empty])
```

`encodeParts` first writes the number of parts as a four-byte big-endian integer, with the most significant byte first.
For each part, it then writes the length in the same format, followed by the part's bytes.

`deriveKey` joins the AES-CMAC outputs for `counter_be32 || input`, starting with counter zero.
FAST then builds its S-box pool and sequence from `wrapperKey` exactly as `FastCipher` does.

Version 1 always uses the same settings, even if `calculateRecommendedParams()` changes later:

- Radix: 67
- S-box count: 256
- Security level: 128 bits

The round counts come from these two rows of the FAST round table:

| Word length | 2   | 3   | 4   | 5   | 6   | 7   | 8   | 9   | 10  | 12  | 16  | 32  | 50  | 64  | 100 |
| ----------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Radix 16    | 67  | 55  | 48  | 43  | 39  | 36  | 35  | 34  | 34  | 33  | 33  | 35  | 38  | 41  | 47  |
| Radix 100   | 40  | 33  | 28  | 27  | 26  | 26  | 25  | 25  | 25  | 26  | 26  | 30  | 34  | 37  | 44  |

For each row, use the two table entries around the input length `n`.
Call their word lengths `x0` and `x1`, and their round counts `y0` and `y1`.
Calculate the value between them with `y0 + ((n - x0) / (x1 - x0)) * (y1 - y0)`.

For input lengths of 100 or more, use the last entry multiplied by `sqrt(n / 100)` instead.
Call the results `r16` and `r100`, then use double-precision arithmetic for these calculations:

```text
f           = (ln(67) - ln(16)) / (ln(100) - ln(16))
rawRounds   = r16 + f * (r100 - r16)
numLayers   = ceil(max(1, rawRounds)) * n
branchDist1 = n <= 2 ? 0 : min(ceil(sqrt(n)), n - 2)
branchDist2 = min(branchDist1 > 1 ? branchDist1 - 1 : 1, n - branchDist1 - 1)
```

For every supported input length, from 10 to 4,104, the raw round count is at least 2e-4 away from a whole number.
Small floating-point differences between platforms therefore cannot change `numLayers`.

A decoder looks for each exact `{ENCRYPTED:` opening marker and reads all consecutive alphabet symbols after it.
The candidate has a valid format only if those symbols are followed by `}` and there are between 10 and `maxTokenLength + 8` of them.

If the run ends with `}`, the next search starts after that brace.
Otherwise, it starts at the character that ended the run.
Any future format that is not compatible with version 1 must use a different opening marker.

## References

- [FAST Paper](https://eprint.iacr.org/2021/1171.pdf)
- [The Next Generation of Performant Data Protection: a New FPE Algorithm](https://insights.comforte.com/the-next-generation-of-performant-data-protection-a-new-fpe-algorithm)
- [Format-Preserving Encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption)
