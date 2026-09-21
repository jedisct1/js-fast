// src/core.ts
function modAdd(a, b, radix) {
  if (radix === 256)
    return a + b & 255;
  return (a + b) % radix;
}
function modSub(a, b, radix) {
  if (radix === 256)
    return a - b & 255;
  return (a + radix - b % radix) % radix;
}
function esLayer(params, pool, data, sboxIndex) {
  const { branchDist1, branchDist2, wordLength, radix } = params;
  const perm = pool.sboxes[sboxIndex].perm;
  const sum = perm[modAdd(data[0], data[wordLength - branchDist2], radix)];
  const next = branchDist1 > 0 ? perm[modSub(sum, data[branchDist1], radix)] : perm[sum];
  data.copyWithin(0, 1, wordLength);
  data[wordLength - 1] = next;
}
function dsLayer(params, pool, data, sboxIndex) {
  const { branchDist1, branchDist2, wordLength, radix } = params;
  const inv = pool.sboxes[sboxIndex].inv;
  const last = inv[data[wordLength - 1]];
  const intermediate = branchDist1 > 0 ? inv[modAdd(last, data[branchDist1 - 1], radix)] : inv[last];
  const next = modSub(intermediate, data[wordLength - branchDist2 - 1], radix);
  data.copyWithin(1, 0, wordLength - 1);
  data[0] = next;
}
function resolveSBoxIndex(seq, layer, sboxCount) {
  return seq.length > 0 ? seq[layer] : layer % sboxCount;
}
function cenc(params, pool, seq, input, output) {
  output.set(input);
  for (let layer = 0;layer < params.numLayers; layer++) {
    esLayer(params, pool, output, resolveSBoxIndex(seq, layer, params.sboxCount));
  }
}
function cdec(params, pool, seq, input, output) {
  output.set(input);
  for (let layer = params.numLayers - 1;layer >= 0; layer--) {
    dsLayer(params, pool, output, resolveSBoxIndex(seq, layer, params.sboxCount));
  }
}

// src/encoding.ts
var encoder = new TextEncoder;
var LABEL_INSTANCE1 = encoder.encode("instance1");
var LABEL_INSTANCE2 = encoder.encode("instance2");
var LABEL_FPE_POOL = encoder.encode("FPE Pool");
var LABEL_FPE_SEQ = encoder.encode("FPE SEQ");
var LABEL_TWEAK = encoder.encode("tweak");
function writeU32Be(value) {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}
function encodeParts(parts) {
  const totalLength = parts.reduce((total, part) => total + 4 + part.length, 4);
  const encoded = new Uint8Array(totalLength);
  const view = new DataView(encoded.buffer);
  let offset = 0;
  view.setUint32(offset, parts.length, false);
  offset += 4;
  for (const part of parts) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    encoded.set(part, offset);
    offset += part.length;
  }
  return encoded;
}
function buildSetup1Input(params) {
  return encodeParts([
    LABEL_INSTANCE1,
    writeU32Be(params.radix),
    writeU32Be(params.sboxCount),
    LABEL_FPE_POOL
  ]);
}
function buildSetup2Input(params, tweak) {
  return encodeParts([
    LABEL_INSTANCE1,
    writeU32Be(params.radix),
    writeU32Be(params.sboxCount),
    LABEL_INSTANCE2,
    writeU32Be(params.wordLength),
    writeU32Be(params.numLayers),
    writeU32Be(params.branchDist1),
    writeU32Be(params.branchDist2),
    LABEL_FPE_SEQ,
    LABEL_TWEAK,
    tweak
  ]);
}

// src/errors.ts
class FastError extends Error {
}

class InvalidRadixError extends FastError {
  name = "InvalidRadixError";
  constructor() {
    super("Radix must be between 4 and 256");
  }
}

class InvalidWordLengthError extends FastError {
  name = "InvalidWordLengthError";
  constructor(message = "Word length must be >= 2") {
    super(message);
  }
}

class InvalidSBoxCountError extends FastError {
  name = "InvalidSBoxCountError";
  constructor() {
    super("S-box count must be > 0");
  }
}

class InvalidBranchDistError extends FastError {
  name = "InvalidBranchDistError";
}

class InvalidLengthError extends FastError {
  name = "InvalidLengthError";
  constructor() {
    super("Input length does not match word length");
  }
}

class InvalidValueError extends FastError {
  name = "InvalidValueError";
  constructor() {
    super("Input value exceeds radix");
  }
}

class InvalidParametersError extends FastError {
  name = "InvalidParametersError";
  constructor(message = "Invalid parameters") {
    super(message);
  }
}

// src/prf.ts
import { createCipheriv } from "node:crypto";
var AES_BLOCK_SIZE = 16;
var AES_KEY_SIZE = 16;
var CMAC_RB = 135;
function aesEncryptBlock(key, block) {
  const cipher = createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  const encrypted = cipher.update(block);
  cipher.final();
  return new Uint8Array(encrypted);
}
function generateCmacSubkeys(key) {
  const block = aesEncryptBlock(key, new Uint8Array(AES_BLOCK_SIZE));
  const k1 = leftShiftAndXor(block, CMAC_RB);
  const k2 = leftShiftAndXor(k1, CMAC_RB);
  return { k1, k2 };
}
function leftShiftAndXor(input, xorByte) {
  const output = new Uint8Array(AES_BLOCK_SIZE);
  let carry = 0;
  for (let i = AES_BLOCK_SIZE - 1;i >= 0; i--) {
    const b = input[i];
    output[i] = (b << 1 | carry) & 255;
    carry = b >> 7 & 1;
  }
  if (input[0] >> 7 & 1) {
    output[AES_BLOCK_SIZE - 1] ^= xorByte;
  }
  return output;
}
function aesCmac(key, message) {
  const { k1, k2 } = generateCmacSubkeys(key);
  const blockCount = message.length === 0 ? 1 : Math.ceil(message.length / AES_BLOCK_SIZE);
  const lastBlockOffset = (blockCount - 1) * AES_BLOCK_SIZE;
  const hasFullLastBlock = message.length > 0 && message.length % AES_BLOCK_SIZE === 0;
  const lastBlock = new Uint8Array(AES_BLOCK_SIZE);
  if (hasFullLastBlock) {
    for (let i = 0;i < AES_BLOCK_SIZE; i++) {
      lastBlock[i] = message[lastBlockOffset + i] ^ k1[i];
    }
  } else {
    const remaining = message.length - lastBlockOffset;
    lastBlock.set(message.subarray(lastBlockOffset));
    lastBlock[remaining] = 128;
    for (let i = 0;i < AES_BLOCK_SIZE; i++) {
      lastBlock[i] ^= k2[i];
    }
  }
  const state = new Uint8Array(AES_BLOCK_SIZE);
  for (let blockIndex = 0;blockIndex < blockCount - 1; blockIndex++) {
    const blockOffset = blockIndex * AES_BLOCK_SIZE;
    for (let i = 0;i < AES_BLOCK_SIZE; i++) {
      state[i] ^= message[blockOffset + i];
    }
    state.set(aesEncryptBlock(key, state));
  }
  for (let i = 0;i < AES_BLOCK_SIZE; i++) {
    state[i] ^= lastBlock[i];
  }
  return aesEncryptBlock(key, state);
}
function deriveKey(masterKey, input, outputLength) {
  if (masterKey.length !== AES_KEY_SIZE) {
    throw new Error("Master key must be 16 bytes");
  }
  if (outputLength === 0) {
    throw new Error("Output length must be > 0");
  }
  const output = new Uint8Array(outputLength);
  const buffer = new Uint8Array(4 + input.length);
  const bufferView = new DataView(buffer.buffer);
  buffer.set(input, 4);
  let bytesGenerated = 0;
  let counter = 0;
  while (bytesGenerated < outputLength) {
    bufferView.setUint32(0, counter, false);
    const cmacOutput = aesCmac(masterKey, buffer);
    const toCopy = Math.min(outputLength - bytesGenerated, AES_BLOCK_SIZE);
    output.set(cmacOutput.subarray(0, toCopy), bytesGenerated);
    bytesGenerated += toCopy;
    counter++;
  }
  return output;
}

// src/prng.ts
import { createCipheriv as createCipheriv2 } from "node:crypto";
var AES_BLOCK_SIZE2 = 16;
var AES_KEY_SIZE2 = 16;

class PrngState {
  key;
  counter;
  buffer = new Uint8Array(AES_BLOCK_SIZE2);
  bufferPos = AES_BLOCK_SIZE2;
  constructor(key, nonce) {
    this.key = new Uint8Array(key);
    this.counter = new Uint8Array(nonce);
  }
  incrementCounter() {
    for (let i = AES_BLOCK_SIZE2 - 1;i >= 0; i--) {
      this.counter[i] = this.counter[i] + 1 & 255;
      if (this.counter[i] !== 0)
        break;
    }
  }
  encryptBlock() {
    const cipher = createCipheriv2("aes-128-ecb", this.key, null);
    cipher.setAutoPadding(false);
    const encrypted = cipher.update(this.counter);
    cipher.final();
    this.buffer.set(new Uint8Array(encrypted));
  }
  getBytes(output) {
    for (let offset = 0;offset < output.length; ) {
      if (this.bufferPos === AES_BLOCK_SIZE2) {
        this.incrementCounter();
        this.encryptBlock();
        this.bufferPos = 0;
      }
      const chunkLength = Math.min(output.length - offset, AES_BLOCK_SIZE2 - this.bufferPos);
      output.set(this.buffer.subarray(this.bufferPos, this.bufferPos + chunkLength), offset);
      this.bufferPos += chunkLength;
      offset += chunkLength;
    }
  }
  nextU32() {
    const bytes = new Uint8Array(4);
    this.getBytes(bytes);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  }
  uniform(bound) {
    if (bound <= 1)
      return 0;
    const bound64 = BigInt(bound);
    const threshold = Number((0x100000000n - bound64) % bound64);
    for (;; ) {
      const r = this.nextU32();
      const product = BigInt(r) * bound64;
      const low = Number(product & 0xffffffffn);
      if (low >= threshold) {
        return Number(product >> 32n);
      }
    }
  }
  cleanup() {
    this.counter.fill(0);
    this.buffer.fill(0);
    this.key.fill(0);
    this.bufferPos = 0;
  }
}
function splitKeyMaterial(keyMaterial, zeroizeIvSuffix) {
  const key = keyMaterial.slice(0, AES_KEY_SIZE2);
  const iv = keyMaterial.slice(AES_KEY_SIZE2, AES_KEY_SIZE2 + AES_BLOCK_SIZE2);
  if (zeroizeIvSuffix) {
    iv[AES_BLOCK_SIZE2 - 1] = 0;
    iv[AES_BLOCK_SIZE2 - 2] = 0;
  }
  return { key, iv };
}
function generateSequence(numLayers, poolSize, keyMaterial) {
  const { key, iv } = splitKeyMaterial(keyMaterial, true);
  const prng = new PrngState(key, iv);
  const seq = new Uint32Array(numLayers);
  for (let i = 0;i < numLayers; i++) {
    seq[i] = prng.uniform(poolSize);
  }
  prng.cleanup();
  key.fill(0);
  iv.fill(0);
  return seq;
}

// src/sbox.ts
function generateSBox(radix, prng) {
  const perm = new Uint8Array(radix);
  const inv = new Uint8Array(radix);
  for (let i = 0;i < radix; i++) {
    perm[i] = i;
  }
  for (let i = radix - 1;i > 0; i--) {
    const j = prng.uniform(i + 1);
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  for (let i = 0;i < radix; i++) {
    inv[perm[i]] = i;
  }
  return { perm, inv };
}
function generateSBoxPool(radix, count, keyMaterial) {
  const { key, iv } = splitKeyMaterial(keyMaterial, false);
  const prng = new PrngState(key, iv);
  const sboxes = [];
  for (let i = 0;i < count; i++) {
    sboxes.push(generateSBox(radix, prng));
  }
  prng.cleanup();
  key.fill(0);
  iv.fill(0);
  return { sboxes, radix };
}

// src/cipher.ts
var AES_KEY_SIZE3 = 16;
var DERIVED_KEY_SIZE = 32;

class FastCipher {
  params;
  masterKey;
  sboxPool;
  destroyed = false;
  cachedTweak = null;
  cachedSeq = null;
  constructor(params, masterKey, sboxPool) {
    this.params = params;
    this.masterKey = new Uint8Array(masterKey);
    this.sboxPool = sboxPool;
  }
  static create(params, key) {
    FastCipher.validateParams(params, key);
    const poolKeyMaterial = deriveKey(key, buildSetup1Input(params), DERIVED_KEY_SIZE);
    const sboxPool = generateSBoxPool(params.radix, params.sboxCount, poolKeyMaterial);
    poolKeyMaterial.fill(0);
    return new FastCipher(params, key, sboxPool);
  }
  static validateParams(params, key) {
    if (params.radix < 4 || params.radix > 256) {
      throw new InvalidRadixError;
    }
    if (params.wordLength < 2 || params.numLayers === 0 || params.numLayers % params.wordLength !== 0) {
      throw new InvalidWordLengthError("Word length must be >= 2 and numLayers must be a positive multiple of wordLength");
    }
    if (params.sboxCount === 0) {
      throw new InvalidSBoxCountError;
    }
    if (params.branchDist1 > params.wordLength - 2) {
      throw new InvalidBranchDistError("branchDist1 must be <= wordLength - 2");
    }
    if (params.branchDist2 === 0 || params.branchDist2 > params.wordLength - 1 || params.branchDist2 > params.wordLength - params.branchDist1 - 1) {
      throw new InvalidBranchDistError("branchDist2 is out of valid range");
    }
    if (key.length !== AES_KEY_SIZE3) {
      throw new Error("Key must be 16 bytes");
    }
  }
  hasCachedSequenceFor(tweak) {
    if (this.cachedSeq === null) {
      return false;
    }
    if (tweak.length === 0) {
      return this.cachedTweak === null;
    }
    const cachedTweak = this.cachedTweak;
    if (cachedTweak === null || tweak.length !== cachedTweak.length) {
      return false;
    }
    return tweak.every((value, index) => value === cachedTweak[index]);
  }
  ensureSequence(tweak) {
    if (this.hasCachedSequenceFor(tweak)) {
      return this.cachedSeq;
    }
    const seqKeyMaterial = deriveKey(this.masterKey, buildSetup2Input(this.params, tweak), DERIVED_KEY_SIZE);
    const seq = generateSequence(this.params.numLayers, this.params.sboxCount, seqKeyMaterial);
    seqKeyMaterial.fill(0);
    this.cachedTweak = tweak.length === 0 ? null : new Uint8Array(tweak);
    this.cachedSeq = seq;
    return seq;
  }
  validateInput(data) {
    if (data.length !== this.params.wordLength) {
      throw new InvalidLengthError;
    }
    for (const value of data) {
      if (value >= this.params.radix) {
        throw new InvalidValueError;
      }
    }
  }
  assertNotDestroyed() {
    if (this.destroyed) {
      throw new Error("Cipher has been destroyed");
    }
  }
  encrypt(plaintext, tweak = new Uint8Array(0)) {
    this.assertNotDestroyed();
    this.validateInput(plaintext);
    const seq = this.ensureSequence(tweak);
    const ciphertext = new Uint8Array(this.params.wordLength);
    cenc(this.params, this.sboxPool, seq, plaintext, ciphertext);
    return ciphertext;
  }
  decrypt(ciphertext, tweak = new Uint8Array(0)) {
    this.assertNotDestroyed();
    this.validateInput(ciphertext);
    const seq = this.ensureSequence(tweak);
    const plaintext = new Uint8Array(this.params.wordLength);
    cdec(this.params, this.sboxPool, seq, ciphertext, plaintext);
    return plaintext;
  }
  destroy() {
    if (this.destroyed)
      return;
    this.masterKey.fill(0);
    this.cachedSeq?.fill(0);
    this.cachedSeq = null;
    this.cachedTweak?.fill(0);
    this.cachedTweak = null;
    for (const sbox of this.sboxPool.sboxes) {
      sbox.perm.fill(0);
      sbox.inv.fill(0);
    }
    this.destroyed = true;
  }
}

// src/params.ts
var SBOX_POOL_SIZE = 256;
var ROUND_L_VALUES = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100];
var ROUND_RADICES = [
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  100,
  128,
  256,
  1000,
  1024,
  1e4,
  65536
];
var ROUND_TABLE = [
  [165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57],
  [131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53],
  [113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52],
  [102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50],
  [94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50],
  [88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49],
  [83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49],
  [79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48],
  [76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48],
  [73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48],
  [71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47],
  [69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47],
  [67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47],
  [40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44],
  [38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44],
  [33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44],
  [32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43],
  [32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43],
  [32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42],
  [32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42]
];
function interpolate(x, x0, x1, y0, y1) {
  if (x1 === x0) {
    return y0;
  }
  const ratio = (x - x0) / (x1 - x0);
  if (ratio <= 0) {
    return y0;
  }
  if (ratio >= 1) {
    return y1;
  }
  return y0 + ratio * (y1 - y0);
}
function roundsForRow(rowIndex, ell) {
  const row = ROUND_TABLE[rowIndex];
  const lastIndex = ROUND_L_VALUES.length - 1;
  const maxWordLength = ROUND_L_VALUES[lastIndex];
  if (ell <= ROUND_L_VALUES[0]) {
    return row[0];
  }
  if (ell >= maxWordLength) {
    const baseRounds = row[lastIndex];
    return Math.max(baseRounds, baseRounds * Math.sqrt(ell / maxWordLength));
  }
  for (let i = 1;i <= lastIndex; i++) {
    const lowerLength = ROUND_L_VALUES[i - 1];
    const upperLength = ROUND_L_VALUES[i];
    if (ell <= upperLength) {
      return interpolate(ell, lowerLength, upperLength, row[i - 1], row[i]);
    }
  }
  return row[lastIndex];
}
function lookupRecommendedRounds(radix, ell) {
  const lastIndex = ROUND_RADICES.length - 1;
  if (radix <= ROUND_RADICES[0]) {
    return roundsForRow(0, ell);
  }
  if (radix >= ROUND_RADICES[lastIndex]) {
    return roundsForRow(lastIndex, ell);
  }
  const logRadix = Math.log(radix);
  for (let i = 1;i <= lastIndex; i++) {
    const lowerRadix = ROUND_RADICES[i - 1];
    const upperRadix = ROUND_RADICES[i];
    if (radix <= upperRadix) {
      return interpolate(logRadix, Math.log(lowerRadix), Math.log(upperRadix), roundsForRow(i - 1, ell), roundsForRow(i, ell));
    }
  }
  return roundsForRow(lastIndex, ell);
}
function calculateRecommendedParams(radix, wordLength, securityLevel = 128) {
  if (radix < 4 || wordLength < 2) {
    throw new InvalidParametersError;
  }
  const secLevel = securityLevel === 0 ? 128 : securityLevel;
  const wCandidate = Math.ceil(Math.sqrt(wordLength));
  const branchDist1 = wordLength <= 2 ? 0 : Math.min(wCandidate, wordLength - 2);
  const branchDist2 = Math.min(branchDist1 > 1 ? branchDist1 - 1 : 1, wordLength - branchDist1 - 1);
  let rounds = lookupRecommendedRounds(radix, wordLength);
  if (rounds < 1)
    rounds = 1;
  const roundsU = Math.ceil(rounds);
  const numLayers = roundsU * wordLength;
  return {
    radix,
    wordLength,
    sboxCount: SBOX_POOL_SIZE,
    numLayers,
    branchDist1,
    branchDist2,
    securityLevel: secLevel
  };
}

// src/tokens/alphabets.ts
function makeAlphabet(name, chars) {
  const charToIndex = new Map;
  for (let i = 0;i < chars.length; i++) {
    charToIndex.set(chars[i], i);
  }
  return { name, chars, radix: chars.length, charToIndex };
}
var DIGITS = makeAlphabet("digits", "0123456789");
var HEX_LOWER = makeAlphabet("hex-lower", "0123456789abcdef");
var ALPHANUMERIC_UPPER = makeAlphabet("alphanumeric-upper", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
var ALPHANUMERIC_LOWER = makeAlphabet("alphanumeric-lower", "0123456789abcdefghijklmnopqrstuvwxyz");
var ALPHANUMERIC = makeAlphabet("alphanumeric", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
var BASE64 = makeAlphabet("base64", "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
var BASE64URL = makeAlphabet("base64url", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-");

// src/tokens/errors.ts
class TokenError extends Error {
}

class UnknownPatternError extends TokenError {
  name = "UnknownPatternError";
  constructor() {
    super("Unknown token pattern");
  }
}

class TokenFormatError extends TokenError {
  name = "TokenFormatError";
  constructor(patternName) {
    super(`Malformed ${patternName} token`);
  }
}

class CycleWalkError extends TokenError {
  name = "CycleWalkError";
  constructor() {
    super("Cycle walk did not converge");
  }
}

// src/tokens/cyclewalk.ts
var MAX_CYCLE_STEPS = 32;
function cycleWalk(input, step, inClass, maxSteps = MAX_CYCLE_STEPS) {
  let value = input;
  for (let steps = 1;steps <= maxSteps; steps++) {
    value = step(value);
    if (inClass(value))
      return { output: value, steps };
  }
  throw new CycleWalkError;
}

// src/tokens/registry.ts
var MIN_SEGMENT_LENGTH = 4;
function simple(name, prefix, bodyRegex, bodyAlphabet, minBodyLength) {
  return {
    kind: "simple",
    name,
    prefix,
    bodyRegex,
    bodyAlphabet,
    minBodyLength
  };
}
function makeSlackPattern(prefix, name, allowUserId = false) {
  const bodyRegex = allowUserId ? /\d+-\d+-(?:\d+-)?[A-Za-z0-9]+/ : /\d+-\d+-[A-Za-z0-9]+/;
  const bodyValidator = new RegExp(`^(?:${bodyRegex.source})$`);
  return {
    kind: "structured",
    name,
    prefix,
    trailingAlphabet: ALPHANUMERIC,
    fullRegex: `${escapeRegex(prefix)}${bodyRegex.source}`,
    parse(body) {
      if (!bodyValidator.test(body))
        return null;
      const parts = body.split("-");
      let totalLen = 0;
      for (const p of parts)
        totalLen += p.length;
      if (totalLen < 20)
        return null;
      const alphabets = [];
      for (const part of parts) {
        if (/^\d+$/.test(part)) {
          alphabets.push(DIGITS);
        } else if (/^[A-Za-z0-9]+$/.test(part)) {
          alphabets.push(ALPHANUMERIC);
        } else {
          return null;
        }
      }
      return { segments: parts, alphabets };
    },
    format(segments) {
      return segments.join("-");
    }
  };
}
function heuristic(name, bodyAlphabet, minLength, maxLength, minEntropy, minCharClasses) {
  return {
    kind: "heuristic",
    name,
    prefix: "",
    bodyAlphabet,
    minLength,
    maxLength,
    minEntropy,
    minCharClasses
  };
}
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var sendgridPattern = {
  kind: "structured",
  name: "sendgrid",
  prefix: "SG.",
  trailingAlphabet: BASE64URL,
  fullRegex: `SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}`,
  parse(body) {
    const dotIdx = body.indexOf(".");
    if (dotIdx === -1)
      return null;
    const seg1 = body.slice(0, dotIdx);
    const seg2 = body.slice(dotIdx + 1);
    if (seg1.length !== 22 || seg2.length !== 43)
      return null;
    return {
      segments: [seg1, seg2],
      alphabets: [BASE64URL, BASE64URL]
    };
  },
  format(segments) {
    return `${segments[0]}.${segments[1]}`;
  }
};
var BUILTIN_PATTERNS = [
  simple("anthropic", "sk-ant-api03-", "[A-Za-z0-9_-]{80,}", BASE64URL, 80),
  simple("openai", "sk-proj-", "[A-Za-z0-9_-]{48,}", BASE64URL, 48),
  simple("openai-legacy", "sk-", "[A-Za-z0-9]{48}", ALPHANUMERIC, 48),
  simple("stripe-secret-live", "sk_live_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
  simple("stripe-publish-live", "pk_live_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
  simple("stripe-secret-test", "sk_test_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
  simple("stripe-publish-test", "pk_test_", "[A-Za-z0-9]{24,}", ALPHANUMERIC, 24),
  simple("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", BASE64URL, 20),
  simple("gitlab", "glpat-", "[A-Za-z0-9_-]{20}", BASE64URL, 20),
  simple("datadog", "ddapi_", "[a-z0-9]{40}", ALPHANUMERIC_LOWER, 40),
  simple("pypi", "pypi-", "[A-Za-z0-9_-]{50,}", BASE64URL, 50),
  makeSlackPattern("xoxb-", "slack-bot"),
  makeSlackPattern("xoxp-", "slack-user", true),
  simple("github-pat", "ghp_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("github-oauth", "gho_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("github-user", "ghu_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("github-server", "ghs_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("github-refresh", "ghr_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("aws-access-key", "AKIA", "[A-Z0-9]{16}", ALPHANUMERIC_UPPER, 16),
  simple("google-api", "AIza", "[A-Za-z0-9_-]{35}", BASE64URL, 35),
  simple("npm", "npm_", "[A-Za-z0-9]{36}", ALPHANUMERIC, 36),
  simple("supabase", "sbp_", "[a-f0-9]{40}", HEX_LOWER, 40),
  simple("grafana", "glc_", "[A-Za-z0-9_-]{30,}", BASE64URL, 30),
  simple("huggingface", "hf_", "[A-Za-z0-9]{34}", ALPHANUMERIC, 34),
  sendgridPattern,
  simple("twilio", "SK", "[a-f0-9]{32}", HEX_LOWER, 32),
  heuristic("fastly", BASE64URL, 32, 32, 4, 3),
  heuristic("aws-secret-key", BASE64, 40, 40, 4, 3)
];

// src/tokens/validate.ts
var bodyValidatorCache = new WeakMap;
function getBodyValidator(pattern) {
  let re = bodyValidatorCache.get(pattern);
  if (!re) {
    re = new RegExp(`^(?:${pattern.bodyRegex})$`);
    bodyValidatorCache.set(pattern, re);
  }
  return re;
}
var fullValidatorCache = new WeakMap;
function getFullValidator(pattern) {
  let re = fullValidatorCache.get(pattern);
  if (!re) {
    re = new RegExp(`^(?:${pattern.fullRegex})$`);
    fullValidatorCache.set(pattern, re);
  }
  return re;
}
function heuristicMarker(patternName) {
  return `[ENCRYPTED:${patternName}]`;
}
function isInAlphabet(s, alphabet) {
  for (let i = 0;i < s.length; i++) {
    if (!alphabet.charToIndex.has(s[i]))
      return false;
  }
  return true;
}
function sameAlphabet(a, b) {
  return a === b || a?.chars === b.chars;
}
function tokenBody(pattern, token, form) {
  const lead = pattern.kind === "heuristic" && form === "encrypted" ? heuristicMarker(pattern.name) : pattern.prefix;
  if (!token.startsWith(lead))
    throw new TokenFormatError(pattern.name);
  const body = token.slice(lead.length);
  let valid;
  if (pattern.kind === "simple") {
    valid = body.length >= pattern.minBodyLength && isInAlphabet(body, pattern.bodyAlphabet) && getBodyValidator(pattern).test(body);
  } else if (pattern.kind === "heuristic") {
    valid = body.length >= pattern.minLength && body.length <= pattern.maxLength && isInAlphabet(body, pattern.bodyAlphabet);
  } else {
    valid = getFullValidator(pattern).test(token);
  }
  if (!valid)
    throw new TokenFormatError(pattern.name);
  return body;
}
function readsBack(pattern, body, expected) {
  const reparsed = pattern.parse(body);
  if (!reparsed || reparsed.segments.length !== expected.segments.length) {
    return false;
  }
  for (let i = 0;i < expected.segments.length; i++) {
    if (reparsed.segments[i] !== expected.segments[i] || !sameAlphabet(reparsed.alphabets[i], expected.alphabets[i])) {
      return false;
    }
  }
  return true;
}
function parseStructured(pattern, body) {
  const parsed = pattern.parse(body);
  if (!parsed || parsed.alphabets.length !== parsed.segments.length || !readsBack(pattern, pattern.format(parsed.segments), parsed)) {
    throw new TokenFormatError(pattern.name);
  }
  for (let i = 0;i < parsed.segments.length; i++) {
    const segment = parsed.segments[i];
    if (segment.length >= MIN_SEGMENT_LENGTH && !isInAlphabet(segment, parsed.alphabets[i])) {
      throw new TokenFormatError(pattern.name);
    }
  }
  return parsed;
}
function formatStructured(pattern, segments, alphabets) {
  const body = pattern.format(segments);
  if (!readsBack(pattern, body, { segments, alphabets })) {
    throw new TokenFormatError(pattern.name);
  }
  return body;
}
function segmentClass(pattern, parsed, index) {
  const probe = [...parsed.segments];
  const alphabet = parsed.alphabets[index];
  return (candidate) => {
    probe[index] = candidate;
    const reparsed = pattern.parse(pattern.format(probe));
    return reparsed !== null && reparsed.segments.length === probe.length && reparsed.segments[index] === candidate && sameAlphabet(reparsed.alphabets[index], alphabet);
  };
}

// src/tokens/scanner.ts
function findAllPositions(text, needle) {
  const positions = [];
  let idx = 0;
  while (idx <= text.length - needle.length) {
    const pos = text.indexOf(needle, idx);
    if (pos === -1)
      break;
    positions.push(pos);
    idx = pos + 1;
  }
  return positions;
}
var stickyRegexCache = new WeakMap;
function getStickyRegex(pattern) {
  let re = stickyRegexCache.get(pattern);
  if (!re) {
    re = new RegExp(pattern.fullRegex, "y");
    stickyRegexCache.set(pattern, re);
  }
  return re;
}
function wouldMatchAt(text, pos, prefixPositions, allPatterns) {
  for (const pattern of allPatterns) {
    if (pattern.kind === "heuristic")
      continue;
    if (!text.startsWith(pattern.prefix, pos))
      continue;
    if (pattern.kind === "simple") {
      if (wouldMatchSimpleAt(text, pos, pattern, prefixPositions, allPatterns)) {
        return true;
      }
    } else {
      if (wouldMatchStructuredAt(text, pos, pattern, prefixPositions, allPatterns)) {
        return true;
      }
    }
  }
  return false;
}
function wouldMatchSimpleAt(text, pos, pattern, prefixPositions, allPatterns) {
  const bodyStart = pos + pattern.prefix.length;
  let bodyEnd = bodyStart;
  while (bodyEnd < text.length) {
    if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]))
      break;
    bodyEnd++;
  }
  if (bodyEnd - bodyStart < pattern.minBodyLength)
    return false;
  const bodyValidator = getBodyValidator(pattern);
  const validate = (body) => body.length >= pattern.minBodyLength && bodyValidator.test(body);
  const truncEnd = findTruncatedEnd(text, bodyStart, bodyEnd, prefixPositions, allPatterns, validate);
  if (truncEnd !== -1)
    return true;
  return validate(text.slice(bodyStart, bodyEnd));
}
function wouldMatchStructuredAt(text, pos, pattern, prefixPositions, allPatterns) {
  const regex = getStickyRegex(pattern);
  regex.lastIndex = pos;
  const match = regex.exec(text);
  if (!match)
    return false;
  const matchEnd = pos + match[0].length;
  const bodyStart = pos + pattern.prefix.length;
  const truncEnd = findTruncatedEnd(text, bodyStart, matchEnd, prefixPositions, allPatterns, (body2) => pattern.parse(body2) !== null);
  if (truncEnd !== -1)
    return true;
  const body = text.slice(bodyStart, matchEnd);
  if (pattern.parse(body) !== null) {
    if (matchEnd < text.length) {
      const nextCh = text[matchEnd];
      if (pattern.trailingAlphabet.charToIndex.has(nextCh)) {
        if (!prefixPositions.has(matchEnd))
          return false;
      }
    }
    return true;
  }
  return false;
}
function scan(text, patterns, allPatterns) {
  const allPats = allPatterns ?? patterns;
  const uniquePrefixes = new Set(allPats.map((p) => p.prefix).filter((p) => p.length > 0));
  const prefixPositions = new Set;
  for (const pfx of uniquePrefixes) {
    for (const pos of findAllPositions(text, pfx)) {
      prefixPositions.add(pos);
    }
  }
  const candidates = [];
  for (const pattern of patterns) {
    if (pattern.kind === "structured") {
      scanStructured(text, pattern, prefixPositions, allPats, candidates);
    } else if (pattern.kind === "heuristic") {
      scanHeuristic(text, pattern, candidates);
    } else {
      scanSimple(text, pattern, prefixPositions, allPats, candidates);
    }
  }
  candidates.sort((a, b) => {
    if (a.start !== b.start)
      return a.start - b.start;
    if (a.pattern.prefix.length !== b.pattern.prefix.length)
      return b.pattern.prefix.length - a.pattern.prefix.length;
    return b.end - b.start - (a.end - a.start);
  });
  const result = [];
  let lastEnd = 0;
  for (const span of candidates) {
    if (span.start >= lastEnd) {
      result.push(span);
      lastEnd = span.end;
    }
  }
  return result;
}
function findTruncatedEnd(text, bodyStart, bodyEnd, prefixPositions, allPatterns, validateLeft) {
  const prefixesInBody = [];
  for (let i = bodyStart + 1;i < bodyEnd; i++) {
    if (prefixPositions.has(i))
      prefixesInBody.push(i);
  }
  if (prefixesInBody.length === 0)
    return -1;
  for (let j = prefixesInBody.length - 1;j >= 0; j--) {
    const splitPos = prefixesInBody[j];
    const leftBody = text.slice(bodyStart, splitPos);
    if (!validateLeft(leftBody))
      continue;
    if (!wouldMatchAt(text, splitPos, prefixPositions, allPatterns))
      continue;
    return splitPos;
  }
  return -1;
}
function scanSimple(text, pattern, prefixPositions, allPatterns, candidates) {
  const bodyValidator = getBodyValidator(pattern);
  const validate = (body) => body.length >= pattern.minBodyLength && bodyValidator.test(body);
  for (const pos of findAllPositions(text, pattern.prefix)) {
    const bodyStart = pos + pattern.prefix.length;
    let bodyEnd = bodyStart;
    while (bodyEnd < text.length) {
      if (!pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]))
        break;
      bodyEnd++;
    }
    if (bodyEnd - bodyStart < pattern.minBodyLength)
      continue;
    const truncEnd = findTruncatedEnd(text, bodyStart, bodyEnd, prefixPositions, allPatterns, validate);
    let finalEnd;
    if (truncEnd !== -1) {
      finalEnd = truncEnd;
    } else {
      const fullBody = text.slice(bodyStart, bodyEnd);
      if (!validate(fullBody))
        continue;
      finalEnd = bodyEnd;
    }
    candidates.push({
      start: pos,
      end: finalEnd,
      pattern,
      body: text.slice(bodyStart, finalEnd)
    });
  }
}
function shannonEntropy(s) {
  if (s.length === 0)
    return 0;
  const freq = new Map;
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
function countCharClasses(s) {
  let hasUpper = false;
  let hasLower = false;
  let hasDigit = false;
  let hasOther = false;
  for (let i = 0;i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 65 && c <= 90)
      hasUpper = true;
    else if (c >= 97 && c <= 122)
      hasLower = true;
    else if (c >= 48 && c <= 57)
      hasDigit = true;
    else
      hasOther = true;
  }
  return +hasUpper + +hasLower + +hasDigit + +hasOther;
}
var WORD_BOUNDARY_RE = /[^A-Za-z0-9_-]/;
function isWordBoundary(text, pos) {
  if (pos === 0)
    return true;
  return WORD_BOUNDARY_RE.test(text[pos - 1]);
}
function isWordBoundaryEnd(text, pos) {
  if (pos >= text.length)
    return true;
  return WORD_BOUNDARY_RE.test(text[pos]);
}
function scanHeuristic(text, pattern, candidates) {
  const { bodyAlphabet, minLength, maxLength, minEntropy, minCharClasses } = pattern;
  let i = 0;
  while (i < text.length) {
    if (!bodyAlphabet.charToIndex.has(text[i])) {
      i++;
      continue;
    }
    if (!isWordBoundary(text, i)) {
      while (i < text.length && bodyAlphabet.charToIndex.has(text[i]))
        i++;
      continue;
    }
    let end = i;
    while (end < text.length && bodyAlphabet.charToIndex.has(text[end]))
      end++;
    const len = end - i;
    if (len >= minLength && len <= maxLength && isWordBoundaryEnd(text, end)) {
      const body = text.slice(i, end);
      if (countCharClasses(body) >= minCharClasses && shannonEntropy(body) >= minEntropy) {
        candidates.push({
          start: i,
          end,
          pattern,
          body
        });
      }
    }
    i = end;
  }
}
function scanStructured(text, pattern, prefixPositions, allPatterns, candidates) {
  const regex = new RegExp(pattern.fullRegex, "g");
  for (let match = regex.exec(text);match !== null; match = regex.exec(text)) {
    const matchStart = match.index;
    if (match[0].length === 0) {
      regex.lastIndex = matchStart + 1;
      continue;
    }
    const matchEnd = matchStart + match[0].length;
    const bodyStart = matchStart + pattern.prefix.length;
    const truncEnd = findTruncatedEnd(text, bodyStart, matchEnd, prefixPositions, allPatterns, (body2) => pattern.parse(body2) !== null);
    if (truncEnd !== -1) {
      candidates.push({
        start: matchStart,
        end: truncEnd,
        pattern,
        body: text.slice(bodyStart, truncEnd)
      });
      continue;
    }
    const body = text.slice(bodyStart, matchEnd);
    if (pattern.parse(body) === null)
      continue;
    if (matchEnd < text.length) {
      const nextCh = text[matchEnd];
      if (pattern.trailingAlphabet.charToIndex.has(nextCh)) {
        if (!prefixPositions.has(matchEnd))
          continue;
      }
    }
    candidates.push({
      start: matchStart,
      end: matchEnd,
      pattern,
      body
    });
  }
}

// src/tokens/transformer.ts
function charsToIndices(body, alphabet) {
  const indices = new Uint8Array(body.length);
  for (let i = 0;i < body.length; i++) {
    const idx = alphabet.charToIndex.get(body[i]);
    if (idx === undefined) {
      throw new Error(`Character not in alphabet '${alphabet.name}'`);
    }
    indices[i] = idx;
  }
  return indices;
}
function indicesToChars(indices, alphabet) {
  let result = "";
  for (let i = 0;i < indices.length; i++) {
    result += alphabet.chars[indices[i]];
  }
  return result;
}
function transformBody(body, alphabet, cipher, mode, tweak) {
  const indices = charsToIndices(body, alphabet);
  const result = mode === "encrypt" ? cipher.encrypt(indices, tweak) : cipher.decrypt(indices, tweak);
  return indicesToChars(result, alphabet);
}
// src/tokens/index.ts
var AES_KEY_SIZE4 = 16;
var textEncoder = new TextEncoder;

class TokenEncryptor {
  key;
  cache = new Map;
  patterns;
  destroyed = false;
  constructor(key) {
    if (key.length !== AES_KEY_SIZE4) {
      throw new Error("Key must be 16 bytes");
    }
    this.key = new Uint8Array(key);
    this.patterns = [...BUILTIN_PATTERNS];
  }
  assertAlive() {
    if (this.destroyed) {
      throw new Error("TokenEncryptor has been destroyed");
    }
  }
  getCipher(pattern, radix, wordLength) {
    if (!Number.isInteger(radix) || radix < 4 || radix > 256) {
      throw new TokenError(`Unsupported alphabet radix for ${pattern.name} pattern`);
    }
    if (wordLength < 2) {
      throw new TokenFormatError(pattern.name);
    }
    const k = `${radix}:${wordLength}`;
    let cipher = this.cache.get(k);
    if (!cipher) {
      const params = calculateRecommendedParams(radix, wordLength);
      cipher = FastCipher.create(params, this.key);
      this.cache.set(k, cipher);
    }
    return cipher;
  }
  makeTweak(patternName, extra) {
    const nameBytes = textEncoder.encode(patternName);
    if (!extra || extra.length === 0)
      return nameBytes;
    const combined = new Uint8Array(nameBytes.length + 1 + extra.length);
    combined.set(nameBytes, 0);
    combined[nameBytes.length] = 0;
    combined.set(extra, nameBytes.length + 1);
    return combined;
  }
  activePatterns(options) {
    if (!options?.types)
      return this.patterns;
    const allowed = new Set(options.types);
    return this.patterns.filter((p) => allowed.has(p.name));
  }
  encrypt(text, options) {
    return this.encryptWithSpans(text, options).text;
  }
  encryptWithSpans(text, options) {
    this.assertAlive();
    const patterns = this.activePatterns(options);
    const scanned = scan(text, patterns, this.patterns);
    if (scanned.length === 0)
      return { text, spans: [] };
    const parts = [];
    const spans = [];
    let cursor = 0;
    for (const span of scanned) {
      parts.push(text.slice(cursor, span.start));
      const original = text.slice(span.start, span.end);
      const encrypted = this.encryptSpan(span, options?.tweak);
      parts.push(encrypted);
      spans.push({
        start: span.start,
        end: span.end,
        original,
        encrypted,
        patternName: span.pattern.name
      });
      cursor = span.end;
    }
    parts.push(text.slice(cursor));
    return { text: parts.join(""), spans };
  }
  decrypt(text, options) {
    this.assertAlive();
    const patterns = this.activePatterns(options);
    const prefixPatterns = patterns.filter((p) => p.kind !== "heuristic");
    const heuristicPatterns = patterns.filter((p) => p.kind === "heuristic");
    const spans = prefixPatterns.length === 0 ? [] : scan(text, prefixPatterns, this.patterns);
    const heuristicHits = heuristicPatterns.length === 0 ? [] : this.findHeuristicMarkerHits(text, heuristicPatterns);
    if (spans.length === 0 && heuristicHits.length === 0)
      return text;
    const parts = [];
    let cursor = 0;
    let spanIndex = 0;
    let hitIndex = 0;
    while (spanIndex < spans.length || hitIndex < heuristicHits.length) {
      const span = spanIndex < spans.length ? spans[spanIndex] : undefined;
      const hit = hitIndex < heuristicHits.length ? heuristicHits[hitIndex] : undefined;
      if (hit && (!span || hit.start < span.start)) {
        if (hit.start >= cursor) {
          parts.push(text.slice(cursor, hit.start));
          parts.push(this.transform(hit.pattern, hit.body, "decrypt", options?.tweak));
          cursor = hit.end;
        }
        hitIndex++;
        continue;
      }
      const nextSpan = spans[spanIndex];
      if (nextSpan.start >= cursor) {
        parts.push(text.slice(cursor, nextSpan.start));
        parts.push(nextSpan.pattern.prefix + this.transform(nextSpan.pattern, nextSpan.body, "decrypt", options?.tweak));
        cursor = nextSpan.end;
      }
      spanIndex++;
    }
    parts.push(text.slice(cursor));
    return parts.join("");
  }
  encryptToken(plaintext, patternName, options) {
    this.assertAlive();
    const pattern = this.patternByName(patternName);
    const body = tokenBody(pattern, plaintext, "plain");
    return this.encryptedLead(pattern) + this.transform(pattern, body, "encrypt", options?.tweak);
  }
  decryptToken(ciphertext, patternName, options) {
    this.assertAlive();
    const pattern = this.patternByName(patternName);
    const body = tokenBody(pattern, ciphertext, "encrypted");
    return pattern.prefix + this.transform(pattern, body, "decrypt", options?.tweak);
  }
  patternByName(patternName) {
    const pattern = this.patterns.find((p) => p.name === patternName);
    if (!pattern)
      throw new UnknownPatternError;
    return pattern;
  }
  encryptedLead(pattern) {
    return pattern.kind === "heuristic" ? heuristicMarker(pattern.name) : pattern.prefix;
  }
  encryptSpan(span, extraTweak) {
    const { pattern, body } = span;
    return this.encryptedLead(pattern) + this.transform(pattern, body, "encrypt", extraTweak);
  }
  transform(pattern, body, mode, extraTweak) {
    const tweak = this.makeTweak(pattern.name, extraTweak);
    if (pattern.kind === "structured") {
      return this.transformStructured(pattern, body, mode, tweak);
    }
    const cipher = this.getCipher(pattern, pattern.bodyAlphabet.radix, body.length);
    return transformBody(body, pattern.bodyAlphabet, cipher, mode, tweak);
  }
  transformStructured(pattern, body, mode, tweak) {
    const parsed = parseStructured(pattern, body);
    const transformed = [...parsed.segments];
    for (let i = 0;i < parsed.segments.length; i++) {
      const segment = parsed.segments[i];
      if (segment.length < MIN_SEGMENT_LENGTH)
        continue;
      const alphabet = parsed.alphabets[i];
      const cipher = this.getCipher(pattern, alphabet.radix, segment.length);
      transformed[i] = cycleWalk(segment, (value) => transformBody(value, alphabet, cipher, mode, tweak), segmentClass(pattern, parsed, i)).output;
    }
    return formatStructured(pattern, transformed, parsed.alphabets);
  }
  findHeuristicMarkerHits(text, patterns) {
    const hits = [];
    for (const pattern of patterns) {
      if (pattern.kind !== "heuristic")
        continue;
      const marker = heuristicMarker(pattern.name);
      let searchFrom = 0;
      while (searchFrom < text.length) {
        const idx = text.indexOf(marker, searchFrom);
        if (idx === -1)
          break;
        const bodyStart = idx + marker.length;
        let bodyEnd = bodyStart;
        while (bodyEnd < text.length && bodyEnd - bodyStart < pattern.maxLength && pattern.bodyAlphabet.charToIndex.has(text[bodyEnd])) {
          bodyEnd++;
        }
        const bodyLen = bodyEnd - bodyStart;
        const trailingAlphaChar = bodyEnd < text.length && pattern.bodyAlphabet.charToIndex.has(text[bodyEnd]);
        if (bodyLen >= pattern.minLength && bodyLen <= pattern.maxLength && !trailingAlphaChar) {
          hits.push({
            start: idx,
            end: bodyEnd,
            body: text.slice(bodyStart, bodyEnd),
            pattern
          });
          searchFrom = bodyEnd;
        } else {
          searchFrom = idx + 1;
        }
      }
    }
    hits.sort((a, b) => a.start - b.start);
    return hits;
  }
  register(pattern) {
    this.assertAlive();
    this.patterns.unshift(pattern);
  }
  destroy() {
    this.destroyed = true;
    this.key.fill(0);
    for (const cipher of this.cache.values())
      cipher.destroy();
    this.cache.clear();
  }
}
export {
  scan,
  cycleWalk,
  UnknownPatternError,
  TokenFormatError,
  TokenError,
  TokenEncryptor,
  MIN_SEGMENT_LENGTH,
  MAX_CYCLE_STEPS,
  HEX_LOWER,
  DIGITS,
  CycleWalkError,
  BUILTIN_PATTERNS,
  BASE64URL,
  BASE64,
  ALPHANUMERIC_UPPER,
  ALPHANUMERIC_LOWER,
  ALPHANUMERIC
};
