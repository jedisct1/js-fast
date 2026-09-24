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
var ZEROS = new Uint8Array(4096);
function incrementCounter(counter) {
  for (let i = AES_BLOCK_SIZE2 - 1;i >= 0; i--) {
    counter[i] = counter[i] + 1 & 255;
    if (counter[i] !== 0)
      break;
  }
}

class PrngState {
  ctr;
  buffer = new Uint8Array(0);
  bufferPos = 0;
  constructor(key, nonce) {
    const counter = new Uint8Array(nonce);
    incrementCounter(counter);
    this.ctr = createCipheriv2("aes-128-ctr", key, counter);
    counter.fill(0);
  }
  getBytes(output) {
    for (let offset = 0;offset < output.length; ) {
      if (this.bufferPos === this.buffer.length)
        this.refill();
      const chunkLength = Math.min(output.length - offset, this.buffer.length - this.bufferPos);
      output.set(this.buffer.subarray(this.bufferPos, this.bufferPos + chunkLength), offset);
      this.bufferPos += chunkLength;
      offset += chunkLength;
    }
  }
  refill() {
    if (this.ctr === null)
      throw new Error("PRNG has been cleaned up");
    this.buffer.fill(0);
    this.buffer = this.ctr.update(ZEROS);
    this.bufferPos = 0;
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
    this.buffer.fill(0);
    this.bufferPos = this.buffer.length;
    if (this.ctr === null)
      return;
    try {
      this.ctr.final();
    } catch {}
    this.ctr = null;
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
function highByteSequence(numLayers, prng) {
  const seq = new Uint32Array(numLayers);
  const bytes = new Uint8Array(Math.min(4 * numLayers, ZEROS.length));
  try {
    for (let i = 0;i < numLayers; ) {
      const chunk = bytes.subarray(0, Math.min(bytes.length, 4 * (numLayers - i)));
      prng.getBytes(chunk);
      for (let offset = 0;offset < chunk.length; offset += 4) {
        seq[i++] = chunk[offset];
      }
    }
  } finally {
    bytes.fill(0);
  }
  return seq;
}
function generateSequence(numLayers, poolSize, keyMaterial) {
  const { key, iv } = splitKeyMaterial(keyMaterial, true);
  const prng = new PrngState(key, iv);
  key.fill(0);
  iv.fill(0);
  try {
    if (poolSize === 256)
      return highByteSequence(numLayers, prng);
    const seq = new Uint32Array(numLayers);
    for (let i = 0;i < numLayers; i++) {
      seq[i] = prng.uniform(poolSize);
    }
    return seq;
  } finally {
    prng.cleanup();
  }
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
  key.fill(0);
  iv.fill(0);
  const pool = { sboxes: [], radix };
  try {
    for (let i = 0;i < count; i++) {
      pool.sboxes.push(generateSBox(radix, prng));
    }
  } catch (error) {
    wipeSBoxPool(pool);
    throw error;
  } finally {
    prng.cleanup();
  }
  return pool;
}
function wipeSBoxPool(pool) {
  for (const sbox of pool.sboxes) {
    sbox.perm.fill(0);
    sbox.inv.fill(0);
  }
}

// src/cipher.ts
var AES_KEY_SIZE3 = 16;
var DERIVED_KEY_SIZE = 32;
function deriveSBoxPool(params, key) {
  const poolKeyMaterial = deriveKey(key, buildSetup1Input(params), DERIVED_KEY_SIZE);
  try {
    return generateSBoxPool(params.radix, params.sboxCount, poolKeyMaterial);
  } finally {
    poolKeyMaterial.fill(0);
  }
}

class FastCipher {
  params;
  masterKey;
  sboxPool;
  ownsPool;
  destroyed = false;
  cachedTweak = null;
  cachedSeq = null;
  constructor(params, masterKey, sboxPool, ownsPool) {
    this.params = params;
    this.masterKey = new Uint8Array(masterKey);
    this.sboxPool = sboxPool;
    this.ownsPool = ownsPool;
  }
  static create(params, key) {
    FastCipher.validateParams(params, key);
    return new FastCipher(params, key, deriveSBoxPool(params, key), true);
  }
  static withSharedPool(params, key, pool) {
    FastCipher.validateParams(params, key);
    if (pool.radix !== params.radix || pool.sboxes.length !== params.sboxCount) {
      throw new InvalidParametersError("S-box pool does not match the parameters");
    }
    return new FastCipher(params, key, pool, false);
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
    let seq;
    try {
      seq = generateSequence(this.params.numLayers, this.params.sboxCount, seqKeyMaterial);
    } finally {
      seqKeyMaterial.fill(0);
    }
    this.cachedSeq?.fill(0);
    this.cachedTweak?.fill(0);
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
    if (this.ownsPool)
      wipeSBoxPool(this.sboxPool);
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
export {
  calculateRecommendedParams,
  InvalidWordLengthError,
  InvalidValueError,
  InvalidSBoxCountError,
  InvalidRadixError,
  InvalidParametersError,
  InvalidLengthError,
  InvalidBranchDistError,
  FastError,
  FastCipher
};
