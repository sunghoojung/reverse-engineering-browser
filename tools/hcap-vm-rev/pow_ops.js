/**
 * Reconstructive model of hCaptcha HSW proof-of-work operations.
 *
 * This is NOT a solver. It documents the host-side PoW mechanics that
 * Origin Trace observed being called from func 606 via import a.Yb.
 *
 * Source: Static analysis of hsw.js qx["Yb"] at offset 1527318
 */

"use strict";

// ---------------------------------------------------------------------------
// 1. Constants observed in Yb implementation
// ---------------------------------------------------------------------------

const POW_BATCH_SIZE = 16;        // Parallel crypto.subtle.digest calls
const POW_ROTATION = 173;          // Byte offset for leading-zero check (mod 20)
const SHA1_DIGEST_SIZE = 20;       // SHA-1 output bytes

// ---------------------------------------------------------------------------
// 2. Leading-zero check (rotated view of SHA-1 digest)
// ---------------------------------------------------------------------------

/**
 * Check if digest has required leading zero bits, with rotation.
 *
 * @param {Uint8Array} digest - 20-byte SHA-1 result
 * @param {number} bits - Required leading zero bits (0-160)
 * @returns {boolean} True if digest passes
 */
function checkLeadingZeroBits(digest, bits) {
  const fullBytes = Math.floor(bits / 8);
  const partialBits = bits % 8;

  // Check full zero bytes (rotated)
  for (let i = 0; i < fullBytes; i++) {
    const byteIdx = (POW_ROTATION + i) % SHA1_DIGEST_SIZE;
    if (digest[byteIdx] !== 0) return false;
  }

  // Check partial byte if needed
  if (partialBits > 0) {
    const byteIdx = (POW_ROTATION + fullBytes) % SHA1_DIGEST_SIZE;
    const threshold = 1 << (8 - partialBits);
    if (digest[byteIdx] >= threshold) return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// 3. Pure JavaScript SHA-1 (fallback when crypto.subtle unavailable)
// ---------------------------------------------------------------------------

/**
 * Pure JS SHA-1 implementation (from hsw.js fallback path).
 *
 * @param {string} message - Input string
 * @returns {Uint8Array} 20-byte digest
 */
function sha1Pure(message) {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  let H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  // Encode as UTF-8 via escape/unescape trick (matches hsw.js)
  let str = unescape(encodeURIComponent(message));
  str += String.fromCharCode(0x80);

  const numBlocks = Math.ceil((str.length / 4 + 2) / 16);
  const blocks = new Array(numBlocks);

  for (let i = 0; i < numBlocks; i++) {
    blocks[i] = new Array(16);
    for (let j = 0; j < 16; j++) {
      blocks[i][j] =
        (str.charCodeAt(64 * i + 4 * j) << 24) |
        (str.charCodeAt(64 * i + 4 * j + 1) << 16) |
        (str.charCodeAt(64 * i + 4 * j + 2) << 8) |
        str.charCodeAt(64 * i + 4 * j + 3);
    }
  }

  // Length in bits (original message, before padding)
  const bitLen = 8 * (str.length - 1);
  blocks[numBlocks - 1][14] = Math.floor(bitLen / 0x100000000);
  blocks[numBlocks - 1][15] = bitLen & 0xffffffff;

  function rotl(x, n) {
    return (x << n) | (x >>> (32 - n));
  }

  function f(t, b, c, d) {
    if (t < 20) return (b & c) ^ (~b & d);
    if (t < 40) return b ^ c ^ d;
    if (t < 60) return (b & c) ^ (b & d) ^ (c & d);
    return b ^ c ^ d;
  }

  for (let i = 0; i < numBlocks; i++) {
    const W = new Array(80);

    for (let t = 0; t < 16; t++) {
      W[t] = blocks[i][t];
    }
    for (let t = 16; t < 80; t++) {
      W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    let [a, b, c, d, e] = H;

    for (let t = 0; t < 80; t++) {
      const temp = (rotl(a, 5) + f(t, b, c, d) + e + K[Math.floor(t / 20)] + W[t]) >>> 0;
      e = d;
      d = c;
      c = rotl(b, 30) >>> 0;
      b = a;
      a = temp;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
  }

  const result = new Uint8Array(20);
  for (let i = 0; i < 5; i++) {
    result[4 * i] = H[i] >>> 24;
    result[4 * i + 1] = (H[i] >>> 16) & 0xff;
    result[4 * i + 2] = (H[i] >>> 8) & 0xff;
    result[4 * i + 3] = H[i] & 0xff;
  }
  return result;
}

// ---------------------------------------------------------------------------
// 4. PoW search (sync fallback)
// ---------------------------------------------------------------------------

/**
 * Synchronous PoW search using pure JS SHA-1.
 *
 * @param {string} prefix - Challenge prefix from wasm
 * @param {number} bits - Required leading zero bits
 * @returns {number} Winning nonce
 */
function powSearchSync(prefix, bits) {
  for (let nonce = 0; ; nonce++) {
    const message = prefix + ":" + nonce.toString(16);
    const digest = sha1Pure(message);
    if (checkLeadingZeroBits(digest, bits)) {
      return nonce;
    }
  }
}

// ---------------------------------------------------------------------------
// 5. PoW search (async with crypto.subtle, batched)
// ---------------------------------------------------------------------------

/**
 * Async PoW search using crypto.subtle.digest with batching.
 * This is the primary path in hsw.js when SubtleCrypto is available.
 *
 * @param {string} prefix - Challenge prefix from wasm
 * @param {number} bits - Required leading zero bits
 * @returns {Promise<number>} Winning nonce
 */
async function powSearchAsync(prefix, bits) {
  const encoder = new TextEncoder();
  const prefixBytes = encoder.encode(prefix + ":");
  const buffers = new Array(POW_BATCH_SIZE);
  const promises = new Array(POW_BATCH_SIZE);

  /**
   * Build input buffer for a nonce.
   */
  function buildInput(bufferIdx, nonce) {
    const nonceHex = nonce.toString(16);
    const totalLen = prefixBytes.length + nonceHex.length;

    let buf = buffers[bufferIdx];
    if (!buf || buf.length !== totalLen) {
      buf = new Uint8Array(totalLen);
      buf.set(prefixBytes);
      buffers[bufferIdx] = buf;
    }

    for (let i = 0; i < nonceHex.length; i++) {
      buf[prefixBytes.length + i] = nonceHex.charCodeAt(i);
    }

    return buf;
  }

  /**
   * Search a batch of nonces starting at base.
   */
  async function searchBatch(base) {
    for (let i = 0; i < POW_BATCH_SIZE; i++) {
      const input = buildInput(i, base + i);
      promises[i] = crypto.subtle.digest("SHA-1", input);
    }

    const digests = await Promise.all(promises);

    for (let i = 0; i < POW_BATCH_SIZE; i++) {
      if (checkLeadingZeroBits(new Uint8Array(digests[i]), bits)) {
        return base + i;
      }
    }

    // Continue with next batch
    return searchBatch(base + POW_BATCH_SIZE);
  }

  return searchBatch(0);
}

// ---------------------------------------------------------------------------
// 6. Host import a.Yb reconstruction
// ---------------------------------------------------------------------------

/**
 * Reconstructive model of host import a.Yb as called by func 606.
 *
 * In hsw.js this is wrapped in uo() (try/catch) and returns a boxed Promise.
 *
 * @param {number} prefixPtr - Pointer to prefix string in wasm memory
 * @param {number} prefixLen - Length of prefix string
 * @param {number} difficultyBits - Required leading zero bits
 * @returns {number} JS handle to Promise<nonce>
 */
function hostYb(prefixPtr, prefixLen, difficultyBits) {
  // In real hsw.js:
  // const prefix = aSJ(prefixPtr, prefixLen);  // decode from wasm memory
  // const bits = difficultyBits >>> 0;
  //
  // return aZl(powSearch(prefix, bits));       // box Promise as handle

  // Reconstructive: show the dispatch
  const prefix = readWasmString(prefixPtr, prefixLen);
  const bits = difficultyBits >>> 0;

  const resultPromise = (async () => {
    try {
      return await powSearchAsync(prefix, bits);
    } catch {
      return powSearchSync(prefix, bits);
    }
  })();

  return addHeapObject(resultPromise);
}

// ---------------------------------------------------------------------------
// 7. Stubs for wasm memory access (not implemented)
// ---------------------------------------------------------------------------

function readWasmString(_ptr, _len) {
  // In real hsw.js: aSJ(ptr, len) via TextDecoder over vu.Hc.buffer
  return "<prefix-from-wasm>";
}

function addHeapObject(value) {
  // In real hsw.js: push to NV heap array, return index
  void value;
  return 1028; // First non-reserved handle
}

// ---------------------------------------------------------------------------
// 8. Call graph summary
// ---------------------------------------------------------------------------

/**
 * JWT entry through PoW:
 *
 *   hsw(jwt, extra, cb)
 *     |
 *     +-- parseCompactJwt(jwt)
 *     |
 *     +-- aeB(payloadJson, unixSec, extra, cb)
 *           |
 *           export Uc / func 491
 *             |
 *             +-- a.Qa (new Promise with wasm executor)
 *             |
 *             +-- func 659 (Promise body)
 *                   |
 *                   +-- func 1033 (529-arm CFF)
 *                         |
 *                         +-- func 606 (732-arm CFF)
 *                               |
 *                               +-- a.Yb (SHA-1 PoW) <-- HERE
 *                               |
 *                               +-- func 218 (fingerprint)
 *                                     |
 *                                     +-- func 323
 *
 * Host imports touched by PoW path:
 *   - a.Qa  : Promise executor
 *   - a.Yb  : SHA-1 leading-zero PoW
 *   - a.Hb  : box wasm string
 *   - a.zb  : drop handle
 *   - a.Sb  : Promise.resolve
 *   - a.h   : JSON.stringify
 *   - a.nb  : Date.now
 *   - a.ta  : performance.now
 */

// ---------------------------------------------------------------------------
// 9. Exports (for testing only, not a solver)
// ---------------------------------------------------------------------------

if (typeof module !== "undefined") {
  module.exports = {
    POW_BATCH_SIZE,
    POW_ROTATION,
    checkLeadingZeroBits,
    sha1Pure,
    powSearchSync,
    powSearchAsync,
    hostYb,
  };
}

// Suppress unused warnings in static analysis
void hostYb;
void powSearchSync;
void powSearchAsync;
