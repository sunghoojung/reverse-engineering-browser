/**
 * HSW VM 320-byte page codec - reconstructed from wasm funcs 282/305/874/1113/526.
 * NOT executable against a live challenge. For static analysis only.
 *
 * Memory layout:
 *   - Pages are 320 bytes
 *   - Each chunk is 328 bytes: 8-byte descriptor + 320-byte payload
 *   - Descriptor[0] = cache flag (0=encrypted, 1=plaintext-cached)
 *   - Keystream is position-dependent, generated per-address
 */
"use strict";

const PAGE = 320;
const HDR = 8;
const CHUNK = PAGE + HDR; // 328 bytes

/**
 * Multiplicative hash constants observed in func 354 and related code.
 * These form a SplitMix64/xxHash-style keystream generator.
 */
const HASH_CONSTANTS = {
  K1: 0x2ABF4F14n,      // 717560084
  K2: 0xD35E69FBn,      // -748166005 as u32
  K3: 0x72D34F59n,      // 1926849369
  K4: 0x8E2B6325n,      // -1910552923 as u32
  K5: 0x11CAE8AAn,      // 298475690
  K6: 0x5AD2BA6Fn,      // 1524303983
  K7: 0x19B6B8F9n,      // 432018953
  K8: 0x503012EEn,      // 1345475438
};

function pageIndex(addr) {
  return ((addr >>> 0) / PAGE) >>> 0;
}

function pageRem(addr) {
  return ((addr >>> 0) % PAGE) >>> 0;
}

/**
 * func 1113: chunk index -> descriptor pointer in linear memory.
 *
 * In the actual module, this maps through a page table or computes
 * a direct offset. Placeholder returns chunk * CHUNK as base layout.
 *
 * @param {number} chunkIndex - Virtual chunk index
 * @returns {number} - Linear memory offset of chunk descriptor
 */
function chunkDescriptor(chunkIndex) {
  // This is a placeholder. The actual implementation likely involves:
  // 1. A page table lookup, or
  // 2. A base address + chunkIndex * CHUNK computation
  // The base address for the main bytecode region is 1,076,864 (data[5])
  const BASE_BYTECODE = 1076864;
  return BASE_BYTECODE + (chunkIndex * CHUNK);
}

/**
 * func 874: address -> i64 keystream word.
 *
 * EXACTNESS: UNKNOWN
 *
 * func 874 is called from load/store (282/305/350/390) with address input,
 * returns i64 keystream. Type signature: (i32) -> (i64).
 *
 * Observed call sites in helpers.txt:
 *   @125364, @125415, @125625 (func 282 load_i32)
 *   @134652 (func 305 store_i32)
 *   @203822, @203872, @204280 (func 350 load_i64)
 *   @231984, @232035, @232147 (func 390 load_i16)
 *   @716038, @716045 (func 1062 load_i8)
 *
 * Constants observed in related func 354 (memory init CFF):
 *   0x2ABF4F14 (717560084)  - xor
 *   0xD35E69FB (-748166005) - mul
 *   0x72D34F59 (1926849369) - sub
 *   0x8E2B6325 (-1910552923) - mul
 *   0x11CAE8AA (298475690)  - add
 *   0x5AD2BA6F (1524303983) - mask/and
 *
 * LIMITATION: func 874 body NOT disassembled in helpers.txt (only call sites).
 * wasm2wat not available to extract exact instruction sequence.
 * The algorithm below is INFERRED from:
 *   1. Return type is i64 (confirmed by i32.wrap_i64 at call sites)
 *   2. Input is virtual address (confirmed by usage pattern)
 *   3. Constants from func 354 are multiplicative hash family
 *   4. Pattern matches SplitMix64/xxHash-style PRF
 *
 * To verify: disassemble hsw-click.wasm func 874 (index 874 = defined func 683)
 * and compare round structure. Until then, this is APPROXIMATE.
 *
 * @param {number} addr - Virtual address (i32)
 * @returns {bigint} - 64-bit keystream value (i64)
 */
function addrKeystream(addr) {
  // APPROXIMATE reconstruction - exact rounds UNPROVEN
  // See comments above for what is known vs inferred
  let x = BigInt(addr >>> 0);

  // Round 1: XOR with constant, multiply, subtract
  x ^= HASH_CONSTANTS.K1;
  x = (x * HASH_CONSTANTS.K2) & 0xFFFFFFFFn;
  x = (x - HASH_CONSTANTS.K3) & 0xFFFFFFFFn;

  // Round 2: multiply, add
  x = (x * HASH_CONSTANTS.K4) & 0xFFFFFFFFn;
  x = (x + HASH_CONSTANTS.K5) & 0xFFFFFFFFn;

  // Extend to 64-bit - SPECULATIVE, not proven
  // Real func 874 may use different upper-half derivation
  const lo = x;
  let y = x ^ HASH_CONSTANTS.K6;
  y = (y * HASH_CONSTANTS.K7) & 0xFFFFFFFFn;
  y = (y - HASH_CONSTANTS.K8) & 0xFFFFFFFFn;

  return (y << 32n) | lo;
}

/**
 * func 526: page touch / mark dirty.
 *
 * When a page is first written, this function marks it and may
 * trigger a decrypt-to-cache operation. After marking, desc[0] = 1.
 *
 * @param {object} mem - Memory interface
 * @param {number} chunkIndex - Chunk to mark
 */
function markDirty(mem, chunkIndex) {
  const desc = chunkDescriptor(chunkIndex);
  // The actual implementation likely:
  // 1. Checks if already cached (desc[0] != 0)
  // 2. If not, decrypts the entire page into a plaintext cache
  // 3. Sets desc[0] = 1
  mem.u8set(desc, 1);
}

/**
 * func 282: load_i32(base, off) -> i32
 *
 * If the page is marked plaintext-cached (desc[0] != 0), loads directly.
 * Otherwise, XORs with the truncated keystream.
 * Handles page boundary crossing when rem > 316.
 *
 * @param {object} mem - Memory interface with u8(), i32_unaligned() methods
 * @param {number} base - Base address
 * @param {number} off - Offset
 * @returns {number} - Decrypted i32 value
 */
function load_i32(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk);
  const slot = desc + HDR + rem;

  // Check cache flag
  const isCached = mem.u8(desc) !== 0;

  // Simple case: no page boundary crossing
  const overlap = rem - (PAGE - 4); // rem - 316
  if (overlap <= 0) {
    if (isCached) {
      return mem.i32_unaligned(slot);
    } else {
      const k = addrKeystream(addr);
      return Number(k & 0xFFFFFFFFn) | 0;
    }
  }

  // Complex case: bytes straddle two pages
  const nextChunk = chunk + 1;
  const nextDesc = chunkDescriptor(nextChunk);
  const nextCached = mem.u8(nextDesc) !== 0;
  const k = addrKeystream(addr);

  const bytes = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    const byteOverlap = i - (4 - overlap);
    if (byteOverlap < 0) {
      // Byte is in current page
      if (isCached) {
        bytes[i] = mem.u8(slot + i);
      } else {
        bytes[i] = Number((k >> BigInt(8 * i)) & 0xFFn);
      }
    } else {
      // Byte is in next page
      const nextSlot = nextDesc + HDR + byteOverlap;
      if (nextCached) {
        bytes[i] = mem.u8(nextSlot);
      } else {
        bytes[i] = Number((k >> BigInt(8 * i)) & 0xFFn);
      }
    }
  }

  const value = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);

  // Final XOR with keystream
  const keyLo = Number(k & 0xFFFFFFFFn) | 0;
  return (value ^ keyLo) | 0;
}

/**
 * func 305: store_i32(base, value, off)
 *
 * Marks both affected pages as dirty, XOR-mixes value with keystream,
 * then stores bytes, splitting when rem > 316.
 *
 * @param {object} mem - Memory interface
 * @param {number} base - Base address
 * @param {number} value - Value to store
 * @param {number} off - Offset
 */
function store_i32(mem, base, value, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk);
  const slot = desc + HDR + rem;

  // Mark both pages dirty
  markDirty(mem, chunk);
  markDirty(mem, chunk + 1);

  // XOR value with keystream
  const k = addrKeystream(addr);
  const keyLo = Number(k & 0xFFFFFFFFn) | 0;
  const mixed = (value ^ keyLo) | 0;

  const overlap = rem - (PAGE - 4);
  if (overlap <= 0) {
    // Simple case: entirely within one page
    mem.i32_unaligned_set(slot, mixed);
  } else {
    // Complex case: split across pages
    const nextDesc = chunkDescriptor(chunk + 1);
    const nextSlot = nextDesc + HDR;

    for (let i = 0; i < 4; i++) {
      const b = (mixed >>> (8 * i)) & 0xFF;
      const byteOverlap = i - (4 - overlap);
      if (byteOverlap < 0) {
        mem.u8set(slot + i, b);
      } else {
        mem.u8set(nextSlot + byteOverlap, b);
      }
    }
  }
}

/**
 * func 350: load_i64(base, off) -> i64
 *
 * Similar to load_i32 but loads 8 bytes. Boundary at rem > 312.
 */
function load_i64(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk);
  const slot = desc + HDR + rem;

  const isCached = mem.u8(desc) !== 0;
  const overlap = rem - (PAGE - 8); // rem - 312

  if (overlap <= 0 && isCached) {
    return mem.i64_unaligned(slot);
  }

  const k = addrKeystream(addr);

  if (overlap <= 0) {
    // Not cached, use keystream directly
    return k;
  }

  // Split across pages - assemble byte by byte
  const nextDesc = chunkDescriptor(chunk + 1);
  const nextCached = mem.u8(nextDesc) !== 0;

  let result = 0n;
  for (let i = 0; i < 8; i++) {
    const byteOverlap = i - (8 - overlap);
    let b;
    if (byteOverlap < 0) {
      if (isCached) {
        b = BigInt(mem.u8(slot + i));
      } else {
        b = (k >> BigInt(8 * i)) & 0xFFn;
      }
    } else {
      const nextSlot = nextDesc + HDR + byteOverlap;
      if (nextCached) {
        b = BigInt(mem.u8(nextSlot));
      } else {
        b = (k >> BigInt(8 * i)) & 0xFFn;
      }
    }
    result |= (b << BigInt(8 * i));
  }

  return result ^ k;
}

/**
 * Decrypt a raw chunk blob using the keystream.
 *
 * @param {Uint8Array} chunkData - 328-byte chunk (8 header + 320 payload)
 * @param {number} chunkIndex - Virtual chunk index for keystream
 * @returns {Uint8Array} - Decrypted 320-byte payload
 */
function decryptChunk(chunkData, chunkIndex) {
  if (chunkData.length !== CHUNK) {
    throw new Error(`Expected ${CHUNK} bytes, got ${chunkData.length}`);
  }

  const payload = new Uint8Array(PAGE);
  const baseAddr = chunkIndex * PAGE;

  for (let i = 0; i < PAGE; i += 8) {
    const addr = baseAddr + i;
    const k = addrKeystream(addr);

    for (let j = 0; j < 8 && (i + j) < PAGE; j++) {
      const keyByte = Number((k >> BigInt(8 * j)) & 0xFFn);
      const encByte = chunkData[HDR + i + j];
      payload[i + j] = encByte ^ keyByte;
    }
  }

  return payload;
}

/**
 * Analyze a data section blob for inner bytecode structure.
 *
 * @param {Uint8Array} blob - Raw data section bytes
 * @returns {object} - Analysis results
 */
function analyzeBlob(blob) {
  const numChunks = Math.floor(blob.length / CHUNK);
  const results = {
    totalChunks: numChunks,
    headerFlags: [],
    subroutineBoundaries: [],
  };

  for (let i = 0; i < numChunks; i++) {
    const chunkStart = i * CHUNK;
    const flag = blob[chunkStart];
    results.headerFlags.push(flag);

    // Check for potential subroutine boundaries
    // (every ~2 chunks based on observed prefixed blob offsets)
    if (i % 2 === 0) {
      const payloadStart = chunkStart + HDR;
      // Look for length prefix patterns
      const b0 = blob[payloadStart];
      const b1 = blob[payloadStart + 1];
      if (b0 === 0 && b1 === 0) {
        results.subroutineBoundaries.push({
          chunk: i,
          offset: chunkStart,
          payloadPreview: Array.from(blob.slice(payloadStart, payloadStart + 16))
            .map(b => b.toString(16).padStart(2, '0')).join(' ')
        });
      }
    }
  }

  return results;
}

module.exports = {
  // Constants
  PAGE,
  HDR,
  CHUNK,
  HASH_CONSTANTS,

  // Core functions
  pageIndex,
  pageRem,
  chunkDescriptor,
  addrKeystream,
  markDirty,
  load_i32,
  store_i32,
  load_i64,

  // Analysis helpers
  decryptChunk,
  analyzeBlob,
};
