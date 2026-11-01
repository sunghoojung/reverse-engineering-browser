/**
 * Artifact 13 / 63d9f8a3 codec fixture (session 5369273503095065946).
 * Parallel to guest_ops_live_fixture.js — do not mix indexes with LIVE_84FEB.
 *
 * Run: node /tmp/hcap-vm-rev/guest_ops_art13_fixture.js
 * Check: node --check /tmp/hcap-vm-rev/guest_ops_art13_fixture.js
 */
"use strict";

const fs = require("fs");
const path = require("path");
const assert = require("assert");
const guest = require("./guest_ops.js");

const PAGE = 320;
const HDR = 8;
const CHUNK = PAGE + HDR;
const PAGE_TABLE_BASE = 1024;
const PERM_ADDR = 4;
const KEYSTREAM_ADDR = 469;
const KEYSTREAM_PERIOD = 96;

const ROOT = __dirname;
const KS_BIN = path.join(ROOT, "keystream_table_63d9.bin");
const PERM_BIN = path.join(ROOT, "perm_table_63d9.bin");

const LIVE = guest.LIVE_63D9;
const KS_FROM_BIN = fs.readFileSync(KS_BIN);
const PERM_FROM_BIN = fs.readFileSync(PERM_BIN);

assert.strictEqual(KS_FROM_BIN.length, 96);
assert.strictEqual(PERM_FROM_BIN.length, 16);
assert.ok(Buffer.compare(KS_FROM_BIN, LIVE.keystream_bytes) === 0, "LIVE_63D9 keystream matches bin");
assert.deepStrictEqual(Array.from(PERM_FROM_BIN), Array.from(LIVE.perm_table), "LIVE_63D9 perm matches bin");

assert.strictEqual(LIVE.codec.load_i32, 859);
assert.strictEqual(LIVE.codec.store_i32, 366);
assert.strictEqual(LIVE.codec.mark_dirty, 1134);
assert.strictEqual(LIVE.codec.keystream, 217);
assert.strictEqual(LIVE.codec.keystream_addr, 469);
assert.strictEqual(LIVE.codec.page_table, 518);
assert.strictEqual(LIVE.exports.Yc, 1170);
assert.strictEqual(LIVE.exports.Pc, 250);
assert.strictEqual(LIVE.exports.Uc, 690);
assert.strictEqual(LIVE.exports.Nc, "memory0");

assert.notStrictEqual(LIVE.codec.load_i32, guest.LIVE_84FEB.codec.load_i32, "art13 indexes diverge from 84feb");
assert.strictEqual(guest.GLUE_LIVE.art12.sha256_prefix, "e25e8466");
assert.strictEqual(LIVE.hsw_mode[0].worker, 349);
assert.strictEqual(LIVE.hsw_mode[1].worker, 667);
assert.strictEqual(LIVE.hsw_mode[2].worker, 724);

class LiveMemory {
  constructor(bytes) {
    this.buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 1 << 20);
    this.buf[0] = 0x11;
    for (let i = 0; i < 16; i++) this.buf[PERM_ADDR + i] = PERM_FROM_BIN[i];
    for (let i = 0; i < 96; i++) this.buf[KEYSTREAM_ADDR + i] = KS_FROM_BIN[i];
  }
  u8(addr) {
    return this.buf[addr >>> 0] || 0;
  }
  u8set(addr, v) {
    this.buf[addr >>> 0] = v & 0xff;
  }
  i32(addr) {
    const a = addr >>> 0;
    const b = this.buf;
    return (b[a] | (b[a + 1] << 8) | (b[a + 2] << 16) | (b[a + 3] << 24)) | 0;
  }
  i32set(addr, value) {
    const a = addr >>> 0;
    const v = value | 0;
    this.buf[a] = v & 0xff;
    this.buf[a + 1] = (v >>> 8) & 0xff;
    this.buf[a + 2] = (v >>> 16) & 0xff;
    this.buf[a + 3] = (v >>> 24) & 0xff;
  }
  i64(addr) {
    const lo = this.i32(addr) >>> 0;
    const hi = this.i32(addr + 4) >>> 0;
    return (BigInt(hi) << 32n) | BigInt(lo);
  }
}

function wrap32(k) {
  return Number(k & 0xffffffffn) | 0;
}

function pageIndex(addr) {
  return ((addr >>> 0) / PAGE) >>> 0;
}

function pageRem(addr) {
  return ((addr >>> 0) % PAGE) >>> 0;
}

/** func 518 */
function pageTable(chunkIndex, mem) {
  const i = chunkIndex >>> 0;
  const perm = mem.u8(PERM_ADDR + (i & 15));
  const mixed = perm | (i & ~15);
  return (PAGE_TABLE_BASE + mixed * CHUNK) >>> 0;
}

/** func 217 — i64.load(469 + addr%96) */
function keystream64(addr, mem) {
  return mem.i64(KEYSTREAM_ADDR + ((addr >>> 0) % KEYSTREAM_PERIOD));
}

/** func 1134 */
function markDirty(mem, chunkIndex) {
  const desc = pageTable(chunkIndex, mem);
  if (mem.u8(desc) !== 0) return;
  mem.u8set(desc, 1);
  const base = desc + HDR;
  const vbase = (chunkIndex >>> 0) * PAGE;
  for (let i = 0; i < PAGE; i++) {
    mem.u8set(base + i, Number(keystream64(vbase + i, mem) & 0xffn));
  }
}

/** func 859 — always final XOR with wrap32(keystream(addr)) */
function load_i32(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = pageTable(chunk, mem);
  const payload = (desc + HDR + rem) >>> 0;
  let v;
  if (mem.u8(desc) !== 0) v = mem.i32(payload);
  else v = wrap32(keystream64(addr, mem));
  if (rem > 316) {
    const next = pageTable(chunk + 1, mem);
    const nbase = next + HDR;
    const warm0 = mem.u8(desc) !== 0;
    const warm1 = mem.u8(next) !== 0;
    const b0 = warm0 ? mem.u8(payload) : Number(keystream64(addr, mem) & 0xffn);
    const b1 =
      rem + 1 < PAGE
        ? warm0
          ? mem.u8(payload + 1)
          : Number(keystream64(addr + 1, mem) & 0xffn)
        : warm1
          ? mem.u8(nbase + (rem + 1 - PAGE))
          : Number(keystream64(addr + 1, mem) & 0xffn);
    const b2 =
      rem + 2 < PAGE
        ? warm0
          ? mem.u8(payload + 2)
          : Number(keystream64(addr + 2, mem) & 0xffn)
        : warm1
          ? mem.u8(nbase + (rem + 2 - PAGE))
          : Number(keystream64(addr + 2, mem) & 0xffn);
    const b3 =
      rem + 3 < PAGE
        ? warm0
          ? mem.u8(payload + 3)
          : Number(keystream64(addr + 3, mem) & 0xffn)
        : warm1
          ? mem.u8(nbase + (rem + 3 - PAGE))
          : Number(keystream64(addr + 3, mem) & 0xffn);
    v = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) | 0;
  }
  return (v ^ wrap32(keystream64(addr, mem))) | 0;
}

/** func 366 */
function store_i32(mem, base, value, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  markDirty(mem, chunk);
  markDirty(mem, chunk + 1);
  let v = (value ^ wrap32(keystream64(addr, mem))) | 0;
  const desc = pageTable(chunk, mem);
  const payload = (desc + HDR + rem) >>> 0;
  if (rem > 316) {
    const next = pageTable(chunk + 1, mem);
    const nbase = next + HDR;
    for (let i = 0; i < 4; i++) {
      const a = (addr + i) >>> 0;
      const byte = (v >>> (8 * i)) & 0xff;
      if (pageIndex(a) === chunk) mem.u8set(payload + i, byte);
      else mem.u8set(nbase + pageRem(a), byte);
    }
  } else {
    mem.i32set(payload, v);
  }
}

function runFixtures() {
  const mem = new LiveMemory(1 << 20);

  assert.strictEqual(pageTable(0, mem), 1024 + 0 * CHUNK);
  assert.strictEqual(pageTable(1, mem), 1024 + 9 * CHUNK);
  assert.strictEqual(pageTable(15, mem), 1024 + 15 * CHUNK);
  assert.strictEqual(pageTable(16, mem), 1024 + ((0 | 16) * CHUNK));

  const k0 = keystream64(0, mem);
  const k96 = keystream64(96, mem);
  assert.strictEqual(k0, k96, "keystream period 96");
  assert.strictEqual(wrap32(k0), KS_FROM_BIN.readUInt32LE(0) | 0);

  assert.strictEqual(load_i32(mem, 0, 40), 0, "cold load plaintext-zero");
  store_i32(mem, 0, 0x12345678, 16);
  assert.strictEqual(load_i32(mem, 0, 16), 0x12345678, "warm load roundtrip");
  const desc0 = pageTable(0, mem);
  assert.strictEqual(mem.u8(desc0), 1, "markDirty set cache flag");
  const raw = mem.i32(desc0 + HDR + 16);
  assert.strictEqual(raw, (0x12345678 ^ wrap32(keystream64(16, mem))) | 0, "payload holds p^ks");

  store_i32(mem, 0, -1, 314);
  assert.strictEqual(load_i32(mem, 0, 314), -1, "split-page roundtrip");

  assert.strictEqual(LIVE.yc_dispatch.arms[0].magic, -174010464);
  assert.strictEqual(LIVE.yc_dispatch.arms[1].magic, -1483911731);
  assert.strictEqual(LIVE.yc_dispatch.arms[7].magic, 672652481);

  console.log("guest_ops_art13_fixture: ok");
  console.log(
    JSON.stringify(
      {
        sha: LIVE.sha256.slice(0, 8),
        codec: LIVE.codec,
        hsw_mode: LIVE.hsw_mode,
        largest_cff_top: LIVE.largest_cff.slice(0, 5),
      },
      null,
      2
    )
  );
}

module.exports = {
  LiveMemory,
  pageTable,
  keystream64,
  markDirty,
  load_i32,
  store_i32,
  PAGE,
  HDR,
  CHUNK,
  KEYSTREAM_ADDR,
  PERM_ADDR,
  runFixtures,
};

if (require.main === module) {
  runFixtures();
}
