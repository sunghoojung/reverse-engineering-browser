/**
 * LIVE_E449 / e449a4e1 codec + profile bind fixture (session 3478526452141784090).
 * Parallel to guest_ops_live_fixture.js / guest_ops_art13_fixture.js —
 * do not mix indexes with LIVE_84FEB or LIVE_63D9.
 *
 * Run: node /tmp/hcap-vm-rev/guest_ops_e449_fixture.js
 * Check: node --check /tmp/hcap-vm-rev/guest_ops_e449_fixture.js
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
const KEYSTREAM_ADDR = 468;
const KEYSTREAM_PERIOD = 96;

const ROOT = __dirname;
const KS_BIN = path.join(ROOT, "keystream_table_e449.bin");
const PERM_BIN = path.join(ROOT, "perm_table_e449.bin");

const LIVE = guest.LIVE_E449;
const KS_FROM_BIN = fs.readFileSync(KS_BIN);
const PERM_FROM_BIN = fs.readFileSync(PERM_BIN);

assert.strictEqual(KS_FROM_BIN.length, 96);
assert.strictEqual(PERM_FROM_BIN.length, 16);
assert.ok(Buffer.compare(KS_FROM_BIN, LIVE.keystream_bytes) === 0, "LIVE_E449 keystream matches bin");
assert.deepStrictEqual(Array.from(PERM_FROM_BIN), Array.from(LIVE.perm_table), "LIVE_E449 perm matches bin");

assert.strictEqual(LIVE.sha256, "e449a4e1e119e7bdff8588785f6182f921fd76fa439cb0e46f44ae83ff7fd74a");
assert.strictEqual(LIVE.bytes, 1030267);
assert.strictEqual(LIVE.codec.load_i32, 719);
assert.strictEqual(LIVE.codec.store_i32, 397);
assert.strictEqual(LIVE.codec.mark_dirty, 404);
assert.strictEqual(LIVE.codec.keystream, 323);
assert.strictEqual(LIVE.codec.keystream_addr, 468);
assert.strictEqual(LIVE.codec.page_table, 600);
assert.strictEqual(LIVE.exports.Yc, 1164);
assert.strictEqual(LIVE.exports.Uc, 424);
assert.strictEqual(LIVE.exports.Sc, "memory0");
assert.strictEqual(LIVE.exports.Pc, 276);

assert.notStrictEqual(LIVE.codec.load_i32, guest.LIVE_84FEB.codec.load_i32, "e449 indexes diverge from 84feb");
assert.notStrictEqual(LIVE.codec.load_i32, guest.LIVE_63D9.codec.load_i32, "e449 indexes diverge from 63d9");
assert.notStrictEqual(LIVE.exports.Yc, guest.LIVE_84FEB.exports.Yc);
assert.notStrictEqual(LIVE.exports.Yc, guest.LIVE_63D9.exports.Yc);

assert.strictEqual(LIVE.hsw_mode[0].worker, 880);
assert.strictEqual(LIVE.hsw_mode[0].trampoline, 1138);
assert.strictEqual(LIVE.hsw_mode[0].magic, 1668574287);
assert.strictEqual(LIVE.hsw_mode[0].arms, 102);
assert.strictEqual(LIVE.hsw_mode[0].entry_state, 70);

assert.strictEqual(LIVE.hsw_mode[1].worker, 874);
assert.strictEqual(LIVE.hsw_mode[1].trampoline, 1068);
assert.strictEqual(LIVE.hsw_mode[1].magic, 1908833735);
assert.strictEqual(LIVE.hsw_mode[1].arms, 120);
assert.strictEqual(LIVE.hsw_mode[1].entry_state, 103);

assert.strictEqual(LIVE.hsw_mode[2].worker, 727);
assert.strictEqual(LIVE.hsw_mode[2].magic, -20745895);
assert.strictEqual(LIVE.hsw_mode[2].arms, 270);
assert.strictEqual(LIVE.hsw_mode[2].entry_state, 152);

assert.strictEqual(guest.LIVE_E449_MAGIC.encrypt_req_data, 1908833735);
assert.strictEqual(guest.LIVE_E449_MAGIC.decrypt_resp_data, 1668574287);
assert.strictEqual(guest.LIVE_E449_MAGIC.update_token, -20745895);

// Wasm bytes are local reverse artifacts and are not shipped in-repo.
if (process.env.HCAP_REQUIRE_WASM === "1") {
  assert.ok(fs.existsSync(path.join(ROOT, LIVE.path)), "e449 wasm path present");
} else if (!fs.existsSync(path.join(ROOT, LIVE.path))) {
  console.warn("skip: e449 wasm not shipped (set HCAP_REQUIRE_WASM=1 to require)");
}

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

/** func 600 */
function pageTable(chunkIndex, mem) {
  const i = chunkIndex >>> 0;
  const perm = mem.u8(PERM_ADDR + (i & 15));
  const mixed = perm | (i & ~15);
  return (PAGE_TABLE_BASE + mixed * CHUNK) >>> 0;
}

/** func 323 — i64.load(468 + addr%96) */
function keystream64(addr, mem) {
  return mem.i64(KEYSTREAM_ADDR + ((addr >>> 0) % KEYSTREAM_PERIOD));
}

/** func 404 */
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

/** func 719 */
function load_i32(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = pageTable(chunk, mem);
  const slot = desc + HDR + rem;
  const warm = mem.u8(desc) !== 0;
  let v;
  const overlap = rem - (PAGE - 4);
  if (overlap <= 0) {
    v = warm ? mem.i32(slot) : wrap32(keystream64(addr, mem));
  } else {
    const nextDesc = pageTable(chunk + 1, mem);
    const nextWarm = mem.u8(nextDesc) !== 0;
    const nextSlot = nextDesc + HDR;
    const splitAt = 4 - overlap;
    const ks = keystream64(addr, mem);
    const bytes = [0, 0, 0, 0];
    for (let i = 0; i < 4; i++) {
      const useNext = i >= splitAt;
      const cached = useNext ? nextWarm : warm;
      if (cached) {
        bytes[i] = useNext ? mem.u8(nextSlot + (i - splitAt)) : mem.u8(slot + i);
      } else {
        bytes[i] = Number((ks >> BigInt(8 * i)) & 0xffn);
      }
    }
    v = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) | 0;
  }
  return (v ^ wrap32(keystream64(addr, mem))) | 0;
}

/** func 397 */
function store_i32(mem, base, value, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = pageTable(chunk, mem);
  const slot = desc + HDR + rem;
  markDirty(mem, chunk);
  markDirty(mem, chunk + 1);
  const mixed = (value ^ wrap32(keystream64(addr, mem))) | 0;
  const overlap = rem - (PAGE - 4);
  if (overlap <= 0) {
    mem.i32set(slot, mixed);
    return;
  }
  const nextSlot = pageTable(chunk + 1, mem) + HDR;
  const splitAt = 4 - overlap;
  for (let i = 0; i < 4; i++) {
    const b = (mixed >>> (8 * i)) & 0xff;
    if (i < splitAt) mem.u8set(slot + i, b);
    else mem.u8set(nextSlot + (i - splitAt), b);
  }
}

function runFixtures() {
  const mem = new LiveMemory(1 << 20);

  assert.strictEqual(pageTable(0, mem), 1024 + 5 * CHUNK);
  assert.strictEqual(pageTable(1, mem), 1024 + 13 * CHUNK);
  assert.strictEqual(pageTable(15, mem), 1024 + 0 * CHUNK);
  assert.strictEqual(pageTable(16, mem), 1024 + ((5 | 16) * CHUNK));

  const k0 = keystream64(0, mem);
  const k96 = keystream64(96, mem);
  assert.strictEqual(k0, k96, "keystream period 96");
  assert.strictEqual(wrap32(k0), KS_FROM_BIN.readUInt32LE(0) | 0);

  assert.strictEqual(load_i32(mem, 0, 40), 0, "cold load plaintext-zero");
  store_i32(mem, 0, 0x12345678, 16);
  assert.strictEqual(load_i32(mem, 0, 16), 0x12345678, "warm load roundtrip");
  const desc0 = pageTable(pageIndex(16), mem);
  assert.strictEqual(mem.u8(desc0), 1, "markDirty set cache flag");
  const raw = mem.i32(desc0 + HDR + 16);
  assert.strictEqual(raw, (0x12345678 ^ wrap32(keystream64(16, mem))) | 0, "payload holds p^ks");

  store_i32(mem, 0, -1, 314);
  assert.strictEqual(load_i32(mem, 0, 314), -1, "split-page roundtrip");

  assert.strictEqual(LIVE.yc_dispatch.func, 1164);
  assert.strictEqual(LIVE.cff_hypothesis.encrypt.func, 874);
  assert.strictEqual(LIVE.cff_hypothesis.decrypt.func, 880);
  assert.strictEqual(LIVE.cff_hypothesis.update_token.func, 727);
  assert.strictEqual(LIVE.cff_hypothesis.yc_is_mode_dispatch, true);
  assert.strictEqual(LIVE.cff_hypothesis.encrypt.bulk_nested, 537);
  assert.strictEqual(LIVE.cff_hypothesis.decrypt.mba_func, 406);
  assert.strictEqual(LIVE.cff_hypothesis.nested_bulk_analogue.role, "cursor_absorb_mba");
  assert.strictEqual(LIVE.helpers[537], "cursor_absorb_mba");
  assert.strictEqual(LIVE.helpers[406], "opaque_u8_roundtrip_sp15");
  assert.strictEqual(LIVE.cff.nested[537].role, "cursor_absorb_mba");
  assert.strictEqual(LIVE.cff.nested[537].unique, 11);
  assert.strictEqual(LIVE.cff.nested[537].entry_state, 0);
  assert.strictEqual(LIVE.cff.nested[537].vs_937, "remapped_cousin_smaller_machine");
  assert.strictEqual(LIVE.cff.nested[406].role, "opaque_u8_roundtrip");
  assert.strictEqual(LIVE.cff.nested[406].analogue_63d9, 273);
  assert.strictEqual(LIVE.cff.nested[406].body_len, 25);

  const enc = require("./cff_e449_encrypt.js");
  assert.strictEqual(enc.ARM_CLUSTERS_537.n_arms, 11);
  assert.strictEqual(enc.ARM_CLUSTERS_537.entry, 0);
  assert.strictEqual(enc.ARM_CLUSTERS_537.exit, 6);
  assert.strictEqual(enc.ARM_CLUSTERS_537.role, "cursor_absorb_mba");
  const stubMem = {
    load32: () => 0,
    load8: () => 0,
    store8: () => {},
  };
  const stub = enc.bulkPack537Stub(stubMem, 0, 0);
  assert.strictEqual(stub.ok, true);
  assert.ok(stub.trace.some((t) => t.to === 6), "537 stub reaches exit");

  console.log("guest_ops_e449_fixture: ok");
  console.log(
    JSON.stringify(
      {
        sha: LIVE.sha256.slice(0, 8),
        yc: LIVE.exports.Yc,
        codec: LIVE.codec,
        hsw_mode: {
          0: LIVE.hsw_mode[0],
          1: LIVE.hsw_mode[1],
          2: LIVE.hsw_mode[2],
        },
        glue: LIVE.glue,
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
