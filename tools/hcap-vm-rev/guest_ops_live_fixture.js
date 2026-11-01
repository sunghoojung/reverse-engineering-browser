/**
 * Live 84febfac codec fixture (session 5369273503095065946).
 * Exercises page_table / keystream / markDirty / load_i32 / store_i32 against
 * extracted perm@4 + keystream@433 tables. Reconstructive only — not a solver.
 *
 * Run: node /tmp/hcap-vm-rev/guest_ops_live_fixture.js
 * Check: node --check /tmp/hcap-vm-rev/guest_ops_live_fixture.js
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
const KEYSTREAM_ADDR = 433;
const KEYSTREAM_PERIOD = 96;

const ROOT = __dirname;
const KS_BIN = path.join(ROOT, "keystream_table_84feb.bin");
const PERM_BIN = path.join(ROOT, "perm_table_84feb.bin");

const LIVE = guest.LIVE_84FEB;
const KS_FROM_BIN = fs.readFileSync(KS_BIN);
const PERM_FROM_BIN = fs.readFileSync(PERM_BIN);

assert.strictEqual(KS_FROM_BIN.length, 96);
assert.strictEqual(PERM_FROM_BIN.length, 16);
assert.ok(Buffer.compare(KS_FROM_BIN, LIVE.keystream_bytes) === 0, "LIVE_84FEB keystream matches bin");
assert.deepStrictEqual(Array.from(PERM_FROM_BIN), Array.from(LIVE.perm_table), "LIVE_84FEB perm matches bin");

assert.strictEqual(LIVE.codec.load_i32, 438);
assert.strictEqual(LIVE.codec.store_i32, 582);
assert.strictEqual(LIVE.codec.mark_dirty, 250);
assert.strictEqual(LIVE.codec.keystream, 695);
assert.strictEqual(LIVE.codec.keystream_addr, 433);
assert.strictEqual(LIVE.codec.page_table, 1157);
assert.strictEqual(LIVE.exports.Yc, 1166);
assert.strictEqual(LIVE.exports.Pc, 537);
assert.strictEqual(LIVE.exports.Uc, 738);

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

/** func 1157 */
function pageTable(chunkIndex, mem) {
  const i = chunkIndex >>> 0;
  const perm = mem.u8(PERM_ADDR + (i & 15));
  const mixed = perm | (i & ~15);
  return (PAGE_TABLE_BASE + mixed * CHUNK) >>> 0;
}

/** func 695 — i64.load(433 + addr%96) */
function keystream64(addr, mem) {
  return mem.i64(KEYSTREAM_ADDR + ((addr >>> 0) % KEYSTREAM_PERIOD));
}

/** func 250 */
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

/** func 438 — always final XOR with wrap32(keystream(addr)) */
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

/** func 582 */
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
  // page_table: chunk 0 → perm[0]=4 → 1024 + 4*328
  const mem = new LiveMemory(1 << 20);
  assert.strictEqual(pageTable(0, mem), 1024 + 4 * CHUNK);
  assert.strictEqual(pageTable(1, mem), 1024 + 0 * CHUNK);
  assert.strictEqual(pageTable(15, mem), 1024 + 6 * CHUNK);
  assert.strictEqual(pageTable(16, mem), 1024 + ((4 | 16) * CHUNK));

  // keystream period 96 @433
  const k0 = keystream64(0, mem);
  const k96 = keystream64(96, mem);
  assert.strictEqual(k0, k96, "keystream period 96");
  assert.strictEqual(wrap32(k0), KS_FROM_BIN.readUInt32LE(0) | 0);

  // cold load: ks XOR ks = 0
  assert.strictEqual(load_i32(mem, 0, 40), 0, "cold load plaintext-zero");

  // store then warm load returns plaintext
  store_i32(mem, 0, 0x12345678, 16);
  assert.strictEqual(load_i32(mem, 0, 16), 0x12345678, "warm load roundtrip");
  const desc0 = pageTable(pageIndex(16), mem);
  assert.strictEqual(mem.u8(desc0), 1, "markDirty set cache flag");
  const slot = desc0 + HDR + 16;
  const raw = mem.i32(slot);
  assert.strictEqual(raw, (0x12345678 ^ wrap32(keystream64(16, mem))) | 0, "payload holds p^ks");

  // split-page rem>316
  store_i32(mem, 0, -1, 314);
  assert.strictEqual(load_i32(mem, 0, 314), -1, "split-page roundtrip");

  // observed selector lists stay frozen
  assert.deepStrictEqual(Array.from(LIVE.observed_dispatch.selectors[537]), [4, 3, 1]);
  assert.deepStrictEqual(Array.from(LIVE.observed_dispatch.selectors[565]), [2, 0, 5]);
  assert.deepStrictEqual(Array.from(LIVE.observed_dispatch.selectors[1087]), [189, 82, 57, 215, 52, 1, 230, 122]);

  // glue-proven live mode workers (Yc → trampoline → CFF)
  assert.strictEqual(LIVE.cff_hypothesis.encrypt.func, 796);
  assert.strictEqual(LIVE.cff_hypothesis.decrypt.func, 298);
  assert.strictEqual(LIVE.cff_hypothesis.update_token.func, 606);
  assert.strictEqual(LIVE.cff_hypothesis.encrypt.trampoline, 1103);
  assert.strictEqual(LIVE.cff_hypothesis.decrypt.trampoline, 777);
  assert.strictEqual(LIVE.cff_hypothesis.yc_is_mode_dispatch, true);
  assert.strictEqual(LIVE.yc_dispatch.role, "mode_and_codec_dispatcher");
  assert.strictEqual(guest.LIVE_MAGIC.encrypt_req_data, 1262290883);
  assert.strictEqual(guest.LIVE_MAGIC.decrypt_resp_data, -1874150846);
  assert.strictEqual(guest.LIVE_HSW_MODE[0].worker, 298);
  assert.strictEqual(guest.LIVE_HSW_MODE[1].worker, 796);
  // sibling analogues demoted
  assert.strictEqual(LIVE.cff_hypothesis.sibling_analogues_unbound.encrypt_like.func, 592);
  assert.strictEqual(LIVE.cff_hypothesis.sibling_analogues_unbound.decrypt_like.func, 243);
  assert.strictEqual(LIVE.helpers[1087], "linear_heap_init_worker");
  assert.strictEqual(LIVE.artifact_13.sha256_prefix, "63d9f8a3");
  assert.strictEqual(LIVE.artifact_13.profile, "LIVE_63D9");
  assert.strictEqual(guest.LIVE_63D9.bytes, 1057758);
  assert.strictEqual(guest.LIVE_63D9.codec.load_i32, 859);
  assert.strictEqual(guest.LIVE_63D9.codec.store_i32, 366);
  if (process.env.HCAP_REQUIRE_WASM === "1") {
  assert.ok(
    fs.existsSync(path.join(ROOT, guest.LIVE_63D9.path)),
    "art13 wasm path present"
  );
} else if (!fs.existsSync(path.join(ROOT, guest.LIVE_63D9.path))) {
  console.warn("skip: LIVE_63D9 wasm not shipped (set HCAP_REQUIRE_WASM=1 to require)");
}

  assert.strictEqual(guest.LIVE_E449.sha256.slice(0, 8), "e449a4e1");
  assert.strictEqual(guest.LIVE_E449.bytes, 1030267);
  assert.strictEqual(guest.LIVE_E449.exports.Yc, 1164);
  assert.strictEqual(guest.LIVE_E449.codec.load_i32, 719);
  assert.strictEqual(guest.LIVE_E449.codec.store_i32, 397);
  assert.strictEqual(guest.LIVE_E449.codec.keystream_addr, 468);
  assert.strictEqual(guest.LIVE_E449.hsw_mode[1].worker, 874);
  assert.strictEqual(guest.LIVE_E449.hsw_mode[0].worker, 880);
  assert.strictEqual(guest.LIVE_E449.hsw_mode[2].worker, 727);
  if (process.env.HCAP_REQUIRE_WASM === "1") {
  assert.ok(
    fs.existsSync(path.join(ROOT, guest.LIVE_E449.path)),
    "e449 wasm path present"
  );
} else if (!fs.existsSync(path.join(ROOT, guest.LIVE_E449.path))) {
  console.warn("skip: LIVE_E449 wasm not shipped (set HCAP_REQUIRE_WASM=1 to require)");
}

  console.log("guest_ops_live_fixture: ok");
  console.log(
    JSON.stringify(
      {
        sha: LIVE.sha256.slice(0, 8),
        codec: LIVE.codec,
        yc_role: LIVE.yc_dispatch && LIVE.yc_dispatch.role,
        cff_bind: {
          encrypt: LIVE.cff_hypothesis.encrypt,
          decrypt: LIVE.cff_hypothesis.decrypt,
          update_token: LIVE.cff_hypothesis.update_token,
        },
        func_1087: LIVE.helpers[1087],
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
