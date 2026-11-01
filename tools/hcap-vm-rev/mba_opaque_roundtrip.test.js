/**
 * mba_opaque_roundtrip.test.js — structural-only checks for opaque u8 helpers.
 *
 * Proves stub identity on {0,1} for 273/406/710 and that ScrambledMemory
 * store8→load8 at SP+15 cancels under the known XOR codec (warm page).
 * Does NOT claim live stack-page warmth for 710/273/406, and does NOT
 * invent MBA / absorb cipher math. See MBA_OPAQUE.md.
 *
 * Run: node /tmp/hcap-vm-rev/mba_opaque_roundtrip.test.js
 */
"use strict";

const assert = require("assert");

const liveDec = require("./cff_live_decrypt.js");
const liveEnc = require("./cff_live_encrypt.js");
const d63 = require("./cff_63d9_decrypt.js");
const e63 = require("./cff_63d9_encrypt.js");
const dE = require("./cff_e449_decrypt.js");
const eE = require("./cff_e449_encrypt.js");

// --- stub identity on synthetic bits (structural) ---
for (const bit of [0, 1]) {
  assert.strictEqual(d63.opaquePred273(bit), bit, "273 stub identity");
  assert.strictEqual(dE.opaquePred406(bit), bit, "406 stub identity");
  assert.strictEqual(liveDec.opaquePred710(bit), bit, "710 stub identity");
}
assert.strictEqual(d63.opaquePred273(0xff) & 1, 1, "273 masks to low bit");
assert.strictEqual(dE.opaquePred406(2) & 1, 0, "406 masks to low bit");

// --- named MBA sample constants exported (unknown cipher — do not invent) ---
assert.strictEqual(liveDec.constants.MBA_I32_710_XOR, 2021161783);
assert.strictEqual(liveDec.constants.OPAQUE_710, 710);
assert.strictEqual(d63.constants.OPAQUE_273, 273);
assert.strictEqual(dE.constants.MBA, 406);

assert.ok(Array.isArray(e63.I64_MBA_SAMPLES_937));
assert.ok(e63.I64_MBA_SAMPLES_937.length >= 4);
assert.strictEqual(e63.I64_MBA_SAMPLES_937[0], 7751723099346266405n);

assert.ok(Array.isArray(eE.I64_MBA_SAMPLES_537));
assert.strictEqual(eE.I64_MBA_SAMPLES_537[0], 3791927442663040578n);

assert.ok(Array.isArray(liveEnc.I64_MBA_SAMPLES_1005));
assert.strictEqual(liveEnc.I64_MBA_SAMPLES_1005[0], 8903399947347151673n);

// --- codec SP+15 store8/load8 cancel (known XOR property; not 273 cipher) ---
function roundtripSp15(Mem) {
  const mem = new Mem(4096);
  const sp = 1024; // synthetic frame base
  for (const b of [0x00, 0x01, 0x5a, 0xa5, 0xff]) {
    mem.store8(sp, b, 15);
    assert.strictEqual(mem.load8(sp, 15), b, `SP+15 cancel 0x${b.toString(16)}`);
  }
}

roundtripSp15(liveEnc.ScrambledMemoryLive);
roundtripSp15(e63.ScrambledMemory63d9);
roundtripSp15(eE.ScrambledMemoryE449);

// isomorphism labels on cluster tables
assert.strictEqual(e63.ARM_CLUSTERS_937.role, "cursor_absorb_mba");
assert.strictEqual(e63.ARM_CLUSTERS_937.vs_1005, "remapped_cousin_different_machine");
assert.strictEqual(eE.ARM_CLUSTERS_537.role, "cursor_absorb_mba");
assert.strictEqual(eE.ARM_CLUSTERS_537.vs_937, "remapped_cousin_smaller_machine");

console.log("ok", {
  opaque_u8: { "84feb": 710, "63d9": 273, e449: 406, verdict: "same_sp15_core" },
  bulk: { "84feb": 1005, "63d9": 937, e449: 537, verdict: "not_isomorphic" },
  samples: {
    i32_710: liveDec.constants.MBA_I32_710_XOR,
    i64_937_n: e63.I64_MBA_SAMPLES_937.length,
    i64_537_n: eE.I64_MBA_SAMPLES_537.length,
    i64_1005_n: liveEnc.I64_MBA_SAMPLES_1005.length,
  },
});
