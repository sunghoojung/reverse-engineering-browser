"use strict";

const assert = require("assert");
const hsw = require("./guest_ops.js");

assert.strictEqual(hsw.HOST_IMPORTS.length, 191, "191 wasm imports on module a (glue catalog)");
assert.strictEqual(hsw.HOST_IMPORTS[0].name, "a");
assert.strictEqual(hsw.HOST_IMPORTS[133].name, "zb");
assert.strictEqual(hsw.HOST_IMPORTS[158].name, "Yb");
assert.strictEqual(hsw.CLICK_WASM.imported_functions, 190);

assert.strictEqual(hsw.hswModeDispatch(0).name, "decrypt");
assert.strictEqual(hsw.hswModeDispatch(1).name, "encrypt");
assert.strictEqual(hsw.hswModeDispatch(2).name, "update_token");
assert.strictEqual(hsw.hswModeDispatch("eyJhbGciOiJub25lIn0.e30.").name, "proof_uc");
assert.strictEqual(hsw.hswModeDispatch(0, false).magic, hsw.MAGIC.decrypt_resp_data);
assert.strictEqual(hsw.hswModeDispatch(1, false).magic, hsw.MAGIC.encrypt_req_data);
assert.strictEqual(hsw.hswModeDispatch(0).magic, hsw.LIVE_MAGIC.decrypt_resp_data);
assert.strictEqual(hsw.hswModeDispatch(1).magic, hsw.LIVE_MAGIC.encrypt_req_data);
assert.strictEqual(hsw.LIVE_84FEB.host_gates.semantic, "takeObject_drop_handle");
assert.strictEqual(hsw.LIVE_63D9.host_gates.gate_idx, 190);
assert.strictEqual(hsw.LIVE_E449.host_gates.gate_import, "t");

const mem = new hsw.LinearMemory(1 << 16);
assert.deepStrictEqual(
  Array.from(mem.buf.slice(4, 20)),
  hsw.PERM_TABLE.slice(),
  "perm table seeded"
);

assert.strictEqual(hsw.chunkDescriptor(0, mem), 1024 + 9 * hsw.CHUNK);
assert.strictEqual(hsw.addrKeystream(0, mem), hsw.addrKeystream(96, mem), "96-byte period");

hsw.store_i32(mem, 0, 0x12345678, 16);
const k16 = Number(hsw.addrKeystream(16, mem) & 0xffffffffn) | 0;
assert.strictEqual(hsw.load_i32(mem, 0, 16), (0x12345678 ^ k16) | 0, "cached page holds xor ciphertext");
assert.strictEqual((hsw.load_i32(mem, 0, 16) ^ k16) | 0, 0x12345678, "cached xor roundtrip");

hsw.store_i32(mem, 0, -1, 314);
const k314 = Number(hsw.addrKeystream(314, mem) & 0xffffffffn) | 0;
assert.strictEqual((hsw.load_i32(mem, 0, 314) ^ k314) | 0, -1, "split-page roundtrip rem>316");

const uncached = new hsw.LinearMemory(1 << 16);
const addr = 40;
const key = Number(hsw.addrKeystream(addr, uncached) & 0xffffffffn) | 0;
assert.strictEqual(hsw.load_i32(uncached, 0, addr), key, "uncached load returns wrap(keystream)");

const cff = hsw.cffLoop(2, {
  2: () => 5,
  5: () => 9,
  9: () => "halt",
});
assert.strictEqual(cff.state, 9);
assert.strictEqual(cff.steps, 3);

const enc = hsw.cffEncrypt(1, mem);
assert.strictEqual(enc.intern.load, 329);
assert.strictEqual(enc.intern.store, 1129);
assert.strictEqual(enc.intern.worker, 585);
assert.strictEqual(enc.intern.arms, 251);
assert.strictEqual(enc.intern.load8, 867);
assert.ok(enc.steps >= 2);

const dec = hsw.cffDecrypt(2, mem);
assert.strictEqual(dec.intern.trampoline, 967);
assert.strictEqual(dec.intern.worker, 612);
assert.strictEqual(dec.intern.arms, 133);
assert.strictEqual(dec.path.includes("func612"), true);

const alt = hsw.cffAlt(3, mem);
assert.strictEqual(alt.intern.trampoline, 656);
assert.strictEqual(alt.intern.worker, 630);
assert.strictEqual(alt.intern.role, "unknown");

hsw.store_i8(mem, 0, 0xab, 20);
assert.strictEqual(hsw.load_u8(mem, 0, 20), 0xab, "func 867 returns plaintext u8");

assert.strictEqual(hsw.CLICK_WASM.cff.encrypt.worker, 585);
assert.strictEqual(hsw.CLICK_WASM.cff.decrypt.worker, 612);
assert.strictEqual(hsw.CLICK_WASM.codec.load_u8, 867);
assert.strictEqual(hsw.CLICK_WASM.codec.store_f32, 799);
assert.strictEqual(hsw.CLICK_WASM.codec.store_f64, 642);
assert.strictEqual(hsw.HSW_MODE[0].click.worker, 612);
assert.strictEqual(hsw.HSW_MODE[1].click.worker, 585);
assert.strictEqual(hsw.CLICK_WASM.cff.nested[816].arms, 20);
assert.strictEqual(hsw.CLICK_WASM.cff.nested[816].role, "vec_or_slice_cursor");
assert.strictEqual(hsw.CLICK_WASM.cff.nested[683].arms, 34);
assert.strictEqual(hsw.CLICK_WASM.cff.nested[343].callee, 356);
assert.strictEqual(hsw.CLICK_WASM.cff.nested[815].role, "opaque_u8_roundtrip");

const digest = new Uint8Array(20);
assert.strictEqual(hsw.checkLeadingZeroBits(digest, 8), true);
digest[(hsw.POW.ROTATION + 0) % 20] = 1;
assert.strictEqual(hsw.checkLeadingZeroBits(digest, 8), false);

assert.strictEqual(hsw.CLICK_SESSION.getcaptcha_json_bytes, 822);
assert.strictEqual(hsw.CLICK_SESSION.postclick_octet_stream_bytes, 2613);
assert.strictEqual(hsw.CLICK_SESSION.challenge, "image_drag_drop");
assert.strictEqual(hsw.OCTET_ENVELOPE.byteLength, 2613);
assert.strictEqual(hsw.OCTET_ENVELOPE.fieldLayout, "unknown");

assert.strictEqual(hsw.CLICK_WASM.exports.Xc, 1158);
assert.strictEqual(hsw.CLICK_WASM.exports.Wc, 1157);
assert.strictEqual(hsw.CLICK_WASM.codec.keystream, 1014);

hsw
  .hsw(0, { n: 1 })
  .then((r0) => {
    assert.strictEqual(r0.worker, 298);
    assert.ok(String(r0.path).includes("777/298"));
    assert.ok(r0.clickFallback.path.includes("decrypt"));
    return hsw.hsw(1, { n: 2 });
  })
  .then((r1) => {
    assert.strictEqual(r1.worker, 796);
    assert.ok(String(r1.path).includes("1103/796"));
    assert.ok(r1.clickFallback.path.includes("encrypt"));
    return hsw.hsw(2, "tok", 1.5);
  })
  .then((r2) => {
    assert.strictEqual(r2.token, "tok");
    return hsw.hsw("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.sig", { k: 1 });
  })
  .then((jwt) => {
    assert.strictEqual(jwt.path, "Uc/func491/func659");
    assert.ok(jwt.payloadBytes > 0);
    console.log("ok", {
      imports: hsw.HOST_IMPORTS.length,
      clickImports: hsw.CLICK_WASM.imported_functions,
      modes: [0, 1, 2, "jwt"].map((m) => hsw.hswModeDispatch(m).name),
      page: hsw.PAGE,
      keystream: "table96",
      cff: { encrypt: 585, decrypt: 612, alt: 630 },
      host_gates: {
        "84feb": hsw.LIVE_84FEB.host_gates.gate_import,
        "63d9": hsw.LIVE_63D9.host_gates.gate_import,
        e449: hsw.LIVE_E449.host_gates.gate_import,
      },
    });
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
