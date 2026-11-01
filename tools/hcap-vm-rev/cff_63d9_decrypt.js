/**
 * cff_63d9_decrypt.js — Reconstructive JS for LIVE_63D9 decrypt path (sha63d9f8a3)
 *
 * Path: window.hsw(0) bbD → Yc magic -174010464 → gated entry 377 → CFF 349 (113 arms)
 *
 * Arm clusters from classify_arms_349_667.js. Shares ScrambledMemory63d9.
 * Decrypt-only: mba_via_273 @arm 68 (analogue of 84feb 710 @arm 19).
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 */

'use strict';

const {
  ScrambledMemory63d9,
  bulkPack937Stub,
  hostCcStub,
  hostNewUint8ArrayStub,
} = require('./cff_63d9_encrypt.js');

/**
 * func 377 — Gated decrypt entry (319 B), not a pure 86 B Result trampoline.
 *
 * Outer: 5-arm br_table + MBA gate, then Result unpack:
 *   sp-=16; call 349(sp+8, arg); unpack via 859/366; sp+=16
 * Intern: 366×6, 859×4, 349×2
 * MBA consts: 2058845549, -1107079157, 762594893, 1875421008, …
 */
function trampoline377(dest, handle, mem, globalStack) {
  // MBA / br_table gate omitted — structure only reaches the Result path
  let sp = globalStack - 16;
  worker349(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * Arm-cluster table for func 349 (113 unique / 114 parsed incl. empty arm0).
 *
 * | cluster              | n  | representative arms                      |
 * |----------------------|---:|---------------------------------------|
 * | state_only           | 34 | 5,7,11,…,**52**(entry),…              |
 * | codec_bulk_via_937   | 33 | 2,3,4,6,8,… (+14/67 on entry walk)    |
 * | codec_loopish        | 12 | 9,12,18,35,…                          |
 * | codec_load_store     | 10 | 1,10,13,**22**,23,…                   |
 * | frame_init_slots     |  7 | 19,40,55,61,78,80,86 (slot **1112**)  |
 * | opaque_misc          |  4 | 24,62,93,107                          |
 * | unreachable_trap     |  3 | 17,66,113                             |
 * | result_pack_exit     |  3 | 53,70,100                             |
 * | mba_via_273          |  1 | **68** (863×32 + 273×17 byte-eq chain)|
 * | host_a_Cc_gate       |  1 | **92** (takeObject; call 190; state←57)|
 * | call_218_new_u8array |  1 | **54** (218→a.hc Uint8Array; state←0) |
 * | call_1154_store16    |  1 | **99** (637×37 + 1154; state←65)      |
 * | early_return         |  1 | 96                                    |
 * | sentinel_branch      |  1 | 98                                    |
 * | codec_byte_rw        |  1 | 110                                   |
 * | empty                |  1 | 0                                     |
 */
const ARM_CLUSTERS_349 = Object.freeze({
  entry: 52,
  host_a_Cc_gate: 92,
  mba_via_273: 68,
  call_218_new_u8array: 54,
  call_1154_store16: 99,
  result_pack_return: Object.freeze([70, 100]),
  result_pack_alt: 53,
  codec_bulk_via_937_n: 33,
  state_only_n: 34,
  frame_init_slots_n: 7,
  frame_slot: 1112,
  note: '273 is decrypt-only here (667 has 0); arm 68 alone holds all 17 calls',
});

/**
 * func 273 — opaque_u8_roundtrip_sp15 (body proven @46672+25).
 * SP-=16; store8(SP, bit, 15) via 1026; return load8(SP, 15) via 863.
 * Isomorphic to e449 406; 84feb 710 = same core + vacuous 5-arm MBA wrapper.
 * Used as AND-chain wrapper on i32.eq. See MBA_OPAQUE.md.
 * UNKNOWN: whether always identity after codec XOR cancel on stack page.
 */
function opaquePred273(bit) {
  // Structural mirror of the SP+15 store8/load8 pair — no MBA invented
  return (bit | 0) & 1;
}

/**
 * func 349 — decrypt CFF worker (state-machine sketch)
 *
 * Entry state: 52
 * Body: 9464 B @98150
 * Params: 2 (ret_slot, handle) via 377
 * Locals: 50 i32; state in local 3
 * br_table: 112 arms / 113 unique @98385
 *
 * Intern: 366×142, 859×114, 863×99, 1026×66, 637×42, 937×34, 273×17
 * Host: a.Cc (190) takeObject ×1 @arm 92; via 218→a.hc new Uint8Array @arm 54
 */
function worker349(retSlot, handle, mem, _sp) {
  let state = 52;
  const locals = new Int32Array(52);
  locals[0] = retSlot;
  locals[1] = handle;
  let frame = _sp | 0;
  locals[2] = frame;
  let steps = 0;
  const trace = [];

  const setState = (n, why) => {
    trace.push({ from: state, to: n, why });
    state = n;
  };

  while (steps++ < 64) {
    switch (state) {
      case 52: {
        // ENTRY state_only — proven MBA consts then force state 22
        // constsTop: 1405340959, 225293289, 1173542695, 46, 22
        locals[7] = Math.imul(locals[7] | 0, 1405340959) + 225293289;
        setState(22, 'entry_mba_to_22');
        break;
      }

      case 22: {
        // codec_load_store — proven: one load32; next→14
        locals[4] = mem.load32(locals[1], 0);
        setState(14, 'after_handle_load');
        break;
      }

      case 14:
      case 67:
      case 2:
      case 3: {
        // codec_bulk_via_937 — call 937(frame+statusSlot, frame+1112); statusSlot varies
        locals[24] = mem.load8(frame, 81);
        bulkPack937Stub(mem, frame + 72, frame + 1112);
        setState(state === 14 ? 65 : 65, 'after_937_bulk');
        break;
      }

      case 65:
      case 90: {
        // state_only chain on linear walk 65→90→67→65 (cycle) — break toward notables
        if (state === 65) setState(90, 'state_only');
        else setState(68, 'break_cycle_to_273_hypothesis');
        break;
      }

      case 68: {
        // mba_via_273 — proven 16× (load8 A == load8 B) funneled through 273, AND-reduced
        // Compares bytes near frame[1624..] vs (local4+offset); 863×32, 273×17
        // Real nextState sketch →72 (may be computed on other path)
        let ok = 1;
        const rhs = locals[4] | 0;
        for (let i = 0; i < 16; i++) {
          const a = mem.load8(frame, 1624 + i);
          const b = mem.load8(rhs, i);
          ok &= opaquePred273(a === b ? 1 : 0);
        }
        ok &= opaquePred273(1);
        setState(ok ? 72 : 40, 'after_273_chain');
        break;
      }

      case 72:
        // UNKNOWN post-memcmp success-ish; hypothesis join toward Cc / pack
        setState(92, 'to_Cc_gate_hypothesis');
        break;

      case 40:
        // UNKNOWN post-memcmp fail-ish OR frame_init overlap — sketch to Cc
        setState(92, 'fail_or_init_to_Cc_hypothesis');
        break;

      case 92: {
        // host_a_Cc_gate — proven: local.get 1; call 190; state←57
        hostCcStub(locals[1]);
        setState(57, 'after_a_Cc');
        break;
      }

      case 57: {
        // codec_bulk_via_937 member (cluster) — UNKNOWN live successor after Cc
        setState(99, 'to_1154_hypothesis');
        break;
      }

      case 99: {
        // call_1154_store16 — proven: 637×37 lane pack + call 1154(frame, 55086, 1076); state←65
        for (let i = 0; i < 4; i++) mem.store64(frame, 0n, 1056 + i * 8);
        mem.store16(frame, 55086, 1076);
        setState(54, 'after_1154_to_218_hypothesis');
        break;
      }

      case 54: {
        // call_218_new_u8array — proven: call 218(local7); tee; store @2104; state←0
        locals[4] = hostNewUint8ArrayStub(locals[7] | 0);
        mem.store32(frame, locals[4], 2104);
        setState(0, 'after_new_Uint8Array');
        break;
      }

      case 0:
        // early path after 218 — UNKNOWN; sketch toward pack
        setState(70, 'to_result_pack');
        break;

      case 70:
      case 100: {
        // result_pack_exit — proven: store32×2 via 366; global.set 0 (sp=frame+2144); →95
        mem.store32(retSlot, locals[4], 4);
        mem.store32(retSlot, locals[6], 0);
        return { ok: locals[6], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_349 };
      }

      case 53:
        // Alternate SP adjust pack →65 — UNKNOWN
        setState(65, 'alt_sp_adjust');
        break;

      case 19:
        // frame_init_slots representative (slot 1112)
        mem.store32(frame, 0, 1112);
        setState(14, 'frame_init_to_bulk');
        break;

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_349,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_349 };
}

/** Yc (1170) decrypt arm only — magic -174010464 → 377 */
function ycDecrypt(dest, handle, mem, globalStack) {
  return trampoline377(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemory63d9,
  trampoline377,
  worker349,
  ycDecrypt,
  opaquePred273,
  ARM_CLUSTERS_349,
  constants: {
    MAGIC: -174010464,
    YC: 1170,
    TRAMPOLINE: 377,
    WORKER: 349,
    ARMS: 113,
    ENTRY_STATE: 52,
    HOST_CC: 190,
    HOST_HC: 169,
    THUNK_218: 218,
    LOAD_I32: 859,
    STORE_I32: 366,
    LOAD8: 863,
    STORE8: 1026,
    STORE16: 1154,
    STORE64: 637,
    BULK: 937,
    OPAQUE_273: 273,
    MARK_DIRTY: 1134,
    KEYSTREAM: 217,
    PAGE_TABLE: 518,
  },
  unknowns: [
    'Full transition graph among 113 arms (entry walk + notables sketched)',
    'MBA gate constants / arm map inside func 377',
    'Whether 273 is pure identity after store8/load8 cancel',
    '937 i64 MBA constants / absorb+rotl cipher identity (arms lifted; math opaque)',
    'Cipher math — intentionally not invented',
  ],
};
