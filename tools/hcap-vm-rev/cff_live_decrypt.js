/**
 * cff_live_decrypt.js — Reconstructive JS for live HSW decrypt path (sha84febfac)
 *
 * Path: window.hsw(0) akZ → Yc magic -1874150846 → trampoline 777 → CFF 298 (115 arms)
 *
 * Mirrors cff_live_encrypt.js; shares ScrambledMemoryLive.
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 */

'use strict';

const { ScrambledMemoryLive } = require('./cff_live_encrypt.js');

/**
 * func 777 — Result trampoline (86 B), isomorphic to 1103
 *   sp-=16; call 298(sp+8, arg); unpack via 438/582; sp+=16
 */
function trampoline777(dest, handle, mem, globalStack) {
  let sp = globalStack - 16;
  worker298(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * Arm-cluster table for func 298 (115 unique / 116 parsed incl. empty arm0).
 * Source: classify_arms_298_796.js over out_84feb/helpers.txt.
 *
 * | cluster              | n  | representative arms                      |
 * |----------------------|---:|---------------------------------------|
 * | codec_bulk_via_1005  | 38 | 7,16,17,18,25,… (+ arm 90 on entry walk)|
 * | state_only           | 33 | 2,6,8,9,…,71,73,74,76,87,…            |
 * | codec_loopish        | 10 | 14,23,38,48,52,77,78,98,101,112       |
 * | frame_init_slots     |  9 | 5,11,21(entry),51,53,57,66,91,94      |
 * | codec_load_store     |  9 | 13,27,29,30,41,63,79,97,100           |
 * | opaque_misc          |  6 | 4,46,62,86,89,111                     |
 * | unreachable_trap     |  3 | 10,72,115                             |
 * | result_pack_exit     |  2 | 3 (return), 22 (mid SP adjust)        |
 * | codec_i64_byte_mix   |  2 | 54,65                                 |
 * | mba_via_710          |  1 | 19 (710×17 byte-eq opaque chain)      |
 * | host_a_Va_gate       |  1 | 85 (local.get 1; call 101; state←2)   |
 * | sentinel_branch      |  1 | 1                                     |
 * | empty                |  1 | 0                                     |
 */
const ARM_CLUSTERS_298 = Object.freeze({
  entry: 21,
  host_a_Va_gate: 85,
  mba_via_710: 19,
  result_pack_return: 3,
  result_pack_alt: 22,
  codec_bulk_via_1005_n: 38,
  state_only_n: 33,
  frame_init_slots_n: 9,
  note: '710 is decrypt-only here (796 has 0); arm 19 alone holds all 17 calls',
});

/**
 * func 710 — opaque_u8_roundtrip_sp15 with vacuous 5-arm MBA wrapper.
 * Body proven @544701+146 (out_84feb/helpers.txt):
 *   state0 MBA fork → arms 2|3 (identical SP+15):
 *     sp-=16; store_u8(sp,arg,15) via 957; load_u8(sp,15) via 859 → state1 → return
 * Core isomorphic to 63d9 273 / e449 406 (those are linear 25 B, no mini-CFF).
 * MBA i32 samples: MBA_I32_710_* below — unknown cipher — do not invent.
 * UNKNOWN: whether live SP+15 always cancels under XOR codec.
 */
function opaquePred710(bit) {
  // Structural stub: arms 2|3 are identical; observable = identity on the bit.
  return (bit | 0) & 1;
}

/**
 * func 298 — decrypt CFF worker (state-machine sketch)
 *
 * Entry state: 21
 * Body: 10218 B @113051
 * Params: 2 (ret_slot, handle) via 777
 * Locals: 57 i32; state in local 3
 * br_table: 114 arms / 115 unique @113290
 *
 * Intern (full-body): 582×138, 438×115, 859×109, 957×85, 858×70, 1005×39, 710×17
 * Host: a.Va (101) ×1 @arm 85
 */
function worker298(retSlot, handle, mem, _sp) {
  let state = 21;
  const locals = new Int32Array(59);
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
      case 21: {
        // ENTRY frame_init_slots — proven shape:
        //   tee frame+1080; call 454; call 231; several load32/xor/store32 pairs;
        //   call 598; branch 46 if local6==384 else 90
        // UNKNOWN: 454/231/598 roles; meaning of 384 threshold
        const base = (frame + 1080) | 0;
        for (const off of [0, 68, 84, 88]) {
          const p = (base + off) | 0;
          const v = mem.load32(p, 0);
          mem.store32(p, v ^ -1, 0);
        }
        const eq384 = (locals[6] | 0) === 384;
        setState(eq384 ? 46 : 90, 'entry_frame_init');
        break;
      }

      case 46:
        // opaque_misc — UNKNOWN
        setState(90, 'rejoin_bulk_UNKNOWN');
        break;

      case 90: {
        // codec_bulk_via_1005 — proven: load8(frame,33); call 1005(frame+24, frame+1080);
        //   branch 107 if load8(frame,24) else 71
        locals[44] = mem.load8(frame, 33);
        // UNKNOWN: 1005 plaintext/ciphertext semantics
        mem.store8(frame, 0, 24); // stub status byte
        setState(71, 'after_1005_status0');
        break;
      }

      case 71: {
        // state_only — proven: if local30 then 71 else 5
        setState(locals[30] ? 71 : 5, 'gate_local30');
        if (state === 71 && steps > 3) setState(5, 'break_self_loop_sketch');
        break;
      }

      case 5: {
        // frame_init_slots — heavy store8×16 (957) + store32 — UNKNOWN layout
        for (let i = 0; i < 16; i++) mem.store8(frame, 0, 200 + i);
        setState(65, 'after_byte_init');
        break;
      }

      case 65: {
        // codec_i64_byte_mix — proven heavy 858×31 then →10
        for (let i = 0; i < 4; i++) mem.store64(frame, 0n, 1600 + i * 8);
        setState(19, 'to_710_memcmp_sketch');
        break;
      }

      case 19: {
        // mba_via_710 — proven 16× (load8 A == load8 B) funneled through 710, AND-reduced
        // Compares frame[1592..1607] vs bytes at (local5+local7) — opaque memcmp
        let ok = 1;
        const rhs = ((locals[5] | 0) + (locals[7] | 0)) | 0;
        for (let i = 0; i < 16; i++) {
          const a = mem.load8(frame, 1592 + i);
          const b = mem.load8(rhs, i);
          ok &= opaquePred710(a === b ? 1 : 0) & 1;
        }
        ok &= opaquePred710(1) & 1;
        // Real: if (ok & 255) state←23 else ←40
        setState(ok ? 23 : 40, 'after_710_chain');
        break;
      }

      case 23:
      case 40:
        // UNKNOWN post-memcmp paths
        setState(85, 'to_Va_gate_hypothesis');
        break;

      case 85: {
        // host_a_Va_gate — proven: local.get 1; call 101; state←2
        // a.Va = takeObject drop (art4 arK); see HOST_GATES.md
        hostVaStub(locals[1]);
        setState(2, 'after_a_Va');
        break;
      }

      case 2: {
        // state_only — proven: if local4 then 93 else 0
        setState(locals[4] ? 93 : 0, 'post_Va_flag');
        break;
      }

      case 93:
        // UNKNOWN success-ish path toward pack
        setState(3, 'to_result_pack');
        break;

      case 0:
        // UNKNOWN zero-path; may error
        setState(3, 'zero_path_pack_hypothesis');
        break;

      case 3: {
        // result_pack_exit — proven return
        // store32(ret, local4, 4); store32(ret, local6, 0); sp = frame+2112; return
        mem.store32(retSlot, locals[4], 4);
        mem.store32(retSlot, locals[6], 0);
        return { ok: locals[6], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_298 };
      }

      case 22:
        // Alternate: SP adjust via global.set 0 then state←71 — UNKNOWN
        setState(71, 'alt_sp_adjust');
        break;

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_298,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_298 };
}

/** a.Va (import 101) — takeObject / drop heap handle; return unused */
function hostVaStub(handle) {
  return handle | 0;
}

/** Yc (1166) decrypt arm only — magic -1874150846 → 777 */
function ycDecrypt(dest, handle, mem, globalStack) {
  return trampoline777(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemoryLive,
  trampoline777,
  worker298,
  ycDecrypt,
  opaquePred710,
  hostVaStub,
  ARM_CLUSTERS_298,
  constants: {
    MAGIC: -1874150846,
    YC: 1166,
    TRAMPOLINE: 777,
    WORKER: 298,
    ARMS: 115,
    ENTRY_STATE: 21,
    HOST_VA: 101,
    STORE8: 957,
    LOAD8: 859,
    STORE64: 858,
    BULK: 1005,
    OPAQUE_710: 710,
    // unknown cipher — do not invent (710 vacuous MBA i32 samples)
    MBA_I32_710_XOR: 2021161783,
    MBA_I32_710_MUL: -129149119,
    MBA_I32_710_SUB: 1245555740,
    MBA_I32_710_AND_LO: -620431147,
    MBA_I32_710_AND_HI: 620431146,
  },
  /** Cross-build analogue map (structural; ids remapped per sha). */
  analogues63d9: Object.freeze({
    worker: 349,
    load_u8: 863,
    store_u8: 1026,
    store_i64: 637,
    store_i16: 1154,
    bulk: 937,
    mba: 273,
    host_gate: 'a.Cc/190 takeObject',
    host_thunk: '218→a.hc/169 new Uint8Array(size)',
    note: '273 body is store8/load8 SP+15 (linear; 710 adds vacuous mini-CFF)',
  }),
  analoguesE449: Object.freeze({
    worker: 880,
    bulk: 537,
    mba: 406,
    note: '406 ≡ 273 linear SP+15; see MBA_OPAQUE.md',
  }),
  unknowns: [
    'Full transition graph among 115 arms (entry walk + notables sketched)',
    'Roles of 454 / 231 / 598 / 974 / 1085 around arm 21/19',
    'Whether 710 SP+15 cancels under XOR codec on the live stack page',
    '1005 lane layout / any response plaintext reconstruction',
    'Cipher math — intentionally not invented',
  ],
};
