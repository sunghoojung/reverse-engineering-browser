/**
 * cff_e449_decrypt.js — Reconstructive JS for LIVE_E449 decrypt path (sha e449a4e1)
 *
 * Path: window.hsw(0) aHz → Yc magic 1668574287 → trampoline 1138 → CFF 880 (102 arms)
 *
 * Arm clusters from classify_arms_874_880.js. Shares ScrambledMemoryE449.
 * Decrypt-only: mba_via_406 @arm 50 (analogue of 63d9 273 @arm 68 / 84feb 710).
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 */

'use strict';

const {
  ScrambledMemoryE449,
  bulkPack537Stub,
  hostAtStub,
  ARM_CLUSTERS_537,
} = require('./cff_e449_encrypt.js');

/**
 * func 1138 — Result trampoline (86 B)
 *   sp-=16; call 880(sp+8, arg); unpack via 719/397; sp+=16
 */
function trampoline1138(dest, handle, mem, globalStack) {
  let sp = globalStack - 16;
  worker880(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * Arm-cluster table for func 880 (102 unique / 103 parsed incl. empty arm0).
 *
 * | cluster              | n  | representative arms                      |
 * |----------------------|---:|---------------------------------------|
 * | codec_bulk_via_537   | 35 | 2,3,4,7,… (+29/7 on entry walk)       |
 * | state_only           | 21 | 10,…,**70**(entry),…                  |
 * | frame_init_slots     | 12 | 28,39,… (slot **1096** family)        |
 * | codec_load_store     | 10 | 5,23,26,…                             |
 * | codec_loopish        |  9 | 6,…,**56**,…                          |
 * | opaque_misc          |  5 | 1,25,43,84,92                         |
 * | unreachable_trap     |  3 | 13,60,102                             |
 * | result_pack_exit     |  3 | 27,53,**71**                          |
 * | mba_via_406          |  1 | **50** (219×32 + 406×17 byte-eq chain)|
 * | host_a_t_gate        |  1 | **90** (takeObject; call 19; state←29)|
 * | early_return         |  1 | 11                                    |
 * | sentinel_branch      |  1 | 8                                     |
 * | empty                |  1 | 0                                     |
 */
const ARM_CLUSTERS_880 = Object.freeze({
  entry: 70,
  host_a_t_gate: 90,
  mba_via_406: 50,
  result_pack_return: Object.freeze([27, 53]),
  result_pack_alt: 71,
  codec_bulk_via_537_n: 35,
  state_only_n: 21,
  frame_init_slots_n: 12,
  frame_slot: 1096,
  note: '406 is decrypt-only here (874 has 0); arm 50 alone holds all 17 calls',
});

/**
 * func 406 — opaque_u8_roundtrip_sp15 (body proven @166577+25).
 * Byte-isomorphic to 63d9 273; 84feb 710 = same core + vacuous 5-arm MBA wrapper:
 *   sp-=16; store_u8(sp, arg, 15) via 364; return load_u8(sp, 15) via 219.
 * Call sites (880 arm 50): 16× (load8 A == load8 B) + 1× final; AND-reduced.
 * See MBA_OPAQUE.md. UNKNOWN: whether always identity after codec XOR cancel.
 */
function opaquePred406(bit) {
  // Structural stub — does not allocate SP or exercise scrambled store/load.
  return (bit | 0) & 1;
}

/**
 * func 880 — decrypt CFF worker (state-machine sketch)
 *
 * Entry state: 70
 * Body: 9594 B @650317
 * Params: 2 (ret_slot, handle) via 1138
 * Locals: 52 i32; state in local 3
 * br_table: 101 arms / 102 unique @650531
 *
 * Intern: 397×156, 719×126, 219×103, 364×70, 988×45, 537×36, 406×17
 * Host: a.t (19) takeObject ×1 @arm 90 — see HOST_GATES.md
 */
function worker880(retSlot, handle, mem, _sp) {
  let state = 70;
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
      case 70: {
        // ENTRY state_only — constsTop 45,56 → force 56
        setState(56, 'entry_to_56');
        break;
      }

      case 56: {
        // codec_loopish — 719×7 + 397×6; next→51
        for (const off of [60, 68]) {
          const v = mem.load32(frame, off);
          mem.store32(frame, v ^ 0, off);
        }
        setState(51, 'after_codec_loopish');
        break;
      }

      case 51:
        setState(29, 'state_only_to_bulk');
        break;

      case 29:
      case 7:
      case 9:
      case 2: {
        // codec_bulk_via_537 — call 537(frame+statusSlot, frame+1096)
        locals[24] = mem.load8(frame, 145);
        bulkPack537Stub(mem, frame + 136, frame + 1096);
        setState(state === 29 ? 12 : 12, 'after_537_bulk');
        break;
      }

      case 12:
      case 82: {
        // state_only chain; break toward mba_via_406
        if (state === 12) setState(82, 'state_only');
        else setState(50, 'break_to_406_hypothesis');
        break;
      }

      case 50: {
        // mba_via_406 — proven 16× (load8 A == load8 B) through 406, AND-reduced
        // Compares bytes near frame[1608..] vs (local4+offset); 219×32, 406×17
        // nextState →58
        let ok = 1;
        const rhs = locals[4] | 0;
        for (let i = 0; i < 16; i++) {
          const a = mem.load8(frame, 1608 + i);
          const b = mem.load8(rhs, i);
          ok &= opaquePred406(a === b ? 1 : 0);
        }
        ok &= opaquePred406(1);
        setState(ok ? 58 : 39, 'after_406_chain');
        break;
      }

      case 58:
        // frame_init overlap / success-ish → host gate hypothesis
        setState(90, 'to_host_t_hypothesis');
        break;

      case 39:
        setState(90, 'fail_or_init_to_host_t');
        break;

      case 90: {
        // host_a_t_gate — proven: local.get 1; call 19; state←29 (takeObject drop)
        hostAtStub(locals[1]);
        setState(71, 'after_a_t_to_pack');
        break;
      }

      case 71: {
        // result_pack_exit alt — stores; sketch toward return packs
        setState(27, 'alt_to_return_pack');
        break;
      }

      case 27:
      case 53: {
        // result_pack_exit — store32×2 via 397; global.set 0
        mem.store32(retSlot, locals[4], 0);
        mem.store32(retSlot, 0, 4);
        return { ok: locals[4], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_880 };
      }

      case 11:
        return { ok: 0, err: 0, flag: 0, trace, early: true, cluster: ARM_CLUSTERS_880 };

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_880,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_880 };
}

/** Legacy stub kept for fixture / require compat */
function cffDecryptE449(_handle, _mem) {
  return {
    worker: 880,
    trampoline: 1138,
    magic: 1668574287,
    entry_state: 70,
    arms: 102,
    glue: 'aHz',
    note: 'use worker880 / trampoline1138 for sketch walk',
  };
}

/** Yc (1164) decrypt arm only — magic 1668574287 → 1138 */
function ycDecryptE449(dest, handle, mem, globalStack) {
  return trampoline1138(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemoryE449Decrypt: ScrambledMemoryE449,
  ScrambledMemoryE449,
  trampoline1138,
  worker880,
  ycDecryptE449,
  cffDecryptE449,
  opaquePred406,
  bulkPack537Stub,
  hostAtStub,
  ARM_CLUSTERS_880,
  ARM_CLUSTERS_537,
  WORKER: 880,
  TRAMPOLINE: 1138,
  MAGIC: 1668574287,
  ENTRY_STATE: 70,
  ARMS: 102,
  GLUE: 'aHz',
  constants: {
    PAGE_SIZE: 320,
    MAGIC: 1668574287,
    WORKER: 880,
    TRAMPOLINE: 1138,
    ENTRY_STATE: 70,
    FRAME_SLOT: 1096,
    BULK: 537,
    MBA: 406,
    HOST_T: 19,
  },
};
