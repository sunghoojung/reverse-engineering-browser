/**
 * cff_e449_encrypt.js — Reconstructive JS for LIVE_E449 encrypt path (sha e449a4e1)
 *
 * Path: window.hsw(1) aJp → Yc magic 1908833735 → trampoline 1068 → CFF 874 (120 arms)
 *
 * Arm clusters from classify_arms_874_880.js over helpers_e449.txt.
 * Helper bodies proven: 219=load_u8, 364=store_u8, 988=store_i64, 537=nested bulk CFF.
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 */

'use strict';

const PAGE_SIZE = 320;

class ScrambledMemoryE449 {
  constructor(size = 1024 * 1024) {
    this.data = new Uint8Array(size);
    this.descriptors = new Map();
    // LIVE_E449 tables: perm @4, keystream @468 period 96
    this.perm = null;
    this.keystreamTable = null;
  }

  // func 600
  getDescriptor(chunkIndex) {
    if (!this.descriptors.has(chunkIndex)) {
      this.descriptors.set(chunkIndex, {
        dirty: false,
        keystream: this._computeKeystream(chunkIndex * PAGE_SIZE),
      });
    }
    return this.descriptors.get(chunkIndex);
  }

  // func 323: i64.load(468 + addr%96)
  _computeKeystream(addr) {
    return BigInt(addr * 0x5851f42d4c957f2d + 0x14057b7ef767814f);
  }

  // func 404
  markDirty(chunkIndex) {
    this.getDescriptor(chunkIndex).dirty = true;
  }

  // func 719 — load_i32
  load32(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this._rawLoad32(addr);
    return (raw ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
  }

  // func 397 — store_i32
  store32(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor(addr / PAGE_SIZE);
    this.markDirty(chunk);
    this.markDirty(chunk + 1);
    const scrambled = (value ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
    this._rawStore32(addr, scrambled);
  }

  /** func 364 — store_u8 XOR (body proven) */
  store8(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor((addr >>> 0) / PAGE_SIZE);
    this.markDirty(chunk);
    const ks = Number(this._computeKeystream(addr) & 0xffn);
    this.data[addr >>> 0] = (value ^ ks) & 0xff;
  }

  /** func 219 — load_u8 XOR & 255 (body proven) */
  load8(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this.data[addr >>> 0] || 0;
    const ks = Number(this._computeKeystream(addr) & 0xffffffffn);
    return ((raw ^ ks) & 0xff) | 0;
  }

  /**
   * func 988 / export Qc — store_i64 XOR rem>312 (body proven)
   * Isomorphic to 63d9 637 / 84feb 858.
   */
  store64(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor((addr >>> 0) / PAGE_SIZE);
    this.markDirty(chunk);
    this.markDirty(chunk + 1);
    const ks = this._computeKeystream(addr);
    const scrambled = BigInt(value) ^ ks;
    const rem = (addr >>> 0) % PAGE_SIZE;
    if (rem > 312) {
      for (let i = 0; i < 8; i++) {
        this.data[((addr >>> 0) + i) >>> 0] = Number((scrambled >> BigInt(8 * i)) & 0xffn);
      }
    } else {
      const dv = new DataView(this.data.buffer, addr >>> 0);
      dv.setBigUint64(0, scrambled & 0xffffffffffffffffn, true);
    }
  }

  /** func 1113 — store_i16 XOR rem>318 */
  store16(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor((addr >>> 0) / PAGE_SIZE);
    this.markDirty(chunk);
    this.markDirty(chunk + 1);
    const ks = Number(this._computeKeystream(addr) & 0xffffffffn);
    const scrambled = (value ^ ks) & 0xffff;
    const rem = (addr >>> 0) % PAGE_SIZE;
    if (rem > 318) {
      this.data[addr >>> 0] = scrambled & 0xff;
      this.data[((addr >>> 0) + 1) >>> 0] = (scrambled >>> 8) & 0xff;
    } else {
      const dv = new DataView(this.data.buffer, addr >>> 0);
      dv.setUint16(0, scrambled, true);
    }
  }

  _rawLoad32(addr) {
    const a = addr >>> 0;
    const d = this.data;
    return (d[a] | (d[a + 1] << 8) | (d[a + 2] << 16) | (d[a + 3] << 24)) | 0;
  }

  _rawStore32(addr, value) {
    const a = addr >>> 0;
    const v = value | 0;
    this.data[a] = v & 0xff;
    this.data[a + 1] = (v >>> 8) & 0xff;
    this.data[a + 2] = (v >>> 16) & 0xff;
    this.data[a + 3] = (v >>> 24) & 0xff;
  }
}

/**
 * Arm-cluster table for func 874 (120 unique / 121 parsed incl. empty arm0).
 * Source: classify_arms_874_880.js over helpers_e449.txt.
 *
 * | cluster              | n  | representative arms                         |
 * |----------------------|---:|------------------------------------------|
 * | codec_bulk_via_537   | 35 | 3,4,8,13,… (+91/40 on entry walk)        |
 * | state_only           | 23 | 1,5,…,**103**(entry),…                   |
 * | codec_loopish        | 16 | 2,6,…,**112**,…                          |
 * | opaque_misc          | 13 | 12,16,20,…                               |
 * | frame_init_slots     | 12 | 7,10,11,… (slot **1100** family)         |
 * | codec_load_store     | 12 | 23,39,46,…                               |
 * | unreachable_trap     |  5 | 35,36,62,98,120                          |
 * | result_pack_exit     |  2 | **107** (return), **104** (alt)          |
 * | host_a_t_gate        |  1 | **41** (call 19; state←106)              |
 * | sentinel_branch      |  1 | 9                                        |
 * | empty                |  1 | 0                                        |
 */
const ARM_CLUSTERS_874 = Object.freeze({
  entry: 103,
  host_a_t_gate: 41,
  result_pack_return: 107,
  result_pack_alt: 104,
  codec_bulk_via_537_n: 35,
  state_only_n: 23,
  frame_init_slots_n: 12,
  frame_slot: 1100,
  note: '537×36 total across bulk arms; 406 absent on encrypt (decrypt-only)',
});

/**
 * func 1068 — Result trampoline (86 B)
 *   sp-=16; call 874(sp+8, arg); unpack via 719/397; sp+=16
 */
function trampoline1068(dest, handle, mem, globalStack) {
  let sp = globalStack - 16;
  worker874(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * func 537 — nested 11-arm CFF (entry state defaults to 0).
 *
 * Body @286484+689; params 2; locals 6 i32 + 11 i64; state local 2.
 * Intern: 719×8, 397×6, 364×2, 219×1 — **no** store_i64 988.
 *
 * Call shape (parents 874/880): `537(frame+statusSlot, frame+cursorSlot)`
 *   statusSlot example 80; cursorSlot = 1100 (874) / 1096 (880).
 *
 * vs 63d9 937: **remapped cousin / smaller machine** (not isomorphic).
 *   Shared: nested CFF/bulk, bounds 0/4/8/12, exit store8×2, zero store_i64.
 *   Different: 11 vs 17 arms; absorb+i64 MBA folded into arm 9 (937 splits).
 * vs 84feb 1005: **remapped cousin / different machine** (1005 = i64 lane pack).
 *
 * Role: `cursor_absorb_mba`. Cipher identity UNKNOWN — do not invent.
 * Arm table: arm_clusters_537.json / ARM_CLUSTERS_537 below.
 */
const ARM_CLUSTERS_537 = Object.freeze({
  entry: 0,
  exit: 6,
  n_arms: 11,
  state_local: 2,
  role: 'cursor_absorb_mba',
  vs_937: 'remapped_cousin_smaller_machine',
  vs_1005: 'remapped_cousin_different_machine',
  byCluster: Object.freeze({
    codec_load_bounds: Object.freeze([0]),
    state_pred_eq: Object.freeze([1]),
    state_only: Object.freeze([2, 3]),
    codec_store_cursor: Object.freeze([4]),
    state_pred_nz: Object.freeze([5]),
    exit_store8_status: Object.freeze([6]),
    codec_store_len0: Object.freeze([7]),
    cursor_advance: Object.freeze([8]),
    codec_absorb_mba: Object.freeze([9]),
    unreachable_trap: Object.freeze([10]),
  }),
  cursor_fields: Object.freeze({
    begin: 0,
    end_or_mark: 4,
    len_or_cap: 8,
    limit: 12,
    counter: 16,
    secondary: 20,
  }),
  note:
    'i64 MBA consts opaque — not simplified; folded into arm 9; see I64_MBA_SAMPLES_537 (unknown cipher — do not invent)',
});

/** Big i64 samples from 537 absorb+MBA arm 9 — unknown cipher — do not invent. */
const I64_MBA_SAMPLES_537 = Object.freeze([
  3791927442663040578n,
  -7715504215185997053n,
  6807663086000598086n,
  2083539279290623862n,
  -8556353375204585132n,
  -3923576772522956476n,
  7715504215185997054n,
  8140823624271946208n,
]);

/**
 * Named-arm structural walk for 537. Does **not** evaluate MBA / absorb cipher math.
 * Returns a trace of arm labels + writes a zero status to dst (store8×2 shape).
 */
function bulkPack537Stub(mem, dst, src) {
  const trace = [];
  let state = ARM_CLUSTERS_537.entry;
  let steps = 0;
  const cur = {
    begin: 0,
    end: 0,
    len: 0,
    limit: 0,
    counter: 0,
    secondary: 0,
  };

  const go = (n, why) => {
    trace.push({ from: state, to: n, why });
    state = n;
  };

  while (steps++ < 32) {
    switch (state) {
      case 0: {
        // ENTRY codec_load_bounds — load offs 4,0,8,12; bounds → 3|5
        cur.end = mem.load32(src, 4);
        cur.begin = mem.load32(src, 0);
        cur.len = mem.load32(src, 8);
        cur.limit = mem.load32(src, 12);
        // Stub always takes the "room remains" side without inventing the predicate.
        go(5, 'entry_bounds_stub_to_5');
        break;
      }
      case 5: {
        // state_pred_nz — len ? 7 : 1
        go(1, 'pred_nz_stub_to_1');
        break;
      }
      case 1: {
        // state_pred_eq — begin==mark ? 2 : 9
        go(9, 'pred_eq_stub_to_9');
        break;
      }
      case 9: {
        // codec_absorb_mba — bump begin/counter; load8; rotl @secondary; i64 MBA →6
        // Cipher NOT evaluated (folds 937 mba_i64_mix + absorb into one arm).
        cur.counter = mem.load32(src, 16);
        cur.secondary = mem.load32(src, 20);
        void mem.load8(cur.begin || src, 0);
        go(6, 'absorb_mba_opaque_to_exit');
        break;
      }
      case 7: {
        // codec_store_len0 — flag=0; store32(cursor, 0, 8); →8|4
        go(4, 'store_len0_stub');
        break;
      }
      case 8: {
        // cursor_advance — begin += len; →9
        go(9, 'cursor_advance_stub');
        break;
      }
      case 4: {
        // codec_store_cursor — store32(cursor, mark, 0); →6
        go(6, 'store_cursor_to_exit');
        break;
      }
      case 2:
      case 3: {
        // state_only → 6 (exit)
        go(6, 'state_only_to_exit');
        break;
      }
      case 6: {
        // EXIT exit_store8_status — store8(dst, bit, 1); store8(dst, flag, 0)
        mem.store8(dst, 0, 1);
        mem.store8(dst, 0, 0);
        return { ok: true, trace, cluster: ARM_CLUSTERS_537 };
      }
      case 10:
        return { ok: false, err: 'unreachable_trap', trace, cluster: ARM_CLUSTERS_537 };
      default:
        return {
          ok: false,
          err: 'unknown_state',
          state,
          trace,
          cluster: ARM_CLUSTERS_537,
        };
    }
  }
  return { ok: false, err: 'step_limit', trace, cluster: ARM_CLUSTERS_537 };
}

/** a.t (import 19) — takeObject / drop heap handle; wasm (i32)->(); see HOST_GATES.md */
function hostAtStub(handle) {
  // Glue not captured; isomorphic to 84feb Va / 63d9 Cc (void takeObject wrap).
  return handle | 0;
}

/**
 * func 874 — encrypt CFF worker (state-machine sketch)
 *
 * Entry state: 103
 * Body: 10433 B @636998
 * Params: 2 (ret_slot, handle) via 1068
 * Locals: 54 i32 + 2 i64; state in local 3
 * br_table: 119 arms / 120 unique @637250
 *
 * Intern: 397×142, 719×138, 364×88, 219×71, 537×36, 988×36
 * Host: a.t (19) takeObject ×1 @arm 41 — see HOST_GATES.md
 */
function worker874(retSlot, handle, mem, _sp) {
  let state = 103;
  const locals = new Int32Array(56);
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
      case 103: {
        // ENTRY state_only — MBA consts then force state 112
        // constsTop: -569536677, 1799746567, 723411253, -723411254, 28, 112
        locals[7] = Math.imul(locals[7] | 0, -569536677) + 1799746567;
        setState(112, 'entry_mba_to_112');
        break;
      }

      case 112: {
        // codec_loopish — load32/store32; next→38
        for (const off of [60, 68]) {
          const v = mem.load32(frame, off);
          mem.store32(frame, v ^ 0, off);
        }
        setState(38, 'after_codec_loopish');
        break;
      }

      case 38: {
        // codec_loopish — store8×10; next→9
        for (let i = 0; i < 4; i++) mem.store8(frame, 0, 80 + i);
        setState(9, 'after_store8_burst');
        break;
      }

      case 9: {
        // sentinel_branch — next→116
        setState(116, 'sentinel_to_116');
        break;
      }

      case 116:
        setState(118, 'state_only');
        break;

      case 118:
      case 23: {
        // codec_load_store chain
        locals[4] = mem.load32(locals[1], 0);
        setState(state === 118 ? 23 : 18, 'after_handle_load');
        break;
      }

      case 18: {
        // codec_loopish → frame_init 48
        mem.store32(frame, 0, 1100);
        setState(48, 'to_frame_init');
        break;
      }

      case 48: {
        // frame_init_slots — slot 1100 family
        mem.store32(frame, 0, 1100);
        mem.store64(frame, 0n, 1104);
        setState(91, 'frame_init_to_bulk');
        break;
      }

      case 91:
      case 40:
      case 3:
      case 4: {
        // codec_bulk_via_537 — call 537(frame+statusSlot, frame+1100)
        locals[30] = mem.load8(frame, 89);
        bulkPack537Stub(mem, frame + 80, frame + 1100);
        setState(61, 'after_537_bulk');
        break;
      }

      case 61: {
        // state_only — walk cycles 61↔40; break toward host gate
        setState(41, 'break_cycle_to_host_t');
        break;
      }

      case 41: {
        // host_a_t_gate — proven: local.get 1; call 19; state←106 (takeObject drop)
        hostAtStub(locals[1]);
        setState(106, 'after_a_t');
        break;
      }

      case 106:
        setState(104, 'to_result_pack_alt');
        break;

      case 104: {
        // result_pack_exit alt — global.set 0; stores; next→73 sketch
        setState(107, 'alt_pack_rejoin');
        break;
      }

      case 107: {
        // result_pack_exit — proven return; store32×2 via 397
        mem.store32(retSlot, locals[4], 0);
        mem.store32(retSlot, 0, 4);
        return { ok: locals[4], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_874 };
      }

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_874,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_874 };
}

/** Legacy stub kept for fixture / require compat */
function cffEncryptE449(_handle, _mem) {
  return {
    worker: 874,
    trampoline: 1068,
    magic: 1908833735,
    entry_state: 103,
    arms: 120,
    glue: 'aJp',
    note: 'use worker874 / trampoline1068 for sketch walk',
  };
}

/** Yc (1164) encrypt arm only — magic 1908833735 → 1068 */
function ycEncryptE449(dest, handle, mem, globalStack) {
  return trampoline1068(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemoryE449,
  trampoline1068,
  worker874,
  ycEncryptE449,
  cffEncryptE449,
  bulkPack537Stub,
  hostAtStub,
  ARM_CLUSTERS_874,
  ARM_CLUSTERS_537,
  I64_MBA_SAMPLES_537,
  WORKER: 874,
  TRAMPOLINE: 1068,
  MAGIC: 1908833735,
  ENTRY_STATE: 103,
  ARMS: 120,
  GLUE: 'aJp',
  constants: {
    PAGE_SIZE,
    MAGIC: 1908833735,
    WORKER: 874,
    TRAMPOLINE: 1068,
    ENTRY_STATE: 103,
    FRAME_SLOT: 1100,
    BULK: 537,
    HOST_T: 19,
    // unknown cipher — do not invent
    I64_MBA_SAMPLES_537,
  },
};
