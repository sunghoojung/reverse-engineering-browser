/**
 * cff_live_encrypt.js — Reconstructive JS for live HSW encrypt path (sha84febfac)
 *
 * Path: window.hsw(1) aHO → Yc magic 1262290883 → trampoline 1103 → CFF 796 (142 arms)
 *
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 * Arm bodies are clustered from helpers.txt; UNKNOWN marks unlifted semantics.
 */

'use strict';

const PAGE_SIZE = 320;

class ScrambledMemoryLive {
  constructor(size = 1024 * 1024) {
    this.data = new Uint8Array(size);
    this.descriptors = new Map();
    // Live tables: perm @4, keystream @433 period 96 (see MEMORY_CODEC.md)
    this.perm = null;
    this.keystreamTable = null;
  }

  // func 1157: chunkIndex → descriptor ptr
  getDescriptor(chunkIndex) {
    if (!this.descriptors.has(chunkIndex)) {
      this.descriptors.set(chunkIndex, {
        dirty: false,
        keystream: this._computeKeystream(chunkIndex * PAGE_SIZE),
      });
    }
    return this.descriptors.get(chunkIndex);
  }

  // func 695: addr → i64 keystream (table[433 + addr%96]) — algorithm exact; table bytes external
  _computeKeystream(addr) {
    // Placeholder when tables not loaded; real path reads keystream_table_84feb.bin
    return BigInt(addr * 0x5851f42d4c957f2d + 0x14057b7ef767814f);
  }

  // func 250
  markDirty(chunkIndex) {
    this.getDescriptor(chunkIndex).dirty = true;
  }

  // func 438 — load_i32
  load32(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this._rawLoad32(addr);
    return (raw ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
  }

  // func 582 — store_i32
  store32(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor(addr / PAGE_SIZE);
    this.markDirty(chunk);
    this.markDirty(chunk + 1);
    const scrambled = (value ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
    this._rawStore32(addr, scrambled);
  }

  /**
   * func 957 — store_u8 (body proven)
   * params (base, value, off); markDirty×1; store8(payload, value XOR wrap32(ks))
   */
  store8(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor((addr >>> 0) / PAGE_SIZE);
    this.markDirty(chunk);
    const ks = Number(this._computeKeystream(addr) & 0xffn);
    this.data[addr >>> 0] = (value ^ ks) & 0xff;
  }

  /**
   * func 859 — load_u8 (body proven)
   * params (base, off) → i32; warm i32.load XOR ks & 255; cold (ks XOR ks) & 255
   * No split-page path (unlike 438).
   */
  load8(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this.data[addr >>> 0] || 0;
    const ks = Number(this._computeKeystream(addr) & 0xffffffffn);
    return ((raw ^ ks) & 0xff) | 0;
  }

  /**
   * func 858 / export Dc — store_i64 (body proven)
   * params (base, i64 value, off); markDirty×2; XOR ks; split if rem > 312
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
      // UNKNOWN exact cross-page byte order beyond proven I64Store8 cascade
      for (let i = 0; i < 8; i++) {
        this.data[((addr >>> 0) + i) >>> 0] = Number((scrambled >> BigInt(8 * i)) & 0xffn);
      }
    } else {
      const dv = new DataView(this.data.buffer, addr >>> 0);
      dv.setBigUint64(0, scrambled & 0xffffffffffffffffn, true);
    }
  }

  // func 866 — rem>316 split; calls 250/1157/695
  storeF32(_base, _value, _offset) {
    /* UNKNOWN body detail beyond rem const 316 */
  }
  // func 914 — rem>312 split; calls 250/1157/695
  storeF64(_base, _value, _offset) {
    /* UNKNOWN body detail beyond rem const 312 */
  }

  _rawLoad32(addr) {
    const dv = new DataView(this.data.buffer, addr);
    return dv.getInt32(0, true);
  }
  _rawStore32(addr, value) {
    const dv = new DataView(this.data.buffer, addr);
    dv.setInt32(0, value, true);
  }
}

/**
 * func 1103 — Result trampoline (86 B)
 *   sp-=16; call 796(sp+8, arg); unpack via 438/582; sp+=16
 */
function trampoline1103(dest, handle, mem, globalStack) {
  let sp = globalStack - 16;
  worker796(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * Arm-cluster table for func 796 (142 unique / 143 parsed incl. empty arm0).
 * Source: classify_arms_298_796.js over out_84feb/helpers.txt.
 *
 * | cluster              | n  | representative arms                         |
 * |----------------------|---:|------------------------------------------|
 * | codec_bulk_via_1005  | 38 | 4,5,6,9,13,19,20,22,…                    |
 * | state_only           | 35 | 2,3,11,…,57,62,65,67,68,75,79,86,87,88,… |
 * | opaque_misc          | 17 | 23,27,44,…                               |
 * | codec_load_store     | 15 | 1,8,10,26,42,…                           |
 * | codec_loopish        | 13 | 7,18,21,25,34,54,69,71,92,104,129,137,140|
 * | frame_init_slots     | 12 | 15,33,39,40,58,61,77,78,103,113,123,130  |
 * | unreachable_trap     |  5 | 48,49,70,80,142                          |
 * | result_pack_exit     |  3 | 94,117,121                               |
 * | host_a_Va_gate       |  1 | 17  (local.get 1; call 101; state←116)   |
 * | export_call_1158     |  1 | 112 (NOT export Xc=1165; internal 5-arg) |
 * | sentinel_branch      |  1 | 116                                      |
 * | codec_i64_byte_mix   |  1 | 132                                      |
 * | empty                |  1 | 0                                        |
 */
const ARM_CLUSTERS_796 = Object.freeze({
  entry: 87,
  host_a_Va_gate: 17,
  call_1158: 112,
  result_pack_return: 117,
  result_pack_alt: Object.freeze([94, 121]),
  codec_bulk_via_1005_n: 38,
  state_only_n: 35,
  frame_init_slots_n: 12,
  note: '1005×39 total matches one call per bulk arm; 710 absent on encrypt',
});

/**
 * func 796 — encrypt CFF worker (state-machine sketch)
 *
 * Entry state: 87
 * Body: 10883 B @594201
 * Params: 2 (ret_slot, handle) via 1103
 * Locals: 57 i32 + 3 i64; state in local 3
 * br_table: 141 arms / 142 unique @594497
 *
 * Intern (full-body): 582×132, 438×124, 957×102, 859×77, 1005×39, 858×32
 * Host: a.Va (101) ×1 @arm 17; internal 1158 ×1 @arm 112
 */
function worker796(retSlot, handle, mem, _sp) {
  let state = 87;
  const locals = new Int32Array(60);
  locals[0] = retSlot;
  locals[1] = handle;
  // locals[2] ≈ frame / SP base in real module (UNKNOWN exact prologue)
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
      case 87: {
        // ENTRY — MBA scramble of local 7 then force state 57 (state_only cluster)
        // Real: local7 = local7 * -670341077 - 2014280188; state←57
        locals[7] = Math.imul(locals[7] | 0, -670341077) - 2014280188;
        setState(57, 'entry_mba');
        break;
      }

      case 57: {
        // state_only opaque predicate → 36 or 119 (UNKNOWN which live path)
        setState(119, 'opaque_pred_UNKNOWN_branch');
        break;
      }

      case 119:
      case 36:
        // UNKNOWN: likely joins frame_init / codec clusters
        setState(15, 'join_frame_init_hypothesis');
        break;

      case 15: {
        // Representative frame_init_slots (cluster n=12) — slots around 1068
        // UNKNOWN: exact stores; structural only
        mem.store32(frame, 0, 1068);
        setState(4, 'after_frame_init_to_bulk');
        break;
      }

      case 4:
      case 5:
      case 6: {
        // codec_bulk_via_1005 — nested CFF 1005 packs i64 lanes via 858
        // UNKNOWN: plaintext / ciphertext relation inside 1005
        bulkPack1005Stub(mem, frame + 24, frame + 1068);
        setState(17, 'demo_to_Va_gate');
        break;
      }

      case 17: {
        // host_a_Va_gate — proven: local.get 1; call a.Va; state←116
        // a.Va = takeObject drop (art4 arK); wasm type (i32)->(); see HOST_GATES.md
        const _va = hostVaStub(locals[1]);
        void _va;
        setState(116, 'after_a_Va');
        break;
      }

      case 116: {
        // sentinel_branch cluster — UNKNOWN predicate target
        setState(112, 'to_1158_hypothesis');
        break;
      }

      case 112: {
        // call 1158 (5-arg internal CFF, 6 arms) — NOT export Xc (1165)
        // Real: call 1158(frame+1068, 12, local8, 1, 1); load 1068/1072/1076; state←82
        call1158Stub(frame + 1068, 12, locals[8] | 0, 1, 1, mem);
        locals[4] = mem.load32(frame, 1068);
        locals[5] = mem.load32(frame, 1072);
        locals[6] = mem.load32(frame, 1076);
        setState(82, 'after_1158');
        break;
      }

      case 82:
        // codec_load_store cluster member — UNKNOWN
        setState(117, 'to_result_pack');
        break;

      case 117: {
        // result_pack_exit — proven return
        // store32(ret, local6, 4); store32(ret, local4, 0); sp = frame+2064; return
        mem.store32(retSlot, locals[6], 4);
        mem.store32(retSlot, locals[4], 0);
        return { ok: locals[4], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_796 };
      }

      case 94:
      case 121:
        // Alternate pack paths (global.set 0 mid-flight, then state←41) — UNKNOWN role
        setState(41, 'alt_pack_continue');
        break;

      case 41:
        setState(117, 'alt_pack_rejoin_UNKNOWN');
        break;

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_796,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_796 };
}

/**
 * func 1005 stub — 21-arm nested CFF; body dominated by store_i64 858×147.
 * Role: i64 lane pack (consts 360..504 step 8). NOT cursor_absorb_mba.
 * vs 937/537: remapped cousin / different machine — see MBA_OPAQUE.md.
 * I64_MBA_SAMPLES_1005 — unknown cipher — do not invent.
 */
function bulkPack1005Stub(mem, _dst, _src) {
  // UNKNOWN: lane layout / cipher linkage. No cipher invented.
  void mem;
}

/** Big i64 samples from 1005 body — unknown cipher — do not invent. */
const I64_MBA_SAMPLES_1005 = Object.freeze([
  8903399947347151673n,
  1033939898872119952n,
  6133261650685032694n,
  -2711949332482305000n,
  2067859243301674926n,
  -3710955241560850903n,
  7848193251255116008n,
  -3364161245090177517n,
]);

/** a.Va (import 101) — takeObject / drop heap handle (art4: arK); return unused */
function hostVaStub(handle) {
  // Mirrors guest_ops.takeObject side effect; CFF does not consume a return.
  return takeObjectDrop(handle);
}

function takeObjectDrop(handle) {
  return handle | 0;
}

/** func 1158 — internal 5-param 6-arm CFF; UNKNOWN purpose */
function call1158Stub(_a, _b, _c, _d, _e, _mem) {
  return 0;
}

/** Yc (1166) encrypt arm only — magic 1262290883 → 1103 */
function ycEncrypt(dest, handle, mem, globalStack) {
  return trampoline1103(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemoryLive,
  trampoline1103,
  worker796,
  ycEncrypt,
  bulkPack1005Stub,
  hostVaStub,
  ARM_CLUSTERS_796,
  I64_MBA_SAMPLES_1005,
  constants: {
    PAGE_SIZE,
    MAGIC: 1262290883,
    YC: 1166,
    TRAMPOLINE: 1103,
    WORKER: 796,
    ARMS: 142,
    ENTRY_STATE: 87,
    HOST_VA: 101,
    INTERNAL_1158: 1158,
    EXPORT_XC: 1165,
    STORE8: 957,
    LOAD8: 859,
    STORE64: 858,
    BULK: 1005,
    // unknown cipher — do not invent
    I64_MBA_SAMPLES_1005,
  },
  /** Cross-build analogue map (structural; ids remapped per sha). */
  analogues63d9: Object.freeze({
    worker: 667,
    load_u8: 863,
    store_u8: 1026,
    store_i64: 637,
    store_i16: 1154,
    bulk: 937,
    mba_decrypt_only: 273,
    host_gate: 'a.Cc/190 takeObject',
    host_thunk: '218→a.hc/169 new Uint8Array(size)',
    bulk_vs: '937 = cursor_absorb_mba; 1005 = i64 lane pack (different machine)',
  }),
  analoguesE449: Object.freeze({
    worker: 874,
    bulk: 537,
    mba_decrypt_only: 406,
    bulk_vs: '537 = cursor_absorb_mba cousin of 937; not 1005',
  }),
  unknowns: [
    'Full transition graph among 142 arms (only entry walk + notables sketched)',
    'Semantic of nested CFF 1005 (i64 packing layout / cipher linkage)',
    'Semantic of internal 1158 (not export Xc=1165)',
    'MBA predicates selecting 36 vs 119 after entry',
    'Any real proof / ciphertext construction',
  ],
};
