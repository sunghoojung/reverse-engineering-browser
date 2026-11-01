/**
 * cff_63d9_encrypt.js — Reconstructive JS for LIVE_63D9 encrypt path (sha63d9f8a3)
 *
 * Path: window.hsw(1) aVj → Yc magic -1483911731 → trampoline 1002 → CFF 667 (136 arms)
 *
 * Arm clusters from classify_arms_349_667.js over helpers_63d9.txt.
 * Helper bodies proven: 863=load_u8, 1026=store_u8, 637=store_i64, 1154=store_i16,
 * 273=opaque byte roundtrip, 218=thunk→a.hc(new Uint8Array(size)).
 * Host gate a.Cc=takeObject (not length). See HOST_GATES.md.
 * RECONSTRUCTIVE ANALYSIS ONLY — does not implement actual cipher / proof bodies.
 */

'use strict';

const PAGE_SIZE = 320;

class ScrambledMemory63d9 {
  constructor(size = 1024 * 1024) {
    this.data = new Uint8Array(size);
    this.descriptors = new Map();
    // LIVE_63D9 tables: perm @4, keystream @469 period 96 (see MEMORY_CODEC.md)
    this.perm = null;
    this.keystreamTable = null;
  }

  // func 518: chunkIndex → descriptor ptr
  getDescriptor(chunkIndex) {
    if (!this.descriptors.has(chunkIndex)) {
      this.descriptors.set(chunkIndex, {
        dirty: false,
        keystream: this._computeKeystream(chunkIndex * PAGE_SIZE),
      });
    }
    return this.descriptors.get(chunkIndex);
  }

  // func 217: addr → i64 keystream (table[469 + addr%96])
  _computeKeystream(addr) {
    // Placeholder when tables not loaded; real path reads keystream_table_63d9.bin
    return BigInt(addr * 0x5851f42d4c957f2d + 0x14057b7ef767814f);
  }

  // func 1134
  markDirty(chunkIndex) {
    this.getDescriptor(chunkIndex).dirty = true;
  }

  // func 859 — load_i32
  load32(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this._rawLoad32(addr);
    return (raw ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
  }

  // func 366 — store_i32
  store32(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor(addr / PAGE_SIZE);
    this.markDirty(chunk);
    this.markDirty(chunk + 1);
    const scrambled = (value ^ Number(this._computeKeystream(addr) & 0xffffffffn)) | 0;
    this._rawStore32(addr, scrambled);
  }

  /**
   * func 1026 — store_u8 (body proven)
   * params (base, value, off); markDirty×1 via 1134; store8(payload, value XOR wrap32(ks))
   */
  store8(base, value, offset) {
    const addr = (base + offset) | 0;
    const chunk = Math.floor((addr >>> 0) / PAGE_SIZE);
    this.markDirty(chunk);
    const ks = Number(this._computeKeystream(addr) & 0xffn);
    this.data[addr >>> 0] = (value ^ ks) & 0xff;
  }

  /**
   * func 863 — load_u8 (body proven)
   * params (base, off) → i32; warm i32.load XOR ks & 255; cold (ks XOR ks) & 255
   * No split-page path (unlike 859). Isomorphic to 84feb func 859.
   */
  load8(base, offset) {
    const addr = (base + offset) | 0;
    const raw = this.data[addr >>> 0] || 0;
    const ks = Number(this._computeKeystream(addr) & 0xffffffffn);
    return ((raw ^ ks) & 0xff) | 0;
  }

  /**
   * func 637 / export Fc — store_i64 (body proven)
   * params (base, i64 value, off); markDirty×2; XOR ks; split if rem > 312
   * Isomorphic to 84feb func 858 / Dc.
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

  /**
   * func 1154 — store_i16 XOR (body proven; rem>318 split)
   * Mislabel corrected: NOT init_opfs_session — pure typed codec store.
   * Yc may still dispatch a magic toward 1154; body is store16.
   */
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
    const dv = new DataView(this.data.buffer, addr);
    return dv.getInt32(0, true);
  }
  _rawStore32(addr, value) {
    const dv = new DataView(this.data.buffer, addr);
    dv.setInt32(0, value, true);
  }
}

/**
 * Arm-cluster table for func 667 (136 unique / 137 parsed incl. empty arm0).
 * Source: classify_arms_349_667.js over helpers_63d9.txt.
 *
 * | cluster              | n  | representative arms                         |
 * |----------------------|---:|------------------------------------------|
 * | codec_bulk_via_937   | 35 | 5,10,19,20,22,… (+106/79 on entry walk) |
 * | state_only           | 31 | 4,12,14,17,…,87,…                        |
 * | opaque_misc          | 19 | 1,3,11,25,…                              |
 * | codec_loopish        | 17 | 2,6,16,…,**121**(entry),…                |
 * | codec_load_store     | 12 | 30,58,73,…                               |
 * | frame_init_slots     | 11 | 7,13,15,39,… (slot **1020** family)      |
 * | unreachable_trap     |  5 | 88,108,114,126,136                       |
 * | result_pack_exit     |  2 | **8** (return), 122 (alt→88 trap sketch) |
 * | host_a_Cc_gate       |  1 | **32** (takeObject; call 190; state←7)  |
 * | call_1154_store16    |  1 | **9** (637×25 + 1154; state←87)          |
 * | call_218_new_u8array |  1 | **55** (218→a.hc Uint8Array; state←86)  |
 * | sentinel_branch      |  1 | 68                                       |
 * | empty                |  1 | 0                                        |
 */
const ARM_CLUSTERS_667 = Object.freeze({
  entry: 121,
  host_a_Cc_gate: 32,
  call_1154_store16: 9,
  call_218_new_u8array: 55,
  result_pack_return: 8,
  result_pack_alt: 122,
  codec_bulk_via_937_n: 35,
  state_only_n: 31,
  frame_init_slots_n: 11,
  frame_slot: 1020,
  note: '937×36 total across bulk arms; 273 absent on encrypt (decrypt-only)',
});

/**
 * func 1002 — Result trampoline (86 B)
 *   sp-=16; call 667(sp+8, arg); unpack via 859/366; sp+=16
 */
function trampoline1002(dest, handle, mem, globalStack) {
  let sp = globalStack - 16;
  worker667(sp + 8, handle, mem, sp);
  const flagWord = mem.load32(sp, 12);
  const flag = flagWord & 1;
  const ok = mem.load32(sp, 8);
  mem.store32(dest, flag, 8);
  mem.store32(dest, flag ? 0 : ok, 4);
  mem.store32(dest, flag ? ok : 0, 0);
  return { ok, err: flag ? ok : 0, flag };
}

/**
 * func 937 — nested 17-arm CFF (entry state 4). Structural stub only.
 *
 * Body @717148+1386; params 2; locals 8 i32 + 16 i64; state local 2.
 * Intern: 859×12, 366×10, 863×2, 1026×2 — **no** store_i64 637.
 *
 * Call shape (parents 349/667): `937(frame+statusSlot, frame+cursorSlot)`
 *   statusSlot ∈ {8..256}; cursorSlot = 1112 (349) / 1020 (667).
 *
 * vs 84feb 1005: **remapped cousin / different machine** (not isomorphic).
 *   Shared: nested CFF once per bulk arm, bounds load 0/4/8/12, exit store8×2.
 *   Different: 17 vs 21 arms; no i64 lane pack (1005: 858×147, consts 360..504/8);
 *   937 is byte-absorb + opaque i64 MBA over a cursor struct.
 *
 * Role: `cursor_absorb_mba`. Cipher identity UNKNOWN — do not invent.
 * Arm table: arm_clusters_937.json / ARM_CLUSTERS_937 below.
 */
const ARM_CLUSTERS_937 = Object.freeze({
  entry: 4,
  exit: 6,
  n_arms: 17,
  state_local: 2,
  role: 'cursor_absorb_mba',
  vs_1005: 'remapped_cousin_different_machine',
  byCluster: Object.freeze({
    mba_i64_mix: Object.freeze([0, 8]),
    state_pred_eq: Object.freeze([1]),
    state_only: Object.freeze([2, 3, 12]),
    codec_load_bounds: Object.freeze([4]),
    codec_absorb_mba: Object.freeze([5, 7]),
    exit_store8_status: Object.freeze([6]),
    mba_i32_pred: Object.freeze([9, 10]),
    codec_store_cursor: Object.freeze([11]),
    cursor_advance: Object.freeze([13]),
    state_pred_nz: Object.freeze([14]),
    codec_store_len0: Object.freeze([15]),
    unreachable_trap: Object.freeze([16]),
  }),
  // Cursor struct at arg1 (reconstructive field names; semantics partial).
  cursor_fields: Object.freeze({
    begin: 0,
    end_or_mark: 4,
    len_or_cap: 8,
    limit: 12,
    counter: 16,
    secondary: 20,
  }),
  note:
    'i64 MBA consts opaque — not simplified; see I64_MBA_SAMPLES_937 (unknown cipher — do not invent)',
});

/** Big i64 samples from 937 mba_i64_mix / absorb arms — unknown cipher — do not invent. */
const I64_MBA_SAMPLES_937 = Object.freeze([
  7751723099346266405n,
  4034149112108046766n,
  392179670175794303n,
  4539628424376761918n,
  2186066324766891979n,
  1793886654591097676n,
  -5511460641829317313n,
  6339919323164002714n,
]);

/**
 * Named-arm structural walk. Does **not** evaluate MBA / rotl cipher math.
 * Returns a trace of arm labels + writes a zero status to dst (store8×2 shape).
 */
function bulkPack937Stub(mem, dst, src) {
  const trace = [];
  let state = ARM_CLUSTERS_937.entry;
  let steps = 0;
  // Shadow of cursor fields — loads only; no MBA outputs committed as cipher.
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
      case 4: {
        // ENTRY codec_load_bounds — seed XOR i32.const -1561962215; load offs 4,0,8,12
        // Real: bounds (end-begin) vs (limit-related) → 12 | 14
        cur.end = mem.load32(src, 4);
        cur.begin = mem.load32(src, 0);
        cur.len = mem.load32(src, 8);
        cur.limit = mem.load32(src, 12);
        // Stub always takes the "room remains" side without inventing the predicate.
        go(14, 'entry_bounds_stub_to_14');
        break;
      }
      case 14: {
        // state_pred_nz — local7 ? 15 : 1
        go(1, 'pred_nz_stub_to_1');
        break;
      }
      case 1: {
        // state_pred_eq — begin==mark ? 2 : 9
        go(9, 'pred_eq_stub_to_9');
        break;
      }
      case 9: {
        // mba_i32_pred — opaque ×1252032833/776825629 → 5|7
        go(5, 'mba_i32_stub_to_absorb');
        break;
      }
      case 5:
      case 7: {
        // codec_absorb_mba — bump begin/counter; load8(begin); rotl mix @secondary;
        // then opaque i64 MBA → temps; next=10. Cipher NOT evaluated.
        cur.counter = mem.load32(src, 16);
        cur.secondary = mem.load32(src, 20);
        void mem.load8(cur.begin || src, 0);
        go(10, 'absorb_mba_opaque_skip');
        break;
      }
      case 10: {
        // mba_i32_pred — commit temps; →8|0
        go(0, 'mba_commit_stub_to_0');
        break;
      }
      case 0:
      case 8: {
        // mba_i64_mix — poly over i64 locals; wrap_i64(mba)+212 → ptr; →3
        // BLOCKER: constants / poly not simplified.
        go(3, 'mba_i64_opaque_to_3');
        break;
      }
      case 3:
      case 2:
      case 12: {
        // state_only → 6 (exit)
        go(6, 'state_only_to_exit');
        break;
      }
      case 13: {
        // cursor_advance — begin-ish += step; →9
        go(9, 'cursor_advance_stub');
        break;
      }
      case 11: {
        // codec_store_cursor — store32(cursor, mark, 0); →6
        go(6, 'store_cursor_to_exit');
        break;
      }
      case 15: {
        // codec_store_len0 — flag=0; store32(cursor, 0, 8); →13|11
        go(11, 'store_len0_stub');
        break;
      }
      case 6: {
        // EXIT exit_store8_status — store8(dst, bit, 1); store8(dst, flag, 0)
        mem.store8(dst, 0, 1);
        mem.store8(dst, 0, 0);
        return { ok: true, trace, cluster: ARM_CLUSTERS_937 };
      }
      case 16:
        return { ok: false, err: 'unreachable_trap', trace, cluster: ARM_CLUSTERS_937 };
      default:
        return {
          ok: false,
          err: 'unknown_state',
          state,
          trace,
          cluster: ARM_CLUSTERS_937,
        };
    }
  }
  return { ok: false, err: 'step_limit', trace, cluster: ARM_CLUSTERS_937 };
}

/** a.Cc (import 190) — takeObject / drop heap handle (art12: azp); return unused */
function hostCcStub(handle) {
  return handle | 0;
}

/** func 218 → a.hc (169) new Uint8Array(size); return kept by callers */
function hostNewUint8ArrayStub(size) {
  return size | 0; // reconstructive: real glue boxes `new Uint8Array(size>>>0)`
}

/** Live isSafeInteger is import a.y (#24), not a.hc — no small thunk in helpers. */
function hostIsSafeIntegerStub(value) {
  return Number.isSafeInteger(value) ? 1 : 0;
}

/**
 * func 667 — encrypt CFF worker (state-machine sketch)
 *
 * Entry state: 121
 * Body: 10780 B @370591
 * Params: 2 (ret_slot, handle) via 1002
 * Locals: 61 i32 + 2 i64; state in local 3
 * br_table: 135 arms / 136 unique @370875
 *
 * Intern: 366×145, 859×142, 1026×82, 863×71, 937×36, 637×26
 * Host: a.Cc (190) takeObject ×1 @arm 32; via 218→a.hc new Uint8Array @arm 55
 */
function worker667(retSlot, handle, mem, _sp) {
  let state = 121;
  const locals = new Int32Array(64);
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
      case 121: {
        // ENTRY codec_loopish — proven: several load32/store32 around MBA consts
        //   51317760 / 17 / 855651072 fingerprint; nextState sketch →106
        for (const off of [60, 68]) {
          const v = mem.load32(frame, off);
          mem.store32(frame, v ^ 0, off);
        }
        setState(106, 'entry_codec_loopish');
        break;
      }

      case 106:
      case 79:
      case 5:
      case 10: {
        // codec_bulk_via_937 — call 937(frame+statusSlot, frame+1020); statusSlot varies
        locals[38] = mem.load8(frame, 9);
        bulkPack937Stub(mem, frame + 72, frame + 1020);
        setState(state === 106 ? 79 : 87, 'after_937_bulk');
        break;
      }

      case 87: {
        // state_only — proven next→13 on linear walk
        setState(13, 'state_only_to_frame_init');
        break;
      }

      case 13:
      case 54: {
        // frame_init_slots — slot 1020 family; stores via 366/637
        mem.store32(frame, 0, 1020);
        mem.store64(frame, 0n, 1024);
        setState(state === 13 ? 54 : 9, 'frame_init_progress');
        break;
      }

      case 9: {
        // call_1154_store16 — proven: heavy 637×25 then call 1154(frame, const, 986); state←87
        // Arm packs i64 lanes then a store16; UNKNOWN payload meaning
        for (let i = 0; i < 4; i++) mem.store64(frame, 0n, 946 + i * 8);
        mem.store16(frame, 13935, 986);
        setState(32, 'after_1154_to_Cc_hypothesis');
        break;
      }

      case 32: {
        // host_a_Cc_gate — proven: local.get 1; call 190; state←7
        hostCcStub(locals[1]);
        setState(7, 'after_a_Cc');
        break;
      }

      case 7: {
        // frame_init_slots member after Cc — UNKNOWN live successor
        setState(55, 'to_218_hypothesis');
        break;
      }

      case 55: {
        // call_218_new_u8array — proven: call 218(local) → a.hc new Uint8Array; store; state←86
        locals[6] = hostNewUint8ArrayStub(locals[11] | 0);
        mem.store32(frame, locals[6], 2012);
        setState(86, 'after_new_Uint8Array');
        break;
      }

      case 86:
        // codec_load_store — UNKNOWN
        setState(8, 'to_result_pack');
        break;

      case 8: {
        // result_pack_exit — proven return
        // store32×2 via 366; sp = frame+2016; return
        mem.store32(retSlot, locals[6], 4);
        mem.store32(retSlot, locals[4], 0);
        return { ok: locals[4], err: 0, flag: 0, trace, cluster: ARM_CLUSTERS_667 };
      }

      case 122:
        // Alternate pack / SP adjust — linear walk then hits trap 88; UNKNOWN live role
        setState(8, 'alt_pack_rejoin_UNKNOWN');
        break;

      case 77:
        setState(8, 'bulk_to_pack_hypothesis');
        break;

      default:
        return {
          ok: 0,
          err: -1,
          flag: 1,
          trace,
          unknownState: state,
          cluster: ARM_CLUSTERS_667,
        };
    }
  }
  return { ok: 0, err: -2, flag: 1, trace, cluster: ARM_CLUSTERS_667 };
}

/** Yc (1170) encrypt arm only — magic -1483911731 → 1002 */
function ycEncrypt(dest, handle, mem, globalStack) {
  return trampoline1002(dest, handle, mem, globalStack);
}

module.exports = {
  ScrambledMemory63d9,
  trampoline1002,
  worker667,
  ycEncrypt,
  bulkPack937Stub,
  hostCcStub,
  hostNewUint8ArrayStub,
  hostIsSafeIntegerStub,
  ARM_CLUSTERS_667,
  ARM_CLUSTERS_937,
  I64_MBA_SAMPLES_937,
  constants: {
    PAGE_SIZE,
    MAGIC: -1483911731,
    YC: 1170,
    TRAMPOLINE: 1002,
    WORKER: 667,
    ARMS: 136,
    ENTRY_STATE: 121,
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
    MARK_DIRTY: 1134,
    KEYSTREAM: 217,
    PAGE_TABLE: 518,
    // unknown cipher — do not invent
    I64_MBA_SAMPLES_937,
  },
  unknowns: [
    'Full transition graph among 136 arms (entry walk + notables sketched)',
    '937 i64 MBA constants / whether absorb+rotl is a known hash (cipher blocker)',
    'Why 667 does not call export Xc (1169) unlike 84feb 796→1158',
    'Payload constants at arm 9 (13935 / 986 band)',
    'Any real proof / ciphertext construction',
  ],
};
