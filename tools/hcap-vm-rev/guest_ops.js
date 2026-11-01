/**
 * Reconstructive model of captured hCaptcha HSW (wasm-bindgen / CFF).
 *
 * Loadable under Node (`require` / `node --check`). Named APIs run on
 * synthetic fixtures. Not decompiled source, not a solver, and does not
 * talk to api.hcaptcha.com.
 *
 * Click-session module (9623810216396876129 / hsw-click.wasm, sha 49086a4a):
 *   190 imports (a..Bc), 969 defined, 22 exports. Page codec is exact:
 *   descriptor 928, keystream 1014, load_i32 329, store_i32 1129, markDirty 248.
 *
 * Live session 5369273503095065946 module (hsw-live-84febfac.wasm, sha 84febfac,
 * 1052328 B) is a different build: 191 imports, 976 defined. Codec indexes move
 * to load_i32 438, store_i32 582, keystream 695 (@433, period 96), page_table 1157.
 * Live native br_table obs (art 6, n=16): Pc export 537 → trampoline 565 → CFF 1087
 * (246 arms) → helper 296. Do not reuse CLICK_WASM indexes for that sha; see
 * LIVE_OBSERVE_5369.md for the delta sketch before editing tables here.
 */
"use strict";

const HOST_IMPORTS = require("./host_imports.js");

/**
 * Historical / click-session mode table (older hsw.js + hsw-click.wasm).
 * Live 84febfac uses LIVE_HSW_MODE + LIVE_MAGIC instead.
 */
const HSW_MODE = Object.freeze({
  0: {
    id: 0,
    name: "decrypt",
    glue: "bau",
    magic: -58720044,
    entry: 424,
    cff: 941,
    click: { magic: 44633705, trampoline: 967, worker: 612, arms: 133 },
  },
  1: {
    id: 1,
    name: "encrypt",
    glue: "kk",
    magic: 1983284732,
    entry: 592,
    cff: 386,
    click: { magic: -77630479, trampoline: null, worker: 585, arms: 251 },
  },
  2: {
    id: 2,
    name: "update_token",
    glue: "Bd",
    magic: null,
    entry: null,
    cff: null,
    click: { magic: -721101446, trampoline: 656, worker: 630, arms: 112, role: "unknown" },
  },
  jwt: { id: "jwt", name: "proof_uc", glue: "aeB", export: "Uc", entry: 491, then: 659 },
});

/**
 * Live art4 glue (sha 8b1349a9) × LIVE_84FEB Yc=1166.
 * Proven: window.hsw(0|1|2) → akZ|aHO|aqa → aaj[at$(8)](magic,…) = export Yc.
 * Art12 (e25e8466) pairs with LIVE_63D9 / art13 instead — see GLUE_LIVE.
 */
const LIVE_MAGIC = Object.freeze({
  decrypt_resp_data: -1874150846,
  encrypt_req_data: 1262290883,
  update_token: 366490014,
  /** Remaining Yc arms are typed codec accessors (not hsw modes). */
  codec_load_family: 1527928521,
  store_i32: -1568355035,
  codec_store_family: -102924451,
  codec_store8_family: 1749293109,
  codec_xor_store_family: -1755051318,
});

const LIVE_HSW_MODE = Object.freeze({
  0: Object.freeze({
    id: 0,
    name: "decrypt",
    glue: "akZ",
    glue_alt: "lL.X",
    magic: LIVE_MAGIC.decrypt_resp_data,
    yc: 1166,
    trampoline: 777,
    worker: 298,
    arms: 115,
    entry_state: 21,
    path: Object.freeze(["hsw(0)", "akZ", "Yc", 777, 298]),
    confidence: "high",
    bind_via: "glue_magic_plus_body",
  }),
  1: Object.freeze({
    id: 1,
    name: "encrypt",
    glue: "aHO",
    magic: LIVE_MAGIC.encrypt_req_data,
    yc: 1166,
    trampoline: 1103,
    worker: 796,
    arms: 142,
    entry_state: 87,
    path: Object.freeze(["hsw(1)", "aHO", "Yc", 1103, 796]),
    confidence: "high",
    bind_via: "glue_magic_plus_body",
  }),
  2: Object.freeze({
    id: 2,
    name: "update_token",
    glue: "aqa",
    magic: LIVE_MAGIC.update_token,
    yc: 1166,
    trampoline: null,
    worker: 606,
    arms: 243,
    path: Object.freeze(["hsw(2)", "aqa", "Yc", 606]),
    confidence: "high",
    bind_via: "glue_magic_plus_body",
    role: "large_cff_host_Va",
  }),
  jwt: Object.freeze({
    id: "jwt",
    name: "proof_uc",
    glue: "tr",
    export: "Uc",
    func: 738,
    aaj_slot: 47,
    note: "JWT path after aSS(); aaj[at$(47)] = Uc; not via Yc mode magics",
  }),
});

/** Glue blobs for session 5369 (reb-api artifacts). */
const GLUE_LIVE = Object.freeze({
  art4: Object.freeze({
    id: "4",
    path: "glue/art4.bin",
    bytes: 1593148,
    sha256_prefix: "8b1349a9",
    pairs_with_wasm: "84febfac",
    window_hsw: Object.freeze({
      0: "akZ",
      1: "aHO",
      2: "aqa",
      jwt: "tr",
    }),
    yc_slot: "aaj[at$(8)]",
    uc_slot: "aaj[at$(47)]",
  }),
  art12: Object.freeze({
    id: "12",
    path: "glue/art12.bin",
    bytes: 1592834,
    sha256_prefix: "e25e8466",
    pairs_with_wasm: "63d9f8a3",
    window_hsw: Object.freeze({
      0: "bbD",
      1: "aVj",
      2: "aOF",
      jwt: "Yf",
    }),
    yc_slot: "aTZ[aWL(8)]",
    uc_slot: "aTZ[aWL(47)]",
  }),
});

const MAGIC = Object.freeze({
  getUint8: 491531597,
  getInt8: 178684004,
  getInt32: -1530686629,
  getUint32: 1506725718,
  getInt16: 78852157,
  getUint16: -1529966573,
  init_opfs_session: -1090220354,
  encrypt_req_data: 1983284732,
  decrypt_resp_data: -58720044,
  pass_string: -1809583456,
  setInt8: -408796390,
  setInt16: -2126377651,
  setInt32: -256723493,
  setFloat32: -1011875692,
  setFloat64: -1686077,
  getFloat32: -1648684026,
  getFloat64: 39508814,
  /** Prefer these on LIVE_84FEB / art4 glue. */
  live_encrypt_req_data: LIVE_MAGIC.encrypt_req_data,
  live_decrypt_resp_data: LIVE_MAGIC.decrypt_resp_data,
  live_update_token: LIVE_MAGIC.update_token,
});

const PAGE = 320;
const HDR = 8;
const CHUNK = PAGE + HDR;
const HEAP_RESERVED = 1028;
const PAGE_TABLE_BASE = 1024;
const PERM_ADDR = 4;
const KEYSTREAM_ADDR = 195;
const KEYSTREAM_PERIOD = 96;

const PERM_TABLE = Object.freeze([
  9, 11, 5, 2, 4, 1, 3, 7, 10, 14, 6, 12, 0, 8, 13, 15,
]);

const KEYSTREAM_TABLE = Buffer.from(
  "444addad3d0d0437414c63ce3b0e427fc2d8741637acbb0f809a381a9b37c557" +
    "e4c41d86c8cf39b54ee553ae8ed76df98cec97602b2963719787139bc566441e" +
    "a98cbbb4e7e9a51da03d794348a90fbe74afb0fd7dd171243ad11f52d8e525ad" +
    "444addad3d0d0437",
  "hex"
);

const HOST_FAMILIES = Object.freeze({
  glue: ["d", "w", "z", "H", "pa", "ya", "Na", "Oa", "Ta", "ib", "sb", "zb", "kc"],
  typed_arrays: ["M", "N", "W", "Y", "_", "aa", "ba", "ra", "Ha", "Ja", "eb", "hb", "tb", "Jb", "Pb", "Zb", "nc", "Cc"],
  reflection: ["c", "e", "i", "n", "s", "u", "v", "x", "y", "C", "D", "E", "F", "R", "X", "fa", "la", "ua", "xa", "Ca", "Fa", "Ia", "Ma", "Pa", "Za", "_a", "ab", "lb", "mb", "ob", "vb", "yb", "Bb", "Cb", "Eb", "Ib", "Kb", "Mb", "Ob", "Rb", "Vb", "Wb", "Xb", "jc", "yc"],
  exceptions: ["na", "Ea", "Ka"],
  strings: ["h", "Da", "fb", "pb", "Hb", "Tb", "dc", "ic"],
  math: ["k", "hc"],
  time: ["q", "t", "V", "ta", "nb"],
  crypto: ["bb", "Ab", "Yb", "qc", "rc"],
  navigator: ["a", "f", "rb", "wb", "Lb", "sc"],
  screen: ["g", "m", "G", "Ba", "Xa"],
  dom: ["j", "S", "ia", "sa", "Aa", "Ua", "db", "xb", "Qb", "ac", "lc", "mc"],
  canvas: ["A", "J", "P", "Q", "$", "ca", "da", "ga", "ma", "za", "Ga", "Wa", "$a", "gb", "kb", "Db", "Gb", "$b", "bc", "cc", "gc", "oc", "Ac", "Bc"],
  performance: ["B", "K", "Z", "ea", "ha", "ja", "ka", "oa", "va", "wa", "La", "Sa", "Va", "Ya", "cb", "Nb", "pc", "uc", "vc"],
  storage: ["U", "qa", "fc"],
  async: ["r", "T", "Qa", "Fb", "Sb", "tc", "wc", "zc"],
  globals: ["L", "O", "jb", "_b"],
  eval_module: ["Ra", "xc"],
  probes: ["b", "l", "o", "p", "I", "qb", "ub", "Ub", "ec"],
});

const CLICK_WASM = Object.freeze({
  session: "9623810216396876129",
  sha256: "49086a4a9de66039f9d4de5b4a332d3b77d0a330b1c80dfde0c6082754e5d539",
  bytes: 1020263,
  imported_functions: 190,
  defined_functions: 969,
  last_import: "Bc",
  codec: Object.freeze({
    page: PAGE,
    hdr: HDR,
    chunk: CHUNK,
    load_i32: 329,
    load_u8: 867,
    store_i32: 1129,
    store_i16: 190,
    store_i8: 1042,
    store_f32: 799,
    store_f64: 642,
    load_i64: 309,
    mark_dirty: 248,
    descriptor: 928,
    keystream: 1014,
    keystream_period: KEYSTREAM_PERIOD,
    keystream_addr: KEYSTREAM_ADDR,
    perm_addr: PERM_ADDR,
    page_table_base: PAGE_TABLE_BASE,
  }),
  exports: Object.freeze({
    Cc: 493,
    Dc: "memory0",
    Ec: 1142,
    Fc: 1095,
    Gc: 227,
    Hc: 538,
    Ic: 896,
    Jc: 661,
    Kc: 309,
    Lc: 1070,
    Mc: 274,
    Nc: 651,
    Oc: 309,
    Pc: 207,
    Qc: 464,
    Rc: 419,
    Sc: 795,
    Tc: 1138,
    Uc: 1155,
    Vc: 1156,
    Wc: 1157,
    Xc: 1158,
  }),
  magic_get: Object.freeze({
    649850271: { name: "getInt32", callee: 329 },
    1064515644: { name: "get_i32_b", callee: 684 },
    "-1851891811": { name: "get_i32_c", callee: 682, swap: true },
    1906301267: { name: "get_i32_d", callee: 555, swap: true },
    "-1525043911": { name: "getUint8", callee: 867, swap: true },
    1650591612: { name: "init_opfs_session", callee: 1154 },
    "-1911521874": { name: "getInt32_swap", callee: 329, swap: true },
    1104144910: { name: "Uc_get", callee: 487 },
    "-1791377095": { name: "getInt64", callee: 695 },
  }),
  magic_set: Object.freeze({
    1875894927: { name: "setFloat32", callee: 799 },
    "-77630479": { name: "encrypt_cff", callee: 585 },
    44633705: { name: "decrypt_cff", callee: 967, worker: 612 },
    297600991: { name: "setInt16", callee: 190 },
    "-1263439021": { name: "setFloat64", callee: 642 },
    "-1622294370": { name: "setInt8", callee: 1042 },
    "-721101446": { name: "alt_cff", callee: 656, worker: 630, role: "unknown" },
    "-2069957989": { name: "setInt32", callee: 1129 },
  }),
  cff: Object.freeze({
    encrypt: Object.freeze({
      magic: -77630479,
      trampoline: null,
      worker: 585,
      params: 4,
      extra_locals: 74,
      body_len: 15474,
      arms: 251,
      unique: 252,
      state_local: 5,
      intern_calls: Object.freeze({
        1129: 204,
        329: 184,
        867: 85,
        1042: 81,
        464: 65,
        816: 38,
        683: 13,
        343: 11,
      }),
      host: Object.freeze({ r: 1 }),
    }),
    decrypt: Object.freeze({
      magic: 44633705,
      trampoline: 967,
      worker: 612,
      params: 2,
      extra_locals: 59,
      body_len: 10747,
      arms: 133,
      unique: 134,
      state_local: 3,
      intern_calls: Object.freeze({
        1129: 152,
        329: 144,
        1042: 86,
        867: 71,
        464: 38,
        816: 36,
      }),
      host: Object.freeze({ r: 1 }),
    }),
    alt: Object.freeze({
      magic: -721101446,
      trampoline: 656,
      worker: 630,
      params: 2,
      extra_locals: 62,
      body_len: 10010,
      arms: 112,
      unique: 113,
      intern_calls: Object.freeze({
        1129: 164,
        329: 143,
        867: 109,
        1042: 71,
        816: 39,
        464: 28,
        815: 17,
      }),
      role: "unknown",
    }),
    result_unpack: Object.freeze({
      stack: 16,
      worker_out: 8,
      flag_src: 12,
      dest_flag: 8,
      dest_err: 4,
      dest_ok: 0,
    }),
    nested: Object.freeze({
      816: Object.freeze({
        body_len: 1255,
        params: 2,
        extra_locals: 29,
        arms: 20,
        unique: 21,
        intern_calls: Object.freeze({ 329: 12, 1129: 7, 1042: 2, 867: 1 }),
        role: "vec_or_slice_cursor",
        fields: Object.freeze({ ptr: 0, end: 4, cap: 8 }),
      }),
      683: Object.freeze({
        body_len: 8347,
        params: 2,
        extra_locals: 127,
        arms: 34,
        unique: 35,
        intern_calls: Object.freeze({ 1129: 80, 329: 18, 309: 4, 464: 2 }),
        role: "unknown",
      }),
      815: Object.freeze({
        body_len: 138,
        params: 1,
        extra_locals: 2,
        arms: 4,
        unique: 5,
        intern_calls: Object.freeze({ 867: 2, 1042: 2 }),
        role: "opaque_u8_roundtrip",
      }),
      343: Object.freeze({ body_len: 9, params: 2, callee: 356, role: "thunk" }),
    }),
  }),
});

/** Live Origin Trace session 5369 module (sha 84febfac). Parallel to CLICK_WASM — do not mix indexes. */
const LIVE_PERM_TABLE = Object.freeze([
  4, 0, 12, 15, 14, 1, 9, 11, 13, 2, 8, 5, 7, 3, 10, 6,
]);

const LIVE_KEYSTREAM_TABLE = Buffer.from(
  "60dfd0cb833e9f8baf7e89a99a80cb3ca88e970764b7525769f1acfc0deef9d0" +
    "91750926c755271cf7f5374ed3efed413f8d5c3cdf1d7aa95c0f1d8483fd8321" +
    "2e55159315d82155abc6fede23c1b6cc6f04a18b3d13da93059dceac5517ba1d",
  "hex"
);

const LIVE_84FEB = Object.freeze({
  session: "5369273503095065946",
  artifact_id: "6",
  sha256: "84febfacc2ead7c5ffcf77b47de95d111990dc3ba7284b9b81b6f2994df6c176",
  bytes: 1052328,
  imported_functions: 191,
  defined_functions: 976,
  br_tables: 763,
  codec: Object.freeze({
    page: PAGE,
    hdr: HDR,
    chunk: CHUNK,
    load_i32: 438,
    store_i32: 582,
    mark_dirty: 250,
    keystream: 695,
    keystream_period: KEYSTREAM_PERIOD,
    keystream_addr: 433,
    page_table: 1157,
    page_table_base: PAGE_TABLE_BASE,
    perm_addr: PERM_ADDR,
  }),
  helpers: Object.freeze({
    101: "host_a_Va_takeObject_gate",
    212: "power_of_two_bounds_predicate",
    250: "mark_dirty_fill_keystream",
    298: "decrypt_cff_worker",
    381: "thunk_call_565",
    438: "load_i32",
    443: "encrypt_trampoline_calls_592",
    458: "arity_ge9_helper_calls_1087",
    537: "export_Pc_cff5",
    544: "encrypt_frame_calls_443",
    54: "host_a_aa_isSafeInteger",
    565: "trampoline_magic_2037874024",
    582: "store_i32",
    68: "host_a_oa_new_Uint8Array",
    695: "keystream64_table",
    710: "opaque_u8_roundtrip_sp15",
    777: "decrypt_trampoline_calls_298",
    778: "alt_cff_calls_757",
    796: "encrypt_cff_worker",
    824: "elem78_hub_calls_387_778",
    838: "noop_empty",
    1003: "decrypt_path_calls_243",
    1005: "i64_lane_pack_bulk",
    1087: "linear_heap_init_worker",
    1103: "encrypt_trampoline_calls_796",
    1141: "thunk_a_oa_new_Uint8Array",
    1157: "page_table",
  }),
  host_gates: Object.freeze({
    gate_import: "Va",
    gate_idx: 101,
    gate_arms: Object.freeze({ decrypt_298: 85, encrypt_796: 17 }),
    semantic: "takeObject_drop_handle",
    thunk_uint8array: Object.freeze({ func: 1141, import: "oa", idx: 68 }),
    isSafeInteger_import: Object.freeze({ name: "aa", idx: 54, thunk: null }),
    see: "HOST_GATES.md",
  }),
  exports: Object.freeze({
    Dc: 858,
    Ec: 714,
    Fc: 213,
    Gc: "memory0",
    Hc: 787,
    Ic: 297,
    Jc: 794,
    Kc: 764,
    Lc: 297,
    Mc: 1062,
    Nc: 634,
    Oc: 752,
    Pc: 537,
    Qc: 1069,
    Rc: 955,
    Sc: 1132,
    Tc: 830,
    Uc: 738,
    Vc: 1163,
    Wc: 1164,
    Xc: 1165,
    Yc: 1166,
  }),
  observed_dispatch: Object.freeze({
    native_wasm_observation_count: 16,
    sample_count_js: 0,
    native_guest_sample_count: 0,
    path: Object.freeze(["Pc", 537, 838, 381, 565, 1087, 296]),
    selectors: Object.freeze({
      537: Object.freeze([4, 3, 1]),
      565: Object.freeze([2, 0, 5]),
      1087: Object.freeze([189, 82, 57, 215, 52, 1, 230, 122]),
      296: Object.freeze([3, 2]),
    }),
    notes: Object.freeze({
      537: "export Pc; CFF entry → 212 / 838→381",
      565: "trampoline; magic 2037874024; arms 3/4/5 call 1087; arm3→458 if arity>=9",
      1087: "246-arm linear_heap_init_worker; callers only 565,458,490,368 — not enc/dec",
      296: "small helper writing via store 582",
      ranked_interpreter_not_live: 1142,
    }),
  }),
  magic: Object.freeze({
    2037874024: Object.freeze({
      only_in: 565,
      use: "arg0 XOR magic XOR arg1 tag before 1087/458 branch",
      scramble: Object.freeze([329978431, 809863288]),
    }),
  }),
  /**
   * Export Yc=1166 is the live mode+codec dispatcher (glue aaj[at$(8)]).
   * Mode arms proven via art4 hsw.js; bodies of 777/1103 are stack trampolines
   * into CFF workers 298 (decrypt) and 796 (encrypt).
   */
  yc_dispatch: Object.freeze({
    export: "Yc",
    func: 1166,
    role: "mode_and_codec_dispatcher",
    confidence: "high",
    note: "Historical magics 1983284732 / -58720044 absent; live magics below.",
    arms: Object.freeze([
      Object.freeze({ magic: 1527928521, callee: 914, family: "codec_load_family" }),
      Object.freeze({ magic: -1568355035, callee: 582, family: "store_i32" }),
      Object.freeze({ magic: -102924451, callee: 322, family: "codec_store_family" }),
      Object.freeze({ magic: 1749293109, callee: 957, family: "codec_store8_family" }),
      Object.freeze({
        magic: 1262290883,
        callee: 1103,
        family: "encrypt_trampoline",
        mode: 1,
        worker: 796,
      }),
      Object.freeze({
        magic: -1874150846,
        callee: 777,
        family: "decrypt_trampoline",
        mode: 0,
        worker: 298,
      }),
      Object.freeze({ magic: -1755051318, callee: 866, family: "codec_xor_store_family" }),
      Object.freeze({
        magic: 366490014,
        callee: 606,
        family: "update_token_cff",
        mode: 2,
        worker: 606,
      }),
    ]),
  }),
  call_1087_sites: Object.freeze([
    Object.freeze({ func: 565, count: 2 }),
    Object.freeze({ func: 458, count: 1 }),
    Object.freeze({ func: 490, count: 1 }),
    Object.freeze({ func: 368, count: 1 }),
  ]),
  /**
   * Live hsw(0)/hsw(1)/hsw(2) ↔ CFF workers (glue-proven).
   * Earlier hub-824 → 243/592 shape bind is demoted to sibling analogues only.
   */
  cff_hypothesis: Object.freeze({
    encrypt: Object.freeze({
      mode: 1,
      glue: "aHO",
      magic: 1262290883,
      trampoline: 1103,
      func: 796,
      arms: 142,
      entry_state: 87,
      params: "stack_frame_via_1103",
      path: Object.freeze([1166, 1103, 796]),
      confidence: "high",
      bind_via: "glue_magic_plus_body",
    }),
    decrypt: Object.freeze({
      mode: 0,
      glue: "akZ",
      magic: -1874150846,
      trampoline: 777,
      func: 298,
      arms: 115,
      entry_state: 21,
      params: "stack_frame_via_777",
      path: Object.freeze([1166, 777, 298]),
      confidence: "high",
      bind_via: "glue_magic_plus_body",
    }),
    update_token: Object.freeze({
      mode: 2,
      glue: "aqa",
      magic: 366490014,
      func: 606,
      arms: 243,
      path: Object.freeze([1166, 606]),
      confidence: "high",
      bind_via: "glue_magic_plus_body",
    }),
    sibling_analogues_unbound: Object.freeze({
      note: "Similar CFF shape; not on the live Yc mode path",
      encrypt_like: Object.freeze({
        func: 592,
        arms: 256,
        path: Object.freeze([824, 387, 544, 443, 592]),
        confidence: "medium-shape-only",
      }),
      decrypt_like: Object.freeze({
        func: 243,
        arms: 136,
        path: Object.freeze([824, 387, 1003, 243]),
        confidence: "medium-shape-only",
      }),
      alt: Object.freeze({
        func: 757,
        arms: 249,
        path: Object.freeze([824, 778, 757]),
        confidence: "low-medium",
      }),
    }),
    hub: Object.freeze({
      func: 824,
      arms: 520,
      elem_slot: 78,
      direct_callers: 0,
      callees_focus: Object.freeze([387, 778]),
      role: "table_hub_not_hsw_mode",
    }),
    not_enc_dec_mode_workers: Object.freeze([1087, 1142, 387, 1014, 243, 592, 757]),
    yc_is_mode_dispatch: true,
  }),
  cff_candidates_unbound: Object.freeze([1142, 387, 1014, 824, 506, 243, 592, 757]),
  glue: GLUE_LIVE.art4,
  artifact_13: Object.freeze({
    id: "13",
    sha256_prefix: "63d9f8a3",
    profile: "LIVE_63D9",
    note: "Remapped in LIVE_63D9 — indexes must not be mixed with LIVE_84FEB.",
  }),
  keystream_bytes: LIVE_KEYSTREAM_TABLE,
  perm_table: LIVE_PERM_TABLE,
  perm_bytes_in_file: true,
});

const LIVE_63D9_PERM_TABLE = Object.freeze([
  0, 9, 3, 14, 6, 5, 11, 1, 2, 13, 7, 12, 4, 8, 10, 15,
]);

const LIVE_63D9_KEYSTREAM_TABLE = Buffer.from(
  "162c658100befada883757b1350d3a11c1230f8e13344fa3b04ebf6d6f6cbb31" +
    "3a77192012221b81c357b7e4e04cebbecd3b22e31fada63bd168bf669679dd17" +
    "c29404376d731dd6b983fb52ff46ff50b4f8118dc63878e5c424a7787aeb4b3d",
  "hex"
);

/** Artifact 13 / hsw-live-63d9f8a3.wasm — parallel profile; do not mix with LIVE_84FEB. */
const LIVE_63D9 = Object.freeze({
  session: "5369273503095065946",
  artifact_id: "13",
  sha256: "63d9f8a367529375945bf1aecf0130fcfbe8846ef54d435500dcdced20d75526",
  bytes: 1057758,
  path: "hsw-live-63d9f8a3.wasm",
  glue: GLUE_LIVE.art12,
  imported_functions: 191,
  defined_functions: 980,
  observations: 0,
  codec: Object.freeze({
    page: PAGE,
    hdr: HDR,
    chunk: CHUNK,
    load_i32: 859,
    store_i32: 366,
    mark_dirty: 1134,
    keystream: 217,
    keystream_period: KEYSTREAM_PERIOD,
    keystream_addr: 469,
    page_table: 518,
    page_table_base: PAGE_TABLE_BASE,
    perm_addr: PERM_ADDR,
  }),
  helpers: Object.freeze({
    24: "host_a_y_isSafeInteger",
    169: "host_a_hc_new_Uint8Array",
    190: "host_a_Cc_takeObject_gate",
    217: "keystream64_table",
    218: "thunk_a_hc_new_Uint8Array",
    250: "export_Pc",
    273: "opaque_u8_roundtrip_sp15",
    349: "decrypt_cff_worker",
    366: "store_i32",
    377: "decrypt_entry_calls_349",
    518: "page_table",
    637: "store_i64",
    667: "encrypt_cff_worker",
    690: "export_Uc",
    724: "update_token_cff",
    859: "load_i32",
    863: "load_u8",
    937: "cursor_absorb_mba",
    1002: "encrypt_trampoline_calls_667",
    1026: "store_u8",
    1134: "mark_dirty_fill_keystream",
    1154: "store_i16",
    1170: "export_Yc",
  }),
  host_gates: Object.freeze({
    gate_import: "Cc",
    gate_idx: 190,
    gate_arms: Object.freeze({ decrypt_349: 92, encrypt_667: 32 }),
    semantic: "takeObject_drop_handle",
    thunk_uint8array: Object.freeze({ func: 218, import: "hc", idx: 169 }),
    isSafeInteger_import: Object.freeze({ name: "y", idx: 24, thunk: null }),
    see: "HOST_GATES.md",
  }),
  cff: Object.freeze({
    nested: Object.freeze({
      937: Object.freeze({
        body_len: 1386,
        params: 2,
        extra_locals: Object.freeze({ i32: 8, i64: 16 }),
        arms: 16,
        unique: 17,
        entry_state: 4,
        state_local: 2,
        intern_calls: Object.freeze({ 859: 12, 366: 10, 863: 2, 1026: 2 }),
        role: "cursor_absorb_mba",
        vs_1005: "remapped_cousin_different_machine",
        cursor_fields: Object.freeze({
          begin: 0,
          end_or_mark: 4,
          len_or_cap: 8,
          limit: 12,
          counter: 16,
          secondary: 20,
        }),
        note:
          "Byte-absorb + opaque i64 MBA over cursor@arg1; status store8×2 @arg0. Not isomorphic to 84feb 1005 (no store_i64 lane pack).",
      }),
      273: Object.freeze({
        body_len: 25,
        params: 1,
        role: "opaque_u8_roundtrip",
        analogue_84feb: 710,
        analogue_e449: 406,
        proven: "sp-=16; store_u8(sp,arg,15) via 1026; return load_u8(sp,15) via 863",
        vs_710: "same_sp15_core; 710 adds vacuous 5-arm MBA wrapper",
      }),
    }),
  }),
  exports: Object.freeze({
    Dc: 957,
    Ec: 515,
    Fc: 637,
    Gc: 404,
    Hc: 752,
    Ic: 1101,
    Jc: 846,
    Kc: 1098,
    Lc: 903,
    Mc: 595,
    Nc: "memory0",
    Oc: 358,
    Pc: 250,
    Qc: 752,
    Rc: 674,
    Sc: 194,
    Tc: 617,
    Uc: 690,
    Vc: 1167,
    Wc: 1168,
    Xc: 1169,
    Yc: 1170,
  }),
  yc_dispatch: Object.freeze({
    export: "Yc",
    func: 1170,
    role: "mode_and_codec_dispatcher",
    confidence: "high",
    arms: Object.freeze([
      Object.freeze({
        magic: -174010464,
        callee: 377,
        family: "decrypt_entry",
        mode: 0,
        worker: 349,
      }),
      Object.freeze({
        magic: -1483911731,
        callee: 1002,
        family: "encrypt_trampoline",
        mode: 1,
        worker: 667,
      }),
      Object.freeze({ magic: -1592771034, callee: 1154, family: "codec_store_family" }),
      Object.freeze({ magic: -1904052616, callee: 1026, family: "codec_store8_family" }),
      Object.freeze({ magic: 1509429953, callee: 574, family: "codec_store_family" }),
      Object.freeze({ magic: -614618436, callee: 229, family: "codec_store_family" }),
      Object.freeze({ magic: -2062624695, callee: 366, family: "store_i32" }),
      Object.freeze({
        magic: 672652481,
        callee: 724,
        family: "update_token_cff",
        mode: 2,
        worker: 724,
      }),
    ]),
  }),
  hsw_mode: Object.freeze({
    0: Object.freeze({
      id: 0,
      name: "decrypt",
      glue: "bbD",
      magic: -174010464,
      yc: 1170,
      trampoline: 377,
      worker: 349,
      arms: 113,
      entry_state: 52,
      confidence: "high",
      bind_via: "glue_magic_plus_body",
      path: Object.freeze(["hsw(0)", "bbD", "Yc", 377, 349]),
    }),
    1: Object.freeze({
      id: 1,
      name: "encrypt",
      glue: "aVj",
      magic: -1483911731,
      yc: 1170,
      trampoline: 1002,
      worker: 667,
      arms: 136,
      entry_state: 121,
      confidence: "high",
      bind_via: "glue_magic_plus_body",
      path: Object.freeze(["hsw(1)", "aVj", "Yc", 1002, 667]),
    }),
    2: Object.freeze({
      id: 2,
      name: "update_token",
      glue: "aOF",
      magic: 672652481,
      yc: 1170,
      trampoline: null,
      worker: 724,
      arms: 257,
      entry_state: 109,
      confidence: "high",
      bind_via: "glue_magic_plus_body",
      path: Object.freeze(["hsw(2)", "aOF", "Yc", 724]),
    }),
    jwt: Object.freeze({
      id: "jwt",
      name: "proof_uc",
      glue: "Yf",
      export: "Uc",
      func: 690,
    }),
  }),
  largest_cff: Object.freeze([
    Object.freeze({ func: 926, arms: 826, size: 30643 }),
    Object.freeze({ func: 569, arms: 767, size: 29363 }),
    Object.freeze({ func: 547, arms: 751, size: 19799 }),
    Object.freeze({ func: 840, arms: 591, size: 27470 }),
    Object.freeze({ func: 1059, arms: 500, size: 30256 }),
    Object.freeze({ func: 1038, arms: 371, size: 13068 }),
    Object.freeze({ func: 1157, arms: 358, size: 12533 }),
    Object.freeze({ func: 724, arms: 257, size: 15720, role: "update_token" }),
    Object.freeze({ func: 667, arms: 136, size: 10780, role: "encrypt_worker" }),
    Object.freeze({ func: 349, arms: 113, size: 9464, role: "decrypt_worker" }),
  ]),
  keystream_bytes: LIVE_63D9_KEYSTREAM_TABLE,
  perm_table: LIVE_63D9_PERM_TABLE,
  perm_bytes_in_file: true,
  note: "Indexes are build-local. Never reuse LIVE_84FEB codec/export numbers here.",
});

/** Alias of LIVE_63D9.hsw_mode — parallel to LIVE_HSW_MODE for the 84feb build. */
const LIVE_63D9_HSW_MODE = LIVE_63D9.hsw_mode;

const LIVE_63D9_MAGIC = Object.freeze({
  decrypt_resp_data: -174010464,
  encrypt_req_data: -1483911731,
  update_token: 672652481,
});

const LIVE_E449_PERM_TABLE = Object.freeze([
  5, 13, 6, 2, 15, 14, 11, 4, 8, 7, 1, 10, 3, 12, 9, 0,
]);

const LIVE_E449_KEYSTREAM_TABLE = Buffer.from(
  "3c4b47fb9884801d970b2327075020898a75912e91ec6deba7ade6a6a5a07996" +
    "26dc8ea07c3ced44d851cef5d2d57be0b4c442304ba876996e5d4916afadd410" +
    "d753cc8f59097a119c46116a3b4bd291438f7221ab14f4e95a595f85e8059c11",
  "hex"
);

/**
 * Session 3478526452141784090 / hsw-live-e449a4e1.wasm — parallel profile.
 * Do not mix indexes with LIVE_84FEB or LIVE_63D9.
 * Glue binders proven via e449_glue_probe.json; mode 0/1 polarity glue-ascii-proven.
 * Nested bulk=537 (vs 937/1005); MBA=406 decrypt-only (vs 273/710); host a.t=19.
 */
const LIVE_E449 = Object.freeze({
  session: "3478526452141784090",
  artifact_id: null,
  sha256: "e449a4e1e119e7bdff8588785f6182f921fd76fa439cb0e46f44ae83ff7fd74a",
  bytes: 1030267,
  path: "hsw-live-e449a4e1.wasm",
  glue: Object.freeze({ decrypt: "aHz", encrypt: "aJp", update_token: "GC", hsw_params: "aQK,Vb,Wz" }),
  glue_note: "Ascii-proven in hsw-live-e449-glue.js: aHz→Yc(1668574287), aJp→Yc(1908833735), GC→Yc(-20745895). See LIVE_E449_GLUE.md",
  imported_functions: 191,
  defined_functions: 974,
  br_tables: 737,
  observations: 0,
  codec: Object.freeze({
    page: PAGE,
    hdr: HDR,
    chunk: CHUNK,
    load_i32: 719,
    store_i32: 397,
    load_u8: 219,
    store_i8: 364,
    store_i16: 1113,
    store_i64: 988,
    store_f32: 618,
    store_f64: 653,
    mark_dirty: 404,
    keystream: 323,
    keystream_period: KEYSTREAM_PERIOD,
    keystream_addr: 468,
    page_table: 600,
    page_table_base: PAGE_TABLE_BASE,
    perm_addr: PERM_ADDR,
    bulk_nested: 537,
    mba_pred: 406,
    host_t: 19,
  }),
  helpers: Object.freeze({
    19: "host_a_t_takeObject_gate",
    219: "load_u8",
    323: "keystream64_table",
    364: "store_i8",
    397: "store_i32",
    404: "mark_dirty_fill_keystream",
    406: "opaque_u8_roundtrip_sp15",
    537: "cursor_absorb_mba",
    600: "page_table",
    618: "store_f32",
    653: "store_f64",
    719: "load_i32",
    727: "update_token_cff",
    874: "encrypt_cff_worker",
    880: "decrypt_cff_worker",
    988: "store_i64",
    1068: "encrypt_trampoline_calls_874",
    1113: "store_i16",
    1138: "decrypt_trampoline_calls_880",
    1164: "export_Yc",
  }),
  host_gates: Object.freeze({
    gate_import: "t",
    gate_idx: 19,
    gate_arms: Object.freeze({ decrypt_880: 90, encrypt_874: 41 }),
    semantic: "takeObject_drop_handle",
    glue: "not_captured_isomorphic_to_84feb_Va_63d9_Cc",
    see: "HOST_GATES.md",
  }),
  exports: Object.freeze({
    Dc: 751,
    Ec: 960,
    Fc: 453,
    Gc: 293,
    Hc: 1080,
    Ic: 591,
    Jc: 1040,
    Kc: 906,
    Lc: 983,
    Mc: 978,
    Nc: 233,
    Oc: 778,
    Pc: 276,
    Qc: 988,
    Rc: 756,
    Sc: "memory0",
    Tc: 591,
    Uc: 424,
    Vc: 1161,
    Wc: 1162,
    Xc: 1163,
    Yc: 1164,
  }),
  yc_dispatch: Object.freeze({
    export: "Yc",
    func: 1164,
    role: "mode_and_codec_dispatcher",
    confidence: "high",
    note: "Magics+callees body-proven; live glue aHz/aJp/GC binds modes 0/1/2.",
    arms: Object.freeze([
      Object.freeze({
        magic: 1908833735,
        callee: 1068,
        family: "encrypt_trampoline",
        mode: 1,
        worker: 874,
      }),
      Object.freeze({ magic: -1301289479, callee: 618, family: "store_f32" }),
      Object.freeze({ magic: 1348470485, callee: 397, family: "store_i32" }),
      Object.freeze({
        magic: -20745895,
        callee: 727,
        family: "update_token_cff",
        mode: 2,
        worker: 727,
      }),
      Object.freeze({ magic: 1378004104, callee: 364, family: "store_i8" }),
      Object.freeze({ magic: 1433943068, callee: 653, family: "store_f64" }),
      Object.freeze({ magic: 1972652449, callee: 1113, family: "store_i16" }),
      Object.freeze({
        magic: 1668574287,
        callee: 1138,
        family: "decrypt_trampoline",
        mode: 0,
        worker: 880,
      }),
    ]),
  }),
  hsw_mode: Object.freeze({
    0: Object.freeze({
      id: 0,
      name: "decrypt",
      glue: "aHz",
      magic: 1668574287,
      yc: 1164,
      trampoline: 1138,
      worker: 880,
      arms: 102,
      entry_state: 70,
      confidence: "high",
      bind_via: "glue_live_plus_yc_body",
      path: Object.freeze(["hsw(0)", "aHz", "Yc", 1138, 880]),
      note: "Live glue aHz; polarity matches trampoline→880",
    }),
    1: Object.freeze({
      id: 1,
      name: "encrypt",
      glue: "aJp",
      magic: 1908833735,
      yc: 1164,
      trampoline: 1068,
      worker: 874,
      arms: 120,
      entry_state: 103,
      confidence: "high",
      bind_via: "glue_live_plus_yc_body",
      path: Object.freeze(["hsw(1)", "aJp", "Yc", 1068, 874]),
      note: "Live glue aJp; polarity matches trampoline→874",
    }),
    2: Object.freeze({
      id: 2,
      name: "update_token",
      glue: "GC",
      magic: -20745895,
      yc: 1164,
      trampoline: null,
      worker: 727,
      arms: 270,
      entry_state: 152,
      confidence: "high",
      bind_via: "glue_live_plus_yc_body",
      path: Object.freeze(["hsw(2)", "GC", "Yc", 727]),
    }),
    jwt: Object.freeze({
      id: "jwt",
      name: "proof_uc",
      glue: null,
      export: "Uc",
      func: 424,
    }),
  }),
  cff_hypothesis: Object.freeze({
    encrypt: Object.freeze({
      mode: 1,
      glue: "aJp",
      magic: 1908833735,
      trampoline: 1068,
      func: 874,
      arms: 120,
      entry_state: 103,
      bulk_nested: 537,
      host_gate_arm: 41,
      frame_slot: 1100,
      params: "stack_frame_via_1068",
      path: Object.freeze([1164, 1068, 874]),
      confidence: "high",
      bind_via: "glue_live_plus_yc_body_plus_arm_clusters",
    }),
    decrypt: Object.freeze({
      mode: 0,
      glue: "aHz",
      magic: 1668574287,
      trampoline: 1138,
      func: 880,
      arms: 102,
      entry_state: 70,
      bulk_nested: 537,
      mba_arm: 50,
      mba_func: 406,
      host_gate_arm: 90,
      frame_slot: 1096,
      params: "stack_frame_via_1138",
      path: Object.freeze([1164, 1138, 880]),
      confidence: "high",
      bind_via: "glue_live_plus_yc_body_plus_arm_clusters",
    }),
    update_token: Object.freeze({
      mode: 2,
      glue: "GC",
      magic: -20745895,
      func: 727,
      arms: 270,
      entry_state: 152,
      bulk_nested: 537,
      path: Object.freeze([1164, 727]),
      confidence: "high",
      bind_via: "glue_live_plus_yc_body_plus_shape",
    }),
    yc_is_mode_dispatch: true,
    nested_bulk_analogue: Object.freeze({
      e449: 537,
      "63d9": 937,
      "84feb": 1005,
      role: "cursor_absorb_mba",
    }),
  }),
  cff: Object.freeze({
    nested: Object.freeze({
      537: Object.freeze({
        body_len: 689,
        params: 2,
        extra_locals: Object.freeze({ i32: 6, i64: 11 }),
        arms: 10,
        unique: 11,
        entry_state: 0,
        state_local: 2,
        intern_calls: Object.freeze({ 719: 8, 397: 6, 364: 2, 219: 1 }),
        role: "cursor_absorb_mba",
        vs_937: "remapped_cousin_smaller_machine",
        vs_1005: "remapped_cousin_different_machine",
        cursor_fields: Object.freeze({
          begin: 0,
          end_or_mark: 4,
          len_or_cap: 8,
          limit: 12,
          counter: 16,
          secondary: 20,
        }),
        note:
          "Byte-absorb + opaque i64 MBA folded into arm 9; status store8×2 @arg0. Smaller cousin of 63d9 937 (not isomorphic); not 84feb 1005 lane pack.",
      }),
      406: Object.freeze({
        body_len: 25,
        params: 1,
        role: "opaque_u8_roundtrip",
        analogue_63d9: 273,
        analogue_84feb: 710,
        proven: "sp-=16; store_u8(sp,arg,15) via 364; return load_u8(sp,15) via 219",
        vs_273: "byte_isomorphic_linear",
        vs_710: "same_sp15_core; 710 adds vacuous 5-arm MBA wrapper",
      }),
    }),
  }),
  largest_cff: Object.freeze([
    Object.freeze({ func: 1142, arms: 752, size: 30447 }),
    Object.freeze({ func: 696, arms: 725, size: 28832 }),
    Object.freeze({ func: 1096, arms: 594, size: 27512 }),
    Object.freeze({ func: 943, arms: 545, size: 20423 }),
    Object.freeze({ func: 727, arms: 270, size: 14756, role: "update_token" }),
    Object.freeze({ func: 874, arms: 120, size: 10433, role: "encrypt_worker" }),
    Object.freeze({ func: 880, arms: 102, size: 9594, role: "decrypt_worker" }),
  ]),
  keystream_bytes: LIVE_E449_KEYSTREAM_TABLE,
  perm_table: LIVE_E449_PERM_TABLE,
  perm_bytes_in_file: true,
  note: "Indexes are build-local. Never reuse LIVE_84FEB/LIVE_63D9 codec/export numbers here.",
});

const LIVE_E449_HSW_MODE = LIVE_E449.hsw_mode;

const LIVE_E449_MAGIC = Object.freeze({
  decrypt_resp_data: 1668574287,
  encrypt_req_data: 1908833735,
  update_token: -20745895,
});


const LIVE_SESSION = Object.freeze({
  id: "5369273503095065946",
  endpoint: "http://127.0.0.1:57457",
  brave: "reb-v0.5.0",
  category_mask: 1920,
  challenge: "image_label_area_select_pattern",
  wasm_sha256_prefix: "84febfac",
  /** Challenge-frame window.hsw minified names match art12 / LIVE_63D9 (bbD/aVj/aOF). */
  active_challenge_glue_names: Object.freeze(["bbD", "aVj", "aOF"]),
  notes:
    "Fingerprint categories off (Aw Snap HandleScope). Native br_table samples capped at 16. " +
    "Both 84febfac and 63d9f8a3 wasm appear in-session; live hsw() string uses 63d9-style glue ids.",
});

const CLICK_SESSION = Object.freeze({
  id: "9623810216396876129",
  getcaptcha_json_bytes: 822,
  postclick_octet_stream_bytes: 2613,
  challenge: "image_drag_drop",
  requests: Object.freeze([
    { id: 4, method: "GET", host: "accounts.hcaptcha.com", decoded: 4359, mime: "text/html" },
    { id: 5, method: "GET", host: "js.hcaptcha.com", decoded: 415879, mime: "application/javascript", artifact: 2 },
    { id: 11, method: "POST", host: "api.hcaptcha.com", decoded: 822, mime: "application/json", role: "getcaptcha" },
    { id: 12, method: "GET", host: "newassets.hcaptcha.com", decoded: 1543169, mime: "application/javascript", artifact: 4 },
    { id: 13, method: "POST", host: "api.hcaptcha.com", decoded: 2613, mime: "application/octet-stream", role: "postclick_proof" },
    { id: 14, method: "GET", host: "newassets.hcaptcha.com", decoded: 33480, mime: "text/javascript", artifact: 6, challenge: "image_drag_drop" },
    { id: 15, method: "GET", host: "imgs3.hcaptcha.com", decoded: 40878, mime: "image/jpeg" },
    { id: 16, method: "GET", host: "imgs3.hcaptcha.com", decoded: 3729, mime: "image/png" },
    { id: 17, method: "GET", host: "imgs3.hcaptcha.com", decoded: 5019, mime: "image/png" },
  ]),
});

const OCTET_ENVELOPE = Object.freeze({
  contentType: "application/octet-stream",
  byteLength: 2613,
  after: { req: 11, mime: "application/json", byteLength: 822, role: "getcaptcha" },
  before: { req: 14, mime: "text/javascript", byteLength: 33480, challenge: "image_drag_drop" },
  fieldLayout: "unknown",
  nativePayload: "METHOD+host only",
});

function hswModeDispatch(mode, preferLive) {
  const table = preferLive === false ? HSW_MODE : LIVE_HSW_MODE;
  if (mode === 0 || mode === "0") return table[0];
  if (mode === 1 || mode === "1") return table[1];
  if (mode === 2 || mode === "2") return table[2];
  return table.jwt || HSW_MODE.jwt;
}

async function hsw(mode, a, b) {
  await alC();
  const d = hswModeDispatch(mode, true);
  if (d.id === 0) return decrypt_resp_data(a);
  if (d.id === 1) return encrypt_req_data(a);
  if (d.id === 2) return update_token(a, float64Snapshot(b));
  const jwt = parseCompactJwt(mode);
  return aeB(JSON.stringify(jwt.payload), Math.round(Date.now() / 1000), a, b);
}

function parseCompactJwt(token) {
  const parts = String(token).split(".");
  if (parts.length < 2) {
    return { header: {}, payload: {}, signature: "" };
  }
  const dec = (s) => {
    try {
      const pad = s + "===".slice((s.length + 3) % 4);
      const b64 = pad.replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
    } catch (err) {
      return {};
    }
  };
  return { header: dec(parts[0]), payload: dec(parts[1]), signature: parts[2] || "" };
}

function alC() {
  return Promise.resolve();
}
function float64Snapshot(x) {
  return x == null ? null : Number(x);
}
function update_token(token, snap) {
  return { token: token == null ? null : String(token), snapshot: snap };
}

const NV = (() => {
  const a = new Array(1024).fill(undefined);
  a.push(undefined, null, true, false);
  return a;
})();

function xX(idx) {
  return NV[idx >>> 0];
}
function addHeapObject(value) {
  NV.push(value);
  return NV.length - 1;
}
function takeObject(idx) {
  const v = NV[idx];
  if (idx >= HEAP_RESERVED) NV[idx] = undefined;
  return v;
}

class LinearMemory {
  constructor(bytes) {
    this.buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 1 << 20);
    this.installTables();
  }
  installTables() {
    this.buf[0] = 0x11;
    for (let i = 0; i < PERM_TABLE.length; i++) this.buf[PERM_ADDR + i] = PERM_TABLE[i];
    for (let i = 0; i < KEYSTREAM_TABLE.length; i++) this.buf[KEYSTREAM_ADDR + i] = KEYSTREAM_TABLE[i];
  }
  u8(addr) {
    return this.buf[addr >>> 0] || 0;
  }
  u8set(addr, v) {
    this.buf[addr >>> 0] = v & 0xff;
  }
  i32_unaligned(addr) {
    const a = addr >>> 0;
    const b = this.buf;
    return (b[a] | (b[a + 1] << 8) | (b[a + 2] << 16) | (b[a + 3] << 24)) | 0;
  }
  i32_unaligned_set(addr, value) {
    const a = addr >>> 0;
    const v = value | 0;
    this.buf[a] = v & 0xff;
    this.buf[a + 1] = (v >>> 8) & 0xff;
    this.buf[a + 2] = (v >>> 16) & 0xff;
    this.buf[a + 3] = (v >>> 24) & 0xff;
  }
  i64(addr) {
    const a = addr >>> 0;
    const lo = this.i32_unaligned(a) >>> 0;
    const hi = this.i32_unaligned(a + 4) >>> 0;
    return (BigInt(hi) << 32n) | BigInt(lo);
  }
}

function pageIndex(addr) {
  return ((addr >>> 0) / PAGE) >>> 0;
}
function pageRem(addr) {
  return ((addr >>> 0) % PAGE) >>> 0;
}

function permNibble(chunkIndex, mem) {
  const i = chunkIndex >>> 0;
  if (mem) return mem.u8(PERM_ADDR + (i & 15));
  return PERM_TABLE[i & 15];
}

function chunkDescriptor(chunkIndex, mem) {
  const i = chunkIndex >>> 0;
  const scrambled = permNibble(i, mem) | (i & ~15);
  return (PAGE_TABLE_BASE + scrambled * CHUNK) >>> 0;
}

function addrKeystream(addr, mem) {
  const p = KEYSTREAM_ADDR + ((addr >>> 0) % KEYSTREAM_PERIOD);
  if (mem) return mem.i64(p);
  const lo = KEYSTREAM_TABLE.readUInt32LE(p - KEYSTREAM_ADDR);
  const hi = KEYSTREAM_TABLE.readUInt32LE(p - KEYSTREAM_ADDR + 4);
  return (BigInt(hi) << 32n) | BigInt(lo);
}

function wrap32(k) {
  return Number(k & 0xffffffffn) | 0;
}

function markDirty(mem, chunkIndex) {
  const desc = chunkDescriptor(chunkIndex, mem);
  if (mem.u8(desc) !== 0) return;
  mem.u8set(desc, 1);
  const base = desc + HDR;
  const vbase = (chunkIndex >>> 0) * PAGE;
  for (let i = 0; i < PAGE; i++) {
    const k = addrKeystream(vbase + i, mem);
    mem.u8set(base + i, Number(k & 0xffn));
  }
}

function load_i32(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk, mem);
  const slot = desc + HDR + rem;
  const isCached = mem.u8(desc) !== 0;
  const overlap = rem - (PAGE - 4);
  const k = addrKeystream(addr, mem);

  if (overlap <= 0) {
    return isCached ? mem.i32_unaligned(slot) : wrap32(k);
  }

  const nextDesc = chunkDescriptor(chunk + 1, mem);
  const nextCached = mem.u8(nextDesc) !== 0;
  const nextSlot = nextDesc + HDR;
  const splitAt = 4 - overlap;
  const bytes = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    const useNext = i >= splitAt;
    const cached = useNext ? nextCached : isCached;
    if (cached) {
      bytes[i] = useNext ? mem.u8(nextSlot + (i - splitAt)) : mem.u8(slot + i);
    } else {
      bytes[i] = Number((k >> BigInt(8 * i)) & 0xffn);
    }
  }
  return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) | 0;
}

function store_i32(mem, base, value, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk, mem);
  const slot = desc + HDR + rem;
  markDirty(mem, chunk);
  markDirty(mem, chunk + 1);
  const mixed = (value ^ wrap32(addrKeystream(addr, mem))) | 0;
  const overlap = rem - (PAGE - 4);
  if (overlap <= 0) {
    mem.i32_unaligned_set(slot, mixed);
    return;
  }
  const nextSlot = chunkDescriptor(chunk + 1, mem) + HDR;
  const splitAt = 4 - overlap;
  for (let i = 0; i < 4; i++) {
    const b = (mixed >>> (8 * i)) & 0xff;
    if (i < splitAt) mem.u8set(slot + i, b);
    else mem.u8set(nextSlot + (i - splitAt), b);
  }
}

function store_i8(mem, base, value, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const slot = chunkDescriptor(chunk, mem) + HDR + rem;
  markDirty(mem, chunk);
  const mixed = (value ^ wrap32(addrKeystream(addr, mem))) & 0xff;
  mem.u8set(slot, mixed);
}

function load_u8(mem, base, off) {
  const addr = (base + off) >>> 0;
  const chunk = pageIndex(addr);
  const rem = pageRem(addr);
  const desc = chunkDescriptor(chunk, mem);
  const slot = desc + HDR + rem;
  const k = wrap32(addrKeystream(addr, mem));
  const raw = mem.u8(desc) !== 0 ? mem.i32_unaligned(slot) : k;
  return (raw ^ k) & 0xff;
}

function store_f32(mem, base, value, off) {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setFloat32(0, Number(value), true);
  store_i32(mem, base, new Int32Array(buf)[0], off);
}

function store_f64(mem, base, value, off) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setFloat64(0, Number(value), true);
  const view = new Uint32Array(buf);
  store_i32(mem, base, view[0] | 0, off);
  store_i32(mem, base, view[1] | 0, off + 4);
}

function resultUnpack(destHandle, workerOut) {
  const flag = workerOut && workerOut.flag ? 1 : 0;
  const ok = flag ? 0 : workerOut && "ok" in workerOut ? workerOut.ok : destHandle;
  const err = flag ? (workerOut && workerOut.err) || 1 : 0;
  return {
    dest: destHandle,
    ok,
    err,
    flag,
    layout: CLICK_WASM.cff.result_unpack,
  };
}

function encrypt_req_data(jsValue) {
  const handle = addHeapObject(jsValue);
  const live = LIVE_HSW_MODE[1];
  return {
    ok: takeObject(handle),
    err: 0,
    flag: 0,
    path: "Yc/aHO/1103/796",
    magic: live.magic,
    trampoline: live.trampoline,
    worker: live.worker,
    arms: live.arms,
    clickFallback: Object.freeze({ path: "Xc/encrypt/func585", magic: -77630479, worker: 585 }),
  };
}
function decrypt_resp_data(jsValue) {
  const handle = addHeapObject(jsValue);
  const live = LIVE_HSW_MODE[0];
  return {
    ok: takeObject(handle),
    err: 0,
    flag: 0,
    path: "Yc/akZ/777/298",
    magic: live.magic,
    trampoline: live.trampoline,
    worker: live.worker,
    arms: live.arms,
    clickFallback: Object.freeze({
      path: "Xc/decrypt/func967/func612",
      magic: 44633705,
      trampoline: 967,
      worker: 612,
    }),
  };
}
function aeB(payloadJson, unixSec, extra, progress) {
  return Promise.resolve({
    path: "Uc/func491/func659",
    payloadBytes: Buffer.byteLength(String(payloadJson || ""), "utf8"),
    unixSec,
    extra: extra == null ? null : extra,
    progress: progress == null ? null : progress,
  });
}

function Wc(magic, a, b, mem) {
  const row = CLICK_WASM.magic_get[magic] || CLICK_WASM.magic_get[String(magic | 0)];
  if (!row) throw new Error("Wc: unknown magic " + magic);
  if (row.name === "init_opfs_session") return 0;
  if (row.callee === 329) return row.swap ? load_i32(mem, b, a) : load_i32(mem, a, b);
  if (row.callee === 867) return row.swap ? load_u8(mem, b, a) : load_u8(mem, a, b);
  if (row.callee === 695) return addrKeystream((a + b) >>> 0, mem);
  return load_i32(mem, row.swap ? b : a, row.swap ? a : b);
}

function Xc(magic, a, b, c, d, e, f, mem) {
  const row = CLICK_WASM.magic_set[magic] || CLICK_WASM.magic_set[String(magic | 0)];
  if (!row) throw new Error("Xc: unknown magic " + magic);
  if (row.callee === 1129) {
    store_i32(mem, a, b, c);
    return;
  }
  if (row.callee === 1042) {
    store_i8(mem, a, b, c);
    return;
  }
  if (row.callee === 585) return encrypt_req_data(xX(a));
  if (row.callee === 967) return decrypt_resp_data(xX(a));
  if (row.callee === 656) {
    return resultUnpack(a, { ok: xX(a), err: 0, flag: 0 });
  }
  if (row.callee === 799) {
    store_f32(mem, a, b, c);
    return;
  }
  if (row.callee === 642) {
    store_f64(mem, a, b, c);
    return;
  }
  return { magic: magic | 0, callee: row.callee, name: row.name, worker: row.worker || null };
}

function Yc(magic, a, b, c, mem) {
  switch (magic | 0) {
    case LIVE_MAGIC.encrypt_req_data:
    case MAGIC.encrypt_req_data:
      return encrypt_req_data(xX(b));
    case LIVE_MAGIC.decrypt_resp_data:
    case MAGIC.decrypt_resp_data:
      return decrypt_resp_data(xX(a));
    case LIVE_MAGIC.update_token:
      return update_token(xX(a), float64Snapshot(b));
    case LIVE_MAGIC.store_i32:
      store_i32(mem, a, b, c);
      return;
    case MAGIC.setInt32:
      store_i32(mem, c, b, a);
      return;
    default:
      return Xc(magic, a, b, c, 0, 0, 0, mem);
  }
}

function cffLoop(entryState, arms, maxSteps) {
  let state = entryState | 0;
  const trace = [];
  const limit = maxSteps == null ? 1024 : maxSteps;
  for (let i = 0; i < limit; i++) {
    trace.push(state);
    const arm = arms[state];
    if (typeof arm !== "function") break;
    const next = arm(state);
    if (next === "halt" || next === state) break;
    state = next | 0;
  }
  return { state, steps: trace.length, trace };
}

function cffEncrypt(handle, mem) {
  const spec = CLICK_WASM.cff.encrypt;
  const intern = {
    load: 329,
    load8: 867,
    store: 1129,
    store8: 1042,
    store64: 464,
    dirty: 248,
    key: 1014,
    desc: 928,
    helper816: 816,
    helper683: 683,
    helper343: 343,
    worker: spec.worker,
    trampoline: spec.trampoline,
    arms: spec.arms,
    state_local: spec.state_local,
    intern_calls: spec.intern_calls,
  };
  const arms = {
    0: () => 1,
    1: () => intern.load,
    [intern.load]: () => intern.load8,
    [intern.load8]: () => intern.store,
    [intern.store]: () => "halt",
  };
  const run = cffLoop(0, arms, 16);
  return { ok: handle, err: 0, flag: 0, intern, steps: run.steps, path: "Xc/func585" };
}

function cffDecrypt(handle, mem) {
  const spec = CLICK_WASM.cff.decrypt;
  const intern = {
    load: 329,
    load8: 867,
    store: 1129,
    store8: 1042,
    store64: 464,
    dirty: 248,
    key: 1014,
    desc: 928,
    helper816: 816,
    worker: spec.worker,
    trampoline: spec.trampoline,
    arms: spec.arms,
    state_local: spec.state_local,
    intern_calls: spec.intern_calls,
  };
  const arms = {
    0: () => intern.trampoline,
    [intern.trampoline]: () => intern.worker,
    [intern.worker]: () => intern.load,
    [intern.load]: () => intern.store,
    [intern.store]: () => "halt",
  };
  const run = cffLoop(0, arms, 16);
  const unpacked = resultUnpack(handle, { ok: handle, err: 0, flag: 0 });
  return {
    ok: unpacked.ok,
    err: unpacked.err,
    flag: unpacked.flag,
    intern,
    steps: run.steps,
    path: "Xc/func967/func612",
  };
}

function cffAlt(handle, mem) {
  const spec = CLICK_WASM.cff.alt;
  const intern = {
    load: 329,
    load8: 867,
    store: 1129,
    worker: spec.worker,
    trampoline: spec.trampoline,
    arms: spec.arms,
    intern_calls: spec.intern_calls,
    role: spec.role,
  };
  const arms = {
    0: () => intern.trampoline,
    [intern.trampoline]: () => intern.worker,
    [intern.worker]: () => "halt",
  };
  const run = cffLoop(0, arms, 16);
  return { ok: handle, err: 0, flag: 0, intern, steps: run.steps, path: "Xc/func656/func630" };
}

const POW = {
  BATCH_SIZE: 16,
  ROTATION: 173,
  SHA1_DIGEST_SIZE: 20,
};

function checkLeadingZeroBits(digest, bits) {
  const fullBytes = Math.floor(bits / 8);
  const partialBits = bits % 8;
  for (let i = 0; i < fullBytes; i++) {
    const byteIdx = (POW.ROTATION + i) % POW.SHA1_DIGEST_SIZE;
    if (digest[byteIdx] !== 0) return false;
  }
  if (partialBits > 0) {
    const byteIdx = (POW.ROTATION + fullBytes) % POW.SHA1_DIGEST_SIZE;
    const threshold = 1 << (8 - partialBits);
    if (digest[byteIdx] >= threshold) return false;
  }
  return true;
}

const api = {
  HOST_IMPORTS,
  HOST_FAMILIES,
  HSW_MODE,
  LIVE_HSW_MODE,
  LIVE_MAGIC,
  LIVE_63D9_HSW_MODE,
  LIVE_63D9_MAGIC,
  LIVE_E449_HSW_MODE,
  LIVE_E449_MAGIC,
  MAGIC,
  PAGE,
  HDR,
  CHUNK,
  HEAP_RESERVED,
  PERM_TABLE,
  KEYSTREAM_TABLE,
  POW,
  CLICK_SESSION,
  CLICK_WASM,
  GLUE_LIVE,
  LIVE_84FEB,
  LIVE_63D9,
  LIVE_E449,
  LIVE_KEYSTREAM_TABLE,
  LIVE_PERM_TABLE,
  LIVE_63D9_KEYSTREAM_TABLE,
  LIVE_63D9_PERM_TABLE,
  LIVE_E449_KEYSTREAM_TABLE,
  LIVE_E449_PERM_TABLE,
  LIVE_SESSION,
  Yc,
  OCTET_ENVELOPE,
  hsw,
  hswModeDispatch,
  parseCompactJwt,
  LinearMemory,
  pageIndex,
  pageRem,
  chunkDescriptor,
  addrKeystream,
  markDirty,
  load_i32,
  load_u8,
  store_i32,
  store_i8,
  store_f32,
  store_f64,
  resultUnpack,
  encrypt_req_data,
  decrypt_resp_data,
  update_token,
  aeB,
  Wc,
  Xc,
  Yc,
  cffLoop,
  cffEncrypt,
  cffDecrypt,
  cffAlt,
  checkLeadingZeroBits,
  xX,
  addHeapObject,
  takeObject,
};

module.exports = api;
