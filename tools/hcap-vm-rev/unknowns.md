# Remaining HSW cores (not a solver)

Session `9623810216396876129`. Tools: reb-api CLI on `http://127.0.0.1:56738`
(`get_session_context`, `get_artifacts`, `get_events`, `get_vm_analysis`,
`inspect_wasm`), static parse of `hsw-click.wasm`, reconstructive `guest_ops.js`.

## Codec — EXACT

| Func | Role |
|---|---|
| 1014 | `i64.load(195 + (addr % 96))` |
| 928 | `1024 + 328 * (perm[chunk&15] \| (chunk&~15))` |
| 329 | load_i32 cached ciphertext / uncached wrap(keystream), split rem>316 |
| 1129 | store_i32 XOR keystream after markDirty |
| 248 | markDirty fill 320 bytes with keystream |
| 867 | load_u8: cached `i32.load` XOR keystream AND 255 (plaintext byte) |
| 799 | store_f32 bits XOR keystream, split rem>316 |
| 642 | store_f64 bits XOR keystream, split rem>312 |

## CFF intern-call map — trampolines + workers identified, arms not decompiled

| Glue magic (Xc) | Trampoline | Worker | Arms | Role |
|---|---|---|---|---|
| -77630479 | — | 585 | 251 | encrypt |
| 44633705 | 967 Result-unpack | 612 | 133 | decrypt |
| -721101446 | 656 Result-unpack | 630 | 112 | unknown (update_token candidate) |

Tried: dump_list + `cff_intern_click.txt` + `cff_classify.txt`. Reconstructive
`cffEncrypt` / `cffDecrypt` / `cffAlt` run intern-call state machines on synthetic
handles. Plan non-goal: every CFF arm.

Nested CFF helpers inside those machines (bodies summarized, roles unnamed):

- **816** 20-arm 1255 B — named `vec_or_slice_cursor` (ptr@0, end@4, cap@8)
- **683** 34-arm 8347 B (encrypt 585) — unnamed nested CFF
- **815** 4-arm 138 B — named `opaque_u8_roundtrip`
- **343** 9 B thunk → 356

Opus 5.5 follow-up (nested intern names):
[Opus 5.5 HSW nested CFF intern names](t3-thread://v1/mcp:52cec821-7997-407f-8369-133784436caa)

Provider `[cyber]` AUP stopped Opus 5.5 on that thread (stayed on 5.5 per user; did not switch to 4.8). 815 named `opaque_u8_roundtrip`. 816 named `vec_or_slice_cursor` from ptr/end/cap loads. 683 still unnamed. Do not flatten 585/612/630 into a live replica.

Opus 5.5 (prior, safety-refused standalone replica):
[Opus 5.5 HSW CFF remap lift](t3-thread://v1/mcp:2a15135d-a5bd-48cc-bef1-72e6a7e757bc)

## POST 2613 octet-stream — envelope known, fields unknown

reb-api `get_events` request 13: decoded 2613. Native payload is METHOD+host
only (hex `completed`). Order: JSON 822 (req 11) → octet-stream 2613 (req 13) →
challenge.js image_drag_drop (req 14 / art 6) → imgs3 tiles. Field layout
unknown. Do not recover tokens.

## Native wasm dispatch samples

0 `wasm_dispatch_observation` rows. Static br_table maps remain. Detector
1.9.0: 1 likely-vm, 3 candidates, 0 failed.

---

## Live builds — remaining unknowns (2026-11-01)

### Host gates — PROVEN (see `HOST_GATES.md`)

| build | import | idx | arms | semantic |
|-------|--------|----:|------|----------|
| 84feb | a.Va | 101 | 298@85 / 796@17 | takeObject drop; wasm `(i32)->()` |
| 63d9 | a.Cc | 190 | 349@92 / 667@32 | takeObject drop; wasm `(i32)->()` |
| e449 | a.t | 19 | 880@90 / 874@41 | takeObject drop (glue isomorphic; not captured) |

Uint8Array thunks: 63d9 **218→a.hc(169)**; 84feb **1141→a.oa(68)**. Real
`isSafeInteger`: 84feb **a.aa#54**; 63d9 **a.y#24** (no small thunks). Not length /
byteLength / PRT instanceof / Date (those are base-catalog or other live imports).

### Opaque / bulk MBA — see `MBA_OPAQUE.md`

- **710/273/406**: same SP+15 core (710 = vacuous 5-arm wrapper). Remaining: live stack-page XOR cancel.
- **1005/937/537**: not isomorphic (1005 = i64 lane pack; 937/537 = `cursor_absorb_mba` cousins). i64 samples exported; math opaque.

### LIVE_84FEB (298/796) — still open

1. ~~Full 115/142-arm transition graphs~~ → see `CFF_GRAPHS.md` / `cff_graphs.js`.
2. Nested CFF **1005** i64 lane layout / cipher linkage (samples on `I64_MBA_SAMPLES_1005`).
3. Whether **710** SP+15 cancels under XOR on the live stack page (MBA itself is vacuous).
4. Internal **1158** vs export Xc=1165.
5. Helpers 454 / 231 / 598 around decrypt entry.

### LIVE_63D9 (349/667) — deepened; still open

Proven this pass (see `LIVE_CFF_349_667.md` / `HOST_GATES.md`):

| Func | Role |
|-----:|------|
| 863 | load_u8 XOR (84feb 859) |
| 1026 | store_u8 XOR (84feb 957) |
| 637 | store_i64 XOR rem>312 (84feb 858) |
| 1154 | store_i16 XOR rem>318 (**not** init_opfs) |
| 273 | opaque store8/load8 SP+15 (84feb 710 analogue; decrypt-only) |
| 218 | thunk → a.hc(169) **`new Uint8Array(size)`** (not isSafeInteger) |
| 190 | a.Cc takeObject gate |

Still open:

1. ~~Full 113/136-arm graphs~~ → `CFF_GRAPHS.md`; **377** MBA 5-arm gate map still open.
2. Nested CFF **937** — arms + role **`cursor_absorb_mba`** lifted; vs 1005 = **remapped cousin / different machine**. Remaining cipher blockers: i64 MBA constants (`7751723099346266405`, …), absorb+rotl hash identity, `wrap+212` ptr bias. See `arm_clusters_937.json` / `LIVE_CFF_349_667.md`.
3. Why encrypt 667 never hits export Xc=1169.
4. Cipher / proof math — out of scope (not a solver).

## LIVE_E449 (sha e449a4e1) — profile + clusters bound

Session `3478526452141784090`. Wasm `/tmp/hcap-vm-rev/hsw-live-e449a4e1.wasm`.
Static analyze via `wasm-analyze` → `out_e449/`. Profile `LIVE_E449` in `guest_ops.js`.
Clusters: `arm_clusters_874_880.json` / `LIVE_CFF_874_880.md` / `cff_e449_{en,de}crypt.js`.

| Item | Status |
|------|--------|
| Yc / magics / trampolines / workers | **Known** (Yc=1164; 1068→874; 1138→880; 727) |
| Codec load/store/keystream/page_table | **Known** (719/397/323@468/600; 219 load_u8; 364 store_u8; 988 store_i64) |
| Mode 0/1 polarity | **Glue-proven** — aHz→880, aJp→874, GC→727 |
| Glue minified names | **Known** via `/tmp/hcap-live-observe2/e449_glue_probe.json` |
| Nested bulk helper | **537** (11-arm lifted; role `cursor_absorb_mba`; vs 937 = smaller cousin) |
| MBA decrypt-only | **406** @arm 50 — body proven SP+15 store8/load8 (≡ 273 / ~710) |
| Host gate | **a.t (19)** takeObject drop @arm 41 (874) / 90 (880) — **proven by type+shape** |
| CFF arm bodies 874/880/727 | **Clustered, not decompiled** (same non-goal as prior builds) |
| Live native dispatch samples for e449 | **0** observed in this pass |

Proven this pass (see `LIVE_CFF_874_880.md` / `arm_clusters_537.json`):

| Func | Role |
|-----:|------|
| 537 | `cursor_absorb_mba` (11-arm; absorb+MBA folded into arm 9) |
| 406 | `opaque_u8_roundtrip_sp15` (364@15 / 219@15; decrypt-only) |
| 19 | a.t takeObject gate (`(i32)->()`) |

Still open:

1. ~~Full 120/102-arm transition graphs~~ → see `CFF_GRAPHS.md` / `cff_graphs.js`.
2. Nested CFF **537** — MBA cipher blockers: i64 consts, absorb+rotl identity, status→parent mapping. See `arm_clusters_537.json`.
3. Whether **406** is identity on `{0,1}` after scrambled SP+15 roundtrip.
4. e449 glue body for `a.t` / Uint8Array / isSafeInteger analogues (binder not captured).
5. Cipher / proof math — out of scope (not a solver).
