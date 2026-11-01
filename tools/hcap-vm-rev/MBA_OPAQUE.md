# MBA / opaque u8 helpers (reconstructive)

Not a solver. Bodies dumped from live wasm; cipher math **not** invented.
Workspace: `/tmp/hcap-vm-rev/`. Cross-build ids are build-local — never mix.

## Isomorphism table

| role | 84feb | 63d9 | e449 | verdict |
|------|------:|-----:|-----:|---------|
| opaque u8 (decrypt-only) | **710** | **273** | **406** | **same SP+15 core**; 710 wraps it in a vacuous 5-arm mini-CFF |
| bulk nested CFF | **1005** | **937** | **537** | **not isomorphic** — 1005 = i64 lane pack; 937/537 = `cursor_absorb_mba` cousins |

Parent call budgets (decrypt / encrypt workers):

| helper | decrypt arm / × | encrypt × |
|--------|-----------------|----------:|
| 710 | 298@19 / ×17 | 0 |
| 273 | 349@68 / ×17 | 0 |
| 406 | 880@50 / ×17 | 0 |
| 1005 | 298 ×39 | 796 ×39 |
| 937 | 349 ×34 | 667 ×36 |
| 537 | 880 ×36 | 874 ×36 |

---

## Opaque u8 — 710 / 273 / 406

### Known structure

All three are used as an AND-chain wrapper on `i32.eq` results inside a single decrypt arm (16× byte-eq + 1× final).

**273** (63d9) — body `@46672+25`, params 1, linear:

```
sp -= 16
store_u8(sp, arg, 15) via 1026
return load_u8(sp, 15) via 863
```

**406** (e449) — body `@166577+25`, params 1, **byte-isomorphic** to 273:

```
sp -= 16
store_u8(sp, arg, 15) via 364
return load_u8(sp, 15) via 219
```

**710** (84feb) — body `@544701+146`, params 1, **5-arm** mini-CFF (`br_table` arms=4 default=4 → unique 5):

| state | arm | effect |
|------:|-----|--------|
| 0 (entry) | MBA fork | opaque i32 poly on arg → set state **2** or **3** |
| 2 | SP+15 A | `sp-=16; store_u8(sp,arg,15) via 957; load_u8 via 859 → local2; state←1` |
| 3 | SP+15 B | **identical** to arm 2 (only `br` depth differs) |
| 1 | return | `return local2` |
| 4 | unreachable | default |

Arms 2 and 3 are observationally the same SP+15 store8/load8 pair as 273/406.
The MBA only chooses between two identical roundtrips — **vacuous for the return value**.

710 MBA i32 samples (exported on `cff_live_decrypt.js` constants; **unknown cipher — do not invent**):

```
2021161783, -129149119, 1245555740, -620431147, 620431146
```

Shape: `x = (arg ^ A) * B - C; ((x & M) | (x & ~M_comp)) != x → 3 else 2`.

Stubs: `opaquePred710` / `opaquePred273` / `opaquePred406` — structural identity on `{0,1}`; no cipher evaluated.

### Unknown cipher (stop inventing)

1. Whether the live stack page at `SP+15` is always warm so codec XOR cancels (identity on the bit).
2. Why 84feb wraps the same core in a mini-CFF + vacuous MBA instead of the linear 25 B form.
3. Any meaning of the 710 MBA constants beyond dead control-flow noise.

---

## Bulk nested — 1005 / 937 / 537

### Known structure

| func | build | body | arms | entry | role | store_i64 |
|-----:|-------|-----:|-----:|------:|------|----------:|
| **1005** | 84feb | +4005 | 21 | 15 | **i64 lane pack** | **858×147** (consts 360…504 step 8) |
| **937** | 63d9 | +1386 | 17 | 4 | **`cursor_absorb_mba`** | **0** |
| **537** | e449 | +689 | 11 | 0 | **`cursor_absorb_mba`** | **0** |

Shared across all three:

- nested CFF called once per parent bulk arm
- 2 params `(statusSlot, cursorOrPackSlot)`
- exit via `store8×2` status (shape)

**937 vs 537** — remapped cousin / smaller machine (not isomorphic):

- shared: bounds loads 0/4/8/12, exit store8×2, zero store_i64, absorb+rotl+i64 MBA
- different: 17 vs 11 arms; 537 folds absorb+MBA into arm 9; 937 splits `mba_i64_mix` / `codec_absorb_mba` / `mba_i32_pred`; 937 entry seeds XOR `-1561962215`

**1005 vs 937/537** — remapped cousin / **different machine**:

- 1005 dominated by bulk `store_i64` lane pack
- 937/537 dominated by byte absorb + opaque i64 MBA over a cursor struct

Cursor fields (937/537, reconstructive names): `begin@0`, `end_or_mark@4`, `len_or_cap@8`, `limit@12`, `counter@16`, `secondary@20`.

Arm tables: `arm_clusters_937.json`, `arm_clusters_537.json`.
Stubs: `bulkPack1005Stub` / `bulkPack937Stub` / `bulkPack537Stub` — structural walks only.

### Unknown cipher (stop inventing)

Big i64 MBA samples (exported as named constants on the encrypt stubs; **unknown cipher — do not invent**):

| helper | sample constants (first few) |
|--------|------------------------------|
| **937** | `7751723099346266405`, `4034149112108046766`, `-5511460641829317313`, … |
| **537** | `3791927442663040578`, `-7715504215185997053`, `6807663086000598086`, … |
| **1005** | `8903399947347151673`, `1033939898872119952`, `6133261650685032694`, … (171 big i64s; lane/MBA opaque) |

Also unknown:

1. Whether absorb+rotl is a named hash compress (do not guess).
2. Meaning of 937 `wrap_i64+212` pointer bias / secondary@20.
3. 1005 lane layout ↔ request/response byte linkage.
4. Status bit → parent CFF state mapping beyond `store8×2` shape.

---

## File map

| artifact | path |
|----------|------|
| this note | `MBA_OPAQUE.md` |
| 84feb decrypt / 710 stub | `cff_live_decrypt.js` |
| 84feb encrypt / 1005 stub | `cff_live_encrypt.js` |
| 63d9 decrypt / 273 stub | `cff_63d9_decrypt.js` |
| 63d9 encrypt / 937 stub | `cff_63d9_encrypt.js` |
| e449 decrypt / 406 stub | `cff_e449_decrypt.js` |
| e449 encrypt / 537 stub | `cff_e449_encrypt.js` |
| structural roundtrip test | `mba_opaque_roundtrip.test.js` |
| body dumps | `out_84feb/helpers.txt` (710), `helpers_63d9.txt` (273), `helpers_e449.txt` (406) |
