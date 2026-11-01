# HSW VM Memory Codec Analysis

## Live build `84febfac` (session 5369273503095065946)

Primary reference for reconstructive work. Module: `hsw-live-84febfac.wasm` (1,052,328 B).

### Summary

320-byte page XOR codec with 8-byte chunk descriptors. **Every load ends with `value XOR wrap32(keystream(addr))`.** Stores XOR then write. `markDirty` materializes a keystream-filled cached page so cold zeros stay coherent (`ks XOR ks = 0`).

| Constant | Value |
|----------|------:|
| page | 320 |
| descriptor hdr | 8 |
| chunk | 328 |
| page_table_base | 1024 |
| perm_addr | 4 |
| keystream_addr | **433** |
| keystream_period | 96 |

### Core functions (live indexes)

| Role | Func | Signature (approx) |
|------|-----:|--------------------|
| chunkDescriptor / page_table | **1157** | `(chunkIndex) -> ptr` |
| addrKeystream | **695** | `(addr) -> i64` |
| markDirty / ensureCached | **250** | `(chunkIndex) -> ()` |
| load_i32 | **438** | `(base, off) -> i32` |
| store_i32 | **582** | `(base, value, off) -> ()` |

Click-era indexes **282 / 305 / 874 / 526 / 1113 / 329 / 1129 / 1014 / 248 / 928** do **not** apply to this sha.

### func 1157 — page table

```
perm_nibble = i32.load8_u(4 + (chunkIndex & 15))
mixed = perm_nibble | (chunkIndex & ~15)
return mixed * 328 + 1024
```

Live perm bytes at mem 4 (`data[1]`, also `perm_table_84feb.bin`):

```
4, 0, 12, 15, 14, 1, 9, 11, 13, 2, 8, 5, 7, 3, 10, 6
```

(Click perm table differed: `9,11,5,2,4,1,3,7,10,14,6,12,0,8,13,15`.)

### func 695 — keystream

```
return i64.load(433 + (addr % 96))
```

Table lives in `data[0]` (vm offset 20 covers 433). Extracted 96 bytes: `keystream_table_84feb.bin`. **Not** equal to click `KEYSTREAM_TABLE` in `guest_ops.js`.

### func 250 — markDirty

1. `desc = 1157(chunkIndex)`
2. If `desc[0] == 0`:
   - `desc[0] = 1`
   - For each byte `p` in `desc+8 .. desc+8+320`:
     - `virt = (p - desc - 8) + chunkIndex*320`
     - `i64.store8(p, keystream(virt))`  // low byte of table word

Fills cache with keystream pad (plaintext-zero encoding).

### func 438 — load_i32

1. `addr = base + off`; `chunk = addr/320`; `rem = addr%320`
2. `payload = 1157(chunk) + 8 + rem`
3. If `desc[0] != 0`: `v = i32.load(payload)` else `v = wrap32(keystream(addr))`
4. If `rem > 316`: rebuild `v` byte-wise across chunk boundary (warm load8 vs cold keystream shifts)
5. **Always** `return v XOR wrap32(keystream(addr))`

### func 582 — store_i32

1. `addr = base + off`; `chunk = addr/320`; `rem = addr%320`
2. `250(chunk)`; `250(chunk+1)`
3. `value ^= wrap32(keystream(addr))`
4. If `rem > 316`: byte-wise `store8` across boundary; else `i32.store(payload, value)`

### Page layout

```
┌─────────────────────────────────────┐
│ Chunk Descriptor (8 bytes)          │
│  [0]: cache_flag (0=cold, 1=warm)   │
│  [1-7]: unused / zero in data segs  │
├─────────────────────────────────────┤
│ Page Payload (320 bytes)            │
│  warm: plaintext XOR keystream      │
└─────────────────────────────────────┘
```

Heap pages begin near vm **1,072,600+** (`data[2…]`); many segments start with `flag=1` already.

### Related helpers on live Pc path

| Func | Role |
|-----:|------|
| 212 | power-of-two / bounds predicate |
| 838 | empty noop |
| 381 | `call 565` |
| 537 | export Pc → CFF into 381/565 |
| 565 | trampoline / magic `2037874024` → 1087 or 458 |
| 1087 | **linear_heap_init_worker** (246-arm; callers 565/458/490/368); not enc/dec |

### File references (live)

- `hsw-live-84febfac.wasm` / `.bin`
- `keystream_table_84feb.bin`, `perm_table_84feb.bin`
- `helpers.txt` (funcs 250,438,582,695,1157,…)
- `guest_ops.js` → `LIVE_84FEB.codec`
- `LIVE_OBSERVE_5369.md`

### Live unknowns

1. Who writes / rotates the 96-byte table at 433 after init (fixed in data0 today).
2. Descriptor bytes `[1-7]` purpose.
3. Full typed load/store family (i64/f32/…) indexes on this build beyond 438/582 (Yc arms → 914/322/957/866 partially mapped).
4. ~~Absolute hsw(0/1)↔592/243~~ **Resolved:** glue binds 298/796 via Yc; 592/243 are unbound siblings.

---

## Older builds (historical)

The section below documents earlier modules (`e0e67a53…` / click `49086a4a…`) where codec funcs were **282 / 305 / 874 / 526 / 1113** or click **329 / 1129 / 1014 / 248 / 928**. Keep for diffing only.

### Historical summary

- Inner bytecode blob ~59 KB at ~1,076,864 with high entropy
- Keystream described as multiplicative hash in some notes; **live 84febfac uses a plain 96-byte table load instead**
- Page size 320 / descriptor 8 / chunk 328 — stable across builds

### Historical function names

| Old index | Role |
|----------:|------|
| 1113 / 928 | chunkDescriptor |
| 874 / 1014 | addrKeystream |
| 526 / 248 | markDirty |
| 282 / 329 | load_i32 |
| 305 / 1129 | store_i32 |

See `LIVE_OBSERVE_5369.md` and `guest_ops.js` `CLICK_WASM` for click-era tables.

## Binding + fixture update (2026-11-01)

### Yc is mode+codec dispatch on 84febfac

Export **Yc=1166** dispatches 8 magics (see `LIVE_84FEB.yc_dispatch`): three `window.hsw` modes (→777/1103/606) plus typed codec accessors (914/582/322/957/866). Historical click magics (`1983284732`, `-58720044`) are absent as `i32.const` here.

### hsw(0/1/2) ↔ CFF (glue-proven via art4)

Live glue: artifact **4** `glue/art4.bin` (1,593,148 B, sha `8b1349a9…`) — **not** art12 (`e25e8466…`, pairs with art13).

`window.hsw` → `akZ` / `aHO` / `aqa` / JWT`tr` → `aaj[at$(8)]` = export **Yc=1166** (JWT uses `aaj[at$(47)]` = **Uc=738**).

| Binding | Magic | Trampoline | Worker | Confidence |
|---------|------:|-----------:|-------:|------------|
| hsw(0) decrypt | **-1874150846** | **777** (86 B) | **298** (115 arms) | **high** |
| hsw(1) encrypt | **1262290883** | **1103** (86 B) | **796** (142 arms) | **high** |
| hsw(2) update_token | **366490014** | — | **606** (243 arms) | **high** |
| JWT proof | — | — | **Uc=738** | **high** |

Sibling shape-only analogues **592 / 243 / 757** (hub 824 path) are **not** on the Yc mode path — demoted to `sibling_analogues_unbound`. Frozen in `LIVE_84FEB.cff_hypothesis` + `LIVE_HSW_MODE`.

### Func 1087

Named **`linear_heap_init_worker`**. Callers 565/458/490/368 only; heap const band; on live Pc path; not enc/dec.

### Related helpers (extended)

| Func | Role |
|-----:|------|
| 777 | decrypt_trampoline → 298 |
| 1103 | encrypt_trampoline → 796 |
| 298 | decrypt CFF worker (hsw 0) |
| 796 | encrypt CFF worker (hsw 1) |
| 606 | update_token CFF (hsw 2) |
| 443 | sibling path → 592 (unbound) |
| 824 | elem78 hub (unbound siblings) |
| 1087 | linear_heap_init_worker |

### Fixture

`guest_ops_live_fixture.js` — roundtrip cold/warm/split-page against extracted bins; asserts codec indexes + cff_hypothesis + helpers[1087].

```
node --check /tmp/hcap-vm-rev/guest_ops_live_fixture.js && node /tmp/hcap-vm-rev/guest_ops_live_fixture.js
```

### Artifact 13 (`63d9f8a3`) — remapped as `LIVE_63D9`

Paired glue: artifact **12** `glue/art12.bin` (sha `e25e8466…`). Module 1,057,758 B; 191 imports / 980 defined.

| Role | Func | Notes |
|------|-----:|-------|
| page_table | **518** | same formula; perm still `@4` |
| keystream | **217** | `i64.load(469 + addr%96)` — addr moved **433→469** |
| mark_dirty | **1134** | |
| load_i32 | **859** | dominant intern |
| store_i32 | **366** | |
| load_u8 | **863** | proven (+66); 84feb 859 analogue |
| store_u8 | **1026** | proven (+47); 84feb 957 analogue |
| store_i64 | **637** | proven (+300, rem>312); 84feb 858 / Dc |
| store_i16 | **1154** | proven (+139, rem>318); **not** init_opfs |
| Yc / Uc / Pc | **1170 / 690 / 250** | memory export **Nc** |
| hsw(0/1/2) | **349 / 667 / 724** | via Yc magics `-174010464` / `-1483911731` / `672652481` |

Tables: `keystream_table_63d9.bin`, `perm_table_63d9.bin`. Fixture: `guest_ops_art13_fixture.js`.
CFF stubs: `cff_63d9_encrypt.js` / `cff_63d9_decrypt.js` (`ScrambledMemory63d9` mirrors these).

### Nested bulk helper 937 (art13)

Role **`cursor_absorb_mba`** (17-arm CFF, entry 4). Parent bulk arms call `937(statusSlot, cursorSlot)` — not an i64 lane packer. **Not isomorphic** to 84feb **1005** (1005 dominated by `store_i64 858×147`; 937 has **zero** store_i64 and instead absorbs bytes + opaque i64 MBA). See `LIVE_CFF_349_667.md`, `arm_clusters_937.json`, `cff_63d9_encrypt.js` (`bulkPack937Stub` / `ARM_CLUSTERS_937`). `LIVE_63D9.cff.nested[937]`.

Cipher blockers: i64 MBA constants; absorb+rotl identity; `+212` ptr bias.

### Nested bulk helper 537 (e449) + MBA 406

Role **`cursor_absorb_mba`** (11-arm CFF, entry 0). Parents 874/880 call `537(statusSlot, cursorSlot)` (slots 1100/1096). **Remapped cousin / smaller machine** vs 63d9 **937** (folds absorb+i64 MBA into arm 9; no separate mba_i32_pred). **Not isomorphic** to 84feb **1005**. See `LIVE_CFF_874_880.md`, `arm_clusters_537.json`, `cff_e449_encrypt.js` (`bulkPack537Stub` / `ARM_CLUSTERS_537`). `LIVE_E449.cff.nested[537]`.

MBA **406** (decrypt-only, 880 arm 50): body proven `@166577+25` — `opaque_u8_roundtrip_sp15` via store_u8 364 / load_u8 219 at SP+15. Isomorphic to 63d9 **273**; analogue of 84feb **710**. `LIVE_E449.cff.nested[406]`.

### Still open for codec family

Full typed load/store family beyond i32/u8/i16/i64 on each build (f32/f64 indexes on 63d9). Keystream rotator after init unknown. **937** / **537** MBA math (arms lifted). Art13 / e449 have 0 live native observations.
