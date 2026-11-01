# HSW Encrypt/Decrypt Core Analysis

Static reverse of captured `hsw.wasm` encrypt/decrypt paths. No live fetch, no
solver, no captured source pasted.

| Item | Value |
|---|---|
| Module | `hsw.wasm` 1,019,112 bytes |
| SHA-256 | `e0e67a53b85862a61d01245a22ed8c8d8730f26372e2836d0d19b0cad40ae70c` |
| Session | `15633105613961270227` (capture), `11517149565663187681` (live) |

## Public entry

| Call | Glue | Magic | Entry | CFF | Meaning |
|---|---|---|---|---|---|
| `hsw(0, x)` | `bau` | `-58720044` | func 424 | func 941 (9,440 B) | Decrypt response |
| `hsw(1, x)` | `kk` / `qX.z` | `1983284732` | func 592 | func 386 (10,480 B) | Encrypt request |

Both paths flow through export `Yc` (func 1169), which dispatches on the first
argument (magic selector).

## Encrypt path

### func 592 (encrypt entry)

- **Offset**: 401745, **Size**: 86 bytes
- **Params**: 2 (retptr, handle), **Locals**: 2
- **Ops**: 42, **call_indirect**: 0
- **Host imports**: none

Minimal trampoline: allocate 16-byte frame, call func 386, read ok/err from
scrambled slots, write result triple `{ok, err, flag}` to retptr.

```wasm
global.get 0            // stack ptr
i32.const 16
i32.sub                 // allocate 16 bytes
local.tee 2
global.set 0
local.get 2
i32.const 8
i32.add
local.get 1             // JS handle
call 386                // CFF core
local.get 2
i32.const 12
call 282                // scrambled load: error handle
local.set 1
local.get 0             // retptr
local.get 2
i32.const 8
call 282                // scrambled load: ok/err flag
i32.const 1
i32.and
local.tee 3
i32.const 8
call 305                // scrambled store: flag
local.get 0
local.get 1
i32.const 0
local.get 3
select
i32.const 4
call 305                // scrambled store: err
local.get 0
i32.const 0
local.get 1
local.get 3
select
i32.const 0
call 305                // scrambled store: ok
local.get 2
i32.const 16
i32.add
global.set 0            // restore stack
end
```

**Intern calls**: `386×1`, `282×2`, `305×3`

### func 386 (encrypt CFF)

- **Offset**: 218984, **Size**: 10,480 bytes
- **Params**: 2, **Locals**: 55
- **Ops**: 4,791
- **br_table arms**: 134 (135 unique destinations)
- **Loop depth**: 1
- **Host imports**: none (pure in-guest transform)

Control-flow-flattened cipher core. 134 states, selector is local (not memory
fetch). Uses scrambled memory for all data access:

| Intern | Count | Role |
|---|---|---|
| 282 | ~200+ | scrambled i32 load |
| 305 | ~150+ | scrambled i32 store |
| 420 | calls | cipher worker (267-arm CFF) |

No host imports means the cipher operates entirely on scrambled guest memory
without touching JS. The 55 locals form a flattened Rust stack frame.

## Decrypt path

### func 424 (decrypt entry)

- **Offset**: 268781, **Size**: 385 bytes
- **Params**: 2 (handle, retptr), **Locals**: 5
- **Ops**: 203, **call_indirect**: 0
- **Host imports**: none

4-arm CFF with MBA (Mixed Boolean Arithmetic) opaque predicates:

```wasm
// MBA constants for state obfuscation
i32.const -1599453365  // XOR mask
i32.const 1118283787   // multiplier
i32.const 868764472    // subtrahend
i32.const 350708125    // OR comparand
```

Flow: validates/transforms input via MBA predicate, allocates 16-byte frame,
calls func 941 twice (decrypt CFF), then writes result triple via scrambled
stores.

**Intern calls**: `941×2`, `282×4`, `305×6`

### func 941 (decrypt CFF)

- **Offset**: unknown (not in top br_table list)
- **Size**: 9,440 bytes
- **Params**: 2, **Locals**: 57
- **Ops**: 4,292
- **br_table**: Not in ≥8-arm list (smaller or different structure)
- **Host imports**: none (pure in-guest transform)

Decrypt core. Unlike func 386, this doesn't appear in the large br_table
inventory. May use nested blocks rather than a single flattened br_table, or
multiple smaller br_tables. The 57 locals exceed func 386's 55.

## Common cipher worker

### func 420 (in-guest cipher walk)

- **Offset**: 257282, **Size**: 11,032 bytes
- **Params**: 1 (context pointer), **Locals**: 28
- **Ops**: 4,723
- **br_table arms**: 267 (268 unique destinations)
- **Loop depth**: 1
- **Host imports**: NONE

Pure in-guest buffer transform. Called from encrypt/decrypt CFFs. Heavy
scrambled memory usage:

| Intern | Count | Role |
|---|---|---|
| 305 (store) | 562 | scrambled i32 store |
| 282 (load) | 395 | scrambled i32 load |
| 354 | several | helper function |

CFF arm families (from opcode-map-f420.json):

| Class | Arms | Example |
|---|---|---|
| `add+or` | ~10 | MBA predicate |
| `add/inc+sub+and` | ~15 | MBA with bounds |
| `call[282]+br` | ~30 | load then branch |
| `call[305,305]+br` | ~20 | store pair |
| `and+shift+call[282]` | ~10 | bitwise + load |

Entry state: 115 (from `i32.const 115; local.set 1; loop; br_table`).

## Scrambled memory layout

All encrypt/decrypt data flows through the 320-byte page codec:

| Function | Role |
|---|---|
| 282 | `load_i32(base, off)` - XOR with keystream |
| 305 | `store_i32(base, value, off)` - XOR with keystream |
| 286 / `Jc` | `store_i64` |
| 350 / `Pc` | `load_i64` |
| 874 | `addr → i64 keystream` |
| 1113 | `page_index → descriptor_pointer` |
| 526 | mark page dirty |

Page geometry:
```
page   = addr / 320
offset = addr % 320
key    = func_874(addr)              // i64
slot   = func_1113(page) + 8 + offset
value' = value XOR i32.wrap(key)
```

JS side mirror: `qX.H` uses `320 * trunc((byteLength - 1024) / 328)` — 1024-byte
prefix, then 328-byte records (8-byte header + 320-byte payload).

## Summary table

| Function | Body | Arms | Params | Locals | Ops | Host imports |
|---|---|---|---|---|---|---|
| 592 (encrypt entry) | 86 B | - | 2 | 2 | 42 | **none** |
| 386 (encrypt CFF) | 10,480 B | 134 | 2 | 55 | 4,791 | **none** |
| 424 (decrypt entry) | 385 B | 4 | 2 | 5 | 203 | **none** |
| 941 (decrypt CFF) | 9,440 B | ? | 2 | 57 | 4,292 | **none** |
| 420 (cipher worker) | 11,032 B | 267 | 1 | 28 | 4,723 | **none** |

**No host imports in the entire encrypt/decrypt path.** All crypto operates
purely on scrambled guest memory. The cipher worker (func 420) is called by both
paths.

## Remaining unknowns

1. **func 941 structure**: Not in large br_table list; may use nested blocks or
   multiple smaller tables. Body not fully disassembled.

2. **func 874 key schedule**: Address-to-keystream function; body not lifted.
   May use data segment 0 (1004 bytes at mem offset 20, entropy 7.79) as a table.

3. **Exact cipher algorithm**: MBA + XOR + scrambled memory = obfuscated
   symmetric cipher. Not attempting to recover algorithm (solver-adjacent).

4. **func 420 caller graph**: Called from 386/941 and also from funcs 225, 544,
   650, 1051. Full call graph not traced.

5. **Handle boxing**: Both entry points receive a JS handle; how the plaintext/
   ciphertext bytes are passed from JS to scrambled memory not fully traced.

## Method

1. Static disassembly via `wasmparser` (never instantiated).
2. br_table classification from `br_tables.txt`.
3. Function body analysis from `abi_callees.txt`, `largest_funcs.txt`.
4. Host import mapping from `host_call_sites.txt`.
5. Opcode maps from `opcode-map-f420.json`, `opcode-map-f218.json`.
