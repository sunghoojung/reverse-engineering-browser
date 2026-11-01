# Host gates across LIVE builds (reconstructive)

Proven from live wasm import types + art4/art12 glue bodies. **Not a solver.**
Base-catalog names in `HOST_TOOLBOX.md` / `toolbox_props.json` (`Va`=PRT,
`Cc`=`.length`, `hc`=`isSafeInteger`, `t`=`new Date`) are for the captured
`hsw.js` only. **Live builds remap minified import names.**

## Worker single-gate pattern

Each encrypt/decrypt CFF worker calls **one** host import once:

```
local.get 1          ;; worker handle arg
call GATE            ;; type (i32) -> ()
i32.const NEXT_STATE
local.set STATE
```

No `drop` needed: the import type is unit. Return value is unused by construction.

| build | worker arms | import | idx | wasm type | glue body | next state |
|-------|-------------|--------|----:|-----------|-----------|------------|
| **84feb** | decrypt 298 / encrypt 796 | **a.Va** | 101 | `(i32)->()` | `function(h){arK(h)}` | 2 / 116 |
| **63d9** | decrypt 349@92 / encrypt 667@32 | **a.Cc** | 190 | `(i32)->()` | `function(h){azp(h)}` | 57 / 7 |
| **e449** | decrypt 880@90 / encrypt 874@41 | **a.t** | 19 | `(i32)->()` | *(glue not captured; isomorphic)* | 29 / 106 |

### Glue proof — takeObject / drop handle

**84feb `arK`** (art4.bin):

```js
function arK(aSA) {
  var aXr;
  var Fr = aVQ(aSA);                 // getObject
  return (aXr = aSA) < 1028 || (aGV[aXr] = aFb, aFb = aXr), Fr;  // free if ≥1028
}
```

`a.Va` wraps it as `function(aSA){arK(aSA)}` — discards the JS return so the
wasm import type is `(i32)->()`.

**63d9 `azp`** (art12.bin):

```js
function azp(Yx) {
  var NW;
  var QN = anB(Yx);                  // getObject (cW heap)
  return (NW = Yx) < 1028 || (cW[NW] = zA, zA = NW), QN;
}
```

`a.Cc` wraps it as `function(Yx){azp(Yx)}` — same void takeObject.

**e449 `a.t`**: same wasm type `(i32)->()` and identical 5-op call shape in
arms 41/90. Glue binder not in the capture set; treated as isomorphic
takeObject drop (see `LIVE_E449.host_gates.glue`).

### What the gate is **not**

| candidate | where it actually lives (live builds) |
|-----------|----------------------------------------|
| TypedArray / Array `.length` | 84feb: `w`/`I`/`T`/`P`; 63d9: `wb`/`Ya`/`mb`/`wa` |
| `ArrayBuffer.byteLength` | not the worker ×1 gate |
| `PerformanceResourceTiming` instanceof | **base** catalog `Va` only; live 84feb `Va` is takeObject |
| `Number.isSafeInteger` | separate imports (below); not the worker gate |
| `new Date(x)` box | **base** catalog `t` only; live e449 `t` is the void gate |

## isSafeInteger / Uint8Array analogues

| build | role | import | idx | wasm type | glue | worker thunk |
|-------|------|--------|----:|-----------|------|--------------|
| 84feb | `isSafeInteger` | **a.aa** | 54 | `(i32)->(i32)` | `Number.isSafeInteger(get(h))` | *(no small thunk in helpers)* |
| 84feb | `new Uint8Array(size)` | **a.oa** | 68 | `(i32)->(i32)` | `box(new Uint8Array(size>>>0))` | **1141** → oa |
| 63d9 | `isSafeInteger` | **a.y** | 24 | `(i32)->(i32)` | `Number.isSafeInteger(get(h))` | *(no small thunk)* |
| 63d9 | `new Uint8Array(size)` | **a.hc** | 169 | `(i32)->(i32)` | `box(new Uint8Array(size>>>0))` | **218** → hc @arms 54/55 |
| e449 | *(analogues)* | — | — | — | glue not captured | not bound this pass |

**Correction:** earlier notes that labeled `218→a.hc` as `isSafeInteger` were
wrong. Live 63d9 `a.hc` is `new Uint8Array`; live `isSafeInteger` is `a.y`.
Live 84feb `isSafeInteger` is `a.aa`; `a.oa` is the Uint8Array ctor.

Thunk 218 / 1141 **keep** their i32 return (tee + store). Worker gates do not.

## Profiles / stubs

| artifact | pointer |
|----------|---------|
| `guest_ops.js` | `LIVE_84FEB.host_gates` / `LIVE_63D9.host_gates` / `LIVE_E449.host_gates` |
| stubs | `cff_live_{en,de}crypt.js` (`hostVaStub`); `cff_63d9_*.js` (`hostCcStub`, `hostNewUint8ArrayStub`); `cff_e449_*.js` (`hostAtStub`) |

## Artifacts

- Glue: `/tmp/hcap-vm-rev/glue/art4.bin` (84feb), `glue/art12.bin` (63d9)
- Layouts: `out_84feb/module-layout.txt`, `out_63d9/…`, `out_e449/…` (type 2 = `(i32)->()`)
- Decoders: `_decode_gates3.js`, `_decode_84feb.js`
- Arm sites: `LIVE_CFF_*.md`, `arm_clusters_*.json`
