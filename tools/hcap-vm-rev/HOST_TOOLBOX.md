# hCaptcha HSW host toolbox (WASM module `a`)

Static reverse of captured `hsw.wasm` + `hsw.js` only. No live fetch, no solver, no captured source dumps.

## Counts

| Item | Value |
|---|---|
| WASM size | 1,019,112 bytes |
| JS loader size | 1,543,201 bytes |
| Import module | `a` only |
| Imported functions | **191** (names `a`…`z`, `A`…`Z`, `_`, `$`, `aa`…`zc`, `Ac`, `Bc`, `Cc`) |
| Imported memories / tables / globals | **0** (memory and table are defined inside the module and exported) |
| Type section | 64 function types |
| Defined functions | 979 (plus 191 imports = 1,170 total funcidx) |
| Exported functions | 21 + memory `Hc` |
| Memory | 1 page-min **18** (1,152 KiB), exported as `Hc` |
| Table | funcref min=max **171**, not imported |
| Mapped to a concrete API or capability class | **191 / 191** |
| Dedicated import, but opaque property name | **9** (see Unknowns) |
| AudioContext / WebGL / fetch / XHR dedicated imports | **0** |

Instantiate site: `WebAssembly.instantiate(aId, amv)` at **hsw.js:1415573**.
Import object: `var amv = { [aSL(126) /* "a" */]: qx }` at **hsw.js:1542542**.
`qx` itself starts at **hsw.js:1523990** (`[aSL(233)]:function` …).

The loader is wasm-bindgen-shaped: JS heap `NV` (1024+4 slots: `undefined, null, true, false`), `xX` = getObject, `aZl` = addHeapObject, `On` = takeObject, `aSJ` = getStringFromWasm (TextDecoder utf-8), `RL` = passStringToWasm (TextEncoder), `uo` = try/catch that stores the exception via export `Ec`. `__wbg_set_wasm` / `awu` installs the instance exports on `vu`.

### Syscall vs glue

| Role | Count | Meaning |
|---|---|---|
| syscall | 123 | Browser/host capability the guest is actually calling |
| glue | 63 | ABI: handles, closures, boxing, memory copies |
| hybrid | 5 | Generic getter that may serve several APIs |

There is **no imported malloc/memcpy/table.grow**. Allocator exports used by the JS glue are `Oc` (malloc) and `Tc` (realloc). Linear memory is guest-owned (`Hc`). Closures go through `a_K` + exports `Fc`/`Qc` and unref import `Na`.

## Capability groups

### Wasm-bindgen glue (13)

Handle table, closures, type boxing/unboxing, string/memory helpers. Not browser APIs; ABI.

`d`, `w`, `z`, `H`, `pa`, `ya`, `Na`, `Oa`, `Ta`, `ib`, `sb`, `zb`, `kc`

### Typed arrays / memory views (18)

Copy between guest linear memory and JS typed arrays/arrays.

`M`, `N`, `W`, `Y`, `_`, `aa`, `ba`, `ra`, `Ha`, `Ja`, `eb`, `hb`, `tb`, `Jb`, `Pb`, `Zb`, `nc`, `Cc`

### JS reflection (45)

Object/Reflect/Proxy/typeof/instanceof/property access. Can reach APIs that have no dedicated import.

`c`, `e`, `i`, `n`, `s`, `u`, `v`, `x`, `y`, `C`, `D`, `E`, `F`, `R`, `X`, `fa`, `la`, `ua`, `xa`, `Ca`, `Fa`, `Ia`, `Ma`, `Pa`, `Za`, `_a`, `ab`, `lb`, `mb`, `ob`, `vb`, `yb`, `Bb`, `Cb`, `Eb`, `Ib`, `Kb`, `Mb`, `Ob`, `Rb`, `Vb`, `Wb`, `Xb`, `jc`, `yc`

### Exceptions (3)

Error construction and throws; uo() stores caught exceptions via wasm export Ec.

`na`, `Ea`, `Ka`

### Strings / JSON / RegExp (8)

JSON.stringify, RegExp, wasm string codec (TextEncoder/TextDecoder sit in the JS glue, not as imports).

`h`, `Da`, `fb`, `pb`, `Hb`, `Tb`, `dc`, `ic`

### Math / BigInt (2)

BigInt.asUintN, Number.isSafeInteger.

`k`, `hc`

### Time (5)

Date.now, Date getters, performance.now.

`q`, `t`, `V`, `ta`, `nb`

### Crypto / random / PoW (5)

crypto.getRandomValues, msCrypto, Node randomFillSync, SHA-1 proof-of-work (Yb).

`bb`, `Ab`, `Yb`, `qc`, `rc`

### Navigator / Chrome (6)

userAgent, platform, language, plugins, chrome.loadTimes.

`a`, `f`, `rb`, `wb`, `Lb`, `sc`

### Screen (5)

availWidth/Height, colorDepth, pixelDepth, screen object.

`g`, `m`, `G`, `Ba`, `Xa`

### DOM / location (12)

document, querySelector, createElement, getElementById, location/referrer/origin/href, attributes.

`j`, `S`, `ia`, `sa`, `Aa`, `Ua`, `db`, `xb`, `Qb`, `ac`, `lc`, `mc`

### Canvas 2D (getContext is generic) (24)

Path/text/style/toDataURL. getContext(type) string is guest-supplied, so webgl is possible through cc.

`A`, `J`, `P`, `Q`, `$`, `ca`, `da`, `ga`, `ma`, `za`, `Ga`, `Wa`, `$a`, `gb`, `kb`, `Db`, `Gb`, `$b`, `bc`, `cc`, `gc`, `oc`, `Ac`, `Bc`

### Performance timeline (19)

Navigation/resource timing fields and getEntriesByType.

`B`, `K`, `Z`, `ea`, `ha`, `ja`, `ka`, `oa`, `va`, `wa`, `La`, `Sa`, `Va`, `Ya`, `cb`, `Nb`, `pc`, `uc`, `vc`

### Storage (3)

localStorage, sessionStorage, indexedDB.

`U`, `qa`, `fc`

### Async / event loop (8)

Promise, queueMicrotask, setTimeout.

`r`, `T`, `Qa`, `Fb`, `Sb`, `tc`, `wc`, `zc`

### Global object handles (4)

globalThis, window, self, Node global.

`L`, `O`, `jb`, `_b`

### Eval / module (2)

eval.toString() native check; Node module.require.

`Ra`, `xc`

### Custom / opaque properties (9)

uj_data, vm_data, ardata, process, versions, messages, errors, node, generic .data.

`b`, `l`, `o`, `p`, `I`, `qb`, `ub`, `Ub`, `ec`

## Signature table

Offsets are byte positions of the `[aSL(k)]:` key in captured `hsw.js`. Bodies are summarized; source is not reproduced.

| Import | Type | Signature | Group | Recovered API | Role | Offset |
|---|---|---|---|---|---|---|
| `a` | 1 | `(i32, i32) → (∅)` | navigator | navigator.platform | syscall | 1525201 |
| `b` | 2 | `(i32) → (i32)` | custom-probe | obj.uj_data | syscall | 1525216 |
| `c` | 4 | `(i32, i32, i32) → (i32)` | reflection | Object.defineProperty | syscall | 1526715 |
| `d` | 2 | `(i32) → (i32)` | glue | heap.clone | glue | 1538888 |
| `e` | 2 | `(i32) → (i32)` | reflection | typeof === "function" | glue | 1537995 |
| `f` | 2 | `(i32) → (i32)` | navigator | obj.navigator | syscall | 1540953 |
| `g` | 2 | `(i32) → (i32)` | screen | screen.availWidth | syscall | 1533341 |
| `h` | 2 | `(i32) → (i32)` | encoding | JSON.stringify | syscall | 1535166 |
| `i` | 2 | `(i32) → (i32)` | reflection | typeof object && !== null | glue | 1533631 |
| `j` | 4 | `(i32, i32, i32) → (i32)` | dom | Element.querySelector | syscall | 1525875 |
| `k` | 20 | `(i64) → (i32)` | math | BigInt.asUintN(64, x) | glue | 1526546 |
| `l` | 2 | `(i32) → (i32)` | custom-probe | obj.process | syscall | 1524216 |
| `m` | 2 | `(i32) → (i32)` | screen | obj.screen | syscall | 1539556 |
| `n` | 2 | `(i32) → (i32)` | reflection | Reflect.ownKeys | syscall | 1540855 |
| `o` | 1 | `(i32, i32) → (∅)` | custom-probe | obj.errors | syscall | 1535472 |
| `p` | 2 | `(i32) → (i32)` | custom-probe | obj.data | hybrid | 1524161 |
| `q` | 2 | `(i32) → (i32)` | time | Date.prototype.getHours | syscall | 1526060 |
| `r` | 4 | `(i32, i32, i32) → (i32)` | async | Promise.then(onFulfilled, onRejected) | glue | 1524926 |
| `s` | 1 | `(i32, i32) → (∅)` | reflection | obj.name (string) | hybrid | 1536184 |
| `t` | 2 | `(i32) → (i32)` | time | new Date(value) | syscall | 1537740 |
| `u` | 2 | `(i32) → (i32)` | reflection | instanceof Promise | glue | 1542054 |
| `v` | 2 | `(i32) → (i32)` | reflection | instanceof Window | syscall | 1541009 |
| `w` | 0 | `(i32, i32) → (i32)` | glue | wasm-bindgen closure adapter | glue | 1540617 |
| `x` | 0 | `(i32, i32) → (i32)` | reflection | Reflect.has | syscall | 1539971 |
| `y` | 2 | `(i32) → (i32)` | reflection | === undefined | glue | 1524111 |
| `z` | 0 | `(i32, i32) → (i32)` | glue | wasm-bindgen closure adapter | glue | 1537924 |
| `A` | 1 | `(i32, i32) → (∅)` | canvas | HTMLCanvasElement.toDataURL | syscall | 1532618 |
| `B` | 7 | `(i32) → (f64)` | performance | PerformanceResourceTiming.responseStart | syscall | 1524611 |
| `C` | 0 | `(i32, i32) → (i32)` | reflection | === (strict equality) | glue | 1539645 |
| `D` | 8 | `(∅) → (i32)` | reflection | Symbol.iterator | glue | 1538052 |
| `E` | 0 | `(i32, i32) → (i32)` | reflection | key in obj | syscall | 1534535 |
| `F` | 8 | `(∅) → (i32)` | reflection | new Object | glue | 1535426 |
| `G` | 2 | `(i32) → (i32)` | screen | screen.pixelDepth | syscall | 1538384 |
| `H` | 0 | `(i32, i32) → (i32)` | glue | wasm-bindgen closure adapter | glue | 1539778 |
| `I` | 2 | `(i32) → (i32)` | custom-probe | obj.versions | syscall | 1527142 |
| `J` | 14 | `(i32, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.moveTo | syscall | 1535107 |
| `K` | 7 | `(i32) → (f64)` | performance | PerformanceTiming.redirectEnd | syscall | 1531877 |
| `L` | 8 | `(∅) → (i32)` | globals | self | syscall | 1531329 |
| `M` | 5 | `(i32, i32, i32) → (∅)` | typedarray | TypedArray.set | glue | 1523998 |
| `N` | 17 | `(i32, i32) → (f64)` | typedarray | obj[index] as number | hybrid | 1540512 |
| `O` | 8 | `(∅) → (i32)` | globals | globalThis | syscall | 1535796 |
| `P` | 21 | `(i32, i32, i32, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.strokeText | syscall | 1530472 |
| `Q` | 1 | `(i32, i32) → (∅)` | canvas | HTMLCanvasElement.width = n | syscall | 1525570 |
| `R` | 2 | `(i32) → (i32)` | reflection | instanceof ArrayBuffer | glue | 1537429 |
| `S` | 2 | `(i32) → (i32)` | dom | window.location / obj.location | syscall | 1532801 |
| `T` | 0 | `(i32, i32) → (i32)` | async | Promise.then(onFulfilled) | glue | 1533272 |
| `U` | 2 | `(i32) → (i32)` | storage | window.sessionStorage | syscall | 1534885 |
| `V` | 2 | `(i32) → (i32)` | time | Date.prototype.getDate | syscall | 1532201 |
| `W` | 2 | `(i32) → (i32)` | typedarray | obj.length | glue | 1534590 |
| `X` | 10 | `(i32, i32, i32, i32) → (i32)` | reflection | Function.prototype.call (2 args) | syscall | 1537161 |
| `Y` | 0 | `(i32, i32) → (i32)` | typedarray | Array.push | glue | 1537535 |
| `Z` | 7 | `(i32) → (f64)` | performance | secureConnectionStart | syscall | 1527253 |
| `_` | 0 | `(i32, i32) → (i32)` | typedarray | view of wasm memory | glue | 1530894 |
| `$` | 3 | `(i32) → (∅)` | canvas | CanvasRenderingContext2D.fill | syscall | 1530949 |
| `aa` | 0 | `(i32, i32) → (i32)` | typedarray | obj[index] boxed | glue | 1533572 |
| `ba` | 0 | `(i32, i32) → (i32)` | typedarray | obj[index] boxed | glue | 1535261 |
| `ca` | 14 | `(i32, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.lineTo | syscall | 1542478 |
| `da` | 3 | `(i32) → (∅)` | canvas | CanvasRenderingContext2D.beginPath | syscall | 1536374 |
| `ea` | 7 | `(i32) → (f64)` | performance | domainLookupEnd | syscall | 1526855 |
| `fa` | 4 | `(i32, i32, i32) → (i32)` | reflection | Reflect.set | syscall | 1538635 |
| `ga` | 5 | `(i32, i32, i32) → (∅)` | canvas | ctx.fillStyle = string | syscall | 1524662 |
| `ha` | 7 | `(i32) → (f64)` | performance | requestStart | syscall | 1532371 |
| `ia` | 5 | `(i32, i32, i32) → (∅)` | dom | Element.removeAttribute | syscall | 1541660 |
| `ja` | 7 | `(i32) → (f64)` | performance | redirectStart | syscall | 1539113 |
| `ka` | 7 | `(i32) → (f64)` | performance | transferSize | syscall | 1533962 |
| `la` | 0 | `(i32, i32) → (i32)` | reflection | new Proxy(target, handler) | syscall | 1538282 |
| `ma` | 3 | `(i32) → (∅)` | canvas | CanvasRenderingContext2D.closePath | syscall | 1540467 |
| `na` | 0 | `(i32, i32) → (i32)` | exceptions | Error(message) | glue | 1532253 |
| `oa` | 7 | `(i32) → (f64)` | performance | responseEnd | syscall | 1540566 |
| `pa` | 0 | `(i32, i32) → (i32)` | glue | wasm-bindgen closure adapter | glue | 1526112 |
| `qa` | 2 | `(i32) → (i32)` | storage | window.localStorage | syscall | 1534996 |
| `ra` | 2 | `(i32) → (i32)` | typedarray | obj.length | glue | 1524061 |
| `sa` | 1 | `(i32, i32) → (∅)` | dom | location.origin / obj.origin | syscall | 1542330 |
| `ta` | 7 | `(i32) → (f64)` | time | performance.now | syscall | 1534434 |
| `ua` | 0 | `(i32, i32) → (i32)` | reflection | Reflect.getOwnPropertyDescriptor | syscall | 1540688 |
| `va` | 2 | `(i32) → (i32)` | performance | instanceof PerformanceNavigationTiming | syscall | 1533713 |
| `wa` | 7 | `(i32) → (f64)` | performance | decodedBodySize | syscall | 1535981 |
| `xa` | 5 | `(i32, i32, i32) → (∅)` | reflection | obj[key] = value (move) | glue | 1526003 |
| `ya` | 0 | `(i32, i32) → (i32)` | glue | wasm-bindgen closure adapter | glue | 1534177 |
| `za` | 1 | `(i32, i32) → (∅)` | canvas | HTMLCanvasElement.height = n | syscall | 1536885 |
| `Aa` | 2 | `(i32) → (i32)` | dom | document.body | syscall | 1536695 |
| `Ba` | 2 | `(i32) → (i32)` | screen | screen.colorDepth | syscall | 1537841 |
| `Ca` | 2 | `(i32) → (i32)` | reflection | Object.keys | syscall | 1531635 |
| `Da` | 1 | `(i32, i32) → (∅)` | encoding | debug/inspect stringify (arR) | glue | 1533819 |
| `Ea` | 1 | `(i32, i32) → (∅)` | exceptions | throw new Error(string) | glue | 1530581 |
| `Fa` | 2 | `(i32) → (i32)` | reflection | iterator.done | glue | 1539850 |
| `Ga` | 5 | `(i32, i32, i32) → (∅)` | canvas | ctx.font = string | syscall | 1537599 |
| `Ha` | 2 | `(i32) → (i32)` | typedarray | obj.length | glue | 1531983 |
| `Ia` | 2 | `(i32) → (i32)` | reflection | typeof === "string" | glue | 1539040 |
| `Ja` | 2 | `(i32) → (i32)` | typedarray | new Uint8Array(buffer) | glue | 1524864 |
| `Ka` | 2 | `(i32) → (i32)` | exceptions | instanceof Error | glue | 1530994 |
| `La` | 2 | `(i32) → (i32)` | performance | window.performance | syscall | 1537662 |
| `Ma` | 0 | `(i32, i32) → (i32)` | reflection | Reflect.get | syscall | 1526380 |
| `Na` | 3 | `(i32) → (∅)` | glue | _wbg_cb_unref | glue | 1534840 |
| `Oa` | 1 | `(i32, i32) → (∅)` | glue | try unwrap JS number as f64 | glue | 1541511 |
| `Pa` | 2 | `(i32) → (i32)` | reflection | iterator.value | glue | 1537282 |
| `Qa` | 0 | `(i32, i32) → (i32)` | async | new Promise(wasm executor) | glue | 1525160 |
| `Ra` | 3 | `(i32) → (∅)` | eval | eval.toString() | syscall | 1541757 |
| `Sa` | 7 | `(i32) → (f64)` | performance | domainLookupStart | syscall | 1532947 |
| `Ta` | 34 | `(f64) → (i32)` | glue | box f64 as JsValue | glue | 1536031 |
| `Ua` | 4 | `(i32, i32, i32) → (i32)` | dom | Element.hasAttribute | syscall | 1531471 |
| `Va` | 2 | `(i32) → (i32)` | performance | instanceof PerformanceResourceTiming | syscall | 1524758 |
| `Wa` | 22 | `(i32, f64, f64, f64, f64, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.bezierCurveTo | syscall | 1532033 |
| `Xa` | 2 | `(i32) → (i32)` | screen | screen.availHeight | syscall | 1538749 |
| `Ya` | 7 | `(i32) → (f64)` | performance | connectStart | syscall | 1536835 |
| `Za` | 4 | `(i32, i32, i32) → (i32)` | reflection | Reflect.defineProperty | syscall | 1530034 |
| `_a` | 0 | `(i32, i32) → (i32)` | reflection | Function.prototype.call (0 args) | syscall | 1531100 |
| `$a` | 23 | `(i32, f64, f64, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.fillRect | syscall | 1540164 |
| `ab` | 2 | `(i32) → (i32)` | reflection | Object.entries | syscall | 1539700 |
| `bb` | 2 | `(i32) → (i32)` | crypto | window.msCrypto | syscall | 1534013 |
| `cb` | 7 | `(i32) → (f64)` | performance | startTime | syscall | 1534789 |
| `db` | 4 | `(i32, i32, i32) → (i32)` | dom | document.createElement | syscall | 1530786 |
| `eb` | 8 | `(∅) → (i32)` | typedarray | new Array | glue | 1537796 |
| `fb` | 4 | `(i32, i32, i32) → (i32)` | encoding | RegExp.prototype.test | syscall | 1539900 |
| `gb` | 2 | `(i32) → (i32)` | canvas | canvas/ctx.height getter | syscall | 1535898 |
| `hb` | 4 | `(i32, i32, i32) → (i32)` | typedarray | TypedArray.subarray | glue | 1531201 |
| `ib` | 20 | `(i64) → (i32)` | glue | box i64 as JsValue | glue | 1536332 |
| `jb` | 8 | `(∅) → (i32)` | globals | window | syscall | 1525626 |
| `kb` | 35 | `(i32, f64, f64, f64, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.arc | syscall | 1542160 |
| `lb` | 2 | `(i32) → (i32)` | reflection | Array.isArray | glue | 1526488 |
| `mb` | 11 | `(i32, i32, i32, i32, i32) → (i32)` | reflection | Function.prototype.call (3 args) | syscall | 1531746 |
| `nb` | 24 | `(∅) → (f64)` | time | Date.now | syscall | 1531699 |
| `ob` | 2 | `(i32) → (i32)` | reflection | === null | glue | 1534487 |
| `pb` | 5 | `(i32, i32, i32) → (∅)` | encoding | obj[i] as string into memory | glue | 1535626 |
| `qb` | 1 | `(i32, i32) → (∅)` | custom-probe | obj.messages | syscall | 1525720 |
| `rb` | 1 | `(i32, i32) → (∅)` | navigator | navigator.language | syscall | 1538468 |
| `sb` | 2 | `(i32) → (i32)` | glue | unwrap boolean | glue | 1541115 |
| `tb` | 8 | `(∅) → (i32)` | typedarray | new Array | glue | 1538104 |
| `ub` | 2 | `(i32) → (i32)` | custom-probe | obj.vm_data | syscall | 1537025 |
| `vb` | 0 | `(i32, i32) → (i32)` | reflection | == (loose equality) | glue | 1539248 |
| `wb` | 2 | `(i32) → (i32)` | navigator | navigator.plugins | syscall | 1540075 |
| `xb` | 2 | `(i32) → (i32)` | dom | window.document | syscall | 1530395 |
| `yb` | 2 | `(i32) → (i32)` | reflection | iterator.next (property) | glue | 1526905 |
| `zb` | 3 | `(i32) → (∅)` | glue | heap.drop / takeObject | glue | 1524724 |
| `Ab` | 2 | `(i32) → (i32)` | crypto | obj.crypto (window.crypto) | syscall | 1527198 |
| `Bb` | 2 | `(i32) → (i32)` | reflection | typeof === "bigint" | glue | 1540797 |
| `Cb` | 2 | `(i32) → (i32)` | reflection | Object.getOwnPropertyNames | syscall | 1541448 |
| `Db` | 21 | `(i32, i32, i32, f64, f64) → (∅)` | canvas | CanvasRenderingContext2D.fillText | syscall | 1534326 |
| `Eb` | 0 | `(i32, i32) → (i32)` | reflection | Reflect.get | syscall | 1536419 |
| `Fb` | 2 | `(i32) → (i32)` | async | queueMicrotask (property) | syscall | 1538832 |
| `Gb` | 18 | `(i32, f64) → (∅)` | canvas | ctx.lineWidth = n | syscall | 1531419 |
| `Hb` | 0 | `(i32, i32) → (i32)` | encoding | getStringFromWasm (box) | glue | 1531928 |
| `Ib` | 4 | `(i32, i32, i32) → (i32)` | reflection | obj[stringKey] | syscall | 1534704 |
| `Jb` | 5 | `(i32, i32, i32) → (∅)` | typedarray | TypedArray.set from wasm bytes | glue | 1541332 |
| `Kb` | 4 | `(i32, i32, i32) → (i32)` | reflection | Function.prototype.call (1 arg) | syscall | 1536073 |
| `Lb` | 9 | `(∅) → (∅)` | navigator | window.chrome.loadTimes() | syscall | 1536940 |
| `Mb` | 0 | `(i32, i32) → (i32)` | reflection | Reflect.construct | syscall | 1525005 |
| `Nb` | 1 | `(i32, i32) → (∅)` | performance | initiatorType string | syscall | 1532997 |
| `Ob` | 2 | `(i32) → (i32)` | reflection | instanceof DOMStringList | syscall | 1541226 |
| `Pb` | 4 | `(i32, i32, i32) → (i32)` | typedarray | TypedArray.slice / Array.slice | glue | 1525492 |
| `Qb` | 2 | `(i32) → (i32)` | dom | location.href | syscall | 1534249 |
| `Rb` | 0 | `(i32, i32) → (i32)` | reflection | obj[key] boxed | syscall | 1542271 |
| `Sb` | 2 | `(i32) → (i32)` | async | Promise.resolve | glue | 1540296 |
| `Tb` | 1 | `(i32, i32) → (∅)` | encoding | optional string into wasm memory | glue | 1532422 |
| `Ub` | 2 | `(i32) → (i32)` | custom-probe | obj.node | syscall | 1538149 |
| `Vb` | 2 | `(i32) → (i32)` | reflection | obj.name boxed | hybrid | 1532315 |
| `Wb` | 2 | `(i32) → (i32)` | reflection | obj.constructor | syscall | 1530731 |
| `Xb` | 2 | `(i32) → (i32)` | reflection | iterator.next() | glue | 1537338 |
| `Yb` | 4 | `(i32, i32, i32) → (i32)` | crypto | SHA-1 proof-of-work | syscall | 1527318 |
| `Zb` | 2 | `(i32) → (i32)` | typedarray | new Uint8Array(length) | glue | 1540234 |
| `_b` | 8 | `(∅) → (i32)` | globals | global (Node) | syscall | 1526183 |
| `$b` | 2 | `(i32) → (i32)` | canvas | instanceof HTMLCanvasElement | syscall | 1540361 |
| `ac` | 1 | `(i32, i32) → (∅)` | dom | document.referrer | syscall | 1533424 |
| `bc` | 3 | `(i32) → (∅)` | canvas | CanvasRenderingContext2D.stroke | syscall | 1525114 |
| `cc` | 4 | `(i32, i32, i32) → (i32)` | canvas | HTMLCanvasElement.getContext | syscall | 1533145 |
| `dc` | 2 | `(i32) → (i32)` | encoding | Object.prototype.toString / toString | hybrid | 1534069 |
| `ec` | 2 | `(i32) → (i32)` | custom-probe | obj.ardata | syscall | 1536527 |
| `fc` | 2 | `(i32) → (i32)` | storage | window.indexedDB | syscall | 1524453 |
| `gc` | 2 | `(i32) → (i32)` | canvas | ctx.fillStyle getter | syscall | 1526800 |
| `hc` | 2 | `(i32) → (i32)` | math | Number.isSafeInteger | glue | 1537103 |
| `ic` | 10 | `(i32, i32, i32, i32) → (i32)` | encoding | new RegExp(pattern, flags) | syscall | 1539164 |
| `jc` | 2 | `(i32) → (i32)` | reflection | instanceof Object | glue | 1526609 |
| `kc` | 1 | `(i32, i32) → (∅)` | glue | try unwrap bigint as i64 | glue | 1530148 |
| `lc` | 2 | `(i32) → (i32)` | dom | document.documentElement | syscall | 1538205 |
| `mc` | 4 | `(i32, i32, i32) → (i32)` | dom | document.getElementById | syscall | 1531541 |
| `nc` | 2 | `(i32) → (i32)` | typedarray | instanceof Uint8Array | glue | 1535320 |
| `oc` | 2 | `(i32) → (i32)` | canvas | canvas/ctx.width getter | syscall | 1532117 |
| `pc` | 7 | `(i32) → (f64)` | performance | connectEnd | syscall | 1534127 |
| `qc` | 1 | `(i32, i32) → (∅)` | crypto | crypto.getRandomValues | syscall | 1530306 |
| `rc` | 1 | `(i32, i32) → (∅)` | crypto | crypto.randomFillSync (Node) | syscall | 1530641 |
| `sc` | 1 | `(i32, i32) → (∅)` | navigator | navigator.userAgent | syscall | 1524272 |
| `tc` | 4 | `(i32, i32, i32) → (i32)` | async | window.setTimeout | syscall | 1526277 |
| `uc` | 7 | `(i32) → (f64)` | performance | encodedBodySize | syscall | 1534640 |
| `vc` | 4 | `(i32, i32, i32) → (i32)` | performance | performance.getEntriesByType | syscall | 1532872 |
| `wc` | 0 | `(i32, i32) → (i32)` | async | new Promise(wasm executor) | glue | 1539302 |
| `xc` | 8 | `(∅) → (i32)` | eval | module.require (Node) | syscall | 1536604 |
| `yc` | 4 | `(i32, i32, i32) → (i32)` | reflection | Reflect.apply | syscall | 1541935 |
| `zc` | 3 | `(i32) → (∅)` | async | queueMicrotask(fn) | syscall | 1524563 |
| `Ac` | 5 | `(i32, i32, i32) → (∅)` | canvas | ctx.strokeStyle = string | syscall | 1536772 |
| `Bc` | 2 | `(i32) → (i32)` | canvas | instanceof CanvasRenderingContext2D | syscall | 1538934 |
| `Cc` | 2 | `(i32) → (i32)` | typedarray | obj.length | glue | 1531279 |

### Notes on selected imports

- `a`: Writes UTF-8 platform string into wasm memory (ptr+len).
- `b`: Custom property; likely injected-script / user-JS probe. Null -> 0.
- `c`: Returns the object after defineProperty.
- `d`: addHeapObject(getObject(idx)); duplicates a JS handle.
- `e`: Type predicate.
- `f`: Typically window.navigator.
- `g`: Wrapped in try/catch (uo).
- `h`: Stringifies a heap object; result boxed.
- `i`: Type predicate.
- `j`: Selector string from wasm memory.
- `k`: Boxes a 64-bit unsigned BigInt.
- `l`: Node-like process object, or a planted field.
- `o`: Passes JS array of handles into wasm (Au).
- `p`: Generic .data getter (ImageData, events, process, etc.).
- `r`: Boxes the follow-on promise.
- `s`: Writes name string into wasm memory.
- `t`: Boxes a Date from a heap value.
- `w`: a_K(..., wasm.Fc, BB); host closure calling guest.
- `z`: a_K(..., wasm.Fc, Ve).
- `A`: Writes data-URL string into wasm memory.
- `B`: f64 timing.
- `D`: Boxes the well-known symbol.
- `H`: a_K(..., wasm.Fc, bci).
- `I`: Typically process.versions (Node/Electron).
- `J`: (ctx, x:f64, y:f64).
- `K`: f64.
- `L`: Worker/window self; 0 if undefined.
- `M`: Copies a heap object into a wasm-backed view (aAf).
- `N`: Unsigned index; result f64 (JS number).
- `P`: (ctx, ptr, len, x, y).
- `W`: Generic length as i32 handle/value (returns JS number boxed? actually returns length directly as i32).
- `X`: fn.call(thisArg, arg1, arg2).
- `Y`: push heap object; returns length.
- `Z`: f64.
- `_`: aAf(ptr,len): Uint8Array subarray of guest memory, boxed.
- `aa`: Unsigned index; result heap handle.
- `ba`: Same shape as aa.
- `ca`: (ctx, x, y).
- `ea`: f64.
- `ga`: String from wasm memory.
- `ha`: f64.
- `ja`: f64.
- `ka`: f64.
- `na`: Boxes a new Error; message from wasm string.
- `oa`: f64.
- `pa`: a_K(..., wasm.Qc, bk).
- `sa`: Writes string into wasm memory.
- `ta`: obj.now() as f64; used on Performance.
- `wa`: f64.
- `xa`: Takes key and value off the heap (On).
- `ya`: a_K(..., wasm.Fc, ais).
- `Da`: wasm-bindgen js_sys::JsValue debug format into memory.
- `Ea`: Host exception from guest string (also used by uo -> wasm.Ec).
- `Na`: Drop wasm-bindgen closure refcount.
- `Oa`: Writes (ok:i32, val:f64) into wasm memory.
- `Qa`: Executor is guest function a_P / wasm.Dc.
- `Ra`: Native-code check (native vs JS eval). Writes source string.
- `Sa`: f64.
- `Ta`: addHeapObject(number).
- `Ua`: Returns boolean as i32.
- `Wa`: 6 f64 args.
- `Ya`: f64.
- `Za`: Boolean result.
- `_a`: fn.call(thisArg).
- `$a`: 4 f64 args.
- `bb`: Legacy IE crypto object.
- `cb`: f64.
- `db`: Tag name from wasm string.
- `fb`: Pattern already a heap RegExp; subject from wasm string.
- `ib`: addHeapObject(bigint/i64).
- `jb`: 0 if typeof window === "undefined".
- `kb`: 5 f64 args.
- `nb`: () -> f64.
- `pb`: Index a string list (e.g. DOMStringList).
- `qb`: Array of handles passed into wasm.
- `rb`: Optional string into memory.
- `sb`: true->1, false->0, else 16777215 sentinel.
- `tb`: Duplicate of eb.
- `ub`: Custom VM/automation probe field.
- `yb`: Boxes the next function/value.
- `zb`: On(idx): drop JS handle.
- `Db`: (ctx, ptr, len, x, y).
- `Eb`: Same family as Ma.
- `Fb`: Boxes the function.
- `Gb`: f64.
- `Hb`: aSJ(ptr,len) then addHeapObject.
- `Ib`: Key from wasm string; optional boxed.
- `Jb`: Copies guest memory slice into a JS typed array (byte-order aware via qd).
- `Lb`: Deprecated Chrome internals; try/catch.
- `Nb`: Writes into wasm memory.
- `Qb`: Optional boxed string handle.
- `Rb`: Key is a heap object (symbol/string).
- `Tb`: If heap value is string, passStringToWasm.
- `Ub`: Could be DOM node or Node.js `process.versions.node` container.
- `Yb`: Host SHA-1 (crypto.subtle.digest + JS fallback). Finds nonce so digest has N leading zero bits. String+difficulty from wasm.
- `_b`: 0 if undefined.
- `ac`: Writes string into wasm memory.
- `cc`: Context type string from wasm (2d/webgl/webgl2 possible).
- `dc`: Boxes toString() result.
- `ec`: Custom probe field.
- `gc`: Boxes current fillStyle.
- `ic`: Both strings from wasm memory.
- `kc`: Writes (ok:i32, val:i64) into wasm memory.
- `pc`: f64.
- `rc`: Takes the typed array off the heap.
- `sc`: Writes string into wasm memory.
- `tc`: (fn, delay).
- `uc`: f64.
- `vc`: Type string from wasm.
- `wc`: Duplicate of Qa.
- `xc`: Boxes require if present.

## Glue helpers (not imports, but required to read `qx`)

| Helper | Offset | Role |
|---|---|---|
| `function jA()` | 16620 | Cached view of wasm memory (`vu.Hc.buffer`) with get/set Int/Float; used to write ptr+len out-params |
| `Nr` | 40902 | `null == x` |
| `uo` | 40937 | `try { fn.apply(this, args) } catch (e) { vu.Ec(addHeapObject(e)) }` |
| `aSJ` | 39792 | `TextDecoder.decode(HEAPU8.subarray(ptr, ptr+len))` |
| `function xX(idx)` | 52280 | `NV[idx]` getObject |
| `RL` | 54019 | passStringToWasm via `Oc`/`Tc` |
| `a_K` | 1420635 | Closure trampoline + FinalizationRegistry; calls guest export |
| addHeapObject (`aTT[4]` / `aZl`) | 1425549 | Standard wasm-bindgen free-list heap |
| `awu` / `__wbg_set_wasm` | 1425656 | `vu = exports` |
| `aDa` | 1433144 | Cached `Uint8Array` over `vu.Hc.buffer` |
| `On` (`qX.F`) | 1433338 | takeObject / drop handle (indices < 1028 reserved) |
| `a_P` | 1434430 | `vu.Dc(a, b, addHeapObject(resolve), addHeapObject(reject))` Promise executor |
| `aAf` | 1437984 | Typed-array view of guest memory |
| `Au` | 1438045 | passArrayToWasm of heap handles |
| `NV` heap init | 1523619 | `new Array(1024).fill(undefined); push(undefined,null,true,false)` |
| `WebAssembly.instantiate` | 1415573 | `instantiate(bytes, amv).then(aZc)` |
| `var qx={` | 1523990 | Module `a` import object |
| `var amv={` | 1542542 | `{ a: qx }` |
| `window.hsw` | 1542570 | Public entry: token parse (`JSON.parse`/`atob`/`Date.now`) then wasm `aeB`/`bau`/`kk`/`Bd` |

`qx` also carries **non-import** JS bindings used after instantiate: `onInit` (`aZc`), `update_token` (`Bd`), `decrypt_resp_data` (`bau`), `encrypt_req_data` (`kk`), `Uc` (`aeB`), `init_opfs_session` (calls export `Xc` with magic `-1090220354`), `__wbg_set_wasm`. Those are exports/wrappers, not the 191 imports.

## Live builds — encrypt/decrypt host gates

Base-catalog names in this file (`Va` = PerformanceResourceTiming, `Cc`/`W`/`ra`/`Ha` = `.length`, `hc` = `isSafeInteger`) are for captured `hsw.js` / `hsw.wasm` only. **Live builds remap import names.**

Across LIVE_84FEB / LIVE_63D9 / LIVE_E449, each encrypt/decrypt CFF worker calls one host import once. Proven semantic: **wasm-bindgen `takeObject` / drop heap handle** (wasm type `(i32)→()`, return unused). Not TypedArray.length / ArrayBuffer.byteLength.

See **[HOST_GATES.md](./HOST_GATES.md)** for the cross-build table, call-shape proof, glue citations, and the corrected `218` / `Uint8Array(size)` thunk story.

## Unknowns / gaps

1. **Opaque property names (9):** `b` (`uj_data`), `ub` (`vm_data`), `ec` (`ardata`), `l` (`process`), `I` (`versions`), `qb` (`messages`), `o` (`errors`), `Ub` (`node`), `p` (`data`). These are real getters, but the object they are applied to is chosen by the guest. Treat as environment/automation probes, not unidentified glue.
2. **No dedicated AudioContext / OfflineAudioContext / WebGL / fetch / XMLHttpRequest / cookie / Intl imports.** Session-level Origin Trace anti-bot hits (canvas/webgl, navigator, web-audio) are **not** proven to come from these 191 imports. WebGL can still be reached because `cc` is `getContext(guestString)`. Arbitrary APIs can be reached via `Ma`/`Eb`/`Ib`/`Rb`/`yc`/`Mb`/`_a`/`X`/`Kb`/`mb`.
3. **Closure adapters `w`,`z`,`H`,`pa`,`ya`:** mapped as wasm-bindgen glue; the *guest* function they trampoline into is an export (`Fc`/`Qc`), not recovered here.
4. **`Yb` PoW:** host SHA-1 with `crypto.subtle.digest("SHA-1")` and a pure-JS SHA-1 fallback, plus a leading-zero-bit check. Difficulty and prefix come from wasm strings. This is a host helper, not a hash oracle for challenge images.
5. **`init_opfs_session`** is on `qx` but **not** a WASM import. Name is leftover/export-side; body is `On(vu.Xc(-1090220354,0,0))`.
6. **Host-link file** (`vm-host-links-v1.json` artifacts 71–73) does not identify individual imports: reasons are `dispatch-samples-unavailable` / `guest-position-unproven`. This catalog is static only.
7. **String tables** `aSL`/`Bq`/`Gl` are encrypted (atob + xorshift). Only `aSL` was fully decoded for this map. Remaining `Bq(...)` identifiers in non-import glue were not needed once `qx` used `aSL`.

## Method

1. Parsed WASM section 1 (types) and section 2 (imports): 191 `kind=func` from module `a`.
2. Located `WebAssembly.instantiate(aId, amv)` and `amv = { a: qx }`.
3. Decoded `aSL` (table `vI()`, seed `4098133109`, add `1831565813`) so `qx` keys and property names became plaintext.
4. Matched each `qx[name]` body to a capability; classified syscall vs glue using wasm-bindgen patterns and signatures.

