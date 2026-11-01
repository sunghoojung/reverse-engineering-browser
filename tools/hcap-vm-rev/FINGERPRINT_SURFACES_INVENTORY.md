# Fingerprint / host-import surfaces (HSW proof-adjacent)

Reconstructive inventory. **No** tokens, sitekeys, or proof bodies.

Primary cites: `HOST_TOOLBOX.md`, `HOST_GATES.md`, `guest_ops.js`, `POW_PATH.md`,
`REQUEST_FLOW.md`, `LIVE_E449_GLUE.md`, `MBA_OPAQUE.md`.

Dedicated **AudioContext / WebGL / fetch / XHR imports: 0** (`HOST_TOOLBOX.md` Counts).
WebGL may still be reached via generic `getContext` (`a.cc`) with a guest-supplied type string.

## `window.hsw` modes that feed encrypt / update / proof

| Mode | Role | LIVE_E449 glue | LIVE_63D9 glue | LIVE_84FEB glue | Wasm path (e449) | Cite |
|-----:|------|----------------|----------------|-----------------|------------------|------|
| 0 | decrypt_resp | `aHz` | `bbD` | `akZ` | Yc → trampoline → decrypt CFF | `guest_ops.js` LIVE_*; `LIVE_E449_GLUE.md` |
| 1 | encrypt_req | `aJp` | `aVj` | `aHO` | Yc → trampoline → encrypt CFF | same |
| 2 | update_token | `GC` | `aOF` | `aqa` | Yc → update CFF | same |
| jwt / extra | proof / Uc | (binder) | (binder) | (binder) | export `Uc` → PoW/fingerprint CFFs | `POW_PATH.md`; `guest_ops.js` jwt entries |

Encrypt/decrypt workers use scrambled memory codecs and nested bulk helpers; see
`MEMORY_CODEC.md`, `MBA_OPAQUE.md`, `LIVE_CFF_*.md`. Cipher MBA polys remain **unknown**.

## Surface table (capability → imports)

| Surface class | What a request-shaped client must match (conceptually) | Example imports (module `a`) | Status | Cite |
|---------------|--------------------------------------------------------|------------------------------|--------|------|
| Navigator UA / platform / language / plugins | Consistent UA, platform, languages, plugin list | `a` platform, `f` navigator, `sc` userAgent, `rb` language, `wb` plugins | **observed** (import→API map) | `HOST_TOOLBOX.md` Navigator/Chrome |
| Chrome / loadTimes | `window.chrome` shape | `Lb` chrome.loadTimes | **observed** | `HOST_TOOLBOX.md` |
| Screen | availWidth/Height, colorDepth, pixelDepth | `g`, `m`, `G`, `Ba`, `Xa` | **observed** | `HOST_TOOLBOX.md` Screen |
| DOM / document / location | documentElement, querySelector, createElement, origin/href/referrer | `j`, `db`, `xb`, `lc`, `sa`, … | **observed** | `HOST_TOOLBOX.md` DOM/location |
| Canvas 2D | toDataURL, fillText/strokeText, styles, getContext | `A`, `P`, `Db`, `ga`, `cc`, `Bc`, `$b`, … (24 listed) | **observed** | `HOST_TOOLBOX.md` Canvas 2D |
| WebGL | No dedicated import; possible via `getContext('webgl*')` | `cc` getContext only | **inferred** | `HOST_TOOLBOX.md` Canvas note; Counts “WebGL … 0” |
| Audio | No dedicated AudioContext import | — | **unknown** / absent as dedicated import | `HOST_TOOLBOX.md` Counts |
| Performance / timing | now, resource/navigation timing fields, getEntriesByType | `ta`/`nb` now, `B` responseStart, `va` PerformanceNavigationTiming, `Va` PRT (base catalog), `La` performance, … | **observed** | `HOST_TOOLBOX.md` Performance timeline; `HOST_GATES.md` live Va remap note |
| Crypto / random | getRandomValues / msCrypto / randomFillSync | `qc`, `bb`, `Ab`, `rc` | **observed** | `HOST_TOOLBOX.md` Crypto |
| PoW SHA-1 | Leading-zero SHA-1 over `prefix + ":" + nonceHex` | `Yb` | **observed** (algorithm + rotation) | `POW_PATH.md` |
| Storage | localStorage, sessionStorage, indexedDB presence | `qa`, `U`, `fc` | **observed** | `HOST_TOOLBOX.md` Storage |
| Async / Promise | Promise wiring for Uc / PoW | `Qa`, `r`, `zc` queueMicrotask, … | **observed** | `HOST_TOOLBOX.md` Async; `POW_PATH.md` |
| TypedArray / ABI glue | Handle table, memcpy-ish, length gates | `M`, `ra`/`Cc` length family, takeObject gates | **observed** | `HOST_TOOLBOX.md` Typed arrays; `HOST_GATES.md` |
| Worker encrypt/decrypt gates | Single host call per CFF worker (live: takeObject void-wrap) | LIVE_84FEB `a.Va`, LIVE_63D9 `a.Cc`, LIVE_E449 `a.t` | **observed** (call shape); semantic is handle drop on live builds | `HOST_GATES.md` |
| Opaque custom props | uj_data, vm_data, ardata, process, versions, … | `b`, `l`, `o`, `I`, `ec`, … | **observed** as probes; payload meaning **unknown** | `HOST_TOOLBOX.md` Custom/opaque |
| Reflection generics | Object/Reflect/Proxy — can reach APIs without dedicated imports | 45 reflection imports | **observed** (class); which APIs are hit at runtime **inferred** | `HOST_TOOLBOX.md` JS reflection |
| Fingerprint CFF cluster | Large CFFs on proof path assemble fingerprint blob | e.g. click-era 218/323; build-specific ids | **observed** (call graph); field layout **unknown** | `POW_PATH.md` Giants chain |
| HTTP headers / cookies | Cookie jar, Origin, Referer, Accept-Language vs UA | Not in wasm import table | **inferred** from normal browser traffic; not inventorying Set-Cookie values | `REQUEST_FLOW.md` retention limits |
| TLS / JA3 / JA4 | Client hello fingerprint | Not in reverse notes | **unknown** | plan Non-goals; absent from cited docs |

## Proof-adjacent data flow (structural)

```
hsw(jwt|modes)
  → instantiate / Yc dispatcher (encrypt|decrypt|update)
  → encrypt CFF packs request material (fingerprint + challenge state)
  → PoW path (Uc): fingerprint CFFs + a.Yb SHA-1
  → POST api.hcaptcha.com (octet-stream or JSON — MIME observed; body layout unknown)
```

See `ENCRYPT_DECRYPT.md`, `OCTET_STREAM.md`, `POW_PATH.md`, `guest_ops.js`.

## Build remapping warning

Minified import **names** move between binder builds. Base-catalog `qx` semantics
(`HOST_TOOLBOX.md` / `qx_decoded.js`) are not always the live meaning of the same
short name (`HOST_GATES.md`: live `Va`/`Cc`/`t` as worker gates are takeObject wraps).
Always pair **import index + live glue** when matching a capture.
