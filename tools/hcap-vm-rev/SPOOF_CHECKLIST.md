# Spoof checklist → recovered surfaces

Maps what a **request-shaped** client would need to match on the public-demo path.
**Does not** implement a client, obtain pass tokens, or POST forged checkcaptcha/proof bodies.

Status tags: `observed` | `inferred` | `unknown`.

| # | Checklist item | Surface / stage | Status | Notes | Cite |
|--:|----------------|-----------------|--------|-------|------|
| 1 | Load `api.js` from `js.hcaptcha.com` with expected query keys | Request stage 2 | **observed** | Artifact retained | `REQUEST_STAGES_INVENTORY.md`, `REQUEST_FLOW.md` |
| 2 | Issue `checksiteconfig` with query keys `v,host,sitekey,sc,swa,spst` | Request stage 3 | **observed** (keys via Performance); body **inferred** empty | Values redacted | `BODY_SHAPES_INVENTORY.md`, live Performance |
| 3 | Present checkbox + challenge iframe documents from `newassets` | Request stage 4 | **observed** | HTML body not retained | `REQUEST_FLOW.md` |
| 4 | Fetch matching `hsw.js` content-hash binder | Request stage 6 | **observed** | Binder defines glue→Yc magics | `LIVE_E449_GLUE.md`, `guest_ops.js` |
| 5 | Instantiate matching wasm build (sha must match binder) | Request stage 7 | **observed** | LIVE_E449 / 63D9 / 84FEB profiles | `STATUS.json`, `guest_ops.js` |
| 6 | `getcaptcha` POST to `/getcaptcha/<sitekey>` returning ~816–822 B JSON | Request stage 8 | **observed** (path+response); request body layout **unknown** | Manifest/motiondata/vmdata shapes recovered in `api.js` | `BODY_SHAPES_INVENTORY.md`, `OCTET_STREAM.md` |
| 7 | Fetch challenge-type script + media (`imgs3` / challenge.js) | Stages 9–10 | **observed** | Needed for interactive challenges; request-only path still unclear without bodies | `REQUEST_STAGES_INVENTORY.md` |
| 8 | Match `Navigator` UA / platform / language / plugins | Navigator surfaces | **observed** | Import map known; exact value sets per session **unknown** | `FINGERPRINT_SURFACES_INVENTORY.md`, `HOST_TOOLBOX.md` |
| 9 | Match `window.chrome` / loadTimes shape | Chrome surface | **observed** | | `HOST_TOOLBOX.md` |
| 10 | Match screen metrics (avail*, depths) | Screen surfaces | **observed** | | `HOST_TOOLBOX.md` |
| 11 | Match DOM/document/location basics | DOM surfaces | **observed** | | `HOST_TOOLBOX.md` |
| 12 | Produce canvas 2D entropy (toDataURL / text / styles) | Canvas surfaces | **observed** | Pixel/hash outputs not recovered | `HOST_TOOLBOX.md` |
| 13 | WebGL vendor/renderer | WebGL via getContext | **inferred** | No dedicated WebGL import | `HOST_TOOLBOX.md` |
| 14 | Audio fingerprint | AudioContext | **unknown** | No dedicated import listed | `HOST_TOOLBOX.md` Counts |
| 15 | Performance.now + resource/navigation timing coherence | Timing surfaces | **observed** | | `HOST_TOOLBOX.md` |
| 16 | `crypto.getRandomValues` (or fallback) available | Crypto surfaces | **observed** | | `HOST_TOOLBOX.md` |
| 17 | Solve / supply SHA-1 leading-zero PoW (`a.Yb`) | PoW surface | **observed** (algorithm) | Prefix assembly **partially unknown** | `POW_PATH.md` |
| 18 | Storage probes (local/session/indexedDB) don’t throw oddly | Storage surfaces | **observed** | | `HOST_TOOLBOX.md` |
| 19 | Encrypt request blob via `hsw(1)` / Yc encrypt worker | Encrypt mode | **observed** (bind path); ciphertext math **unknown** | MBA bulk helpers not fully lifted | `guest_ops.js`, `MBA_OPAQUE.md`, `LIVE_CFF_*.md` |
| 20 | Decrypt responses via `hsw(0)` when server returns opaque payload | Decrypt mode | **observed** (bind path); cipher **unknown** | | same |
| 21 | `update_token` / `hsw(2)` when binder requires | Update mode | **observed** (bind path) | | `LIVE_E449_GLUE.md` |
| 22 | JWT/proof path `hsw(jwt,…)` → `Uc` fingerprint+PoW pack | Proof mode | **observed** (graph); field layout **unknown** | | `POW_PATH.md` |
| 23 | POST encrypt/proof-class to `api.hcaptcha.com` (octet-stream response ~2.3–2.6 KiB) | Request stage 11 | **observed** (response MIME/len); request CT/body **unknown** | `hsw(1)`/`hsw(0)` structural binds | `BODY_SHAPES_INVENTORY.md`, `OCTET_STREAM.md` |
| 24 | Align `Origin` / `Referer` / `Accept-Language` with UA | Headers | **inferred** | Not captured as wasm imports | `REQUEST_FLOW.md` limits |
| 25 | Carry site cookies / session identifiers | Cookies | **inferred** | Values not inventoried (would be secrets) | — |
| 26 | TLS client fingerprint (JA3/JA4) match | TLS | **unknown** | Out of cited notes | plan Non-goals |
| 27 | checkcaptcha pass submit | Request stage 12 | **unknown** in cited captures | No successful pass body retained; **out of scope to forge** | `REQUEST_FLOW.md`; plan Non-goals |
| 28 | Opaque custom props (`uj_data`, `vm_data`, …) | Custom probes | **observed** as imports; meaning **unknown** | | `HOST_TOOLBOX.md` |
| 29 | Live worker host-gate (takeObject once per encrypt/decrypt CFF) | Host gates | **observed** | Name remapped per build | `HOST_GATES.md` |
| 30 | Scrambled memory codec (320-page XOR) consistency | Memory codec | **observed** (structure) | | `MEMORY_CODEC.md`, `guest_ops.js` |

| 31 | Supply motion/timing buffer coherent with `On.getData` (md/mu/mm, pm, kd/ku, dm) | Motion surfaces | **observed** (collector + event codes); wire packing **unknown** | Feeds `topLevel` / `motiondata` | `BODY_SHAPES_INVENTORY.md`, `api.js` |
| 32 | Include getcaptcha manifest keys (`v,session,widgetId,widgetList,href,prev,imd,topLevel`) | getcaptcha pre-body | **observed** in JS; presence on HTTP wire **inferred** | From `getGetCaptchaManifest` | `BODY_SHAPES_INVENTORY.md` |
| 33 | Attach `vmdata` from HSW submitvm path when binder requires | getcaptcha / check-api | **observed** (async fill in `api.js`); bytes **unknown** | — | `BODY_SHAPES_INVENTORY.md` |
| 34 | Use credentialed XHR/fetch (`withCredentials` / `credentials:include`) to `api.hcaptcha.com` | Transport | **observed** (helper defaults) | — | `api.js` HTTP helper |
| 35 | Accept `arraybuffer` (octet-stream) as well as JSON on api responses | Transport | **observed** (helper) | Matches encrypt-class responses | `api.js`, `OCTET_STREAM.md` |

## Reading guide

- **`observed`**: recovered from wasm/JS map, network stage table, or live Performance/DOM observe.
- **`inferred`**: expected for a browser-shaped client but not proven in cited artifacts.
- **`unknown`**: not recovered; inventing values or cipher would exceed reconstructive scope.

## Explicit non-goals (this checklist)

- Runnable HTTP client that spoofs until submit succeeds.
- Obtaining or submitting pass tokens / forged `checkcaptcha` bodies.
- Solving visual challenges.

See plan Non-goals and `README.md` under `/tmp/hcap-vm-rev/`.
