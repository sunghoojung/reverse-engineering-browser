# Request-stage inventory (public-demo path)

Reconstructive inventory only. **No** live tokens, sitekeys, or raw proof/checkcaptcha bodies.

Sources: `REQUEST_FLOW.md`, `OCTET_STREAM.md`, `ENCRYPT_DECRYPT.md`, `LIVE_SESSION_NEW.md`,
live Performance entries observe (`/tmp/hcap-live-observe2/e449_scripts.json`), session manifests.

Native Origin Trace rows often retain **METHOD + host only**; paths below are from artifact URLs
or Performance resource names when recorded. Bodies are almost never retained.

## Stage table

| # | Stage | Method class | Host (class) | Path / shape | Body retained? | Path retained? | Status | Cite |
|--:|-------|--------------|--------------|--------------|----------------|----------------|--------|------|
| 1 | Demo document | GET | `accounts.hcaptcha.com` | `/demo` (main_frame) | No (HTML outside JS/wasm retain) | Partial (host in native; path from navigation) | **observed** | `REQUEST_FLOW.md` §demo; `OCTET_STREAM.md` stage table |
| 2 | Widget loader | GET | `js.hcaptcha.com` | `/1/api.js` (+ query: `reportapi`, `custom`, `pstissuer`) | Artifact yes (JS) | Yes (artifact URL) | **observed** | `REQUEST_FLOW.md` req 166 / art 69; session 115219 art 2 |
| 3 | Siteconfig probe | GET/XHR | `api.hcaptcha.com` | `/checksiteconfig` (+ `v`, `host`, `sitekey` query — **values redacted**) | No in native | Yes in Performance name (live observe) | **observed** (path via Performance; absent in older native-only session 6576) | `e449_scripts.json`; contrast `REQUEST_FLOW.md` “checksiteconfig Not recorded” |
| 4 | Checkbox / challenge iframes | GET | `newassets.hcaptcha.com` | `/captcha/v1/<build>/static/hcaptcha.html#frame=checkbox\|challenge&…` | HTML not retained | Path from wasm/iframe URL | **observed** | `REQUEST_FLOW.md` reqs 168/169; `LIVE_SESSION_NEW.md` |
| 5 | Telemetry / logo | GET/fetch | `*.w.hcaptcha.com` | `/logo.png` (when Performance names it) | No | Sometimes (Performance) | **observed** | `REQUEST_FLOW.md` reqs 167/171; `e449_scripts.json` |
| 6 | HSW binder | GET | `newassets.hcaptcha.com` | `/c/<content-hash>/hsw.js` | Artifact yes | Yes | **observed** | `REQUEST_FLOW.md` art 71; session 115219 art 4 (`hsw-live-e449-glue.js`) |
| 7 | Wasm module | instantiate (not always a network GET) | `newassets.hcaptcha.com` | Same build tree as iframe / binder | Artifact yes (wasm bytes) | Label/URL on artifact | **observed** | `REQUEST_FLOW.md` arts 70/72/73; `STATUS.json` LIVE_E449 sha |
| 8 | getcaptcha-class POST | POST/XHR | `api.hcaptcha.com` | `/getcaptcha/<sitekey>` when Performance names it; else host-only | **No** (native METHOD+host) | Performance yes / native often no | **observed** (host+MIME); path **observed** live Performance, **unknown** in native-only rows | `REQUEST_FLOW.md` req 172; `e449_scripts.json`; `OCTET_STREAM.md` |
| 9 | Challenge asset script | GET | `newassets.hcaptcha.com` | `/captcha/v1/<build>/challenge/<type>/…` | Sometimes (challenge.js artifact) | Yes when artifact/Performance | **observed** | `OCTET_STREAM.md` challenge.js; `e449_scripts.json` `image_label_area_select` |
| 10 | Challenge media | GET | `imgs3.hcaptcha.com` | `/tip/<…>/…` (image/video) | No in these notes | Performance names only | **observed** (fetch class) | `e449_scripts.json`; `LIVE_SESSION_NEW.md` canvas challenges |
| 11 | Encrypt / proof-class POST | POST/XHR | `api.hcaptcha.com` | Path often **unknown** in native; response sometimes `application/octet-stream` | Request body **unknown**; response length sometimes known | Often unknown | **observed** (METHOD+host+response MIME/len in session 962); path **unknown** | `OCTET_STREAM.md` req 13 (2613 B octet-stream response); `ENCRYPT_DECRYPT.md` |
| 12 | checkcaptcha / pass submit | POST | `api.hcaptcha.com` | checkcaptcha-class | Not retained in cited captures | Not retained | **unknown** in cited sessions (no later hCaptcha POST after getcaptcha in `REQUEST_FLOW.md`) | `REQUEST_FLOW.md` “checkcaptcha Not recorded” |
| 13 | pst-issuer | — | `pst-issuer.hcaptcha.com` | Appears as `pstissuer` query on `api.js` | N/A | Query key only | **inferred** (no dedicated request row in `REQUEST_FLOW.md`) | `REQUEST_FLOW.md` pst-issuer note |

## Ordering (typical public demo)

```
demo → api.js → checksiteconfig → hcaptcha.html iframes → logo/telemetry
    → hsw.js → wasm instantiate → getcaptcha → challenge assets
    → (user/challenge interaction) → encrypt/proof-class POST(s)
    → checkcaptcha (not seen in cited passive/partial sessions)
```

`window.hsw` modes that feed those POSTs (no bodies): decrypt `hsw(0)`, encrypt `hsw(1)`,
update_token `hsw(2)`, JWT/proof `hsw(jwt,…)` → export `Uc` — see `guest_ops.js` / `POW_PATH.md`.

## Retention limits (important for spoof readers)

| Channel | What you get |
|---------|----------------|
| Native Origin Trace network | METHOD + host; MIME/protocol on response; decoded lengths; rarely paths |
| Artifact store | JS/wasm bytes when admitted; not HTML challenge DOM; not POST bodies |
| Performance resource names (live evaluate) | Full URL strings including query — **redact sitekeys/tokens before filing** |

## Body-shape recovery (2026-11-01 deepen)

See `BODY_SHAPES_INVENTORY.md` for the full table. Headline updates:

| Stage | New / tightened finding | Status |
|-------|-------------------------|--------|
| 3 checksiteconfig | Performance name proves path + query keys `v,host,sitekey,sc,swa,spst`; body empty/absent | **observed** (keys); body **inferred** empty |
| 8 getcaptcha | Performance proves path `/getcaptcha/<sitekey>`; response JSON **816–822** B decoded; request body still **unknown**; `api.js` exposes **manifest / motiondata / vmdata** object shapes that feed the challenge chat | path+response **observed**; request layout **unknown**; manifest keys **observed** in JS |
| 11 encrypt/proof | Response octet-stream **2613** or **2376** B; request CT/len/layout **unknown**; `hsw(1)`/`hsw(0)` are structural encrypt/decrypt binds | response envelope **observed**; request **unknown** |

Live Performance XHR `transferSize`/`encodedBodySize` for `api.hcaptcha.com` are **0** (Timing-Allow-Origin), so sizes come from native `decoded_body_length` on **responses** only.

## Sessions referenced

| Session / observe | Role |
|-------------------|------|
| `6576076265513586860` | `REQUEST_FLOW.md` chronological native table |
| `9623810216396876129` | `OCTET_STREAM.md` octet-stream proof-class POST |
| `11521922066149179537` | Live e449 capture; Performance observe `e449_scripts.json` |
| `5369273503095065946` / LIVE_84FEB notes | `LIVE_OBSERVE_5369.md` wasm/mode bind |
