# Request body shapes (getcaptcha / encrypt-class)

Reconstructive inventory only. **No** live tokens, sitekeys, raw proof bytes, or forged POSTs.

Sources: live Performance (`perf-live-shapes.json`), `api.js` artifact 2 (sha `96c4dbc6…`),
`OCTET_STREAM.md`, `CLICK_FLOW_962.md`, `LIVE_OBSERVE_5472.md`, `ENCRYPT_DECRYPT.md`,
`guest_ops.js` / `REQUEST_STAGES_INVENTORY.md`.

Native Origin Trace retains **METHOD+host** and **response** MIME/decoded length.
Request bodies are **not** retained (`payload_truncated=false`). Performance Resource
Timing on cross-origin XHR often reports `transferSize=0` (no Timing-Allow-Origin).

## A. checksiteconfig (pre-getcaptcha)

| Field | Value | Status | Cite |
|-------|-------|--------|------|
| Method / initiator | XHR (`xmlhttprequest`) | **observed** | live Performance |
| Path | `/checksiteconfig` | **observed** | live Performance name |
| Query keys | `v` (build), `host`, `sitekey` (redacted), `sc`, `swa`, `spst` | **observed** (keys only) | live Performance |
| Body | empty / none (GET-shaped XHR; size 0) | **inferred** | size 0 + query-only URL |

## B. getcaptcha-class POST

### Network envelope

| Field | Value | Status | Cite |
|-------|-------|--------|------|
| Method | POST XHR | **observed** | `REQUEST_FLOW.md` / `OCTET_STREAM.md` / Performance |
| Host | `api.hcaptcha.com` | **observed** | native + Performance |
| Path | `/getcaptcha/<sitekey>` | **observed** (Performance); **unknown** in native host-only rows | live Performance; `e449_scripts.json` |
| Response MIME | `application/json` | **observed** | `OCTET_STREAM.md` req 11; `REQUEST_FLOW.md` req 172 |
| Response decoded length | **816–822** B (session-dependent) | **observed** | 822 (962), 816 (6576), 822 (`CLICK_FLOW` correction) |
| Response encoded length | ~878 B (one row) | **observed** | `REQUEST_FLOW.md` |
| Request Content-Type | — | **unknown** (not in native; not literal in `api.js` near path) | — |
| Request body length | — | **unknown** | Performance sizes 0 |
| Request field layout on the wire | — | **unknown** | no body capture |

### Manifest / chat-side shapes recovered from `api.js` (not the wire body)

These objects are built in the parent widget and passed into the challenge iframe chat.
They are the strongest recovered **pre-POST** structure; whether every key is copied
verbatim into the HTTP body is **inferred / unknown**.

**`getGetCaptchaManifest()`** returns:

```
{
  v: 1,
  st?: Date.now(),          // when creating a fresh object
  session: <session id>,
  widgetList: <captcha id list>,
  widgetId: <this.id>,
  imd?: <init metadata>,
  topLevel: On.getData(),   // motion / timing buffers
  href: window.location.href,
  prev: <deep copy of widget _state>
}
```

Status: **observed** (function body in `api.js` artifact 2).

**Challenge setup object `R`** (before `challenge.setup`):

```
{
  a11yChallenge, manifest, width, height, charity, link, action, rqdata,
  mfa_phone, mfa_phoneprefix, mfa_email, wdata, errors, imd,
  actionStart, initChallengeStart,
  vmdata?   // filled asynchronously via submitvm / _n(…sitekey…)
}
```

Status: **observed** (object literal in `api.js`).

**`check-api` chat answer**:

```
{ motiondata: On.getData(), imd, vmdata? }
```

Status: **observed**.

### Motion / fingerprint buffer (`On.getData`)

| Item | Detail | Status |
|------|--------|--------|
| Collector | `On.getData()` → `_cleanStaleData()` then `_data`; alternate collector copies `timeBuffers[e]` + `e+"-mp"` mean periods into `_manifest` | **observed** |
| Event codes | mouse `md/mu/mm`, pointer `pm`, key `kd/ku`, `devicemotion` `dm` | **observed** |
| Sample tuple | `[windowX, windowY, Date.now()]` | **observed** |
| Wire packing of `topLevel` / `motiondata` | JSON vs encrypted blob | **unknown** |

## C. Encrypt / proof-class POST (post-click)

### Network envelope

| Field | Value | Status | Cite |
|-------|-------|--------|------|
| Method | POST XHR | **observed** | `OCTET_STREAM.md` req 13 |
| Host | `api.hcaptcha.com` | **observed** | same |
| Path | often **unknown** in native; may still be `/getcaptcha/<sitekey>` on refresh paths | **unknown** / **inferred** | Performance shows getcaptcha on Refresh; click-era path not named |
| Response MIME | `application/octet-stream` | **observed** | req 13 |
| Response decoded length | **2613** B (session 962) or **2376** B (`LIVE_OBSERVE_5472`) | **observed** | varies by session |
| Response encoded (completed) | 3112 (962) | **observed** | `OCTET_STREAM.md` |
| Request Content-Type | — | **unknown** | — |
| Request body length | — | **unknown** | — |
| Request / response field layout | — | **unknown** | withdrawn prior header guesses |

### Structural producers / consumers (no body link)

| Role | Bind | Status | Cite |
|------|------|--------|------|
| Binary **request** producer | `hsw(1)` → encrypt_req_data → Yc → encrypt CFF | **observed** (glue/path) | `ENCRYPT_DECRYPT.md`, `guest_ops.js` |
| Binary **response** consumer | `hsw(0)` → decrypt_resp_data | **observed** (glue/path) | same |
| Linked to req 13 by body or wasm sample | — | **unknown** (0 dispatch samples; no body) | `OCTET_STREAM.md` |

### Transport hints in `api.js` HTTP helper

- XHR: optional `responseType=arraybuffer` (falls back to JSON + `Accept: application/json`).
- `withCredentials` when not legacy.
- `fetch`: `credentials:"include"`; sets `content-type: application/json` when `responseType==="json"`; body is `e.data`.
- Base hosts: `https://api.hcaptcha.com`, `https://api2.hcaptcha.com`.

Status: **observed** (helper source). Which helper fires for encrypt-class POST remains **inferred**.

## D. What is still blocking a request-shaped client

1. Exact **request** Content-Type and byte length for getcaptcha and encrypt-class POSTs.
2. Whether the HTTP body is JSON of the manifest/`R` object, `application/x-www-form-urlencoded`, multipart, or an `hsw(1)` ciphertext wrapping those fields.
3. Octet-stream **response** field layout (and matching decrypt input).
4. checkcaptcha path / body (still absent from cited captures).

## Evidence files (scratch)

- `{SCRATCH}/perf-live-shapes.json` — live Performance API rows (sitekeys redacted)
- `{SCRATCH}/getGetCaptchaManifest.txt` — extracted function body
- `{SCRATCH}/api-js-body-shape-mine.txt` / `api-js-deeper.txt` — string mines
