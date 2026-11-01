# hCaptcha public demo — recorded request / event flow

Session `6576076265513586860`  
Source files (local only): `events.jsonl`, `origin-trace.jsonl`, `request-signals.jsonl`, `artifacts/manifest.jsonl`  
Tab 8, browser pid `72857`, hCaptcha renderer pid `73455`.  
Native network payloads are `METHOD` + **host only** (128-byte inline payload; none of these rows set `payload_truncated`). Paths below come from captured artifact URLs when an exact request link exists; otherwise path is **not recorded**.

Long hex query/fragment values are redacted. Request bodies, cookies, sitekeys, and tokens are not reproduced.

Time column `t_hcap` is milliseconds from browser `request_started` seq 548 (`GET accounts.hcaptcha.com`). Session had already been on `demo.fingerprint.com` for ~462 s.

---

## Stage list (recorded vs inferred)

| Stage | Status in this capture |
|---|---|
| Demo document `accounts.hcaptcha.com` | **Recorded** (main_frame HTML, 4359 decoded bytes). Body not retained as an artifact. |
| `api.js` load | **Recorded.** `GET js.hcaptcha.com/1/api.js` → artifact 69. |
| `checksiteconfig` | **Not recorded.** No JSON GET/XHR to an hCaptcha host between `api.js` and the iframes. |
| `hcaptcha.html` iframe | **Recorded** (two `sub_frame` loads of `newassets.hcaptcha.com`). Path from wasm artifact URL: `/captcha/v1/[build]/static/hcaptcha.html`. HTML body not retained. Challenge frame fragment has `frame=challenge`. Sibling frame looks like the checkbox copy (same decoded size, served `from_cache`). |
| `hsw.js` | **Recorded.** `GET newassets.hcaptcha.com/c/[content-hash]/hsw.js` → artifact 71 (1 543 201 bytes). |
| Wasm instantiate | **Recorded as artifacts**, not as a network fetch. Artifact 70 = empty 8-byte `WebAssembly.Module`. Artifacts 72/73 = 1 019 112-byte module (same digest); 72 `webassembly_instantiate`, 73 `unknown`. |
| `getcaptcha` | **Inferred, not proven by path.** Sole hCaptcha JSON XHR is `POST api.hcaptcha.com` (816 decoded bytes, 200). Path not in the probe payload; body not retained. |
| `checkcaptcha` | **Not recorded.** No later hCaptcha POST. |
| Image challenge assets | **Not recorded.** No `resource_type=image` to an hCaptcha host. |
| Telemetry / `logo.png` | **Inferred from MIME/size.** Two XHR GETs to `*.w.hcaptcha.com` returned `image/png` 2593 bytes each. Path not recorded. |
| `pst-issuer` | **Not recorded as a request.** Only appears as the `pstissuer` query key on `api.js` (`https://pst-issuer.hcaptcha.com`). |

---

## Chronological request table

Filter: `request_initiated` / `request_started` / `request_completed` / `request_failed` / `request_redirected` whose decoded payload host contains `hcaptcha.com` (including `js.`, `api.`, `accounts.`, `newassets.`, `*.w.`). No hCaptcha `request_failed` or `request_redirected` rows exist.

`status_code` on `request_started`/`request_initiated`/`request_completed` is 0 in the native envelope; the HTTP status lives on the paired `response_started` event (included as a note column). `resource_type` is only meaningful on `request_started` (completed rows reset to 0).

Resource types: `0=main_frame`, `1=sub_frame`, `3=script`, `12=favicon`, `13=xhr`.

| t_hcap (ms) | pid | seq | type | method | host + path | HTTP status | resource_type | req_id | artifact_id |
|---:|---:|---:|---|---|---|---:|---|---:|---|
| 0.0 | 72857 | 548 | request_started | GET | `accounts.hcaptcha.com` *(path not recorded)* | — | main_frame | 161 | — |
| 155.3 | 72857 | 561 | *response_started* | — | `text/html; protocol=h2` | **200** | — | 161 | — |
| 157.3 | 72857 | 562 | request_completed | — | *(host not in payload)* | — | — | 161 | — |
| 159.7 | 73455 | 1 | request_initiated | GET | `js.hcaptcha.com` | — | — | 455597 | — |
| 167.0 | 72857 | 563 | request_started | GET | `js.hcaptcha.com/1/api.js` *(path from artifact 69)* | — | script | 166 | — |
| 216.5 | 72857 | 564 | *response_started* | — | `application/javascript; protocol=h2` | **200** | — | 166 | — |
| 225.2 | 72857 | 565 | request_completed | — | decoded 415879 | — | — | 166 | — |
| 227.7 | 72857 | 566 | *artifact_captured* | — | accepted | — | — | 166 | **69** |
| 245.4 | 73455 | 24 | request_initiated | GET | `c68b2b0f6c21.w.hcaptcha.com` | — | — | 455598 | — |
| 245.5 | 72857 | 567 | request_started | GET | `c68b2b0f6c21.w.hcaptcha.com` *(path not recorded; response `image/png` 2593 B → telemetry/logo candidate)* | — | xhr | 167 | — |
| 251.9 | 72857 | 568 | request_started | GET | `newassets.hcaptcha.com/captcha/v1/[build]/static/hcaptcha.html` *(path from wasm artifact URL; challenge iframe)* | — | sub_frame | 168 | — |
| 265.2 | 72857 | 569 | request_started | GET | `newassets.hcaptcha.com` *(same decoded size as 168; path not on this request)* | — | sub_frame | 169 | — |
| 289.9 | 73455 | 88 | request_initiated | GET | `accounts.hcaptcha.com` | — | — | 455599 | — |
| 290.0 | 72857 | 570 | request_started | GET | `accounts.hcaptcha.com` *(path not recorded; favicon)* | — | favicon | 170 | — |
| 299.2 | 72857 | 571 | *response_started* | — | `image/png; protocol=http/1.1` | **200** | — | 167 | — |
| 299.5 | 72857 | 572 | request_completed | — | decoded 2593 | — | — | 167 | — |
| 316.2 | 72857 | 573 | *response_started* | — | `text/html; protocol=h2` | **200** | — | 168 | — |
| 318.3 | 72857 | 574 | *response_started* | — | `text/html; protocol=h2` **from_cache** (flags=2) | **200** | — | 169 | — |
| 323.1 | 72857 | 575 | *response_started* | — | `text/plain; protocol=h2` | **404** | — | 170 | — |
| 324.3 | 72857 | 576 | request_completed | — | decoded 0 | — | — | 170 | — |
| 365.7 | 72857 | 577 | request_completed | — | decoded 694539 | — | — | 168 | — |
| 366.1 | 72857 | 578 | request_completed | — | decoded 694539 | — | — | 169 | — |
| 395.1 | 73455 | 89 | request_initiated | GET | `8373350c6d72.w.hcaptcha.com` | — | — | 455602 | — |
| 395.2 | 72857 | 579 | request_started | GET | `8373350c6d72.w.hcaptcha.com` *(path not recorded; `image/png` 2593 B → second telemetry/logo candidate)* | — | xhr | 171 | — |
| 422.4 | 73455 | 91 | request_initiated | POST | `api.hcaptcha.com` | — | — | 455603 | — |
| 422.5 | 72857 | 580 | request_started | POST | `api.hcaptcha.com` *(path not recorded; JSON 816 B → getcaptcha candidate)* | — | xhr | 172 | — |
| 422.9 | 72857 | 581 | *artifact_captured* | — | empty wasm module (`\0asm\x01\0\0\0`, 8 B) | — | — | 0 | **70** |
| 451.8 | 72857 | 582 | *response_started* | — | `image/png; protocol=http/1.1` | **200** | — | 171 | — |
| 452.2 | 72857 | 583 | request_completed | — | decoded 2593 | — | — | 171 | — |
| 470.2 | 72857 | 584 | *response_started* | — | `application/json; protocol=h2` | **200** | — | 172 | — |
| 470.3 | 72857 | 585 | request_completed | — | decoded 816 | — | — | 172 | — |
| 471.9 | 73455 | 93 | request_initiated | GET | `newassets.hcaptcha.com` | — | — | 455604 | — |
| 472.0 | 72857 | 586 | request_started | GET | `newassets.hcaptcha.com/c/[content-hash]/hsw.js` *(path from artifact 71)* | — | script | 173 | — |
| 490.3 | 72857 | 587 | *response_started* | — | `application/javascript; protocol=h3` | **200** | — | 173 | — |
| 533.0 | 72857 | 588 | request_completed | — | decoded 1543201 | — | — | 173 | — |
| 542.8 | 72857 | 589 | *artifact_captured* | — | accepted | — | — | 173 | **71** |

`origin-trace.jsonl` links renderer `request_initiated` → browser `request_started` with relation `request_initiator` / confidence `observed` for reqs 166, 167, 170, 171, 172, 173. Main-frame 161 and both iframes 168/169 have no renderer initiator row (browser-driven navigations). Artifact 69 is `artifact_request` correlated to req 166; artifact 71 to req 173.

`request-signals.jsonl`: every hCaptcha request profile has **zero signals**.

No further hCaptcha network events after req 173. The rest of the session is unrelated `api.factors.ai` polling from the earlier fingerprint.com tab.

---

## Per-request notes

### 161 — demo document
`GET accounts.hcaptcha.com`, main_frame, 200, 4359 decoded bytes. Not captured as an artifact (HTML is outside the JS/wasm retain set).

### 166 / artifact 69 — api.js
Exact URL: `https://js.hcaptcha.com/1/api.js` with query keys `reportapi`, `custom`, `pstissuer` (values are the public accounts / pst-issuer origins; not dumped). VM analysis: candidate, `vm_score=60`, families bytecode/dispatch/exits/state. Related request ids 161, 166, 167, 170.

### 167 — telemetry/logo candidate (parent page)
XHR GET `c68b2b0f6c21.w.hcaptcha.com` → `image/png` 2593 bytes. **Not** `checksiteconfig` (that API is JSON). Path absent.

### 168 — challenge iframe (`hcaptcha.html`)
sub_frame, 200, 694539 decoded bytes, h2. Frame `3346427699321862858`. Wasm artifacts 70/72/73 are scoped to this frame; their URL path is `/captcha/v1/b1c4f881f907b3e342c934423e51c70d282dc1a1/static/hcaptcha.html` and the fragment includes `frame=challenge`. HTML not retained.

### 169 — second iframe, cache hit
sub_frame, 200, flags `from_cache`, encoded_data_length 0, decoded 694539 (same as 168). Frame `17437143504006294829`. No wasm artifacts on this frame. Compatible with the checkbox iframe sharing the same document.

### 170 — favicon 404
`GET accounts.hcaptcha.com`, favicon, 404 `text/plain`.

### 171 — telemetry/logo candidate (challenge frame)
Same shape as 167: XHR GET `8373350c6d72.w.hcaptcha.com` → `image/png` 2593 bytes.

### 172 — getcaptcha candidate
XHR `POST api.hcaptcha.com` → 200 `application/json` 816 decoded / 878 encoded. Path and body **not recorded**, so this cannot be distinguished from another small JSON POST by URL. Timing (after iframe HTML, before `hsw.js`) matches typical `getcaptcha`. No image-challenge fetches follow.

### 173 / artifact 71 — hsw.js
`https://newassets.hcaptcha.com/c/373d8f355b87f7b8ceaeb891f31f5284f170bd7d17e88d2b0b448f6b85a3c16a/hsw.js`, 1 543 201 bytes, h3. VM analysis: candidate, `vm_score=60`, families bytecode/dispatch/exits/handlers.

---

## Wasm artifacts and instantiate

| artifact | origin | bytes | sha256 prefix | creator_event | notes |
|---|---|---:|---|---|---|
| 70 | `webassembly_module` | 8 | `93a44bbb…` | 0 (captured seq 581) | Empty module: magic+version only. Not the hsw image. |
| 71 | `network_response` | 1543201 | `cabf8ffb…` | 587 | `hsw.js`. |
| 72 | `webassembly_instantiate` | 1019112 | `e0e67a53…` | 0 (captured seq 590) | Full module; likely-vm `vm_score=75`. |
| 73 | `unknown` | 1019112 | `e0e67a53…` (same as 72) | 0 (captured seq 591) | Observation target (`artifact_id=73` on all wasm samples). Same finding as 72. |

No `module_compiled` / `module_instantiated` probe types, no `wasm_guest_dispatch`, no `wasm_guest_invocation`, no `js_dispatch_observation`.

---

## `wasm_dispatch_observation` — 16 events

All pid `73455`, `artifact_id=73`, challenge frame, 128-byte native payload, `payload_truncated=false`, trailer bytes 24..127 zero. Layout: `u16 version=1`, `u16 size=128`, then LE u32 `function_index`, `module_byte_offset`, `selector`, `table_count`, `sample_index`.

Then gap seq 128: `native_wasm_dispatch_budget_incomplete` — the 16 samples are a budget cap, not a complete br_table trace.

| sample_index | seq | function_index | offset | selector | table_count | selected_arm | is_default |
|---:|---:|---:|---:|---:|---:|---:|---|
| 0 | 112 | 422 | 268080 | 3 | 5 | 3 | no |
| 1 | 113 | 422 | 268080 | 4 | 5 | 4 | no |
| 2 | 114 | 422 | 268080 | 0 | 5 | 0 | no |
| 3 | 115 | 225 | 63202 | 0 | 6 | 0 | no |
| 4 | 116 | 225 | 63202 | 3 | 6 | 3 | no |
| 5 | 117 | 225 | 63202 | 1 | 6 | 1 | no |
| 6 | 118 | 420 | 257282 | 115 | 267 | 115 | no |
| 7 | 119 | 420 | 257282 | 44 | 267 | 44 | no |
| 8 | 120 | 420 | 257282 | 104 | 267 | 104 | no |
| 9 | 121 | 420 | 257282 | 210 | 267 | 210 | no |
| 10 | 122 | 420 | 257282 | 75 | 267 | 75 | no |
| 11 | 123 | 420 | 257282 | 212 | 267 | 212 | no |
| 12 | 124 | 420 | 257282 | 251 | 267 | 251 | no |
| 13 | 125 | 420 | 257282 | 81 | 267 | 81 | no |
| 14 | 126 | 420 | 257282 | 146 | 267 | 146 | no |
| 15 | 127 | 420 | 257282 | 218 | 267 | 218 | no |

Three physical sites: a 5-arm table in fn 422, a 6-arm table in fn 225, and a 267-arm table in fn 420 (10 of 16 samples). No default-arm sample (`selector < table_count` on every row). These are physical Wasm `br_table` selectors, not guest opcodes.

---

## `wasm_indirect_observation` — 16 events

Same envelope; fields LE u32 `function_index`, `module_byte_offset`, `table_index`, `slot`, `callee`, `resolution`, `sample_index`. Trailer 32..127 zero. All `resolution=resolved` (0), `table_index=0`. Then gap seq 145: `native_wasm_indirect_budget_incomplete`.

| sample_index | seq | function_index | offset | slot | callee |
|---:|---:|---:|---:|---:|---:|
| 0 | 129 | 216 | 31685 | 77 | 700 |
| 1 | 130 | 700 | 532691 | 106 | 432 |
| 2 | 131 | 634 | 459284 | 140 | 387 |
| 3 | 132 | 387 | 229663 | 137 | 896 |
| 4 | 133 | 870 | 701612 | 101 | 1097 |
| 5 | 134 | 1097 | 893575 | 79 | 1033 |
| 6 | 135 | 404 | 235912 | 17 | 199 |
| 7 | 136 | 976 | 778188 | 165 | 321 |
| 8 | 137 | 404 | 235835 | 165 | 321 |
| 9 | 138 | 404 | 235912 | 4 | 866 |
| 10 | 139 | 976 | 778188 | 165 | 321 |
| 11 | 140 | 404 | 235835 | 165 | 321 |
| 12 | 141 | 404 | 235912 | 4 | 866 |
| 13 | 142 | 976 | 778188 | 165 | 321 |
| 14 | 143 | 404 | 236293 | 1 | 805 |
| 15 | 144 | 994 | 798468 | 165 | 321 |

11 unique `(function, offset)` sites. Callee 321 appears 6 times (slot 165). Opcode workspace for artifacts 72/73 reports 1024 handlers and **0** native guest samples — dispatch/indirect rows are not guest-PC samples.

Immediately after instantiate the challenge frame records fingerprint-style host calls (1164 canvas, 93 webgl, 30 web_audio, 23 navigator) including `canvas.toDataURL`. Those are not network stages.

---

## What was **not** recorded

- **`checksiteconfig`** — no JSON GET/XHR to hCaptcha between `api.js` and the iframes. Request ids 166 → 167 with nothing in between on an hCaptcha host.
- **`checkcaptcha`** — no second `POST api.hcaptcha.com` (or other hCaptcha POST) after req 172. Capture continues for ~3 more minutes on other sites, so this is a missing stage, not an early session cut.
- **Image challenge assets** — no `resource_type=image` to hCaptcha; no `imgs*.hcaptcha.com`. Consistent with a checkbox/passive `getcaptcha` (small JSON, no tile URLs fetched).
- **`pst-issuer.hcaptcha.com` as a request** — only a query parameter on `api.js`.
- **URL paths on network events** — native sink stores host only. Paths exist solely on JS/wasm artifact URLs (api.js, hsw.js, hcaptcha.html). XHR paths (`getcaptcha`, logo) are unknown.
- **Request/response bodies** for HTML, XHR, and JSON. Artifact kinds retained here are `javascript` and `wasm` only.
- **Iframe HTML artifact** — 694 539-byte documents completed, not captured.
- **Guest bytecode** — renderer seq 108 in the challenge frame: `artifact_capture_failed` / `runtime_buffer_no_vm_signal`. Zero `wasm_guest_dispatch` / `wasm_guest_invocation`.
- **Complete wasm observation streams** — both budgets incomplete after 16 samples.
- **Request-signal profiles** — empty for every hCaptcha request (`n_signals=0`, `parent_depth=0`).
- **Navigation identity** — `navigation_id` is `"0"` on these rows.
- **Initiator for document/iframe navigations** — reqs 161, 168, 169 have `initiator_request_id=0`.

---

## Capture-gap events in the hCaptcha window

| t_hcap (ms) | pid | seq | type | payload |
|---:|---:|---:|---|---|
| 565.8 | 73455 | 108 | artifact_capture_failed | `runtime_buffer_no_vm_signal` |
| 584.1 | 73455 | 128 | gap | `native_wasm_dispatch_budget_incomplete` |
| 601.6 | 73455 | 145 | gap | `native_wasm_indirect_budget_incomplete` |

Earlier `active_memory_limit` / `allocating_script_url_unavailable` failures belong to the fingerprint.com page, not this flow.
