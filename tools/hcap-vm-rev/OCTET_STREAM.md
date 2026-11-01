# POST api.hcaptcha.com octet-stream envelope (session 962, req 13)

Reconstructive analysis only. No solver. No captured payload bytes, tokens,
sitekeys, or request/response bodies. No calls to `api.hcaptcha.com`.

Session `9623810216396876129` served idle from Origin Trace loopback
`http://127.0.0.1:56738`. Tools: `reb-api` `get_health`, `get_session_context`,
`get_artifacts`, `get_events`, `inspect_wasm`, `get_vm_analysis`,
`get_vm_opcode_workspace`, `get_vm_host_links` (GET analysis, no `--read-only`
on this build).

Companion module: `/tmp/hcap-vm-rev/octet_envelope.js`.

## What 2613 actually is

Native events store **METHOD+host only** on `request_started` and
**MIME+protocol** on `response_started`. Bodies are not retained.
`payload_truncated=false` on every req 11–17 row. POST line for req 13 is
21 bytes: `POST api.hcaptcha.com`.

`decoded_body_length` on `request_completed` is the **decoded response body**.
That is proven by artifact size identity:

| req | decoded_body_length | artifact | byte_size |
|-----|--------------------:|----------|----------:|
| 5 | 415879 | 2 `api.js` | 415879 |
| 12 | 1543169 | 4 `hsw.js` | 1543169 |
| 14 | 33480 | 6 `challenge.js` | 33480 |

Req 13 therefore:

| field | value | status |
|---|---|---|
| method + host | `POST api.hcaptcha.com` | proven |
| resource_type | 13 (xhr) | proven |
| HTTP status | 200 | proven |
| response Content-Type | `application/octet-stream` | proven (`response_started`) |
| protocol | h3 | proven |
| decoded response length | **2613** | proven (`request_completed`) |
| encoded_data_length (completed) | 3112 | proven |
| encoded_data_length (response_started) | 471 | proven |
| request Content-Type | — | **UNKNOWN** |
| request body length | — | **UNKNOWN** |
| URL path | — | **UNKNOWN** |
| field layout of the 2613 bytes | — | **UNKNOWN** |

The reconstructive envelope records the **response** MIME and decoded length.
It does not claim the POST request body was 2613 bytes.

## Named stages (order proven)

Times are milliseconds from req 4 `GET accounts.hcaptcha.com` start.

| stage | req | method host | MIME | decoded | t_rel |
|---|---|---|---|---:|---:|
| demo_document | 4 | GET accounts.hcaptcha.com | text/html | 4359 | 0 |
| api_js | 5 | GET js.hcaptcha.com | application/javascript | 415879 | 110.2 |
| telemetry_png_parent | 6 | GET `*.w.hcaptcha.com` | image/png | 2593 | 186.2 |
| hcaptcha_html_challenge_frame | 7 | GET newassets.hcaptcha.com | text/html | 694539 | 209.7 |
| hcaptcha_html_checkbox_frame | 8 | GET newassets.hcaptcha.com | text/html (from_cache) | 694539 | 210.2 |
| favicon_404 | 9 | GET accounts.hcaptcha.com | text/plain 404 | 0 | 225.2 |
| telemetry_png_challenge_frame | 10 | GET `*.w.hcaptcha.com` | image/png | 2593 | 300.5 |
| **getcaptcha_json** | **11** | **POST api.hcaptcha.com** | **application/json** | **822** | **325.2** |
| hsw_js | 12 | GET newassets.hcaptcha.com | application/javascript | 1543169 | 370.3 |
| wasm_stub | art 3 | instantiate | application/wasm | 8 | — |
| wasm_instantiate | art 5 | instantiate | application/wasm | 1020263 | — |
| **octet_stream** | **13** | **POST api.hcaptcha.com** | **application/octet-stream** | **2613** | **68135.0** |
| **challenge_js_image_drag_drop** | **14** | GET newassets.hcaptcha.com | text/javascript | 33480 | 68333.0 |
| challenge_image_jpeg | 15 | GET imgs3.hcaptcha.com | image/jpeg | 40878 | 68366.3 |
| challenge_image_png_a | 16 | GET imgs3.hcaptcha.com | image/png | 3729 | 68366.5 |
| challenge_image_png_b | 17 | GET imgs3.hcaptcha.com | image/png | 5019 | 68366.7 |

`getcaptcha` as the name of req 11 is **inferred** (JSON XHR POST to
`api.hcaptcha.com` after iframe HTML, before `hsw.js`). The path is not in
the native payload.

Req 13 starts **67.810 s** after req 11 (click/HSW dwell, not an immediate
follow-up). RTT start→`response_started` is **190.122 ms**. Req 14
(`challenge/image_drag_drop/challenge.js`, artifact 6, 33480 B) starts
**7.709 ms** after req 13 completes. Three `imgs3.hcaptcha.com` images follow.

Renderer pid 9470 `request_initiated` pairs: 62113→req 11, 62115→req 13.

## Envelope (no payload bytes)

Schema version `1` is this reconstructive document, not a recovered wire tag.

```
{
  version: 1,
  contentType: "application/octet-stream",
  byteLength: 2613,
  after:  { stage: "getcaptcha_json", contentType: "application/json", byteLength: 822 },
  before: { stage: "challenge_js_image_drag_drop", contentType: "text/javascript", byteLength: 33480 }
}
```

Produced by `encodeEnvelope()` in `octet_envelope.js`.

## Field layout

```
offset  size  field
------  ----  -----
UNKNOWN UNKNOWN UNKNOWN
```

No version byte, length prefix, PoW nonce, fingerprint digest, or telemetry
blob is established. Prior notes that guessed 16–32 B headers and ~2 KB
encrypted telemetry are **not proven** and are withdrawn.

Folded in from sibling reconstructive work (comments only, not this blob):

- `hsw(0)` → `decrypt_resp_data` (magic `-58720044`, func 424 / CFF 941) is
  the documented consumer of **binary responses**.
- `hsw(1)` → `encrypt_req_data` (magic `1983284732`, func 592 / CFF 386) is
  the documented producer of **binary requests**.
- Those paths exist on the HSW glue object; they are **not linked** to req 13
  by body capture or `wasm_dispatch_observation` (0 native samples).
- `get_vm_host_links` for artifacts 4 and 5 cover network seq 19–39 (through
  `hsw.js` complete) and **do not** include seq 42–44 (req 13).
- Artifact 5: 1,020,263 B, sha256 `49086a4a…`, `vm_score` 75 likely-vm,
  190 imports, 742 `br_table`, 144 `call_indirect`, 886 dispatch sites,
  selected offset 585250. Opcode workspace: 1024 handlers, 0 samples.

## Unknowns

1. URL path of both POSTs (getcaptcha vs checkcaptcha vs other).
2. Request Content-Type and request body length for req 13.
3. Any byte of the 2613-byte response (and of the request).
4. Field layout: version, lengths, order, cipher, padding.
5. Whether `encrypt_req_data` / `decrypt_resp_data` ran on this exchange.
6. Challenge JWT / sitekey / n-proof contents (not recovered, not wanted).
7. Meaning of encoded 3112 vs decoded 2613 (framing vs request+response).

## Related artifacts

| id | kind | bytes | sha256 prefix | role |
|---|---|---:|---|---|
| 2 | javascript | 415879 | `96c4dbc6` | api.js |
| 3 | wasm | 8 | `93a44bbb` | empty module |
| 4 | javascript | 1543169 | `d08c6ce0` | hsw.js |
| 5 | wasm | 1020263 | `49086a4a` | instantiate, likely-vm |
| 6 | javascript | 33480 | `16d85251` | `challenge/image_drag_drop/challenge.js` |
