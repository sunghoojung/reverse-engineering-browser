# Native network observations v3: response bodies

Status: implemented source candidate. The overlay compiles against portable
harnesses of the pinned Chromium types; patched Brave compilation and a live run
are still required (see [Acceptance](#acceptance)).

Version 1 ([startup v1](native-network-startup-v1.md)) owns request identity
and lifecycle, version 2 ([network v2](native-network-v2.md)) the request target
and body. This part of v3 adds one child record, type 33 `response_body`, and
produces the existing sensitive artifact kind 4 `response_body`. Nothing in a v1
or v2 record changes. [SAFETY.md](../SAFETY.md) governs capture and export.

## Capture

Response bodies follow the request content gate of v2: only sessions started
with `--reb-capture-request-content` (`REB_CAPTURE_REQUEST_CONTENT=1`) with the
Network and Artifact categories. Metadata-only sessions record no
`response_body` record and tee nothing new.

The existing proxied-loader tee (`patches/0002`, `patches/0013`) is the only
capture path. `NativeArtifactCaptureSink::MaybeCaptureResponse` keeps scripts
and Wasm as before, in every artifact session, and hands every other response
to `browser/native_response_body_capture.cc`:

- Kept by default: documents, JSON, text, XML, fetch and XHR responses, and any
  other subresource.
- Skipped unless `--reb-capture-response-media` (`REB_CAPTURE_RESPONSE_MEDIA=1`):
  fonts and media (resource types 5 and 8, `font/*`, `audio/*`, `video/*`, font
  application types), and images that page elements load (resource types 4 and
  12, `image/*` except `image/svg+xml`). A fetch or XHR image is kept.
- The tee forwards decoded bytes, so the artifact holds the decoded body. The
  record keeps the `Content-Encoding` codings as sent and flags bodies Chromium
  left encoded for client-side decoding.
- The source pipe closing does not prove a whole body. The loader's completion
  status decides: an error is `aborted`, `net::ERR_ABORTED` or the page closing
  its pipe is `cancelled`. A body whose completion never arrives is kept after
  10 s and flagged.
- A body without a declared length that is still open after a second is
  snapshotted as `partial` when it has grown by half since the last snapshot,
  at most 15 times, so snapshots stay within three times the body. Open bodies
  at capture end or expiry become one last `partial` record. The record of the
  ended body supersedes every snapshot.

## `response_body` (type 33)

Category `network`, the v2 child envelope (flags 0, payload size 128,
navigation, status, error, transfer sizes and resource type zero, the parent's
identity, `parent_event_id` below its own sequence). The parent is the
`response_started` record, or the `request_redirected` record for state 8. Its
time is when the body ended or was snapshotted. Little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | state |
| 5 | 1 | flags |
| 6 | 1 | content type length, 0 to 64 |
| 7 | 1 | coding count, 0 to 4 |
| 8 | 8 | body length: decoded bytes that passed the tee, so far for `partial` |
| 16 | 8 | captured length: bytes in the named artifact |
| 24 | 4 | codings, one byte each in `Content-Encoding` order, zero after the count |
| 28 | 2 | partial index: n for the n-th snapshot, else 0 |
| 30 | 2 | reserved, zero |
| 32 | 32 | SHA-256 of the captured bytes, or zero |
| 64 | 64 | normalized content type, as in v2, zero padded |

| State | Meaning |
| ---: | --- |
| 1 `captured` | The whole body is the named artifact |
| 2 `captured_truncated` | The first 16 MiB are the named artifact |
| 3 `partial` | The body is still open; the artifact is what arrived so far |
| 4 `aborted` | The network failed before the end; any bytes that arrived are the artifact |
| 5 `cancelled` | The page or browser stopped the request; any bytes that arrived are the artifact |
| 6 `empty` | The body ended with zero bytes, or the loader sent no body |
| 7 `not_modified` | HTTP 304; no body |
| 8 `redirected` | A redirect hop; Chromium discards its body |
| 9 `not_captured_type` | Media or a font, not asked for |
| 10 `not_captured_artifact_unavailable` | Artifact category off, receiver disconnected or session inactive |
| 11 `not_captured_transfer_refused` | The in-flight pool, the tee or the artifact queue refused it |
| 12 `not_captured_session_budget` | The session's response body budget was used |

Flags: bit 0 `shared`, identical bytes were already retained in this
configuration and `artifact_id` names that earlier artifact; bit 1 served from
the HTTP cache; bit 2 served by a service worker; bit 3 bytes still encoded
(client-side decoding); bit 4 more than four codings, the rest not recorded;
bit 5 completion not observed; bit 6 content type present. Other bits are zero.

Codings: 1 `gzip` (and `x-gzip`), 2 `deflate`, 3 `br`, 4 `zstd`, 5 `dcb`,
6 `dcz`, 7 `compress`, 15 any other token. `identity` is not a coding.

Rules, shared by the C++ core, the Python evidence validator and the Origin
Trace decoder (`make network-request-wire-check`):

- `artifact_id` is nonzero, the digest nonzero and the captured length nonzero
  all together, or none of them. `shared` needs an artifact.
- Captured length is at most body length. With L = min(body length, 16 MiB):
  state 1 has captured equal to a nonzero body length; state 2 has a body over
  16 MiB and captured 16 MiB; state 3 has a nonzero body and captured L;
  states 4 and 5 have captured 0 or L; states 6 to 9 have body length 0;
  states 10 to 12 have no artifact.
- Partial index is nonzero exactly for state 3. Bit 5 only with states 1, 2
  and 6. Bit 4 only with four codings. Coding bytes follow the coding count.
- Content type: bit 6 if and only if the length is nonzero, normalized as in
  v2, zero after its length. Reserved bytes are zero.

## Response body artifact

Kind 4 `response_body`, capture origin 1 `network_response`, always sensitive,
execution context 0. Its `creator_event_id` is the `response_started` record,
the same join as script artifacts: by `request_id` and creator, never by URL. A
shared record's artifact keeps its first creator. The manifest URL is the
request's scheme, host, explicit port, path and query, or its origin past
8 KiB; the MIME type is Chromium's, or `application/octet-stream`. The ACK
becomes `artifact_captured` or `artifact_capture_failed` with the creator as
`parent_event_id`. Script and Wasm responses keep kinds 1 and 2 and get no
`response_body` record unless the artifact channel is unavailable.

The receiver still refuses the kind without `--allow-sensitive`, which the
launcher passes for content sessions.

## Bounds

- Disabled: unchanged; every sink returns at its emitter load. Metadata-only:
  one relaxed load per response start, completion and untyped body.
- Each kept body reserves its declared length, or one 64 KiB chunk that grows,
  in the 32 MiB in-flight pool it shares with scripts and request content, and
  holds that share until the artifact writer drops it. A full pool is state 11,
  never a stall. Fifty parallel bodies of unknown length hold 3.2 MiB.
- At most 16 MiB per body. Past it the tee keeps the prefix and counts every
  byte.
- SHA-256 runs off the UI sequence. The capture-end flush hashes on the UI
  sequence, bounded by the pool.
- Unique bytes per session are budgeted: 512 MiB by default, 1 MiB to 16 GiB
  with `--reb-response-body-budget-bytes` (`REB_RESPONSE_BODY_BUDGET_MIB`).
  Identical bytes are stored once by SHA-256 and charge nothing; a receiver
  refusal refunds them. The launcher grows a content session's receiver store
  by both budgets.
- Every refusal is a named state. The session summary counts states 2 and 9 to
  12 under `request_content_not_retained`, category `response_body`.

## Bodies the proxy never sees

Service-worker and memory-cache answers and requests that failed before a
response have no browser `response_started`, so they have no `response_body`
record. Traffic says the proxy recorded no response for them; it never shows
an empty body.

## Agent access

Bytes are read with `get_artifact_content`; `get_events` with
`type=response_body` and `request_id` names the artifact. MCP keeps its rules:
binary is refused and oversized JSON returns a structural summary.

## Consumers

- The broker validates type 33 in `IsValidEvent`; a rejected record is a
  visible sequence gap. The backend keeps it in its network window, and trace
  steps name it instead of decoding it as text.
- Origin Trace joins the newest record whose parent is the request's final
  `response_started`. The Traffic tabs are General, Preview, Response,
  Initiator, Timing, Signals and Evidence. Response shows the state, codings,
  lengths and digest, then the bytes as syntax-colored text with pretty print,
  wrap, find, copy and hex (always hex for binary). Preview shows a bounded
  JSON tree, a raster image whose signature matches its bytes, plain text, or
  markup as source. HTML and SVG are never rendered. Reads are ranged 2 MiB at a
  time and rechecked by size and SHA-256.

## Validation

`make native-artifact-capture-check` drives the real network sink, artifact
sink, response capture and production receiver and broker: JSON, gzip HTML,
brotli and service-worker JSON, a fetched PNG, a chunked stream partial then
captured, an aborted prefix, 304, a redirect, a cancelled body, a skipped font,
digest dedupe, budget exhaustion, receiver refusal refund, 50 parallel bodies,
the full pool, 16 MiB truncation, a missing completion, coding order, the
capture-end partial, media opt-in, metadata-only sessions and tee refusal.
`make native-network-capture-check` covers the redirect and unavailable records.
`tests/network_request_test.cpp` checks layout parity and every valid and
malformed record. `tools/check-traffic-response-ui.mjs` and
`make rendered-ui-check` cover the tabs.

## Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout,
   run `make brave-doctor` and `make brave-probe-check`, and compile the
   browser target. No patch changed.
2. With an authorized fixture, compare server bytes with retained artifacts for
   JSON, HTML, an image, gzip and brotli, a chunked response, server-sent
   events, an aborted download, a 304, a redirect and a service-worker-served
   response; load 50 responses in parallel; exhaust a small budget; and watch
   browser memory stay within the pool.
