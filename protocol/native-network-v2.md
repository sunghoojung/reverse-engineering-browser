# Native network observations v2: request target and body

Status: implemented source candidate. The overlay compiles against portable
harnesses of the pinned Chromium types, but patched Brave compilation and a
real-browser run are still required (see [Acceptance](#acceptance)).

Version 1 ([native-network-startup-v1.md](native-network-startup-v1.md)) still
owns startup, admission, request identity, lifecycle and the host-only
`request_started` payload. Version 2 adds two network records that are children
of those lifecycle records and one sensitive artifact kind. Nothing in a v1
record changes, so v1 readers and stored v1 sessions keep their meaning.
[SAFETY.md](../SAFETY.md) governs authorization, capture and export.

## Why

A host-only row such as `POST api.hcaptcha.com` cannot tell `/checksiteconfig`
from `/getcaptcha/<sitekey>` or `/checkcaptcha/<sitekey>/<key>`, and says
nothing about what was sent. v2 records the request target and describes every
request body, and retains the bytes only where the session allows it.

## Two capture levels

| Session | `request_body` record | `request_target` record | Body bytes |
| --- | --- | --- | --- |
| Network category off, or no session | none | none | none |
| Network on (metadata) | always: kind, state, length, normalized content type, SHA-256 | none | none |
| Network on with request content | always, as above | start and every redirect, with the full target as a `request_target` artifact past 116 bytes | at most 16 MiB per request, as a `request_body` artifact |

Request content is the session's sensitive content gate for requests:

- The browser switch `--reb-capture-request-content` admits it. It is read once
  at session start with the other session switches and needs the Network
  category. Without the Artifact category, the body records say the channel was
  unavailable instead of retaining bytes.
- The live launcher sets that switch for `REB_CAPTURE_REQUEST_CONTENT=1`, which
  requires category bits 256 (Network) and 1024 (Artifact), and then starts the
  artifact receiver with `--allow-sensitive`. `make live` leaves it off, and
  sessions started by `reb-api session start` or the MCP `start_live_session`
  tool always set it to 0.
- The packaged app's "Full request and response content" mode, its default
  research profile, sets `REB_CAPTURE_REQUEST_CONTENT=1` when the category mask
  allows it, reading the mask with the launcher's grammar (decimal or `0x`
  hexadecimal). A mask it cannot read turns nothing on, and the launcher
  reports it. "Metadata only" sets 0. An explicit environment value wins.
- The receiver still refuses the sensitive kind unless it was started with
  `--allow-sensitive`; that refusal is reported as an `artifact_capture_failed`
  event joined to the body record.

The digest, length and content type are metadata recorded in every Network
session. A SHA-256 of a low-entropy body can be confirmed by guessing, so it is
withheld for password form posts (below). Redaction stays an explicit
export-copy operation and never rewrites retained records or artifacts.

## Records

Both records use the v3 320-byte envelope with category `network`, flags 0,
payload size 128, navigation, status, error, transfer sizes and resource type
zero, and the same session, process, thread, tab, request, initiator, frame and
BrowserContext identity as their parent. `parent_event_id` is the exact parent
sequence, which is always lower. Consumers join a child only by that parent
reference, never by URL or adjacency. Payloads are little endian.

### `request_body` (type 22)

Emitted once per admitted request, immediately after `request_started`, as its
child. It describes the body as the page created it at request start; redirects
do not emit another one.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | body kind |
| 5 | 1 | capture state |
| 6 | 1 | flags |
| 7 | 1 | content type length, 0 to 64 |
| 8 | 8 | body length: bytes in in-memory elements |
| 16 | 8 | captured length: bytes in the body artifact |
| 24 | 4 | element count |
| 28 | 4 | reserved, zero |
| 32 | 32 | SHA-256 of the whole in-memory body, or zero |
| 64 | 64 | normalized content type, zero padded |

The envelope's `artifact_id` names the body artifact for states 4 and 5 and is
zero otherwise. That artifact's `creator_event_id` is this record's sequence.

Body kinds: 0 none, 1 in-memory bytes, 2 file, 3 blob or data pipe, 4 chunked
(streaming) data pipe, 5 mixed (more than one kind), 6 an element Chromium did
not identify.

Flags: bit 0 content capture was enabled; bit 1 digest present; bit 2 digest
not computed because the body exceeds 4 MiB; bit 3 length counts in-memory
parts only (any non-bytes part); bit 4 content type present; bit 5 a
`Content-Type` header was sent but was not a bounded media type, so it is not
recorded. Other bits are zero.

| State | Meaning |
| ---: | --- |
| 1 `no_body` | No body object or no elements (kind 0) |
| 2 `empty` | In-memory bytes totalling zero; digest of the empty string |
| 3 `metadata_only` | Content capture off for this session |
| 4 `captured` | The whole body was queued as the named artifact |
| 5 `captured_truncated` | The first 16 MiB were queued; the length and digest describe the whole body |
| 6 `not_captured_body_kind` | An unknown part, or a file, blob or stream part not read; nothing was read |
| 7 `not_captured_artifact_unavailable` | Artifact category off, receiver disconnected or session inactive |
| 8 `not_captured_transfer_refused` | The artifact queue or the background copy refused it |
| 9 `not_captured_url` | Not HTTP(S). Captures before payload version 2 targets also used it for URLs over 8 KiB |
| 10 `not_captured_session_budget` | The session's request-content byte budget was used |
| 11 `not_captured_credential_form` | Chromium marked a password form post; no bytes and no digest |

Validation rules, shared by the C++ core, the Python evidence validator and the
Origin Trace decoder:

- kind 0 if and only if state 1; then element count and body length are zero.
  Any other kind has at least one element, and mixed has at least two.
- bit 3 is set exactly for kinds other than 0 and 1.
- A digest is present only for in-memory bytes no longer than 4 MiB. Bit 2 is
  set only for in-memory bytes longer than 4 MiB. Other in-memory bodies carry
  exactly one of the two, except state 11, which carries neither. Without
  bit 1 the digest bytes are zero.
- Content type: bit 4 if and only if the length is nonzero, never with bit 5;
  the value is lower-case `type/subtype` RFC 9110 token characters with
  parameters such as `charset` or a multipart boundary removed. Bytes after the
  length are zero.
- captured length is at most body length and is nonzero only for states 4 and
  5. State 4 has captured equal to a nonzero body length; state 5 has a nonzero
  captured length below the body length. Both need bit 0, in-memory bytes and a
  nonzero `artifact_id`; every other state has `artifact_id` zero.
- State 3 has bit 0 clear. States 4 through 10 have bit 0 set. States 7 to 10
  need a nonzero in-memory body.
- [v3](native-network-v3.md#request-body-reads) adds bit 6 and state 12 for
  bodies the browser read, and states 7 to 10 for file, blob and stream bodies.

### `request_target` (type 23)

Emitted only with request content, immediately after `request_started` and
after every `request_redirected`, as the child of that record. A renderer also
emits one as the child of its own `request_initiated` for a request the proxy
never sees; see [v3](native-network-v3.md#requests-answered-in-the-renderer).

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `2` (`1` in older captures) |
| 2 | 2 | payload size, `128` |
| 4 | 4 | target length: bytes of path plus `?query` |
| 8 | 1 | scheme: 0 other, 1 http, 2 https, 3 ws, 4 wss |
| 9 | 1 | retention (version 2), zero in version 1 |
| 10 | 2 | explicit port, or 0 for the scheme default |
| 12 | 116 | the first `min(length, 116)` target bytes, zero padded |

The target is Chromium's canonical path and query. It never contains
credentials or a fragment; the host stays in the parent's v1 payload. Target
bytes are nonzero and every byte after them is zero. An invalid URL reports
length 0.

Retention says where the bytes past the prefix went:

| Value | Meaning |
| ---: | --- |
| 0 `complete` | The target is at most 116 bytes, so the prefix holds all of it |
| 1 `retained` | The whole target is the `request_target` artifact the envelope's `artifact_id` names |
| 2 `not_retained_artifact_unavailable` | Artifact category off, receiver disconnected, session inactive, or a renderer record ([v3](native-network-v3.md#requests-answered-in-the-renderer)) |
| 3 `not_retained_transfer_refused` | The in-flight pool or the background copy refused it |
| 4 `not_retained_session_budget` | The session's request-content byte budget was used |
| 5 `not_retained_url` | No HTTP(S) or WebSocket origin, or longer than Chromium's 2 MiB URL limit |

Value 0 if and only if the length is at most 116; value 1 if and only if
`artifact_id` is nonzero. A version 1 record has byte 9 and `artifact_id` zero
and a truncated prefix without its rest.

When a body artifact exists, its manifest `url` holds the complete URL
(scheme, host, explicit port, path and query) when that fits 8 KiB, and the
origin otherwise.

## Request content artifacts

Kind 8 `request_body` and kind 9 `request_target`, capture origin 10
`network_request`. Both are always
sensitive (flag bit 0), have execution context 0 and a nonzero creator: the
`request_body` or `request_target` record that names them. No other kind may
use that origin. A body's MIME type is the normalized content type, or
`application/octet-stream` when none was recorded. A full target's bytes are
the path and query, its MIME type is `text/plain`, and its manifest `url` is the
origin (`scheme://host[:port]`). Receivers, the backend and the UI reject any
other combination. The receiver's ACK produces `artifact_captured` or
`artifact_capture_failed` with the creator record's sequence as
`parent_event_id`, as for response artifacts. A body that changed between its
record and the copy is an `artifact_capture_failed` with reason
`request_content_changed`; a full queue after the copy is
`transfer_queue_full_or_disconnected`. The Origin Trace Sources workspace lists
neither kind; Traffic shows them with their request.

## Hot path and bounds

- Disabled: one atomic load, as in v1. Nothing is classified, hashed or copied.
- Every admitted request: one more 320-byte record, a walk over the body
  element list, a non-allocating `Content-Type` lookup and at most 4 MiB of
  SHA-256 on the browser UI sequence. Bodies above 4 MiB are marked, not hashed.
- Issue #436 asks that request bodies be copied and hashed on a background
  sequence while a reference keeps the body alive. The copy into the artifact
  and the artifact's digest are (next item). The record's own digest stays on
  the UI sequence on purpose, and this version keeps it there:
  - It is metadata of every Network session, and the record is emitted as the
    start's immediate child. Hashing elsewhere would defer the record past the
    start for every request with a body, and add to metadata sessions the
    capture-end and expiry losses that deferred reads have
    ([v3](native-network-v3.md#request-body-reads)).
  - A metadata session holds no reference to the body after the start
    returns, so there is nothing to hash later without keeping every body
    alive in a session that retains none.
  - The 4 MiB bound caps the work. SHA-256 runs at about 3 GB/s with the ARMv8
    and x86 SHA extensions that BoringSSL uses (3.0 GB/s for 4 MiB blocks with
    OpenSSL 3.6 on the Apple silicon machine this was measured on), so the
    worst case is about 1.4 ms once per such request, and only while capture
    is active. Most bodies are a few kilobytes and hash in microseconds.
- Request content: one more record per start or redirect. A body, and a target
  past 116 bytes, is charged to the session's byte budget, then copied and
  hashed on a background sequence while a reference keeps the immutable body
  alive, and streamed to the receiver in data frames of at most 64 KiB. Each
  frame holds its share of the 32 MiB in-flight pool it shares with response
  tees until the writer sends it, so the pool bounds bytes in flight rather
  than requests. The UI sequence copies only the target string. A pool that
  refuses a frame is `artifact_capture_failed` with `active_memory_limit`.
- The budget counts unique bytes: identical content already queued in the
  session configuration is refunded, because the receiver stores one blob per
  SHA-256. It defaults to 256 MiB and is set per session with
  `--reb-request-content-budget-bytes` (1 MiB to 4 GiB), which the launcher
  takes from `REB_REQUEST_CONTENT_BUDGET_MIB`, set by the app start panel's
  **Request content budget** or the start option `request_content_budget_mib`.
  The session summary's budget checks carry the budget in force and the unique
  request content retained, and `get_session_context` reports the limit as
  `capture_options.content_limits`. There is no body count; the
  launcher raises a content session's receiver to 65,536 artifacts and
  256 MiB plus the budget. Each refusal is a named state, never silence.
- The request is never delayed, consumed or altered. Content sessions read
  file, blob and stream parts as described in
  [v3](native-network-v3.md#request-body-reads).
- Queue loss is reported as in v1. A lost child leaves its request with no
  body or target record, which consumers show as "no record", not as no body.

## Consumers

- The broker accepts types 22 and 23 only when `IsValidEvent` accepts them; a
  rejected record is a visible sequence gap.
- The backend's bounded network window keeps both types with the lifecycle
  records, so busy fingerprint traffic cannot evict them. Metadata-only
  evidence packages carry neither payload, exactly as for other events.
- The broker's trace index links each child to its parent through
  `parent_event` only. A child never becomes its request's latest lifecycle
  record, so `request_lifecycle` edges run from one lifecycle record to the
  previous one. A trace step for a child names the record and its payload
  size instead of decoding the binary payload as text.
- Origin Trace joins children to their exact parent. A row with a target shows
  the captured path and query as text, with a marker when truncated. The
  request detail shows the full URL once its `request_target` artifact is read,
  or why the rest was not retained, and the body capture state, content type,
  length, digest, kind and, for retained bodies, the bytes decoded as UTF-8
  text. Bodies are read by range, 2 MiB at a time on request; the backend
  checks size and SHA-256 on every read and the view rechecks the digest once
  every byte is shown. A malformed child is shown
  as malformed in its own request instead of failing the whole refresh.
  Missing records read "no body record". Captured text is never parsed as HTML.
- A request trace's `invocation_value_flow` join searches a retained body,
  after the same size and SHA-256 check, for the exact digested value of a
  settled JavaScript invocation; see
  [native JavaScript invocation](native-js-invocation-v1.md#identity-and-relations).
  Without request content no body is retained and the join reports nothing.

## Validation

`make native-network-capture-check` drives the actual sink: disabled, expiry,
metadata-only, content, truncation, the digest bound, each body kind, password
forms, unavailable, refused, budget and unsupported-URL outcomes for bodies and
full targets, and redirect targets, checking every produced record with the
core validator.
`tests/network_request_test.cpp` (in `make native-tests`) checks overlay/core
layout parity, content-type normalization, every state and many malformed
records, and the receiver's sensitive policy and manifest round trip.
`make network-request-wire-check` compares the C++ verdicts with the Python
validator and the shipped decoders. `make native-artifact-capture-check` runs
request bodies and an 8 KB full target through the real sinks, the production
receiver with and without `--allow-sensitive`, and the broker; it drives 5,000
bodies to the byte budget, digest dedupe, the shared in-flight pool, the
background copy and every target retention state. `make rendered-ui-check` shows a retained
body containing markup and a metadata-only body in the packaged app.

## Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout,
   run `make brave-doctor` and `make brave-probe-check`, and compile the
   browser target. No patch changed; the existing proxy hooks already pass the
   full `ResourceRequest`.
2. With an authorized fixture, compare server receipts with native records for
   JSON, form, multipart, `Blob`, `ReadableStream` and file uploads, a password
   form, a 307 redirect of a POST, a 5 MiB body, a body above 16 MiB, an 8 KB
   GraphQL GET and a session that exhausts a small byte budget.
3. On the authorized hCaptcha demo, confirm that each `api.hcaptcha.com` POST
   shows its endpoint path, and that `checksiteconfig`, `getcaptcha` and
   `checkcaptcha` bodies are retained and their digests match.
4. Repeat with "Metadata only" and confirm no target record or body artifact
   exists while every body record keeps its length, type and digest.

Response bodies are described in [native network v3](native-network-v3.md).
File, `Blob` and stream request bodies are read in content sessions; see
[v3](native-network-v3.md#request-body-reads).
