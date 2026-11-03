# Native JavaScript invocation observations v1

A call of an armed JavaScript function gets an identity that V8 assigns at
entry and carries across the call's awaits and promise jobs. There is no CDP,
page JavaScript or debugger. The reviewed design, including why each rule and
limit below exists, is
[native JavaScript invocation identity v1](../docs/product/native-js-invocation-v1.md).

## Enablement

Rebuild Brave with V8 patch `0011`, Chromium patch `0021` and the overlay.
Launch a native live session with
`REB_NATIVE_JS_INVOCATION_SITES=/absolute/path/sites.json`. The launcher adds
`--js-flags=--reb-js-invocation-capture` and
`--reb-js-invocation-sites=/absolute/path/sites.json`. The category mask must
include VM (512); request records also need Network (256). The site file is
read once per session, must be identical for the browser lifetime, and
changing it needs a browser restart. The flag alone arms nothing, and the
file alone emits nothing.

`REB_NATIVE_JS_INVOCATION_DIGESTS=1` additionally passes
`--reb-js-invocation-digests`, the session's sensitive opt-in for
settled-value digests. The launcher accepts it only with a site file and
prints a sensitive-capture label. Without it every settle record says
`digest_state: not_requested`.

`--reb-js-invocation-capture` implies `--reb-js-dispatch-capture`, so the
compile-path settings of
[JavaScript dispatch capture](native-js-dispatch-v1.md#enablement) apply: no
code cache, compilation cache or streaming, and eager source positions.
Functions that start at an armed site are never optimized. Workers, worklets
and service workers are unsupported: their isolates never arm a site, and a
Wasm or loader record on a worker thread reads as `not_observed`.

## Site file

`native-js-invocation-sites-v1` has the exact form of
[`native-js-dispatch-sites-v1`](native-js-dispatch-v1.md#site-file) with
`shape` fixed to `function-entry`:

```json
{"sites":[{"anchor_offset":120,"artifact_id":"12","artifact_sha256":"<64 lowercase hex>","byte_offset":118,"shape":"function-entry","source_length":456,"source_sha256":"<64 lowercase hex>"}],"version":1}
```

`anchor_offset` is the UTF-16 offset of the function's V8 start position: the
`(` that opens the parameter list of a function, method, getter or setter, or
the first character of an arrow function's head. `source_sha256` and
`source_length` are computed exactly as for dispatch sites.
`tools/native-js-invocation-site.py ARTIFACT_PATH:ARTIFACT_ID:BYTE_OFFSET`
writes the file from a retained artifact and the UTF-8 offset of a `(`, and
refuses any other character.

The browser sends the renderer only fixed 44-byte records: `source_sha256`
(32 bytes), `source_length` (u32), `anchor_offset` (u32), shape byte 3 and 3
zero bytes. A dispatch record (shape 1 or 2) is refused here and a
function-entry record is refused as a dispatch site.

Generators, async generators, class constructors and class initializer
functions are never armed; see the design for why.

## V8 embedder interface

`include/v8-callbacks.h` and `include/v8-isolate.h` gain
`v8::JsInvocationSite`, `JsInvocationStart`, `JsInvocationSettle`,
`JsInvocationContext`, `JsInvocationCallbacks`,
`Isolate::SetJsInvocationCallbacks` and `Isolate::GetCurrentJsInvocation`.
`kJsInvocationSiteLimit` and `kJsInvocationArgumentLimit` are 8 and
`kJsInvocationDigestByteLimit` is 1 MiB. V8 pulls the epoch (0 means
inactive) and the sites when the epoch changes. `enabled(epoch, slot)` runs
before anything is allocated for the call. `digests(epoch)` reports the
session's opt-in. `start` and `settle` run synchronously on the isolate thread
and must not execute JavaScript, allocate V8 objects, block or perform I/O.
`GetCurrentJsInvocation` never allocates.

The current invocation is carried in the continuation-preserved embedder
data slot as an internal wrapper; `GetContinuationPreservedEmbedderData` and
its V2 form return the embedder's own value. A write through the embedder API
inside running script keeps the current invocation; a write with no script on
the stack replaces it.

## Renderer admission and loss

Blink admits a start only from a live local document context and attaches
its frame and a stable 64-bit digest of the document's `DocumentToken`. The
renderer sink rechecks the configuration generation, session, VM category and
expiry, requires the start to name its slot's configured site exactly, and
claims one of 256 starts for the configuration and one of 64 for the site.
Settles have no separate budget: each admitted call settles at most once.
Request records claim one of 256 per configuration. Records travel through
the existing 8,192-slot renderer ring and browser bridge.

| Loss | Visible as |
| --- | --- |
| Configuration budget (256 starts) exhausted | one `gap`, `native_js_invocation_budget_incomplete`, per configuration |
| A site budget (64 starts) exhausted | one `gap`, `native_js_invocation_site_budget_incomplete`, per configuration |
| Request budget (256) exhausted | one `gap`, `native_js_invocation_request_budget_incomplete`, per configuration |
| Emitter rejected an admitted record | one `gap`, `native_js_invocation_transport_unavailable`, per configuration |
| Record invalid, site mismatch, digest without the opt-in, or context is not a live document | one `gap`, `native_js_invocation_input_unavailable`, per configuration |
| Settle job ran after its document went away | one `gap`, `native_js_invocation_settle_unavailable`, per configuration |
| Function compiled before arming | one `gap`, `native_js_invocation_site_<n>_compiled_before_arming`, per configuration and slot |
| Generator, constructor or initializer at the site | one `gap`, `native_js_invocation_site_<n>_unsupported_function`, per configuration and slot |
| Renderer ring full | the ring's existing drop counter |

Gaps are `vm` category events whose payload is the reason text.

## Wire contract

All three events are category `vm`, envelope protocol 3, with a 128-byte
little-endian version-1 payload. `session_id`, `sequence_number`,
`monotonic_time_ns`, `process_id` and `thread_id` are nonzero;
`artifact_id`, `parent_event_id`, `navigation_id` and `flags` are zero. The
renderer does not know the browser's numeric navigation ID; the document a
call ran in is the payload's `document_id`. Wide identities are decimal
strings in JSON. Event numbers 24 to 26 follow 22 and 23, which the
request-body capture contract takes; renumbering never changes a layout.

### `js_invocation_start` (24)

`frame_id` is nonzero and `request_id` is zero.

| Offset | Field | Type | Rule |
| --- | --- | --- | --- |
| 0 | version (1) | u16 | |
| 2 | size (128) | u16 | |
| 4 | site slot | u8 | 0 to 7 |
| 5 | flags | u8 | bit 0 parent unknown, bit 1 arguments truncated; other bits zero |
| 6 | argument count | u16 | actual arguments excluding the receiver, saturating at 65535; bit 1 is set exactly when it exceeds 8 |
| 8 | script ID | u32 | nonzero V8 script ID, scoped to the renderer isolate |
| 12 | anchor offset | u32 | UTF-16, below source length |
| 16 | source length | u32 | UTF-16, nonzero |
| 20 | invocation ID | u32 | nonzero, never reused in the isolate |
| 24 | parent invocation ID | u32 | the invocation current at entry, or 0; below the invocation ID; 0 with bit 0 |
| 28 | site sample index | u16 | below 64 |
| 30 | sample index | u16 | below 256 |
| 32 | argument kinds | 8 x u8 | for each described argument 1 to 14; zero beyond the count |
| 40 | argument low bits | 8 x u32 | integer: low 32 bits; boolean: 0 or 1; otherwise and beyond the count 0 |
| 72 | source SHA-256 | 32 bytes | the armed site's key |
| 104 | document ID | u64 | nonzero digest of the DocumentToken |
| 112 | reserved, all zero | 16 bytes | |

Value kinds: 1 integer, 2 non-integer number, 3 string, 4 symbol,
5 undefined, 6 null, 7 boolean, 8 BigInt, 9 other object, 10 function,
11 array, 12 `ArrayBuffer`, 13 typed array or `DataView`, 14 promise.

### `js_invocation_settle` (25)

`frame_id` is nonzero and `request_id` is zero.

| Offset | Field | Type | Rule |
| --- | --- | --- | --- |
| 0 | version (1) | u16 | |
| 2 | size (128) | u16 | |
| 4 | site slot | u8 | 0 to 7 |
| 5 | outcome | u8 | 1 fulfilled, 2 rejected |
| 6 | via | u8 | 1 synchronous return (fulfilled only), 2 synchronous throw (rejected only), 3 the native promise the caller received |
| 7 | value kind | u8 | 1 to 14 |
| 8 | invocation ID | u32 | nonzero |
| 12 | value length | u32 | string: UTF-16 length; array: element count; available bytes: byte length; other kinds 0 |
| 16 | digest state | u8 | 0 not requested, 1 present, 2 not digestible, 3 too large, 4 unavailable |
| 17 | digest encoding | u8 | with state 1: 1 UTF-8 for a string, 2 raw bytes for an `ArrayBuffer` or view; otherwise 0 |
| 18 | flags | u8 | bit 0 lossy UTF-8 (a lone surrogate became U+FFFD), strings only |
| 19 | reserved | u8 | zero |
| 20 | digest byte length | u32 | with state 1: encoded bytes hashed, at most 1 MiB; at least the UTF-16 length for a string, equal to the value length for bytes |
| 24 | rolling hash | u64 | with state 1: `h = h * 0x100000001b3 + byte` modulo 2^64 over those bytes |
| 32 | value SHA-256 | 32 bytes | with state 1 only; otherwise zero |
| 64 | document ID | u64 | nonzero |
| 72 | reserved, all zero | 56 bytes | |

State 2 never applies to a fulfilled string or bytes; state 3 applies only to
a fulfilled string or bytes; state 4 only to fulfilled bytes that are
detached, shared or variable-length. A rejection is never digested. Without
the opt-in the state is 0 and every digest field is zero.

### `js_invocation_request` (26)

`request_id` is the renderer request ID (nonzero, below 2^32) that the
`request_initiated` record written immediately before carries. `frame_id` may
be zero.

| Offset | Field | Type | Rule |
| --- | --- | --- | --- |
| 0 | version (1) | u16 | |
| 2 | size (128) | u16 | |
| 4 | state | u8 | 2 inside the invocation, 3 unknown |
| 5 | reserved | 3 bytes | zero |
| 8 | invocation ID | u32 | nonzero exactly with state 2 |
| 12 | sample index | u16 | below 256 |
| 14 | reserved | u16 | zero |
| 16 | reserved, all zero | 112 bytes | |

Only two cases are recorded: a request started by script while an
invocation was current (2), and a request started with no script on the stack
while at least one admitted invocation of the configuration had not settled
(3). A request started by script outside any invocation produces no record.

### Invocation context of Wasm records

A consumer record carries `js_invocation_state` (u8: 0 not observed, 1 none,
2 inside, 3 unknown), 3 zero bytes and `js_invocation_id` (u32, nonzero
exactly with state 2):

| Event | Version | Context bytes | Reserved after |
| --- | --- | --- | --- |
| `wasm_dispatch_observation` (17) | 2 | 24..32 | 32..128 |
| `wasm_indirect_observation` (20) | 2 | 32..40 | 40..128 |
| `wasm_guest_invocation` (19) | 4 | 84..92 | 92..128 |

Earlier versions reserved those bytes and still decode, as not observed.
Guest dispatch records stay version 1; each names its guest invocation, which
carries the context. VM Lab rows show the context as
`js_invocation: {state, invocation_id}` and omit it when not observed.
`none` and `unknown` are coverage limits, not evidence that the work is
unrelated to an invocation.

## Identity and relations

An invocation is `(session_id, process_id, invocation_id)`. The broker's
origin-trace index draws two observed edges from those exact keys and never
from time:

- `issued_during_invocation`: from the renderer's `request_initiated` record
  to the start record, when a `js_invocation_request` with state 2 names the
  same session, process and request ID;
- `invocation_settlement`: from a settle record to the start record of the
  same invocation.

A reused key, an evicted start or an unknown request draws no edge. At trace
time, where identity ends at the renderer's request record, Origin Trace adds
an `invocation_value_flow` step, counted as a correlated link, only when
exactly one settle record of the same session and renderer process, earlier in
that process's sequence and with a present digest, has a body window of
exactly its digested length whose rolling hash and SHA-256 both match. Two
matches are the gap `value_flow_ambiguous`; a search past 16 MiB of hashed
windows is `value_flow_unsearched`. Only the stated encoding is matched: a
percent-encoded, escaped or encrypted copy is not found and is not reported as
a negative. The body is the request-body capture contract's sensitive
`request_body` artifact (capture origin `network_request`) whose creator is
the traced request's `request_body` child record, read only when its size and
SHA-256 match the manifest. Until that contract is merged no such record
exists, so the join has no input and reports nothing.

## Validation boundary

`include/reb/js_invocation.hpp` is the core encoder, decoder and validator;
the overlay's `common/native_js_invocation.h` is the renderer copy.
`tests/js_invocation_test.cpp` sets every field through both copies, requires
identical bytes and checks every rule, the Wasm context versions and the
rolling hash reference (`"abc"` is `0x014a08000118b972`). The broker,
`tools/validate-evidence-store.py`, the Rust backend, the shipped viewer and
the native app's Swift trace builder apply the same rules.
`tools/check-native-js-invocation.py` drives authored records through the
real broker and backend; `origin-trace-invocation-cases.json` is shared by
the Rust and Swift trace builders; the portable admission suite drives the
real renderer sink; and the `RebNativeJsInvocation*` cctests run in the native
V8 runtime workflow. None of these is a rebuilt-Brave run.
