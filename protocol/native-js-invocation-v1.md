# Native JavaScript invocation observations v1

A call of an armed JavaScript function gets an identity that V8 assigns at
entry and carries across the call's awaits and promise jobs. There is no CDP,
page JavaScript or debugger. The reviewed design, including why each rule and
limit below exists, is
[native JavaScript invocation identity v1](../docs/product/native-js-invocation-v1.md).

## Enablement

Rebuild Brave with V8 patches `0011`, `0023`, `0024` and `0025`, Chromium
patches `0021`, `0066` and `0067` and the overlay.
Launch a native live session with
`REB_NATIVE_JS_INVOCATION_SITES=/absolute/path/sites.json`. The launcher adds
`--js-flags=--reb-js-invocation-capture` and
`--reb-js-invocation-sites=/absolute/path/sites.json`. The category mask must
include VM (512); request records also need Network (256). The browser reads
the site file when the session starts. Records name sites by slot, so a slot
keeps its site for the browser's lifetime: a file that renumbers a slot the
browser has sent refuses the session, while armed flags and appended slots
may change. With `REB_NATIVE_JS_INVOCATION_LIVE=1` the running capture also
follows later versions of the file; see [Revisions](#revisions). The flag
alone arms nothing, and the file alone emits nothing.

`REB_NATIVE_JS_INVOCATION_DIGESTS=1` additionally passes
`--reb-js-invocation-digests`, the session's sensitive opt-in for
settled-value digests. The launcher accepts it only with a site file and
prints a sensitive-capture label. Without it every settle record says
`digest_state: not_requested`.

Captures the packaged app starts arm its saved site set
(`js-invocation-sites-v1.json` in Application Support, version 1 of the format
below) from a private per-launch copy, an empty version 2 slot table when
nothing is saved, with digests on in Content mode and off in Metadata mode; an
explicit environment value wins. They set `REB_NATIVE_JS_INVOCATION_LIVE=1`,
so the capture follows the saved set, and
`REB_NATIVE_JS_INVOCATION_IF_SUPPORTED=1`: if the Brave's V8 image does not
define `reb_js_invocation_capture`, the launcher starts the session without
the sites and digests and prints `JavaScript invocation tracking:
unavailable`, instead of refusing the session. Without that switch a missing
flag still refuses the session. Agent-started sessions arm sites only from the
named options `js_invocation_sites` or `js_invocation_saved_sites` (their own
saved set, never the app's, even when empty), from a private copy and without
that switch; only `js_invocation_saved_sites` follows its set while the
session runs. Digests need `js_invocation_digests`. See
[live session control](http-api.md#live-session-control). The
routes that resolve and save sites are in
[the HTTP API](http-api.md#saved-javascript-invocation-sites).

`--reb-js-invocation-capture` implies `--reb-js-dispatch-capture`, so the
compile-path settings of
[JavaScript dispatch capture](native-js-dispatch-v1.md#enablement) apply: a
script that an armed invocation or dispatch site names compiles on the main
thread without a code cache or the compilation cache and with eager source
positions, and every other script compiles as usual.
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
refuses any other character. The backend computes the same key when Origin
Trace saves a site by name or position; both check
`tools/fixtures/native-js-invocation/site-cases.json`.

Version 2 is a slot table of 0 to 256 entries, each with an `armed` boolean,
in the same canonical form with sorted keys:

```json
{"sites":[{"anchor_offset":120,"armed":false,"artifact_id":"12","artifact_sha256":"<64 lowercase hex>","byte_offset":118,"shape":"function-entry","source_length":456,"source_sha256":"<64 lowercase hex>"}],"version":2}
```

Entry n is slot n. A disarmed slot keeps its site so later slots are not
renumbered; it records no new call. Version 1 is a slot table whose 1 to 256
entries are all armed. The backend writes version 2 when it revises a
following capture's file; the app's empty set starts as
`{"sites":[],"version":2}`.

The browser sends the renderer only fixed 44-byte records: `source_sha256`
(32 bytes), `source_length` (u32), `anchor_offset` (u32), shape byte 3, a
flags byte whose bit 0 means disarmed, and 2 zero bytes. Any other flag bit,
a dispatch record (shape 1 or 2) here, or a function-entry record as a
dispatch site is refused. A null record array means the session tracks no
invocations; an empty one means it tracks with no slot yet.

Generators, async generators, class constructors and class initializer
functions are never armed; see the design for why.

## Revisions

A capture launched with `REB_NATIVE_JS_INVOCATION_LIVE=1` follows the saved
set while it runs. The launcher first looks for the help text `armed sites
revisable while running` of `reb_js_invocation_capture` in the Brave's V8
image. A Brave without it keeps the startup sites and the launcher prints that
saved functions apply from the next capture; an empty slot table, which such a
Brave would refuse, then arms nothing. Otherwise the launcher creates
`js-invocation-sites-generation` (decimal `0`) in the session directory and
passes it to Brave as `--reb-js-invocation-sites-generation` and to the
backend as `--js-invocation-session-generation`.

Whenever the backend reads the saved set, it compares it with the capture's
slot table. A removed site is disarmed in its slot, a saved one is armed
again in its slot, and a new one takes the next slot; a site saved after all
256 slots are used waits for the next capture and its saved entry says
`armed_in_capture: false`. The backend replaces the site file with the new
slot table and then the generation file with the next decimal, each by an
atomic rename, so Brave never applies a generation without its table. A
write that fails keeps the capture's table, reports `revision_error`, and is
retried at the next listing.

Brave's broker writer reads the generation on its wake of about 250 ms. A
greater one makes it reread the site file on that thread, and the browser
sequence sends the table to every renderer of the session
(`UpdateJsInvocationSites`); a renderer that starts later is configured with
it. A table that renumbers a slot or is invalid is refused with one
`native_js_invocation_sites_revision_refused` gap and the capture keeps its
previous table. The renderer applies a table within its configuration:
retained slots keep their site, ordinals and open calls and take the new
armed flag, an omitted slot is disarmed, new slots are appended, and a
revision counter advances. A table that renumbers a slot or is malformed is
refused with the configuration's `native_js_invocation_input_unavailable` gap.

V8 reads the counter through `JsInvocationCallbacks::revision` at its next
sync and copies the sites again without ending the epoch, so a call that
started before a revision settles after it and keeps its invocation ID. A
function compiled while its slot was armed records again when the slot is
re-armed, without recompiling. A function compiled while its slot was
disarmed or did not exist reports `compiled_before_arming`; it gains tracking
when its page reloads, because a script an armed site names skips the code
cache and the compilation cache.

## V8 embedder interface

`include/v8-callbacks.h` and `include/v8-isolate.h` gain
`v8::JsInvocationSite`, `JsInvocationStart`, `JsInvocationSettle`,
`JsInvocationContext`, `JsInvocationCallbacks`,
`Isolate::SetJsInvocationCallbacks` and `Isolate::GetCurrentJsInvocation`.
`kJsInvocationSiteLimit` is 256 (8 before patch `0023`), the most slots the
records' one-byte site slot can name; `kJsInvocationArgumentLimit` is 8 and
`kJsInvocationDigestByteLimit` is 1 MiB. V8 pulls the epoch (0 means
inactive) and the sites when the epoch changes, or when the optional
`revision(epoch)` changes: then it copies the sites again and keeps the
epoch's invocation IDs, so a call in flight settles under the new sites. A
slot copied with `source_length` 0 is disarmed. `enabled(epoch, slot)` runs
before anything is allocated for the call. `digests(epoch)` reports the
session's opt-in. `start` returns whether the embedder recorded the call; V8
wraps, carries and settles only a recorded call, so every recorded start has
exactly one settle or a `settle_unavailable` gap and no other call does.
`start` and `settle` run synchronously on the isolate thread and must not
execute JavaScript, allocate V8 objects, block or perform I/O.
`GetCurrentJsInvocation` never allocates. Invocation IDs are never reused in
an isolate; after 2^30 - 1 of them V8 stops reporting calls and reports the
`ids_exhausted` site status once per configuration and slot.

The current invocation is carried in the continuation-preserved embedder
data slot as an internal wrapper; `GetContinuationPreservedEmbedderData` and
its V2 form return the embedder's own value. A write through the embedder API
inside running script keeps the current invocation; a write with no script on
the stack replaces it.

## Renderer admission and loss

Blink admits a start only from a live local document context and attaches
its frame and a stable 64-bit digest of the document's `DocumentToken`. The
renderer sink rechecks the configuration generation, session, VM category and
expiry and requires the start to name its slot's configured site exactly.
Every call of every armed site is then recorded: there is no count per site
or per configuration. Each recorded start takes its site's next ordinal,
from 0 in each configuration, so a start the full ring dropped is a missing
ordinal beside the ring's drop count; a start refused as input takes none.
A start that is refused or dropped is not recorded, so V8 neither carries nor
settles that call and it never counts as open.
A gap the ring could not take is held and written before the next start or
settle record once the ring has room, or when the configuration ends; the
ring's drop counter covers it until then.
The renderer counts recorded starts that have not settled, so a loader start
outside script is reported as unknown only while one may be open. A settle
closes its start even when the settle record itself is refused, dropped or
unavailable. Request records take the configuration's next request ordinal
the same way. Records travel through the existing 8,192-slot renderer ring
and browser bridge; per-record work is a fixed-size encode and one ring
write, and none allocates.

| Loss | Visible as |
| --- | --- |
| V8 used every invocation ID of the isolate | one `gap`, `native_js_invocation_ids_exhausted`, per configuration |
| Emitter rejected an admitted record | one `gap`, `native_js_invocation_transport_unavailable`, per configuration |
| Record invalid, site mismatch, digest without the opt-in, or context is not a live document | one `gap`, `native_js_invocation_input_unavailable`, per configuration |
| Settle job ran after its document went away | one `gap`, `native_js_invocation_settle_unavailable`, per configuration |
| Function compiled before arming | one `gap`, `native_js_invocation_site_<n>_compiled_before_arming`, per configuration and slot |
| Generator, constructor or initializer at the site | one `gap`, `native_js_invocation_site_<n>_unsupported_function`, per configuration and slot |
| Renderer ring full | the ring's existing drop counter, and a missing site or request ordinal |
| Browser refused a site revision that renumbers a slot or is invalid | one `gap`, `native_js_invocation_sites_revision_refused`, per refused revision; the capture keeps its table |
| Renderer refused a site revision | one `gap`, `native_js_invocation_input_unavailable`, per configuration |

Gaps are `vm` category events whose payload is the reason text. Version 1
records came from builds with budgets: those builds also wrote
`native_js_invocation_budget_incomplete`,
`native_js_invocation_site_budget_incomplete` and
`native_js_invocation_request_budget_incomplete`, which consumers still
name.

## Wire contract

All three events are category `vm`, envelope protocol 3, with a 128-byte
little-endian version 2 payload. `session_id`, `sequence_number`,
`monotonic_time_ns`, `process_id` and `thread_id` are nonzero;
`artifact_id`, `parent_event_id`, `navigation_id` and `flags` are zero. The
renderer does not know the browser's numeric navigation ID; the document a
call ran in is the payload's `document_id`. Wide identities are decimal
strings in JSON. Event numbers 24 to 26 follow 22 `request_body` and 23
`request_target` of [native network v2](native-network-v2.md); renumbering
never changes a layout.

### `js_invocation_start` (24)

`frame_id` is nonzero and `request_id` is zero.

| Offset | Field | Type | Rule |
| --- | --- | --- | --- |
| 0 | version (2) | u16 | |
| 2 | size (128) | u16 | |
| 4 | site slot | u8 | 0 to 255, below the armed site count |
| 5 | flags | u8 | bit 0 parent unknown, bit 1 arguments truncated; other bits zero |
| 6 | argument count | u16 | actual arguments excluding the receiver, saturating at 65535; bit 1 is set exactly when it exceeds 8 |
| 8 | script ID | u32 | nonzero V8 script ID, scoped to the renderer isolate |
| 12 | anchor offset | u32 | UTF-16, below source length |
| 16 | source length | u32 | UTF-16, nonzero |
| 20 | invocation ID | u32 | nonzero, never reused in the isolate |
| 24 | parent invocation ID | u32 | the invocation current at entry, or 0; below the invocation ID; 0 with bit 0 |
| 28 | site ordinal | u32 | this start's ordinal among its site's starts in the configuration |
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
| 0 | version (2) | u16 | |
| 2 | size (128) | u16 | |
| 4 | site slot | u8 | 0 to 255, below the armed site count |
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
| 0 | version (2) | u16 | |
| 2 | size (128) | u16 | |
| 4 | state | u8 | 2 inside the invocation, 3 unknown |
| 5 | reserved | 3 bytes | zero |
| 8 | invocation ID | u32 | nonzero exactly with state 2 |
| 12 | ordinal | u32 | this record's ordinal among the configuration's request records |
| 16 | reserved, all zero | 112 bytes | |

Only two cases are recorded: a request started by script while an
invocation was current (2), and a request started with no script on the stack
while at least one recorded invocation of the configuration had not settled
(3). A request started by script outside any invocation produces no record.

### Version 1 records

Builds before V8 patch `0023` and Chromium patch `0066` wrote version 1. It
has the same layout except: the site slot is 0 to 7; start bytes 28..30 are a
u16 site sample index below 64 and bytes 30..32 a u16 sample index below 256;
request bytes 12..14 are a u16 sample index below 256 and bytes 14..16 are
zero. Every consumer still reads version 1 with those rules. The event query
reports a version 1 start's site sample index as `site_sample_index` and its
sample index as `sample_index`; a version 2 start reports its site ordinal as
`site_sample_index` and `sample_index` as null.

### Invocation context of Wasm records

A consumer record carries `js_invocation_state` (u8: 0 not observed, 1 none,
2 inside, 3 unknown), 3 zero bytes and `js_invocation_id` (u32, nonzero
exactly with state 2):

| Event | Version | Context bytes | Reserved after |
| --- | --- | --- | --- |
| `wasm_dispatch_observation` (17) | 2 | 24..32 | 32..128 |
| `wasm_dispatch_observation` (17) | 3 | 24..32 | 40..128 |
| `wasm_indirect_observation` (20) | 2 | 32..40 | 40..128 |
| `wasm_guest_invocation` (19) | 4 | 84..92 | 92..128 |

Dispatch payload version 3 keeps the invocation context at 24..32 and uses
32..40 for the direct caller. See
[native Wasm dispatch](native-wasm-dispatch-v1.md). Earlier versions reserved
those bytes and still decode, as not observed.
`wasm_dispatch_overflow` (28) and `wasm_indirect_overflow` (29) do not carry
this context or a caller. They name an execution a budget refused and are not
observations.
Guest dispatch records stay version 1; each names its guest invocation, which
carries the context. VM Lab rows show the context as
`js_invocation: {state, invocation_id}` and omit it when not observed.
`none` and `unknown` are coverage limits, not evidence that the work is
unrelated to an invocation.

### Event queries

`get_events` and `wait_for_events` leave each record's `payload` as the
128-byte hex and add `js_invocation` beside it: `kind` `start`, `settle` or
`request` with that record's fields, or `{status: invalid}` with no fields for
a record any rule above refuses. Value kinds, `via` and the digest state are
named. A settle's digest is never decoded. A start's `site_slot`,
`source_sha256` and `anchor_offset` match one entry of the site file the
session armed, which `get_js_invocation_sites` lists with its label. The field
map is in [the HTTP API](http-api.md#filtered-and-paged-reads).

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
a negative. The body is the sensitive `request_body` artifact of
[native network v2](native-network-v2.md) (capture origin `network_request`)
whose creator is the traced request's `request_body` child record, read only
when its size and SHA-256 match the manifest. It exists only under request
content capture (`REB_CAPTURE_REQUEST_CONTENT=1`) and holds at most the first
16 MiB of the body. The join reads a body only when it is at most 1 MiB
(`REQUEST_BODY_LIMIT` in `apps/origin-trace-backend/src/origin_trace.rs`).
Without a retained body, or past that size, the join has no input and reports
nothing.

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
