# Native JavaScript dispatch observations v1

This path instruments Brave/V8 bytecode generation directly. There is no CDP,
page JavaScript, debugger, or caller-fed sampler. The design review, including
why each limit below exists, is
[native JavaScript dispatch-site probe v1](../docs/product/native-js-dispatch-v1.md).

## Enablement

Rebuild Brave with the tracked V8 patch `0010`, Chromium patch `0020` and the
overlay. Launch a native live session with
`REB_NATIVE_JS_DISPATCH_SITES=/absolute/path/sites.json`. The launcher adds
`--js-flags=--reb-js-dispatch-capture` and
`--reb-js-dispatch-sites=/absolute/path/sites.json`. The category mask must
include VM (512). The site file is read once per session, must be identical
for the browser lifetime, and changing it needs a browser restart. The flag
alone arms nothing, and the file alone emits nothing.

While the V8 flag is set, V8 neither consumes nor produces code caches, the
in-memory compilation cache, script streaming and the lazy compile dispatcher
are off, and source positions are recorded eagerly. Functions that contain an
armed site are never optimized. This mode is not performance-neutral.
Workers, worklets and service workers are unsupported.

## Site file

`native-js-dispatch-sites-v1` is exact compact canonical JSON (keys sorted,
no whitespace, no trailing newline), at most 4096 bytes, validated by
[the schema](native-js-dispatch-sites-v1.schema.json):

```json
{"sites":[{"anchor_offset":120,"artifact_id":"12","artifact_sha256":"<64 lowercase hex>","byte_offset":118,"shape":"switch","source_length":456,"source_sha256":"<64 lowercase hex>"}],"version":1}
```

- 1 to 8 sites, each `(source_sha256, anchor_offset)` unique.
- `shape` is `switch` or `indexed-call`.
- `source_sha256` is SHA-256 over the script text as UTF-16LE code units.
  The text is the artifact decoded as strict UTF-8 with one leading U+FEFF
  removed. `source_length` is its length in UTF-16 code units and
  `anchor_offset < source_length` is the UTF-16 offset of the `switch`
  keyword or of the `[` that opens the callee's computed member.
- `artifact_id`, `artifact_sha256` (raw artifact bytes) and `byte_offset`
  (the static site's UTF-8 `location.byte_offset`) record where the site came
  from. The browser validates their format and does not use them for matching.

The analyzer writes this file from static interpreter-candidate sites. Only
`switch` and `indexed call` sites can be armed; see the review for the shapes
that are refused and why.

The browser sends the renderer only fixed 44-byte site records
(little-endian): `source_sha256` (32 bytes), `source_length` (u32),
`anchor_offset` (u32), `shape` (u8, 1 switch, 2 indexed call) and 3 zero
bytes. The renderer never parses JSON.

## V8 embedder interface

`include/v8-callbacks.h` and `include/v8-isolate.h` gain
`v8::JsDispatchSite`, `v8::JsDispatchObservation`, `v8::JsDispatchCallbacks`
and `Isolate::SetJsDispatchCallbacks`. V8 pulls the embedder epoch (0 means
inactive) at bytecode generation and before each trace, and pulls the armed
sites when the epoch changes. `enabled(epoch, slot)` runs before any frame
walk or handle and must not allocate or call into V8. `observe` and `status`
run synchronously on the isolate thread and must not execute JavaScript,
allocate V8 objects, block or perform I/O. `kJsDispatchSiteLimit` is 8.

## Renderer admission and loss

Blink admits an observation only from a live local document context and
attaches its frame identity. The renderer sink rechecks the configuration
generation, session, VM category and expiry, then claims one of 256 samples
for the configuration and one of 64 for the site. Records travel through the
existing 8,192-slot renderer ring and browser bridge.

| Loss | Visible as |
| --- | --- |
| Configuration budget (256) exhausted | one `gap`, `native_js_dispatch_budget_incomplete`, per configuration |
| A site budget (64) exhausted | one `gap`, `native_js_dispatch_site_budget_incomplete`, per configuration |
| Emitter rejected an admitted record | one `gap`, `native_js_dispatch_transport_unavailable`, per configuration |
| Record invalid, or context is not a live document | one `gap`, `native_js_dispatch_input_unavailable`, per configuration |
| Armed after its function was compiled | one `gap`, `native_js_dispatch_site_<n>_compiled_before_arming` (`n` is the slot, 0 to 7), per configuration and slot |
| Renderer ring full | the ring's existing drop counter |

Gaps are `vm` category events whose payload is the reason text.

## Wire contract

Event type `js_dispatch_observation` (numeric 21), category `vm`, envelope
protocol 3. `session_id`, `sequence_number`, `monotonic_time_ns`, `process_id`,
`thread_id` and `frame_id` are nonzero. `artifact_id`, `parent_event_id`,
`navigation_id`, `request_id` and `flags` are zero; `tab_id` may be set by the
browser bridge. Wide identities are decimal strings in JSON.

The payload is exactly 128 bytes, little-endian, version 1:

| Offset | Field | Type | Rule |
| --- | --- | --- | --- |
| 0 | version (1) | u16 | |
| 2 | size (128) | u16 | |
| 4 | shape | u8 | 1 switch, 2 indexed call |
| 5 | selector kind | u8 | 1 integer, 2 non-integer number, 3 string, 4 symbol, 5 undefined, 6 null, 7 boolean, 8 BigInt, 9 object |
| 6 | site slot | u8 | 0 to 7, index in the site file |
| 7 | flags | u8 | bit 0 new activation, bit 1 parent unknown, bit 2 parent search truncated, bit 3 handler span present; other bits zero |
| 8 | script ID | u32 | nonzero V8 script ID, scoped to the renderer process isolate |
| 12 | anchor offset | u32 | UTF-16, below source length |
| 16 | source length | u32 | UTF-16, nonzero |
| 20 | selector low 32 bits | u32 | integer: low 32 bits of the two's-complement value; boolean: 0 or 1; otherwise 0 |
| 24 | handler script ID | u32 | nonzero only with flag bit 3 |
| 28 | handler start | u32 | UTF-16 source position, with flag bit 3 |
| 32 | handler end | u32 | above handler start, with flag bit 3 |
| 36 | activation ID | u32 | nonzero |
| 40 | parent activation ID | u32 | 0 when none; nonzero only below the activation ID and without flag bits 1 and 2 |
| 44 | site sample index | u16 | below 64 |
| 46 | configuration sample index | u16 | below 256 |
| 48 | source SHA-256 | 32 bytes | the armed site's key |
| 80 | reserved, all zero | 48 bytes | |

A `switch` record has no handler span. An `indexed call` record has a handler
span only when the callee is a JavaScript function with a script. Selector
contents beyond these bits, arguments, receivers and string contents are never
copied. Unknown versions, sizes, enum values, flag bits, nonzero reserved bytes
and inconsistent fields are rejected consistently by C++, Rust and
JavaScript.

## Identity

The record names a site by `(source_sha256, source_length, anchor_offset,
shape)`, the same key as the site file. The analyzer joins it to a captured
JavaScript artifact whose decoded text has that key, and to the static site
whose JavaScript anchor maps to that UTF-16 offset. Activation IDs are scoped
to one renderer process isolate; a parent is the nearest enclosing armed
frame at the child's first admitted dispatch and only when that frame has
already dispatched in the same configuration.

## Validation boundary

`include/reb/js_dispatch.hpp` is the core encoder, decoder and validator; the
overlay's `common/native_js_dispatch.h` is the renderer copy. The broker,
`tools/validate-evidence-store.py` and the evidence package accept the event
only through these rules; an exported package keeps its metadata, never the
selector bits, handler span or source key. `make native-tests` runs
`tests/js_dispatch_test.cpp`, which sets every field through both copies and
requires identical bytes, then checks every validation rule.

`build/reb-native-js-dispatch-golden --case <mode>` emits one event through the
overlay encoder and the core JSON writer. Its valid cases name the owned fixture
[`tools/fixtures/native-js-dispatch/two-level-vm.js`](../tools/fixtures/native-js-dispatch/README.md),
an outer `switch` interpreter whose handler runs an inner `ops[code[pc++]](s)`
interpreter, with the fixture's real key and anchors. These are authored
records: they prove that the producers and readers agree, not that a rebuilt
Brave emitted them. Live acceptance needs the pinned replay, the V8 cctests and
a rebuilt Brave run on that fixture.
