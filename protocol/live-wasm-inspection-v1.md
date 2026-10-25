# Live Wasm inspection v1

The existing `POST /api/debugger/actions` surface adds
`list_live_wasm_objects` and `read_live_wasm_memory`. These are explicit,
effectful operations in an attached, navigated **disposable Object Lab page**,
not retained-artifact reads or an extension of captured-document execution.
Create the disposable experiment and navigate it through existing actions first.
Both operations require its exact `target_id`. Baseline tabs are refused.

## Listing and ownership

`list_live_wasm_objects` queries the default realm's WebAssembly Instance,
Module and Memory prototypes rather than scanning properties of every object.
The response's `wasm` contains `listing_id`, `target_id`, `document_epoch`,
`objects`, and per-kind `coverage`. Each object has an opaque listing-local `id`
and `kind` (`instance`, `module`, `memory`). These are prototype-based candidates:
changed prototypes/built-ins can affect discovery; a memory read performs the
WebAssembly Memory getter's brand check when built-ins are unchanged.

At most 32 objects per kind survive the query. The renderer's `queryObjects`
step itself can temporarily materialize all matching objects and trigger GC; it
is not a bounded heap scan. Commands have deadlines, but a timeout cannot undo
renderer work. Other realms/workers and objects with changed prototypes are not
covered. Results report truncation, not a global inventory claim.

Only one listing is retained. Refreshing it releases its old group. All handles
expire after 60 seconds, even if no further request arrives. Target replacement,
connection replacement, navigation/document epoch drift, and expired or
superseded listings are rejected rather than rebound. Actions use the existing
serialized debugger action and ownership guards. Handles retain objects and may
affect garbage collection until released. A failed or timed-out group release
retires the owned debugger transport rather than accumulating remote roots or
retrying an uncertain cleanup command. The release outcome and remote retention
remain uncertain until disconnect completes. Only the exact old handle-owning
transport is stopped, never the browser or a replacement debugger connection.

CDP prototype queries provide no proven module-to-script/artifact identity.
`script_id` and `artifact_id` are therefore null and linkage is `unavailable`.
URLs, constructor names, static exports, and retained bytecode are not proof of
live instance ownership. Artifact-ID-only memory reads are not supported.

## Memory slices

`read_live_wasm_memory` requires `target_id`, `listing_id`, `object_id`,
`offset`, `length` (1–4096), and `confirmed: true`. For an Instance also supply
its explicit memory `export_name`; for a Memory omit it. A Module is compiled
code, not a live memory, and cannot be read. Missing/non-memory exports fail.
Offsets are safe nonnegative integers and the entire slice must fit the current
buffer. No implicit clipping occurs.

The `memory` result includes exact byte values (0–255), offset, length, observed
buffer byte length, `shared`, and `atomic: false`. Growth and shared-memory
writes can race a read. No causal attribution, Wasm instruction trace, atomic
snapshot, or fidelity to a previous read is claimed. Bytes remain in the
explicit response only, not debugger snapshots, artifacts or logs. Treat them
as potentially sensitive and review before sharing.

The helper runs target-side JavaScript and calls WebAssembly/Object/Reflect and
typed-array built-ins. It does not invoke arbitrary export functions or export
property accessors, but replaced built-ins can execute target code. Effects
metadata retains code-execution/browser-control and downstream network
uncertainty; neither operation becomes a read-only MCP tool.

## Heap ingest and Memory Origin Trace

The native analyzer accepts V8's node/edge metadata and does not assume JSON
member ordering. Unpaired UTF-16 code units are displayed as U+FFFD and set
`string_limit_reached` to disclose lost text fidelity; stored capture bytes are
unchanged. Valid surrogate pairs remain exact UTF-8. Errors distinguish malformed
JSON (with byte offsets), unsupported/missing metadata, inconsistent counts,
empty captures, 8 MiB chunk/256 MiB capture bounds, and event loss. Connection or
document changes invalidate capture. Event loss refuses analysis of a possibly
incomplete snapshot; it does not silently retry or increase transport bounds.

Memory Origin Trace arms a click breakpoint then samples at supported JavaScript
function boundaries. It is not an allocation hook or a Wasm-instruction sampler.
Zero steps means no supported pause was observed, including a page that has no
click or only Wasm activity. Direct bounded slices do not require a click.

Validation uses authored layouts, a fresh local Node/V8 heap snapshot, actual
Node inspector queries, and the owned localhost browser fixture. Node inspector
checks are not Chromium/Brave attach acceptance.
