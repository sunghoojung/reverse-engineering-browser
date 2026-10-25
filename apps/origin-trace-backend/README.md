# Origin Trace Rust backend

This crate owns Origin Trace's loopback HTTP API, durable workspaces, analysis
adapters, and live CDP session orchestration. The macOS application bundles the
backend and VM analyzer as native executables. Neither the live session nor
browser development server requires Python. Native probes, the evidence broker,
artifact receiver, debugger transport, decoder, and heap analyzer remain C++.

```sh
make origin-trace-backend
make ui
apps/origin-trace-backend/target/debug/reb-api list
apps/origin-trace-backend/target/debug/reb-api mcp --endpoint-file /tmp/reb-api-endpoint
make backend-e2e
```

`get_session_context` (`GET /api/session/context`) is the first read for a
connected agent. It reports `live_admission`, the health `instance_id`, and
separate bounded Wasm script and artifact inventories without joining them or
returning the full debugger snapshot. MCP annotates its actual effects
admission; direct HTTP reports admission as unknown. See the
[agent guide](../../docs/development/local-coding-agents.md#start-with-compact-session-context)
for privacy omissions, inventory limits, conditional reads, and action errors.

`reb-api mcp` projects [`protocol/openapi.json`](../../protocol/openapi.json)
onto a local stdio MCP server. Tool names are the OpenAPI operation IDs. The
default list is read-only. `--allow-effects` also lists the other operations.
That flag is explicit and is not authorization, capture redaction, or
permission to send results to a model provider. `--session-dir` reads
`research-ui.endpoint` from that directory only. `/api/health` must report
`status: ok` before any tool is advertised, and the health document is not
printed. Binary responses are refused before a request. JSON larger than
the inline limit returns a structural summary and does not inline source,
bytecode, or request bodies. [`scripts/reb-api-mcp.sh`](../../scripts/reb-api-mcp.sh)
is the same-machine launcher for Cursor, Codex, Claude Code, Grok Bot, and
T3 Code. Its default and fresh configs use
`~/.config/origin-trace/reb-api.endpoint` with `--require-live`. The live launcher
publishes that private canonical alias; idle/demo startup cannot claim it.
Reconnect rereads the file instead of freezing a session directory or port.
A changed file or live backend identity retires the existing connection, never
replaying a pending action on the replacement. `--require-live` checks live
capture, a running/paused debugger, and backend identity at startup and before
tool calls; idle/unavailable states produce an endpoint-specific error with
`code=idle_backend`, `code=debugger_unavailable`, or `code=state_conflict`.
`get_session_context` stays available after that startup check until the
endpoint file or instance changes. Explicit
session selectors retain their intentional stored-evidence behavior unless
`--require-live` is added. See
[OpenAPI MCP projection](../../protocol/http-api.md#openapi-mcp-projection)
and [local coding agents](../../docs/development/local-coding-agents.md).

`backend-e2e` uses Node.js 22 or newer and a disposable browser profile. Set
`ORIGIN_TRACE_TEST_BROWSER` to a Chromium-compatible executable on other hosts.
It exercises isolation and disposal, interception, Repeater timeout, cancel, bounded response line diffs, and UI contract rejection,
Object Lab, breakpoints, heap analysis, Memory Origin Trace, page and worker
hooks, request-field comparisons, and automation through the public HTTP API.
The fixture serves only synthetic localhost content. After `make app-build`,
`node tools/check-origin-trace-launcher.mjs` verifies packaged startup and shutdown.
`make javascript-check` also runs the field-provenance projection checks without
a browser, covering exact UTF-8 handoffs, source identity, search cancellation,
chain prefixes, and bounds. These checks run in CI through `make lint`.
`cargo test` covers HTTP
contracts, locality, bounded reads, durable state conflicts, and worker shutdown.
The `origin_trace_gap` HTTP regressions cover native queue markers sharing their
anchor identity, missing anchors, repeated markers, unrelated streams, malformed
markers, genuine duplicate events, exact large IDs, and bounded coverage. The
native Swift builder runs the same synthetic cases during `make app-build`.
Shared cases also cover reused request/event identifiers across sessions, exact
large string IDs, omitted selectors, and malformed/missing session selectors.
`GET /api/origin-trace` and `reb-api call get_origin_trace` accept optional
`session_id`; concrete UI selections always send it. Unresolved cross-session
matches are explicitly ambiguous, while an absent exact match remains empty.
See [exact trace selection](../../protocol/http-api.md#exact-request-trace-selection).

## Bounded native event polling

`GET /api/events` reads at most the newest 64 MiB plus one boundary byte.
It returns independent newest general and native-network lifecycle windows,
each capped by `limit` (at most 5,000). Canvas/WebGL floods cannot take network
slots within the scanned tail. All seven lifecycle types, including redirect,
failed, and response-completed outcomes, are retained in arrival order. Older
records remain on disk, but records before the byte budget are not searched.

`event_window.scope` is `store` only when the scan includes byte zero; otherwise
it is `bounded_tail`. Counts include validated records in that declared scope,
not just displayed rows, and are **not session totals**. `sequence_gaps` sums
forward jumps of each session/process high-water mark in arrival order. Late
arrivals do not subtract earlier jumps. `queue_drops` adds canonical positive
unsigned marker payloads (one for an invalid/zero marker payload); it may overlap
sequence jumps. Both totals saturate explicitly rather than wrapping.

The polling cache verifies exact overlapping bytes, the preceding boundary byte,
and file identity before reusing record summaries. Rotation, truncation, rewrites,
and malformed/incomplete tails invalidate reuse. A complete final JSON record
without a newline is accepted but reparsed when appended. Cache waiters do not
hold any of the four shared reader permits. Work stays bounded by the tail,
not the total capture size; overlapping records avoid repeated JSON parsing.

The live native application uses this Rust endpoint. The separate Swift
stored-evidence URL-scheme reader has not yet gained these windows/counters or
this bounded cache. Its native parity and macOS build/UI acceptance remain an
explicit gate; the UI labels legacy-reader counts as visible-window-only.

The listener accepts only `127.0.0.1`, `localhost`, or `::1`; every API request
validates Host, Origin, and fetch-site headers. Static serving allowlists the
application assets explicitly. Stored identifiers and public response schemas follow
[`protocol/openapi.json`](../../protocol/openapi.json).

The native Console panel uses `src/native_console.rs` and the bundled C++
`OriginTraceNativeConsole` bridge. `REB_BRAVE_BINARY` or `--brave-binary` selects
the rebuilt custom browser; `--native-console` can override the bridge. This
separate session uses no CDP connection. It owns a temporary profile and both
process groups, validates bounded replies, and retires ambiguous exchanges. See
[Native Console v2](../../protocol/native-console-v2.md).

Each browser connection owns a native transport process, a bounded event queue,
and command deadlines. Failed domain initialization retires that connection so
the next refresh retries the complete setup. `make backend-e2e` also exercises
startup success, domain errors and timeouts, and disabled content capture using
a synthetic local CDP transport before its browser checks. Experiment actions verify browser-context ownership.
Disposal stops owned pages, workers, recipes, requests, and retained objects.
Worker cancellation terminates its process group, including descendants. Network
capture is opt-in for standalone sessions and enabled by the packaged research
profile. HTTP Traffic uses a single browser-level CDP transport with flattened
sessions, passive Target events, http(s) pages already published on the
debugger target list, and recursive attachment for page, iframe and
worker targets. `--capture-target-limit` defaults to 32 (range 1–128), covering
initializing and ready targets with stable owners. Waiting admission prefers
the oldest page, then the oldest non-page, when slots free. A full event queue
drops debugger events and keeps the browser socket open; `event_queue_drops`
records that loss separately from owner-loss gaps. The shared event budget is 64 MiB; requested browser Network
buffers share a 128 MiB aggregate budget divided across the configured limit.
The selected debugger remains separate, and the global ledger retains 1000 rows
and eight body retrieval jobs. Exact owner/session-qualified bodies cannot cross
focus switches, target replacement or reconnect. Retired owners leave retained
history and explicit unfinished-evidence gaps. A rejected duplicate-session cleanup
can also be confirmed ended by exact recorded ancestor-session detachment or
target destruction. That proof preserves unrelated owners instead of closing the
shared transport; unknown cleanup failures still retire it with a visible gap.
`network.capture_epoch` remains the focused debugger/selection identity, not the
HTTP owner token.

Supplementary HTTP target-list discovery validates the browser connection and
catalog epoch from before the list read, then admits under the catalog lock.
It retains at most 4,096 retired target IDs per connection. At that limit, list-only
recovery fails closed and coverage is visibly partial until capture reconnects;
normal browser Target events continue. No first-navigation or short-lived-page
capture guarantee is added.

Passive capture does not pause startup or guarantee the first full URL:
requests before attachment/Network.enable and very short-lived targets can
lack a debugger row. Unmatched native rows stay in the Traffic ledger as
host-only metadata.

Worker attachment can affect lifecycle/timeouts. No baseline startup-hold mode
is enabled. WebSocket v1 remains selected-target scoped. The coverage notice
identifies attached/missing target IDs, failures, overflow and gaps. Browser Target
setup failure visibly falls back to eight page-only polling connections (512 MiB
aggregate event budget, 128 MiB requested browser buffers) and retries browser
setup after 30 seconds. Independent worker/OOPIF capture is absent in fallback.
The focused debugger's transport and buffers are additional in both modes.

`tools/check-traffic-multitarget-browser.mjs` exercises real Chromium with the
native transport against synthetic loopback pages, including blank new tabs,
navigation, background fetches, focus changes and target closure; Linux CI runs
it in addition to the fault-injected HTTP/CDP lifecycle regressions. Captured Traffic values are raw by default; sensitive field selection
for disposable experiments still requires confirmation.

The API CLI embeds the versioned OpenAPI document and requires an explicit
loopback URL or endpoint file. The VM analyzer reads bounded input prefixes,
reports omissions, and writes private analysis documents. The base detector is
served at `/api/analysis/vm`; the inspector-free opcode workspace is served at
`/api/analysis/vm/opcodes`. A Wasm likely-vm workspace lists static `br_table`
and `call_indirect` arms from the selected function and a bounded call/table
neighborhood. Without dispatch samples it keeps `sampler-unavailable`. Without
a runtime snapshot it keeps `snapshot-bytes-unavailable` and names the guest-byte
walk `static-module-only` instead of inventing a program counter. A workspace
failure does not hide a valid detector
document. Its executable is
`origin-trace-vm --artifacts DIR --events FILE`.
Static guest-byte previews recognize a conservative subset of complete numeric `Uint8Array.of(...)` and
`new Uint8Array([...])` literals, `Uint8Array.from("...", c => c.charCodeAt(0))`,
`Uint8Array.fromBase64("...")`, and
`new Uint8Array(new TextEncoder().encode("..."))`. String conversion follows the
explicit constructor: character mapping truncates the first UTF-16 unit per
string-iterator element, whereas TextEncoder produces UTF-8. The preview keeps
256 bytes and hashes the full recognized initializer; its producer is always
`static-initializer`, with an original-source byte offset and truncation flag.
Malformed or noncanonical base64 may stay unavailable. Bare string constructor
arguments, variables, unresolved assignments, custom
mappers/decoders, and shadowed built-ins stay unavailable. A slash outside masked
comments or quoted strings also leaves the preview unavailable with a lexical-
ambiguity reason: this bounded recognizer does not distinguish regex literals
from division. Slashes inside supported string/base64 arguments remain valid.
Recognition reads at
most 16 MiB and examines at most 4096 constructors. It never evaluates captured
source, executes a decoder, or labels a static preview as a runtime snapshot.
A workspace with only this preview reports `static-initializer-only`; without
either preview it reports `runtime-snapshot-unavailable`.

VM documents persist exact session launch provenance from
[`capture-provenance-v1`](../../protocol/capture-provenance-v1.md). Missing metadata
stays unknown, and a current debugger connection never relabels saved findings.


The offline `origin-trace-vm-pack apply` and `compare` commands add declarative
relevance rankings or compare digest-bound workspace v2 documents. They preserve
generic evidence and uncertainty, never execute source, and write private
no-clobber reports. See [VM analysis packs v1](../../protocol/vm-analysis-pack-v1.md).
Offline `reb-api describe OPERATION --action ACTION` also exposes source-backed
advisory effects and prerequisites while retaining the operation's common
guards. See the [execution metadata contract](../../protocol/http-api.md#execution-metadata).
These annotations do not authorize execution or automatic retries.
For local Codex and Claude Code workflows, `reb-api list --json` provides offline
machine-readable discovery and `reb-api call ... --read-only` opts into a
conservative pre-dispatch effect guard. The guard rejects browser controls,
helpers, writes, multiplexed actions and unknown metadata; inert analysis POSTs
can be eligible. It is not a privacy filter or authorization grant, and CLI
`--output` still writes explicitly requested files. Existing calls without the
flag are unchanged. See [local coding agents](../../docs/development/local-coding-agents.md)
for session selection, provider-sharing boundaries, supported skill discovery
and native-versus-HTTP limitations.
`reb-api call get_analysis_catalog --base-url URL` returns the embedded current VM
profile, rule definitions, and reviewed sources without touching evidence or
starting analysis. See [Analysis Catalog v1](../../docs/product/analysis-catalog-v1.md).

`reb-api call get_api_observation_catalog --base-url URL` derives a bounded
endpoint/parameter and JSON-shape catalog from the newest retained Traffic
requests. It preserves scoped source identities and explicit unknowns, leaves
raw Traffic unchanged, and never sends a target request. See the
[API observation catalog contract](../../protocol/api-observation-catalog-v1.md).

`reb-api call get_network_request --read-only` retrieves exactly one retained
Traffic row using the catalog's original instance, epoch, public request ID,
target ID and unrounded monotonic start. It rejects stale owners, duplicate
public IDs and missing exact records rather than fetching or substituting data.
The raw row and its existing truncation/unavailability flags are preserved;
the complete JSON response is capped at 8 MiB, including escaping. The operation
does not copy a full debugger snapshot or contact a target. Raw values can be
sensitive even with the read-only guard. See the
[exact request contract](../../protocol/http-api.md#exact-retained-traffic-request)
and [agent workflow](../../docs/development/local-coding-agents.md).
The existing synthetic candidate-bridge browser journey verifies populated
HTTP/CLI raw-row fidelity and no replay; unit cases cover stale, ambiguous,
evicted, redirect-hop, body-completion and whole-response size boundaries.

Request Field Trace uses `src/provenance.rs` for bounded in-process projection of
request call sites and same-target primitive string matches. Hashes are captured
only while selected-value capture is enabled. Request-time snapshots survive
hook eviction; session and capture revision guards prevent late results from
restoring erased observations. See the
[feature design](../../docs/product/request-field-provenance-v1.md).

Live `Debugger.scriptParsed` WebAssembly modules are copied from CDP bytecode
into the session artifact store as `kind=wasm` and
`capture_origin=webassembly_compile`. CDP `scriptSource` is empty for those
scripts; non-empty `bytecode`, or `Debugger.getWasmBytecode`, is what gets
decoded. `GET /api/debugger/source` returns that module as standard base64
(`encoding` is `base64`, `byte_size` is the decoded length). The artifact keeps
the raw bytes, capped at 16 MiB, with artifact IDs at or above 2^32. The
backend appends the receiver manifest line directly because the browser already
holds the receiver's one authenticated connection. Pass
`--capture-session-id` for that manifest; otherwise the artifacts directory's
parent name, then an existing manifest session, is used.

Captured WASM inspection uses `src/wasm.rs` and the shared `origin-trace-wasm`
helper. `GET /api/wasm?artifact_id=ID` verifies the complete artifact before
bounded inert decoding. The native app bundles the same helper; see
[WASM Inspection v1](../../protocol/wasm-inspection-v1.md) for limits and
coverage semantics. HTTP tests verify offsets, imported function numbering,
CLI parity, malformed and oversized input, partial coverage, and corruption.

Exact artifact lookups used by content and deobfuscation requests keep
an in-memory manifest index capped at 64 MiB and 100,000 artifact IDs. It retains
manifest bytes and numeric ID/offset pairs, not parsed JSON trees or blob content.
Every indexed lookup rereads and compares the exact manifest bytes; on Unix, unchanged
prefixes of the same file reuse validation and only complete appended rows are
parsed. Unterminated tails, rewrites, rotation and truncation rebuild the index.
Change stamps before/after the read and validation reject observed concurrent
changes; this is not a stopped-store lease.
Duplicate IDs and malformed rows anywhere in the manifest still reject the
lookup, even after the selected row. Over-cap stores fall back to complete
streaming validation within the same five-second deadline, never a partial index.
A bounded line lookahead avoids reparsing a large prefix on fallback; the cache
lock is released before streaming, preserving independent reader concurrency.
One bounded file-identity/minimum-size hint avoids repeat indexing attempts for
an over-record-cap file. The hint only selects complete streaming validation;
it never authorizes a returned artifact. Shrink or replacement discards it. A
same-size rewrite to fewer, larger rows may stay uncached, but is still fully
validated on every lookup.
The previous and current byte buffers can coexist (at most 128 MiB), plus the
bounded index. Waiting lookups do not occupy shared reader permits. Full blob
hash verification still runs for every content read; only metadata parsing is
reused. Non-Unix platforms conservatively rebuild rather than reuse the index.
`python3 tools/benchmark-artifact-lookup.py PATH_TO_RELEASE_BACKEND` measures
process-cold, warm and append lookups over an authored 50,000-record manifest.
Compare preserved binaries built with the same release toolchain; the benchmark
never reads capture stores or sends requests outside its own loopback fixture.
See the [measured results and validation limits](../../docs/development/backend-artifact-lookup-performance.md).

Immutable JavaScript source facts use `GET /api/source-facts` with exact
`session_id` and `artifact_id`. The adapter verifies the complete artifact and
strict UTF-8 before invoking the existing Rust/Oxc worker under its shared lock.
`reb-api describe get_source_facts` and `reb-api call get_source_facts` expose the
same [versioned contract](../../protocol/javascript-source-facts-v1.md), including
original-byte ranges, lexical binding/effect facts and explicit partial or
unavailable coverage. No source is executed or rewritten.
`make check` also runs the real-worker HTTP/CLI integration test after building
the helper. Standalone backend `cargo test` keeps that test explicitly ignored;
set `REB_SOURCE_FACTS_TEST_WORKER` to the built worker and run
`cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml source_facts_real_worker_http_and_cli -- --ignored`
to exercise that boundary directly.

Durable Analyst/notebook and API Collection replacements now share a
[cooperative cross-process writer lease](../../protocol/workspace-writer-lease-v1.md)
with the native Swift handlers. A busy writer fails promptly with 409; stale
expected generations remain explicit conflicts. Both readers/writers preserve
atomic snapshots, and a post-publication synchronization failure is reported as
an uncertain save. The contract documents private directories, reserved sidecars,
parent aliases and the supported local-filesystem boundary.

API failures preserve their HTTP status and human `error` text and add stable
`code` and bounded `details` fields. The shared envelope and enum live in
`src/error.rs` and the OpenAPI `Error`, `ErrorCode`, and `ErrorDetails` schemas.
Codes are selected at known failure branches, never by matching error prose.
Legacy paths without a precise reason use `unspecified` or their existing
constructor's coarse `invalid_request`, `state_conflict`, or `protocol_error`.
The initial precise coverage is workspace generation conflicts, unavailable
selected debugger targets and helpers, debugger/worker resource limits,
worker cancellation/deadlines, POST body deadlines, and uncertain debugger or
native-console exchanges. No ambiguous-target classification is inferred from
an ordinary missing-target result, and target selection behavior is unchanged.

A `timeout` with `details.phase=request_body` happens before action dispatch.
An interrupted queued/partial write or a command whose reply is lost, malformed, or late has
`command_outcome_unknown`; it may already have had effects. No code is a retry
instruction or a rollback/no-op guarantee. Worker cancellation and deadlines
also do not undo work already performed. Existing effect/prerequisite metadata
still governs which action may be taken.

Analyst, JWT Decoder and native Console application failures keep HTTP 200 and
their existing `ok`, `outcome`, `status`, `runtime.status` and text fields, and
add the same reason fields. Clients must inspect the application result as well
as HTTP status. `reb-api call` continues to print successful HTTP JSON and keep
its existing transport-based exit status; non-2xx errors retain their stderr
format. Offline `reb-api spec` and `describe` include the reason contracts.
Details contain only fixed enum values and validated generation numbers, never
inputs, URLs, credentials, capture content, diagnostics or stack traces.

For machine-readable non-2xx HTTP errors, use `reb-api call ... --json-errors`.
This opt-in mode emits one JSON object on stderr with `http_status`, allowlisted
`code`/`details`, a human `error` limited to 512 UTF-8 bytes, and an explicit
`error_truncated` boolean. Legacy errors fall back to `unspecified`; malformed
or non-JSON bodies get a fixed diagnostic rather than a raw body dump. Unknown
reason details are discarded. This flag cannot be combined with `--show-headers`.
Default stderr, success stdout (including HTTP 200 application failures), and
exit codes are unchanged: 0 for successful HTTP transport, 1 for non-2xx HTTP,
2 for CLI/connection/read failures. Response ingestion remains capped at 64 MiB.
For non-2xx responses whose body cannot be read within the existing timeout/size
limit, JSON mode emits a fixed safe diagnostic with the observed HTTP status and
keeps exit 2. Preflight and connection failures before HTTP headers keep ordinary
CLI diagnostics and exit 2; no HTTP status is invented. Commands are never retried.

`POST /api/evidence/packages/validate` and `reb-api call
validate_evidence_package` validate supplied metadata packages inertly. The
versioned [package contract](../../protocol/evidence-package-v1.md) defines
bounded duplicate-rejecting parsing, canonical content identity, reference and
coverage checks, and the exact metadata whitelist. Validity never authenticates
an exporter or re-verifies omitted artifact bytes. This operation does not read
or write configured evidence stores.

`POST /api/evidence/packages/export` (`export_evidence_package`) now reads exact
explicit metadata selections from cooperatively stopped configured stores.
Shared nonblocking leases exclude updated broker, receiver and backend-clear
writers; pinned safe descriptors, complete bounded scans and full selected-blob
hashes precede canonical output. Raw payloads, URLs, headers, bodies and artifact
bytes are omitted. Missing legacy guards are unsupported for export and clear;
no socket or capture boolean substitutes for a lease. The package contract
explains reserved paths, private directories, limits and threat boundaries.
CLI `--output PATH` is private, atomic and no-clobber for JSON or binary output;
an export must pass validation before its final file is created.

`POST /api/evidence/packages/compare` (`compare_evidence_packages`) validates two
supplied original package documents and compares explicitly selected declared
metadata facets. Exact scoped references, changed fields, unmatched/cross-scope
ambiguities, unknown observer regimes and bounded deterministic pages remain
visible. A declared hash match never reverifies absent raw bytes. This read-only
operation does not touch stores, helpers, capture or network. See the
[comparison contract](../../protocol/evidence-comparison-v1.md).

## Float32 diagnostics

`POST /api/float32/compare` and `reb-api call compare_float32` inspect explicit raw
word arrays, base64 buffers or complete hash-verified artifact identities. The
optional reference produces separate raw-byte, word, numeric and caller-tolerance
results. Bounds, exceptional values, endian/layout assumptions and null/partial
policies are documented in [Float32 Comparison v1](../../protocol/float32-comparison-v1.md).
The cold operation is in-process, read-only and uses the existing I/O admission
pool. No native capture or executable helper is involved.

## Raw Traffic values and local copies

CDP Traffic preserves bounded URLs and header/body values, including credentials,
without automatic masking. Headers expose `headers_truncated`; document URLs
expose `document_url_truncated`. Provenance source URLs carry optional
`source_truncated`, including upstream hook truncation. Values remain inert text.
`network.instance_id` and `network.capture_epoch` identify backend/attachment
lifetimes; response-body completions from a retired epoch cannot update the next
attachment's same-id record. Reconnecting still clears the ephemeral ledger.

The UI can explicitly export one selected raw or best-effort redacted copy;
see [the copy contract](../../protocol/traffic-capture-copy-v1.md). This is not
`reb-metadata-only-v1`, whose guarded store export is unchanged. No raw capture
is uploaded or sent to an AI service. Synthetic-only tests cover credentials,
body forms, bounds, capture-off and retention; UI tests cover copy isolation and
retired clipboard owners.

Retained CDP rows include bounded [source timing evidence](../../protocol/network-timing-v1.md). Missing clocks and lifecycle anomalies remain explicit; legacy display durations do not establish HAR fidelity.
Enabled network content capture also retains bounded [WebSocket message observations](../../protocol/websocket-capture-v1.md) in the existing debugger snapshot; no message replay or handshake credentials are added.

### Owned cooperative VM fixture

`--owned-vm-fixture PATH` overrides the bounded repository-owned helper location;
otherwise the app resolves `OriginTraceOwnedVmFixture` beside its executable or
`build/reb-native-vm-fixture` for development. This startup option is not exposed
through HTTP. The API accepts only the built-in register/stack fixture names.
GET `/api/vm-debugger` is inert; explicit control POSTs are strict, identity-bound
and limited to 2 KiB. See [owned-vm-debugger-v1](../../protocol/owned-vm-debugger-v1.md).

Build and check the helper with `make owned-vm-helper-check`. The normal `make
check` gate also runs the ignored real-helper actor acceptance test with the
compiled helper path. Running it directly requires `REB_OWNED_VM_TEST_HELPER` and
`cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml
owned_vm_real_helper -- --ignored`.

## Scoped local response overrides

For explicit local response/JavaScript snapshots, use the
[scoped local override manager](../../protocol/local-overrides-v1.md).
Preview and prepare are offline; `--arm` applies one reviewed, expiring rule to
an exact primary disposable target, while guarded `--disarm` cannot clear a
replacement rule accidentally. The API never reads an arbitrary filesystem path.

## Literal marker fuzz CLI

Use `node tools/prepare-marker-fuzz.mjs --input authored.json` from the repository
root to preview a bounded, explicitly authored body/query marker plan. Save the
reviewed plan with `--output`, then execute only with `tools/run-marker-fuzz.mjs`
and its matching `--arm` digest against an exact disposable Repeater session.
The CLI owns sequential/count/rate/aggregate-byte/deadline budgets; the backend
adds strict per-case literal scope/digest checks and exact guarded cancellation.
Ordinary Repeater behavior is unchanged. See
[the versioned workflow](../../protocol/marker-fuzz-v1.md) for input, commands,
privacy boundaries, per-case evidence and stop-on-unknown behavior.

## Local element screenshot markup

`inspect_element_document` and `capture_element_screenshot` use bounded CDP
snapshot/layout/screenshot reads on the exact selected primary disposable page.
The original owner/document/revision is rechecked before and after capture;
PNG and DOM text/attributes are never retained in debugger state or written to
files. The feature refuses observed form/private/editable content and frames,
while explicitly retaining unknown pixel sensitivity, timing and occlusion.
See [Element screenshot v1](../../protocol/element-screenshot-v1.md).

VM Lab host positions are a separate digest-bound [host-links v1 report](../../protocol/vm-host-links-v1.md). Host payloads are not duplicated; missing dispatch evidence stays unknown.
### Main-resource terminal handoffs

A document or worker main-script request can begin in a parent CDP session and
finish in its child session. Capture keeps the original public request ID,
target and owner. It accepts a child `loadingFinished` only with a single
pending candidate, exact bounded loader/frame or worker-target identity,
compatible observed ancestry, a nondecreasing timestamp and live owners on the
same connection. Completed collisions and dropped request history block this
adoption; ambiguous events never become guessed completions. Private provenance
is capped by the 1,000-row ledger and 512-entry target-lineage limit.

After proven completion, body retrieval uses the terminal event's exact session;
it does not transfer unrelated requests or invent response headers/status.
Missing responses and detached body owners remain incomplete/unavailable. This
repairs a lifecycle handoff, not passive capture of a target's first requests.
