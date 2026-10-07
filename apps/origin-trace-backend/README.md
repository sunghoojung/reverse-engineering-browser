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
make backend-e2e
```

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
and command deadlines. Experiment actions verify browser-context ownership.
Disposal stops owned pages, workers, recipes, requests, and retained objects.
Worker cancellation terminates its process group, including descendants. Network
capture defaults to metadata; sensitive field selection requires confirmation.

The API CLI embeds the versioned OpenAPI document and requires an explicit
loopback URL or endpoint file. The VM analyzer reads bounded input prefixes,
reports omissions, and writes private analysis documents. Its executable is
`origin-trace-vm --artifacts DIR --events FILE`.
Offline `reb-api describe OPERATION --action ACTION` also exposes source-backed
advisory effects and prerequisites while retaining the operation's common
guards. See the [execution metadata contract](../../protocol/http-api.md#execution-metadata).
These annotations do not authorize execution or automatic retries.
`reb-api call get_analysis_catalog --base-url URL` returns the embedded current VM
profile, rule definitions, and reviewed sources without touching evidence or
starting analysis. See [Analysis Catalog v1](../../docs/product/analysis-catalog-v1.md).

Request Field Trace uses `src/provenance.rs` for bounded in-process projection of
request call sites and same-target primitive string matches. Hashes are captured
only while selected-value capture is enabled. Request-time snapshots survive
hook eviction; session and capture revision guards prevent late results from
restoring erased observations. See the
[feature design](../../docs/product/request-field-provenance-v1.md).

Captured WASM inspection uses `src/wasm.rs` and the shared `origin-trace-wasm`
helper. `GET /api/wasm?artifact_id=ID` verifies the complete artifact before
bounded inert decoding. The native app bundles the same helper; see
[WASM Inspection v1](../../protocol/wasm-inspection-v1.md) for limits and
coverage semantics. HTTP tests verify offsets, imported function numbering,
CLI parity, malformed and oversized input, partial coverage, and corruption.

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
or write configured evidence stores; selected-store export is not implemented.
