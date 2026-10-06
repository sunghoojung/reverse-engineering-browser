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
