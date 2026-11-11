# Origin Trace backend

Rust provides local evidence analysis, HTTP API and CLI/MCP adapters. Capture is
native Brave/V8 C++. CDP execution and its transport, injected hooks, evaluation,
stepping, live heap inspection, page screenshots, replay and browser automation
have been removed; there is no fallback or replacement claimed for those features.

`/api/debugger` and its subroutes return HTTP410 and are absent from OpenAPI/MCP
discovery. The old `--debugger-transport` and `--devtools-active-port` options are
rejected. The CDP-backed `/api/network/catalog` and `/api/network/request` reads
were also removed and return 404; native network records keep no bodies to
rebuild them. Session context and deobfuscation keep their version 1 debugger
fields as fixed retirement values. The OpenAPI document carries no schema for a
removed route: a backend test fails if any component schema is unreachable or
any `x-source` path is missing.
Native Console and the explicitly owned VM fixture debugger remain separate,
native-backed features. `/api/vm-debugger` is not the removed CDP debugger.

## Development

Use the repository Makefile and `.agents/skills/reb-validation`:

```sh
make origin-trace-backend
cargo test --locked --manifest-path apps/origin-trace-backend/Cargo.toml
make lint
make check
make e2e
make sanitize
```

The backend binds loopback only and verifies request origin/host. Capture session
and artifact identities are explicit; missing evidence does not become inferred
causality. Existing artifacts, VM analysis, native events, source facts, bounded
decoding, saved collections and evidence export remain local workflows.
Only `reb-api mcp` exposes the existing versioned HTTP contract; effectful tools
remain opt-in, not authorization to inspect an unowned target.

## Graph layout

`POST /api/graph-layout` lays out graphs the UI sends with Triskel, vendored
unmodified with its {fmt} headers under [`vendor/`](vendor/README.md).
[`build.rs`](build.rs) compiles them with the C ABI bridge in
[`cpp/triskel_bridge.cpp`](cpp/triskel_bridge.cpp) as C++23 at `-O2` in every
profile, so the backend build needs GCC 14 or later, Clang 18 or later, or a
current Apple Clang; CI sets `CXX_x86_64_unknown_linux_gnu=g++-14` on Ubuntu
and `CXX_aarch64_apple_darwin=clang++` on macOS, which also keeps the cc crate
off CI's sccache compiler shim.
Only the hidden `--graph-layout-worker` mode of this binary calls Triskel, in a
contained process per request with a deadline, a budget per graph and a memory
limit; the server never does. Limits and failure statuses are in
[`protocol/http-api.md`](../../protocol/http-api.md#graph-layout). The packaged
app ships the MPL-2.0 and MIT texts, with where Triskel's source is, as
`Contents/Resources/GraphLayoutLicenses.txt`.

## Live capture lifecycle

A live backend (`--socket`) belongs to one native event broker, which the
launcher starts first. The backend reads the broker as running while some
process holds the exclusive lock the broker keeps on its event store guard
(`<store>.reb-lock-v1`) for its whole life. The kernel drops that lock even
when the broker is killed, so a socket file left behind never reads as a
broker. Every capture surface reports one `capture_state`: `running`,
`stop_requested`, `stopped`, `ended` (the broker shut down on its own and
removed its socket), `lost` (it is gone and left its socket, so it was killed
or crashed), or `not_live` for idle and demo backends. Exits are final.

Stop signals only a running broker, and only while `--broker-pid` still names
the process it named when the backend started; the start time is compared, so
a reused PID is never signaled. A stop that times out stays `stop_requested`
and can be repeated. Clear refuses while the broker runs and empties the
derived trace and signal stores before the event store, so an interrupted
clear never leaves derived records for cleared events; clearing again finishes
it. `--demo-evidence` with `--socket`, and `--broker-pid` without `--socket`,
are rejected at startup.

Endpoint files keep their one-line format. The backend holds an exclusive lock
on the exact file it published until it exits, and publishers serialize on the
directory, so retiring removes only that file, never a successor's at the same
port. `reb-api mcp` refuses an endpoint file that no running backend holds as
stale, which is what a killed backend leaves behind. `--owner-pid` stops the
backend, retiring its endpoint, once that parent process is gone; the app's
private stored-evidence backend uses it.

## MCP agent workflow

`reb-api mcp` answers `initialize` with a short workflow guide (orient,
evidence filters, the Console in a chosen frame, document-start for child
frames, invocation sites and, with `--allow-session-start`, starting and
ending a session). A unit test in `src/bin/reb_api/mcp.rs` fails if the guide
names a tool the contract does not serve. Tool descriptions come from the
OpenAPI operation descriptions in `protocol/openapi.json`.

- `src/session_launch.rs` turns `start_live_session` options into launcher
  switches. Request content and its byte budget, request stacks,
  document-start permission, invocation sites and digests are set only from
  named options; inherited switches are removed or forced off. Saved sites come from the agent sessions' own store and are armed
  from a private per-launch copy.
- `src/native_console.rs` annotates every target with `frame`, and child
  frames with `top_relation` and `out_of_process`, derived from the listing,
  and reports a live connection's `selection` (`selected`, `stale`, `none`).
- `src/session_context.rs` reports `capture_options` from the launcher's
  `--session-*` labels.

`tests/mcp_stdio.rs` drives agent sessions through a stand-in launcher, and
`make native-console-check` drives the iframe Console flow through
`reb-api mcp` against the real C++ bridge and a synthetic browser peer. The
recipes are in the [agent cookbook](../../docs/development/agent-cookbook.md)
and the [`reb-api-workflow` skill](../../.agents/skills/reb-api-workflow/SKILL.md).

## Native Wasm observations

See [native-wasm-dispatch-v1](../../protocol/native-wasm-dispatch-v1.md). Runtime
sampling stays C++; Rust validates exact artifacts and physical dispatch sites,
and the viewer displays native observations without calling them guest PCs.
`get_events` also returns `wasm_observation` decoded from the event payload
alone, including for a module that has no opcode workspace.
Physical observations and adapter guest samples can describe the same br_table
execution, so workspaces count them separately and never add them.
A rebuilt browser is required. Portable tests are not a full native browser build.

## Limits

Removed CDP functionality is unavailable rather than silently routed through a
fallback. Native artifact/source coverage can be narrower than previous CDP
capture. Workers, arbitrary interpreter guest PCs and host causality require
additional native implementation and verification. Saved legacy CDP metadata
retains its historical provenance; a current native session never relabels it.

## Dispatch classification and opcode claims

Classification and workspace extraction share one per-artifact work and memory
budget. The parsed semantic gate only removes recovered opcode claims and reports their
count; it never changes the detector tier, score, finding ID or dispatch
inventory. See the [classification contract](../../protocol/vm-dispatch-classification-v1.md).
Claims come from switches and handler tables, including function arrays,
rotated loops, aliases and called temporaries, helper fetches, and threaded
chains and cycles whose next-handler index is fetched at an advancing
cursor. Their short owned test programs, each beside look-alikes that must
claim nothing, are inline in `src/vm_review_inputs.rs`.
The scaling test exercises analysis plus workspace extraction, and the ignored
`vm_opcode::tests::measure_classifier_pipeline` test accepts a newline-separated
input list through `REB_CLASSIFIER_MEASURE_INPUTS` for local measurements.

JavaScript classification uses unmodified Oxc 0.155.0. The successful parse is
shared by classification and binding proof. A linear AST prepass admits the
upstream semantic ancestor walks and block-hoisting expansion before they run.
Every classification caller re-executes itself through a shared hidden worker
entry, including the CLI, backend, API executable and Cargo harnesses. Packaged
names do not change worker selection; no sibling analyzer is discovered.
The standalone `OriginTraceVMAnalyzer` remains the live-session batch CLI.
Artifacts up to 8 MiB are analyzed in full within a separate temporary heap
ceiling of 64 MiB + 80 times source bytes (704 MiB at 8 MiB). The worker allocator
checks every allocation before calling the system allocator, including arena,
semantic, indexing and serialization storage. Refusal exits only that worker,
with fixed-size allocation/work telemetry. The caller keeps the same artifact
work ledger and the existing 128 MiB retained-record cap. A five-minute deadline
plus one minute per started MiB is only a hang backstop. Worker timeout, crash,
spawn and protocol failures are distinct counted `analysis-worker-failed`
omissions, never saved or cached. The CLI fails and the API returns 503; an
unchanged-input retry runs again. Workers clear inherited environment variables,
close extra descriptors and deny network access. Source crosses anonymous pipes only;
it is never executed or written to a temporary source file.

Reserved 32/64 MiB recursive stacks are separate from heap accounting. Actual
worker allocation peaks (including 32 bytes of overhead per allocation) are
reported by the ignored measurement test as `parser_peak_bytes`. Process RSS
also includes resident stack pages, allocator/runtime overhead and the parent;
measure both processes together. The 8 MiB target is below roughly 1 GiB peak
RSS on a local workstation, not a guarantee about unrelated concurrent work.
Oversize, dense, excessively nested and unavailable-worker inputs have counted
omissions.

Claims describe the statically bound table. Runtime replacement through `eval`
or `Function`, Proxy or reflection, global-object writes, sloppy `arguments`
aliasing, and conditional or never-executed initialization are not modeled.
Runtime evidence from native guest capture is the authority for what actually
executes.
