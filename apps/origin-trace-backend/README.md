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

## Native Wasm observations

See [native-wasm-dispatch-v1](../../protocol/native-wasm-dispatch-v1.md). Runtime
sampling stays C++; Rust validates exact artifacts and physical dispatch sites,
and the viewer displays native observations without calling them guest PCs.
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
The scaling test exercises analysis plus workspace extraction, and the ignored
`vm_opcode::tests::measure_classifier_pipeline` test accepts a newline-separated
input list through `REB_CLASSIFIER_MEASURE_INPUTS` for local measurements.

JavaScript classification uses unmodified Oxc 0.155.0. The successful parse is
shared by classification and binding proof. A linear AST prepass admits the
upstream semantic ancestor walks and block-hoisting expansion before they run.
The existing `origin-trace-vm` executable (bundled as `OriginTraceVMAnalyzer`)
also hosts an internal, non-executing analysis worker. Keep it beside the backend
when distributing binaries; a missing worker is a counted omission.

Artifacts up to 8 MiB are analyzed in full within a separate temporary heap
ceiling of 64 MiB + 80 times source bytes (704 MiB at 8 MiB). The worker allocator
checks every allocation before calling the system allocator, including arena,
semantic, indexing and serialization storage. Refusal exits only that worker,
with fixed-size allocation/work telemetry. The caller keeps the same artifact
work ledger and the existing 128 MiB retained-record cap. A 30-second worker
deadline is a final containment boundary. Source crosses anonymous pipes only;
it is never executed or written to a temporary source file.

Reserved 32/64 MiB recursive stacks are separate from heap accounting. Actual
worker allocation peaks (including 32 bytes of overhead per allocation) are
reported by the ignored measurement test as `parser_peak_bytes`. Process RSS
also includes resident stack pages, allocator/runtime overhead and the parent;
measure both processes together. The 8 MiB target is below roughly 1 GiB peak
RSS on a local workstation, not a guarantee about unrelated concurrent work.
Oversize, dense, excessively nested and unavailable-worker inputs have counted
omissions. The [owned retention ledger](../../tools/fixtures/dispatch-retention/README.md)
checks emitted claims and separately verifies runtime ground truth with Node.
