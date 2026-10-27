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
