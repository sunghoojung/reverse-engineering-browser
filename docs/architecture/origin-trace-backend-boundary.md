# Origin Trace backend boundary

Origin Trace has two local backend layers with different constraints. They
should not be migrated as one unit.

## Keep the browser evidence backend native

The event broker, artifact receiver, native probes, and browser transports stay
in C++. They share fixed native records with the Brave integration, already
enforce bounded hot-path behavior, and are exercised together by the native
end-to-end and sanitizer gates. Rewriting those services does not simplify the
Origin Trace application and would create a second implementation of its most
sensitive wire and storage contracts.

## Origin Trace control plane

The Rust crate under `apps/origin-trace-backend/` replaces the former Python
services. `app.rs` owns loopback HTTP routing and application composition;
`evidence.rs`, `origin_trace.rs`, and `workspace.rs` own stored evidence,
projections, and durable workspaces. `debugger/` owns CDP session state, page
and worker connections, bounded events, experiment ownership, hooks, and
cancellation. Adapters invoke the Rust deobfuscator and existing native workers.

The macOS app bundles `OriginTraceBackend` and `OriginTraceVMAnalyzer` and the
live-session launcher invokes them directly. `make ui` uses the same backend.
The OpenAPI-backed Rust CLI preserves operation IDs and explicit endpoint
selection. There is one production owner per route and no runtime proxy.

Migration verification compared deterministic HTTP fixtures and disposable
browser workflows against a frozen copy of the released implementation outside
the repository. The regression fixture in `tools/check-origin-trace-debugger.mjs`
exercises public APIs against synthetic localhost content with a fresh profile.
Builds and packaged sessions no longer depend on Python. Python remains for
repository-only benchmark and evidence validation tooling.

## Compatibility requirements

The replacement must preserve:

- loopback-only binding and current Host/Origin validation;
- the versioned HTTP schemas and exact identifier representation;
- bounded reads, response bodies, worker output, and concurrency;
- metadata-only defaults and all redaction behavior;
- last-understandable evidence when refresh fails;
- private session and durable-workspace file permissions;
- clean termination of child processes when Origin Trace closes.

The Brave integration, native event/artifact protocols, and stored evidence
formats are out of scope for this migration.
