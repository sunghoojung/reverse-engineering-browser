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

## Migrate the Origin Trace control plane

The migration target is the Python control plane under `apps/research-ui/`:

- `server.py` owns loopback HTTP routing and application composition;
- `evidence_store.py`, `origin_trace.py`, and `api_collection.py` own bounded
  reads and projections over stored evidence;
- `debugger_bridge.py` and `debugger/` own the live CDP session state machine;
- adapters invoke the existing Rust deobfuscator and native decoder, heap, and
  debugger-transport workers.

Rust is preferred over Go for this boundary. The repository already ships a
Rust worker, Cargo can build static helper executables for the native app, and
Rust makes request schemas, process ownership, cancellation, and bounded byte
buffers explicit without adding a second managed runtime to the macOS bundle.

## Migration sequence

The control plane must be replaced behind its existing HTTP and helper-process
contracts rather than by changing browser capture at the same time.

1. **Freeze compatibility fixtures.** Record every route in `protocol/openapi.json`
   plus malformed input, unavailable worker, timeout, cancellation, and stale
   evidence behavior. Exercise the same fixtures against Python and Rust.
2. **Extract pure services.** Port evidence-store reads, Origin Trace
   projection, API collection, and durable-file replacement first. These have
   deterministic inputs and do not require a live browser.
3. **Add worker supervision.** Move bounded subprocess invocation, deadlines,
   cancellation, output caps, and shutdown into one Rust supervisor while
   retaining the current Rust, Node, and native workers.
4. **Port live debugger orchestration last.** Replace the CDP state machine
   only after recorded transport transcripts cover attach, navigation,
   renderer crash, reconnect, pause, and stop behavior.
5. **Switch packaging once.** Change the native app and live launcher to the
   Rust server only when the compatibility suite passes. Remove the Python
   runtime requirement and old implementation in that same change.

During migration there must still be one production owner for each route. Do
not introduce a permanent Python-to-Rust proxy, duplicate evidence stores, or
an alternate API. A temporary comparison harness may run both implementations
against immutable fixtures, but only one may serve the application.

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
