# Native implementation

Public C++ interfaces live in [`include/reb/`](../include/reb/). Implementations
are grouped by responsibility; executable entry points remain in `apps/` and
`services/`.

| Directory | Owns | Dependencies within the native library |
| --- | --- | --- |
| `capture/` | Event records, validation, JSON encoding, and VM finding payloads | VM findings use the event contract |
| `evidence/` | Broker retention, artifact storage, origin correlation, and request signal profiles | Broker and correlation use event records; artifact storage is independent |
| `transport/` | Authenticated local IPC and debugger WebSocket transport | Independent of evidence storage and analysis |
| `analysis/` | Decoding and heap snapshot queries | Independent of capture and services; decoding uses zlib |

The bounded SPSC queue is header-only in `include/reb/spsc_ring.hpp`. Browser
probes and their shared-memory transport remain in the tracked
[Brave integration](../browser/integration/brave/README.md).

Keep process lifecycle, command-line parsing, and service composition in the
executable entry points. Library components should not start services or depend
on application code. Capture must not depend on storage or analysis. Preserve
the [protocol contracts](../protocol/README.md) when changing public records.

## Building and testing a component

[`mk/native.mk`](../mk/native.mk) declares each executable's object dependencies.
Add a new implementation to its consumers explicitly. Do not link every native
component into a test: doing so hides missing dependencies and allows unrelated
changes to affect that test.

For example, build and run the broker unit test with:

```sh
make build/tests/event_broker_test
./build/tests/event_broker_test
```

Native tests live in `tests/`. Use `make socket-e2e` or
`make artifact-socket-e2e` to exercise service boundaries, then run the complete
[contribution gate](../CONTRIBUTING.md#quality-gate).
