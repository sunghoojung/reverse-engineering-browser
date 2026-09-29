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

## Building a component

[`mk/native.mk`](../mk/native.mk) declares each executable's object dependencies.
Add a new implementation to its consumers explicitly. This keeps missing
dependencies visible and avoids rebuilding unrelated executables.

For example, build the broker and run the deterministic evidence path with:

```sh
make broker
make e2e
```

The native dependency check runs through `make native-build-test`. Run the
complete [contribution gate](../CONTRIBUTING.md#quality-gate) before handoff.
