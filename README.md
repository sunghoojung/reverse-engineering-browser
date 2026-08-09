# Reverse Engineering Browser

Private workspace for a Brave-based browser harness used in authorized website
security research.

The project goal is to observe browser behavior through native browser
instrumentation, not page JavaScript hooks. Native C++ probe surfaces emit
bounded telemetry to a browser-process broker, which streams normalized events
to a local research interface.

## Start here

Validate the tracked workspace and native foundation:

```sh
make check
./build/reb-event-demo
```

Prepare the pinned upstream Brave checkout without downloading Chromium, then
apply the integration tracked by this repository:

```sh
./scripts/bootstrap-brave.sh
./scripts/sync-browser-integration.sh
```

When you are ready for the large Chromium download and full Brave initialization:

```sh
./scripts/bootstrap-brave.sh --init
```

Check the local Apple toolchain and compile the tracked Brave probe:

```sh
make brave-doctor
make brave-probe-check
```

## Current implementation

The repository includes a dependency-free C++ vertical slice for the probe event path:

- a fixed-size, versioned event record;
- a bounded single-producer, single-consumer ring buffer;
- explicit dropped-event accounting;
- a bounded broker with validation, sequence-gap detection, and eviction accounting;
- a native binary event stream and versioned JSONL evidence store;
- a native macOS Origin Trace application that reads the broker evidence store;
- a threaded producer and consumer demo;
- unit tests and sanitizer support.

The current producer is a deterministic development stand-in for the Brave adapter. It
validates the complete local path before Chromium shared memory and Mojo IPC are added.

## Native development

Requirements:

- a C++20 compiler;
- GNU Make or a compatible `make` implementation.

```sh
make
make test
./build/reb-event-demo
```

## Origin Trace application

On macOS, build the demo evidence and open the native Origin Trace application:

```sh
make app
```

This builds `build/Origin Trace.app`, writes the demo evidence, and opens the
application. It is a native WebKit window with no browser address bar and no
localhost server. The application and broker stay local.

The demo includes linked Navigator, Canvas, WebAssembly, and Network events.
The research workflow starts from a request field and works backward through
the available evidence.

For browser-based UI development only, run:

```sh
make ui
```

Then open `http://127.0.0.1:7319`.

Run sanitizer checks. Linux uses AddressSanitizer and UndefinedBehaviorSanitizer;
macOS uses UndefinedBehaviorSanitizer:

```sh
make sanitize
```

## Layout

```text
apps/                  research UI and runnable development tools
browser/               tracked Brave integration and ignored source worktree
docs/                  documentation index
include/ and src/       dependency-free native event foundation
protocol/              shared browser, broker, and UI contracts
services/event-broker/ local browser-process bridge and evidence broker
scripts/               setup and workspace validation
tests/                 native unit and concurrency tests
tools/                 development and analysis utilities
```

All project-owned Brave changes live in `browser/integration/brave` as tracked
overlays and patches. The pinned upstream `brave-core` checkout and Chromium
build output live under `browser/worktree` and are intentionally excluded from
Git. This keeps every unique project file in one GitHub repository without
duplicating hundreds of gigabytes of reproducible upstream source.

Brave and Chromium initialization requires substantial storage. Keep at least
150 GiB free before running `./scripts/bootstrap-brave.sh --init`; 200 to 250
GiB is recommended for comfortable development and updates.

## Docs

- [Technical architecture](./reverse-engineering-browser.md)
- [System architecture diagram](./system-architecture.md)
- [Feature list](./feature_list.md)
- [Workspace architecture](./docs/README.md)
- [Brave integration](./browser/README.md)
