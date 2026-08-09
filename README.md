# Reverse Engineering Browser

Private workspace for a Brave-based browser harness used in authorized website security research.

The project goal is to observe browser behavior through native browser instrumentation, not page JavaScript hooks. Native C++ probe surfaces emit bounded telemetry to a browser-process broker, which streams normalized events to a local harness for human researchers and AI agents.

## Start here

Validate the tracked workspace and native foundation:

```sh
make check
./build/reb-event-demo
```

Prepare the linked private Brave source checkout without downloading Chromium:

```sh
./scripts/bootstrap-brave.sh
```

When you are ready for the large Chromium download and full Brave initialization:

```sh
./scripts/bootstrap-brave.sh --init
```

## Current implementation

The repository includes a dependency-free C++ foundation for the probe event path:

- a fixed-size, versioned event record;
- a bounded single-producer, single-consumer ring buffer;
- explicit dropped-event accounting;
- a threaded producer and consumer demo;
- unit tests and sanitizer support.

This standalone code is intentionally small. It validates the data structures before they are adapted to Chromium shared memory and Mojo IPC.

## Native development

Requirements:

- a C++20 compiler;
- GNU Make or a compatible `make` implementation.

```sh
make
make test
./build/reb-event-demo
```

Run sanitizer checks. Linux uses AddressSanitizer and UndefinedBehaviorSanitizer;
macOS uses UndefinedBehaviorSanitizer:

```sh
make sanitize
```

## Layout

```text
apps/                  research UI, MCP server, and runnable development tools
browser/               Brave integration files and ignored source worktree
docs/                  documentation index
include/ and src/       dependency-free native event foundation
protocol/              shared browser, broker, UI, and MCP contracts
services/event-broker/ local browser-process bridge and evidence broker
scripts/               setup and workspace validation
tests/                 native unit and concurrency tests
tools/                 development and analysis utilities
```

The private `brave-core` source is linked as a shallow Git submodule at
`browser/worktree/src/brave`. Chromium source and browser build output are
downloaded beside it and intentionally excluded from this repository.

Brave and Chromium initialization requires substantial storage. Keep at least
150 GiB free before running `./scripts/bootstrap-brave.sh --init`; 200 to 250
GiB is recommended for comfortable development and updates.

## Docs

- [Technical architecture](./reverse-engineering-browser.md)
- [System architecture diagram](./system-architecture.md)
- [Version 1 scope](./v1-scope.md)
- [Feature list](./feature_list.md)
- [Workspace architecture](./docs/README.md)
- [Brave integration](./browser/README.md)
