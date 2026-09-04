# Reverse Engineering Browser

Native browser observability for authorized reverse engineering.

[![Continuous integration](https://github.com/sunghoojung/reverse-engineering-browser/actions/workflows/ci.yml/badge.svg)](https://github.com/sunghoojung/reverse-engineering-browser/actions/workflows/ci.yml)

Reverse Engineering Browser is a local-first research harness built around a
custom Brave integration. Dormant native C++ probes capture selected browser
behavior, move bounded records through the browser process, and persist
normalized evidence for inspection in the Origin Trace macOS application.

The project is an active research prototype. Its native event path, broker,
evidence stores, artifact channel, deterministic producer, Origin Trace
interface, and tracked Brave overlays are implemented and tested. The custom
browser build remains an advanced workflow because it uses the full Brave and
Chromium toolchain.

## Why this exists

Page-level JavaScript hooks can miss browser-internal context and can change
the environment being studied. This project observes selected native browser
boundaries while keeping the capture path separate from interpretation.

The result is an evidence trail designed to answer questions such as:

- Which script, frame, worker, or WebAssembly artifact caused an event?
- Which browser signals contributed to a network request?
- Where did a value originate, and what evidence supports that conclusion?
- Can a hypothesis be tested in a disposable context without changing the
  baseline capture?

## Architecture

```text
native probe -> bounded renderer transport -> browser-process bridge
             -> local event broker -> evidence store -> Origin Trace
```

![Reverse Engineering Browser system architecture](./docs/architecture/system-architecture.svg)

The design keeps renderer work bounded and non-blocking, preserves raw evidence
alongside later interpretations, and makes dropped events and sequence gaps
visible. Cross-process records are versioned and retain session, navigation,
frame, artifact, event, and parent identifiers.

## What is implemented

| Area | Current proof point |
| --- | --- |
| Native capture foundation | C++20 fixed-size events, bounded shared-memory queues, disabled fast paths, and explicit drop accounting |
| Broker and evidence | Authenticated local sockets, validation, correlation, sequence-gap detection, JSONL evidence, and versioned contracts |
| Artifact capture | Acknowledged, bounded transfer of immutable JavaScript and WebAssembly blobs with SHA-256 manifests |
| Debugger transport | Dependency-free C++20 loopback WebSocket transport with bounded, versioned private pipes to the Python state adapter |
| Origin Trace | Native macOS application plus a browser-only development path for request-first evidence inspection, sources, memory analysis, and experiments |
| Brave integration | Reproducible overlays and ordered patches pinned to specific Brave and Chromium revisions |
| Verification | Native unit tests, socket and application end-to-end tests, sanitizers, repository hygiene checks, and macOS bundle verification in CI |

The [feature roadmap](./docs/product/feature-list.md) separates the broader
product direction from the currently proven vertical slices. Detailed design
and subsystem contracts live in the [documentation index](./docs/README.md).

## Quick start

Requirements for the local foundation:

- a C++20 compiler;
- Python 3;
- zlib headers and library;
- GNU Make or a compatible `make` implementation.

Build and run the test suite:

```sh
make check
make e2e
./build/reb-event-demo
```

On macOS, build demo evidence and open the native Origin Trace application:

```sh
make app
```

For browser-based UI development on any supported host:

```sh
make ui
```

Then open `http://127.0.0.1:7319`. The native application is the normal product
path; the local server is a development convenience.

## Custom Brave integration

Preparing and building Brave is optional for work on the native foundation,
broker, evidence contracts, and deterministic UI path.

Prepare the pinned upstream checkout without downloading Chromium:

```sh
./scripts/bootstrap-brave.sh
```

Initialize Chromium, apply the repository-owned integration, and verify the
native probe target:

```sh
./scripts/bootstrap-brave.sh --init
./scripts/sync-browser-integration.sh
make brave-doctor
make brave-probe-check
```

Normal live sessions route the browser-facing DevTools WebSocket through the
bounded C++ debugger transport. Python retains the existing HTTP contracts,
CDP interpretation, and debugger state.

For a capture that must not attach DevTools to the live page, start native
quiet mode:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

This mode does not open a remote-debugging endpoint or start the CDP debugger
bridge. The patched V8 runtime treats page-authored `debugger;` statements as
no-ops before Inspector handling, while the native evidence probes and captured
Sources remain available. Live Page sources, breakpoints, stepping, watches,
and the console are intentionally unavailable in this mode. This removes the
debugger attachment and pause signals; it does not promise that arbitrary code
cannot fingerprint the custom browser or measure instrumentation overhead.

Initialization needs at least 150 GiB of free space; 200 to 250 GiB is the
practical recommendation. The default shallow-history mode avoids unnecessary
Git history. Use `--full-history` only when an investigation requires it.

The generated upstream checkout lives under `browser/worktree/` and is never
tracked. All project-owned Brave files live in mirrored overlays or minimal
ordered patches under `browser/integration/brave/`.

## Engineering principles

- Local by default: services bind to loopback or user-only local sockets, and
  captured evidence is never uploaded automatically.
- Bounded by design: probe work, queues, payloads, searches, and experiments
  have explicit limits and visible failure states.
- Evidence before inference: raw observations remain available when later
  analyzers assign meaning or confidence.
- Privacy-aware capture: credentials, authorization headers, cookies, request
  bodies, and personal content are excluded by default.
- Reproducible integration: browser changes must apply cleanly to the pinned
  upstream revisions from a clean checkout.

This software is intended only for systems you own or are explicitly
authorized to assess. It is not designed to bypass access controls or conceal
malicious activity.

## Repository map

```text
.agents/skills/         repository-specific agent validation workflows
apps/                   demos, producers, and the Origin Trace interface
browser/                pinned Brave integration and ignored upstream checkout
docs/                   architecture, product direction, and feature designs
include/ and src/       dependency-free native event foundation
protocol/               versioned event, trace, and command contracts
services/               local event broker and artifact receiver
tests/                  native, socket, integration, and UI tests
tools/                  offline validation and analysis utilities
```

## Development

Run the complete local quality gate before handing off a change:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

CI runs source formatting, shell, Python, workflow, repository hygiene, native,
end-to-end, sanitizer, and macOS application checks. Version tags matching
`v*` build a locally signed macOS archive and publish it through GitHub
Releases.

Start with [CONTRIBUTING.md](./CONTRIBUTING.md) before making a change. Coding
agents should also read [AGENTS.md](./AGENTS.md) and use the repository skills
under `.agents/skills/` for UI, Brave, and handoff validation.

## Documentation

- [Documentation index](./docs/README.md)
- [Technical architecture](./docs/architecture/technical-architecture.md)
- [System architecture](./docs/architecture/system-architecture.md)
- [Feature roadmap](./docs/product/feature-list.md)
- [Feature catalog](./docs/product/feature-catalog.md)
- [Origin Trace application](./apps/research-ui/README.md)
- [Brave workspace](./browser/README.md)
