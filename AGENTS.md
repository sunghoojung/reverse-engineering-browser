# Reverse Engineering Browser - Agent Guide

## Mission

Build a local-first browser research harness for authorized reverse engineering.
The product connects low-level browser observations to a normalized evidence
timeline that a human researcher can inspect and work backward from.

Optimize for trustworthy evidence, predictable overhead, and maintainable
systems code. Do not optimize for bypassing access controls or concealing
malicious activity.

## Current scope

Work on these areas:

1. The dependency-free C++ event and queue foundation.
2. The event broker, correlation model, and evidence storage.
3. The local research UI.
4. Versioned contracts between browser probes and the broker.
5. Tracked Brave integration overlays and patches.

MCP is intentionally deferred. Do not create an MCP server, dependency, API,
or documentation unless the user explicitly brings it back into scope.

## Repository map

```text
apps/
  reb-event-demo/       Small concurrency and event-path demonstration
  reb-event-producer/   Deterministic browser-event development producer
  research-ui/          Local human-facing investigation interface
browser/
  config/               Pinned upstream browser revisions
  integration/brave/    Tracked Brave overlays, patches, and instructions
  worktree/             Ignored local Brave and Chromium checkout
docs/                    Architecture and contributor documentation
include/reb/             Public dependency-free C++ headers
protocol/                Versioned event and command contracts
services/event-broker/   Event validation, correlation, storage, and querying
src/                     C++ implementations
tests/                   Native unit and integration tests
tools/                   Developer and offline analysis tools
```

## Source ownership

- This repository is the only project repository.
- `browser/worktree/` is an ignored upstream checkout. Never stage or commit it.
- Store authored Brave files under `browser/integration/brave/overlay/` using
  the same relative path they have inside `brave-core`.
- Store minimal upstream edits under `browser/integration/brave/patches/`.
- A browser integration change is incomplete until its overlay or patch is
  reproducible from a clean pinned upstream checkout.
- Do not edit generated files or changelogs.

## Architecture boundaries

The intended evidence path is:

```text
native probe -> bounded renderer transport -> browser-process bridge
             -> event broker -> evidence store -> research UI
```

- Page JavaScript must not be the authoritative probe layer.
- Renderer probes must not write files, open harness sockets, or call the UI.
- The UI reads normalized broker output. It does not instrument pages itself.
- Every cross-process record has an explicit version and fixed ownership.
- Preserve session, navigation, frame, artifact, event, and parent identifiers.
- Keep capture separate from interpretation. Raw evidence must remain available
  even when a later analyzer assigns a different meaning to it.

## Hot-path rules

Browser probes run in sensitive code paths. They must be:

- disabled by default;
- bounded in memory and work per event;
- non-blocking;
- allocation-free on the inactive path;
- explicit about dropped events and sequence gaps;
- observational unless an experiment mode clearly authorizes mutation.

Never silently lose evidence. When a bounded queue is full, increment a visible
drop counter or emit a gap marker as soon as capacity returns.

## Data and privacy

- Default to metadata, sizes, hashes, and stable identifiers.
- Do not capture credentials, authorization headers, cookies, request bodies,
  or personal content by default.
- Any sensitive capture must be session-scoped, visibly enabled, documented,
  and covered by redaction tests.
- Keep all services bound to localhost unless the user explicitly changes the
  threat model.
- Never upload captured evidence automatically.

## C++ standards

- Use C++20 and the standard library unless a dependency has a clear benefit.
- Prefer value types, RAII, explicit ownership, and fixed-width integer types.
- Avoid exceptions and hidden allocation in probe and transport code.
- Make concurrent invariants visible in names, comments, and tests.
- Use acquire and release ordering only where the synchronization contract is
  documented. Prefer simpler correctness over clever lock-free code.
- Keep public protocol structs trivially copyable and guard their ABI with
  `static_assert` checks.
- Format C++ with the repository `.clang-format` configuration.

## UI standards

- Make the evidence chain understandable before adding visual density.
- Every row must expose time, source, category, operation, and correlation IDs.
- Search and filters must never mutate the stored evidence.
- Insert captured values as text, never executable HTML.
- Show loading, empty, disconnected, malformed-event, and sequence-gap states.
- Keep the interface usable with a keyboard and at narrow viewport sizes.

## Change workflow

Do not use the `no-mistakes` skill, gate, remote, or pipeline in this
repository. Use the explicit validation commands below and normal GitHub pull
request checks.

1. Inspect the relevant contract and existing tests before editing.
2. Reproduce bugs through the closest available end-to-end path.
3. Make the smallest coherent architectural change.
4. Add or update tests for behavior, failure, and boundary conditions.
5. Update the nearest README when ownership or usage changes.

Do not mix unrelated cleanup into a feature commit. Preserve user changes in a
dirty worktree and never reset or overwrite them to simplify your task.

## Validation

Run the narrowest relevant checks during development, then run the full local
gate before handing work off:

```sh
make check
make e2e
make sanitize
python3 -m py_compile apps/research-ui/server.py
git diff --check
```

For Brave integration changes, also verify:

1. Overlay paths map to real `brave-core` paths.
2. Patches apply cleanly to the pinned revision.
3. GN files pass `gn format --dry-run` when the browser toolchain is available.
4. The affected target compiles when full Xcode and the Chromium toolchain are
   installed.

If a required platform tool is unavailable, report the exact missing tool and
do not claim that validation passed.

## Definition of done

A change is done only when:

- behavior works through the intended user-facing path;
- limits, drops, malformed input, and disabled behavior are tested;
- documentation matches the implementation;
- no generated checkout or sensitive evidence is staged;
- all available required checks pass;
- remaining validation gaps are stated plainly.
