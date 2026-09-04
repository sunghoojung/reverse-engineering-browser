# Reverse Engineering Browser - Agent Guide

This file is the authoritative operating contract for coding agents working in
this repository. The Makefile owns executable commands, subsystem READMEs own
local operating details, and versioned files under `protocol/` own wire and
storage contracts.

## Start every task here

1. Read `git status --short` and the relevant diff. Existing changes belong to
   the user unless proven otherwise. Never reset, clean, overwrite, or reformat
   unrelated work.
2. Read the nearest subsystem README, public contract, and existing tests before
   editing. Use `rg` and `rg --files`, excluding `browser/worktree/`.
3. Classify the affected surface and load the matching repository skill:

   | Surface | Required skill |
   | --- | --- |
   | Any implementation handoff or validation failure | `reb-validation` |
   | Origin Trace UI, native app, packaging, assets, keyboard use, or visual behavior | `reb-ui-e2e` |
   | Brave bootstrap, pins, overlays, patches, or browser compilation | `reb-brave-verify` |

4. For bug fixes, reproduce the problem through the closest user-facing path
   before editing. Record the state, action, and visible or observable failure.
5. Make the smallest coherent change, test it at the narrowest useful layer,
   then run the complete handoff gate.

Do not use the `no-mistakes` skill, remote gate, or alternate pipeline in this
repository. Use the repository skills under `.agents/skills/` and the commands
defined here.

## Mission and boundaries

Build a local-first browser research harness for authorized reverse
engineering. Connect low-level browser observations to a normalized evidence
timeline that a researcher can inspect and work backward from.

Optimize for trustworthy evidence, predictable overhead, maintainable systems
code, and reproducible browser integration. Do not optimize for bypassing
access controls or concealing malicious activity.

Current project scope:

1. Dependency-free C++ event and queue foundations.
2. Event validation, correlation, evidence storage, and artifact transfer.
3. The native Origin Trace application and browser-only development UI.
4. Versioned contracts between probes, browser processes, services, and UI.
5. Tracked Brave integration overlays, patches, pins, and bootstrap tooling.

MCP is intentionally deferred. Do not create an MCP server, dependency, API, or
documentation unless the user explicitly restores it to scope.

## Repository ownership

```text
.agents/skills/         Task-specific validation workflows
.github/workflows/      Pull request checks and release builds
apps/                   Demos, producers, analysis tools, and Origin Trace
browser/config/         Pinned upstream Brave and Chromium revisions
browser/integration/    Tracked browser overlays, patches, and instructions
browser/worktree/       Ignored generated Brave and Chromium checkout
docs/architecture/      System design and diagrams
docs/product/           Roadmap, feature catalog, and versioned designs
include/reb/ and src/    Public C++ interfaces and implementations
protocol/               Versioned event, trace, storage, and command contracts
services/               Event broker and artifact receiver
tests/                  Native, socket, fixture, integration, and UI tests
tools/                  Offline validation and analysis utilities
```

Ownership rules:

- This is the only project repository. Never stage or commit
  `browser/worktree/`; it is a reproducible upstream checkout.
- Put complete project-authored Brave files in
  `browser/integration/brave/overlay/` at their real `brave-core` relative
  paths. Put minimal upstream edits in ordered patches under
  `browser/integration/brave/patches/`.
- A browser change is incomplete until overlays and patches reproduce from the
  pinned revisions through the synchronization script.
- Never edit generated files, generated checkouts, changelogs, or captured
  evidence unless the task explicitly targets that evidence.
- Keep product and architecture documents under `docs/`. Keep operating
  instructions beside their subsystem. Keep the root README focused on the
  product, setup, quality signals, repository map, and documentation routes.
- When moving documentation, update inbound links and remove obsolete copies.

## Architecture invariants

The intended evidence path is:

```text
native probe -> bounded renderer transport -> browser-process bridge
             -> event broker -> evidence store -> research UI
```

- Page JavaScript is never the authoritative probe layer.
- Renderer probes never write files, open harness sockets, call the UI, or wait
  for storage or analysis.
- The UI consumes normalized broker output and never instruments pages itself.
- Every cross-process record has an explicit version and fixed ownership.
- Preserve session, navigation, frame, execution context, artifact, event, and
  parent identifiers across boundaries.
- Keep capture separate from interpretation. Preserve raw evidence when an
  analyzer assigns or later revises meaning.
- Keep all services on localhost or user-only local transports unless the user
  explicitly changes the threat model.

## Hot-path, data, and privacy rules

Browser probes run in sensitive execution paths. They must remain disabled by
default, allocation-free while inactive, bounded in memory and per-event work,
non-blocking, and observational unless a visibly enabled experiment authorizes
mutation.

Never lose evidence silently. A full queue must increment a visible drop
counter or emit a gap marker as soon as capacity returns. Test disabled,
capacity, expiration, malformed-input, and sequence-gap behavior whenever a
change can affect those states.

Default capture to metadata, sizes, hashes, stable identifiers, and bounded
previews. Do not capture credentials, authorization headers, cookies, request
bodies, or personal content by default. Sensitive capture must be
session-scoped, visibly enabled, documented, and covered by redaction tests.
Never upload evidence automatically.

## Engineering standards

### C++ and concurrency

- Use C++20 and the standard library unless a dependency has a clear
  architectural benefit.
- Prefer value types, RAII, fixed-width integers, and explicit ownership.
- Avoid exceptions and hidden allocation in probes and transports.
- State concurrent invariants in names, comments, and tests. Use acquire and
  release ordering only when the synchronization contract is documented.
- Keep public protocol structs trivially copyable and protect their ABI with
  `static_assert` checks.
- Format C++ with the repository `.clang-format` configuration.

### Origin Trace UI

- Make the evidence chain understandable before adding visual density.
- Every evidence row exposes time, source, category, operation, and correlation
  identifiers.
- Search and filters never mutate stored evidence. Captured values are inserted
  as text, never executable HTML.
- Cover loading, empty, disconnected, malformed-event, and sequence-gap states.
  Preserve the last understandable evidence when refresh fails.
- Verify keyboard use, visible focus, narrow layouts, scrolling, truncation,
  overlays, and selected state. Reject clipped controls, collisions, unexplained
  blank space, and unreadable relationships.
- `make app` is the normal macOS product path. `make ui` is only for browser
  development or when the native path is unavailable.
- Keep native assets under `apps/research-ui/macos/` and verify the packaged app
  loads them rather than source-tree paths.

### Scripts, contracts, and documentation

- Keep shell and Python entry points deterministic, non-interactive by default,
  and explicit about missing tools or partial results.
- Treat protocol schemas, public C++ structs, socket records, and evidence files
  as versioned compatibility boundaries. Update producers, consumers, tests,
  fixtures, and nearby documentation together.
- Document why a boundary or limit exists. Avoid comments and docs that merely
  restate the code.
- Prefer relative repository links and verify them after moving or renaming
  files.

## Change workflow

1. Reproduce or characterize the current behavior at the closest end-to-end
   boundary.
2. Inspect the relevant contract, producer, consumer, and tests.
3. Implement the smallest architectural change that preserves the invariants
   above.
4. Add tests for success, failure, disabled behavior, and relevant limits.
5. Update the nearest README or versioned design when ownership, operation, or
   user-visible behavior changes.
6. Review the final diff for unrelated edits, generated files, sensitive data,
   and accidental changes under `browser/worktree/`.

Do not mix unrelated cleanup into a feature change. If a pre-existing problem
blocks the task, report it with evidence instead of overwriting user work.

## Validation

Use `reb-validation` to select focused feedback while developing. Before
handing off any repository change, run the complete local gate:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

For Origin Trace HTML, JavaScript, Swift, native packaging, application assets,
or user-visible behavior, also use `reb-ui-e2e`. For app, packaging, or icon
changes, run:

```sh
make app-build
codesign --verify --deep --strict "build/Origin Trace.app"
```

For changes under `browser/integration/brave/`, browser pins, bootstrap, or
synchronization:

1. Verify fixture-based bootstrap or sync behavior as applicable.
2. Verify overlay destinations exist at the pinned revision.
3. Verify every patch preflights and applies cleanly.
4. Run `make brave-doctor` without changing global Xcode selection.
5. Run `make brave-probe-check` when the initialized toolchain is available.
6. Run `gn format --dry-run` for changed GN files and compile the affected
   target when full Xcode and Chromium tooling are installed.

Never report an unavailable or skipped check as passing. State the exact
missing tool, first actionable failure, or dirty upstream condition.

## Definition of done and handoff

A change is complete only when:

- behavior works through the intended user-facing or system boundary;
- limits, drops, malformed input, disabled behavior, and privacy controls are
  tested where relevant;
- documentation and contracts match the implementation;
- no generated checkout, build output, sensitive capture, or unrelated user
  change is included;
- every available required check passes;
- each unavailable or skipped check has an exact reason.

In the final handoff, lead with what now works. List changed files by purpose,
report each required validation command as passed, failed, unavailable, or
skipped, and end with any remaining risk or the next concrete action.
