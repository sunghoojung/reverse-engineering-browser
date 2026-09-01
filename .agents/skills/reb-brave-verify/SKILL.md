---
name: reb-brave-verify
description: Verify Reverse Engineering Browser bootstrap, pins, Brave overlays, patches, synchronization, and browser compilation. Use when project-owned browser integration must reproduce against the pinned upstream checkout and strongest available Brave toolchain.
---

# Verify the Brave Integration

Prove that project-owned browser changes reproduce from the pinned Brave and
Chromium revisions and compile at the strongest locally available layer.

## Establish ownership and upstream state

1. Read the browser-specific rules and validation steps in
   [AGENTS.md](../../../AGENTS.md).
2. Read [browser/README.md](../../../browser/README.md) and
   [browser/integration/brave/README.md](../../../browser/integration/brave/README.md).
3. Inspect the project diff and both revision pins. Complete authored files must
   live in the mirrored overlay; minimal upstream edits must live in ordered
   patches.
4. Inspect the relevant upstream checkout for local modifications before
   synchronizing. `browser/worktree/` is generated external state and must never
   be staged, committed, cleaned, or repaired implicitly.

A revision mismatch or dirty upstream checkout is a stop condition for any
operation that would overwrite it. Report the exact state and leave it intact.

## Prove reproducibility in layers

1. Run the relevant bootstrap fixture test when revision handling or bootstrap
   behavior changed.
2. Run the synchronization fixture test for pins, overlays, patches, or sync
   behavior.
3. Confirm every overlay destination is a real path at the pinned revision and
   every patch preflights and applies cleanly in order.
4. Run `make brave-doctor`. Do not change the system-wide Xcode selection.
5. When the initialized checkout is at the expected revisions and safe to use,
   apply changes only through `./scripts/sync-browser-integration.sh`.
6. Run `make brave-probe-check` for the exact native probe target. For changed
   GN files, run `gn format --dry-run` with the bundled browser toolchain. Build
   each affected target when full Xcode and Chromium tooling are installed.

Never copy or patch files into the checkout by hand. Repository fixtures prove
tracked synchronization behavior but do not substitute for a real pinned
checkout or browser compile.

## Review browser invariants

Confirm capture remains disabled by default, inactive paths are allocation-free,
active work is bounded and non-blocking, drops are visible, and observational
capture does not mutate page behavior. Test failure, disabled, capacity,
expiration, and sequence-gap behavior when the change reaches those concerns.

## Report evidence

Report:

- pinned Brave and Chromium revisions;
- upstream revision and dirty-state results;
- overlay and patch reproducibility;
- doctor and native probe target results;
- GN formatting and affected compile results.

Mark each layer passed, failed, unavailable, or skipped, with the exact reason
for anything other than passed. Do not report a browser build as passing when
only fixtures or the native probe target passed. Use `reb-validation` for the
remaining repository gate.
