---
name: reb-brave-verify
description: Verify Reverse Engineering Browser changes to the tracked Brave integration, bootstrap flow, overlays, or patches. Use for browser integration work that must reproduce against pinned upstream checkouts and compile with the available Brave toolchain.
---

# Verify the Brave Integration

Prove that project-owned browser changes remain reproducible from the pinned
upstream revisions and work in the strongest locally available toolchain.

## Establish ownership and state

1. Read `Source ownership` and the Brave portion of `Validation` in
   [AGENTS.md](../../../AGENTS.md).
2. Read [browser/README.md](../../../browser/README.md) and
   [browser/integration/brave/README.md](../../../browser/integration/brave/README.md)
   for the current setup and synchronization contract.
3. Inspect the project diff and both pinned revision files. Confirm each authored
   file is in the mirrored overlay and each minimal upstream edit is in an
   ordered patch.
4. Treat `browser/worktree/` as external generated state. Never stage or commit
   it. Before applying integration changes, check the relevant upstream
   checkouts for local modifications and stop rather than overwrite unrelated
   work.

## Validate in layers

Start with repository-owned deterministic checks:

- run the bootstrap fixture test when bootstrap behavior or revision handling
  changed;
- run the browser synchronization fixture test for overlays, patches, pins, or
  sync behavior;
- verify overlay destinations correspond to real paths in the pinned checkout;
- verify every patch preflights and applies cleanly at its pinned revision.

Then run `make brave-doctor`. Use its result to decide which deeper checks are
actually available. Do not change the system-wide Xcode selection to make the
check pass.

When the initialized pinned checkout is clean enough to use, apply the tracked
integration through the repository synchronization script. Never copy or patch
files into the checkout by hand. Run `make brave-probe-check` for the exact
native probe target. If GN files changed, run `gn format --dry-run` with the
browser toolchain. Compile the affected target when the complete Xcode and
Chromium toolchain are installed.

Preserve the hot-path invariants while reviewing results: capture is disabled
by default, inactive work is allocation-free, active work is bounded and
non-blocking, drops are visible, and observation does not mutate page behavior.
Verify failure, disabled, capacity, expiration, and sequence-gap behavior when
the change can affect them.

## Stop safely

- A revision mismatch, dirty upstream checkout, failed patch preflight, or
  missing toolchain component is a concrete stop condition for the affected
  layer.
- Do not repair or discard upstream checkout changes unless the user explicitly
  asks.
- Do not claim a browser build passed when only repository fixtures or the
  native probe unit target passed.

## Report evidence

Report the pinned Brave and Chromium revisions, upstream dirty-state result,
overlay and patch reproducibility, probe-target result, GN formatting result,
and affected compile result. Mark each layer passed, failed, unavailable, or
skipped, with the exact reason for anything other than passed. Use
`reb-validation` for the remaining repository gate.
