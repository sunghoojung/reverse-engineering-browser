---
name: reb-ui-e2e
description: Reproduce and verify Origin Trace through its user-facing UI. Use for UI bugs or features, visual regressions, keyboard and narrow-layout behavior, native macOS packaging, application assets, and user-visible evidence states. Do not use for backend-only testing.
---

# Verify Origin Trace End to End

Prove behavior through the interface a researcher actually uses. Unit and API
tests support this workflow but do not replace visual and interaction evidence.

## Prepare the user path

1. Read the `UI standards` and `Validation` sections in
   [AGENTS.md](../../../AGENTS.md), then read the run instructions in
   [apps/research-ui/README.md](../../../apps/research-ui/README.md).
2. Inspect the relevant UI tests and implementation before changing anything.
3. For a bug, reproduce it before editing through the closest user-facing path.
   Record the exact state, action, and visible failure.
4. Use `make app` for the normal macOS product path. Use `make ui` only for
   browser-based development or when the native path is genuinely unavailable.
5. Use deterministic demo evidence or a bounded temporary fixture. Do not point
   the app at sensitive captures unless the user explicitly placed them in
   scope.

## Exercise behavior

Use available app or browser UI control to interact with the rendered product.
Verify the changed workflow from launch to visible outcome, then inspect a
fresh screenshot. State explicitly when UI control or screenshot capability is
unavailable.

Cover the states relevant to the change, including failure and boundary states.
For shared timeline or shell work, check loading, empty, disconnected,
malformed-event, and sequence-gap behavior. Confirm that the last known-good
evidence remains understandable when a refresh fails.

Check interaction quality:

- complete the primary flow with the keyboard;
- inspect the narrowest supported practical window or viewport;
- verify focus visibility, scrolling, truncation, overlays, and selected state;
- confirm captured values render as text and cannot become executable markup;
- reject clipped controls, overlapping content, unexplained blank space, or
  unreadable evidence relationships.

For native shell, bundle, icon, or packaging changes, run the additional app
build and code-signing checks required by `AGENTS.md`. Verify the packaged app
loads its bundled assets at runtime rather than relying on source-tree paths.

## Test and compare

Run the directly related UI unittest module while iterating, then `make ui-test`
for the complete UI suite. Use `reb-validation` for the final repository gate.
After a fix, repeat the original reproduction steps and compare the same state
before and after. Do not accept a passing HTTP response or DOM assertion as the
sole proof of a visual change.

## Report evidence

State which product path was tested, which states and interactions were
covered, and what the user now sees. List the commands that passed and identify
screenshots or other visual evidence when available. Report untested states and
missing platform capabilities plainly.
