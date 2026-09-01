---
name: reb-ui-e2e
description: Reproduce and verify Origin Trace through its user-facing interface. Use for UI behavior, visual regressions, keyboard or narrow-layout work, native macOS packaging, and application assets. Do not use for backend-only changes.
---

# Verify Origin Trace End to End

Prove the changed behavior through the interface a researcher uses. Automated
tests support this workflow but do not replace interaction and visual evidence.

## Prepare the product path

1. Read `Origin Trace UI` and `Validation` in
   [AGENTS.md](../../../AGENTS.md), then read
   [apps/research-ui/README.md](../../../apps/research-ui/README.md).
2. Inspect the relevant implementation and UI tests. For a bug, record the
   exact starting state, action, and visible failure before editing.
3. Use `make app` for the normal macOS product path. Use `make ui` only for
   browser development or when native app control is unavailable.
4. Use deterministic demo evidence or a bounded temporary fixture. Do not open
   sensitive captures unless the user explicitly placed them in scope.

## Exercise the interface

Use available UI control to complete the changed workflow from launch to the
visible outcome. For the browser development path, prefer
`npx -y chrome-devtools-axi` when available. After each state-changing action,
verify the result with a fresh snapshot or screenshot.

Cover the states the change can affect. Shared shell and timeline work normally
requires loading, empty, disconnected, malformed-event, sequence-gap, and
refresh-failure states. Confirm that refresh failures preserve the last
understandable evidence.

Check interaction quality at the same time:

- complete the primary flow with the keyboard and inspect focus visibility;
- test the narrowest practical supported window or viewport;
- inspect scrolling, truncation, overlays, selected state, and long content;
- confirm captured values remain inert text rather than executable markup;
- reject clipped controls, overlaps, unexplained blank space, and unreadable
  evidence relationships.

For native shell, bundle, icon, or packaging work, verify that the packaged app
loads bundled assets at runtime rather than source-tree paths. Run the app build
and strict code-signature checks from `AGENTS.md`.

## Compare and test

Run the directly related UI unittest while iterating, then `make ui-test`. After
the change, repeat the original reproduction steps in the same state and compare
the visible result. A successful HTTP response, process launch, DOM assertion,
or screenshot alone is not sufficient evidence of an interactive fix.

Use `reb-validation` for the final repository gate.

## Report evidence

State which product path, viewport or window size, states, pointer actions, and
keyboard interactions were tested. Describe what the user now sees and identify
the fresh visual evidence. Mark untested states and unavailable UI-control or
platform capabilities explicitly.
