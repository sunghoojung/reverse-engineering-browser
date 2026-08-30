---
name: reb-validation
description: Select and run evidence-backed validation for Reverse Engineering Browser changes. Use when testing, verifying, preparing a handoff, or investigating a local check failure. Route interactive Origin Trace acceptance and Brave toolchain verification to their dedicated skills.
---

# Validate Reverse Engineering Browser

Produce a trustworthy validation result with the smallest useful feedback loop
during development and the complete required gate before handoff.

## Establish scope

1. Read the `Validation` and `Definition of done` sections in
   [AGENTS.md](../../../AGENTS.md). They are authoritative if commands change.
2. Inspect the working tree and relevant diff before choosing checks. Treat
   pre-existing modifications as user work and do not clean, reset, format, or
   overwrite them.
3. Exclude `browser/worktree/` from repository searches and Git operations. It
   is an ignored upstream checkout, not project source.
4. Do not use the `no-mistakes` skill, a remote gate, or an alternate pipeline.

## Choose the validation depth

For a development check, start with the smallest command that exercises the
changed behavior. Follow dependencies rather than matching filenames only:

- Shared C++ headers or implementations can affect every native test. Run the
  directly related test binary first, then `make test` when shared behavior is
  involved.
- Broker, artifact receiver, IPC, producer, or evidence-store changes usually
  need the related socket test or `make e2e` in addition to unit tests.
- Research UI Python changes should start with the directly related unittest
  module. HTML, JavaScript, Swift, packaging, or user-visible behavior also
  needs the `reb-ui-e2e` workflow.
- Shell, Python, workflow, and repository-hygiene changes should use the
  matching Makefile lint target. Do not substitute syntax checks for the
  repository's configured linters.
- Browser bootstrap or integration-sync script changes need their fixture-based
  tests. Changes under `browser/integration/brave/` also need the
  `reb-brave-verify` workflow.

When handing off an implementation, run the complete local gate from
`AGENTS.md`, even if focused checks already passed. Add the documented macOS or
Brave checks when those surfaces changed. Do not silently reduce the gate based
on elapsed time.

## Handle failures

- Preserve the first actionable failure and its command output.
- Continue with independent checks only when they can reveal additional useful
  information without masking the first failure.
- If the request is validation-only, do not edit source to repair failures.
- Distinguish a product failure from a missing platform tool, unavailable
  toolchain, or pre-existing dirty-worktree issue.
- Never report a skipped or unavailable check as passing.

## Report evidence

Give each required command one status: passed, failed, unavailable, or skipped.
For anything other than passed, state the exact reason. End with the overall
result and any remaining validation gap. Include a focused reproduction command
when a failure remains.
