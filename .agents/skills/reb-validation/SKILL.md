---
name: reb-validation
description: Validate Reverse Engineering Browser changes and report evidence for handoff. Use for focused test selection, full local gates, or failure triage. Route user-visible Origin Trace work and Brave integration work to their dedicated skills.
---

# Validate Reverse Engineering Browser

Select the smallest useful feedback loop while developing, then produce a
complete and auditable handoff result.

## Establish scope

1. Read `Validation` and `Definition of done and handoff` in
   [AGENTS.md](../../../AGENTS.md). That file owns the current gate.
2. Inspect `git status --short` and the relevant diff. Preserve pre-existing
   changes and exclude the generated `browser/worktree/` checkout.
3. Identify every affected boundary, not only the edited filenames. Shared
   contracts require checks for each producer and consumer.
4. Add `reb-ui-e2e` for user-visible Origin Trace behavior. Add
   `reb-brave-verify` for browser pins, bootstrap, synchronization, overlays,
   patches, or compilation.

Do not use `no-mistakes`, a remote gate, or a substitute validation pipeline.

## Choose focused checks

| Changed surface | First useful evidence |
| --- | --- |
| One C++ component | Its directly related test binary, then `make test` if shared code is involved |
| Broker, IPC, producer, artifact transfer, or evidence store | Related native test plus the matching socket test or `make e2e` |
| Research UI Python | The directly related unittest module, then `make ui-test` |
| Origin Trace HTML, JavaScript, Swift, packaging, or assets | `reb-ui-e2e` plus the directly related automated tests |
| Shell, Python, workflow, or repository tooling | The matching Makefile lint target and fixture test |
| Documentation or repository skills | Workspace and repository hygiene checks, link inspection, skill validation, and `git diff --check` |
| Brave integration or setup | Relevant fixture tests plus `reb-brave-verify` |

Prefer behavior and contract checks over tests that only match implementation
wording. A syntax check does not replace the configured linter or an
end-to-end path.

## Run the handoff gate

Before handing off a repository change, run the complete command block from
`AGENTS.md`, even when focused checks passed. Add its documented macOS or Brave
checks when those surfaces changed. Do not silently narrow the gate because of
elapsed time.

Review the final diff after testing. Confirm it contains no generated checkout,
build output, captured evidence, secrets, or unrelated user changes.

## Handle failures

- Preserve the first actionable failure and its command output.
- Continue only with independent checks that can add useful evidence without
  obscuring the first failure.
- In a validation-only request, do not edit product code to repair a failure.
- Distinguish product failures from missing tools, unavailable platform
  toolchains, dirty upstream state, and pre-existing worktree failures.
- Never label a skipped or unavailable check as passing.

## Report evidence

Give every required check one status: passed, failed, unavailable, or skipped.
For anything other than passed, state the exact reason and a focused reproduction
command when one exists. End with the overall result and the remaining risk or
validation gap.
