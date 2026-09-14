---
name: reb-release
description: Build, validate, version, and publish the Reverse Engineering Browser macOS app. Use when preparing a branch, pull request, release tag, or distributable app, not for ordinary local development.
---

# Ship the Reverse Engineering Browser

Keep the published source revision, CI result, and release artifact tied to the
same commit. Local builds prove the developer path, but releases must be built
from a clean CI checkout rather than uploaded from a workstation.

## Establish scope

1. Read `git status --short` and the relevant diff before making changes.
   Preserve unrelated work and do not stage generated output or user data.
2. Classify the request:
   - **Local development:** build and test a change without publishing it.
   - **Source publication:** commit, push, or open a pull request.
   - **Release:** create a version tag and publish a release artifact.
3. Do not commit `build/`, `browser/worktree/`, captured evidence,
   credentials, or generated changelogs. Versioned source, tests, and
   documentation are the release inputs.

## Local development and validation

For a macOS application change, use the normal product path:

```sh
make app
```

Exercise the changed behavior through the application. Use `reb-ui-e2e` for
Origin Trace UI, native shell, packaging, or asset changes. Use
`reb-brave-verify` when a change reaches pinned Brave integration.

Before handing off a change or proposing source publication, run the complete
local gate:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

For native macOS packaging, also run:

```sh
make app-build
codesign --verify --deep --strict "build/Origin Trace.app"
```

Report missing tools and unavailable checks precisely. Do not describe a
skipped check as passing.

## Publish source

Use a small, coherent branch and pull request by default. Use the `codex/`
prefix when creating a branch unless the user specifies another name. Commit
and push only when the user explicitly asks for those external changes.

After pushing, use the repository CI result as the clean-checkout evidence:

- `.github/workflows/ci.yml` runs lint plus the native, UI, end-to-end, and
  sanitizer layers across macOS and Linux as applicable.
- Successful pull requests receive a short-lived macOS application preview
  artifact.

Do not replace CI validation with a locally built application, and do not
publish directly from an unreviewed workstation state.

## Create a release

Create a release only after the intended commit is on `main`, CI is green, and
the user explicitly authorizes the version tag and release publication.

The existing release workflow triggers when a `v*` tag is pushed. It checks out
that exact tag, runs `make check`, builds `Origin Trace.app`, verifies its
signature, archives it, and creates the GitHub release. Confirm the tag points
at the approved `main` commit before pushing it.

The repository currently creates an ad-hoc-signed ZIP, suitable for development
and internal testing. For a public macOS distribution, treat Developer ID
signing, hardened runtime, notarization, stapling, and Gatekeeper verification
as a separate release-hardening requirement. Do not claim that an ad-hoc-signed
artifact is a notarized public release.

## Handoff

State the commit or tag, the validation results, CI status, artifact name, and
distribution status. Separate completed publication from local-only work and
call out any unavailable tool or unsigned or unnotarized artifact.
