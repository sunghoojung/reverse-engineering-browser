# Origin Trace v0.3.2 companion release

> Historical record of the published v0.3.2 release. Current source is the
> v0.5.0 paired release; see [paired-release.md](paired-release.md). The
> companion workflow now skips paired sources on pull requests and refuses to
> publish them.

This procedure publishes only Origin Trace. It does not build, upload or certify
Brave. Do not use the paired release workflow or substitute the historical Brave
archive for native compatibility evidence.

## Acceptance

1. Complete the Traffic integration and required review; merge only after all
   required checks pass. Keep the release preparation separate until then.
2. On the final source, run `make lint`, `make check`, `make e2e`,
   `make sanitize` and `git diff --check`. Review rendered Traffic behavior.
3. The companion pull-request workflow on cloud macOS builds the app, verifies
   its signature, runs `check-origin-trace-package.mjs` with stock Chrome and
   `check-origin-trace-native-close.mjs`, and archives the tested candidate.
   It also runs `node tools/check-companion-warning.mjs`: actual XCUITest input
   exercises the production compatibility alert, default/click Continue Offline,
   explicit Start Unverified Session, failure Retry, later sessions and modal
   reopen. An owned fake Development executable only records a launch and exits;
   exact launch counts and named screenshots are checked outside the UI-test
   sandbox. Inspect package/native-close/warning diagnostics. These tests require
   cloud macOS execution; authoring or source-contract checks alone do not pass
   native interaction acceptance. They establish no real-browser compatibility.
4. Confirm the release scope and disclose that the historical Development browser
   is not a validated native pair. New native VM/runtime-buffer functionality
   requires a compatible separately built browser and independent acceptance.

## Publication

After approval, manually dispatch `release-companion.yml` on the reviewed main
revision with its full 40-character `source_sha`. That SHA must still be main when
checked out. The workflow reruns package acceptance, records an immutable artifact
ID, and downloads those bytes into a read-only checkout for publication. Only the
publish job has `contents: write`; it creates a fresh `v0.3.2` tag and release and
verifies the remote asset sizes and SHA256 digests. Existing tags/releases are
never replaced or adopted. A failed partial publication needs inspection, not a
blind retry or tag deletion.

Assets are the macOS arm64 ZIP, companion provenance and SHA256SUMS. The ZIP's
Info.plist must match the source version, build number and companion release type.
The artifact is ad-hoc signed and not notarized. There is no universal/Intel,
Windows or Linux application artifact.

`OriginTraceReleaseType` in Info.plist explicitly selects the companion path.
Missing values remain the historical paired mode; unknown values fail closed.
The paired tag workflow excludes v0.3.2. Its browser source-equivalence, checksum
and full paired acceptance requirements are unchanged.

Normal live launch still discovers only the Development bundle. Its identity is
not a capability proof, so companion builds warn before starting it. The existing
explicit launcher/backend path can use stock Chrome CDP; the package test uses
that path with a disposable profile. This does not make Chrome a native capture
replacement. Missing-browser startup and explicit offline operation remain
supported.
