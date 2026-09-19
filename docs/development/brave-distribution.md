# Brave distribution builds

The fast `Component_arm64` output is for local probe iteration. It links to
shared libraries in `out/`, so copying only its `.app` does not make a portable
download. Use a separate `Static_arm64` output for a self-contained Apple
silicon app. This is a non-component, non-debug development-channel build,
not an official Brave release. The updater and Sparkle are disabled so the
custom probes cannot be replaced by an automatic stock-browser update.

## Build

Start with a pinned, synchronized Brave checkout as described in
[the browser workspace guide](../../browser/README.md). Use an isolated build
machine or checkout for distribution work so the normal component output stays
available. Keep at least 150 GiB free and preferably 200 to 250 GiB. Install
`sccache` and verify the toolchain first:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave make brave-doctor
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave make brave-probe-check
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave REB_BRAVE_JOBS=8 \
  ./scripts/build-brave-distribution.sh
```

The wrapper selects Brave's `Static` build in `out/Static_arm64`, with Siso and
`sccache`, no debug symbols, no updater, and no signing credentials. The first
build is substantially larger than an incremental component build because
`is_component_build` changes compilation inputs. Do not switch the existing
component output to static or commit either output directory.

Package a specific project version only after the browser build succeeds:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave \
  ./scripts/package-brave-distribution.sh v0.1.4
```

The packager rejects component and updater-enabled outputs, refuses to
overwrite an existing archive, ad-hoc signs a copy of the app, verifies the
signature, and tests an extracted ZIP. It prints the archive's SHA-256 hash.
The generated ZIP is under `build/` by default and is for development testing,
not an automatically published release.

## Release gate

Build the publishable artifact from the intended Git tag in a clean, trusted
CI checkout. Record the tag commit, pinned Brave/Chromium/V8 revisions, build
configuration, checks, and ZIP hash with the release. Test the extracted app
with Origin Trace in a fresh live session, including native fingerprint events
and opt-in Canvas images. Publish only after that gate passes. The
[standard GitHub-hosted macOS runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
does not have enough disk for this source build.

Do not register a personal Mac as a self-hosted runner for this public
repository. [GitHub warns that pull-request code can compromise public-repo
self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use).
Use an isolated build host with a trusted-only job trigger and no personal
credentials instead. Until that infrastructure exists, the local ZIP is a
verified development preview, not the source of an official release asset.

Ad-hoc signing is not Developer ID signing or notarization. A broadly
distributed macOS browser also needs hardened-runtime signing, notarization,
stapling, and Gatekeeper verification before it should be described as a
normal public installer.
