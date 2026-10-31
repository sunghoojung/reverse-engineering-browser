# Origin Trace + Brave v0.5.0 paired release

A paired release publishes Origin Trace together with the exact Brave Browser
Development build it was accepted with. v0.5.0 pairs the app with a new browser
built locally from the pinned sources in [`browser/config/`](../../browser/config)
(Brave `v1.95.52`, Chromium `151.0.7922.108`) and this repository's overlays and
patches. The historical companion-only path is recorded in
[companion-release.md](companion-release.md).

The browser is not built in clean CI: the
[standard hosted runner lacks the disk](brave-distribution.md#release-gate).
The release discloses that it is a local workstation build, ad-hoc signed, not
notarized and not an official Brave release. CI fetches it from a pinned URL and
checks it against pinned SHA-256 digests, the browser-input equivalence of the
build commit and the app's pairing pin before anything is published.

## 1. Build and package the browser

On the build workstation, from a pinned and synchronized checkout at the commit
that will be recorded as `build_source`:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave ./scripts/build-brave-distribution.sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave \
  ./scripts/package-brave-distribution.sh v0.5.0
```

The packager prints the ZIP's SHA-256. After this, the browser inputs listed in
[`scripts/prepare-release-brave.sh`](../../scripts/prepare-release-brave.sh)
(`browser`, `include`, `src`, `protocol`, `services` and the Brave scripts)
must not change before the release, or CI refuses the pair.

## 2. Record identity and provenance

Extract the ZIP into a fresh directory, then read the app's CDHash and version:

```sh
zip=build/Brave-Browser-Development-v0.5.0-macos-arm64.zip
check="$(mktemp -d)"
ditto -x -k "$zip" "$check"
app="$check/Brave Browser Development.app"
codesign --verify --deep --strict "$app"
cdhash="$(codesign -dvvv "$app" 2>&1 | sed -n 's/^CDHash=//p')"
version="$("$app/Contents/MacOS/Brave Browser Development" --version)"
python3 tools/write-brave-provenance.py \
  --zip "$zip" \
  --sha256 <SHA-256 printed by the packager> \
  --source-commit <full build_source commit> \
  --build-args /absolute/path/to/src/out/Static_arm64/args.gn \
  --executable-version "$version" \
  --cdhash "$cdhash"
```

[`write-brave-provenance.py`](../../tools/write-brave-provenance.py) is
deterministic and offline. It writes
`Brave-Browser-Development-v0.5.0-macos-arm64.provenance.json` beside the ZIP,
refuses to replace an existing file, and prints the record's SHA-256. It:

- verifies the ZIP name and SHA-256 and records its size;
- reads the Brave, Chromium, V8 and depot_tools pins from
  `browser/config/*.rev` at the build commit, not from the working tree;
- records the effective `args.gn` assignments, following its
  `//out/.../args_generated.gni` import, and refuses anything other than a
  static, non-official, non-debug arm64 development build with the updater and
  Sparkle off, or one that re-enables bundled Brave services;
- redacts credential-named build arguments and local home paths;
- checks that the executable version matches the pinned Chromium major and
  Brave minor version.

`write-brave-provenance-test.py` covers these cases with synthetic inputs.

## 3. Host the browser assets

Upload the ZIP and its provenance JSON unchanged to a prerelease in this
repository, as for `preview-0.3.2-6b984ab`. Never replace those assets later:
the pins below name their exact bytes.

## 4. Fill the reviewed pin

Replace every `PLACEHOLDER` in one change:

| Value | Where | Source |
| --- | --- | --- |
| `source_url` | pin block in `scripts/prepare-release-brave.sh` | `https://github.com/sunghoojung/reverse-engineering-browser/releases/download/<prerelease tag>` |
| `brave_sha256` | same block | SHA-256 printed by the packager |
| `provenance_sha256` | same block | SHA-256 printed by the provenance tool |
| `build_source` | same block | full build commit; it must stay reachable from `main` |
| `OriginTracePairedBrowserCDHash` | `apps/research-ui/macos/Info.plist` | `cdhash` from step 2 |

`brave_name` is already `Brave-Browser-Development-v0.5.0-macos-arm64` and must
match the Info.plist version. While any value is unfinished,
`./scripts/prepare-release-brave.sh` lists it and exits before any platform,
network or filesystem work, and `tools/write-release-pair.py` refuses to write
the pair, so the release workflow cannot pass. Merge the browser build commit
into `main` with a merge commit, not a squash, so CI can diff against it.

## 5. Validate and publish

Run the local gate from [AGENTS.md](../../AGENTS.md#validation), including the
native app checks. The pull request runs
[`release.yml`](../../.github/workflows/release.yml) without publishing:

1. `make check`, the app build and its strict signature check;
2. `prepare-release-brave.sh`: placeholder check, browser-input equivalence
   with `build_source`, pinned download and SHA-256 check, strict Brave
   signature, Brave CDHash equal to the Info.plist pin, and `--version`;
3. the packaged launcher with the extracted Brave, native close/Quit,
   unverified-browser warning XCUITest and rendered UI checks;
4. `write-release-pair.py`: pair provenance, checksums and release notes.

After merge, manually dispatch `release.yml` with the full `main` commit as
`source_sha` and `v0.5.0` as `release_tag`, or push the `v0.5.0` tag at that
commit. Only `v0.5.0` is admitted (`REVIEWED_TAG` in
[`publish-release-pair.py`](../../tools/publish-release-pair.py)). The publish
job creates a fresh tag and release and verifies remote sizes and digests; it
never replaces or adopts an existing tag or release.

Release assets: `Origin-Trace-v0.5.0-macos.zip`,
`Brave-Browser-Development-v0.5.0-macos-arm64.zip`, its `.provenance.json`,
`Origin-Trace-Brave-v0.5.0.provenance.json` (schema
`origin-trace-release-pair-v2`) and `SHA256SUMS-v0.5.0.txt`. The release notes
are generated by `write-release-pair.py`.

## Browser pairing in the app

Info.plist declares `OriginTraceReleaseType` `paired` and the paired browser's
CDHash. [`BrowserPairing.swift`](../../apps/research-ui/macos/BrowserPairing.swift)
reads the discovered browser's code directory hash. A Brave version string
cannot identify the build: every build from one Brave pin reports the same
version, and the v0.3.0 browser from the same `v1.95.52` pin reports
`151.1.95.0`. The CDHash also seals the
nested frameworks and resources, survives ZIP extraction and moving the app,
and changes with any rebuild.

Automatic and **New Live Session** launches start directly only for that exact
browser. Any other browser, an unsigned one, or a build whose pin is still a
placeholder shows **This browser pairing has not been verified**, with
**Continue Offline** as the default and **Start Unverified Session** as an
explicit choice. Developer builds of Brave therefore always ask. This is a
compatibility check, not a security boundary. The native app build runs
`tools/check-browser-pairing.swift`; the release workflow runs the warning
XCUITest with an unsigned fake browser.
