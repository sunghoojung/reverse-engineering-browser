# Origin Trace + Brave v0.6.0 paired release

A paired release publishes Origin Trace together with the exact Brave Browser
Development build it was accepted with. v0.6.0 pairs the app with a new browser
built locally from the pinned sources in [`browser/config/`](../../browser/config)
(Brave `v1.99.57`, Chromium `157.0.8103.79`, V8 15.7) and this repository's
overlays and patches. It is the first build from these pins, and the first
compile of every Chromium, Blink and Brave change since v0.5.1; follow the
[build-day runbook](#build-day-runbook-for-v060). v0.5.1 was the last new browser
(Brave `v1.95.52`, Chromium `151.0.7922.108`), and v0.5.2 paired it again
unchanged; see [Reuse an unchanged browser](#reuse-an-unchanged-browser). The
historical companion-only path is recorded in [companion-release.md](companion-release.md).

The browser is not built in clean CI: the
[standard hosted runner lacks the disk](brave-distribution.md#release-gate).
The release discloses that it is a local workstation build, ad-hoc signed, not
notarized and not an official Brave release. CI fetches it from a pinned URL and
checks it against pinned SHA-256 digests, the browser-input equivalence of the
build commit and the CDHash its provenance records before anything is published.

## Build-day runbook for v0.6.0

Each compile attempt costs hours, so the steps run in fail-fast order and each
names the evidence it produces. The examples use `REPO` for a clean clone of this
repository and `WT` for a new, empty Brave worktree on the build disk:

```sh
REPO=/absolute/path/to/reb-v060
WT=/absolute/path/to/reb-brave-157
BRAVE="$WT/src/out/Component_arm64/Brave Browser Development.app/Contents/MacOS/Brave Browser Development"
REB_API="$REPO/apps/origin-trace-backend/target/debug/reb-api"
```

### What is known before the build

Checked without a checkout or compiler in #501:

- The pins agree: Brave `v1.99.57` names Chromium `157.0.8103.79`, whose `DEPS`
  names V8 `307108153d1e`; depot_tools `1afcf0756e47` predates the Brave tag.
- Ordered replay: every pinned file the stacks touch, with Brave's own patches
  applied first, takes all 24 Brave, 50 Chromium and 22 V8 patches in sync
  order with plain `git apply`, and they reverse newest first back to that
  baseline. `sync-browser-integration.sh` itself, run twice on those files,
  gives the same bytes and then applies nothing. Many `index` lines predate the
  157 pins; sync never reads them.
- Every quoted include in the overlay and in patch-added lines resolves at the
  pins (325 headers). Every upstream name they use exists there. The four
  overlay mojoms parse with Chromium 157's own parser. Every GN file the stacks
  change passes the pinned `gn format --dry-run`, and the patched service flag
  files pass `check-brave-services.py --brave` under the pinned gn.
- Every object `brave-probe-check` compiles maps to the GN target that builds
  its source at the pins.
- Host clang with `-Wunsafe-buffer-usage` and its libc check, over the offline
  harnesses, finds no raw pointer offset or libc buffer call in integration
  code without a compiled v0.5.1 precedent; Chromium makes both errors in
  `brave/`, Blink and content. No overlay or patch code calls a deprecated V8
  15.7 API.

None of this is a compile. Overload resolution, templates, `-Werror` warnings,
Mojo-generated code and Brave's `chromium_src` overrides are first checked by
step 4.

### 1. Fetch the build commit

Build from the merge commit of #501, or a later `main` commit that changes no
browser input. That commit becomes `build_source`. The release refuses the pair
if any browser input differs between it and the released commit, so merge
nothing that touches them until the pin PR in step 8 is merged. The browser
inputs are exactly what the Brave build reads, listed in `browser_inputs` in
`prepare-release-brave.sh`: `browser` (pins, overlays and patches), the six
Brave scripts, and the two patch-stack helpers they import
(`tools/brave_patch_contract.py` and `tools/check-integrated-brave-state.py`).
`include`, `src`, `protocol`, `services` and the app are not inputs: no overlay
source or GN target reads them. `make check` compiles the overlay sources
against `include` and `src` to keep the browser and its consumers compatible.

```sh
git clone https://github.com/sunghoojung/reverse-engineering-browser.git "$REPO"
cd "$REPO"
git checkout --detach <full build commit>
git status --short    # prints nothing
```

### 2. Preflight, in minutes

```sh
uname -m                                          # arm64
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -version
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -license check
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun --sdk macosx --show-sdk-version
node --version                                    # v24.16.0 or later on the 24 line
corepack pnpm --version                           # 11.11.0 or later
command -v pnpm                                   # Brave's DEPS hooks run this one
command -v sccache cargo python3
df -h "$(dirname "$WT")"                          # at least 150 GiB free; plan for about 350 GiB
python3 tools/check-brave-services.py            # patch contract only
make lint check e2e sanitize                      # this checkout is the one CI saw
```

Chromium 157 accepts macOS SDK 15 or newer for a non-official build; Xcode
26.x is enough. If `corepack pnpm` reports an older pnpm, Corepack is reusing a
cached version from the `v1.95.52` pin, which accepted 11.9: make Corepack
provide 11.11.0 or later before step 3, or Brave's `pnpm install` stops.
Brave's DEPS hooks run the first `pnpm` on `PATH`, not `corepack pnpm`, and
`brave/vendor/web-discovery-project` pins pnpm 11.25.0. A fixed-version pnpm
from Nix or Homebrew stops that hook with `This project is configured to use
11.25.0 of pnpm`. Put a Corepack shim first on `PATH` for the build, which
follows each project's `packageManager` pin:

```sh
corepack enable --install-directory "$PWD/build/corepack-shims" pnpm
export PATH="$PWD/build/corepack-shims:$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0
```

The 350 GiB plan covers the component checkout and output, the later
`Static_arm64` output, and a second checkout if a fix needs one.

### 3. Initialize a fresh pinned worktree

A checkout from the 151 pins cannot be reused: `adopt` and `advance-patch` do
not cover a pin change. Keep the old checkout until v0.6.0 is accepted if
there is room, and start a new one:

```sh
export REB_BRAVE_WORKTREE="$WT"
REB_BRAVE_JOBS=<cores> ./scripts/build-integrated-brave.sh --init
```

An interrupted run resumes when you repeat the same command.

### 4. Integrated build: where a failure shows first

The wrapper runs, in order, and stops at the first failure:

1. disk reserve, pin and clean-tree checks, then `bootstrap-brave.sh --init`
   (download and Brave init; the pre-initialization stack is empty at `v1.99.57`);
2. `make brave-doctor` (depot_tools at its pin);
3. `sync-browser-integration.sh`: overlay copy and the three stacks. A failure
   here contradicts the replay above; keep the tree and report the patch;
4. repository-only native checks (`make demo native-probe-admission-check
   native-proxy-policy-check`, `./build/reb-event-demo`);
5. Brave's `--prepare_only` and `components/policy:generate_policy_templates`.
   This runs `gn gen`, the first evaluation of the overlay `BUILD.gn`, the
   patched GN files and the mojom targets;
6. `check-brave-services.py --args` on the generated `args.gn`;
7. `make brave-foundation-check`: every integration object, then the proxy
   adapter unit tests, then the generated fingerprint binding checks. This is
   the first compile of the overlay and the patched upstream sources;
8. the full component browser build (hours);
9. `make app-build native-console-check` and the companion signature.

If `brave-foundation-check` stops with `ninja: error: unknown target
'obj/...o'`, a path in the probe list of `scripts/brave-toolchain.sh` does not
match this pin: list the real ones with
`(cd "$WT/src" && buildtools/mac/gn outputs out/Component_arm64 //<dir>:<target>)`
and fix the list as a tooling-only change (`adopt`).

### 5. Fixing a compile error

Pick the path from the table in
[Fixing a compile error](integrated-brave-build.md#fixing-a-compile-error): a
fix to one existing patch-owned file keeps the checkout through `advance-patch`;
anything else goes through the development loop and ends with a fresh `--init`
from the merged fix. `adopt` and `advance-patch` compare the two commits, so
make the fix on a branch from the build commit with nothing else in it.
Each fix moves the build commit of step 1 to the fixed commit.

None of these has been seen; they are where a first build is most likely to stop:

| If it stops at | The likely fix |
| --- | --- |
| Brave's `pnpm install` with a `devEngines` package manager error | pnpm is older than 11.11.0: have Corepack provide a newer one |
| `gn gen` naming an overlay or patched `BUILD.gn` label | a dependency moved at 157: find its new label and change the overlay `BUILD.gn` or the patch |
| `gn gen` header-check errors | `CI` is set in the environment, which makes Brave pass `--check`; unset it. The overlay's `*_blink.h` headers belong to no target by design |
| `-Wunsafe-buffer-usage` or `-Wunsafe-buffer-usage-in-libc-call` in an overlay or patched file | iterator arithmetic on a type without bounded iterators, or a libc buffer call: wrap the expression in `UNSAFE_BUFFERS` (`base/compiler_specific.h`) as the probe sink does, or copy through `base::span` |
| Mojo-generated code for `cloneable_message.mojom` | a typemap the build uses lacks the `reb_task_origin` getter; the Blink and common traits both have it. (`BeginNavigationParams` keeps its old constructor: its REB field is `[MinVersion=1]` and last, and Mojo emits one constructor per version) |
| A `chromium_src` override or Brave macro next to a REB hunk | Brave changed the override at `v1.99.57`; only textual replay was checked. Move the REB hunk to the overridden function |
| The Siso `chromium_src` redirect or the `sccache` patches (Brave 0008 to 0010) | Brave's Siso config changed shape; rebuild without `cc_wrapper` to confirm, then regenerate those patches |
| The full build, in a file outside the probe list | an indirect include or a template from a changed header; fix it in the development loop and add the file to the probe list |

### 6. Focused gates on the built browser

```sh
REB_BRAVE_DIRECTORY="$WT/src/brave" make brave-probe-check
python3 tools/check-brave-services.py --args "$WT/src/out/Component_arm64/args.gn"
python3 tools/check-brave-services.py --brave "$WT/src/brave" --gn "$WT/src/buildtools/mac/gn"
make native-console-build
python3 tools/check-native-console.py --binary build/reb-console --browser "$BRAVE"
REB_BRAVE_BINARY="$BRAVE" make compiled-script-capture-check
```

`check-native-console.py --browser` is the native Console runtime gate: a
disposable profile, a local fixture, Blink and V8 execution, timeout recovery,
preview and Unicode limits and teardown. `compiled-script-capture-check` drives
every way a script reaches V8 through a real session and compares the stored
sources (#446, #450).

### 7. Live acceptance

Every case runs on an owned loopback fixture in a visibly labeled session, per
[SAFETY.md](../../SAFETY.md). `REB_BRAVE_BINARY="$BRAVE" make live-acceptance-check`
serves the fixtures in `tools/live_acceptance/`, runs every session below and
prints PASS, FAIL or the exact MANUAL steps per case
([tools README](../../tools/README.md#live-acceptance)). The budget cases run in
their own session with 1 MiB budgets, so they do not cut the content cases
short. One content session covers most cases:

```sh
REB_NATIVE_PROMISE_STACKS=1 "$REB_API" session start \
  --url http://127.0.0.1:<port>/ --localhost-only \
  --request-content --confirm-sensitive-capture --canvas-images \
  --request-stacks --document-start --wasm-dispatch --wasm-call-indirect \
  --brave-binary "$BRAVE" --sessions-root "$(mktemp -d)" \
  --duration-seconds 3600 > session.json
EP="$(python3 -c 'import json; print(json.load(open("session.json"))["endpoint_file"])')"
"$REB_API" call get_session_context --read-only --endpoint-file "$EP"
"$REB_API" call get_session_summary --read-only --endpoint-file "$EP"
```

`get_session_context` must report `request_stacks` and promise stacks on. Open
each fixture page with `session_action` (`open_url`), then read the evidence:
`get_session_summary` for checks, unresolved tabs and every refusal count;
`get_requests` for each row's tab, body case and budget state;
`get_request_headers`, `get_request_cookies`, `get_cookie_provenance` and
`get_request_stack` for one request; `get_events` and `wait_for_events` for
debugger observations. An agent connected with
`scripts/reb-api-mcp.sh --endpoint-file "$EP" --permission full` can run the same reads (see the
[agent cookbook](agent-cookbook.md)). End the session with
`session_action` (`end`, `confirm`).

| Session | Cases | Issue |
| --- | --- | --- |
| Content session | Baseline: Wasm `br_table` and `call_indirect`, the Canvas readback image, network and fingerprint surfaces | release notes |
| Content session | Every request on its tab: parser, fetch and XHR loads; `sendBeacon` and keepalive at unload; a removed iframe; dedicated, nested and shared workers (one and two tabs); a service worker's install fetches, passthrough, `respondWith(fetch())`, cache answer and a fetch after its last tab closed; speculation-rules prefetch and prerender; `window.open`, a download and a redirect chain. `get_session_summary` reports zero unresolved | #425 |
| Content session | Request and response headers equal what the echo server saw and sent across two redirect hops; a 200 KiB response header block kept whole; DevTools opened on the same page shows the same headers as without capture | #427 |
| Content session | JSON, HTML, image, gzip and brotli, chunked and streamed bodies kept with exact bytes and digest; an aborted download, a 304, a redirect and a service-worker answer each carry their reason; 50 parallel responses all kept; a navigation answered from `preloadResponse`; a burst then silence; the response budget shown when it runs out | #428 |
| Content session | A 150-frame stack through wrappers matches DevTools frame for frame; 5,000-deep recursion keeps 1,024 frames and the omitted count; inline, `eval` and network script frames resolve; `fetch` from a Wasm import shows Wasm frames; an `await` chain shows async frames; one call site's stack is sent once | #429 |
| Content session | A JS-set cookie and server `Set-Cookie` with SameSite and Secure variants: sent, received and blocked cookies match the server, and the JS write links to its script position | #430 |
| Content session | An 8 KB GraphQL GET URL; a 5 MiB JSON POST, a multipart upload with a file and a stream-body `fetch` with exact bytes and digest; 40 parallel scripts all kept; 5,000 small POSTs kept until the request budget runs out, which is shown | #436 |
| Content session | An agent waits for the next fetch to `/api/x` and reads its stack, the next click handler and its position, and the next CSP violation | #434 phase 1 |
| Metadata session (the same start without `--request-content`, `--confirm-sensitive-capture` and `--canvas-images`) | No header, cookie or body value is recorded; an `eval` frame reports `source_not_retained` | #427, #429, #430 |
| Session without `--request-stacks` | No stack walk runs | #429 |
| Not runnable from Origin Trace | The pausing debugger: conditional breakpoint, scopes, step, resume, navigation and idle disarm, the lease deadline and the review cases in [native-debugger-v1.md](../product/native-debugger-v1.md#acceptance-still-required) | #434 phase 3 |

Two acceptance items need a profiler rather than a fixture: "the inactive probe
path costs one atomic load and allocates nothing" (#425, #427, #434, #436) and
"browser memory stays bounded by the in-flight pool" (#428, #436). Record how
each was measured.

The pausing debugger has no launch path: nothing in `run-live-session.sh` or the
app passes `--reb-native-debugger` to Brave or `--native-debugger-socket` to the
backend, by the policy in [native-debugger-v1.md](../product/native-debugger-v1.md#guard-rails).
Running phase 3 needs a reviewed experiment switch first; v0.6.0 ships it off.

### 8. Package, pin and publish

1. Build the distribution from the same checkout, at the same commit
   ([section 1](#1-build-and-package-the-browser)): `build-brave-distribution.sh`,
   then `package-brave-distribution.sh v0.6.0`.
2. Extract the ZIP, rerun the native Console runtime gate and a short content
   session against the extracted app, and record its identity and provenance
   ([section 2](#2-record-identity-and-provenance)).
3. Upload the ZIP and provenance to a new prerelease, for example
   `brave-0.6.0-<short build commit>` ([section 3](#3-host-the-browser-assets)).
4. Open the pin pull request ([section 4](#4-fill-the-reviewed-pin)). In the same
   change, move each release note claim in `PENDING_LIVE` in
   [`write-release-pair.py`](../../tools/write-release-pair.py) that step 7
   confirmed to `ACCEPTED_LIVE`, and delete the rest. The pair writer refuses a
   new browser build while any claim is pending, so the release check fails
   until this is done. The pin pull request must change no browser input.
5. Merge it with a merge commit, then dispatch `release.yml`
   ([section 5](#5-validate-and-publish)).

### Issue map

| Issue | Closes on |
| --- | --- |
| #439 pins | Steps 3 to 6 passing on this commit, with the build and test logs in the issue |
| #425 tabs | Step 6, the #425 rows of step 7 and the inactive-path measurement |
| #427 headers | Step 6, the #427 rows of step 7 including the DevTools comparison |
| #428 bodies | Step 6, the #428 rows of step 7 and the memory bound |
| #429 stacks | Step 6, the #429 rows of step 7 and the off-flag case |
| #430 cookies | Step 6 and the #430 rows of step 7 |
| #434 debugger | Phase 1: step 6 and its step 7 row. Phase 3: a reviewed launch path and its live cases; it stays open after v0.6.0 |
| #436 limits | Step 6, the #436 rows of step 7 and the memory bound |
| #435 tracking | When the issues above close |

## 1. Build and package the browser

On the build workstation, from a pinned and synchronized checkout at the commit
that will be recorded as `build_source`:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave ./scripts/build-brave-distribution.sh
REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave \
  ./scripts/package-brave-distribution.sh v0.6.0
```

The packager prints the ZIP's SHA-256. After this, the browser inputs listed in
[`scripts/prepare-release-brave.sh`](../../scripts/prepare-release-brave.sh)
(`browser`, the Brave scripts and their two patch-stack helpers) must not
change before the release, or CI refuses the pair.

## 2. Record identity and provenance

Extract the ZIP into a fresh directory, then read the app's CDHash and version:

```sh
zip=build/Brave-Browser-Development-v0.6.0-macos-arm64.zip
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
`Brave-Browser-Development-v0.6.0-macos-arm64.provenance.json` beside the ZIP,
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

`brave_name` names the release the browser was built for, here
`Brave-Browser-Development-v0.6.0-macos-arm64`. It must be the Info.plist
version or an earlier one. While any value is unfinished,
`./scripts/prepare-release-brave.sh` lists it and exits before any platform,
network or filesystem work, and `tools/write-release-pair.py` refuses to write
the pair, so the release workflow cannot pass. For a new browser build the pair
writer also refuses while any release note claim in its `PENDING_LIVE` list has
not been moved to `ACCEPTED_LIVE` or deleted. Merge the browser build commit
into `main` with a merge commit, not a squash, so CI can diff against it.

### Reuse an unchanged browser

A release that changes nothing in the browser inputs can pair the previous
browser build again instead of building a new one. Keep the whole pin block,
including `brave_name`, `build_source` and both digests, and bump only the
application version. The browser ZIP and provenance keep the name and
`release` of the version they were built for, because the provenance digest is
pinned and the record cannot be rewritten. CI still refuses the pair if any
browser input differs from `build_source`. Set
`REVIEWED_BRAVE_TAG` in
[`publish-release-pair.py`](../../tools/publish-release-pair.py) to that
browser release; v0.5.2 paired the v0.5.1 build this way. v0.6.0 does not:
it builds a new browser, so its pin names v0.6.0.

## 5. Validate and publish

Run the local gate from [AGENTS.md](../../AGENTS.md#validation), including the
native app checks. The pull request runs
[`release.yml`](../../.github/workflows/release.yml) without publishing:

1. `make check`, the app build and its strict signature check;
2. `prepare-release-brave.sh`: placeholder check, browser-input equivalence
   with `build_source`, pinned download and SHA-256 check, strict Brave
   signature, Brave CDHash equal to its provenance record, and `--version`;
3. the packaged launcher with the extracted Brave, native close/Quit,
   live-session startup XCUITest and rendered UI checks;
4. `write-release-pair.py`: pair provenance, checksums and release notes.

After merge, manually dispatch `release.yml` with the full `main` commit as
`source_sha` and `v0.6.0` as `release_tag`, or push the `v0.6.0` tag at that
commit. Only `v0.6.0` is admitted (`REVIEWED_TAG` in
[`publish-release-pair.py`](../../tools/publish-release-pair.py)). The publish
job creates the tag, uploads the assets to a draft release, verifies the draft's
remote sizes and digests, and only then publishes it. A draft that fails
verification is deleted. A published release that then fails its check is
withdrawn to a draft for inspection rather than deleted. A rerun adopts a tag
that names the same tested commit and has no release, and replaces only a draft
with this exact source and title. It never replaces an existing release, a tag
at another commit, or anyone else's draft. Every publishing run, manual or tag
push, shares one concurrency group, so two cannot publish at once.

Release assets: `Origin-Trace-v0.6.0-macos.zip`,
`Brave-Browser-Development-v0.6.0-macos-arm64.zip`, its `.provenance.json`,
`Origin-Trace-Brave-v0.6.0.provenance.json` (schema
`origin-trace-release-pair-v2`) and `SHA256SUMS-v0.6.0.txt`. The release notes
are generated by `write-release-pair.py`.

## Live sessions and the browser identity

Origin Trace starts a live session directly with the Brave Browser Development
build it finds (beside the app, `REB_BRAVE_BINARY`, or a registered
application). There is no pairing prompt, so developer builds start the same
way, with one exception: the launcher refuses a build that does not define
every native V8 flag the session requests. V8 ignores an unknown `--js-flags`
entry and every later one, so a stale build would otherwise capture without
quiet mode or dispatch evidence and report nothing. The release pins its
browser by bytes instead: the ZIP and provenance SHA-256 digests in the reviewed
pin, and the CDHash recorded in the provenance.
A Brave version string cannot identify the build, because every build from one
Brave pin reports the same version; the v0.3.0 browser from the same `v1.95.52`
pin also reports `151.1.95.0`. The CDHash seals the nested frameworks and
resources, survives ZIP extraction and moving the app, and changes with any
rebuild, so `prepare-release-brave.sh` compares it with the extracted app. The
release workflow runs the live-session startup XCUITest with an unsigned fake
browser and the native V8 switches off, because the fake contains no V8.
