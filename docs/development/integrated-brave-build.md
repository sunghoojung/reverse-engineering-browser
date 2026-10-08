# Integrated Brave build candidate

This branch combines the accepted `main` application with the original native
Console (#112), renderer admission (#131), worker (#129 → #140 → #141), and
proxy (#138) draft histories. The worker stack is integrated once through #141.
Original draft PRs remain open. This aggregate is a **build-and-test candidate**;
it must not be merged or described as a compiled release before the pinned
browser and runtime gates below pass.

## One build path

Use a clean checkout of this integration branch on an Apple silicon Mac with
full Xcode (including an already accepted license), C++20 and zlib, Make,
Python 3.8 or newer, Rust/Cargo, Node.js >=24.16.0 and <25, and Corepack or pnpm. The entrypoint never
installs system tools, accepts licenses, changes global Xcode selection, or enables
worker/proxy capture. Set `DEVELOPER_DIR` for a nonstandard full Xcode location,
and `REB_NODE_DIRECTORY` for the supported Node installation if necessary.
For initialization, first builds and unproven/incomplete builds, keep at least
150 GiB free on the Brave filesystem; 200–250 GiB is recommended.
A full source build takes hours. A small Linux workspace is not a build host.

From the repository root:

```sh
# Record this exact source revision with your build evidence.
git rev-parse HEAD
# First build only: downloads the pinned upstream source trees.
./scripts/build-integrated-brave.sh --init
# Later builds with the same initialized checkout:
./scripts/build-integrated-brave.sh
```

For a different build disk, set `REB_BRAVE_WORKTREE=/absolute/path/to/worktree`
for both invocations. For an already initialized checkout only, the existing
`REB_BRAVE_DIRECTORY=/absolute/path/to/src/brave` override is supported.
The wrapper refuses a mismatched `--init` destination and stops on any failure.
It checks all three upstream pins before mutation, rejects revision, integration,
remote and output overrides, and refuses unrecognized upstream edits. First-run
`--init` requires clean upstream checkouts. A missing checkout is initialized
normally. A pristine unborn Brave Git repository left before the first successful
fetch is also admitted only for `--init`: it must contain only its own `.git`, no
index files/refs/pending operation, and only the official Brave fetch remote URLs. Custom hooks, hook/monitor
configuration or configuration includes require inspection and are refused.
This narrowly permits safe initialization to continue; a partial checkout with
user content, a wrong remote, symlinks or initialized mismatched pins still stops.
Repeated runs without `--init` accept
only the exact locally recorded post-sync state for this integration commit,
including ignored overlay/patch destinations; symlink destinations are refused.
The private source receipt is `build/integrated-brave-state.json`. Only after
all browser, native tests, companion build and signature steps succeed does the
wrapper write `build/integrated-brave-complete.json`. These are local build
receipts, not source artifacts.

A verified repeat for the exact integration commit, upstream state, component
output path, GN args and browser executable can use an adaptive free-space
reserve: the larger of **50 GiB or the allocated size of the existing component
output**. This conservatively leaves room to duplicate the existing output during
rebuilding/linking plus a substantial minimum; it is a headroom heuristic, not a
guarantee against running out of disk. Initialization always requires 150 GiB.
Missing/stale/incomplete successful-build proof, changed source/args/browser, or
an unmeasurable output never earns the smaller reserve. The disk check runs
before downloads, synchronization or build changes. Source/pin errors still
stop the build independently of free space.
If a receipt is missing or no longer matches, preserve the checkout and use a
fresh pinned worktree. Never stash/reset/clean or discard edits to bypass this
guard. The helper does none of those operations.

The wrapper runs the existing doctor and sync, offline native foundations,
the full development browser build (which prepares Brave's component GN args),
pinned probe compilation (including the native Console runtime), the separate
proxy adapter unit-test executable, and
Origin Trace packaging/Console checks. It verifies the companion signature. The ordinary `make native-console-check`
uses the real C++ bridge and Rust HTTP backend with a synthetic Python browser
peer. Companion JavaScriptCore checks are a separate layer. Neither establishes
execution in the patched Brave renderer.
`make brave-foundation-check` can repeat only the pinned native compilation and
proxy tests; `make brave-probe-check` still compiles the probe objects alone.
The focused commands support `REB_BRAVE_OUTPUT_DIRECTORY`; this wrapper rejects
that override so the browser and focused checks both use `out/Component_arm64`.
`REB_BRAVE_JOBS` applies to both the full browser and focused native builds.

The output is **Brave plus the matched Origin Trace companion**, including its
bundled backend, native tools and UI. They are two cooperating applications, not
one fused executable. The component browser output is under
`browser/worktree/src/out/Component_arm64/` (or the selected worktree's `src/out/`).
The default live launcher looks for `Brave Browser.app/Contents/MacOS/Brave Browser`
there; if Brave's channel gives the app a different name, set `REB_BRAVE_BINARY`
to the executable actually built in that directory. The companion is
`build/Origin Trace.app`. Use the existing [live-session path](../../browser/README.md)
and keep both from the same integration revision, or use the explicitly verified
source-compatible browser checkpoint described below. Component output is for local
use and must not be copied as a standalone portable `.app`.

## Capability and status manifest

| Capability | Source status | Runtime/build status |
| --- | --- | --- |
| Accepted main evidence pipeline, CDP debugger/worker extraction, Analyst UI, experiments and reliability repairs | Preserved from final main; integration commit ancestry records the exact base | Existing main functionality; recheck the matched candidate in a fresh live session |
| Native Console #112 and renderer probe admission #131 | Integrated into production target sources; disabled/opt-in behavior unchanged | Offline protocol/admission checks available; exact pinned browser compilation and runtime verification remain required |
| Native worker source, metadata, authority and acknowledged transfer #129/#140/#141 | Linked but dormant foundation, including disabled Blink observations and Mojo contract | No production service observer, binder/adapter, controller, broker/UI adapter or activation; no native worker end-to-end claim |
| Native proxy policy and partition adapter #138 | Separately compiled foundation; intentionally not dependencies of `:browser` | Offline policy and explicit pinned `proxy_partition_adapter_unittests`; successful preparation remains runtime-blocked; no browser routing or UI activation |
| Pinned aggregate browser | Build instructions and all source changes present | Unverified until this exact integration revision completes pinned build and live runtime gates |

The source-of-truth pins remain:

- Brave: `v1.95.52` (`browser/config/brave-core.rev`)
- Chromium: `151.0.7922.108` (`browser/config/chromium.rev`)
- V8: `20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921` (`browser/config/v8.rev`)

A full browser build does **not** compile the proxy preparation-only targets by
itself. Do not add proxy dependencies to `:browser` or activate dormant worker
flags to make a build appear more complete. These require separate implemented
and reviewed runtime adapters, not a packaging switch.

## Acceptance checklist and evidence

Record `git rev-parse HEAD`, the pins and resolved upstream commits, platform,
Xcode/Node versions, build configuration, commands and exit statuses. Keep test
captures and logs local; do not commit credentials, captures, personal paths or
private session evidence. Mark unavailable, skipped and failed checks explicitly.
Source composition and bounded offline checks are not pinned-browser evidence.

Before handing off a candidate, run the repository gate:

```sh
make lint
make check
make e2e
make sanitize
git diff --check
```

On the supported build host, also establish:

- [ ] Exact upstream pin matches, clean/reviewed source state, overlay destinations
      present, and every patch preflights/applies through the supported sync.
- [ ] `make brave-doctor`, GN formatting (`gn format --dry-run` on the changed
      overlay BUILD.gn), `make brave-foundation-check`, and full Brave build pass.
- [ ] `make app-build`, native Console checks, and strict companion signature pass.
- [ ] Start the matched apps in a fresh disposable live session. Verify baseline
      evidence, request/profile and Canvas flows, debugger/source extraction,
      experiments, and accepted main Analyst close/Stay/Discard behavior.
- [ ] After the actual patched browser is built, run its separate native Console
      runtime gate from this repository (substitute the real executable, not the
      enclosing `.app` directory):

      ```sh
      python3 tools/check-native-console.py --binary build/reb-console \
        --browser "/absolute/path/to/Brave.app/Contents/MacOS/Brave"
      ```

      This launches a disposable profile and a local fixture, explicitly opting
      into native Console to exercise Blink/V8, timeout recovery, preview/Unicode
      limits and teardown. It is not run by the wrapper's generic Console target;
      keep it unverified until this command passes on the built browser.
- [ ] Native Console: explicit document selection and opt-in; primitive success,
      errors, navigation/close invalidation, disabled state, bounded output and
      no automatic replay. Check native sampling retry after full-queue rejection.
- [ ] Worker dormant-state smoke: native worker data does not appear as a working
      feature; current CDP extraction remains intact. Offline worker tests cover
      disabled/expired claims, malformed identity, generation/document mismatch,
      bounded pressure/drop accounting, acknowledgement, retirement and teardown.
- [ ] Proxy dormant-state smoke: ordinary groups do not claim traffic isolation;
      preparation remains blocked; adapter tests compile/run explicitly. Offline
      tests cover immutable ownership, restore, transfer and rejection cases.

Production worker enablement additionally needs real observer ownership,
parent/document/partition identity, binder disconnect/crash/navigation handling,
lease expiry/revocation, receiver acknowledgement/backpressure and broker/UI
end-to-end tests. Production proxy enablement additionally needs actual partition
creation and network routing, DNS/WebRTC/service-worker coverage, reconnect,
restore and teardown isolation tests. See the
[worker source](../../protocol/native-worker-source-v1.md),
[worker metadata](../../protocol/native-worker-observation-v1.md),
[worker transfer](../../protocol/native-worker-transfer-v1.md), and
[proxy lifecycle](../../protocol/native-proxy-containers-v1.md) contracts for the
full gates. None are waived by this aggregate build.

## Optional portable development package

Only after the component build and runtime checks pass, follow the
[distribution guide](brave-distribution.md). Its separate macOS arm64 static
build requires `sccache` and additional disk:

```sh
./scripts/build-brave-distribution.sh
./scripts/package-brave-distribution.sh <your-development-version>
```

Keep the matched Origin Trace companion with it, record the ZIP hash, and test
an extracted package. This remains an ad-hoc-signed development preview until
trusted release, signing/notarization and distribution gates pass. This branch
does not publish a release or provide a precompiled browser download.

## Reuse the completed browser for the final companion update

The accepted main merge for #149 is
`f0e2b940d4790ce545869d060dfcb6ca9af312f9`. Its candidate-experiment UI/Rust
changes are now included in this aggregate. Compared with browser-build
checkpoints `54d3150a8ca6074a366b0ffc0a02705011bb58ef` and its startup-repair
child `cb4036e3fd1a734bd3aa65f8106707f3ffe6b96f`, the native Brave inputs are
unchanged: all three pins, Brave overlays, ordered Brave/Chromium/V8 patches,
bootstrap/sync/toolchain scripts, C++ Console/debugger transports, and native
wire headers/contracts. The changed HTTP/deobfuscator contracts belong to the
new companion; build its backend, UI and workers together through `make app-build`.

This is source-compatibility evidence, not proof that an existing browser binary
finished building or passed runtime tests. Let an active build finish. Do not
pull, switch, reset, synchronize or edit its checkout/worktree/receipts while it
runs. Keep the entire component output in place; its `.app` depends on that
output tree. Complete the pinned/browser gates above before treating it as a
verified browser.

After the final aggregate's exact-head repository CI and review pass, use the
final commit SHA from the PR handoff in a **separate new source checkout**. This
builds only the new Origin Trace release bundle, including all release helpers;
it neither bootstraps nor recompiles Brave:

```sh
git clone https://github.com/sunghoojung/reverse-engineering-browser.git reb-origin-trace-update
cd reb-origin-trace-update
# Replace REVIEWED_FINAL_SHA with the exact final reviewed commit from the handoff.
git checkout --detach REVIEWED_FINAL_SHA
make app-build
codesign --verify --deep --strict "build/Origin Trace.app"
```

Verify the actual old development-browser bundle and executable before launch.
Set `BRAVE_APP` to its existing absolute path, without moving or copying it:

```sh
BRAVE_APP="/absolute/path/to/existing/worktree/src/out/Component_arm64/Brave Browser Development.app"
if test -x "$BRAVE_APP/Contents/MacOS/Brave Browser Development" &&
   test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$BRAVE_APP/Contents/Info.plist")" = "com.brave.Browser.development"; then
  REB_BRAVE_BINARY="$BRAVE_APP/Contents/MacOS/Brave Browser Development" \
    "./build/Origin Trace.app/Contents/MacOS/OriginTrace"
else
  echo "Stop: verify the existing development-browser bundle path and identifier."
fi
```

The launch is skipped if either check fails. Directly executing
`Contents/MacOS/OriginTrace` carries the environment into the app; do not assume
that an environment variable before macOS `open` reaches a LaunchServices app.
The app validates the development bundle identifier, then passes the resolved
browser path and all bundled helper paths to its live-session subprocess. Choose
the session's capture boundary in the app. Wait for the old Brave build to finish,
then quit the old Origin Trace normally, saving work and responding to its draft
prompts, before launching the new bundle. Do not force-kill an app or run two
session controllers against the old session/profile.
No duplicate debug helpers are needed for this packaged route.

Record the **browser source revision** (54d3150a or cb4036e, as actually used),
resolved upstream pins, actual browser path and successful build/runtime evidence
separately from the **new companion source revision** (`git rev-parse HEAD` in the
new checkout). Never relabel an old browser as compiled from the new companion
commit. The older source-state/completion receipts remain untouched. The wrapper
is deliberately not used to waive those guards or resynchronize an old worktree.
