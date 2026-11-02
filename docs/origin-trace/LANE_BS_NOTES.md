# Lane BS — wave24 cold-identity feasibility scaffold

**Owned startup ordering established; native cold identity remains blocked.**
The [portable scaffold](../../tools/fixtures/cold-identity/README.md) executes
exact original authored glue and two tiny owned Wasm modules. Deferred startup
returns a genuine instance object that the harness can retain before fixture
initialization mutates state. Eager glue and Wasm start imports mutate before
post-return registration is possible and are refused. These are synthetic
program results, not native IDs, original-site callbacks, actual HSW startup
feasibility or a v1 transport implementation.

## Scope and inputs

Worked only in `/tmp/hsw-lane-worktrees/reb-BS-cold-identity`, starting at REB
`b2dce5ffb7cd559edd9acd8db8015643e911282b`, after reading `LANE_ROUTING.md`.
Initial status contained only that supplied untracked routing file; it is not
included in the deliverable. Read [BP](LANE_BP_NOTES.md), the repository safety
policy, build wiring, fixture/tool READMEs and `reb-validation` /
`reb-brave-verify`. `rg` is unavailable; bounded Git/find searches were used.

Read HSW's `analysis/gaps/gap1-guest-ops/ORIGINAL_BOUNDARY_TRANSPORT_V1.md`
through `/Users/sunny/.t3/worktrees/hsw-reconstruct`. That worktree was at
`cf7e7fa365510e1d49bdd4d5610ec03ee0308380`; the contract file has no diff against
the supplied PR head `1f64cff66c962cdb251fb838e5a9d0f2a37d5551`.
No HSW file was modified, retained target source was evaluated or BF identity
substituted for authored input identity.

No Verify, native-console start, live capture, target activity, source rewrite,
synthetic live transport, CDP, breakpoint, browser bootstrap/sync, push or PR.
Parent owns folds and PRs. Repository checks use their configured owned fixtures;
`make e2e` is skipped because its [native-console check](../../tools/check-native-console.py) sends start actions.

## Deliverable and observed behavior

[owned-program.js](../../tools/fixtures/cold-identity/owned-program.js) is the
498-byte complete original owned script. [pairs.json](../../tools/fixtures/cold-identity/pairs.json)
pins that script's SHA-256, the exact decoded bytes/digests of the 60-byte
no-start module and 63-byte start module, explanatory WAT and all four engine
pins. The host compiles the original source without injected code and passes
exact decoded module bytes. The deliberate import represents fixture state
mutation; no browser DOM or real page mutation is exercised.

[run.mjs](../../tools/fixtures/cold-identity/run.mjs) checks input hashes,
one-byte-change rejection and pin drift before compiling in an isolated Node
realm. [exercise.js](../../tools/fixtures/cold-identity/exercise.js) is reusable
shell input for a future pinned `d8` run. Its 13 named cases cover deferred
ordering, same-pair/different-instance equality, disabled and late attachment,
eager-glue/start-function refusal, six explicit owner invalidation reasons and
original exception propagation. Duplicate and missing-instance registration
are checked within those cases.

The retained object is an actual `WebAssembly.Instance`, not a guessed instance
ordinal. However, its reference equality is **not a native opaque instance ID**.
Document/context/instance/artifact/expiry/detach invalidation is driven by
explicit harness-owner notifications; actual browser observers, realm teardown,
automatic expiry and native root lifetime remain untested. No transport methods,
capability strings, identity bundle, callback records or terminal counters are
manufactured. `nativeCoverage` is null. All results retain
`SCAFFOLD_ONLY_NATIVE_IDENTITY_UNTESTED`, `pinnedEngineVerified:false`,
`nativeInstanceIdTested:false`, no original-boundary transport, no live joins,
zero deterministic joins and false parity/raw-rendering-parity/production proof.

The [fixture README](../../tools/fixtures/cold-identity/README.md#pinned-engine-continuation)
gives the next pinned-shell command and native cctest acceptance sequence.
Current guest IDs are assigned only in admitted executing guest frames;
`GetCurrentWasmGuestContext` cannot provide a cold identity outside that stack.
A native implementation must bind an already-existing real instance before
initialization, check the same ID at execution and invalidate actual lifetimes.
Running the initializer just to obtain an ID would violate cold attachment.
The eager/start results reject the post-return model; they do not rule out a
future engine hook between internal allocation and start execution. The actual
HSW pair's startup order remains unknown.

## Environment and validation

Pins remain Brave `v1.95.52`, Chromium `151.0.7922.108`, V8
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`, depot_tools
`a20039648c0de69d8156906b18052bd47e9bf230`. There is no lane-local
`browser/worktree/src/brave`, so independent upstream commits, dirty state,
overlay destinations, ordered replay and idempotence cannot be resolved.
`/Applications/Xcode.app` is absent. `xcodebuild -version` exits 1 because the
active developer directory is `/Library/Developer/CommandLineTools`. At startup the lane
filesystem had about 54 GiB free, below the 150 GiB first/unproven build reserve.
No large download, alternate checkout or global Xcode change was attempted.

- **Passed:** `node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run.mjs`, 13 named cases, exact input/pin checks and altered-byte rejection. Node 26.8.2 / V8 14.6.202.34-node.28; this is not the pinned engine.
- **Passed:** `node --check` for all three fixture JavaScript files. The normal root-glob syntax check does not discover this nested fixture, so these were checked explicitly.
- **Passed:** `make lint`, exit 0; `make repository-check` also passed after staging the six deliverables.
- **Passed:** `make check`, exit 0, including the explicitly enabled native golden, owned-helper and source-worker HTTP/CLI cases. Other configured ignored measurement/fixture tests remain ignored; no cold native-ID acceptance exists in this gate.
- **Passed:** `make sanitize`, exit 0, using macOS's configured `undefined` profile. Its component artifact check explicitly skips analyzer and HTTP/controller paths without optional `--analyzer` / `--backend`; it is not browser runtime acceptance.
- **Skipped by explicit task constraint:** `make e2e`. Its `native-console-check` prerequisite executes HTTP `action:start` in the scripted-peer fixture, which conflicts with the requested no-native-console-start boundary. No replacement gate or Makefile override was used.
- **Unavailable:** `make brave-doctor`, exit 2; first actionable failure: `Brave checkout is missing: /private/tmp/hsw-lane-worktrees/reb-BS-cold-identity/browser/worktree/src/brave`.
- **Unavailable:** pinned `d8` execution, native cold-ID acceptance, real document/context invalidation and executing HSW-pair startup feasibility; no initialized checkout, full Xcode or native cold-ID interface.
- **Skipped, not applicable to these tool/docs files:** `make brave-probe-check`, patch replay/destination checks, GN formatting and browser compilation; no pin, overlay, patch or GN file changed. `make app-build`, packaged codesign and `make rendered-ui-check` also do not apply; no Origin Trace UI/Swift/packaging/asset surface changed.
- **Passed:** all 17 local documentation links and explicit anchors, scoped diff/content review, `git diff --check` and staged whitespace check. Only the six intended files are staged; routing, build output and synthetic test stores are excluded.

## Parent handoff

Fold only this note and `tools/fixtures/cold-identity/`. Routing, ignored build
outputs, logs and synthetic test stores are excluded. No production API,
protocol, browser pin, overlay, patch or Makefile wiring changed.

The next concrete action is to run the shared owned suite in the pinned engine
on an initialized supported host, then implement/test genuine cold native
identity using the README acceptance sequence. Complete original-site
observations, async ownership, bounded value transport and browser lifecycle
invalidation remain BP follow-on work. Do not expose this scaffold through BQ
or advertise native original-boundary availability.
