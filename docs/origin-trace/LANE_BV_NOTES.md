# Lane BV — wave25 pinned-engine cold native identity

**Pinned runtime blocked; native binding design and fail-closed acceptance stubs
added. No native ID API is implemented.** The unchanged Node scaffold still
establishes owned startup ordering only. The separate native entrypoint exits
78 before initialization because there is no native test host. It does not
promote a retained JS object to native identity or provide a transport.

## Scope and deliverables

Worked only in `/tmp/hsw-lane-worktrees/reb-BV-pinned-cold-id`, branch
`lane-BV-pinned-cold-id`, from `57f46b5efa7e9abb5f7ab63a033ea9859946eeb5`
(REB PR #374 after BS). Read the supplied `LANE_ROUTING.md` first. Initial
status contained only that untracked routing file; it remains excluded.
Applied the lane-local `reb-validation` and `reb-brave-verify` skills, safety
policy and integrated build guidance. `rg` is unavailable; bounded Git/file
searches were used. No other checkout was edited.

Read HSW's `analysis/gaps/gap1-guest-ops/ORIGINAL_BOUNDARY_TRANSPORT_V1.md`
through `/Users/sunny/.t3/worktrees/hsw-reconstruct`, at
`f3a0e026def03f9ffdfab16a92237b6978efbe9d`. HSW was read-only. The owned hashes
remain distinct from BF's target pair; no vendor source was executed.

Owned changes:

- [Native design](#native-cold-instance-binding-proposal):
  proposed engine operations, independent coldness witnesses, exact-object and
  executing-pair association, shared cold/warm IDs, bounded registry and native
  handle/invalidation ownership. All are proposals, not new V8 declarations.
- [Native exercise](../../tools/fixtures/cold-identity/native-exercise.js):
  future cctest-host assertions for cold lookup, first original import, two
  original-pair instances, shared-module instances, interleaving/full GC,
  invalidation and eager/start negatives. Positive native paths are unrun.
  No native host is implemented.
- [Unavailable entrypoint](../../tools/fixtures/cold-identity/run-native.mjs):
  checks exact bytes/pins and absent/accessor/incomplete-host refusal in isolated
  Node realms, leaves the actual instance cold, and deliberately exits 78.
- [Fixture README](../../tools/fixtures/cold-identity/README.md): continuation
  command and limits. BS's `owned-program.js`, `pairs.json`, `exercise.js` and
  `run.mjs` are unchanged, including all existing flags and 13 cases.

No production file, Makefile, gate, HTTP/MCP operation, browser pin, overlay,
patch, BQ ingress, callback stream or runtime identity bundle was added.
No Verify, native-console start, browser/target activity, bootstrap/init/sync,
download, Xcode install/global selection change, push or PR was performed.

## What the design resolves and leaves open

[Patch 0008](../../browser/integration/brave/patches/v8/0008-capture-adapter-guest-state.patch)
allocates native instance IDs at admitted Liftoff entry and exposes guest
context only after a selected dispatcher boundary on the live stack. Its weak
global handle is GC-updated, not a lifetime root. The owned module contains no
`br_table`; warming it would neither satisfy cold binding nor establish that
selected context. No upstream patch was attempted without an initialized tree.

The proposed bind takes an already-existing native instance handle and allocates
an ID only on successful binding. It requires an independent native coldness
witness armed before construction; otherwise prior execution is unknown and
binding refuses. An armed owner is not a reserved instance ID. The execution
transition must precede the first start/export/import instruction, not merely
the eventual mutation callback. Caller-supplied `initialized:false` cannot
establish this. Wasm coldness also cannot establish original JS initialization
order or all nine transport capabilities.

Current-instance lookup must resolve the actual innermost bound Wasm instance
without selected dispatch, and fail closed instead of borrowing an outer ID.
Cold and later warm lookups must share one native object/ID association while
preserving existing guest admission and reset semantics. The native owner must
independently check executing script/module bytes and own/release real V8
handles. These are specific implementation obligations, still uncompiled and
unrun on the pinned engine.

| BS acceptance | This lane's evidence | Remaining gate |
| --- | --- | --- |
| 1. Exact bytes and existing cold instance | Node exact-input checks and actual cold object construction pass. | Native compile/object/pair association and native bind. |
| 2. Lookup before initialize | Native entrypoint stops unavailable with zero mutations and no ID. | Implement and run real engine-backed lookup while still cold. |
| 3. First import, two instances, GC, fail-closed lifetime | Assertions specified in native test-host exercise; none run against a native host. | Pinned native adapter/cctest plus actual root/collection and bounds tests. |
| 4. Eager glue and Wasm start | Existing Node negatives still refuse; native post-return negatives specified. | Real native refusal; any claimed pre-start alternative needs its own hook/order evidence. |
| 5. Destruction and document/navigation invalidation | Explicitly not claimed. | Native context/instance teardown and browser runtime observers. |

## Native cold instance binding proposal

**Offline design and acceptance stubs; no native API is implemented.**
This extends [BS's acceptance sequence](../../tools/fixtures/cold-identity/README.md#pinned-engine-continuation).
The instance ID is only one prerequisite of HSW's eight-field identity and nine
capabilities. Nothing here supplies a transport, original-site observation,
executing HSW-pair proof, terminal coverage or browser lifecycle acceptance.

### Existing engine boundary

[V8 patch 0008](../../browser/integration/brave/patches/v8/0008-capture-adapter-guest-state.patch)
uses `EnterGuestFrame` to allocate instance IDs after module admission, on
instrumented Liftoff entry. `RebGuestInstance::root` is a **weak**, GC-updated
global handle; despite its name it does not retain an otherwise dead instance.
`ResetRebGuestCapture` destroys those handles and preserves `next_id`.
`GetCurrentRebGuestContext` walks actual Wasm frames, requires tracked identities
and a selected dispatcher boundary, and returns false outside that stack.

The owned deferred module has **no `br_table`**. Even running its initializer
would not create the selected dispatcher context that this lookup requires.
Adding a dispatch just for this test changes the exact bytes and fails its
purpose. An existing JS reference, weak map, retained export, module hash or
object ordinal must not be formatted as a native ID.

### Proposed native operations

These are proposed C++ engine/embedder operations, **not declarations added to
V8, HTTP commands, Console operations or page APIs**. Exact V8 signatures and
hook locations require inspection/compilation against the pinned initialized
tree. Do not export the test-host names below to a page.

| Operation | Native inputs | Result and constraints |
| --- | --- | --- |
| Arm owner | Current native context, explicit enabled lease/generation, independently checked exact script/module admission policy | A native owner scope, not an instance ID. Install coldness witnesses before compiling/instantiating the owned program. Disabled/unsupported setup refuses without allocating probe state. |
| Bind existing instance | Owner scope, actual `v8::Local<v8::Value>` identifying an existing `WasmInstanceObject` | Only on success, allocate a nonzero native ID and bind that exact object/context/pair. No JS property lookup, `instanceof`, proxy unwrapping, initializer/export call or reservation. Reject unknown coldness, warming, wrong context/pair, duplicates, capacity and retired owners. |
| Lookup existing instance | Owner scope, actual native instance handle | Return its existing ID only; never mint, admit or warm on lookup. Clear output before every failure. |
| Lookup current bound instance | Owner scope and current native context | Resolve the innermost actual Wasm instance at an original import through a bounded native stack walk. Return an already-bound ID only, without a selected dispatcher or `br_table` prerequisite. Never skip an unbound/foreign/unsupported innermost Wasm frame to borrow an outer ID. Outside Wasm return unavailable. |
| Invalidate binding/owner | Exact native instance or native owner generation and reason | Revoke the target binding, or all bindings of a retired owner, before releasing roots/frame references. Targeted invalidation leaves other bindings intact. Idempotent; never recycle an ID or rebind an invalidated object within that owner. |

Use distinct statuses such as `disabled`, `unsupported`, `coldness-unknown`,
`already-started`, `wrong-owner`, `pair-mismatch`, `already-bound`, `capacity`,
`id-exhausted`, `not-bound` and `retired`. All failures contain no ID. Use opaque
monotonic native values in an owner/isolate namespace, never addresses or user
strings. Check overflow without wraparound. A future native formatter may
expose a scalar token matching the contract grammar; this fixture constructs
no identity bundle and prints no ID.

#### Coldness needs an independent witness

An existing object proves neither that it is cold nor that its glue has not
initialized. Arm the proposed owner **before construction**; allocate the ID
**after construction**, at bind. This reserves no instance or ID. Instances
predating the witness are unavailable even if a caller says `initialized:false`.

The witness must observe actual allocation and the earliest execution transition,
including a Wasm start function and JS-to-Wasm entry, before the first
instruction/import. Observing `owned.mutate` is already too late. Imported
function re-exports, optimized calls and other entry modes need explicit
coverage; missing modes refuse binding. A bounded native weak entry with no ID
remembers a new candidate and marks it started monotonically before execution,
even when not yet bound. A full witness table makes eligibility unavailable,
never assumes an unseen object is cold. Disable/re-enable and policy replacement
retire the generation and cannot recover coldness retrospectively.

The deferred returned object can then bind before `initialize`. Eager glue calls
the export before returning; the start module calls it before construction
returns. Both must refuse this **post-return** bind. An internal pre-start model
requires a separate real hook/order test. If initialization predates complete
v1 identity, retain refusal and request a separately versioned lifecycle from
the contract owner. Never reset initialized state.

This witness establishes Wasm execution order only. Original glue initialization
sites, source spans/closures and safe subscription delivery remain separate BP
work. A native Wasm ID alone cannot make v1 available.

The proposed native entry stores a GC-updated actual-object key, owner/context
generation, independently verified pair association, optional ID and a monotonic
state: `candidate-cold` → `bound-cold` → `bound-active`, or `candidate-cold` →
`started-unbound` when execution precedes bind. Unknown entries cannot bind.
Invalidation leads to `retired`; keep a weak per-object tombstone until collection
or owner retirement so invalidating a still-cold object cannot accidentally
make it eligible again. All candidate, bound and tombstone slots count against
the same fixed capacity. A live owner cannot hide a full table by forgetting
retired objects. Active bound lookup keeps the ID; cold bind never accepts
`started-unbound`, `bound-active` or `retired`.

#### Shared native identity and lifetime

Extract the GC-updated instance key/ID allocation from the warm-frame path into
a shared native registry, or prove an equally strict bridge. Cold bind and later
admitted execution must reuse the same actual-object entry. Two instances of
equal modules, including instances sharing one module, must never share IDs.
Keep guest module/site admission intact: a cold entry grants no numeric-local/
memory capture. Replacing guest policy or resetting capture must revoke shared
identities that policy owns and notify attachments; stale tokens cannot survive
under an apparently live owner. Preserve guest invocation/parent/drop semantics
and monotonic IDs.

Proposed initial fixed limits are 16 candidate/bound entries per isolate and
128 Wasm frames examined per current-instance query. Expose exhausted/unknown
control results. Never evict a live binding, hash/allocate on a disabled hot
path or borrow a prior frame after missing identity. Bind can hash outside the
probe hot path; current lookup performs no JS, file/socket I/O or unbounded work.

The attachment owner, separate from the weak identity key, deliberately retains
a bounded strong V8 handle while attached if needed. Invalidation releases it
synchronously. Test movement while retained, then prove actual collection after
all attachment/JS/export roots are dropped. Explicit invalidation while JS still
retains an instance is not destruction. Context/document/navigation teardown
must revoke before callbacks can use the old generation. No owner pointer may
outlive its isolate.

#### Exact executing pair

The native host independently checks the compiled original script's exact UTF-8
input and the selected instance's actual module wire bytes against
[pairs.json](../../tools/fixtures/cold-identity/pairs.json). Preserve native compile/context and actual-instance
associations. JS-supplied digests, static module matches and stack proximity do
not establish an executing glue/Wasm pair. Do not invoke target getters/functions
to discover identity. The owned pair is not BF's HSW pair and cannot inherit
BF's hashes or original-site coordinates.

The proposed creation witness must associate that exact allocated instance with
the native compiled-script identity and actual constructor callsite that created
it, not merely a matching script elsewhere in the context. Require the native
creation event and independently checked original source position; if the pinned
engine cannot supply that association, executing-pair acceptance stays blocked.

### Executable test stub

[native-exercise.js](../../tools/fixtures/cold-identity/native-exercise.js) specifies a **test-only** native host
named `__rebColdIdentityNativeTest`. A future cctest installs it during owned
context setup, arms native witnesses, then compiles the exact original script.
No adapter is supplied here. Expected methods:

| Test-host method | Return | Native obligation |
| --- | --- | --- |
| `bindExisting(value)` | Opaque string ID or `null` | Call native bind; map refusals to `null`, never implement a JS registry. |
| `lookupExisting(value)` | Existing opaque string ID or `null` | Resolve the actual native object without minting an ID. |
| `lookupCurrent()` | Existing opaque string ID or `null` | Resolve the actual innermost executing native instance at this synchronous import. |
| `invalidate(value)` | `undefined` | Revoke the exact binding and release its native attachment root. |
| `forceFullGc()` | `undefined` | Perform pinned engine full/moving GC through cctest. |

Positive assertions are **unrun**: lookup while still cold; same native ID at
the first authored import; two instances from the exact same original pair;
an additional instance sharing the first compiled module; interleaved
imports and full GC with retained objects; no ID before bind/after invalidation;
duplicate/malformed/proxy refusal; warm/eager/start negatives. The extra
same-module constructor is test code, not a rewrite of the original program.
No private site, event stream or transport callback is fabricated.

That extra constructor tests object identity only. Its native test owner must
separately admit/check the actual owned test script that contains it; it is not
a second execution of `owned-program.js` and cannot inherit that glue's digest
as its executing-script identity. The first factory-created instance remains
the exact-original-glue pair case. Native cctest must check these associations
directly; the JS token assertions cannot establish them.

Own-data method checks reject missing/malformed hosts without invoking getters.
They cannot attest a function is native. Even a future completed JS assertion
run exits 78 and reports `NATIVE_TEST_HOST_ASSERTIONS_ONLY`, `nativeInstanceIdTested:false`
and `pinnedEngineVerified:false`. Only independently recorded native cctest/
source/binary evidence can support native acceptance. Changing a global object
or these flags supplies none. Tokens stay private to the test, never output.

```sh
node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run-native.mjs
## Expected exit 78: BLOCKED_NATIVE_COLD_ID_API_UNAVAILABLE, zero mutations.
```

[run-native.mjs](../../tools/fixtures/cold-identity/run-native.mjs) independently verifies the exact owned bytes
and pins, compiles the unmodified original script in isolated Node realms, and
checks absent, accessor and incomplete hosts. It supplies no native callbacks
or IDs. All three refusal assertions must hold; the process **still exits 78**,
not success. Unexpected assertions exit nonzero as errors. It never searches
for/launches an engine or trusts provenance JSON. It does not run positive
native cases on Node. The original 13-case scaffold remains unchanged.

On a supported host, record pinned source commits, ordered patch state, build
args, actual binary path/SHA-256/version and exits independently. Run the
unchanged suite in pinned `d8` before implementing the adapter. Ordinary `d8`
running `owned-program.js native-exercise.js` must exit 78 without the
cctest-only host. Installed browsers, Android `d8` and arbitrary same-version
shells cannot substitute for pinned build provenance.

### Remaining native acceptance

Besides executing the positive stub against native operations, cctest must
directly check native object/compiled-byte associations, not just token equality.
Add capacity/overflow, disabled/no-state, expired/replaced owner, wrong-context/
pair and nested cross-instance import barriers. Prove late arming has unknown
coldness and the first entry witness precedes every supported start/export/import
path. Add an original throwing import with unchanged exceptions/returns and
check existing guest tests with/without the new hooks.

Context disposal/recreation, dropped-instance collection, root release and new
generation acceptance require the native owner outside the destroyed realm.
Real document/navigation invalidation additionally needs the browser runtime.
These are follow-on gates, untested by retained-object GC assertions or BS's
owner notifications. Full original-boundary transport remains unavailable.

## Exact environment blockers

All commands below ran from this lane worktree. Source pins remain Brave
`v1.95.52`, Chromium `151.0.7922.108`, V8
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`, depot_tools
`a20039648c0de69d8156906b18052bd47e9bf230`. No independent upstream checkout
commits, dirty states, overlay destinations or ordered replay can be established
from this lane's missing generated checkout.

| Command | Exit | Observed result |
| --- | ---: | --- |
| `test -d /Applications/Xcode.app` | 1 | Full Xcode absent. |
| `xcode-select -p` | 0 | `/Library/Developer/CommandLineTools`. |
| `xcodebuild -version` | 1 | Requires Xcode; active developer directory is a command line tools instance. |
| `df -k .` | 0 | `/dev/disk3s5`, 53,529,580 available KiB = 51.05 GiB, below the 150 GiB first/unproven build reserve. |
| `test -d browser/worktree/src/brave` | 1 | No lane-local initialized Brave checkout. |
| `command -v d8` | 0 | `/opt/homebrew/bin/d8`, an Android dex launcher, not V8. |
| `/opt/homebrew/bin/d8 --version` | 1 | Integer-expression diagnostic, then unable to locate a Java Runtime. No V8 version. |
| `mdfind 'kMDItemFSName == "d8"c'` | 0 | Android SDK dex launcher and a pnpm store directory; no V8 shell returned. |
| `/Users/sunny/Library/Android/sdk/build-tools/36.0.0/d8 --version` | 1 | Unable to locate a Java Runtime; no V8 version. |

Resolved PATH launcher:
`/opt/homebrew/share/android-commandlinetools/cmdline-tools/latest/bin/d8`,
SHA-256 `57335fee880b9c269ba9eabdc9034f3b1f34e7b0d64a6d6bc6e40b65ffda4d49`.
Spotlight SDK launcher:
`/Users/sunny/Library/Android/sdk/build-tools/36.0.0/d8`, SHA-256
`b773a721be3d4988dea9660815a9e441b76100e5b0f5c72b5893cfadadc76c6f`.
Hashes were obtained with `Path.resolve(strict=True)` and
`hashlib.sha256(path.read_bytes()).hexdigest()`. The pnpm `files/d8` hit is a
directory, not an executable. No fixture was passed to either Android launcher.
A broader `find /Applications /opt/homebrew /usr/local /private/tmp /Users/sunny -name d8 -type f -print`
was stopped with SIGTERM (exit 143) after several minutes without output; that
incomplete scan establishes no absence.
These probes do not establish exhaustive disk absence, but locate no pinned
V8 binary or usable provenance record. No Java installation or alternate engine
was attempted.

## Validation

- **Passed:** initial `node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run.mjs`, exit 0, all 13 cases and unchanged exact-input/altered-byte/pin checks. Node 26.8.2 / V8 14.6.202.34-node.28 is not the pinned engine.
- **Unavailable as designed:** `node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run-native.mjs`, exit 78, `BLOCKED_NATIVE_COLD_ID_API_UNAVAILABLE`. Three offline refusal assertions hold, zero fixture mutations, no native host assertions completed. This is not a passing native acceptance test.
- **Passed:** `node --check` for both added JS files, exit 0.
- **Passed:** `make lint`, exit 0, including the configured Clippy, source/tooling and repository checks. Nested fixture syntax/refusal checks were also run explicitly.
- **Passed:** `make sanitize`, exit 0, using macOS's configured `undefined` profile. Its component artifact check explicitly skips analyzer and HTTP/controller paths without optional `--analyzer` / `--backend`; this is not browser runtime acceptance.
- **Passed:** `make check`, exit 0, including configured native golden, owned-helper and source-worker HTTP/CLI cases. Other configured ignored fixture/measurement tests retain their ignored status. There is no native cold-ID acceptance test in this gate.
- **Passed:** `make repository-check` after staging deliverables, 22 local file links/anchors, scoped content review, `git diff --check` and staged whitespace check. Only the four owned deliverables are included; routing, build/log output and synthetic stores are excluded.
- **Skipped by explicit lane constraint:** `make e2e` (native Console start actions) and `make brave-doctor` (checkout missing). No target or safety gate was changed to bypass them.
- **Unavailable:** pinned `d8`, cold native cctest, executing HSW-pair startup and actual context/instance/document/navigation invalidation. Missing pinned native binary/checkout and full Xcode; first/unproven build disk reserve is unmet. No supported build was attempted.
- **Skipped, not applicable:** `make brave-probe-check`, patch replay/destination/idempotence, GN formatting and affected/full browser compilation: no browser integration file changed, and no initialized toolchain exists. App build/codesign/rendered UI checks do not apply to fixture/docs-only changes.

All outputs retain `nativeInstanceIdTested:false`, `pinnedEngineVerified:false`,
`nativeOriginalSitesTested:false`, `browserLifecycleTested:false`,
`originalBoundaryTransportAvailable:false`, `nativeCoverage:null`,
`liveJoinTested:false`, zero deterministic joins and false parity/raw-rendering
parity/production proof. Even a future completed JS test-host assertion run
cannot attest its functions are native; separate cctest and binary/source
evidence is required. No production transport availability or native coverage
is claimed.

## Parent fold

Fold only this note and the changes under `tools/fixtures/cold-identity/` into
REB PR #374. No separate PR is needed for these owned fixture/design changes.
Exclude routing, ignored build/log output and synthetic test stores. Parent
owns folding, pushing, PR work and merging.

Next concrete action: on an already-supported initialized host, record exact
pinned source/binary provenance and run the original scaffold in pinned `d8`;
then implement the proposed native witness/bind/current lookup and run native
cctests. Real browser invalidation and the remaining BP transport requirements
stay follow-on. Keep BQ transport unavailable until the genuine producer exists.
