# Lane BP — wave23 native original-boundary transport

**Architecture-blocked; native transport not implemented.** REB at
`13edcc68b7c45f4133758e7bae48ea261c740cc7` cannot supply
`hsw.original-boundary-transport.v1` through its current native interfaces.
There is no native registration, original-value callback or complete runtime
identity channel to wire to BJ/BA. Live linked chains remain zero and coverage,
executing-artifact pairing, parity and production proof remain unattested.
This is the explicitly permitted blocked-architecture handoff, not a completed
implementation or a new advertised capability.

## Scope and evidence

Worked only in `/tmp/hsw-lane-worktrees/reb-BP-transport`, after reading its
`LANE_ROUTING.md`. Initial status contained only that supplied untracked file.
Read the HSW reference worktree
`/tmp/hsw-lane-worktrees/lane-BP-reb-transport` at
`1137fbbc9dde4cc211afe69a56d5546e42d8b4c1`, without modifying it. The inputs were
BM's `analysis/gaps/gap1-guest-ops/ORIGINAL_BOUNDARY_TRANSPORT_V1.md`, BJ's
`LANE_BJ_NOTES.md` and BN's `LANE_BN_NOTES.md`.

Only this note is a lane deliverable. No production code, HTTP contract, UI,
probe, browser pin, overlay or patch changed. No live capture or target browser
was started; no prior-lane capture endpoint was contacted or inferred. Required
repository checks use their isolated synthetic backends/peers and owned fixtures.
No Verify, captcha/proof invocation, source rewrite, synthetic live transport,
CDP, breakpoint, review agent, push or PR occurred. Parent folds this lane.

Applied the repository `reb-validation` workflow. Read `reb-ui-e2e`,
`reb-brave-verify` and `reb-api-workflow` while classifying the native boundaries;
this final change is documentation only. `rg` was unavailable, so discovery used
bounded `git ls-files`, `git grep`, Python, `find` and `grep` operations, excluding
the generated browser checkout.

## Current product boundary

Offline inspection of the versioned
[OpenAPI contract](protocol/openapi.json) found exactly these runtime commands:
`evaluate`, `inspect`, `complete`, `await`, `release`, `cancel`, `store`, `source`,
`listeners`, `monitor`, `unmonitor`, `poll`, `clear`, `last`, `traffic`.
There are no boundary paths or boundary component schemas, and neither v1
transport nor plan literal occurs in tracked `apps/`, `browser/integration/`,
`protocol/`, `src/` or `include/` production files.

The relevant HTTP operation is `native_console_action`,
`POST /api/native-console/actions`, with `action:runtime` and an explicitly
selected live document. The backend
[`validate_command`](apps/origin-trace-backend/src/native_console.rs)
rejects an unknown runtime operation with `Invalid runtime operation` before
native runtime dispatch, once the existing session prerequisites are satisfied.
An idle backend first rejects the missing session; a fabricated session ID is
not a way to test native attachment. This lane did not send that request to a
live page. BJ/BN's reported HTTP and live structural observations are prior-lane
evidence, not a new BP runtime acceptance result.

The boundary inventory can be reproduced without network or capture:

```sh
python3 - <<'PY'
import json
from pathlib import Path
spec = json.loads(Path('protocol/openapi.json').read_text())
commands = spec['components']['schemas']['NativeConsoleRuntimeCommand']['oneOf']
print([op for item in commands for op in item['properties']['operation']['enum']])
print([path for path in spec['paths'] if 'boundary' in path])
print([name for name in spec['components']['schemas'] if 'boundary' in name.lower()])
PY
```

This characterizes offline API availability; it does not prove executing code,
runtime attachment, whole-page absence of hooks or a live negative callback test.

## Concrete implementation gaps

| Existing boundary | What it actually supplies | Why it cannot satisfy BM v1 |
| --- | --- | --- |
| [Console Mojo](browser/integration/brave/overlay/components/reverse_engineering_browser/common/native_console.mojom) and [renderer agent](browser/integration/brave/overlay/components/reverse_engineering_browser/renderer/native_console_agent.cc) | Exact document token, bounded command/reply, main-world context, deadline, context-release reset. | No cold registration lifecycle, executing-pair/instance identity, native event subscription or producer ownership. Existing document guards should be reused, not renamed as the eight-field identity. |
| [Public V8 console bridge](browser/integration/brave/patches/v8/0004-expose-native-console-public-interface.patch) | Explicit REPL/read-only lexical evaluation and bounded global lexical-name enumeration. | No arbitrary private closure access, original call/return observer, serializer return, cache state or finalizer append callback. Completing or retaining a function does not expose these. |
| [Native JS dispatch](protocol/native-js-dispatch-v1.md) and [V8 patch 0010](browser/integration/brave/patches/v8/0010-observe-native-js-dispatch-sites.patch) | Up to eight switch/indexed-call sites, selector kind/low bits, activation/parent metadata and optional handler spans. | BF needs 41 callback plus 13 support registrations, many at ordinary calls, returns and assignments. Arguments, receiver contents and strings are intentionally absent. Increasing the site cap would not supply the missing event semantics or async edges. |
| [Native Wasm guest capture](protocol/native-wasm-guest-v1.md) and [V8 patch 0008](browser/integration/brave/patches/v8/0008-capture-adapter-guest-state.patch) | Selected Liftoff numeric locals/memory and actual synchronous guest-stack identities. | Its public interface explicitly fails for cross-instance chains, untracked frames and async work. Instance IDs are assigned to admitted executing guest frames, not reserved for a pre-initialization JS attachment. It does not bind the original glue to that Wasm instance or observe JS closure values. |
| [Native probe component](browser/integration/brave/overlay/components/reverse_engineering_browser/README.md) | Fixed operation metadata, bounded event queues and explicit loss; optional bounded canvas result artifact. | Audio buffers, WebGL results, arguments and most return values are intentionally not captured. Queue drops do not establish original boundary coverage. Retained artifacts do not establish executing-instance pairing. |
| [Console runtime](browser/integration/brave/overlay/components/reverse_engineering_browser/renderer/native_console_runtime.cc) and [v2 contract](protocol/native-console-v2.md) | Ephemeral handles, primitive previews, DOM event monitors, messages and resource metadata. | No producer/collector tokens or dataflow edges. Text previews truncate and replace invalid UTF-8, so they cannot preserve the original UTF-16 serializer text, including unpaired surrogates. HTTP polling is not the required in-realm synchronous transport object. |

The nine capabilities therefore cannot be truthfully advertised together.
Adding only an HTTP operation, page-global object, queue or fake callback
adapter would leave the native observations absent. Subscription cannot invoke
HSW, a collector or a serializer to manufacture those observations.

Cold attachment also has an unresolved ordering prerequisite: the actual paired
Wasm instance must already be identifiable before the observed initialization.
The present engine interface cannot establish this. BP has not established
that the target's startup order permits it. Do not reserve an invented instance,
substitute a console binding ID, attach warm and clear `initialized`, or weaken
BM's identity requirements to make this pass.

BN's known-global completion issue remains separate. The current `Complete`
implementation begins from `context->Global()->GetPrototype()` and stops at
unsupported descriptors/interceptors. That is a code inspection finding, not a
confirmed cause of BN's `hsw` failure. Changing it without a rebuilt-browser
reproduction would neither establish private closure access nor deliver BM's
transport, so this lane includes no speculative completion fix.

## Next implementation boundary

1. Establish startup feasibility with an owned synthetic program first: exact
   original script/pair, genuine instance identity, cold registration and
   invalidation on document/context/instance replacement. If the real pair
   cannot meet this ordering, retain the blocker and take a separately versioned
   lifecycle proposal to the contract owner; v1 does not permit retroactive IDs.
2. Add a dedicated V8 original-site observation interface and ordered engine
   patches. Independently check the executing original bytes, UTF-16/UTF-8 spans
   and span digests from BF's actual machine report. Capture original entry,
   branch/cache decisions, returns and append records while preserving original
   returns/exceptions. Do not repurpose selector metadata or source rewriting.
3. Add native Promise/resource ownership through the scheduler, audio and font
   continuations, with per-invocation wrapper identities and explicit observed
   raw/input edges. Interleaved and reversed completions, pending-cache hits and
   epoch resets must remain distinct. Stack proximity and equal payloads cannot
   establish these edges.
4. Add bounded native value snapshots and an owned renderer subscription. Keep
   probes nonblocking and disabled by default; perform no file/socket I/O or
   arbitrary JS execution inside probe callbacks. Define the safe delivery point
   to the in-realm listener separately from raw observation, preserving snapshots
   before mutations. The existing JS dispatch callback contract forbids JS
   execution in the hook, so directly calling BJ from it is not a valid shortcut.
5. Reuse the existing HTTP-facing, exact-document control path for explicit
   arming/status/detach when the engine support exists. Wire a native-backed
   in-realm transport to BJ only after independently validating all nine
   capabilities and the complete cold identity. Keep raw values and serializer
   text out of HTTP status/errors and automatic evidence/export. Publish no
   successful placeholder capability while support is absent.
6. Enforce BM's 512-attempt/60-second bounds, reserved terminal slot, bounded
   snapshot count/bytes and loss/pending/restore accounting. Detach must stop
   ingress and synchronously report truthful terminal coverage without awaiting
   page Promises; BA still owns async hash drain. Navigation, expiry, full queues,
   late callbacks and partial attachment must invalidate incomplete coverage.
7. Prove the complete native-to-BJ-to-BA path with authored fixtures before
   separately authorized target observation. Required cases include private
   nested closures, two interleaved async producers, cache hit/miss/pending,
   original UTF-16 serializer returns, independent final-ID mismatch, mutation
   after snapshot, disabled/full/malformed/gap/expiry behavior and cleanup.

These are outstanding implementation steps, not changes made by BP. BM's fake
transport and two synthetic `LINKED_METADATA` chains remain synthetic. Existing
`TRANSPORT_REPORTED_UNATTESTED` and BA untrusted-caller labels must stay intact
even after a genuine producer exists.

## Validation and environment

REB input pins are Brave `v1.95.52`, Chromium `151.0.7922.108`, V8
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`, depot_tools
`a20039648c0de69d8156906b18052bd47e9bf230`. There is no
`browser/worktree/src/brave` in this lane, so resolved upstream commits,
destination checks, ordered patch replay and idempotence cannot be established.
`/Applications/Xcode.app` is absent; `xcodebuild -version` exits 1 because the
active developer directory is `/Library/Developer/CommandLineTools`. The
workspace disk reported 58 GiB free,
below the documented 150 GiB first/unproven integrated-build reserve. No large
download/bootstrap, alternate checkout, sync or global Xcode change was attempted.

- **Passed:** offline production API/schema and native-hook inventory above.
- **Passed:** `make lint` (exit 0).
- **Passed:** `make check` (exit 0), including the Makefile's explicitly enabled
  golden, owned-helper and source-worker HTTP cases. Cargo's other ignored
  fixture/measurement cases retain their configured ignored status; no native
  original-boundary acceptance test exists in this result.
- **Passed:** `make e2e` (exit 0), including native Console's scripted peer,
  exact snapshot pipeline, evidence-store checks and owned VM dispatch. Its
  pipeline explicitly does not exercise V8/Blink hooks, Mojo IPC or the browser
  artifact socket runtime.
- **Passed:** `make sanitize` (exit 0), using the Makefile's macOS
  `undefined` sanitizer profile. Its component test explicitly skips analyzer
  and HTTP/controller checks without their optional arguments; the separate
  repository checks cover those configured paths. No Brave runtime is implied.
- **Unavailable:** `make brave-doctor`, exit 2; first actionable failure:
  `Brave checkout is missing: .../browser/worktree/src/brave`.
- **Unavailable:** native original-boundary runtime acceptance; no implemented
  producer/subscription, no initialized browser checkout and no full Xcode.
- **Skipped, not applicable:** `make brave-probe-check`, GN formatting and
  affected/full browser compilation; no integration file changed and no
  initialized toolchain exists. Packaged app build, codesign, rendered UI and
  visual/keyboard interaction checks are also not applicable to this note-only
  change. They are not passing browser or application results.
- **Passed:** all 12 local note links resolve; final diff/content review,
  `git diff --check` and staged whitespace check. Only this note is included;
  routing, build output, synthetic evidence and logs are excluded.

Parent's next concrete action is an engine implementation lane on a supported,
initialized pinned browser build environment, starting with the cold-identity
feasibility fixture. Repeating console completion, polling or BA installation
cannot close this residual.
