# Owned cold-identity feasibility scaffold

This fixture starts [BP's first implementation step](../../../docs/origin-trace/LANE_BP_NOTES.md#next-implementation-boundary).
It establishes **host-visible startup ordering for an owned synthetic pair**.
It does not implement native identity, original-site observation, a browser
registration API, or `hsw.original-boundary-transport.v1`. Its reference binding
is private harness bookkeeping and cannot be passed to BJ/BQ as a transport.

Run the portable check from the repository root:

```sh
node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run.mjs
```

The relative command above assumes the repository root; the script resolves all
inputs relative to itself. It needs only Node.js and never opens a browser,
starts a service, reads a capture, contacts a target, or executes vendor code.
Package/Makefile wiring remains parent-owned; run it explicitly.

## Exact owned inputs

[owned-program.js](owned-program.js) is the complete original authored glue.
The host compiles its exact UTF-8 text with `vm.Script`; it does not prepend,
rewrite, wrap or inject instrumentation into that source. Its deliberate
`owned.mutate` import is part of the authored program, not an original-site
probe. The mutation counter represents fixture application initialization;
there is no DOM or actual page here. Creating the module/instance and defining
the factory are bootstrap work, so this does not claim zero JavaScript work
before registration.

[pairs.json](pairs.json) pins the 498-byte glue, its SHA-256, two complete Wasm
byte strings, their decoded lengths/digests, readable WAT descriptions, and the
four repository engine/tooling pins. Hex is decoded directly into the bytes
compiled by the engine. WAT is explanatory; no WAT compiler is used. The 60-byte
positive module imports `owned.mutate` and exports `initialize`, which calls
that import. The 63-byte negative module additionally starts `initialize`
during instantiation. These are owned hashes, distinct from the HSW BF pair;
no BF map, site coordinate or target startup behavior is inferred.

[run.mjs](run.mjs) checks the exact byte identities and pin drift before
executing either program. It also checks rejection of one-byte changes to the
glue and both modules. A fresh isolated Node realm compiles the unmodified
program and runs [exercise.js](exercise.js) with string code generation disabled.
Only a cached copy of the authored manifest is exposed through `read`; output
contains authored digests, fixed case labels and booleans, never an instance
handle or target value. Node/V8 versions are reported. A passing Node run
always retains `pinnedEngineVerified:false` and `nativeInstanceIdTested:false`.

## What the ordering cases establish

- Deferred startup returns a genuine `WebAssembly.Instance`. The harness retains
  that actual object before calling its original exported `initialize` function.
  The original Wasm import then sees the binding already active. No token is
  reserved before an instance exists.
- Two executions of identical glue/Wasm bytes create different instance objects.
  An attachment to the first cannot match the second. Artifact hashes identify
  inputs, not an executing instance.
- Missing-instance, disabled, duplicate and already-initialized registration are
  refused by the harness. Ordinary disabled activity still runs. Eager glue and
  a Wasm start import both mutate before the returned program exposes its
  instance; this post-return registration model must refuse them. This does
  **not** prove that a future internal engine hook could not register earlier.
- Explicit owner invalidation releases the retained reference once, refuses
  rebinding and stops counting registered mutations while ordinary work still
  runs. The document/context/instance/artifact/expiry labels model notifications;
  they are not real Blink observers, clock expiry or realm destruction tests.
- Original Wasm returns and an original import exception remain observable.

The result is `SCAFFOLD_ONLY_NATIVE_IDENTITY_UNTESTED`. A JavaScript object
reference is genuine instance equality in this fixture, but is not the native
opaque `instanceId` required by HSW. The suite mints no runtime identity bundle,
reports no native coverage, and never manufactures transport callbacks, source
availability, live joins, parity or proof. It cannot establish startup order
for the actual HSW pair.

## Pinned-engine continuation

The input pins are Brave `v1.95.52`, Chromium `151.0.7922.108`, V8
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`, depot_tools
`a20039648c0de69d8156906b18052bd47e9bf230`. Use the repository's
[integrated build path](../../../docs/development/integrated-brave-build.md)
and [Brave skill](../../../.agents/skills/reb-brave-verify/SKILL.md) on an
initialized supported host. Do not bootstrap or substitute an installed browser
merely to turn this scaffold's result green.

The same original program and suite are shell-compatible scaffold inputs for a
built `d8` from that pinned checkout. From the repository root, after the Node
input check and independent source/binary provenance checks:

```sh
/path/to/pinned/v8/out/native-runtime/d8 \
  tools/fixtures/cold-identity/owned-program.js \
  tools/fixtures/cold-identity/exercise.js
```

That command is **unrun** here. `read`/`print` are shell host functions, not page
APIs. The suite does not verify a shell binary's provenance; its
`pinnedEngineVerified` stays false even when a caller selects a pinned build.
Record checkout commits, ordered patch state, build arguments, actual shell
version/binary and command result separately. A successful shell run would
establish engine startup ordering only, not native IDs or browser acceptance.

The next native cctest must use these exact owned bytes, with this acceptance
sequence before proposing any production API:

1. Compile the original script and Wasm from checked bytes. Retain the actual
   instantiated engine object while cold. Bind a native ID only to that existing
   object; no reservation, ordinal guessed from a dispatch, console document ID,
   backend ID, fake transport or source rewrite can substitute.
2. Establish an engine-backed lookup before invoking `initialize`. The current
   [guest-state patch](../../../browser/integration/brave/patches/v8/0008-capture-adapter-guest-state.patch)
   only assigns IDs at admitted executing guest frames. Its
   `GetCurrentWasmGuestContext` stack lookup fails outside such a live frame;
   calling the initializer to obtain an ID would make this fixture warm.
   There is no cold lookup API to call in this scaffold. Do not change the
   fixture's truthful result by labeling the retained JS reference a native ID.
3. At the first original import, check that the same native ID resolves the
   same executing instance and exact original pair. Repeat with two instances
   of the same module, interleaving and forced GC to check handle lifetime.
   Before an ID exists or after it is invalidated, lookup must fail closed.
4. Repeat the negative eager-glue and Wasm-start cases. An internal hook may
   potentially observe an allocated instance before its start function; require
   an actual hook/order test to claim that. If initialization predates the
   complete genuine identity, refuse v1 and take a separately versioned lifecycle
   proposal to the contract owner. Never clear initialized state retroactively.
5. Destroy/replace actual V8 contexts and instances, then wire real native
   document/navigation invalidation in the browser. Reject the old generation,
   release native roots, and require fresh run/transport objects. Owner calls in
   this JS model do not prove those lifecycle sources or automatic cleanup.

Original JS closure/site callbacks, safe delivery, async/resource ownership,
complete eight-field identity, nine capabilities, bounded snapshots and terminal
coverage remain separate BP follow-on work. No production contract, overlay,
patch or operation is added here. Full Xcode and the initialized Brave/V8
checkout are unavailable in BS; see the [lane handoff](../../../docs/origin-trace/LANE_BS_NOTES.md).

## BV native cold-ID continuation

[The native binding proposal](../../../docs/origin-trace/LANE_BV_NOTES.md#native-cold-instance-binding-proposal) specifies binding an
already-existing engine instance, an independent pre-execution coldness witness,
shared cold/warm native identity, exact-pair admission and lifetime ownership.
It adds no V8 API or production patch. [native-exercise.js](native-exercise.js)
is a future native test-host contract; its positive assertions are unrun.
The original owned inputs and 13-case Node scaffold remain unchanged.

```sh
node --disallow-code-generation-from-strings tools/fixtures/cold-identity/run-native.mjs
```

This additional entrypoint deliberately exits **78 (unavailable)** after
checking exact inputs and missing/malformed native-host refusal. It constructs
a cold actual instance, performs zero fixture mutations, and binds no ID. It
does not launch a shell or accept a JS adapter as native provenance. All native,
pinned-engine, transport and production flags remain false; coverage stays null.
See [BV's command/blocker record](../../../docs/origin-trace/LANE_BV_NOTES.md)
before claiming any pinned-engine or native acceptance result.
