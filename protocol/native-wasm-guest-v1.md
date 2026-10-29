# Native Wasm guest observations v1

This opt-in path captures actual Liftoff numeric locals and linear-memory bytes
inside Brave/V8. It does not use CDP, execute an emulator, or accept page-reported
PCs. A reviewed adapter interprets these observations; arbitrary interpreter
semantics cannot be inferred from a `br_table` selector alone.

## Enablement and supported target

Use a rebuilt browser containing the ordered V8/Chromium patches and overlay.
Set `REB_NATIVE_WASM_DISPATCH=1` and
`REB_NATIVE_WASM_GUEST_ADAPTER=/absolute/path/adapter.json` when launching a
native session. The category mask must include VM (512) and artifacts (1024);
include Canvas (1) for the public fixture's synchronous host probe.
The adapter is immutable for the browser lifetime, bounded to 8192 bytes, and
must exactly match canonical compact JSON (no trailing newline). See
[native-wasm-guest-adapter-v1.schema.json](native-wasm-guest-adapter-v1.schema.json)
for one site and
[native-wasm-guest-adapter-v2.schema.json](native-wasm-guest-adapter-v2.schema.json)
for up to eight. Restart the browser to change it. Capture remains subject to session/category,
expiration, document, artifact authorization, and resource limits.

The pinned [public QuickJS fixture](../tools/quickjs-native-fixture/README.md)
provides a real, unmodified interpreter and a source/binary-verified mapping:
function 414, dispatch module offset 132727, opcode-address i32 local 320.
Bytecode base/length are bounded memory chains from local 10. The Rust verifier
checks the exact module digest and actual compiled fetch/selector/bounds pattern.
Other adapters are explicitly adapter-declared, not automatically verified ISA
recovery. This target establishes no hCaptcha-specific support.

### Multi-site adapters

A version 2 adapter lists 1 to 8 dispatch sites of one module, each with its
own function, br_table offset, PC local, bytecode chain, opcode format and
import call offsets. A version 1 adapter is read as a one-site version 2
adapter. Sites must name distinct dispatcher functions in strictly increasing
`function_index` order: that rejects duplicate sites, gives one canonical
spelling, and makes every activation belong to exactly one site, so its parent
walk and host attribution stay unambiguous. Two dispatch loops in one function
are not supported.

All sites share one `sample_limit` (at most 256), the renderer's 128 sampled
activations and its document bindings. The 16 MiB snapshot budget is therefore
never multiplied per site: it stays at most 256 snapshots of 65536 bytes. When
the shared limit is reached the next sample at any site records
`native_guest_sample_limit`, as with one site. The browser's session parser
refuses a malformed version 2 adapter (too large, 0 or more than 8 sites, a
duplicate or out-of-order site, a per-site or over-limit budget, or version 1
keys mixed in) and the native session does not start.

## Capture and identity

Event 18 (`wasm_guest_dispatch`) has a 128-byte version-1 little-endian payload
and event 19 (`wasm_guest_invocation`) a 128-byte version-3 payload. Readers
still accept version-1 invocations, which reserved bytes 72..128, and
version-2 invocations, which reserved bytes 80..128. The
authoritative offsets and encoders are `include/reb/wasm_guest.hpp` and overlay
`common/native_wasm_guest_wire.h`; no native structure padding is serialized.
The event header retains the original renderer process/sequence identity.
Invocation events identify exact module, instance, activation and retained
adapter artifact. Dispatch events retain raw PC-local bits, checked signed
adjustment, resolved byte-offset PC, selector, separately decoded opcode,
bytecode artifact/range, and recipe SHA-256. Dispatch parent is its exact
invocation event. Wide identity, raw-bit, memory-base and adjustment JSON fields use canonical
decimal strings. The resolved PC is a bounded JSON integer (at most 65535).

Numeric local indices include parameters and are not limited to the first 32
locals. Compiler metadata and active-frame checks control access; reference
values and host addresses are never exposed. Memory snapshots reject shared
memory and out-of-bounds/overflowing ranges. A snapshot is at most 65536 bytes;
adapter sample limit is 1–256, with a 16 MiB aggregate bytecode-snapshot budget
(module and adapter artifacts are additional). The renderer retains
at most 128 distinct sampled activations per capture configuration; this can
stop coverage before the sample limit. Separately, the engine bounds its active
frame/instance bookkeeping. Resource exhaustion
fails closed rather than silently resetting a budget or inventing observations.

Module and adapter artifacts are acknowledged before publishing invocation
records; snapshots are acknowledged before dispatch records. Pending host
records retain original parent IDs and wait for that exact retained dispatch.
Rejection, navigation, expiry and bounded-queue loss clear the binding; they do
not retarget it to the last successful sample. Delayed IDs retract provisional
sequence holes in broker/Rust/JS/Swift summaries. Explicit drops remain drops.

### Parent activation and exact outer dispatch

| Invocation bytes | Field |
| --- | --- |
| 64..72 | `parent_invocation_id`: the enclosing guest activation, or 0 |
| 72..80 | `parent_dispatch_sequence_number`: that activation's retained dispatch that was current when this one began, or 0 |
| 80..84 | `site_index`: this activation's position in the adapter's sorted site list, below 8 |
| 84..128 | reserved, zero |

A nonzero parent dispatch requires a nonzero parent and a smaller sequence
number than the invocation marker. Version 1 reserved bytes 72..80, so a
version-1 marker has no exact dispatch. Versions 1 and 2 reserved bytes 80..84,
so their site is 0. Every dispatch of an activation is at the site its marker
names; the dispatch payload carries that site's function and module offset, and
the browser and analyzer refuse a dispatch at any other configured site.

V8 resolves the parent once per activation, at its first selected boundary,
with one walk of at most 128 Wasm frames. JavaScript frames between them, such
as a host import that reenters Wasm, are skipped, as in host attribution. The
nearest enclosing activation that reached a selected boundary, at any
configured site, is the parent. Tracked activations that never did, such as a
dispatcher call that only runs a native function, are skipped. An enclosing
frame of the same dispatcher function, or of any other configured site's
dispatcher function, without identity (it began while capture was off, its
instance was not tracked, or the frame table overflowed), a non-Liftoff frame,
or a deeper stack makes the parent unresolved: V8 never skips to an older
activation. The renderer gives V8 that function predicate with the site
predicate. It matches function indexes only, so an unrelated module's frame
with a configured index also makes the parent unresolved, never misattributed. Without guest
capture compiled in, enabled and unexpired there is no walk and no state.

The renderer names the parent's retained current dispatch, the same exact
dispatch used for host parents. Every later selected boundary of the parent
revokes it, and so does a selected boundary without identity. When the parent
is unresolved, or its current dispatch was not retained (sample limit,
snapshot failure, transport loss, revocation or another document), the marker
names at most the parent activation with dispatch 0, and the renderer emits
`native_guest_parent_unresolved` once per capture configuration. Nothing is
guessed. The browser validates these fields and never retargets them; a named
dispatch that the browser later turns into a gap leaves the link unproven in
the [opcode workspace](vm-opcode-workspace-v2.md#observed-claims-and-nested-guests).
A guest call or host reentry of the same interpreter, such as QuickJS
`JS_CallInternal` recursion, therefore names its caller's call dispatch, and an
inner interpreter at another configured site names the outer site's current
dispatch.

### Module binding and loss accounting

The renderer sends module bytes with the first sample of a document binding and
then only empty-module samples, until the browser reports a verdict through
`NativeProbeClient.NativeGuestModuleStatus(epoch, module_token, accepted)`. The
token is the sequence number of the dispatch that carried the bytes; a verdict
for a retired configuration or another token has no effect. Acceptance means the
module and adapter artifacts were both accepted by the receiver. A rejection
makes the next sample resend the bytes, at most 3 transfers per binding; after
that the renderer records `native_guest_module_unavailable` and stops sampling
that binding. Samples sent while a transfer is pending bind to it, and become
explicit gaps if it is rejected.

Every browser refusal of a guest capture (invalid record, adapter or module
mismatch, missing owning document, unbound or lost module binding, snapshot
transfer failure, sample budget) emits a `gap` that reuses the refused
dispatch's own renderer process and sequence number, so it closes that
provisional hole instead of leaving it. Invocation sequence numbers are reused
by later samples and are not filled this way.

Host API-call and property-read records travel the parent-binding path for at
most 256 records per capture configuration; later ones stay on the ordinary
queue without a parent after one `native_guest_host_parent_budget` marker. The
browser publishes each routed host exactly once: with its parent and module
artifact when that dispatch is published, or immediately without a parent when
the parent was lost (`native_guest_host_parent_lost`) or more than 64 hosts are
already held (`native_guest_host_parent_omitted`). Host records are never
dropped because their parent was. About 250 ms before session expiry the
browser turns unresolved guest dispatches into `native_guest_pending_at_expiry`
gaps and publishes their held hosts unparented, because the session refuses
every record after expiry.

### Engine cost and module admission

`--reb-wasm-guest-capture` (added by the launcher when an adapter is set) is
what compiles a runtime call on every Wasm function entry and the numeric-local
descriptors at each `br_table`; physical dispatch observation alone does not.
Module admission is a three-way decision: another function of an unknown module
defers, an admitted digest tracks the instance, and a definite rejection is
remembered weakly per module until the capture interval or policy changes, so a
hot function in an unrelated module is never hashed again. Returned frames are
reclaimed by a stack walk only when the 128-entry frame table is full.

## Host causality and limits

Configured direct import call offsets must be strictly increasing, and each one
must be a direct call to an imported function in module code, including helper
functions. With several sites a host belongs to the innermost selected
activation of any site: the renderer asks V8 for the nearest activation of each
site's dispatcher and keeps the most recently entered one (engine invocation
identities grow with entry). Only that site's import offsets attribute the
host, so an outer site's import list never claims a call made inside an inner
interpreter. An adapter whose sites list no import offsets skips the walk. Native parsing and Rust admission apply the same 8192-byte adapter
and 65536-byte snapshot limits. At a synchronous native host probe the actual Wasm
stack must contain the same instance and interpreter activation as the current
retained instruction. Reentry uses its own activation; returns, traps, exceptions
and new dispatch failures invalidate stale parents. An empty import list proves
no host association. Parent invocation zero means no enclosing activation was
resolved; see [parent activation](#parent-activation-and-exact-outer-dispatch).
When a retained invocation names a parent at another dispatch site, the opcode
workspace can link it as a nested guest; see
[observed claims and nested guests](vm-opcode-workspace-v2.md#observed-claims-and-nested-guests).

Native host reports expose a semantic guest position only for the source-verified
dataflow binding; explicit adapters retain raw observations without upgrading
the declared PC mapping to proof. A direct host parent proves synchronous
execution position, not request-value
provenance. Async work, cross-process network causality, workers/documentless
contexts, unsupported tiers or mappings, and arbitrary guest ISA decoding are
not inferred. The old physical-dispatch event 17 remains distinct from guest
instruction observations.

## Validation status

Portable native admission/ACK tests, actual C++-encoded cross-language fixtures,
strict Rust artifact/site validation, and actual-script offline UI tests cover
contracts and rejection paths. The V8 cctests
`RebNativeGuestNestedActivationExactParent`,
`RebNativeGuestParentUnresolvedFailsClosed`,
`RebNativeGuestParentBarrierCoversEveryDispatcher` and
`RebNativeGuestParentWalkNeedsEnabledCapture` cover the parent walk across
dispatcher functions, its bound and its absence while capture is off; the
public QuickJS cctest witnesses exact parents for guest calls. The portable
admission suite drives the real renderer sink through exact, lost, revoked,
unresolved, cross-document, disabled and expired parents, and through a
two-site, two-level case: an inner interpreter at site 1 names the exact
current dispatch of site 0, both sites exhaust one sample budget, and hosts
belong to the innermost site. Running the public interpreter normally proves
its fixture behavior only, not that the patched hook fired. Compiled V8 cctests
and a rebuilt Brave run retaining QuickJS guest records and synchronous Canvas
parents are separate required acceptance layers. Do not describe source replay,
mocked boundaries, or offline DOM tests as full browser runtime acceptance.
