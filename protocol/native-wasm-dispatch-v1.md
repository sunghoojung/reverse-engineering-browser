# Native Wasm dispatch observations v1

This path instruments Brave/V8 C++ directly. There is no CDP, JavaScript
injection, caller-fed sampler or fallback. It is partial work toward #327,
not arbitrary interpreter guest-PC recovery.

## Enablement

Rebuild Brave with all tracked V8, Chromium and overlay changes. The packaged
Origin Trace app sets `REB_NATIVE_WASM_DISPATCH=1` by default whenever VM and
artifact categories are both enabled; an explicit `0` opts out. With the
standalone `make live` launcher, set `REB_NATIVE_WASM_DISPATCH=1` explicitly; VM
and artifact categories must both be enabled. Manual browser launches may use
`--js-flags=--reb-wasm-br-table-dispatch`. The flag alone does not authorize or
activate capture: the session must be active, connected and unexpired.

The diagnostic flag forces Liftoff-only compilation and disables native-module
cache reuse/deserialization. It is not a performance-neutral profiler. Only
executing `br_table` instructions in document Liftoff code are sampled.
`call_indirect` has its own flag and record, described
[below](#call_indirect-observations). A worker, worklet, jitless, or
non-Liftoff execution is a named scope gap, not an observation and not
silence; see [unsupported scope](#unsupported-scope).

## Unsupported scope

Forcing Liftoff stays the disclosed diagnostic mode. Each dispatch flag implies
`liftoff_only` and refuses native-module cache reuse, so a module compiled for
that diagnostic does not tier up out of the instrumented compiler. With the
flag off, Liftoff emits no hook instruction and no scope notice is delivered.

Until other compilers and realms are instrumented, an execution outside
document Liftoff code is a coalesced `gap`, once per configuration per reason.
It is not a `wasm_dispatch_observation` or a `wasm_indirect_observation`. The
payload is only the reason. There is no function index, module offset,
selector, slot, or sample.

| Reason | When |
| --- | --- |
| `native_wasm_dispatch_worker_unsupported` | A Liftoff `br_table` hook ran in a worker global scope. |
| `native_wasm_dispatch_worklet_unsupported` | A Liftoff `br_table` hook ran in a worklet global scope. |
| `native_wasm_dispatch_jitless_unsupported` | A capture session starts, or `SyncCompile` runs, while `jitless` or `wasm_jitless` is set and the `br_table` flag is on. |
| `native_wasm_dispatch_left_liftoff` | A Wasm function is published at TurboFan, or the `br_table` runtime is entered from a non-Liftoff frame, while the `br_table` flag is on. |
| `native_wasm_indirect_worker_unsupported` | The worker case for `call_indirect`. |
| `native_wasm_indirect_worklet_unsupported` | The worklet case for `call_indirect`. |
| `native_wasm_indirect_jitless_unsupported` | The jitless case for `call_indirect`. |
| `native_wasm_indirect_left_liftoff` | The non-Liftoff case for `call_indirect`. |

A worker or worklet gap means the hook ran and the realm was that scope. The
selector or table slot is not copied into a document observation. The Liftoff
admission predicate goes false once that stream's 16-observation budget is
full, and the hook does not run again, so a worker or worklet execution after
the budget is not visited. A scope notice that does arrive is still recorded;
the budget gap does not consume the scope slot. A full ring does not mark the
scope gap sent.

Jitless on this desktop pin does not execute Wasm. `--jitless` does not imply
`wasm_jitless` except on tvOS, where DrumBrake exists. Without DrumBrake,
`wasm_jitless` is a readonly false, and `WasmCodeManager::TryAllocate`
DCHECKs `!jitless`, so a cctest must not allocate Wasm code with that flag set.
`SyncCompile` notifies before decoding, so a module that fails decoding still
names the mode and never maps code. Where DrumBrake is compiled in, an
interpreter `br_table` or `call_indirect` records the same jitless reason for
that stream only, still without a sample. A notice the embedder cannot admit,
including a TurboFan publication on a thread with no current isolate, is
remembered and drained on the next isolate-thread drain, including session
start. The first session that can admit a left-Liftoff notice records it. A
later session does not repeat it unless another publication or non-Liftoff
runtime entry happens. Jitless is read from the process flags at every session
start. The notice names the scope. It does not claim that a particular
instruction ran.

A realm that is neither a document, a worker global scope, nor a worklet
global scope still produces no observation and no named gap.

`RebNativeBrTableDisabledCompilation` and
`RebNativeCallIndirectDisabledCompilation` compile Liftoff with the flag off
and never reach a callback. `RebNativeBrTableFlagOffTurbofanHasNoScopeGap`
does the same for TurboFan, including the scope callback.
`RebNativeBrTableLeftLiftoff` and `RebNativeCallIndirectLeftLiftoff` compile
with the flag on at TurboFan. `FlagScope` does not apply the `liftoff_only`
implication, so the function can leave Liftoff; the tests require the scope
notice and zero observations while the indirect call still returns its real
result. `RebNativeBrTableJitlessUnsupported` sets `jitless` and both dispatch
flags, then `SyncCompile`s one invalid byte. Decode fails before
`TryAllocate`. The test requires one jitless notice on each stream, zero
observations, and that a repeated unadmitted left-Liftoff notice drains once.
`RebNativeBrTableJitlessFlagOffHasNoScopeGap` is that compile with both flags
off and requires no notice. `NativeWasmScopeGaps` requires each reason string,
coalescing, a scope notice after the sample cap, a full-ring retry, and the
session-start probe. A rebuilt Brave is required before a live session shows
any of this. These tests are not a live browser run.

The V8 checks are
`browser/integration/brave/patches/v8/0014-report-wasm-dispatch-scope-gaps.patch`,
replayed after `0012-attribute-wasm-br-table-direct-caller.patch`. A non-Liftoff
`br_table` returns before that patch's caller walk, so the gap does not invent
a caller. Chromium `0017-observe-native-wasm-dispatch.patch` names a worker or
worklet before a selector or slot is copied. `0022-attribute-wasm-br-table-direct-caller.patch`
adds the caller arguments and uses them only on the document observation.
`0024-report-wasm-dispatch-scope-gaps.patch` installs the jitless and
left-Liftoff callback after `0022`.

## Producer and identity

The compiler inserts a C++ builtin/runtime call before an executing `br_table`.
An allocation-free admission predicate runs before V8 frame lookup. The runtime
supplies the actual unsigned selector, function index, instruction byte offset
and explicit arm count. A module offset is a physical Wasm address, **not an
interpreter guest PC**, and a selector is not automatically a guest opcode.

Blink supplies exact document identity and native capture context. Renderer and
browser validate the session, generation, category, expiry and document token.
The browser captures the module through the artifact receiver and emits the
observation only after accepted ACK. Stale navigation/configuration callbacks
are rejected. Observations of the same module in the same document share one
module artifact; each is emitted once that artifact is accepted (or at once if
it already was). Capture is capped at 16 observations per configuration and
16 MiB per module. A lost observation becomes a `gap` in its own renderer
sequence slot. Queue, transport and budget losses are explicit incompleteness,
never invented samples. Every observation the browser refuses, whether
malformed, over the host or browser budget, without its owning document or
without the artifact channel, fills its own slot with a gap, not only the first
one. A record still waiting for its module when the capture ends becomes
`native_wasm_dispatch_pending_at_capture_end` in its slot.

## Wire contract

Event type `wasm_dispatch_observation` (numeric17), category `vm`, protocol3.
The accepted artifact ID lives in the event envelope. Parent event and
navigation IDs remain zero rather than inventing causality. Runtime artifacts
use existing capture origin `unknown`; the typed event establishes provenance.

The payload is exactly128bytes, explicitly little-endian:

| Offset | Field | Type |
| --- | --- | --- |
|0|version (1)|u16|
|2|size (128)|u16|
|4|function index|u32|
|8|module instruction offset|u32|
|12|unsigned selector|u32|
|16|explicit table arm count|u32|
|20|sample index (0–15)|u32|
|24|reserved, all zero|104bytes|

Version 2 replaces the first 8 reserved bytes with the JavaScript invocation
context: `js_invocation_state` (u8 at 24), 3 zero bytes and
`js_invocation_id` (u32 at 28), leaving 96 reserved bytes. Version 1 still
decodes, as not observed. See
[invocation context of Wasm records](native-js-invocation-v1.md#invocation-context-of-wasm-records).

Version 3 keeps that context and stores the direct caller in the next 8 bytes:

| Offset | Field | Type |
| --- | --- | --- |
| 32 | caller kind | u8 |
| 33 | reserved, all zero | 3 bytes |
| 36 | caller function index | u32 |
| 40 | reserved, all zero | 88 bytes |

Caller kind 0 is `unknown`: the host, another instance, a frame that is not
a Liftoff function of this module, or a frame whose code could not be read.
The index is then 0 and is not function index 0.
Kind 1 is `same-instance`: the index is that function in this module, imports
included, and may be 0. Kind 2 and above is rejected. Versions 1 and 2 still
decode. Their caller bytes stay zero, which means the caller was **not
observed**. That is not kind 0. A rebuilt browser is required before a live
session writes version 3. This build does not invent samples a rebuilt browser
has not produced.

The caller is only the live frame immediately above the `br_table`, and only
when that frame is a Liftoff function of the same instance. The walk does not
skip a host or foreign frame to an older same-instance frame. Each observation
is one activation: two instances do not share a stack, and arrival order is
not a caller. A multi-frame stack is not reconstructed. `return_call` replaces
the caller frame, so the record names the frame that is live, not the function
that executed the `return_call`. Parent event and navigation IDs stay zero
unless a real parent event exists. This caller is not that parent.

Offsets start at8 and are below16MiB. Function index and count are below16MiB.
Any u32 selector is legal; selector>=count denotes the default arm. Scope IDs,
sequence and monotonic time are required; wide identities remain decimal strings.
Unknown versions, nonzero reserved bytes, malformed length/encoding and invalid
envelope flags are rejected consistently by C++, Rust and JavaScript.

### Event queries

`get_events` and `wait_for_events` leave `payload` as the 128-byte hex and add
`wasm_observation` beside it. The field map is the one the opcode-workspace
reader uses. A decoded dispatch object has `function_index`,
`module_byte_offset`, `selector`, `table_count`, `sample_index`,
`js_invocation_state` and `js_invocation_id`. Payload version 3 also has
`direct_caller` (`kind` and `function_index`). Versions 1 and 2 omit it: those
bytes were not a caller. An indirect object has `function_index`,
`module_byte_offset`, `sample_index`, `js_invocation_state` and
`js_invocation_id`, plus `table_index`, `slot`, `callee_function_index` and
`resolution` (`resolved`, `null`, `out-of-bounds`, `foreign`, `unresolved`).
`js_invocation_state` is the stored integer (0 not observed, 1 none, 2 inside,
3 unknown). Version 1 decodes as not observed. `callee_function_index` is the
stored index, 0 unless `resolution` is `resolved`. `status` is `decoded` or
`invalid`. Invalid carries no fields. Dispatch accepts payload versions 1, 2,
and 3. Indirect accepts 1 and 2. Any other version is invalid in full and is
not decoded as a version-2 prefix. The record must also be protocol 3,
category `vm`, and flags 0. This decode does not build an opcode workspace or
open the module, so a module the detector never admits still has rows here.
It does not recover a guest PC or invent a sample. Workspace rows remain a
separate, module-checked view.
See [filtered event reads](http-api.md#filtered-and-paged-reads).

## Reader and viewer

Rust verifies artifact digest and exact session/frame/artifact scope, then parses
the real module function/site/count before matching a selector to a static arm.
Imported function indices and multiple sites sharing a selector are distinct.
Native observations are separate from legacy guest-VM samples; no sentinel or
overloaded guest fields are used. At an adapter dispatch site the same execution
also produces a `wasm_guest_dispatch` record, so workspace counts for the two
streams overlap and are never summed. Each function body is decoded at most once,
when a record names it, within the 16 MiB module bound. A module whose sections
do not decode keeps its records visible as `native-wasm-module-undecodable` with
their counts instead of dropping them. The viewer labels guest PC unknown. A version 3 same-instance caller is the
live Liftoff frame the runtime walked. A version 3 unknown caller is an explicit host,
other instance, non-Liftoff frame, or unreadable frame, not a guessed index. Versions 1 and 2 omit the
caller because they did not walk one. Parent event id stays zero: the caller
field is not a parent edge, and guest positions remain unproven.

## Validation boundary

`make check` includes actual C++ encoding → Rust verified artifact/workspace →
shipped JavaScript validation, including malformed and maximum-width goldens.
Portable native tests cover admission, expiry, masks, cap/drop, ACK and lifecycle.
These do not prove that a full Brave browser builds or the native V8 cctests run.
Before live acceptance, replay complete stacks on the pinned Brave-initialized
tree, compile the browser and run an owned two-selector Wasm fixture, including
navigation, disable/expiry and transport-loss cases. #327 remains open until its
remaining guest-PC/host-causality acceptance criteria are actually demonstrated.

## call_indirect observations

A threaded or handler-table interpreter dispatches through `call_indirect` or
`return_call_indirect`. When its table is filled at run time, static analysis
withholds handler claims. This record supplies the runtime side: which table
slot one indirect call used and which function the entry held.

### Enablement and cost

The V8 flag `--reb-wasm-call-indirect-dispatch` is off by default and separate
from the `br_table` flag. The native launcher adds it for
`REB_NATIVE_WASM_CALL_INDIRECT=1`, which also requires the VM and Artifact
categories. The packaged Origin Trace app sets that variable by default under
the same rule as `br_table`; `make live` leaves it off unless set. Like the `br_table` flag it forces Liftoff-only compilation and
refuses native-module cache reuse and deserialization, so a module never runs
without the hook it was promised.

With the flag off, Liftoff emits no instruction for the hook: it sits behind a
branch on the flag inside the compiler, so a compiled function has the
instruction sequence of an unpatched compiler. The one difference is that the
new builtin, like the `br_table` one, shifts the jump-table slots of builtins
listed after it; no call is added or changed. The cctest
`RebNativeCallIndirectDisabledCompilation` compiles the same caller with the
flag on and off: only the flag-on build is larger, and with the flag off a
registered callback is never reached. With the flag on and capture
inactive, the runtime returns after one null check or the embedder's
allocation-free admission predicate, before any frame walk or handle.

### Producer

Before the call, Liftoff stores the function-relative instruction offset, the
table immediate and the dynamic i32 index in a stack record and calls a
runtime builtin. The dynamic index stays on the operand stack, so the call's
own bounds, null and signature checks run unchanged afterwards and still trap.
The runtime confirms a Liftoff frame and the `0x11` or `0x13` opcode at the
offset, then reads the table entry without allocating: a materialized funcref
names its function and owning instance; a lazy placeholder names both directly.
No argument value, local or memory byte is read.

| Resolution | Value | Meaning |
| --- | --- | --- |
| `resolved` | 0 | The entry is a function of this instance; the callee is its index in this module's function space, imports first. |
| `null` | 1 | The entry is null; the call traps. |
| `out-of-bounds` | 2 | The slot is past the table's current length; the call traps. |
| `foreign` | 3 | The entry is a function of another instance. |
| `unresolved` | 4 | The entry or table could not be read without allocation. |

Only `resolved` carries a callee; every other value carries callee 0. Tables
indexed by i64 (`table64`) are not observed.

Blink, the renderer sink, the browser host and the artifact sink apply the same
document, session, generation, category and expiry rules as `br_table`
observations, through the same bounded transport. A separate budget allows 16
records per configuration in the renderer and in the browser, so one stream
never starves the other. The renderer coalesces input and budget losses into
one gap per configuration: `native_wasm_indirect_input_unavailable` or
`native_wasm_indirect_budget_incomplete`. A full ring does not mark a gap as
sent, so it is retried. A record the transport refuses frees its sample index
and fills the sequence slot it took with
`native_wasm_indirect_transport_unavailable`, as `br_table` does with
`native_wasm_dispatch_transport_unavailable`. The browser fills each refused
record's own slot with `native_wasm_indirect_browser_budget_incomplete`,
`native_wasm_indirect_limit_or_invalid`, `native_wasm_indirect_module_invalid`,
`native_wasm_indirect_document_unavailable` or
`native_wasm_indirect_artifact_unavailable`. A record waiting for its
module ACK shares the `br_table` path: it becomes a gap in its own sequence slot
when the document or artifact is lost or the session nears expiry. Observations
of one module in one document, from either stream, share one module artifact.

### Wire contract

Event type `wasm_indirect_observation` (numeric 20), category `vm`, protocol 3.
The artifact ID, scope and identity rules are those of
`wasm_dispatch_observation`. The payload is exactly 128 bytes, little-endian:

| Offset | Field | Type |
| --- | --- | --- |
| 0 | version (1) | u16 |
| 2 | size (128) | u16 |
| 4 | caller function index | u32 |
| 8 | module instruction offset | u32 |
| 12 | table index | u32 |
| 16 | dynamic slot | u32 |
| 20 | callee function index | u32 |
| 24 | resolution (0 to 4) | u32 |
| 28 | sample index (0 to 15) | u32 |
| 32 | reserved, all zero | 96 bytes |

Version 2 adds the JavaScript invocation context at bytes 32..40, as for
`br_table`, leaving 88 reserved bytes; version 1 still decodes.

Function, table and callee indexes are below 16 Mi and the offset is at least 8
and below 16 Mi. Any u32 slot is legal. C++, Python, Rust and JavaScript reject
unknown versions, nonzero reserved bytes, a callee on an unresolved entry, an
unknown resolution and invalid envelope flags alike. Event queries return this
payload as `wasm_observation` with `resolution` named, as described
[above](#event-queries). The hex payload remains.

### Reader

Rust verifies the artifact digest and scope, then decodes the named function
once and requires a `call_indirect` or `return_call_indirect` at the offset
whose table immediate equals the record's table, and a resolved callee inside
the module's function space. Accepted rows become
`native_wasm_indirect_observations`; at interpreter-candidate sites, resolved
rows become `native-wasm-indirect` observed claims compared with the element
segments' slot claim. See
[observed claims](vm-opcode-workspace-v2.md#observed-claims-and-nested-guests).
Rows are read only into an opcode workspace, which the detector creates for a
module with a `br_table` or `call_indirect` inside a loop. A module whose only
dispatch is a loop-free `return_call_indirect` chain has no workspace, so its
rows stay in the event store without rows or claims in VM Lab.

### Validation boundary

`make check` runs the C++ golden producer through the Rust reader and workspace,
the portable renderer and browser component tests (disabled, expired,
malformed, transport loss, the 16-record limit, full rings, document loss and
expiry), and the shipped viewer. The six `RebNativeCallIndirect*` cctests run in
the native V8 runtime workflow. None of these is a rebuilt-Brave run: live
acceptance still needs the pinned browser build and an owned interpreter whose
table is filled at run time, including navigation, disable, expiry and
transport loss.
