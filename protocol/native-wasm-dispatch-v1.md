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
replayed after `0013-record-wasm-execution-outcomes.patch`. A non-Liftoff
`br_table` returns before the direct-caller walk from `0012`, so the gap does
not invent a caller. Chromium `0017-observe-native-wasm-dispatch.patch` names a
worker or worklet before a selector or slot is copied. `0022-attribute-wasm-br-table-direct-caller.patch`
adds the caller arguments and uses them only on the document observation.
`0024-report-wasm-dispatch-scope-gaps.patch` installs the jitless and
left-Liftoff callback after `0023-record-wasm-execution-outcomes.patch`.

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
16 MiB per module. Raising that global cap does not keep a hot function from
filling it. A session can instead restrict admission before a sample index is
taken: a module-digest allowlist, a function-index allowlist and denylist
(deny wins), and a maximum number of retained samples per function. Empty
lists and a zero maximum keep the historical behavior. A module whose digest
is not allowed, and a function that is denied or past its own maximum, does
not advance the sample index. The same controls apply to `call_indirect`,
which also has a maximum per caller function and module byte offset. The two
streams keep independent counters. `session_action`
`reset_wasm_sample_budgets` restarts both sample indexes at 0 in the same
browser session and starts a new overflow ring for each stream. It first
publishes each stream's pending omitted count for the epoch being closed.
The next retained sample is index 0, and the next overflow identity may reuse
ring index 0. It does not change the policy, the session id, or the capture
configuration, and it does not invent a sample, a caller, or a parent. The
browser notices the reset file on its writer wake, about 250ms later, and
only when the generation is greater than the last one it applied. The backend
replaces that file by rename under an exclusive lock, so a reader sees a
whole decimal and two overlapping resets cannot publish the same generation.
Executions before that wake still belong to the previous epoch. A rebuilt
Brave is required before a live session honors the policy, the reset, or the
overflow records. `sample_index` remains the configuration slot, 0 through
15, not a per-function index and not an interpreter guest PC.

A filtered record is an exclusion, not a capacity loss. The renderer coalesces
it once per budget epoch into `native_wasm_dispatch_filtered`. A new
configuration and `reset_wasm_sample_budgets` each start an epoch. A
per-function refusal is
`native_wasm_dispatch_function_budget_incomplete`. The browser names the same
cases `native_wasm_dispatch_browser_filtered` and
`native_wasm_dispatch_browser_function_budget_incomplete` on each refused
record. The global 16 still coalesces into
`native_wasm_dispatch_budget_incomplete`. None of these refusals disables the
stream: the admission predicate stays true so a later execution can keep a
compact identity in the [overflow ring](#overflow-identities). The predicate
turns false when that ring's omitted counter saturates or the budget epoch is
resetting. A per-function, per-module, or per-site refusal leaves the other
functions able to take a remaining full-observation slot. These gaps do not
carry the dropped function, offset, or selector; the overflow identity does.
A lost observation becomes a `gap` in its own renderer
sequence slot. Queue, transport and budget losses are explicit incompleteness,
never invented samples. A malformed module and a missing document are refused
before a sample slot is taken. The artifact sink releases the slot if the
private copy fails validation after the claim, so a later valid execution of
that function can still be kept. Every observation the browser refuses, whether
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
separate, module-checked view. Overflow identities are a separate
`wasm_overflow` object; see [overflow identities](#overflow-identities).
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
never starves the other. Executions that a budget refuses keep compact identities
in the same [overflow ring](#overflow-identities). The 16 full records stay
the cap, and the stream stays enabled past that cap until the omitted counter
saturates. The sample-budget policy in the `br_table` section applies here
independently, including the per-call-site maximum. A filtered record is
`native_wasm_indirect_filtered` in the renderer and
`native_wasm_indirect_browser_filtered` in the browser. A per-function refusal
is `native_wasm_indirect_function_budget_incomplete` or
`native_wasm_indirect_browser_function_budget_incomplete`. A per-call-site
refusal is `native_wasm_indirect_site_budget_incomplete` or
`native_wasm_indirect_browser_site_budget_incomplete`. None of those disable
the stream. The renderer coalesces input and budget losses into
one gap per budget epoch: `native_wasm_indirect_input_unavailable` or
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

## Execution outcomes

A dispatch record is the instruction that was about to run. It does not say
whether that call returned, trapped, or is still inside the function. This
record is the follow-up for one host-visible Wasm call. It does not change
the `call_indirect` resolution enum: that enum is only the table entry.
A signature mismatch on a resolved entry stays `resolved` and adds a trap
with reason `signature_mismatch`. It is never stored as resolution `null`.

The producer is V8 patch `0013-record-wasm-execution-outcomes`, replayed
after patches `0000` through `0012`. The renderer deadline and
`RequestInterrupt` nudge are Chromium patch
`0023-record-wasm-execution-outcomes`, replayed after patches through
`0022`.

### What is known

The engine's own trap message is the reason. This record does not re-check
the signature, so a legal subtype is not reported as a mismatch. The named
reasons are `signature_mismatch`, `unreachable`, `out_of_bounds`,
`null_entry` (`null function` only, not a null dereference), and `interrupt`.
Any other Wasm trap message is reason `unknown`. That value means the engine
trapped and this record does not name the message. On a still-executing
record the reason is `unknown` because it is not a trap.

`out_of_bounds` may name `table`, `memory`, `data_segment`,
`element_segment`, `array`, or `string`. Other reasons leave bounds at 0.
Bounds 0 on an out-of-bounds trap means the class was not one of those names.

The function index and module offset are separate known bits. A clear bit
stores integer 0, and that 0 is not an index or an offset. Function index 0
with the bit set is the real import at index 0. A trap's index and offset
come from the Liftoff frame when that frame's position is a function-body
offset inside the function and the resulting module offset lies in the wire
bytes at or after byte 8. A function-body offset of 0 is left unknown: the
prologue stack check uses position 0 and is not an instruction. A non-Liftoff
frame leaves both unknown. The offset is not copied from the last sample.

A still-executing record and an interrupt, when this call has taken an
instrumented sample, name that sample's function and offset. That is the
last instrumented instruction, not a recovered trap program counter. The
related sample index and stream (`br_table` or `call_indirect`) point at it.
A call that has taken no instrumented instruction does not emit
still-executing.

### Deadline and interrupt

The deadline is five seconds of `base::TimeTicks` from host-call entry, or
from the first instrumented instruction if entry was not reported. The
renderer posts that wait only when a new host-visible call opens on the main
isolate. The task calls `v8::Isolate::RequestInterrupt`. That is not
`TerminateExecution`. It sets V8's no-heap-write interrupt byte and lowers
the stack limit so the next check enters the runtime.

Where that check runs depends on the tier:

- Liftoff with dynamic tiering, the default when TurboFan is enabled, does
  not put a stack check in the loop. It polls when the tiering budget runs
  out, in `Runtime_WasmTriggerTierUp`.
- An optimized loop polls in `Runtime_WasmStackGuardLoop`, and only after
  that interrupt byte is set.
- A real stack overflow, or the lowered limit, polls in
  `Runtime_WasmStackGuard`.

Each of those runtimes calls the heartbeat before `SealHandleScope`. The
heartbeat allocates no V8 handles. When five seconds have passed and this
call has an instrumented sample, it emits one `still_executing` record and
leaves the call open. A second check does not emit another. One delayed
task is in flight at a time. If it runs for a call that has not yet reached
five seconds, the interrupt callback posts the time still remaining instead
of queueing another task per call. A due deadline whose check did not poll
retries after 50ms. A call that has already returned leaves that one
interrupt as a no-op. A call blocked inside a host import does not hit a
Wasm loop or a tier-up check until it returns to Wasm.

A call that returns emits neither a trap nor a still-executing record. The
deadline does not trap and does not end the session. A nested frame and an
outermost tail callee do not arm another task.

Interrupt is separate. `RequestWasmExecutionInterrupt` stores the current
configuration generation and then, when the renderer has installed the
nudge, calls the same `RequestInterrupt` on the main isolate. The next
stack check on a thread that has an open host call for that generation emits
one trap with reason `interrupt`, keeps the samples already emitted, closes
the call, and returns `ThrowWasmError` for the uncatchable message
`execution interrupted`. It does not terminate the isolate, so a later call
in the same document can run. A stack check with no open host call leaves
the request. Replacing the configuration clears it. A disabled configuration
does not accept a request. A request that arrives after the target call has
already returned applies to the next tracked call of that configuration
whose stack check runs.

### Where the interrupt can be reached

`NativeProbeClient` is bound to the renderer main sequence in
`NativeProbeTransport::Connect`. A stuck main-thread Wasm call cannot pump
that pipe, so a method on it cannot deliver an interrupt. The browser socket
in `native_probe_ipc.h` is an authenticated hello plus disconnect-to-stop.
It has no command the UI or `reb-api` can send to set the flag. An IO-thread
receiver whose only method stored the generation and called
`RequestInterrupt` would be thread-safe, but nothing in the browser process,
the session socket, or Origin Trace invokes such a method. That
cross-process control is not in this change. It would be a new mojom, a
browser remote, a socket or API command, and a UI control, and it cannot be
proven without a rebuilt Brave. What a rebuilt browser honors is the
in-process stack check and the main-isolate `RequestInterrupt` above.

Workers are not given an isolate pointer. A worker isolate is not
process-lifetime, and a delayed task must not keep it. A worker call to
`RequestWasmExecutionInterrupt` still nudges the main isolate, because that
pointer is process-wide. Portable tests do not execute V8. They call the
heartbeat directly.

### Wire contract

Event type `wasm_execution_outcome` (numeric 27), category `vm`, protocol 3.
The payload is exactly 128 bytes, little-endian, version 1. Version 1
already carries the JavaScript invocation context.

| Offset | Field | Type |
| --- | --- | --- |
| 0 | version (1) | u16 |
| 2 | size (128) | u16 |
| 4 | kind: trap 0, still_executing 1 | u8 |
| 5 | reason (0 to 5) | u8 |
| 6 | bounds (0 to 6; only for out_of_bounds) | u8 |
| 7 | known bits: function 1, module offset 2 | u8 |
| 8 | function index, or 0 when unknown | u32 |
| 12 | module offset, or 0 when unknown | u32 |
| 16 | invocation id, nonzero | u32 |
| 20 | related sample index, or `0xffffffff` when none | u32 |
| 24 | related stream: none 0, br_table 1, call_indirect 2 | u8 |
| 25 | reserved, zero | 3 bytes |
| 28 | JavaScript invocation state | u8 |
| 29 | reserved, zero | 3 bytes |
| 32 | JavaScript invocation id | u32 |
| 36 | reserved, zero | 92 bytes |

The invocation id is assigned by the renderer for one host-visible call,
including across an outermost `return_call`. A trap with no open host call
emits nothing. The outcome budget is 16 records per configuration, separate
from `br_table` and `call_indirect`. Renderer gaps are
`native_wasm_execution_input_unavailable`,
`native_wasm_execution_budget_incomplete`, and
`native_wasm_execution_transport_unavailable`. Browser gaps are
`native_wasm_execution_browser_budget_incomplete`,
`native_wasm_execution_limit_or_invalid`,
`native_wasm_execution_document_unavailable`,
`native_wasm_execution_artifact_unavailable`,
`native_wasm_execution_module_unavailable` (no module for that document),
and `native_wasm_execution_module_unresolved` (more than one, so none is
chosen). A record that still has module bytes shares the module artifact
with the other Wasm streams. A still-executing or interrupt record carries
no module bytes; the browser attaches the one module already captured for
that document. A pending module uses the same ACK queue and, if it is lost,
the existing `native_wasm_dispatch_artifact_or_document_lost` gap.

### Named omissions

- No browser-process, session-socket, or Origin Trace control sets the
  interrupt. See [where the interrupt can be reached](#where-the-interrupt-can-be-reached).
  A rebuilt Brave is required before a live session emits these records.
  The portable tests do not execute V8.
- The five-second `RequestInterrupt` is installed for the main isolate only.
  A call blocked in a host import is not observed until execution returns
  to Wasm. A returned call can still leave one already-posted interrupt,
  and that check does not emit a record.
- Opcode workspace rows are not projected for this event. The event remains
  in the evidence store and decodes in the viewer.
- Workers and non-Liftoff frames are not given a function index or module
  offset. A trap message this record does not name stays reason `unknown`.
  A message that is not a Wasm trap is not reported.
- A call with no instrumented instruction does not emit still-executing.
- The ledger is one host call per thread. A catchable exception, or Wasm
  that calls JavaScript which calls Wasm again, does not emit a trap. The
  next outermost entry drops the previous call without a record.

### Validation boundary

`make check` runs the C++ golden producer through the Rust reader and workspace,
the portable renderer and browser component tests (disabled, expired,
malformed, transport loss, the 16-record limit, full rings, document loss and
expiry), and the shipped viewer. `NativeWasmExecutionOutcomes` in the renderer
admission test and the artifact-capture test cover a signature-mismatch trap
distinct from resolution `null`, a still-executing record while the call is
open, an interrupt that leaves a later call able to run, and a normal return
that emits neither. The six `RebNativeCallIndirect*` cctests run in the native
V8 runtime workflow. None of these is a rebuilt-Brave run: live acceptance
still needs the pinned browser build. The new Liftoff hooks are not executed
by the portable tests.

## Overflow identities

Full observations stay capped at 16 per stream per budget epoch. An execution
that a budget refuses is not discarded without a trace. The refusal can be
the module allowlist, the function allow or deny list, the per-function
maximum, the per-call-site maximum on `call_indirect`, or the 16-record
stream cap. The renderer keeps a fixed ring of 32 compact identities per
stream per budget epoch. Thirty-two is twice the full-observation cap: a
fixed renderer array, large enough to name the sites that ran after a budget
refused them, and not another 128-byte module transfer. The ring is not a
full observation. It has no parent event and no module artifact id. The
renderer does not assign those, and this record does not invent them.

`wasm_dispatch_overflow` (numeric 28) and `wasm_indirect_overflow` (numeric
29), category `vm`, protocol 3. Parent event id is 0. Artifact id is 0. The
payload is little-endian and exactly 32 bytes for `br_table` or 40 bytes for
`call_indirect`. Version is 1. `wasm_execution_outcome` keeps numeric 27.

`br_table` payload:

| Offset | Field | Type |
| --- | --- | --- |
| 0 | version (1) | u16 |
| 2 | size (32) | u16 |
| 4 | kind (1 identity, 2 omitted) | u8 |
| 5 | reserved (0) | u8 |
| 6 | ring index | u16 |
| 8 | function index | u32 |
| 12 | module instruction offset | u32 |
| 16 | unsigned selector | u32 |
| 20 | explicit arm count | u32 |
| 24 | omitted count | u32 |
| 28 | reserved (0) | u32 |

`call_indirect` payload:

| Offset | Field | Type |
| --- | --- | --- |
| 0 | version (1) | u16 |
| 2 | size (40) | u16 |
| 4 | kind (1 identity, 2 omitted) | u8 |
| 5 | reserved (0) | u8 |
| 6 | ring index | u16 |
| 8 | caller function index | u32 |
| 12 | module instruction offset | u32 |
| 16 | table index | u32 |
| 20 | dynamic slot | u32 |
| 24 | resolution (0 to 4) | u32 |
| 28 | omitted count | u32 |
| 32 | reserved (0) | u64 |

Kind 1 is one identity that fit in the ring. Its omitted count is 0 and its
ring index is below 32. Function, arm and table indexes are below 16 Mi, and
the offset is at least 8 and below 16 Mi, the same bounds as a full
observation. Any u32 selector or slot is legal. Kind 2 is the count of valid
executions that did not fit. Its identity fields, ring index and resolution
are 0, and the omitted count is at least 1. A resolved indirect identity does
not carry a callee; that index exists only on a full
`wasm_indirect_observation`.

The ring index is a slot in this budget epoch's ring, not an execution
counter. Sequence number orders the records. A reused index after a new
configuration or `reset_wasm_sample_budgets` is not a drop.

Unknown versions, the wrong size, a kind other than 1 or 2, a nonzero reserved
field, an identity that also carries an omitted count, an omitted record that
also carries an identity, a ring index past 31, an out-of-range index or
offset, an unknown resolution, or a nonzero artifact id or parent event id are
invalid. C++, Rust, Python, JavaScript and the Swift trace builder reject
them. They are not partial observations. Bytes past the payload in the
inline record must be zero.

The budget gap is unchanged and still marks the refusal. The ring does not
replace it. Each identity is written when the execution is seen. The omitted
record is one cumulative snapshot of one budget epoch, written when that
epoch closes: `reset_wasm_sample_budgets`, or when the configuration retires
(the renderer emitter is replaced or cleared). If several omitted records
exist, the count is the maximum, not the sum. The count saturates at 2^32−1
and does not wrap; at that point the hook stops for that epoch. A later reset
starts a new epoch, so saturation does not keep the next epoch disabled. The
omitted record's session, time, frame, process and thread are one admission.
The count is not incremented until that admission is visible, so the record
cannot mix two executions or name an older epoch. The counter word is tagged
with that admission's budget epoch. Installing a later epoch's scope stores a
new tag and a zero count, so a late increment cannot be added to the next
epoch. A probe queue that cannot take the coalesced budget gap does not also
push the identity; that execution is one queue drop, and it does not consume
a ring slot. A probe queue that cannot take an identity does not consume a
ring slot either; that loss stays a queue drop. A probe queue that cannot
take the omitted record when the epoch closes leaves the count unpublished.
A crash before that close loses the omitted count; the budget gap and any
identities already enqueued remain. A late increment after the snapshot is
read and before the emitter is cleared can be missed.

The admission predicate stays true after the 16 full observations and after a
per-function, per-module, or per-site refusal, so V8 still walks a frame for
later executions and those executions can be named or counted. Other functions
can still take a remaining full-observation slot. The predicate turns false
when the omitted counter saturates or the budget epoch is resetting.

`get_events` and `wait_for_events` leave `payload` as the hex and add
`wasm_overflow` beside it. `status` is `decoded` or `invalid`. Invalid carries
no fields. A decoded identity has `kind` `identity`, `ring_index`,
`function_index` and `module_byte_offset`. A `br_table` identity also has
`selector` and `arm_count`. A `call_indirect` identity also has `table_index`,
`slot` and `resolution` (`resolved`, `null`, `out-of-bounds`, `foreign`,
`unresolved`). An omitted record has `kind` `omitted` and `omitted_count`,
and no site. This decode does not build an opcode workspace or open a module.

Opcode workspaces do not copy these identities into
`native_wasm_observations` or `native_wasm_indirect_observations` and do not
match them to static arms. That would claim a module artifact the record does
not carry. They stay event-store records.

A rebuilt Brave is required before a live session emits these records. The
in-process sink test is not a live browser run, and it does not invent a
sample the browser has not produced.
