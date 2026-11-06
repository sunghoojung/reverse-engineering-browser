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
executing `br_table` instructions in document contexts are supported; workers
and jitless execution are not implemented. `call_indirect` has its own flag and
record, described [below](#call_indirect-observations).

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

Offsets start at8 and are below16MiB. Function index and count are below16MiB.
Any u32 selector is legal; selector>=count denotes the default arm. Scope IDs,
sequence and monotonic time are required; wide identities remain decimal strings.
Unknown versions, nonzero reserved bytes, malformed length/encoding and invalid
envelope flags are rejected consistently by C++, Rust and JavaScript.

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
their counts instead of dropping them. The viewer labels guest PC unknown. Context
links can be correlated, but host-call causality and guest positions remain
unproven without genuine parent/invocation evidence.

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
unknown resolution and invalid envelope flags alike.

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
