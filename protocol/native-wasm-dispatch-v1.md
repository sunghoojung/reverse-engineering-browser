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
16 MiB per module. An execution past that cap keeps a compact identity, up to
a separate ring, described in [Overflow identities](#overflow-identities).
The 16 full observations stay the cap. A lost observation becomes a `gap` in its own renderer
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
never starves the other. Executions past that cap keep compact identities in
the same [overflow ring](#overflow-identities); the 16 full records stay the cap. The renderer coalesces input and budget losses into
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

### Validation boundary

`make check` runs the C++ golden producer through the Rust reader and workspace,
the portable renderer and browser component tests (disabled, expired,
malformed, transport loss, the 16-record limit, full rings, document loss and
expiry), and the shipped viewer. The six `RebNativeCallIndirect*` cctests run in
the native V8 runtime workflow. None of these is a rebuilt-Brave run: live
acceptance still needs the pinned browser build and an owned interpreter whose
table is filled at run time, including navigation, disable, expiry and
transport loss.

## Overflow identities

Full observations stay capped at 16 per stream per configuration. An execution
that does not receive one of those records is not discarded without a trace.
The renderer keeps a fixed ring of 32 compact identities per stream per
configuration. Thirty-two is twice the full-observation cap: a fixed renderer
array, large enough to name the sites that ran after the cap, and not another
128-byte module transfer. The ring is not a full observation. It has no parent
event and no module artifact id. The renderer does not assign those, and this
record does not invent them.

`wasm_dispatch_overflow` (numeric 27) and `wasm_indirect_overflow` (numeric 28),
category `vm`, protocol 3. Parent event id is 0. Artifact id is 0. The payload
is little-endian and exactly 32 bytes for `br_table` or 40 bytes for
`call_indirect`. Version is 1.

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

The ring index is a slot in this configuration's ring, not an execution
counter. Sequence number orders the records. A reused index after a new
configuration is not a drop.

Unknown versions, the wrong size, a kind other than 1 or 2, a nonzero reserved
field, an identity that also carries an omitted count, an omitted record that
also carries an identity, a ring index past 31, an out-of-range index or
offset, or an unknown resolution are invalid. C++, Rust, Python and JavaScript
reject them. They are not partial observations. Bytes past the payload in the
inline record must be zero.

The budget gap is unchanged and still marks the cap. The ring does not replace
it. Each identity is written when the execution is seen. The omitted record is
one cumulative snapshot written when the configuration retires (the renderer
emitter is replaced or cleared). If several omitted records exist, the count
is the maximum, not the sum. The count saturates at 2^32−1 and does not wrap;
at that point the hook stops. A probe queue that cannot take an identity does
not consume a ring slot; that loss stays a queue drop. A probe queue that
cannot take the omitted record at retirement leaves the count unpublished.
A crash before retirement loses the omitted count; the budget gap and any
identities already enqueued remain. A late increment after the retirement
snapshot is read and before the emitter is cleared can be missed.

The admission predicate stays true after the 16 full observations, so V8 still
walks a frame for later executions and those executions can be named or
counted. It turns false when the omitted counter saturates or the
configuration ends.

Opcode workspaces do not copy these identities into
`native_wasm_observations` or `native_wasm_indirect_observations` and do not
match them to static arms. That would claim a module artifact the record does
not carry. They stay event-store records.

A rebuilt Brave is required before a live session emits these records. The
in-process sink test is not a live browser run, and it does not invent a
sample the browser has not produced.
