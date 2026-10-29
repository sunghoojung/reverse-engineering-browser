# Native Wasm dispatch observations v1

This path instruments Brave/V8 C++ directly. There is no CDP, JavaScript
injection, caller-fed sampler or fallback. It is partial work toward #327,
not arbitrary interpreter guest-PC recovery.

## Enablement

Rebuild Brave with all tracked V8, Chromium and overlay changes. With the native
live-session launcher, set `REB_NATIVE_WASM_DISPATCH=1` explicitly; VM and
artifact categories must both be enabled. Manual browser launches may use
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
never invented samples.

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
categories. Like the `br_table` flag it forces Liftoff-only compilation and
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
never starves the other. The renderer coalesces each loss into one gap per
configuration: `native_wasm_indirect_input_unavailable`,
`native_wasm_indirect_transport_unavailable` or
`native_wasm_indirect_budget_incomplete`. A full ring does not mark a gap as
sent, so it is retried. The browser reports
`native_wasm_indirect_browser_budget_incomplete`,
`native_wasm_indirect_limit_or_invalid`, `native_wasm_indirect_module_invalid`
and `native_wasm_indirect_document_unavailable`. A record waiting for its
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
