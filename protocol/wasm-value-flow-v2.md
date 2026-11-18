# WASM Value Flow v2 and Call Sites v1

`GET /api/wasm/value-flow?artifact_id=<id>&function=<index>&offset=<byte>[&operand=<n>]`
or `...&function=<index>&local=<n>` returns `wasm-value-flow-v2`: the complete
static slice of where one value inside one function comes from and where it
goes, through the calls it crosses, paged. `get_wasm_value_flow` projects the
route for agents. `GET /api/wasm/call-sites?artifact_id=<id>&function=<index>`
returns `wasm-call-sites-v1`, every direct call site of one function, paged;
`get_wasm_call_sites` projects it. The native `reb://app/api/wasm/value-flow`
and `reb://app/api/wasm/call-sites` routes and `origin-trace-wasm --artifacts
DIR --artifact-id ID --value-flow 'function=1&offset=40'` use the same Rust
provider ([`wasm_value_flow.rs`](../apps/origin-trace-backend/src/wasm_value_flow.rs)).
The slice is computed by
[`wasm_value_slice.rs`](../apps/origin-trace-backend/src/wasm_value_slice.rs)
over the def-use simulation in
[`wasm_def_use.rs`](../apps/origin-trace-backend/src/wasm_def_use.rs), with
function summaries from
[`wasm_summaries.rs`](../apps/origin-trace-backend/src/wasm_summaries.rs) and
call sites from
[`wasm_call_index.rs`](../apps/origin-trace-backend/src/wasm_call_index.rs);
operator effects and control frames come from the stack layer
[`wasm_stack.rs`](../apps/origin-trace-backend/src/wasm_stack.rs) that the
[readable view](wasm-pseudocode-v1.md) also uses. The CLI prints the document
or `{error, status}`.

The provider verifies the artifact's size and SHA-256 against the manifest
before decoding, on every request, exactly as [WASM inspection](wasm-inspection-v2.md)
does: content integrity is never cached. What the analyses build (simulations,
slices, summaries, the call index) is cached keyed by that hash, so a changed
module never reuses a stale result. The provider never executes the module,
invokes imports, writes analysis files or changes capture. Raw evidence stays
as captured; every item in the document maps back to an original byte offset
of the module whose `sha256` the document names.

## Request

| Parameter | Meaning |
| --- | --- |
| `artifact_id` | Canonical nonzero artifact ID of a captured `wasm` artifact. Required. |
| `function` | Function index, imported functions counted first. An imported or undefined index is 404. |
| `offset` | Original module byte offset where one instruction of that function starts. A position inside an instruction is 404. |
| `operand` | With `offset`: one operand, counted in text order (the first operand pushed is 0). For `br_if` and `br_table` the values the branch carries come first and the selector last; a block's `end` has the block's results as its operands. Without it the seed is the instruction itself. |
| `local` | Instead of `offset`: every definition of one local (its parameter or zero value, each `local.set` and `local.tee`, and each join of it). |
| `direction` | `backward`, `forward` or `both` (default). Each direction is walked to completion on its own; `both` lists every source of `backward` and every sink of `forward`. |
| `control` | `true` also follows `control` edges backward (see Classes). Default `false`. |
| `interprocedural` | `true` (default) enters the functions calls name; `false` keeps calls opaque: arguments into them are sinks and results out of them are sources. |
| `node_offset`, `node_limit` | The page of nodes, in walk order. Default 0 and 256; the limit is at least 1 and has no maximum. |
| `source_offset`, `source_limit`, `source_kind` | The page of sources, default 0 and 100, optionally only those of one node kind. |
| `sink_offset`, `sink_limit`, `sink_kind` | The page of sinks, the same way. |
| `join_offset`, `join_limit` | The page of incoming entries listed for each join of the node page. Default 0 and 64. |

Give exactly one of `offset` and `local`. Unknown, repeated, non-canonical or
out-of-range parameters fail with 400 rather than widening the slice. An
instruction that neither consumes nor produces a value (`block`, `nop`), an
instruction no declared path reaches, an `operand` past the instruction's
operands and a page limit of 0 are 400. A seed at or after the point where the
simulation stopped, or past the last instruction it simulated, is 400; so is a
whole `try_table` or `try` seed whose body the simulation stopped inside, since
its catch values were never made.

The seed is the instruction. When it records an operand that no node of its
own consumes (a block's `end`, a carried value of `br`, `br_if` or
`br_table`), that operand's producers are the roots of the walk. An operand
seed starts from that operand's value alone, backward at its producer and
forward at its consumers; the instruction's other operands and its own results
are not followed, unless the walk meets the instruction again as a producer
of the value (around a loop), where it is followed like any node of its kind.
A whole `try_table` seed is every one of its catch clauses' exception values.

## Simulation

The body is walked once with an abstract operand stack and abstract locals.
Every instruction that consumes or produces a value becomes a node at its byte
offset. Synthetic nodes stand for parameters and the zero value of declared
locals (at the body or local declaration offset), exception values a handler
receives, an operand a reachable instruction found missing (`unknown`), joins
where control paths merge, and memory cells (below).

Code that no declared path reaches (after `br`, `br_table`, `return`,
`unreachable`, a throw or a tail call, until the enclosing `else`, `catch` or
`end`) creates no node: its reads, calls and stores cannot feed a slice or be
reported as sinks, and a loop it contains gets no header joins. A tail call is
a call whose results feed a `return` at the same instruction.

Merges follow structured control flow only, so no target is guessed:

- A block, `if` or `try` join sits at its `end` (or handler). It exists for
  each result slot and each local whose incoming values differ, and lists
  every incoming edge with the branch that carried it.
- A loop join sits at its `loop` instruction for every loop parameter and every
  local the loop body writes that is read again: at or after the loop, or
  anywhere in a loop around it. A local nothing reads again gets no join and
  records no entry value, so a loop nest that writes thousands of dead locals
  stays linear. Its incoming edges are the entry value and each back edge.
- A `try` or `try_table` handler joins each local the body defined with its
  value at entry and every definition inside the body, since a throw can happen
  between any two of them. A `try_table` reached at entry gives its catch
  clauses exception values even when its body ends in `br`, `return` or a
  throw, as compiled code usually does.

Join incoming `via` values: `entry`, `fallthrough`, `br`, `br_if`, `br_table`,
`br_on`, `then_end` (an `if` arm reaching `else`), `if_false` (the implicit
false path of an `if` without `else`) and `catch`; `store` and `global_set`
name the store or `global.set` a forwarded or memory edge came from.
`via_offset` is the byte offset of the transfer.

Memory has two layers. Exact: a full-width load (`i32`, `i64`, `f32`, `f64`,
`v128`) reads the value of the latest full-width store of the same type to the
same address in the same basic block when nothing between them may have
overwritten it. The address is a key: a constant, or a base value plus a
displacement, where `local.get` and `local.tee` read through to the value they
carry and an add of a constant moves the displacement (wrapping as the add
wraps); the instruction's static offset is kept beside it. A store to another
key may write any address, so it ends every fact but its own; stores to other
offsets of the same key keep each other's. Such a load is not a source: its
`forwarded_store` edge carries the stored value, and its address is still
followed as `address`. A `global.set` reaches a later `global.get` of the same
global in the same block, with no call between, as `forwarded_global`, and
that `global.get` is not a source either. Atomic accesses, lane accesses,
narrow stores, `atomic.fence`, bulk memory operations and `memory.grow` end
exact facts; calls and every control transfer end both facts and forwarded
globals.

May: every load and store of one width at one address key meets at a
`memory_cell` node, joined by `memory_may` edges: each store's value into the
cell, and the cell into each load that a store precedes or shares an
outermost loop with. Other bases may alias the same bytes, so these edges are
possible flow, never proven, and the slice labels them so.

Control: each join has `control` edges from the decisions (`if`, `br_if`,
`br_table`) its incoming paths are control dependent on, from the
post-dominator tree of the body's basic blocks, and from an incoming
conditional branch itself; each decision has `control` edges from the
decisions it depends on.

Operators whose stack effect is not modeled (stack switching) stop the
simulation with a named omission, and the prefix before them stays valid with
one exception: a loop still open at the stop is named in an omission, values
read in it may also arrive by back edges after the stop, and its header joins
carry `incomplete: true`. There is no instruction or work budget: the walk
runs to the end of the body unless the request is cancelled. One guard
protects the machine: a prescan predicts the memory the simulation will hold
from the body's instruction, join and branch counts, and a body that would
need more than half of what this machine can hold is refused up front, as
400 `resource_limit`, with the counts in the message. Nothing is simulated
partially because of size.

Captured bytes need not validate. A reachable instruction that finds fewer
operands than it needs gets `unknown` values; a path that carries fewer or more
values into a merge than the block declares is padded with `unknown` values or
cut to the declared count; values left on the stack at an `end` flow nowhere.
Each is a named omission and the document is `partial`. Malformed binary or
control structure fails with 422.

## Slice

The slice is one complete breadth-first walk per direction over the def-use
graph, linear in the slice. It has no node, depth or edge cap. Every node is
discovered once and records the edge to its parent toward the seed, so any
node's path to the seed is a walk up the tree.

### Classes

Edges have classes and the walk runs in class order, each phase to
exhaustion before the next: `value` (operands, locals, joins, arguments,
results, stored values, forwarded stores and globals, `select` operands and
selectors), then `address` (the address operand of a load, store, atomic or
`table.get`), then `memory_may`, then `control` (only with `control=true`). A
node's `class` is the weakest edge on its path to the seed: `value` provably
carries the value, `address` only computed where it was read, `memory_may`
may be the value through memory, `control` only decided which path ran.
Forward, an address operand carries the value to its read or write as the
value itself (that access is where the value goes), so forward phases are
`value` and `memory_may`; control edges are never followed forward.

### Ends and roles

Backward, producers are followed until a source: `param`, `local_init`,
`const`, `exception_value`, `unknown`, `import_call`, `call_indirect`,
`call_ref`, `memory`, `atomic` and `table` are leaves; `global_get` and
`load` are leaves unless forwarded; a `call` is a leaf only when calls are
opaque. The address operands of `load`, `atomic` and `table.get` are still
followed, as `address`. An atomic read-modify-write returns the old memory
value, so only its address feeds it.

Forward, consumers are followed through `operation`, `select` (value
operands), `local_set`, `local_tee`, `local_get`, joins, forwarded loads and
globals and memory cells. Any other consumer is a sink: a store (address or
value side), the address of a load, import call and opaque call arguments, the
selector of `call_indirect`, `call_ref`, `if`, `br_if`, `br_table` and
`select`, `global_set`, `return`, `throw` and `drop`. An `import_call` sink is
where the value crosses into JavaScript. A node reached over a carrying edge
and a stopping one (a `select`'s operand and its selector) is a sink and
continues.

Each node's `role` is the first that applies of `seed`, `source`, `sink`,
`boundary` and `interior`; `seed`, `source`, `sink` and `boundary` are also
independent flags, since a call can be where the value comes from and where it
goes in the same loop. A local seed's parameter or zero value is also a
source; an instruction seed is a source only when the walk meets it again as a
leaf of the value.

### Calls

With `interprocedural=true`, a call to a function defined in the module is
crossed, not stopped at:

- Forward through argument `k`: the walk enters the callee's parameter `k`
  (`call_param` edge) and continues inside the callee, listing its sinks with
  their `function`. The callee's summary says which of its results parameter
  `k` reaches; each such result of this call carries the value on in the
  caller over a `summary` edge, so the flow returns to the right call site. A
  callee whose parameter is never read and reaches no result makes the call a
  sink.
- Backward through result `r`: the walk enters the callee's returns of slot
  `r` (`call_result` edge) and continues inside the callee, listing its
  sources; each argument whose parameter reaches `r` continues in the caller
  over a `summary` edge.
- Inside a callee, a parameter reached backward and a return reached forward
  are `boundary` nodes, not ends: the summary edge at the call site already
  carries the value across them. A callee entered this way is listed in
  `functions`.

A summary is the set of result slots a parameter reaches, through the same
value edges and through the summaries of the functions the callee calls:
exact and as deep as the call graph, computed on demand for the entries a
slice asks about, once per module hash, with a fixpoint over recursive cycles
(a parameter that returns only through the recursion itself reaches nothing).
A callee that cannot be simulated (undecodable, or refused by the memory
guard) is named in an omission and stays opaque: arguments into it are sinks
and results out of it are sources.

Direct callers of the seed's function are counted in `callers` from the call
index; `get_wasm_call_sites` lists them.

### Condensed locals

`local.get`, `local.set` and `local.tee` move a value without changing it.
They are walked and counted (`transport_count`) but not listed; the edge from
a listed node to its listed parent names the locals the value passed through
(`edge.locals`, nearest first) and, when any were skipped, the edge that
enters the parent (`edge.through`: how the parent consumed or produced the
value), while `edge.kind` stays the node's own.

## Document

The [OpenAPI schema](openapi.json) defines `WasmValueFlow` and
`WasmCallSites`.

- `function_index`, `type_index`, `byte_offset` and `byte_end` (the body),
  `params`, `locals` and `results` identify the seed's function.
- `evidence` is `declared_static` and `complete` is always `false`: the slice
  is derived from the bytes, not observed.
- `status` is `computed`, or `partial` when a simulation stopped at an
  unmodeled operator, a body did not validate, a callee could not be entered
  or the seed local is never touched; `omissions` lists every reason, uncapped.
- `request` echoes the direction, flags and pages.
- `seed` repeats the request's seed, lists the root node ids and, for an
  instruction seed, `operand_count`.
- `instructions_simulated`, `simulation_stopped_at` and `simulation_bytes`
  describe the seed function's simulation; `cached` says the slice itself was
  reused from an earlier request for the same seed; `functions` lists every
  function the slice entered, the seed's first.
- `node_count`, `transport_count`, `source_count`, `sink_count`, `join_count`
  and `boundary_count` are exact totals over the complete slice.
- `nodes` is one page in walk order: the seed first, then by distance, value
  class before address, memory may and control. `next_node_offset` continues
  it. `path_nodes` holds every listed ancestor of a page node that is not
  itself on the page, in the same shape, so each page node's path to the seed
  is in the document.
- A node carries `id` (stable across pages), `walk` (its position in walk
  order), `kind`, `byte_offset`, `function`, `direction` (`seed`, `backward`,
  `forward`), `class`, `depth` (listed ancestors to its root), `role`, the
  `seed`, `source`, `sink` and `boundary` flags, `results`, `parent` (an id, or
  null for a root), `edge` (null for a root, else `kind`, `operand`, `result`,
  `via` and `via_offset` when the edge is a join or forwarded edge, `locals`,
  and `through`), and when they apply `local`, `slot`, `join`, `global`,
  `callee` (with `import` for an imported function: `module` and `name`,
  escaped and capped at 128 bytes), `type`, `table`, `tag` and `cell` (a
  memory cell's address key: `memory`, a constant `address` or the
  `base_offset` of the node whose value is the base plus a `displacement`,
  the static `offset` and `width`). Edge kinds: `operand`, `local`,
  `local_set`, `global_set`, `address`, `stored_value`, `forwarded_store`,
  `forwarded_global`, `argument`, `callee_index`, `callee_ref`, `selector`,
  `return`, `drop`, `merge`, `memory_may`, `control`, `call_param`,
  `call_result` and `summary`.
- `joins` lists the joins (`phi` and `memory_cell` nodes) of the node page
  with `incoming_count` and one page of incoming entries, each `from` (a node
  id when that producer is in the backward slice, else null), `from_kind`,
  `from_offset`, `via` and `via_offset`; a memory cell's entries are its
  stores, `via: store`.
- `sources` and `sinks` each carry the exact `count`, a `kinds` histogram
  (`kind`, `class`, `count`), the kind filter and `filtered_count`, and one
  page of items: `id`, `walk`, `kind`, `class`, `byte_offset`, `function`,
  `seed`, the identifying fields above and `text`. A client that wants an
  item's path requests the node page at its `walk` with `node_limit=1`.
- `callers` is `{count, indirect, undecoded}` with `interprocedural`, else
  null.
- `limits` names the bounds that remain: the engine's body and local limits,
  the simulation memory budget, and the text and expression caps.

`wasm-call-sites-v1` carries `function_index`, `imported`, the exact `count`,
one page of `sites` (`caller`, `byte_offset`, `tail`) by caller then offset
with `next_offset`, `indirect` (`exported`, `start`, `element`, `referenced`
by a `ref.func`), and `undecoded`, the bodies the index could not decode.

### Structure and content

Structure is every field except two. `text` (the instruction's mnemonic and
immediates, constants included) and `expression` (a bounded nested rendering
of the value a node produces, such as a load with its address) are derived
from captured bytes and are content, as inspection rows are.
`reb-api mcp` omits both below Full access (`--omit-content`); kinds, offsets,
indices, classes and edges stay readable at every level.

## Bounds and paging

- Input: a module of any size is read whole. One body: 7,654,321 bytes, the
  size engines accept. Locals: 50,000, the count engines accept. Larger is 400.
- Simulation: no instruction or work budget; the memory guard above.
- Slice: no node, depth or edge cap; a request that goes away stops the walk
  and is answered 499 `cancelled`, and a cancelled request leaves nothing in
  the caches.
- Response: no byte cut. The provider never shortens a document to fit a
  transport; it pages. `reb-api mcp` inlines a result only when its compact
  and pretty-printed forms both fit `x-reb-mcp.inline_json_limit_bytes`
  (131,072). Both operations declare their page parameters under
  `x-reb-mcp-page` (`node_limit`, `source_limit`, `sink_limit` and
  `join_limit`; `limit`), and the projection halves each from the value given,
  or the parameter's schema default, and asks again until the result fits or
  every one is 1; only then does the structural summary apply. The returned
  `request` says which page came back and the `next_*` offsets continue it.
- `expression`: three levels deep and 160 bytes. `text`: 160 bytes; a
  `try_table` lists its first 8 catch clauses and then their count. A float
  constant whose decimal form is longer than 24 characters is written in its
  shortest round-trip exponent form, as the block graph's rows write it.
- Caches: simulations, slices, summaries and the call index are kept per
  module hash and bounded by the bytes they hold (half of the simulation
  budget for simulations, a sixteenth of the machine for slices and the call
  index), oldest first; a request still answers when nothing is cached, only
  later.

The backend runs on the bounded blocking reader pool. The UI fetches one slice
at a time and aborts a superseded request. The Trace value panel seeds from
Inspect rows only; it is hidden while the block graph is open, and graph
blocks are not a seed.
