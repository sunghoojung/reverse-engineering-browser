# WASM Value Flow v1

`GET /api/wasm/value-flow?artifact_id=<id>&function=<index>&offset=<byte>[&operand=<n>]`
or `...&function=<index>&local=<n>` returns `wasm-value-flow-v1`: a bounded
static slice of where one value inside one function comes from and where it
goes. `get_wasm_value_flow` projects the route for agents. The native
`reb://app/api/wasm/value-flow` route and `origin-trace-wasm --artifacts DIR
--artifact-id ID --value-flow 'function=1&offset=40'` use the same Rust
provider ([`wasm_value_flow.rs`](../apps/origin-trace-backend/src/wasm_value_flow.rs)
over the def-use simulation in
[`wasm_def_use.rs`](../apps/origin-trace-backend/src/wasm_def_use.rs)). The CLI
prints the document or `{error, status}`.

The provider verifies the artifact's size and SHA-256 against the manifest
before decoding, exactly as [WASM inspection](wasm-inspection-v1.md) does. It
never executes the module, invokes imports, writes analysis files or changes
capture. Raw evidence stays as captured; every item in the document maps back
to an original byte offset of the module whose `sha256` the document names.

## Request

| Parameter | Meaning |
| --- | --- |
| `artifact_id` | Canonical nonzero artifact ID of a captured `wasm` artifact. Required. |
| `function` | Function index, imported functions counted first. An imported or undefined index is 404. |
| `offset` | Original module byte offset where one instruction of that function starts. A position inside an instruction is 404. |
| `operand` | With `offset`: one operand, counted in text order (the first operand pushed is 0). For `br_if` and `br_table` the values the branch carries come first and the selector last; a block's `end` has the block's results as its operands. Without it the seed is the instruction itself. |
| `local` | Instead of `offset`: every definition of one local (its parameter or zero value, each `local.set` and `local.tee`, and each join of it). |
| `direction` | `backward`, `forward` or `both` (default). |
| `max_nodes` | 1 to 4096, default 256. The slice records at most four edges and four join entries per node of this cap, and the response lists at most four edges per listed node (see Bounds). |
| `max_depth` | 1 to 256, default 32 edges from the seed. |
| `interprocedural` | `true` adds one bounded step across direct calls; default `false`. |

Give exactly one of `offset` and `local`. Unknown, repeated, non-canonical or
out-of-range parameters fail with 400 rather than widening the slice. An
instruction that neither consumes nor produces a value (`block`, `nop`), an
instruction no declared path reaches, and an `operand` past the instruction's
operands are 400. A seed at or after the point where the simulation stopped,
or past the last instruction it simulated, is 400 with code `resource_limit`;
so is a whole `try_table` or `try` seed whose body the simulation stopped
inside, since its catch values were never made.

The seed is the instruction. When it records an operand that no node of its
own consumes (a block's `end`, a carried value of `br`, `br_if` or
`br_table`), that operand's producer is an ordinary node one step from the
seed, so the leaf and address rules below apply to it as to any producer; an
operand seed always lists its producer, in a forward slice too. A whole
`try_table` seed is every one of its catch clauses' exception values.

## Simulation

The body is walked once with an abstract operand stack and abstract locals.
Every instruction that consumes or produces a value becomes a node at its byte
offset. Synthetic nodes stand for parameters and the zero value of declared
locals (at the body or local declaration offset), exception values a handler
receives, and an operand a reachable instruction found missing (`unknown`).

Code that no declared path reaches (after `br`, `br_table`, `return`,
`unreachable`, a throw or a tail call, until the enclosing `else`, `catch` or
`end`) creates no node: its reads, calls and stores cannot feed a slice or be
reported as sinks, and a loop it contains gets no header joins.

Merges follow structured control flow only, so no target is guessed:

- A block, `if` or `try` join sits at its `end` (or handler). It exists for
  each result slot and each local whose incoming values differ, and lists every
  incoming edge with the branch that carried it.
- A loop join sits at its `loop` instruction for every loop parameter and every
  local the loop body writes. Its incoming edges are the entry value and each
  back edge.
- A `try` or `try_table` handler joins each local the body defined with its
  value at entry and every definition inside the body, since a throw can happen
  between any two of them. A `try_table` reached at entry gives its catch
  clauses exception values even when its body ends in `br`, `return` or a
  throw, as compiled code usually does.

Join incoming `via` values: `entry`, `fallthrough`, `br`, `br_if`, `br_table`,
`br_on`, `then_end` (an `if` arm reaching `else`), `if_false` (the implicit
false path of an `if` without `else`) and `catch`. `via_offset` is the byte
offset of the transfer.

Memory is conservative. A load is a source; its address operands are followed
backward as the load's address slice. An atomic read-modify-write returns the
old memory value, so backward follows only its address; `table.get` follows its
index, and other table results follow nothing. A load is linked to an earlier store
(`forwarded_store`) only when both are full width of the same type
(`i32`, `i64`, `f32`, `f64`, `v128`), use the same memory and static offset,
and take the address from equal constants, and the store is the latest one in
the same basic block with no other store, call, atomic, `atomic.fence` or
memory operation in
between. Every other load stays a source. Globals are not forwarded the same
way: a `global.get` is always a source, even right after a `global.set` of the
same global.

Operators whose stack effect v1 does not model (stack switching) stop the
simulation with a named omission, and so do the instruction cap, the work
budget and the deadline. The prefix before the stop is valid with one
exception: a loop still open at the stop is named in an omission, values read
in it may also arrive by back edges after the stop, and its header joins carry
`incomplete: true`. The document is `partial`.

Captured bytes need not validate. A reachable instruction that finds fewer
operands than it needs gets `unknown` values; a path that carries fewer or more
values into a merge than the block declares (an `if` without `else` whose arm
leaves a value, a catch whose tag does not match its target) is padded with
`unknown` values or cut to the declared count; values left on the stack at an
`end` flow nowhere. Each is a named omission and the document is `partial`.
Malformed binary or control structure fails with 422.

## Slice

Backward from the seed, producers are followed until a source: `param`,
`local_init`, `const`, `global_get`, `call`, `import_call`, `call_indirect`,
`call_ref`, `memory`, `exception_value` and `unknown` are leaves; `load`,
`atomic` and `table` are sources whose address operands are still followed.
Calls are leaves because their result is produced by the callee.

Forward from the seed's value, consumers are followed through `operation`,
`select` (value operands), `local_set`, `local_tee`, `local_get`, joins and
`forwarded_store` loads. Any other consumer is a sink: a store (address or
value side), call arguments, the selector of `call_indirect`, `call_ref`,
`if`, `br_if`, `br_table` and `select`, `global_set`, `return`, `throw` and
`drop`. An `import_call` sink is where the value crosses into JavaScript.

A node's ends are independent: a call whose result returns to its own
argument around a loop, or a load whose address is the value it loaded, is a
source and a sink in one slice, and the seed instruction is also a source when
its own value feeds it back. `sources` and `sinks` list every such node.

## Document

The [OpenAPI schema](openapi.json) defines `WasmValueFlow`.

- `function_index`, `type_index`, `byte_offset` and `byte_end` (the body),
  `params`, `locals` and `results` identify the function.
- `evidence` is `declared_static` and `complete` is always `false`: the slice
  is derived from the bytes, not observed.
- `status` is `computed`, or `partial` when any cap, deadline or unmodeled
  operator cut it. `truncated` says which, and `omissions` says where.
- `seed` repeats the request's seed, lists the seed nodes and, for an
  instruction seed, `operand_count`, the operands the instruction consumes.
- `nodes` carry `id`, `kind`, `byte_offset`, `source` and `sink` (the node's
  ends), `role` (one label, the first that applies of `seed`, `source`,
  `sink`, `frontier` for a node at the depth cap whose own inputs or uses were
  not followed, and `interior`), `direction`, `depth`, `results`, and when they apply
  `local`, `global`, `function`, `type`, `table`, `tag`, `slot`, `join` and
  `import` (`module` and `name` of an imported function, escaped and capped
  at 128 bytes).
- `edges` are `{from, to, kind, operand, result}` between listed nodes, with
  `via` and `via_offset` on join and `forwarded_store` edges. Kinds:
  `operand`, `local`, `local_set`, `global_set`, `address`, `stored_value`,
  `forwarded_store`, `argument`, `callee_index`, `callee_ref`, `selector`,
  `return`, `drop` and `merge`.
- `joins` list every join in the slice with `incoming_count` and up to 64
  incoming edges, each with `from` (a node ID, or null when that producer is
  outside the listed nodes), `from_kind`, `from_offset`, `via` and
  `via_offset`. When a join has more, `truncated.joins` is set.
- `sources` and `sinks` are node IDs.
- `interprocedural` is `{requested, steps, direct_callers}`. A step is
  `caller_argument` (a parameter in the slice and the argument slot of a direct
  call site), `caller_result` (a return in the slice and the call site that
  receives it), `callee_param` (an argument in the slice and the callee
  parameter it binds) or `callee_return` (a call result in the slice and the
  callee that produced it). `direct_callers` reports how many direct sites were
  found, whether the scan finished, and `also_reachable_indirectly` when the
  function is exported, the start function, in an element segment or named by
  `ref.func`, so direct sites are not every caller. A body elsewhere in the
  module that does not decode is skipped with `scan_complete: false` and an
  omission naming it; it does not fail the request.

### Structure and content

Structure is every field except two. `text` (the instruction's mnemonic and
immediates, constants included) and `expression` (a bounded nested rendering
of the value a node produces, such as a load with its address) are derived
from captured bytes and are content, as inspection rows are.
`reb-api mcp` omits both below Full access (`--omit-content`); kinds, offsets,
indices and edges stay readable at every level.

## Bounds

- Input: 64 MiB, the block graph's limit. One body: 7,654,321 bytes, the size
  engines accept. Locals: 50,000, the count engines accept. Larger is 400.
- Simulation: 2,000,000 instructions and 4,000,000 work units (instructions,
  loop-write, snapshot and join entries, every `br_table` target and every
  `try_table` catch clause with its values, and every value an instruction
  records, a branch copies or carries, or a merge joins, so a block with many
  results and many branches to it is bounded in time and memory). The
  loop-write pass reads the whole body and records a write
  in the innermost loop only and passes each loop's set to its enclosing loop
  at `end`, so it is linear in the bytes plus the joins it implies. Loops that
  each write many locals imply nesting depth times locals joins; the budget
  and the deadline are checked inside those loops, and past either the prefix
  is returned as `partial`.
- Slice: `max_nodes`, four edges and four join entries per node of the cap
  (`4 * max_nodes` in all), 64 entries per join, `max_depth`, and a
  four-second deadline shared with the simulation. At most 32 omissions are
  listed; the last says how many more there were.
- Response: 120,000 bytes pretty-printed, both as returned and with `text`,
  `expression` and long strings replaced by omission objects, as `reb-api mcp`
  does below Full access, so the result is inlined at every level (the inline
  limit is 131,072). Past it, the seed, sources, sinks and joins are kept first,
  then the steps nearest the seed; kept nodes are renumbered in walk order,
  `truncated.bytes` is set and an omission gives the counts. Every document
  lists at most four edges per listed node, nearest the seed first, with
  `truncated.edges` set past it, so a larger `max_nodes` never lists fewer
  nodes.
- `expression`: three levels deep and 160 bytes. `text`: 160 bytes; a
  `try_table` lists its first 8 catch clauses and then their count. A float
  constant whose decimal form is longer than 24 characters is written in its
  shortest round-trip exponent form (`-2.2250738585072014e-308`), as the
  block graph's rows and labels write it, so the cap keeps its value. The seed
  ranks first in the byte cut, so a cut document always lists it.
- Interprocedural: 64 steps and 256 direct call sites, within the same deadline.

The backend runs on the bounded blocking reader pool. The UI fetches one slice
at a time and aborts a superseded request. The Sources panel seeds from Inspect
rows only; it is hidden while the block graph is open, and graph blocks are not
a seed.
