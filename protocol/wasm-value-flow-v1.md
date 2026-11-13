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
| `operand` | With `offset`: one operand, counted in text order (the first operand pushed is 0). Without it the seed is the instruction itself. |
| `local` | Instead of `offset`: every definition of one local (its parameter or zero value, each `local.set` and `local.tee`, and each join of it). |
| `direction` | `backward`, `forward` or `both` (default). |
| `max_nodes` | 1 to 4096, default 256. Edges and join entries are capped at four per node. |
| `max_depth` | 1 to 256, default 32 edges from the seed. |
| `interprocedural` | `true` adds one bounded step across direct calls; default `false`. |

Give exactly one of `offset` and `local`. Unknown, repeated, non-canonical or
out-of-range parameters fail with 400 rather than widening the slice. An
instruction that neither consumes nor produces a value (`block`, `nop`) and an
`operand` past the instruction's operands are 400.

## Simulation

The body is walked once with an abstract operand stack and abstract locals.
Every instruction that consumes or produces a value becomes a node at its byte
offset. Synthetic nodes stand for parameters and the zero value of declared
locals (at the body or local declaration offset), exception values a handler
receives, and a value popped from an empty stack in unreachable code
(`unknown`).

Merges follow structured control flow only, so no target is guessed:

- A block, `if` or `try` join sits at its `end` (or handler). It exists for
  each result slot and each local whose incoming values differ, and lists every
  incoming edge with the branch that carried it.
- A loop join sits at its `loop` instruction for every loop parameter and every
  local the loop body writes. Its incoming edges are the entry value and each
  back edge.
- A `try` or `try_table` handler joins each local the body defined with its
  value at entry and every definition inside the body, since a throw can happen
  between any two of them.

Join incoming `via` values: `entry`, `fallthrough`, `br`, `br_if`, `br_table`,
`br_on`, `then_end` (an `if` arm reaching `else`), `if_false` (the implicit
false path of an `if` without `else`) and `catch`. `via_offset` is the byte
offset of the transfer.

Memory is conservative. A load is a source; its address operands are followed
backward as the load's address slice. A load is linked to an earlier store
(`forwarded_store`) only when both are full width of the same type
(`i32`, `i64`, `f32`, `f64`, `v128`), use the same memory and static offset,
and take the address from equal constants, and the store is the latest one in
the same basic block with no other store, call, atomic or memory operation in
between. Every other load stays a source.

Operators whose stack effect v1 does not model (stack switching) stop the
simulation with a named omission. The prefix before them is still valid and
the document is `partial`. A malformed stack shape becomes an `unknown` value
and an omission; malformed binary or control structure fails with 422.

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
- `nodes` carry `id`, `kind`, `byte_offset`, `role` (`seed`, `source`, `sink`,
  `interior`, or `frontier` for a node at the depth cap whose own inputs or
  uses were not followed), `direction`, `depth`, `results`, and when they apply
  `local`, `global`, `function`, `type`, `table`, `tag`, `slot`, `join` and
  `import` (`module` and `name` of an imported function, escaped and capped
  at 128 bytes).
- `edges` are `{from, to, kind, operand, result}` between listed nodes, with
  `via` and `via_offset` on join and `forwarded_store` edges. Kinds:
  `operand`, `local`, `local_set`, `global_set`, `address`, `stored_value`,
  `forwarded_store`, `argument`, `callee_index`, `callee_ref`, `selector`,
  `return`, `drop` and `merge`.
- `joins` list every join in the slice with all of its incoming edges, each
  with `from` (a node ID, or null when that producer is outside the slice),
  `from_kind`, `from_offset`, `via` and `via_offset`.
- `sources` and `sinks` are node IDs.
- `interprocedural` is `{requested, steps, direct_callers}`. A step is
  `caller_argument` (a parameter in the slice and the argument slot of a direct
  call site), `caller_result` (a return in the slice and the call site that
  receives it), `callee_param` (an argument in the slice and the callee
  parameter it binds) or `callee_return` (a call result in the slice and the
  callee that produced it). `direct_callers` reports how many direct sites were
  found, whether the scan finished, and `also_reachable_indirectly` when the
  function is exported, the start function, in an element segment or named by
  `ref.func`, so direct sites are not every caller.

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
- Simulation: 2,000,000 instructions and 32,000,000 work units (instructions,
  snapshot and join entries); past either the prefix is returned as `partial`,
  and a seed past the stop point is 400 with code `resource_limit`.
- Slice: `max_nodes`, four edges and four join entries per node, `max_depth`,
  and a four-second deadline shared with the simulation.
- `expression`: three levels deep and 160 bytes.
- Interprocedural: 64 steps and 256 direct call sites, within the same deadline.

The backend runs on the bounded blocking reader pool. The UI fetches one slice
at a time and aborts a superseded request.
