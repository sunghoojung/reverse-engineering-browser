# VM dispatch classification v1

The [schema](vm-dispatch-classification-v1.schema.json) owns the
`dispatch_classification` object. VM detector producer `1.6.0` and later write
it to every analyzed result as `frontend.dispatch_classification` in
[`vm-analysis-v1`](vm-analysis-v1.schema.json). Opcode workspace producer
`2.9.0` and later copy it onto the matching workspace in
[`vm-opcode-workspace-v2`](vm-opcode-workspace-v2.md). Both embed the same
definition. A Rust test fails if a copy, including the OpenAPI components,
drifts from the standalone schema.

## Why it exists

Static VM analysis used to treat every dispatcher as a bytecode interpreter
with a cursor. A one-shot router, a compiled `match`, or a control-flow
flattened state machine was either missed or reported as a guest ISA. This
record answers three structural questions about every dispatch site before any
opcode or decode logic runs.

| Field | Values | Question |
| --- | --- | --- |
| `dispatch_kind` | `switch_on_value`, `handler_table`, `compare_chain`, `export_per_role`, `threaded`, `unknown` | How does control pick the next handler? |
| `selector_source` | `cursor_index`, `cursor_pointer`, `frame_slot`, `call_argument`, `handler_address`, `constant`, `unknown` | Where is the selector value produced? |
| `repeats` | `loop`, `once`, `unknown` | Is the selector re-derived each loop iteration from advanced state, or does the dispatch fire once per call? |

`role` is derived from those three fields only. Consumers recompute it and
reject a document whose role disagrees.

- `interpreter-candidate`: `repeats=loop` with `cursor_index`,
  `cursor_pointer` or `frame_slot`, on `switch_on_value`, `handler_table` or
  `compare_chain`.
- `multiplexer`: `repeats=once` with `call_argument` on the same kinds. One call
  routes to one function. Its arms or constants are routing labels.
- `other`: everything else, including threaded chains, flattened state
  machines and ordinary compiled branching.

`confidence` is always `structural`, never `observed`. Classification is
analyzer interpretation of stored artifact bytes. It never rewrites captured
evidence, never raises a VM tier and does not feed the structural score.

## What the classifier recognizes

WebAssembly, per function body:

- `br_table` is `switch_on_value`. `call_indirect` is `handler_table`, or
  `threaded` when its table index is the result of an earlier indirect call.
  `return_call_indirect` is `threaded`.
- An equality ladder (`local.get; i32.const C; i32.eq; if` or `br_if`, also
  `i32.ne` and `i32.eqz`) on one subject with at least three distinct constants
  is `compare_chain`.
- A module with no other site and at least two exported functions gets one
  module-level `export_per_role` record.

The selector is traced through a symbolic operand stack. Validator arity from
`wasmparser` keeps unmodeled operators from wiping it. A module that does not
validate is still classified with untyped tracing, which drops to unknown
instead of guessing.

- A load through `base + index` with an advanced index (`pc = pc + n`) is
  `cursor_index`; through one advanced pointer it is `cursor_pointer`.
- A position reloaded from a fixed slot of a stable base (`pc = frame[k]`)
  before the fetch, or a selector read from such a slot, is `frame_slot`.
- A scaled memory lookup (`table[op * 4]`) is traced to its index, so a
  handler-pointer or remap table inherits the source of the opcode.
- A parameter that the function never writes is `call_argument`. Locals written
  only with constants are `constant`, the shape of control-flow flattening.

`repeats=loop` needs the producing load or write inside the enclosing loop and
the loop to advance the state the selector comes from. A cursor local must be
written in the loop. A frame slot must be stored back in the loop as arithmetic
over its own prior value (`pc + n`). A constant state write or a linked-list
step does not count. A site outside every loop is `once`. A site in a loop
whose selector the loop does not advance is `unknown`.

JavaScript, per comment- and literal-masked function region, with nested
function bodies excluded:

- `switch (selector)` is `switch_on_value`; `name[selector](...)` is
  `handler_table`.
- `if (k === C)` tests or `k === C ?` ternaries on one name with at least three
  distinct integer constants are `compare_chain`.
- `h = h(...)` inside a loop is `threaded` with `handler_address`.
- `buf[i]`, `buf[i++]`, and `charCodeAt`, `charAt`, `codePointAt`, `getUint8`
  style accessors are cursor reads. A position on an object (`code[f.pc++]`) or
  a local copy of one is `frame_slot`; it repeats only when the loop advances it
  (`++`, `+=`, `f.pc = f.pc + n`), not when it is merely assigned.
- `buffer_kind` flags a cursor buffer as `string` (string case labels, string
  accessors or a string-literal binding), `typed-array`, `array` or `unknown`.
  A tokenizer loop over a string stays `switch_on_value` / `cursor_index` /
  `loop`; the flag adds no other claim.

These are syntactic matches inside one region, not data-flow proof. Anything
outside the recognized forms stays `unknown`.

## Record evidence

Every site carries the artifact ID, `location` (Wasm function index and code
entry offset, or JavaScript line, column and region start), the byte offset and
size of the dispatch instruction or first comparison, a bounded `selector`
rendering of the instructions or source expression that produced the
selector, the offset of the closest producing write or load, the arm or
comparison count, and the loop range.

`call_indirect` sites keep `table`: table index, type index, and the real table
slots whose function signature equals the call type. Slots come from element
segments placed at their evaluated offsets. A segment offset that reads an
imported global is relative and fills no slot.

The object lists at most 256 sites. Interpreter candidates and multiplexers
are listed before other sites, so the bound never hides them behind ordinary
branching. `site_count`, `role_counts` and `kind_counts` cover every classified
site, and `omitted_site_count` names the rest.

## Downstream use

Only `interpreter-candidate` sites can carry guest-opcode claims:

- JavaScript integer case values and numeric handler tables become workspace
  opcode handlers only at an interpreter candidate. Operand-width guesses and
  owned-effect reachability walks therefore never start from a router.
- A Wasm `br_table` arm keeps its physical selector, but a dispatch sample
  promotes it to `guest-opcode-isa` only at an interpreter candidate.
- A multiplexer is shown as `router, no guest opcodes claimed`.

## Limits and known gaps

- A byte-cursor loop over text, such as a format-string or tokenizer loop, is
  structurally an interpreter candidate. `buffer_kind` flags JavaScript string
  buffers; Wasm has no equivalent signal.
- An opcode fetched through a helper call (`op = next(state)`) is `unknown`.
  The classifier does not follow calls.
- JavaScript bindings are matched by name inside one region. Shadowed names,
  destructuring and cross-region aliases are not resolved.

Fixtures and their expected classifications are in
[`tools/fixtures/dispatch-shapes`](../tools/fixtures/dispatch-shapes/README.md).
