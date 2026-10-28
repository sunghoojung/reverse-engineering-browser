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
`wasmparser` keeps unmodeled operators from wiping it. In a function that does
not validate, an operator without arity, including a call, drops the stack to
unknown; its operands never become the selector.

- A load through `base + index` with an arithmetically advanced index
  (`pc = pc ± n`, through masks or width casts) is `cursor_index`; through one
  advanced pointer it is `cursor_pointer`. A linked-list step, a reload or a
  call result is not an advance.
- A table read at an index nothing advances is a lookup, not a cursor. It takes
  the source of its index: `call_argument` when every index is an unwritten
  argument, `unknown` when one comes from a call, as in a worklist drained by
  `pop()`.
- A position reloaded from a fixed slot of a stable base (`pc = frame[k]`)
  before the fetch, or a selector read from such a slot, is `frame_slot`.
- A scaled memory lookup (`table[op * 4]`) is traced to its index, so a
  handler-pointer or remap table inherits the source of the opcode.
- A parameter is `call_argument`. Normalizing it in place (`key = key & 255`)
  keeps that source, and a constant default written outside any loop (a bounds
  guard) does not replace it. Constant writes inside a loop make it the seed of
  a flattened state machine instead, which is `constant`.

Every write that can reach the selector is a separate alternative. A rotated
loop, which fetches the first opcode before the loop and the next at its latch,
is therefore an interpreter candidate through the latch fetch. The site takes
the alternative that a loop re-derives with a cursor-like selector, then any
loop-derived one, then the strongest source.

`repeats=loop` needs the producing load or write inside the enclosing loop and
the loop to advance the state the selector comes from. A cursor local must be
advanced in the loop. A frame slot must be stored back in the loop as
arithmetic over its own prior value (`pc + n`). A constant state write or a
linked-list step does not count. A site outside every loop is `once`. A site in
a loop whose selector the loop does not advance is `unknown`.

Local traces are memoized only when complete. A trace cut short by a cycle
through its own writes, the depth bound or the step budget is recomputed per
site, so a site's classification never depends on the order sites are
queried.

JavaScript, per comment- and literal-masked function region, with nested
function bodies excluded:

- `switch (selector)` is `switch_on_value`; `name[selector](...)`, also through
  `.call(...)` or `.apply(...)`, is `handler_table`.
- `if (k === C)` tests or `k === C ?` ternaries on one name with at least three
  distinct integer constants are `compare_chain`.
- `h = h(...)` inside a loop is `threaded` with `handler_address`.
- `buf[i]`, `buf[i++]`, and `charCodeAt`, `charAt`, `codePointAt`, `getUint8`
  style accessors are cursor reads when the region advances `i` arithmetically
  (`i++`, `i += n`, `i = i + n`). An index that is only assigned, such as
  `id = queue.pop()`, is a lookup and takes the index's own source.
- A position on an object (`code[f.pc++]`) or a local copy of one is
  `frame_slot`; it repeats only when the loop advances it, not when it is
  merely assigned.
- An argument coerced in place (`k = k | 0`) stays `call_argument`.
- Each region is indexed once: every binding, including each binding of a
  comma declaration (`var op = code[pc++], a = code[pc]`), every write and
  every arithmetic advance by name. Loop bodies include braceless and
  statement-form bodies such as `do switch (...) {...} while (...)`.
- `buffer_kind` flags a cursor buffer as `string` (string case labels, string
  accessors or a string-literal binding), `typed-array`, `array` or `unknown`.
  A tokenizer loop over a string stays `switch_on_value` / `cursor_index` /
  `loop`; the flag adds no other claim.

These are syntactic matches inside one region, not data-flow proof. Anything
outside the recognized forms stays `unknown`. `dispatch_kind: "unknown"` is
reserved for a selection mechanism the classifier cannot name; the current
producer does not emit it, and `kind_counts` always counts it.

## Record evidence

Every site carries the artifact ID, `location` (Wasm function index and code
entry offset, or JavaScript line, column and region start), the byte offset and
size of the dispatch instruction or first comparison, a bounded `selector`
rendering of the instructions or source expression that produced the
selector, the offset of the closest producing write or load, the arm or
comparison count, and the loop range.

`call_indirect` sites keep `table`: table index, type index, and the real table
slots whose function signature equals the call type, scanned once per table
and type. Slots come from element segments placed at their evaluated offsets,
evaluating defined globals through earlier globals. An offset that reads an
imported global, directly or through a defined global, is relative and fills
no slot. A segment ending past the table's declared minimum is out of range
and fills no slot. A `ref.null` item empties its slot; any other non-`ref.func`
item stores a reference whose function is unknown, so it never matches a type
and never erases knowledge silently.

The object lists at most 256 sites. Interpreter candidates and multiplexers
are listed before other sites, so the bound never hides them behind ordinary
branching. `site_count`, `role_counts` and `kind_counts` cover every classified
site, and `omitted_site_count` names the classified sites that are not listed.

## Work bounds

Classification work is bounded so a generated script or module cannot stall
analysis. Each selector query has a step budget. Each artifact has a total step
budget. Each JavaScript function region classifies at most 4096 sites. A site
found past a bound is not classified and is counted in `omissions` as
`classification-work-limit` with `omitted_records`. JavaScript regions beyond
the detector's region work bound add `classification-region-limit`. A module
whose sections do not decode for classification adds
`classification-unavailable`. A bound is never silent.

## Downstream use

Only `interpreter-candidate` sites can carry guest-opcode claims. This is a
requirement, not a blocklist:

- A JavaScript integer `switch` yields opcode handlers only when that switch
  is an interpreter-candidate site. A numeric handler table (`t[3] = function`
  or an object map) yields handlers only when the same region dispatches
  through it, as `t[selector](...)` or `t[selector].call(...)`, at an
  interpreter-candidate site. A table with no such dispatch, a dispatch through
  a temporary (`h = t[op]; h()`), or a dispatch in another function yields
  none. Operand-width guesses and owned-effect reachability walks therefore
  never start from a router.
- Classification never changes a tier or score. When recovery finds handlers
  that no interpreter-candidate site supports, the workspace keeps the tier
  and records `handler-withheld` instead of `handler-unavailable`. The
  JavaScript `likely-vm` demotion still applies only when recovery itself finds
  no handler.
- A Wasm `br_table` arm keeps its physical selector, but a dispatch sample
  promotes it to `guest-opcode-isa` only at an interpreter candidate.
- A multiplexer is shown as `router, no guest opcodes claimed`.

## Limits and known gaps

- A byte-cursor loop over text, such as a format-string or tokenizer loop, is
  structurally an interpreter candidate. `buffer_kind` flags JavaScript string
  buffers; Wasm has no equivalent signal.
- An opcode fetched through a helper call (`op = next(state)`) is `unknown`.
  The classifier does not follow calls.
- Without flow order, an argument that is unconditionally overwritten before
  dispatch still counts as a reaching `call_argument` alternative.
- JavaScript bindings are matched by name inside one region. Shadowed names,
  destructuring and cross-region aliases are not resolved. A handler table
  used through a temporary or from a nested function supplies no opcodes.
- The declared minimum is a lower bound for an imported table, so an imported
  table's out-of-range segment may still fit at instantiation. It is reported,
  not placed.

Fixtures and their expected classifications are in
[`tools/fixtures/dispatch-shapes`](../tools/fixtures/dispatch-shapes/README.md).
