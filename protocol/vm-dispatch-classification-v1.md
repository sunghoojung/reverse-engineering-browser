# VM dispatch classification v1

The [schema](vm-dispatch-classification-v1.schema.json) owns the
`dispatch_classification` object. VM detector producer `1.6.0` and later write
it to every analyzed result as `frontend.dispatch_classification` in
[`vm-analysis-v1`](vm-analysis-v1.schema.json). Opcode workspace producer
`2.9.0` and later copy it onto the matching workspace in
[`vm-opcode-workspace-v2`](vm-opcode-workspace-v2.md). Both embed the same
definition. A Rust test fails if a copy, including the OpenAPI components,
drifts from the standalone schema.

This contract lands as one unit with the commits that introduce and then
correct it (526178a, 7258370, f4092e3 and their follow-ups). No document was
released against an earlier draft, so it keeps version 1; do not treat any of
those commits alone as a released contract.

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

`role` is derived from those three fields plus two recorded refinements,
`buffer_kind` and `selector.through_lookup`. Consumers recompute it and reject
a document whose role disagrees.

- `interpreter-candidate`: `repeats=loop` with `cursor_index`,
  `cursor_pointer` or `frame_slot`, on `switch_on_value`, `handler_table` or
  `compare_chain`, except a cursor loop over text or call arguments
  (`buffer_kind` `string` or `arguments`), whose cases are characters or
  argument values, and a switch or ladder whose selector is a second-level
  lookup (`through_lookup`, such as `types[q[head++]]`), which is a walk. A
  handler table reads its handler through one lookup by design, so
  `through_lookup` does not demote it.
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
  `pop()`. An index that was itself loaded at a cursor keeps the cursor source
  and sets `through_lookup`.
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

Local traces are memoized with what computing them fresh costs: the steps
they consume and how many levels below their own depth they reach. A memo hit
charges both, so a site that reaches a memoized trace near the depth or step
bound is limited exactly as if it had traced it itself, and a site's
classification never depends on the order sites are queried. A trace the step
budget cut short is kept with its consumed steps as a lower bound: a query that
cannot afford them is limited at once, any other recomputes. A trace cut by a
cycle through its own writes or by the depth bound is never kept.

Constant and handler-address alternatives that differ only in where they were
written merge per enclosing loop, so a run of constant writes before a loop
cannot crowd out the loop's own fetch. Every write of a local is examined,
charged as a trace step; there is no silent prefix.

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
  accessors or a string-literal binding), `arguments` (the `arguments` object),
  `typed-array`, `array` or `unknown`. It reads at most 64 bindings of the
  buffer, once per buffer name. A tokenizer loop over a string keeps
  `switch_on_value` / `cursor_index` / `loop` and is role `other`.
- Bracket pairing uses a bitset of opening positions and one `u32` closing
  offset per opening, with a stack per bracket kind. An offset lookup uses
  the opening rank. Dense `{}` input needs about 2.2 index bytes per source
  byte; unmatched regex brackets add no rescans.

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
and fills no slot. Instantiation applies active segments in order and traps at
the first that does not fit, so every later active segment is `unreached` and
fills no slot either; earlier placements only matter for an imported table,
which keeps them. A `ref.null` item empties its slot; any other non-`ref.func`
item stores a reference whose function is unknown, so it never matches a type
and never erases knowledge silently.

`populated_slot_count` is the corrected count of placed slots. It is not a
ranking input: the detector's Wasm ranking keeps its own element fanout, which
sums segment entries, so classification never moves a tier or score. A ranking
change needs its own ranking version.

The object lists at most 256 sites. Interpreter candidates and multiplexers
are listed before other sites. Within a role, structural scheduling strength
breaks ties before source order. A JavaScript loop bounding the selector cursor
against the fetched buffer's length precedes otherwise similar cursor sites. `site_count`, `role_counts` and `kind_counts` cover every classified
site, and `omitted_site_count` names the classified sites that are not listed.

## Work bounds

Classification work is bounded so a generated script or module cannot stall
analysis. One meter per artifact covers all classifier work, JavaScript and
Wasm, and every classifier loop charges it for the work it actually does:
bracket pairing, loop intervals, statement ends, the region index, if-ladder
scans, Wasm table parsing and type-matching slot scans, symbolic simulation
per operator, `repeats` and slot-advance walks, buffer scans and every trace
step. The meter also bounds the bytes the index and symbolic traces retain at
once (128 MiB). A memo hit charges the lookup and the copy it returns, never
the work it saved.

Each walk that many sites share is done once. A boundary sweep indexes the
innermost loop and a fixed 32-level ancestor index finds the closest loop
satisfying a monotone containment/advance predicate without materializing a
nesting chain. Store-back offsets are indexed once per slot and carrier.
Element placement uses compact slot vectors and stable four-pass radix sorting,
retaining the last segment assignment at each slot. Active functions and segment
membership are indexed by table during parsing, and canonical signature groups
share matching-slot lists across all indirect sites.

Producer 1.7.0 and workspace producer 2.10.0 share the same meter through
classification, lexical claim resolution and workspace table extraction. Vector
capacities, masks, token/scope indexes, table layouts, matching lists and
symbolic indexes reserve their retained bytes before growing. Exhaustion in
the downstream pass is also recorded on the analysis and any returned workspace.
A scaling test runs this analysis-to-workspace path, including deep nested
loops, many element tables, scope noise and dense punctuation. It is distinct
from process RSS, which also includes unchanged recovery, artifact storage,
serialization, the runtime and allocator overhead.

Each selector query also has a logical step budget of 4096 steps, replayed on
memo hits so a site's result never depends on query order. It is a semantic
bound, not a work charge.

Work goes to the strongest dispatch evidence first, so noise cannot starve an
interpreter. JavaScript regions are classified in pattern-rank order, and the
sites inside a region in strength order (first a cursor fetch bounded by
that same buffer's length, then other loop-enclosed cursor-like fetches) before the 4096-site region bound. Every Wasm function is simulated,
then sites are classified module-wide in strength order.

- When the meter is exhausted, classification stops. Every site found but not
  classified is counted as `classification-work-limit` with `omitted_records`,
  and the detail counts the regions or functions never examined. The
  opcode-claim gate reports such a site as not classified because of the work
  limit, never as "not a cursor-advancing loop".
- A site whose trace hit the depth, per-query step or alternatives bound, or
  whose Wasm function ran out of symbolic nodes, is classified `unknown` and
  counted as `classification-trace-limit`. A bound never yields a confident
  different source, and no bound cuts a list of writes or stores silently.
- JavaScript regions beyond the detector's region work bound add
  `classification-region-limit`. A module whose sections do not decode for
  classification adds `classification-unavailable`.

## Downstream use

Only `interpreter-candidate` sites can carry guest-opcode claims. The
classification is never an input to handler recovery, tier or score:

- JavaScript handler recovery is unchanged; it alone decides the tier and the
  score. The opcode-claim gate is a pure post-filter on what recovery returns:
  it removes claims and never adds one.
- A recovered `switch` case survives only when that switch is an
  interpreter-candidate site. A recovered table entry (`t[3] = function` or an
  object map) survives only when the region dispatches through that table, as
  `t[selector](...)` or `t[selector].call(...)`, including from a nested
  function of the region, at an interpreter-candidate site. A dispatch through
  a temporary (`h = t[op]; h()`) ties nothing, and a table with no such site
  is withheld as unclassified.
- A table ties only to calls that read its own binding. A token pass over
  masked source records function, arrow, block, loop-head, catch and class
  scopes, then resolves uses after indexing hoisted declarations. An arrow's
  parameters apply only to its own body. Identifiers are complete spans,
  including long and Unicode names, never bounded prefixes. Implicit
  `arguments`, named function expression bindings, class-internal names,
  destructuring and unresolved syntax are ambiguous unless an explicit binding
  proves the reference. `eval` and `with` make their enclosing function opaque.
  An exhausted or incomplete scope pass withholds claims with a counted
  `handler-withheld` omission. A property such as `this.ops` matches only property
  sites. Operand-width guesses and owned-effect reachability walks use only
  surviving handlers.
- The gate reads the roles of every classified site from the same metered
  classification run that produced the analysis, never the bounded listed
  document and never a second classification pass.
- When the gate removes handlers, the workspace records `handler-withheld`
  with their count instead of `handler-unavailable`, and the tier stays what
  recovery decided. A differential test runs every owned input with and
  without the gate and requires equal tier and score.
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
- A JavaScript rotated loop (`op = code[pc++]` before the loop and at its end)
  classifies as an interpreter candidate, but handler recovery, which is
  unchanged, yields no handlers for it, as it did before classification
  existed. This is a known false negative of recovery, not of the
  classification.
- On the pinned public QuickJS debug build, 13 of 384 sites are interpreter
  candidates, including the opcode dispatch at function 414; 7 sites are
  trace-limited unknowns, among them byte-cursor format-string parsers.
- Selector bindings inside the classifier are matched by name inside one
  region. Shadowed names, destructuring and cross-region aliases are not
  resolved there; only the opcode-claim gate resolves table scopes. A handler
  table used through a temporary supplies no opcodes.
- Structural scheduling is not semantic proof. More than 4096 equally strong
  sites in one region can still omit a later interpreter. The omitted site count
  is explicit; neither strength ordering nor withholding changes VM ranking.
- The declared minimum is a lower bound for an imported table, so an imported
  table's out-of-range segment may still fit at instantiation. It is reported,
  not placed.

Fixtures and their expected classifications are in
[`tools/fixtures/dispatch-shapes`](../tools/fixtures/dispatch-shapes/README.md).
