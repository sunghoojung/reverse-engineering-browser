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

JavaScript is parsed once per artifact with pinned Oxc crates. Script mode is
tried first, then module mode on failure. The successful AST and Oxc semantic
scope graph supply both classification and table-binding proofs. AST spans are
original UTF-8 byte offsets; comments, regex literals, templates, automatic
semicolon insertion and Unicode names do not require text-based guessing.

- `switch (selector)` is `switch_on_value`; computed member calls, including
  `.call` and `.apply`, are `handler_table`.
- Equality tests on one resolved symbol with at least three distinct integer
  constants are `compare_chain`. `h = h(...)` is `threaded`.
- Indexed reads and byte/string accessors are cursor reads when the bound
  index advances in the loop. A numerically initialized cursor also qualifies
  when assigned a new position. Writes in functions stored in the dispatched
  table count, including `pc++`, `pc += k` and `pc = code.length`. A switch arm
  dispatching that table shares this evidence.
- Direct calls to statically bound, unreassigned function declarations propagate
  an invoking loop for at most 16 edges. This recognizes a loop calling a
  `step()` helper without repeatedly traversing function bodies. Unknown call
  targets and values returned by helpers are not inferred.
- Object positions are `frame_slot`; a repeating frame slot requires an
  arithmetic advance. A worklist index assigned from `queue.pop()` is unknown.
- In-place parameter coercions preserve `call_argument`. Definitions and writes
  are keyed by semantic symbols, never spelling alone.
- String labels, string accessors, string bindings and `arguments` buffers
  suppress interpreter roles. Array and typed-array initializers remain
  explicit buffer refinements. A second lookup retains `through_lookup`.

Each AST node and scope is indexed once, inheriting its function and loop from
its parent. No function body is copied or rescanned for each enclosing function.
Unmodified Oxc 0.155.0 resolves references against its completed bindings. A
linear prepass bounds its ancestor walks before semantic analysis; no vendored
resolver or alternate binding rules are used.

Outside these structural rules, selectors stay `unknown`. A parse or semantic
error produces one counted `parse-failed` artifact omission and no site or table
proof. The artifact's classification is unknown, not a guessed interpretation of
a partial AST; recovered claims are withheld with that reason.

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
imported global, directly or through a defined global, is relative: it fills no concrete slot and invalidates earlier slots in that
table that it could overwrite. Later concrete segments establish their slots again. A segment ending past the table's declared minimum is out of range
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
Wasm, using conservative admission charges and explicit query charges for:
parser admission, AST/scope indexing, selector queries, Wasm table parsing and type-matching slot scans, symbolic simulation
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

Producer 1.8.0 and workspace producer 2.11.0 share the same meter through
classification, semantic claim resolution and workspace table extraction. Vector
capacities, table layouts, matching lists and symbolic indexes reserve their
retained bytes before growing. Temporary JavaScript parser/semantic storage has
a separate allocation ceiling, with actual peak telemetry on the same meter. Wasm constant-expression
operand stacks reserve capacity before each growth, including global initializers. Exhaustion in
the downstream pass is also recorded on the analysis and any returned workspace.
A scaling test runs this analysis-to-workspace path, including deep nested
loops, many element tables, scope noise and dense punctuation. It is distinct
from process RSS, which also includes unchanged recovery, artifact storage,
serialization, the runtime and allocator overhead.

Each selector query also has a logical step budget of 4096 steps, replayed on
memo hits so a site's result never depends on query order. It is a semantic
bound, not a work charge.

JavaScript accepts sources up to 8 MiB. Parser admission pre-charges 64 work
units per byte; pipe transfer adds two units per source byte and one per reply byte. The unmodified Oxc parser
and semantic builder run by re-executing the calling binary (`current_exe`) in
an internal worker mode. The CLI, backend, API executable and Cargo test harnesses
share the same entry point; there is no sibling discovery or version-skew path. Its allocator checks every allocation, reallocation overlap and
32 bytes of per-allocation overhead against 64 MiB + 80 times source bytes,
bounded to 704 MiB. No worst-case arena is reserved. The arena, semantic vectors,
classifier indexes and serialized reply all count; the measured peak returns to
the artifact meter. On refusal the allocator writes fixed-size telemetry and
exits the disposable worker before calling the system allocator. It never
unwinds inside GlobalAlloc. The caller records an omission and withholds proof.
An operational failure instead produces `analysis-worker-failed` with one counted
artifact and a `timeout`, `crash`, `spawn` or `protocol` detail. No analysis,
workspace or host-link document is persisted, and the backend never caches that
failure. The CLI exits nonzero; the API returns HTTP 503 with
`dependency_unavailable`, the counted reason, and a retry instruction. The next
request retries unchanged inputs. A successful earlier document remains intact.
The wall-clock deadline is only a hang backstop: five minutes plus one minute per
started MiB, up to thirteen minutes. Deterministic work and allocation meters
still own resource refusal. The worker starts with an empty environment (only
test-entry flags in libtest), closes descriptors beyond its three pipes, and
refuses startup if its network containment cannot be installed. macOS also denies
file reads and writes after startup; Linux denies network socket operations.
Source and compact results travel through bounded anonymous pipes, never disk.
Only compact site/proof records survive under the separate 128 MiB retained cap.
A parser reservation cannot consume that cap. Reserved 32 MiB recursive stacks
(64 MiB for deep syntax) are not charged as retained heap. Peak RSS includes
resident stack pages, allocator slack, both processes and unchanged recovery;
the measured 8 MiB target is approximately 1 GiB or less on a local workstation.

An iterative lexical guard refuses more than 8192 nested delimiters or operators
in one expression. Delimiter scopes and sibling expression boundaries reset the
local expression counter; object properties and switch arms never accumulate. Strings, template text, comments and regexp bodies are atomic
for this guard; template substitutions re-enter syntax. Literal bytes never count
as nesting. This admission pass cannot create claims; Oxc owns syntax and binding. A linear AST prepass bounds hoisting by intervening block scopes
times binding-pattern bytes (at most twice source bytes). It also pre-charges
twice the sum of AST node depths, an upper bound on scope-resolution and syntax
ancestor walks, plus redeclaration and private-name suggestion work. Semantic
admission allows at most 128 units per source byte and draws those units from
the remaining artifact work budget. Normal code with depth well below 100 stays
admissible; pathological scope chains are counted refusals. Tests require those
refusals while retaining linear scaling assertions for other generated shapes.
All resource refusals remain distinct from syntax failures.

JavaScript sites are scheduled artifact-wide in structural strength order:
first a cursor fetch bounded by that same buffer's length, then other
loop-enclosed fetches, before the 4096-site artifact bound. Every Wasm function
is simulated, then sites are classified module-wide in strength order.

- When the meter is exhausted, classification stops. Every site found but not
  classified is counted as `classification-work-limit` with `omitted_records`,
  including exhaustion partway through a site: the incomplete record is omitted,
  not emitted as a literal unknown site. The detail counts artifacts or
  functions never examined. The
  opcode-claim gate reports such a site as not classified because of the work
  limit, never as "not a cursor-advancing loop".
- A site whose trace hit the depth, per-query step or alternatives bound, or
  whose Wasm function ran out of symbolic nodes, is classified `unknown` and
  counted as `classification-trace-limit`. A bound never yields a confident
  different source, and no bound cuts a list of writes or stores silently.
- JavaScript parser admission refusal is a counted `classification-work-limit`.
  A module whose sections do not decode adds `classification-unavailable`.
- `parse-failed` counts syntax or semantic failures. `analysis-worker-failed`
  counts retryable execution failures. `handler-binding-unproven` counts numeric
  function entries without a unique static binding. `classification-region-limit` counts bounded
  region omissions. All producer reasons are accepted by every embedded schema
  and the real UI validator and displayed as inert text.

## Downstream use

Only `interpreter-candidate` sites can carry guest-opcode claims. The
classification is never an input to handler recovery, tier or score:

- JavaScript handler recovery is unchanged; it alone decides the tier and the
  score. The opcode-claim gate is a pure post-filter on what recovery returns:
  it removes claims and never adds one.
- A recovered `switch` case survives only when that switch is an
  interpreter-candidate site. A recovered table entry (`t[3] = function`, an
  object map, or a function element of an array literal) survives only when
  the region dispatches through that table, as
  `t[selector](...)` or `t[selector].call(...)`, including from a nested
  function of the region, at an interpreter-candidate site. A dispatch through
  a temporary (`h = t[op]; h()`) ties nothing, and a table with no such site
  is withheld as unclassified.
- A table ties only to references resolving to its declaration's Oxc symbol,
  with exactly one static write (initializer or assignment). A
  declaration without an initializer followed by its only assignment qualifies.
  Block `let`/`const`, hoisting, Annex B, catch parameters, named functions,
  parameter defaults, classes and shorthand use Oxc's semantic rules. Unresolved
  globals and implicit non-arrow `arguments` have no provable table symbol.
  `with` in an enclosing scope makes static name resolution ambiguous. A failed/incomplete analysis
  always withholds claims.
  An Annex B block function's implicit replacement of an existing `var` table
  also counts as a write, although it has no ordinary reference-write AST node.
- An array entry's opcode is its AST position, counting holes, and a recovered
  handler index must equal it. Elements after a spread have no static position
  and no proof. A table whose entries are written through a computed member
  (`t[k] = f`, `delete t[k]`, destructuring) or reordered in place (`splice`,
  `shift`, `unshift`, `reverse`, `sort`, `copyWithin`, `fill`) is unproven:
  an entry's position no longer names its handler.
- `obj.ops` requires the same resolved receiver symbol and static, non-computed
  property name, with a single static write to that key. Distinct receivers are
  independent; private `#ops` never matches ordinary `ops`. `this.ops` requires
  initialization and dispatch in the same function, with exactly one static
  assignment in that function's own `this` scope and no other static write to
  that key through `this` in it.
- Operand-width guesses and owned-effect reachability use only surviving
  handlers. Exact AST case/property spans connect proof records to unchanged
  recovery; workspace extraction never parses the artifact a second time.
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

Claims describe the statically bound table. Runtime replacement through `eval`
or `Function`, Proxy or reflection, global-object writes, sloppy `arguments`
aliasing, and conditional or never-executed initialization are not modeled.
Runtime evidence from native guest capture is the authority for what actually
executes.

- A byte-cursor loop over text, such as a format-string or tokenizer loop, is
  structurally an interpreter candidate. `buffer_kind` flags JavaScript string
  buffers; Wasm has no equivalent signal.
- An opcode fetched through a helper call (`op = next(state)`) is `unknown`.
  Only a statically bound direct helper invocation can propagate loop context;
  returned values are not followed.
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
- A table used through a temporary supplies no opcode claims.
- Structural scheduling is not semantic proof. More than 4096 equally strong
  sites in one artifact can still omit a later interpreter. The omitted site count
  is explicit; neither strength ordering nor withholding changes VM ranking.
- The declared minimum is a lower bound for an imported table, so an imported
  table's out-of-range segment may still fit at instantiation. It is reported,
  not placed.

Fixtures and their expected classifications are in
[`tools/fixtures/dispatch-shapes`](../tools/fixtures/dispatch-shapes/README.md).
