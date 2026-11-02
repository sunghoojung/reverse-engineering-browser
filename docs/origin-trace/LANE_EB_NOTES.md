# Lane EB, wave54 region-scoped `get_source_facts`

**Worker, API and contract change landed; no browser attestation.**
`get_source_facts` now accepts an optional
`region_start_byte`/`region_end_byte` pair. The analysis unit becomes the
innermost callable body containing that original byte range, so a glue bundle
whose whole-program analysis reaches a budget and returns zero resolutions can
still produce exact facts for one callable. Coverage declares what it covered:
every response carries `coverage.analyzed_range`, a narrower range can never be
reported as `complete`, and a name that leaves the analyzed body is
`unresolved` with the new reason `outside-analyzed-region` rather than a
resolution guessed from a declaration table this report left open. The
whole-program AST node budget also rose from 32768 to 262144 nodes, which is
what admits mid-size scripts that previously produced nothing at all.

The repository gate proves the mechanism in the worker, through the HTTP
adapter, and through the generic CLI against the real Rust/Oxc worker. No Brave
toolchain exists on this machine, so nothing here is attested inside a running
browser or against live capture.

## Why raising the budget alone was not the answer

Lane DV measured `max_ast_nodes: 32768` against a roughly 1.5 MB
single-expression hCaptcha glue bundle and got
`AST node budget exceeded; no lexical resolutions produced`: a hard fail with
empty fact tables. Raising that one number does not fix the bundle case,
because the next limit is the declaration budget. `max_facts` is 16384 across
all five tables and is checked against scopes plus bindings plus callables
before any reference is resolved, so a file with more declarations than that
reaches the same empty-table outcome by a different route.

Measured on synthetic bundles of the same shape (one glue IIFE of small
recursive functions plus one target callable), with the debug worker on this
machine:

| Bundle | Whole program | Region at the target callable |
| --- | --- | --- |
| 127 KiB | partial, 16384 facts; **zero** at the old budget | partial, 28 facts |
| 385 KiB | partial, **zero** facts, declaration budget | partial, 28 facts |
| 775 KiB | `unavailable`, preflight complexity budget | `unavailable`, same |

The first row is what the raised node budget buys, confirmed by rebuilding the
worker with the old 32768 and re-running: that file produced
`AST node budget exceeded` and no facts before this lane. The second row is DV's
failure mode, and a region is the only thing that answers it; a region produced
the same 28 facts at the old budget too, so scope, not the raise, is the
load-bearing change. The third row is a bound this lane does not move; it is
described under Known bounds.

A caller-supplied budget was rejected as the API. Two reports of the same bytes
would then disagree about what was admitted, and a client could ask for work
the worker exists to bound. The budget stays fixed and declared; the caller
chooses scope instead.

## API shape

Both parameters are optional, must appear together, and are canonical unsigned
decimals. They form a half-open range of original UTF-8 bytes inside the
verified source at Unicode scalar boundaries; equal offsets address one cursor,
which is the natural gesture from a Sources selection or a known table offset.
A half pair, a reversed range, an offset past the verified byte size and an
offset inside a multi-byte scalar are all 400. No other parameter was added and
none became optional.

```sh
reb-api call get_source_facts --endpoint-file /tmp/reb-api-endpoint \
  --param session_id=1 --param artifact_id=2 \
  --param region_start_byte=393216 --param region_end_byte=393216
```

The range selects no bytes by itself. It is a *cursor into the parse*, not a
slice: the analysis unit is the innermost callable body containing it. A range
no callable body contains analyzes the whole program, which keeps the scoped
request honest rather than inventing a fragment to analyze.

Slicing bytes and parsing the slice was the alternative, and it is wrong at the
contract level. A slice's meaning depends on the bytes around it: its scope
chain, its strictness, and whether its syntactic position is a statement or an
expression at all. The facts would carry real-looking ranges derived from a
program that does not exist.

## Mechanism

`apps/deobfuscator-worker/src/source_facts.rs` parses the complete source
exactly as before. The requested range is resolved inside that parse by
`Select`, which descends only into nodes containing the range and records the
innermost callable body it passes through. Cost is the spine plus one span test
per sibling, so selection does not depend on bundle size.

The three existing traversals then share one predicate, `analyzing`: a node is
analyzed when its span overlaps the analyzed window. Enclosing nodes always
overlap, so the real scope chain above the selected body is retained while its
siblings are skipped. Because the window is itself an AST node span, every
other node is contained in it, contains it, or is disjoint; nothing straddles.

The predicate is applied at four points in each of `Count`, `Declarations` and
`Effects`: statements, expressions, functions and arrow functions. Statements
and expressions cover every unbounded descent except one, and callables are
gated because a class body is neither: without that gate an enclosing class
would contribute every sibling method's declarations to a selected method's
report. `Effects` reads the window from the `Declarations` it consumes rather
than holding its own copy, because the two traversals index the same span-keyed
maps and a disagreement would be a missing-entry panic, not a wrong fact.

`coverage.analyzed_range` is a required field on both the worker and HTTP
schemas. The HTTP adapter checks the claim against the request it made instead
of trusting it: an unscoped request must report the whole source, a scoped one
must report a range containing what was asked, and a range narrower than the
source can never carry `complete` status. Those three checks are the reason a
worker cannot answer a narrow question with a broad claim or the reverse.

## Why region scoping cannot invent a resolution

Pruning a traversal makes declaration tables incomplete, and resolving against
an incomplete table is exactly the guess this profile already refuses for
declaration-budget exhaustion. Every skip therefore marks scopes open:
`Declarations::skipped` inserts the current scope and the nearest var scope into
an `incomplete` set. Those two are sufficient because skipped syntax can only
declare lexically into the scope it sits in or hoist a `var` to the nearest var
scope; scopes nested inside skipped syntax are not in the report at all.

`resolve` then refuses an open scope before it reads its name table, so neither
a hit nor a miss there becomes a fact. A hit is refused as well as a miss: a
skipped sibling could hold a duplicate declaration of the same name, which
would make the honest answer an ambiguity set rather than the single binding the
partial table shows.

The selected callable body and everything nested inside it are complete, because
nothing inside the window is skipped. That is why a region still produces useful
facts: parameters, locals, nested closures and their operations resolve exactly,
with original byte ranges.

Direct `eval` and `with` do not become a hole. Both can only add bindings to a
scope, and the only scopes a skipped `eval` or `with` can affect are the ones
the report already declared open: the environment they alter is their own var
scope, which is either inside the skipped syntax (absent from the report) or on
the retained chain (already open). An `eval` or `with` inside the window is
walked and still sets the existing global `dynamic-scope` behavior.

## Known bounds

- **The preflight admission bound, not the AST budget, is now the ceiling for
  large bundles.** `preflight_nodes` is 500000 tree-sitter nodes with a
  one-second parse deadline, and it is shared by every worker operation. On the
  synthetic shape above, sources from roughly 775 KiB returned
  `unavailable: JavaScript preflight exceeded its complexity budget`, and at
  1.7 MB the deadline fired instead. DV's actual 1.5 MB bundle is therefore
  still refused at admission, before any of this lane's code runs, and
  `max_source_bytes: 4194304` remains unreachable for dense minified code.
  Raising that bound is a separate change: it is the guard in front of a
  recursive-descent parser for `source_facts`, `request_field`, `fold`,
  deobfuscation and the candidate-experiment queries, so it needs its own
  depth, memory and timing analysis rather than being moved here. **This is the
  next concrete action for the glue census.**
- **The node budget raise is reasoned, not profiled.** 262144 was chosen to sit
  below the preflight node bound that already admitted the source, so that the
  node budget stops being the first limit reached. Transient memory grows with
  it, because declaration tables are built before the fact budget is checked; no
  allocation profile was taken, and the worst case was bounded by argument
  (declarations are a fraction of nodes) rather than measured.
- **`outside-analyzed-region` is weaker than unscoped resolution.** It
  deliberately does not distinguish a declaration in the skipped part of the
  file from a genuine global. An unscoped report separates those as
  `external-or-implicit`; a region trades that distinction for the ability to
  produce anything at all. A scoped report is not a smaller version of an
  unscoped one.
- **Facts outside `analyzed_range` exist and are not errors.** The retained
  enclosing structure keeps its own facts: the program scope and region, a spine
  callable and its parameters, the eager-argument regions of a call whose
  argument is the selected function. Those regions can be empty shells, which is
  how the selected callable keeps a truthful `entry_order` among the arguments
  of the call that receives it. Local order values rank the facts a report
  emitted; under a region they do not imply a position among siblings it never
  analyzed.
- **A region does not guarantee facts.** If the selected body is itself over a
  budget, the response is still the honest empty-table partial, now carrying the
  range it attempted and a note naming the narrower request. That path is
  pinned by `a_region_whose_callable_still_exceeds_a_budget_fails_closed`.
- **The effect region for a selected body can be absent.** Classes and
  async/generator bodies are declared frontiers in this profile, so a selected
  method body appears in `callables` with no `callable-body` region. The cursor
  sweep asserts the callable, not the region, for exactly this reason.
- **Nothing here is a claim about ownership.** These are lexical declarations
  and effects over retained bytes. A scoped report says even less than an
  unscoped one. It does not establish module owners, cross-build identity, a
  call target, or that a resolved binding still holds its declared function.
- **Not exercised in the UI.** Sources **Facts** still requests whole artifacts
  and does not expose the region. Its coverage line therefore can never be a
  scoped claim. The panel tolerates the new coverage field and does not display
  it; a bundle that reports a reached budget is narrowed through `reb-api`
  instead. No rendered UI evidence was produced because no UI behavior changed.

## Privacy

No new data is read, retained or transmitted. A region narrows which bytes of an
already-verified local artifact are interpreted, which strictly reduces what the
response describes. Request-body retention is untouched; DV's retention question
remains a policy decision under [`SAFETY.md`](../../SAFETY.md). Diagnostics stay
fixed strings and never carry source excerpts, and the new frontier ranges are
offsets into bytes the caller already holds.

## Changed files

| File | Purpose |
| --- | --- |
| `apps/deobfuscator-worker/src/source_facts.rs` | Region admission, `Select`, the shared `analyzing` gate in all three traversals, open-table refusal, `analyzed_range`, budget notes, and the raised node budget |
| `apps/origin-trace-backend/src/source_facts.rs` | Adapter checks that the declared coverage answers the request that was made |
| `apps/origin-trace-backend/src/deobfuscation.rs` | Forwards the requested range to the worker and validates against it |
| `apps/origin-trace-backend/src/app.rs` | The two query parameters, the paired-or-neither rule, and byte-range admission against the verified source |
| `protocol/openapi.json` | Parameters, `coverage.analyzed_range`, the new unknown reason in both closed vocabularies, the node budget, and the route's uncertainties |
| `protocol/javascript-source-facts-v1.md` | Region semantics, coverage honesty, budget reasoning and the resolution it refuses |
| `protocol/http-api.md` | CLI route summary for the new pair |
| `apps/deobfuscator-worker/README.md` | Worker-side meaning of the optional region |
| `apps/research-ui/README.md` | That the Facts panel does not expose the region, and where to narrow instead |
| `apps/origin-trace-backend/tests/http.rs` | Region forwarding, CLI projection, coverage-claim refusals, 400 admission cases, and the real-worker end-to-end case |
| `tools/check-origin-trace-debugger.mjs` | UI-consumer fixtures kept contract-valid |

## Validation

Run in `/tmp/hsw-lane-worktrees/reb-EB-ast-budget`.

| Command | Result |
| --- | --- |
| `make lint` | passed |
| `make check` | passed, including `source_facts_real_worker_http_and_cli` against the built Rust/Oxc worker |
| `make e2e` | passed |
| `make sanitize` | passed |
| `git diff --check` | passed |
| `cargo test` (deobfuscator worker) | passed, 53 tests |
| `cargo test --test http source_facts` | passed, 4 tests plus the real-worker case |
| `node tools/check-origin-trace-debugger.mjs` | passed |
| `make app-build` | passed |
| `codesign --verify --deep --strict "build/Origin Trace.app"` | passed |
| `make rendered-ui-check` | skipped: no UI behavior changed; also unavailable, no full Xcode on this machine |
| `make brave-doctor` | skipped: nothing under `browser/integration/brave/`, no pin and no probe changed |
| `make brave-probe-check` | skipped: same reason |

Each new case was confirmed to fail before the change. Disabling the open-table
refusal in `resolve` fails both the bundle case and
`an_open_declaration_table_never_resolves_or_looks_external`, which then reports
a skipped outer declaration as a resolved binding. Disabling the statement gate
in `Declarations` makes the same test resolve `outer` from a table it should
have declared open. Disabling the callable gate fails
`selecting_one_method_skips_its_siblings_in_the_same_class`, which is the case
that gate exists for. `every_cursor_offset_keeps_one_consistent_report` sweeps
every admissible cursor over five awkward sources, including classes,
try/catch, generators, optional chaining, templates, `with` and direct `eval`,
and asserts the ownership invariants the adapter enforces; that sweep is what
would catch a traversal pair that disagreed about which nodes a report contains.

This is repository and component evidence. It does not attest the route inside a
running Brave build, against live capture, or in the rendered Origin Trace
application. No live session, capture clear, or `native_console start` occurred.
