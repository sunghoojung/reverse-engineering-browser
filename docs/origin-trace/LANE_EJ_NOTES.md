# Lane EJ, wave58 shared preflight admission bound

**Worker, contract and documentation change landed; no browser attestation.**
The shared Tree-sitter admission guard in front of every deobfuscation-worker
operation now admits the dense obfuscated-glue class it used to refuse, and its
verdict is a function of the supplied bytes rather than of machine speed.
`preflight_nodes` moves from a free-standing `500000` to
`MAX_SOURCE_BYTES / 2` = `2097152`, and the iterative traversal no longer
consults a wall clock. A 1,556,811-byte synthetic bundle at real minifier
density is admitted by both an optimized and an unoptimized worker, with
identical verdicts and identical region-scoped facts.

Admission is not coverage, and this lane does not claim it is. A whole-glue
`get_source_facts` on that bundle is now *admitted* and still returns the honest
empty-table partial at the AST node budget, naming the narrower request. What
changes is that lane EB's region path, the fold/deobfuscation path and the
function/candidate queries now reach these bytes at all.

## Why 500000 nodes and one second tripped

Lane EB left this as the next concrete action: the node bound, not the AST
budget, was the ceiling for large bundles, and moving it needed its own depth,
memory and timing evidence rather than a constant bump. Two measurements decided
the shape of the change, and both argue against a bare raise.

### Node density, not byte size, is what the old bound measured

`MAX_SOURCE_BYTES` advertises 4 MiB. A 500000-node bound turns that into an
undeclared and much lower byte cap whose value depends on how dense the source
is. Measured on synthetic sources with a clean parse, release build, this
machine:

| Shape | Bytes | Nodes | Nodes/byte | Tree depth | Parse ms | Walk ms | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Long string table | 4,194,134 | 211,893 | 0.051 | 13 | 55 | 8 | 40 MiB |
| Minified, unique short globals | 1,556,768 | 1,220,648 | 0.784 | 19 | 204 | 43 | 135 MiB |
| Minified, unique short globals | 4,194,462 | 3,089,912 | 0.737 | 19 | 538 | 108 | 338 MiB |
| **Minified, locals reused per scope** | 1,556,811 | 1,699,091 | **1.091** | 17 | 289 | 60 | 186 MiB |
| **Minified, locals reused per scope** | 4,194,375 | 4,549,643 | **1.085** | 17 | 811 | 165 | 495 MiB |
| `[0,0,0,...]` / `a,a,a` | 1,048,578 | 1,048,581 | 1.000 | 3 | 285 | 53 | 197 MiB |
| `a=>0;` repeated | 1,048,575 | 1,258,291 | 1.200 | 3 | 209 | 47 | 161 MiB |
| `a+a+a...` | 1,048,577 | 1,572,867 | 1.500 | **524,290** | 225 | 68 | 239 MiB |
| `;;;;` | 1,048,576 | 2,097,153 | **2.000** | 2 | 352 | 80 | 294 MiB |

Two things fall out. The grammar's ceiling is two nodes per byte, reached by
empty statements, so a node bound of *N* admits **any** source of *N*/2 bytes
whatever its shape. And the density that matters for this project is not the
0.74–0.87 band a first synthetic suggested: real minifier output reuses
one-character locals in every scope, which measures **1.09 nodes per byte** and
is the densest realistic JavaScript shape. The repository test fixture uses that
shape for exactly this reason; the looser one would have understated the bound.

At 1.09 nodes per byte, 500000 nodes is a **458 KiB** effective ceiling for
minified code, against a declared 4 MiB. That is the defect.

### The node bound cannot bound parse memory, so raising it costs no memory

The bound is evaluated during the traversal, which runs after
`parse_with_options` has already returned a complete tree. The whole tree is
therefore built and paid for before the first node is counted. Measured through
the real release worker on a 4 MiB source of empty statements, which the guard
**refuses**:

```text
path-semis-4mib  bytes=4194304  peak_rss_mib=1177.8  ok=False
                 errs=['JavaScript preflight exceeded its complexity budget']
```

1,177.8 MiB of transient tree for a source that produces no analysis at all.
That exposure is a function of `MAX_SOURCE_BYTES` times node density times
roughly 115–200 bytes per node, and it existed before this lane at every value
of the node bound. The consequence is the main memory argument here: **raising
the node bound adds no new peak-memory exposure for any source inside the byte
cap**, because the tree is already allocated either way. It only changes how
much of an already-paid-for tree may be used. Tightening the real exposure needs
a different mechanism and is listed under Known bounds.

### A clock inside the traversal made admission non-deterministic

The old guard checked `Instant::now()` on every node of the walk against a
one-second budget shared with the parse. That is what EB saw as "at 1.7 MB the
deadline fired instead", and it is worse than a size bound: it makes the same
bytes admissible or not depending on how fast the machine is.

Measured directly, with the node bound lifted and nothing else changed, on the
same 1.5 MB bundle:

| Worker | Preflight parse | Preflight walk | Verdict against a 1 s budget |
| --- | --- | --- | --- |
| Optimized (shipped) | 233 ms | 54 ms | admitted in 287 ms |
| Unoptimized | 1,254 ms | 345 ms | **refused**, "exceeded its time budget" |

Tree-sitter's parser is C and barely moves between profiles; the Rust chunk and
progress callbacks and the Rust walk do. An unoptimized build is a stand-in for
a machine roughly three times slower than this one, which is an ordinary
machine. So raising the constant alone would have shipped an admission decision
that a slower researcher's laptop disagrees with, for an evidence tool whose
budget reasoning already refuses to let two reports of the same bytes disagree
about what was admitted.

This is pinned as a test rather than left as prose: restoring the walk clock and
the one-second budget fails both new preflight tests, one because the glue class
stops being admitted and one because a source over the node bound starts
reporting the time budget instead of the complexity budget.

## Why a region-scoped preflight was rejected

The mission allowed a scoped admission path matching EB's region-scoped
`source_facts`. It is not sound here, for two measured reasons.

The depth bound must cover the whole tree. `source_facts` resolves a requested
region *inside the parse of the complete source*, which is EB's load-bearing
contract decision because a byte slice's meaning depends on the scope chain and
strictness around it, so Oxc's recursive descent still runs over every byte.
A traversal that skipped siblings would admit a source whose untouched part
overflows the native stack. The `a+a+a...` row above is that case: 1 MiB of it
reaches tree depth 524,290 while every other shape measured stays under 20.

And scoping would save almost nothing. At the byte cap the parse is 552 ms of a
691 ms preflight, and the parse is whole-source regardless because the region is
a cursor into it. Scoping the walk saves at most the remaining 20% and gives up
the only safety property the walk provides. The node count is the one scopable
part, and scoping it would bound nothing that is not already bounded.

## What the bound and the budget are now

`MAX_TREE_NODES = MAX_SOURCE_BYTES / 2 = 2097152`, expressed against the byte
cap it guards rather than as a magic number:

- Any source up to 1,048,576 bytes is admitted whatever its shape, with no
  density assumption, because the grammar cannot exceed two nodes per byte.
- Above that it is a density bound. At the measured 1.09 nodes per byte of real
  minifier output the practical ceiling is about 1.9 MB of minified code.
- The 1,556,723-byte target glue class is admitted for any density up to 1.347
  nodes per byte, a 23% margin over the densest realistic shape measured.
- Worst case at the bound: 0.57 s parse optimized, 1.80 s unoptimized, and a
  measured 250 MiB transient tree.

`PARSE_BUDGET` is a named four-second constant on the parse only. It is a
pathological-grammar backstop that must not decide admission: four seconds
clears the 1.80 s unoptimized parse at the node bound by more than twice, and a
single pathological parse still answers inside the five-second deadline
`DeobfuscationService` applies to the process, so a refusal stays a recoverable
diagnostic and the next JSON-line request still works instead of the worker
being killed. The traversal consults no clock at all; it is bounded by node
count and tree depth.

Every diagnostic string is unchanged, so no consumer of the worker contract has
to learn a new refusal.

## Measured result

Real worker, final constants, both build profiles, synthetic minified glue at
1.09 nodes per byte:

| Source | Nodes | Optimized | Unoptimized |
| --- | --- | --- | --- |
| 794,709 B minified | 867,707 | ok, 435 ms, 128 MiB | ok, 1,499 ms |
| **1,556,811 B minified (glue class)** | 1,699,091 | **ok, 451 ms, 247 MiB** | **ok, 2,341 ms** |
| 2,097,175 B minified | 2,284,667 | refused, complexity budget | refused, complexity budget |
| 4,194,142 B minified | 3,089,696 | refused, complexity budget | refused, complexity budget |
| 4,194,134 B string table | 211,893 | ok, 95 ms, 40 MiB | ok, 507 ms |

Before this change the first two rows were
`JavaScript preflight exceeded its complexity budget` with nothing analyzed.

The same glue-class source is admitted by the `OriginTraceDeobfuscator` binary
inside the signed `Origin Trace.app` bundle, in 529 ms at 247 MiB, so the
measured behavior is the shipped worker and not only a development build. That
is still component evidence: the native app was not launched and no UI view
issued the request.

On the 1,556,811-byte bundle, `source_facts` through the real worker, identical
in both profiles:

| Request | Result |
| --- | --- |
| Whole program | `partial`, 0 facts, `["AST node budget exceeded; no lexical resolutions produced", "request region_start_byte and region_end_byte to analyze one callable body instead"]` |
| Region at a callable body | `partial`, 78 facts, `analyzed_range {41,123}`, `"analysis covered coverage.analyzed_range only; omitted syntax remains unknown"` |

That pair is the honest coverage story. Admission does not make a whole-glue
census available; it makes the region path, the fold path and the function and
candidate queries reach the bundle, and the whole-program answer still says
plainly that it resolved nothing and which narrower request can.

## Blast radius

The guard is shared, so this moves for every caller at once:

| Caller | Path |
| --- | --- |
| `main::analyze` | Deobfuscation and folding of the original source |
| `main::validate_derived` | The complete derived text before any rewrite receipt is published |
| `source_facts::analyze` | Whole-program and region-scoped lexical facts |
| `preflight::function_at` | The `function_at_byte` query |
| `preflight::candidate_function_at` | The candidate-experiment bridge |

The lane brief also listed `request_field`. It does not use this guard:
`request_field` is a JSON-pointer extractor with its own 128 KiB body cap and no
JavaScript parse. Nothing else in the repository hardcodes the preflight limits;
`source_facts` now reports `preflight_depth` and `preflight_nodes` from the
guard's own constants so a declared limit cannot drift from the bound that
actually decided admission.

Two consequences worth stating. Admitting larger sources means larger Oxc
arenas and larger declaration tables behind the guard; those are bounded by the
existing `max_ast_nodes` and `max_facts` budgets, which fail closed with empty
tables, and that is the path the 1.5 MB bundle takes above. And derived text is
capped at 4 MiB plus the 512 KiB replacement budget while the node bound is
derived from the 4 MiB source cap, so a rewrite that grows a source already near
the node bound can be refused at derived validation; that returns
`error_kind: "derived-validation"`, preserves the original text and discards the
rewrite receipts, which is the existing fail-closed behavior and is now
documented in the worker README.

## Known bounds

- **`max_source_bytes` is still unreachable for the densest code.** The node
  bound admits minified code to about 1.9 MB, not 4 MiB. Closing that gap was
  measured and rejected in this lane: a 4 MiB minified source needs about 4.6M
  nodes, its parse costs 2.4 s unoptimized, and a budget large enough to admit
  it deterministically would no longer leave a recoverable diagnostic inside the
  five-second process deadline. The byte cap stays the declared limit and the
  node bound stays the honest narrower one.
- **Transient parse memory is not bounded by this guard and was not reduced.**
  1,177.8 MiB measured on a refused 4 MiB source, and about 250 MiB at the new
  admission ceiling. The tree is complete before any node is counted, so
  bounding it needs a different mechanism, such as refusing inside the parse
  progress callback on consumed bytes, or a smaller byte cap for this operation.
  Neither is attempted here. This lane did not make the exposure worse: it is
  the same tree either way.
- **The refusal *reason* above the bound can still depend on the profile.** For
  sources far above the node bound the parse may exhaust `PARSE_BUDGET` before
  the walk reaches the node that would refuse them: a 4 MiB source of empty
  statements reports the complexity budget optimized and the time budget
  unoptimized. The *decision* is refused in every case and in every profile;
  only the diagnostic differs. This is strictly narrower than the behavior
  before the change, where the clock could change the decision itself.
- **The density evidence is synthetic.** No captured artifact body was parsed in
  this lane, by design. The 1.09 nodes per byte figure comes from authored text
  shaped like minifier output, and the real `acf7687c` glue's density was not
  measured. The claim that it becomes admissible rests on that figure plus the
  stated 23% margin, and on the fact that real glue carries long string literals
  that only lower density. It is an argument from measurement, not an
  observation of the artifact.
- **Nothing here is attested in a browser.** No Brave toolchain exists on this
  machine. No live session, no capture, no `native_console start`, no rendered
  Origin Trace evidence, and no UI behavior changed: the Sources Facts panel
  still requests whole artifacts and does not expose a region, so a bundle that
  reports a reached budget is still narrowed through `reb-api`.
- **Admission says nothing about meaning.** A larger source being parseable does
  not make its facts a call graph, an ownership claim, or a statement about what
  the code does. Every existing limitation in
  [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md)
  and the [method coverage](../product/deobfuscation-method-coverage.md) applies
  unchanged.

## Privacy

No new data is read, retained or transmitted, and no captured bytes were used to
measure anything. The guard decides whether an already-verified local artifact
may be parsed at all; relaxing it does not widen what a response describes.
Diagnostics remain fixed strings with no source excerpts. The capture and
retention boundaries in [`SAFETY.md`](../../SAFETY.md) are untouched.

## Changed files

| File | Purpose |
| --- | --- |
| `apps/deobfuscator-worker/src/preflight.rs` | Node bound derived from the byte cap, named `PARSE_BUDGET`, the clock removed from the traversal, the reasoning for each bound, and tests for the glue class and the bound's determinism |
| `apps/deobfuscator-worker/src/source_facts.rs` | Declared limits reported from the guard's constants, the updated budget note, and the admitted-but-honest dense-bundle test |
| `apps/deobfuscator-worker/README.md` | What the shared bound is, which operations it fronts, that admission does not depend on the machine, and the derived-text interaction |
| `protocol/openapi.json` | `preflight_nodes` const in both response schemas |
| `protocol/javascript-source-facts-v1.md` | The bound's derivation, the shape-independent floor, the density ceiling and what a refusal looks like |
| `docs/product/deobfuscation-method-coverage.md` | The preflight paragraph: new bound, no traversal clock, parse backstop |
| `apps/origin-trace-backend/tests/http.rs` | Declared-limits fixture |
| `tools/check-origin-trace-debugger.mjs` | UI-consumer fixtures kept contract-valid |
| `docs/origin-trace/LANE_EJ_NOTES.md` | This note |

## Validation

Run in `/tmp/hsw-lane-worktrees/reb-EJ-preflight-nodes`.

| Command | Result |
| --- | --- |
| `make lint` | passed |
| `make check` | passed, including `source_facts_real_worker_http_and_cli` against the built Rust/Oxc worker |
| `make e2e` | passed |
| `make sanitize` | passed |
| `git diff --check` | passed |
| `cargo test` (deobfuscator worker) | passed, 56 tests |
| `node tools/check-origin-trace-debugger.mjs` | passed |
| `make app-build` | passed |
| `codesign --verify --deep --strict "build/Origin Trace.app"` | passed |
| `make rendered-ui-check` | skipped: no UI behavior changed; also unavailable, no full Xcode on this machine |
| `make brave-doctor` | skipped: nothing under `browser/integration/brave/`, no pin and no probe changed |
| `make brave-probe-check` | skipped: same reason, and no initialized toolchain exists here |

Each new case was confirmed to fail before the change, in two separate ways.
Restoring `MAX_TREE_NODES = 500_000` fails
`the_node_bound_admits_the_dense_minified_glue_class` and
`a_dense_minified_bundle_is_admitted_and_still_reports_what_it_covered`, the
second reporting `unavailable` with the preflight diagnostic and no facts.
Restoring the clock inside the traversal with a one-second budget fails
`the_node_bound_admits_the_dense_minified_glue_class` and
`a_source_over_the_node_bound_is_refused_by_the_bound_not_by_a_clock`, which is
the determinism half of the change rather than the constant.

This is repository and component evidence from one machine. It does not attest
the guard inside a running Brave build, against live capture, or in the rendered
Origin Trace application, and it does not establish that any particular captured
artifact is admissible.
