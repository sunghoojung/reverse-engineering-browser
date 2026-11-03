# REB Rust deobfuscation worker

This is the bounded Rust worker boundary for JavaScript deobfuscation. It
accepts one JSON request per line on stdin and emits one JSON response per line
on stdout. It never executes the analyzed JavaScript.

The production pipeline parses JavaScript with Oxc and performs bounded static
primitive folding, constant propagation, string normalization and literal-index
recovery, member normalization, conservative dead-expression/branch removal,
and bounded interpretation of closed proxy/decoder calls and loop/switch dispatchers.
It returns original byte ranges for every rewrite and recoverable diagnostics.
See the [method coverage and limitations](../../docs/product/deobfuscation-method-coverage.md)
for the precise supported subsets and regression evidence.

## Run

```sh
cargo build --locked --manifest-path apps/deobfuscator-worker/Cargo.toml
cargo run --manifest-path apps/deobfuscator-worker/Cargo.toml
make deob-benchmark
```

Example request:

```json
{"source":"const value = 1 + 2 * 3;"}
```

Runtime Hooks may instead include `function_at_byte`, a zero-based UTF-8 byte
offset in the original source. The worker returns the innermost enclosing
function's `kind`, `start`, `end`, and `body_start` byte offsets in
`function_location`, without executing or rewriting the script. In this query
mode, `derived_source` is empty and `function_location` is null when the cursor
is outside a function. The retired CDP debugger was its only caller; no current
Origin Trace view issues this query, and it remains part of the worker contract.

The worker is a separate process bundled as `OriginTraceDeobfuscator` in the
native macOS app. `DeobfuscationService.swift` invokes it with a five-second
wall-clock deadline and projects its original UTF-8 byte ranges into the shared
UI response. It reads only the selected captured JavaScript artifact.

The browser development server uses this worker when available, with an explicitly
labelled Python lexical fallback when it is not built. Rust does not classify
obfuscation. Unknown decoder operations remain unresolved. Modeled prototype-dependent
coercions require the explicit standard-intrinsics assumption.

Requests are read with bounded buffers. An oversized record is drained through
the next newline, rejected, and flushed before reading another record. The
request cap allows JSON escaping of a 4 MiB source. At most 4,096 rewrites and
64 syntax diagnostics are retained. Further rewrites set
`transformations_truncated`; the remaining source is preserved unchanged.

See [the response contract](../../protocol/deobfuscation-v1.md).

Before recursive Oxc parsing, a heap-backed Tree-sitter preflight admits only
error-free JavaScript trees with depth at most 128, at most 2,097,152 nodes, and
a parse that asks its allocator for at most 384 MiB. Excessive nesting returns a
recoverable diagnostic and leaves the next JSON-line request usable. Both
grammars must support the input syntax.

That node bound is one tree-sitter node per two bytes of the 4 MiB source cap,
and it is shared by every operation here: deobfuscation, derived-text
validation, `source_facts`, and the `function_at_byte` and candidate queries.
Nothing behind it runs until it passes, so it decides whether a large
obfuscated bundle can be analyzed at all. The grammar cannot exceed two nodes
per byte, so a source up to 1,048,576 bytes is admitted whatever its shape;
above that, admission depends on density, and real minifier output measures
about 1.09 nodes per byte, which puts the practical ceiling near 1.9 MB of
minified code. The 4 MiB byte cap is still unreachable for the densest sources.

The depth and node bounds read a finished tree, so neither can bound what
building that tree costs. The parse heap ceiling is the bound that runs inside
the parse: tree-sitter's allocator is counted, and the parse is stopped from its
progress callback once the count passes 384 MiB. Without it a refused source was
paid for in full first, up to a measured 2,011.7 MiB on a 4 MiB source of nested
sequence expressions; with it that source is refused at 441.2 MiB. The ceiling is
192 bytes of parser heap per admissible node, against a densest admissible tree
that measures 136 and real minifier output that measures 118, so it clears the
whole realistic admission range. It does narrow the pathological end: a source
built from parser-stack-splitting shapes larger than about 1.2 MB is refused
here instead of by node count, and a deeply nested source above roughly 690 KB
now reports the memory ceiling rather than the depth bound. Both were refusals
before.

Admission depends only on the supplied bytes. The traversal is bounded by node
count and tree depth and never consults a clock, and the parse heap count is a
byte total whose allocation sizes and order follow the grammar and the source,
so the same source is admitted or refused identically on a slow machine and on
an unoptimized build, with the same diagnostic and the same peak. Only the
tree-sitter parse keeps a wall-clock backstop, four seconds, sized well above
the measured parse cost at the node bound so it cannot decide admission for a
source that bound admits; it exists for pathological grammar behavior and stays
inside the five-second process deadline so the refusal is still a recoverable
diagnostic rather than a killed worker. Every pathological shape measured now
reaches the heap ceiling well before that clock in either profile, so the
refusal diagnostic for a 4 MiB source of empty statements, which used to be the
complexity budget optimized and the time budget unoptimized, is the parse
memory budget in both.

Before accepting rewrites, the complete derived text passes the same bounded
preflight and Oxc parser with the original parse goal. Derived text is capped at
4 MiB plus the 512 KiB replacement budget, so a rewrite that grows a source
already near the node bound can be refused by it; that returns
`error_kind: "derived-validation"`, preserves the original text, and discards
all rewrite receipts. This establishes syntax acceptance, not semantic equivalence.
Object shorthand properties retain their original spelling and are not folded.

All modeled values share a monotonic 8 MiB allocation-work allowance and
250,000-node allowance across the whole analysis, including closed decoder
calls. Owned arrays cache their full clone cost and depth; copies reserve the
complete cost before allocation and have no unrestricted `Clone` implementation.
Array slots, string copies/coercions, primitive spelling, and nested value copies
consume the allowance, and dropping a temporary does not refund it. Value depth
is capped at 64. These are conservative model-work limits, not a measured process
RSS ceiling; parser, source, mapping and transport bounds remain separate.
Exhaustion preserves unresolved calls and sets `transformations_truncated`.

Intrinsic modeling is suppressed for member updates, deletion, exposed
prototype/constructor paths, `Reflect`/`Proxy`/`Function` references and unmodeled
member calls, as well as existing property writes, shadowing and dynamic-scope
conflicts. Computed calls remain unsupported.

With the explicit, effective standard-intrinsics assumption, ordinary
expressions can reuse the closed interpreter's existing `String.fromCharCode`,
string `charCodeAt`, `charAt`, `indexOf` and literal-separator `split` model.
Only recognized, non-optional static-member shapes are admitted; aliases,
computed calls, unknown receivers/arguments, getters and coercion hooks remain
unresolved. Direct primitive results are labelled `intrinsic-call`; enclosing
concatenation or index reductions retain their own transformation family.
Intermediate split arrays are never emitted. Default mode is unchanged, and
all existing Unicode, arity, value, loop and shared allocation bounds apply.

`make deob-benchmark` runs the worker against the versioned technique corpus in
`tools/fixtures/deobfuscation-benchmark/`.
Each reviewed fixture in `corpus-v2.json` compares original and derived typed
observations in Node, requires
the expected transformation families, rejects budget truncation, and reports
wall time, rewrite count, changed-source coverage, and child peak RSS. The
fixtures are repository-owned regression programs, not captured or untrusted
malware samples.
The runner rejects manifests outside this fixture directory. It is a trusted
developer test tool, never a sandbox or a route for analyzing captured code.
Observations distinguish undefined, null, array holes and own property presence,
boolean/number types, exact binary64 finite numbers (including negative zero),
NaN and infinities. JSON string escapes preserve UTF-16 units. Fixtures can
explicitly report `completion` (normal or throw) and an ordered `effects` array;
the harness does not wrap the source or catch its exceptions. Accessors, exotic
objects, symbols, cycles and shared-object identity are unsupported observations.
The Node observer is preloaded before each fixture, capturing descriptor,
prototype, array, number-bit, serialization and output operations before the
fixture can replace them. Observation containers have null prototypes, so
inherited `toJSON` hooks cannot change the report. This preserves leading strict
directives and top-level scope. The non-enumerable `__rebObserveFixtureV2` name
is reserved for the test protocol; fixtures must not target the harness itself.
Descriptor attributes and runtime behavior beyond these authored observations
are not compared. The oracle has depth, property, string, output, time and Node
heap limits; these do not make execution of untrusted JavaScript safe.
Run `python3 tools/run-deobfuscation-benchmark.py --oracle-self-test` without a
worker to verify that deliberately wrong observations, including mutated-host
helpers, are rejected. Every
full benchmark also runs those controls. Reported source coverage is changed
original bytes, and child peak RSS includes both Node and worker processes.

## Inert source facts

The `source_facts` operation reuses this worker's preflight and Oxc parser to
return bounded lexical declarations, callable ranges and evaluation-region
facts over the exact supplied bytes. The public API binds them to a verified
immutable artifact; worker-local IDs alone are not cross-source identities.
An optional `region` narrows the work to the innermost callable body containing
that original byte range, which is how a bundle too large for the whole-program
budgets still yields facts for one callable. The range is resolved inside the
parse of the complete source; a byte slice is never parsed on its own, and
scopes holding syntax the report skipped stop resolving names instead of
guessing at them.
See [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md)
for the API/CLI, byte coordinates, budgets, unknown frontiers and deliberately
limited meaning of ordering and binding resolution. The operation does not
rewrite source, resolve values, follow imports, or execute analyzed code.

## Invocation site queries

The `invocation_site` operation finds the function a
[native JavaScript invocation site](../../protocol/native-js-invocation-v1.md)
names, for `GET /api/js-invocation-sites/resolve` and the saved-site actions.
A request carries the BOM-free script text and exactly one of `name`, a dotted
name of 1 to 8 identifiers, or `byte_offset`, a UTF-8 offset in that text. It
walks the same bounded tree-sitter preflight tree, so text in strings,
templates and comments never matches, and replies
`reb-invocation-site-worker-v1` with byte offsets and syntax facts only: for a
name, at most 32 matching definitions and 32 with the same final segment, each
with its parameter-list `(`, kind, binding text and any reason V8 would not
arm it; for a position, the innermost enclosing definition or why there is
none. The backend checks every offset against the verified artifact, computes
the site key itself and decides what to refuse.

Candidate experiments additionally submit `candidate_end_byte` with
`function_at_byte`. The strict query admits a complete literal range in a
declared-synchronous function body and adds `candidate_eligible: true` to the
function location. Ordinary queries set it false. Missing flags from older
workers refuse only this bridge. Async/generator functions, comments, templates,
accessors and parameter defaults remain unsupported; no query executes source.
See [the bridge contract](../../docs/product/candidate-experiment-v1.md).
