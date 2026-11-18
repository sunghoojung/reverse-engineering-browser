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

A request record is as long as the source it carries; there is no request,
source or rewrite cap. At most 64 syntax diagnostics of a source Oxc rejects are
returned. `transformations_truncated` reports that some expression ran out of
its own evaluation allowance below; the rest of the source is still folded.

Each request is exactly one operation. Untagged records are deobfuscation
(`source`, optional `assume_intrinsics`) or, when they carry
`function_at_byte`, the function lookup (`source`, `function_at_byte`,
optional `candidate_end_byte`); `source_facts`, `invocation_site` and
`request_field` are named by `operation`. Unknown operations and unknown fields
are refused with `error_kind: "invalid-request"`, and every other refusal names
its kind too. See [the response contract](../../protocol/deobfuscation-v1.md).

No source is refused for its size, nesting or node count. Oxc's parser and the
passes over its tree recurse on the native stack, so before parsing the worker
measures the source's lexical nesting with `reb-js-lexer`, a parser-free token
pass that never recurses, and runs the request on a stack of 32 MiB plus 16 KiB
per nesting level. The stack is mapped rather than committed, so only the depth
a pass reaches costs memory. Real bundles nest 150 to 200 levels; a 196,608-deep
sequence expression is parsed and analyzed. Both grammars must support the
input syntax; malformed syntax is the only refusal.

The `function_at_byte` and candidate queries and `invocation_site` read a
Tree-sitter tree. Tree-sitter builds it on the heap and every walk uses a cursor
or parent links, so neither the parse nor a query recurses, and a tree with an
error node is refused rather than queried.

Before accepting rewrites, the complete derived text passes the same Oxc parser
with the original parse goal. Replacement text may grow the source to at most
eight times its size, which a proportional rewrite never approaches; past that
the remaining calls are preserved and `transformations_truncated` is set. A
derived text Oxc rejects returns `error_kind: "derived-validation"`, preserves
the original text, and discards all rewrite receipts. This establishes syntax
acceptance, not semantic equivalence.
Object shorthand properties retain their original spelling and are not folded.

Each top-level evaluation (a constant initializer, a branch test, an
expression, one decoder table element) starts with its own allowance: 250,000
interpreter steps, 8 MiB of allocation work and 250,000 value nodes, including
the closed decoder calls it makes. A whole bundle therefore folds as far as any
one of its expressions can, instead of stopping once a file-wide budget is
spent. Owned arrays cache their full clone cost and depth; copies reserve the
complete cost before allocation and have no unrestricted `Clone` implementation.
Array slots, string copies/coercions, primitive spelling, and nested value copies
consume the allowance, and dropping a temporary does not refund it. Value and
expression depth are capped at 64 and an inline replacement at 16 KiB. These
bound one modeled expression, never which sources or how many expressions are
analyzed. Exhaustion preserves that expression's unresolved call and sets
`transformations_truncated`.

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

The `source_facts` operation reuses this worker's Oxc parser to return every
lexical declaration, callable range, evaluation region and operation of the
exact supplied bytes, with no fact, node or frontier budget. It writes each row
as compact JSON straight to stdout, so a whole-bundle report is never built as
a second JSON tree. The public API binds the report to a verified immutable
artifact; worker-local IDs alone are not cross-source identities. An optional
`region` narrows the work to the innermost callable body containing that
original byte range. The range is resolved inside the parse of the complete
source; a byte slice is never parsed on its own, and scopes holding syntax the
report skipped stop resolving names instead of guessing at them.
See [JavaScript source facts v2](../../protocol/javascript-source-facts-v2.md)
for the API/CLI, byte coordinates, row pages, unknown frontiers and deliberately
limited meaning of ordering and binding resolution. The operation does not
rewrite source, resolve values, follow imports, or execute analyzed code.

## Invocation site queries

The `invocation_site` operation finds the function a
[native JavaScript invocation site](../../protocol/native-js-invocation-v1.md)
names, for `GET /api/js-invocation-sites/resolve` and the saved-site actions.
A request carries the BOM-free script text and exactly one of `name`, a dotted
name of 1 to 8 identifiers, or `byte_offset`, a UTF-8 offset in that text. It
walks the same Tree-sitter syntax tree, so text in strings,
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
