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
is outside a function. The live debugger converts CDP UTF-16 columns before
querying and uses the body start to find V8's first breakable entry point.

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
error-free JavaScript trees with depth at most 128 and at most 500,000 nodes,
within one second. Excessive nesting returns a recoverable diagnostic and leaves
the next JSON-line request usable. Both grammars must support the input syntax.
Before accepting rewrites, the complete derived text passes the same bounded
preflight and Oxc parser with the original parse goal. Derived text is capped at
4 MiB plus the 512 KiB replacement budget. A failed check returns
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
See [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md)
for the API/CLI, byte coordinates, budgets, unknown frontiers and deliberately
limited meaning of ordering and binding resolution. The operation does not
rewrite source, resolve values, follow imports, or execute analyzed code.

Candidate experiments additionally submit `candidate_end_byte` with
`function_at_byte`. The strict query admits a complete literal range in a
declared-synchronous function body and adds `candidate_eligible: true` to the
function location. Ordinary queries set it false. Missing flags from older
workers refuse only this bridge. Async/generator functions, comments, templates,
accessors and parameter defaults remain unsupported; no query executes source.
See [the bridge contract](../../docs/product/candidate-experiment-v1.md).
