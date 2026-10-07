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

`make deob-benchmark` runs the worker against the versioned technique corpus in
`tools/fixtures/deobfuscation-benchmark/`.
Each case compares the original and derived observable result in Node, requires
the expected transformation families, rejects budget truncation, and reports
wall time, rewrite count, changed-source coverage, and child peak RSS. The
fixtures are repository-owned regression programs, not captured or untrusted
malware samples.

## Inert source facts

The `source_facts` operation reuses this worker's preflight and Oxc parser to
return bounded lexical declarations, callable ranges and evaluation-region
facts over the exact supplied bytes. The public API binds them to a verified
immutable artifact; worker-local IDs alone are not cross-source identities.
See [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md)
for the API/CLI, byte coordinates, budgets, unknown frontiers and deliberately
limited meaning of ordering and binding resolution. The operation does not
rewrite source, resolve values, follow imports, or execute analyzed code.
