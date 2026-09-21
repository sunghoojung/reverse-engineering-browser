# REB Rust deobfuscation worker

This is the bounded Rust worker boundary for JavaScript deobfuscation. It
accepts one JSON request per line on stdin and emits one JSON response per line
on stdout. It never executes the analyzed JavaScript.

The production pipeline parses JavaScript with Oxc and performs bounded static
primitive folding, constant propagation, string normalization and literal-index
recovery, member normalization, and conservative dead-expression/branch removal.
It returns original byte ranges for every rewrite and recoverable diagnostics.
See the [method coverage and limitations](../../docs/product/deobfuscation-method-coverage.md)
for the precise supported subsets and regression evidence.

## Run

```sh
cargo test --manifest-path apps/deobfuscator-worker/Cargo.toml
cargo run --manifest-path apps/deobfuscator-worker/Cargo.toml
```

Example request:

```json
{"source":"const value = 1 + 2 * 3;"}
```

The worker is a separate process bundled as `OriginTraceDeobfuscator` in the
native macOS app. `DeobfuscationService.swift` invokes it with a five-second
wall-clock deadline and projects its original UTF-8 byte ranges into the shared
UI response. It reads only the selected captured JavaScript artifact.

The browser development server uses this worker when available, with an explicitly
labelled Python lexical fallback when it is not built. Rust does not classify
obfuscation. Dynamic decoders and prototype-dependent evaluation stay unresolved.

Requests are read with bounded buffers. An oversized record is drained through
the next newline, rejected, and flushed before reading another record. The
request cap allows JSON escaping of a 4 MiB source. At most 4,096 rewrites and
64 syntax diagnostics are retained. Further rewrites set
`transformations_truncated`; the remaining source is preserved unchanged.

See [the response contract](../../protocol/deobfuscation-v1.md).
