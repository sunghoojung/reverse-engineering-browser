# REB Rust deobfuscation worker

This is the bounded Rust worker boundary for JavaScript deobfuscation. It
accepts one JSON request per line on stdin and emits one JSON response per line
on stdout. It never executes the analyzed JavaScript.

The first production slice uses Oxc for JavaScript parsing and performs only
finite numeric constant folding. It returns the rewritten source, the exact
original byte range for every rewrite, statement/comment evidence, and
recoverable syntax diagnostics. Sparse arrays, dynamic expressions, calls, and
non-finite arithmetic remain unchanged.

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

The browser development server continues to use the Python lexical formatter;
the response identifies its engine. The Rust slice does not classify obfuscation
or recover string tables. Those omissions are explicit, not zero-confidence
claims about the input.

Requests are read with bounded buffers. An oversized record is drained through
the next newline, rejected, and flushed before reading another record. The
request cap allows JSON escaping of a 4 MiB source. At most 4,096 rewrites and
64 syntax diagnostics are retained. Further rewrites set
`transformations_truncated`; the remaining source is preserved unchanged.

See [the response contract](../../protocol/deobfuscation-v1.md).
