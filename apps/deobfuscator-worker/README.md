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

The worker is intentionally a separate process. The Python Research UI can
invoke it through a bounded subprocess adapter after the wire contract and
transform provenance have stabilized.
