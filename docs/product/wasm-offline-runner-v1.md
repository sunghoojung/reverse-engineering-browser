# WASM Laboratory: offline function runs v1

A researcher or agent who suspects that one function of a captured module is
SHA-256, or decodes a payload, can now run that function on chosen inputs and
compare the result with test vectors, without the page, the network or the
browser. In Sources, **More > Run offline…** on a captured Wasm module opens the
dialog; agents call `run_wasm_function` through `reb-api mcp`.

What runs, and what cannot happen:

- One exported or indexed function, on an explicit request that confirms it.
  Nothing runs automatically or from an analysis.
- The `wasmi` interpreter (pure Rust, fuel metering, no JIT) inside the local
  backend. Every import is a stub that returns only values the request supplies,
  or traps, and every call it receives is recorded. Memory, tables and globals
  the module imports are fresh and empty.
- Fuel, memory pages, table elements, call depth and a wall-clock deadline bound
  each run. Each limit, each trap and an import called without a stub is its
  own named outcome. The start function runs only when asked.
- Memory can be written before the call and read after it, within 256 KiB each.
  Expected results and memory bytes are compared exactly, so a caller without
  content access still learns whether its vectors matched.
- The captured bytes are verified by SHA-256 and never changed. A run is stored
  as a derived experiment record with the module hash, function, inputs digest,
  interpreter version and limits.

Return values, import arguments and memory bytes are content: an agent receives
them only at Full access. The contract, limits and outcomes are in
[WASM run v1](../../protocol/wasm-run-v1.md), and the policy in
[SAFETY](../../SAFETY.md#observation-and-experiments).

Not covered: running a function inside the page or the browser, calling real
host imports, emulating JavaScript glue code, or reporting a trap's byte offset
(the interpreter does not expose one). A result describes the tested inputs
only; the interpreter can differ from a browser engine in NaN bit patterns and
in resource exhaustion.
