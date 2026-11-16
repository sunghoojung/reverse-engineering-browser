# WASM Laboratory: library identification v1

Most of a captured module is compiler runtime, libc, an allocator or language
standard library code. Disassembler suites answer "which part is custom?" with
function ID databases, signature matching and constant finders; Origin Trace now
gives a researcher and an agent the evidence-based part of that answer for Wasm.

One static report per module, `get_wasm_identification`, says:

- **Toolchain and runtime.** Rust, C or C++, clang, LLVM wasm-ld, Emscripten,
  wasm-bindgen, WASI, wasi-libc, Go, TinyGo, AssemblyScript, .NET, Kotlin/Wasm,
  Dart, Swift, Zig, Binaryen and component tooling, each with a confidence and
  the producers entries, custom sections, imports, exports and names it rests on.
- **Well-known functions.** Suggested labels such as `JS glue: fetch` for a
  wasm-bindgen import, `WASI fd_write`, `wasm-bindgen allocator: malloc` or
  `Rust core library`, each citing the record that supports it.
- **Crypto and encoding constants.** SHA-1/SHA-2, MD5, AES, ChaCha, CRC-32,
  Base64 and hash and PRNG magic values in data segments or constant immediates,
  each complete or partial with its matched count, and the functions whose
  immediates name a matched table's address.

In Sources, **Inspect** shows the summary above the listing, and every chip opens
the byte it rests on. The Graph's **Functions** menu badges labeled functions.

Identification never executes the module and never concludes from absence. Its
labels are suggestions kept apart from captured names and from researcher names,
and a constant match shows presence, not that an algorithm runs. Bounds, the
evidence and confidence rules and the permission levels are in the
[versioned contract](../../protocol/wasm-identification-v1.md).

Not included: body-hash signature matching across modules (planned with module
diffing), analyst names for functions, and any claim drawn from execution.
