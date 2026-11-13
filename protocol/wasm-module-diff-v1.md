# WASM module diff v1

`GET /api/wasm/diff?artifact_id=<A>&compare_artifact_id=<B>` returns
`wasm-module-diff-v1`: a match table between the functions of two captured core
WebAssembly modules, for example two builds of one site's module. A is the
version the analyst already understands and B is the one to carry that
understanding to. Both identifiers are canonical nonzero unsigned 64-bit
strings naming two different `wasm` artifacts in this backend's artifact store;
they may come from the same session or from different sessions in that store.
The MCP and `reb-api` operation is `get_wasm_module_diff`. The native
`reb://app/api/wasm/diff` route and
`origin-trace-wasm --artifacts DIR --artifact-id A --diff-with B` use the same
Rust provider. The CLI prints the document or `{error, status}`.

The provider verifies each module's complete size and SHA-256 against the
manifest before decoding, using the same `wasmparser` decoder as
[WASM inspection](wasm-inspection-v1.md). It never executes either module,
invokes an import, fetches anything, writes analysis files, or modifies capture.
Original bytes are never changed: every derived row maps back to a body range
in its module, and the module's SHA-256.

## Function identity

A function is identified by its module's SHA-256 and its function index, which
counts imported functions first, as everywhere else in Origin Trace. The
document names `a.sha256` and `b.sha256` once, and each row side carries its
`function` index. An analyst name, a note or a label attached to
`(a.sha256, function)` can be carried to `(b.sha256, function)` through a
matched row without relying on artifact IDs, which differ between stores.

## Fingerprints

`fingerprint_version` is 1. Any change to a rule below, to the opcode classes,
to the similarity weights, or to the decoder spelling a fingerprint reads bumps
it, and fingerprints of different versions are never compared.

**Body hash** (internal, used for the `identical` method): the first 16 bytes
of SHA-256 over the body's exact bytes, locals included.

**Normalized body hash** (`normalized`, 16 hex digits): the first 8 bytes of a
SHA-256 over the declared signature, the multiset of declared local types
(group order ignored), and every instruction in order. Each instruction
contributes its original encoded bytes, except:

| Instruction | What is hashed instead | What is ignored |
| --- | --- | --- |
| `call`, `return_call`, `ref.func` | the callee's signature | the function index |
| `call_indirect`, `return_call_indirect` | the type's signature and the table index | the type index |
| `call_ref`, `return_call_ref` | the type's signature | the type index |
| `block`, `loop`, `if`, `try`, `try_table` | the block type, with a type index replaced by its signature | the type index |
| `local.get`, `local.set`, `local.tee` | parameters by index; other locals by order of first use, with the local's type | how non-parameter locals are numbered |
| `global.get`, `global.set` | order of first use in this function, with the global's type and mutability | the global index |
| `i32.const`, `i64.const` whose value is an address in the static data span | a marker | the value |
| loads, stores and atomics whose memory offset is an address in the static data span | the opcode, alignment and memory index | the offset |

The static data span runs from the lowest to the highest end of the active
data segments of memory 0 whose offset is a constant. A value is an address
when it lies in that span and is at least 1,024: small integers are far more
often counts and flags than addresses, and common toolchains place static data
at or above 1,024. Because the rule is a range test, a genuine constant that
happens to fall inside the span is normalized too, which only makes the hash
coarser. Every other immediate, including other constants, branch depths,
memory and table indexes, lanes, and GC type immediates, is kept as encoded.
Two functions with the same normalized hash differ at most in renumbering and
relocation; the row status is then `renumbered`.

**Structural fingerprint** (`structure`, 16 hex digits): the first 8 bytes of a
SHA-256 over the signature, a hash of the control skeleton (the sequence of
`block`, `loop`, `if`, `else`, `end`, branch, `return`, `unreachable`, `try`,
`catch` and throw instructions), the log2 bucket of the count in each of 17
opcode classes (structure, branch, direct call, indirect call, local, global,
load, store, constant, integer arithmetic, float arithmetic, compare,
conversion, SIMD, atomic, memory, table and reference, other), and the exact
direct call-site and distinct-callee counts. It ignores every immediate,
operand order within a class, and counts within one power of two.

**Similarity score** (0 to 1), for the structural pass and propagated matches:
0.45 x histogram overlap (sum of minimums over sum of maximums of the 17 class
counts) + 0.15 x instruction-count ratio + 0.2 x the mean ratio of block, loop
and branch counts + 0.1 x the mean ratio of call-site and distinct-callee
counts + 0.1 if the control skeletons are identical. A ratio is the smaller
count over the larger, and 1 when both are zero.

## Matching

Passes run in this order and each considers only functions no earlier pass
matched. A key shared by exactly one open function on each side is a match;
a key shared by more is a tie and is left for later passes.

1. `import_name`: imports by module and field name.
2. `identical`: defined functions by body hash.
3. `normalized`: defined functions by normalized body hash.
4. `export_name`, then `name`: defined functions by first export name, then by
   name-section name.
5. `call_graph`: from each matched pair, the k-th call sites of two bodies with
   the same number of call sites propose their callees as a pair, and a pair
   with exactly one open callee, or one open caller, on each side proposes
   that pair. A proposal needs equal signatures and a similarity of at least
   0.5. A function proposed for two partners stays open. Rounds repeat, at
   most 16, while they add matches.

Passes 1 to 5 repeat until none adds a match. Then:

6. `structural`: open defined functions that share no exact key with another
   open function are scored against up to 64 open functions of the other side
   with the same signature and the nearest instruction counts. A pair is
   matched only when each is the other's best, the score is at least 0.75, and
   both beat every runner-up by at least 0.01. Candidates within 0.01 of the
   best form an `ambiguous` row.

Passes 1 to 5 then run once more to carry the structural matches along the
call graph. Finally, functions still tied by body hash or normalized hash form
`ambiguous` rows with score 1. A tie is never resolved by index order or any
other forced pick.

## Document

The [OpenAPI schema](openapi.json) defines `WasmModuleDiff`,
`WasmModuleDiffRow` and `WasmModuleDiffFunction`.

- `a` and `b` give each module's `artifact_id`, `sha256`, `session_id`,
  `byte_size`, `imported_functions`, `defined_functions` and
  `analyzed_functions`.
- `summary` counts every row by status and every matched row by method,
  whatever page or `status` filter was requested, and reports the number of
  similarity comparisons and the elapsed time.
- Each row has `status`, `method` and `score` (both null for an unmatched
  function), and `a` and `b` sides (null on the side a function is missing
  from). A side gives `function`, `byte_offset` and `byte_end` (the body range;
  equal for an import, at its import entry), `name` (name section, else first
  export, escaped single-line text of at most 128 bytes), `import` (module and
  field) or null, `type` (the declared signature), `instructions`, and the
  `normalized` and `structure` fingerprints (null for an import).
- An `ambiguous` row has null sides and `candidates` with up to 16 functions
  per side and `truncated`.

Statuses, in page order:

| Status | Meaning |
| --- | --- |
| `changed` | Matched; the normalized hashes differ, or an import's signature changed. |
| `added` | Only in B. |
| `removed` | Only in A. |
| `ambiguous` | Tied candidates; no pair was chosen. |
| `unclassified` | Unmatched when a limit or the deadline stopped the comparison, so it may not really be added or removed. |
| `renumbered` | Matched; bytes differ but the normalized hashes are equal. |
| `identical` | Matched; the body bytes, or an import's name and signature, are equal. |

Rows are ordered by status, then function index. `status` narrows the rows to
a comma separated list of these names; an unknown or repeated name fails with
400. `row_offset` and `row_limit` (1 to 1,000, default 200) page them, and a
page also stops at 98,304 bytes of serialized rows so it fits a 128 KiB MCP
result. `row_window` gives `offset`, `rows`, `total_rows` and `next_offset`,
null at the end. `requested_statuses` echoes the filter, or null.

The report holds no instruction text, constant value, data byte or custom
section content, so it is structure at every permission level. Function,
import and export names are returned as in `get_wasm_functions`.

## Bounds and errors

- Maximum module input: 64 MiB each, the block graph's limit.
- Maximum functions per module: 262,144, imports included. A larger module is
  compared on that prefix and named in `omissions`.
- A body over 7,654,321 bytes or a function with more than 50,000 locals is
  rejected as malformed, since web engines reject both.
- Structural comparisons: 4,000,000 in all and 64 per function.
- One four-second deadline covers fingerprinting and matching, below the
  native helper's five-second process limit.
- When a limit or the deadline stops the work, `status` is `partial`,
  `omissions` names the step, and every function left unmatched is
  `unclassified` instead of `added` or `removed`.
- The two most recent reports stay in memory, keyed by both artifact IDs and
  SHA-256 digests, so paging a pair does not repeat the comparison.

Errors use the shared `Error` body: 400 for a malformed or repeated parameter,
the same artifact twice, a non-WebAssembly artifact or an oversized module; 404
for a missing artifact; 422 for an empty or malformed module, an unsupported
version or component encoding, or disagreeing function and code counts; 500
for an integrity failure. A module that declares no functions is valid: its
other side is entirely added or removed, and `omissions` says so.

## Library signatures

The fingerprints are meant to become library signatures later. A signature
entry is `(fingerprint_version, signature hash, normalized hash)` with a
label, and the structural fingerprint as a weaker fallback key. Matching a
module against a signature set is the `normalized` pass followed by the
`structural` pass with the set as side A: a normalized hash held by more than
one labeled entry is a tie, reported as ambiguous rather than picked. Because
the normalized hash already ignores call targets, globals and static data
addresses, a function from one library build keeps its hash in another
program that links it at different indexes and addresses, as long as its own
body and inlining are unchanged. Toolchain and crypto-constant identification
is a separate analysis and is not part of this contract.
