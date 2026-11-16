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
at or above 1,024. Every other immediate, including other constants, branch
depths, memory and table indexes, lanes, and GC type immediates, is kept as
encoded.

The normalized hash is deliberately coarse, because it is a matching key.
Bodies with equal normalized hashes can still differ in three ways it cannot
see:

- a constant inside the data span, whether or not it is used as an address;
- which function of the same signature a call or `ref.func` reaches, or the
  order of calls to functions of one signature;
- which global of the same type is read or written.

The row status (below) checks the first two. The third is a known limit.

**Address map** (internal, used for the status): for each address the
normalized hash replaced, in order, the data segment it falls in (by start
order) and its offset in that segment. A relocation that moves segments keeps
the map; a different constant changes it. The map compares positions, not the
bytes stored there: data inserted inside a segment moves every later offset
in it, so a function reading past the insertion point is `changed` even when
it reads the same bytes, and a function reading a segment whose bytes changed
can still be `identical`. Keying on the stored bytes instead would call a
changed constant into a zero-filled or repeating region relocated, so the map
errs toward `changed`.

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
matched or grouped. A key shared by exactly one open function on each side is
a match; a key shared by more is a tie and is left for later passes.

1. `import_name`: imports by module, field, signature and position among the
   imports sharing those, then by module, field and position among the imports
   sharing the names, so a changed signature still pairs and an import name
   used twice pairs each use.
2. `identical`: defined functions by signature and body hash, but only bodies
   that name nothing by an index that can renumber: no call, function
   reference, global, table, element, data segment, tag, GC type or
   type-indexed block, and no static data address. Equal bytes elsewhere can
   mean a different function: after a function is inserted early, A's
   `call 1` thunk has the bytes of B's `call 1` thunk, which calls what was A's
   function 0. The signature is part of the key because the bytes do not
   carry it: `local.get 0` is the same bytes over an `i32` and an `i64`.
3. `normalized`: defined functions by normalized body hash together with the
   address map, then by normalized body hash alone, so readers of moved data
   pair with the reader of the same offset.
4. `export_name`, then `name`: defined functions by first export name, then by
   name-section name.
5. `call_graph`: rounds starting from every matched pair. For each pair in a
   round:
   - when the two bodies normalize equally and have the same number of call
     sites, the k-th call sites sit at corresponding places, so their callees
     are proposed, each distinct pair of targets once however many call sites
     repeat it, but only when neither callee has another open callee of the
     pair that looks more like it;
   - the open callees, and separately the open callers, of the pair are
     compared with each other, and a pair that is each other's best
     same-signature candidate by at least 0.01 is proposed;
   - a proposal needs a similarity of at least 0.5;
   - a pair with more than 64 open callees or callers on either side proposes
     nothing from that set, so one function called from everywhere cannot make
     the work quadratic.

   Scores come from one matrix per pair and set, used by both checks, and
   each is computed once per comparison. After every pair in the round has
   proposed, a function proposed for exactly one partner, by every proposer,
   is paired; one proposed for two or more partners forms a `call_graph` tie
   with them. Which pair was visited first never decides a contested
   function. A round the budget stops accepts nothing. The next round looks
   at the new pairs and the matched pairs next to them.

Passes 1 to 5 repeat while propagation adds matches, at most four rounds.
Then:

6. `structural`: open defined functions that share no exact key with another
   open function are scored against the open functions of the other side with
   the same signature and the nearest instruction counts: up to 64, or fewer
   when the comparisons left, divided by every function on both sides that
   could be scored, cannot pay for 64; below 4 the pass is not run. Each A
   function keeps the candidates within 0.01 of its best score. Every open B
   function also scores its own nearest A candidates, so a function outside
   an A function's window, even one an unrelated A function happened to
   score, is not reported as added only for that reason: if it ties an A
   function's own best within 0.01 without being among that function's best
   candidates already, it contests that function. Then:
   - every tie is joined into a group first: a function with more than one such
     candidate, a candidate that more than one function ranks best within
     0.01, and a contesting B function together with the contested function
     and its own best candidates join that group;
   - a pair is then accepted only when its score is at least 0.75, neither side
     is in a group, and the B candidate's best claimant beats every other
     claimant by at least 0.01;
   - a pass the budget stops accepts no pair and forms no group, because
     mutual best is only meaningful once every candidate was scored.

Passes 1 to 5 run once more from the structural matches. Finally, functions
still tied by body hash or normalized hash form groups. When both modules'
type, import, function, table, memory, global, element, data, data count and
tag sections are byte-equal, every index a body names means the same item on
both sides except call and `ref.func` targets, which the status checks; then
a tie member whose signature, body hash and address map no other member on
either side shares is first paired, by the `identical` method, with the one
member on the other side that has them. So a module compared with itself is
all `identical` even when many of its functions normalize alike. A tie is
never resolved by index order or any other forced pick, and every step iterates in
a fixed order, so the same pair of modules gives the same table every time,
page after page.

## Document

The [OpenAPI schema](openapi.json) defines `WasmModuleDiff`,
`WasmModuleDiffRow` and `WasmModuleDiffFunction`.

- `a` and `b` give each module's `artifact_id`, `sha256`, `session_id`,
  `byte_size`, `imported_functions`, `defined_functions` and
  `analyzed_functions`.
- `summary` counts every row by status and every matched row by method,
  whatever page or `status` filter was requested. It also gives
  `ambiguous_groups`, the number of similarity scores computed, and the
  elapsed time.
- Each row has a `status`. A matched row also has `method` and `score`, and an
  ambiguous row has its tie's `method` and `score`; both are null otherwise.
  Its `a` and `b` sides are null on the side a function is missing from.
- A side gives:
  - `function`;
  - `byte_offset` and `byte_end`: the body range, or both at the import
    entry for an import;
  - `name`: the name section, else the first export, as escaped single-line
    text of at most 128 bytes;
  - `import`: module and field, or null;
  - `type`: the declared signature;
  - `instructions`;
  - the `normalized` and `structure` fingerprints, null for an import.
- Each member of a tie is its own `ambiguous` row with one side set and
  `group` (`id`, and how many functions of A and of B tie), so paging reaches
  every member of a large tie.

Statuses, in page order:

| Status | Meaning |
| --- | --- |
| `changed` | Matched; the bodies differ in more than renumbering and relocation as this contract can tell, or an import's names or signature changed. |
| `added` | Only in B. |
| `removed` | Only in A. |
| `ambiguous` | A member of a tie; no pair was chosen. |
| `unclassified` | Unmatched when a limit or the deadline stopped the comparison, so it may not really be added, removed or tied. |
| `renumbered` | Matched; the bytes differ, but the normalized hashes and the address maps are equal, and every call site and `ref.func` names the matched function on the other side. |
| `identical` | Matched; the body bytes, the normalized hashes and the address maps are equal, and every call site and `ref.func` names the matched function on the other side, or an import's names and signature are equal. The normalized hash makes the signature, each global's type and each named type's signature part of the check. Two globals of the same type are still not told apart, and the address map compares positions, not stored bytes. |

Rows are ordered by status, then by tie, then by function index. `status`
narrows the rows to a comma separated list of these names; an unknown or
repeated name fails with 400. `row_offset` and `row_limit` (1 to 1,000,
default 200) page them. A page also stops before the whole document,
pretty-printed as the MCP server measures its inline limit, passes 122,880
bytes, so a page of long mangled names still fits the 131,072-byte limit.
Continue from `row_window.next_offset`, which is null at the end; a page can
hold fewer rows than `row_limit`. `row_window` also gives `offset`, `rows` and
`total_rows`. `requested_statuses` echoes the filter, or null.

Only a complete report pages reliably. A partial report is not kept, so each
page is a new comparison that can stop at a different point, and since rows
are ordered by status a later page can repeat or skip rows of an earlier one.
Every partial report says so in `omissions`; retry for a complete report
before paging.

The report holds no instruction text, constant value, data byte or custom
section content, so it is structure at every permission level. Function,
import and export names are returned as in `get_wasm_functions`.

## Bounds and errors

- Maximum module input: 64 MiB each, the block graph's limit.
- Maximum functions per module: 262,144, imports included. A larger module is
  compared on that prefix and named in `omissions`; imports past it are
  counted, not kept.
- A body over 7,654,321 bytes or a function with more than 50,000 locals is
  rejected as malformed, since web engines reject both.
- Similarity scores: 4,000,000 in all, across propagation and the structural
  pass, and at most 64 per function in the structural pass.
- One four-second deadline covers the request, below the native helper's
  five-second process limit. It counts from when the request arrived, before
  it waited for a reader, so reading and verifying both modules count too. It
  is checked every 4,096 section entries while parsing, before each body,
  every 4,096 instructions inside one, before each exact pass, at each
  propagation step and before each structural candidate set. A parse it
  stops says the module's function count is unknown. Global and local
  first-use numbering use tables indexed by number, so no body costs more
  than linear work between two checks.
- When a limit or the deadline stops a step:
  - `status` is `partial`;
  - `omissions` names the step and why it stopped, and how many of each
    module's functions were fingerprinted;
  - every function left unmatched is `unclassified` instead of `added`,
    `removed` or `ambiguous`;
  - matches made before the stop stand.
- The loopback backend keeps the two most recent complete reports in memory,
  keyed by the store and both artifact IDs and SHA-256 digests, so paging a
  pair does not repeat the comparison. A partial report is not kept, so a
  retry makes a fresh attempt. The native `reb://` route starts a new helper process for each
  page and filter, so each of its pages repeats the comparison inside the
  same bound.

Errors use the shared `Error` body:

| Status | When |
| --- | --- |
| 400 | a malformed or repeated parameter, the same artifact twice, a non-WebAssembly artifact, or an oversized module |
| 404 | a missing artifact |
| 422 | an empty or malformed module, an unsupported version or component encoding, or disagreeing function and code counts |
| 500 | an integrity failure |

A module that declares no functions is valid: its other side is entirely
added or removed, and `omissions` says so. That note does not make the
report partial: `status` is `partial` only when something was left
uncompared.

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
