# WASM Identification v1

`GET /api/wasm/identification?artifact_id=<id>[&row_offset=<n>&row_limit=<n>]`
returns `wasm-identification-v1` for one captured core WebAssembly module: which
toolchain and runtime built it, which functions are well-known glue, runtime,
allocator or library code, and where known cryptographic, checksum, encoding and
mixing constants sit. The MCP tool is `get_wasm_identification`. The native
`reb://app/api/wasm/identification` route and `origin-trace-wasm --artifacts DIR
--artifact-id ID --identification [--row-offset N --row-limit N]` use the same
Rust provider ([`wasm_identification.rs`](../apps/origin-trace-backend/src/wasm_identification.rs)
and the constant catalog in [`wasm_constants.rs`](../apps/origin-trace-backend/src/wasm_constants.rs)).
The [OpenAPI schema](openapi.json) defines `WasmIdentification`.

The provider verifies the complete file size and SHA-256 against the manifest,
as [WASM inspection](wasm-inspection-v1.md) does, then reads the module with the
same pinned `wasmparser`. It never executes the module, invokes imports, fetches
resources, writes files or modifies capture.

## What a report claims

Capture stays separate from interpretation. Every item maps back to a module byte
offset in the bytes named by `artifact_id` and `sha256`, and the raw evidence is
never changed. Three rules hold everywhere:

- **Evidence, not inference.** Each conclusion lists the exact records it rests
  on. Nothing is concluded from absence: a module without a producers section is
  unlabeled, not "not Rust", and an empty `conclusions` list says only that no
  rule matched.
- **Suggestions, not names.** Function labels are analyzer suggestions with the
  offset of the record that supports them. They are kept apart from captured
  names (the name section, exports) and from analyst names, and never replace
  either.
- **Presence, not execution.** A constant match shows that the values are in the
  bytes, not that an algorithm runs; a table can be dead data and one immediate
  can coincide with an unrelated value. An address reference is an
  `i32.const` or `i64.const` naming a matched table's start address, or a load
  whose constant offset falls inside the table, not an observed load. Any
  other immediate inside a table's range is not counted: Emscripten's data
  starts at 1024, so loop bounds and sizes land inside tables all the time.

## Document

- `status`: `complete`, or `partial` when `omissions` names a limit, a deadline
  or a malformed advisory section.
- `summary`: the labels of non-low toolchain conclusions, the labeled-function
  count, the suggestion count and the constant match counts.
- `toolchain.conclusions`: `id`, `label`, `kind` (`language`, `compiler`,
  `linker`, `runtime`, `bindings`, `system_interface`, `optimizer`),
  `confidence`, `evidence_count`, `evidence_truncated` and up to 16 `evidence`
  items. Each item is `record` (`producers`, `custom_section`, `import`,
  `export`, `name`), `byte_offset`, a bounded `detail`, `function_index` when the
  record names a function, and its own `confidence`.
- `toolchain.producers`, `target_features`, `source_mapping_url`,
  `external_debug_info`, `custom_sections` and `name_section`: the stored facts
  those sections hold, each with its offset.
- `functions`: `imported_functions`, `defined_functions`, `labeled_functions`,
  and `suggestions` as compact rows named by `suggestion_fields`:
  `[function_index, label, category, library, confidence, record, byte_offset]`.
  Function indexes include imported functions.
- `constants.matches`: `id`, `label`, `family`, `location` (`data` or
  `immediate`), `match` (`complete` or `partial`), `matched` and `total`
  elements, `byte_offset` and `byte_end`. A match is complete only when every
  element matched: 255 of 256 is partial. A data match adds `data_segment` and
  `data_segments` (every segment it spans), `encoding`, `runs`,
  `memory_address` (null when the segment's offset is not a constant),
  `referenced_by` (`function_index`, `byte_offset`, `via` `address_immediate`
  or `load_offset`), `reference_count` and `hex`. An immediate match adds
  `function_index` and `sites` (`byte_offset`, `operator`, where
  `i32.const pair` is two adjacent halves of one 64-bit element).
- `coverage`: data segments and bytes, bytes scanned, whether the data scan
  finished, function bodies and immediates scanned.

### Confidence

Confidence is categorical. `high` rests on a declaration or a marker one
toolchain owns: a producers entry, `go:buildid`, a `wbg` import, a
`__wbindgen_` export, a `wasi_snapshot_preview1` import, a hashed Rust symbol.
`medium` rests on a distinctive naming convention another toolchain could also
follow, such as `malloc`, `invoke_*` or `__heap_base`. `low` rests on a name a
toolchain shares with ordinary code, such as `env.abort` or an algorithm word in
a function name. A conclusion's confidence is its strongest single item; more
items of the same strength do not raise it. The summary omits `low` conclusions.

### Constants

Sets come from their definitions: SHA-1, SHA-224/256/384/512 initial values and
round constants, the MD5 sine table and initial state, the AES S-box, inverse
S-box and Te0..Te3/Td0..Td3 tables, CRC-32, CRC-32C and MSB-first CRC-32 tables
and polynomials, the ChaCha and Salsa20 constants, Base64, URL-safe Base64,
Base32 and alphanumeric alphabets, and the FNV, MurmurHash3, xxHash, SipHash,
PCG, xorshift64*, SplitMix64, golden-ratio and MT19937 magic values. Labels name
every algorithm sharing a set (the SHA-256 initial value is also the BLAKE2s IV).
The SHA-2 tables are copied from the pinned `sha2` crate and the backend tests
recompute digests with them; the MD5, CRC and AES tables are checked against
known vectors.

Data segments are scanned for runs of consecutive set elements as bytes, 32-bit
words in either byte order, and 64-bit words in either order or as two 32-bit
little-endian halves, high half first. A run starts only at a distinctive
element and needs a set-specific minimum length; runs of one set that continue
the table form one match. Immediates are `i32.const`, `i64.const` (also against
32-bit sets, since Go keeps 32-bit values in i64), and `f32.const`, `f64.const`
and `v128.const` lanes by their bits. Two adjacent `i32.const` values, high or
low half first, that spell one 64-bit element count for the 64-bit set, so a
32-bit SHA-512 implementation is SHA-512 rather than a partial SHA-256. A
function matches a set when it holds a set-specific number of distinct
elements. A table split across segments whose memory addresses touch, as
Binaryen's memory packing leaves it, is one match when the second part
continues the table where the first stopped. A match another match fully explains
is dropped: four MD5 words inside a five-word SHA-1 state, the alphanumeric
alphabet inside a complete Base64 alphabet.

## Bounds and errors

- Maximum input: 64 MiB, the block graph's budget. Larger artifacts fail with
  HTTP 400.
- One four-second deadline for the whole report, inside the native helper's
  five-second process deadline. Reading sections, labeling, the data scan,
  clustering, merging, suppression and the immediate scan all poll it, and
  `omissions` names the phase and how far it got.
- Records are kept up to 65,536 of each kind (imports, exports, names, data
  segments, custom sections) and counted past that; `function_names` and the
  function counts stay exact for what was read. At most 8,192 data runs and
  512 candidate matches are kept before merging; the rest are counted. Merging
  and suppression are each one pass over sorted matches.
- At most 32 conclusions of 8 evidence items, 16 producers, 32 target
  features, 32 custom sections, 4 suggestions per function (each label once),
  16,384 suggestions, 64 constant matches (complete and larger first), and 4
  references and 4 sites per match. Every cap reports a count and an omission
  or `*_truncated` flag.
- One page pretty-printed is at most 126,000 bytes, inside the 131,072-byte
  MCP inline limit, which reb-api mcp applies to both the compact and the
  pretty-printed text. Everything but the suggestions is held to 96,000 bytes,
  with
  fewer evidence items, listed sections and references when it would not fit
  (an omission says so); suggestion rows fill the rest of the page.
- Captured text in labels and details is escaped, single-line and at most 96
  bytes, so a read-only MCP result, which omits strings over 160 characters,
  keeps every label. URLs are at most 512 bytes.
- `row_offset` and `row_limit` page `functions.suggestions` only, at most 1024
  rows and the page byte budget; `suggestion_window.next_offset` continues.
  Toolchain and constants are whole on every page. Another query parameter, an
  offset past the suggestions or a limit outside 1 to 1024 fails with HTTP 400.
- A non-Wasm artifact fails with 400, a missing one with 404, an integrity
  failure with 500. An empty, malformed or non-core module fails with 422 and a
  named reason. A malformed name, producers or target_features section is
  advisory: the report stays usable and `omissions` names it.
- A legacy-mangled name counts as Rust only when it ends at its `E` with a
  `17h<hash>` segment. An Itanium C++ name such as `_ZN4core6Engine4stepEv`
  carries parameter types after the `E` and names no Rust crate.

## Content and permission levels

The report is structure: identifiers, counts, offsets, bounded names and
labels. It is readable at every `reb-api mcp --permission` level. The only
captured content is `hex` on a data match, up to 64 matched bytes, which
`--omit-content` (read-only, ask and auto) removes. Full access returns it; the
bytes beyond a match are read with `get_artifact_text encoding=hex`.

## Interface

Sources shows the summary above the Inspect listing: a toolchain line, constant
matches and the labeled-function count. Each chip reveals its evidence byte in
the listing or hex view. **Details** lists every conclusion's evidence, each
match's referencing functions and the first 200 suggestions. The Graph's
**Functions** menu badges each suggested function with its category, and its
filter matches the labels; badges come from a map built once per report. The UI
requests a report only when Inspect or Graph is opened, verifies its identity
against the selected bytes, renders inert text, keeps the last report on a
failed retry, and caches at most four reports; returning to an evicted one reads
it again. `tools/check-wasm-identification-ui.mjs` checks these states offline.
