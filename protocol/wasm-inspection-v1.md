# WASM Inspection v1

`GET /api/wasm?artifact_id=<id>[&sections=<names>]` returns `wasm-inspection-v1`
for one captured core WebAssembly module. The identifier is a canonical nonzero
unsigned 64-bit string. The optional `sections` filter is described below. The
loopback route rejects any other query parameter, so a misspelled filter fails
instead of returning a whole-module document the caller will read as scoped. The
native `reb://app/api/wasm` route and `origin-trace-wasm --artifacts DIR
--artifact-id ID [--sections NAMES]` use the same Rust provider. The CLI prints
either the inspection document or `{error, status}`; a printed provider error is
not a successful inspection even though the process exited normally. The native
route does not implement `sections` and answers for the whole module, which
`coverage.requested_sections` reports as `null`.

The provider verifies the complete file size and SHA-256 against the manifest
before decoding. It does not execute the module, invoke imports, fetch resources,
write analysis files, or modify capture. Artifact kind and path containment use
the existing evidence-store boundary. Sensitive artifacts retain their existing
capture policy; inspection does not enable capture.

## Document

The [OpenAPI schema](openapi.json) defines `WasmInspection` and its rows. The
response includes artifact identity, SHA-256, byte size, status, decoded section,
function and instruction counts, rows, limits, omissions, section coverage, and a
notice.

Rows distinguish sections, types, imports, function declarations, exports,
tables, memories, globals, tags, start functions, defined functions, local
groups, decoded instructions, data segments, element segments, and opaque custom
sections. Function indexes include imported functions. Function headers identify
their declared type.

A `declaration` row carries the function-section entry for one function: its
index and the type index it declares. That mapping is static data in the
function section, so an export can be resolved to its declared type without
decoding a single function body. Section rows label a section with the same name
the `sections` filter uses, so a row label and the request that selects it
cannot drift apart.

All offsets are zero-based positions in the original binary. `byte_end` is an
exclusive end for sections, bodies, instructions, local groups and segments.
Metadata entries without a complete item range use a point coordinate
(`byte_end == byte_offset`). Recursive type groups share the group's start.
Section ranges describe the payload, excluding the section ID and size prefix.

Instruction text uses WASM mnemonics followed by the parser's named immediate
fields, rather than claiming to be round-trippable WAT. Branch tables preview
32 targets and show their default and a visible limit marker. Function type
lists preview 32 parameters/results. Data bytes preview the first 32 bytes as
hex. Custom data is opaque; GC layouts and constant expressions remain in the
original bytes. Names are quoted with escaped control characters, keeping each
row on one line so display text cannot shift byte-offset relationships.
These presentation limits are labeled in the text. Metadata
text is capped at 512 UTF-8 bytes plus a limit marker, with `text_truncated`.

`decoded` means an unfiltered traversal reached the module end without
unsupported sections or a traversal limit. It does not establish type validity,
runtime invocation, JS/WASM crossings, traps, memory growth, VM semantics, or
value provenance. `partial` names unvisited coverage; counts describe decoded
entries only. Malformed binary or function control structure fails with HTTP
422, preserving original bytes. Unsupported component/version encodings also
fail with 422.

## Section requests and coverage

`sections` is a comma separated list of section names: `custom`, `type`,
`import`, `function`, `table`, `memory`, `global`, `export`, `start`, `element`,
`code`, `data`, `data_count`, `tag`. Omitting it requests the whole module. An
empty value, an unknown name, a repeated parameter, or a value over 128 bytes
fails with HTTP 400 rather than widening to the whole module.

A request exists because the 8,192-row budget is shared. Code-section
instructions can consume it inside the first few dozen function bodies of a
large module, and the binary format places the data and trailing custom sections
after the code section, so an unfiltered document can never reach them. Naming
the sections that matter keeps those tables, and the export-to-type chain,
inside the same budget.

A request narrows which sections produce rows. It never narrows the traversal:
section framing, the imported-function count, the function declarations behind
every function index, and the function/code count agreement check hold exactly
as they do for an unfiltered request. Section rows are kept for every section,
including excluded ones, so a filtered document still names the bytes it did not
decode.

`coverage` declares what the document covers:

- `requested_sections` is the scope the response actually used, or `null` for
  the whole module. A caller compares it with the filter it sent; a route that
  does not implement the filter answers `null`, which must not be read as a
  filtered answer.
- `analyzed_sections` names sections present in these bytes that were requested
  and decoded to their end.
- `excluded_sections` names sections present in these bytes that the request did
  not select. Their contents were never read, so an excluded section's entries,
  function bodies and control structure stay unverified and a successful
  filtered response is not evidence that those bytes are well formed.
- `truncated_sections` names requested sections this document does not
  completely cover, because a limit stopped decoding or this version cannot
  decode them. `omissions` names which.
- `section_map_complete` is true when traversal reached the module end, so the
  three lists together name every section in these bytes and a requested section
  absent from all three is absent from the module.

A filtered document is always `partial`, even when the request happened to
exclude nothing present in these bytes, and `omissions` names the requested
sections. `defined_functions` counts the code-section bodies the traversal
enumerated; `instructions` counts decoded instructions only, so an excluded code
section reports zero instructions rather than none existing.

## Bounds and ownership

- Maximum complete input: 2 MiB. Oversized artifacts fail with HTTP 400.
- Maximum decoded rows: 8,192, shared by metadata and instructions. A section
  request spends that budget only on the sections it names.
- Maximum `sections` request: 128 bytes, every section name once.
- Maximum sections: 128; traversal also checks a two-second deadline.
- Limit exhaustion returns partial coverage without decoding the remainder.
- The backend executes on its bounded blocking reader pool. Native inspection
  uses one helper at a time, private temporary output, an 8 MiB output limit,
  and a five-second process deadline. Busy helpers return 409; unavailable
  helpers return 503. The UI imposes a ten-second request timeout.
- The UI verifies identity, bounded rows and coordinates, renders inert text,
  and caches at most four inspection documents keyed by artifact ID and hash.

The Origin Trace UI requests whole-module inspection and renders `status` and
`omissions`, so a filtered document would be shown as partial with its requested
sections named. It does not send `sections` today.

Sources opens captured WASM in Hex. Inspect switches to the derived listing;
Hex returns to original evidence. Enabled offset buttons reveal the matching
hex row when that byte was formatted. Hex formatting covers every retained byte
whose rows fit in the 8 MiB editor index. A longer module keeps a labeled
prefix, and an offset past that prefix stays disabled. Find searches the
formatted hex, not bytes left outside the index.
Inspection errors provide Retry inspection, and Hex remains available.
