# WASM Inspection v1

`GET /api/wasm?artifact_id=<id>` returns `wasm-inspection-v1` for one captured
core WebAssembly module. The identifier is a canonical nonzero unsigned 64-bit
string. The native `reb://app/api/wasm` route and `origin-trace-wasm --artifacts
DIR --artifact-id ID` use the same Rust provider. The CLI prints either the
inspection document or `{error, status}`; a printed provider error is not a
successful inspection even though the process exited normally.

The provider verifies the complete file size and SHA-256 against the manifest
before decoding. It does not execute the module, invoke imports, fetch resources,
write analysis files, or modify capture. Artifact kind and path containment use
the existing evidence-store boundary. Sensitive artifacts retain their existing
capture policy; inspection does not enable capture.

## Document

The [OpenAPI schema](openapi.json) defines `WasmInspection` and its rows. The
response includes artifact identity, SHA-256, byte size, status, decoded section,
function and instruction counts, rows, limits, omissions, and a notice.

Rows distinguish sections, types, imports, exports, tables, memories, globals,
tags, start functions, defined functions, local groups, decoded instructions,
data segments, element segments, and opaque custom sections. Function indexes
include imported functions. Function headers identify their declared type.

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

`decoded` means traversal reached the module end without unsupported sections
or a traversal limit. It does not establish type validity, runtime invocation,
JS/WASM crossings, traps, memory growth, VM semantics, or value provenance.
`partial` names unvisited coverage; counts describe decoded entries only.
Malformed binary or function control structure fails with HTTP 422, preserving
original bytes. Unsupported component/version encodings also fail with 422.

## Bounds and ownership

- Maximum complete input: 2 MiB. Oversized artifacts fail with HTTP 400.
- Maximum decoded rows: 8,192, shared by metadata and instructions.
- Maximum sections: 128; traversal also checks a two-second deadline.
- Limit exhaustion returns partial coverage without decoding the remainder.
- The backend executes on its bounded blocking reader pool. Native inspection
  uses one helper at a time, private temporary output, an 8 MiB output limit,
  and a five-second process deadline. Busy helpers return 409; unavailable
  helpers return 503. The UI imposes a ten-second request timeout.
- The UI verifies identity, bounded rows and coordinates, renders inert text,
  and caches at most four inspection documents keyed by artifact ID and hash.

Sources opens captured WASM in Hex. Inspect switches to the derived listing;
Hex returns to original evidence. Enabled offset buttons reveal the matching
hex row. Offsets beyond the existing 20,000-row hex viewer remain labeled and
cannot imply successful navigation. Find searches the displayed listing.
Inspection errors provide Retry inspection, and Hex remains available.
