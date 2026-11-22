# WASM Inspection v2

`GET /api/wasm?artifact_id=<id>[&sections=<names>][&row_offset=<n>|&byte_offset=<b>][&row_limit=<n>]`
returns `wasm-inspection-v2`: one window of rows from the inspection of one
captured core WebAssembly module of any size. The identifier is a canonical
nonzero unsigned 64-bit string. The optional `sections` filter is described
below. The loopback route rejects any other query parameter, so a misspelled
filter fails instead of returning a whole-module document the caller will read
as scoped. The native `reb://app/api/wasm` route forwards to this loopback route
on the backend the stored-evidence window runs, so it takes the same parameters.
`origin-trace-wasm --artifacts DIR --artifact-id ID [--sections NAMES]
[--row-offset N] [--row-limit N]` prints the same window from the same Rust
provider. The CLI prints either the inspection document or `{error, status}`; a
printed provider error is not a successful inspection even though the process
exited normally.

The provider verifies the complete file size and SHA-256 against the manifest on
every request, before decoding. It does not execute the module, invoke imports,
fetch resources, write analysis files, or modify capture. Artifact kind and path
containment use the existing evidence-store boundary. Sensitive artifacts retain
their existing capture policy; inspection does not enable capture.

## What changed from v1

Version 1 refused modules over 2 MiB and stopped at 8,192 rows, 128 sections,
8,192 function declarations or two seconds, so the code section of a real module
was cut a few dozen bodies in and its data and trailing custom sections were
never reached. Version 2 inspects every byte:

- Any module size, every section, every row. There is no deadline: the request
  is polled every 4,096 rows, and one that goes away stops the decode and is
  answered 499 `cancelled`.
- The document is always a window. `rows` holds at most `row_limit` rows and
  `row_window` names where they sit in `total_rows`; `next_offset` continues.
  `limits` is gone, and with it every `max_*` and `deadline_ms` member.
- `byte_offset` starts a window at the row for an original byte, and
  [Find](#find) searches the text of every row on the backend.
- Rows lose `text_truncated`. Names, branch tables and type lists are complete;
  only a data segment's text previews its bytes, because Hex shows every byte of
  its range.
- Function declaration rows appear whenever the function section is selected,
  including in an unfiltered document.

## Index and windows

The first request for a module and section request walks the whole module once.
It decodes every requested section, entry and function body, counts their rows,
and keeps an index of where each unit's rows begin: a section header, a
section's run of entries, one function body. A window bisects that index and
decodes only the units it shows, straight from the original bytes, so a window
anywhere in a module costs about as much as the first. The backend keeps four
indexes, keyed by module SHA-256 and section request. An index holds a few dozen
bytes per function body and none of the module's bytes, which are read and
verified again for every window.

`row_offset` (default 0, at most `total_rows`) names the first row. `byte_offset`
instead names an original byte: the window starts at the first row whose
`byte_offset` equals it, or else at the last row that starts before it, and
`row_window.offset` says which row that is. A byte before the first row or past
the end of the module fails with 400, and passing both parameters fails with
400. `row_limit` is 1 to 2048 (default 2048), and a window also stops at 98,304
bytes of serialized rows so it fits one 128 KiB MCP result.

## Document

The [OpenAPI schema](openapi.json) defines `WasmInspection` and its rows. The
response includes artifact identity, SHA-256, byte size, status, decoded section,
function and instruction counts, the row window, omissions, section coverage, and
a notice. Counts describe the whole module, not the window.

Rows distinguish sections, types, imports, function declarations, exports,
tables, memories, globals, tags, start functions, defined functions, local
groups, decoded instructions, data segments, element segments, and opaque custom
sections. Function indexes include imported functions. Function headers identify
their declared type. A `declaration` row carries the function-section entry for
one function: its index and the type index it declares, so an export resolves to
its declared type without decoding a function body. Section rows label a section
with the same name the `sections` filter uses, so a row label and the request
that selects it cannot drift apart. A `call`, `return_call` or `ref.func` row
names its target in `target_function_index`.

All offsets are zero-based positions in the original binary. `byte_end` is an
exclusive end for sections, bodies, instructions, local groups and segments.
Metadata entries without a complete item range use a point coordinate
(`byte_end == byte_offset`). Recursive type groups share the group's start.
Section ranges describe the payload, excluding the section ID and size prefix.
Rows are in binary order: `byte_offset` never decreases from one row to the
next.

Instruction text uses WASM mnemonics followed by the parser's named immediate
fields, rather than claiming to be round-trippable WAT. Branch tables list every
target and their default; function types list every parameter and result. A
data segment's text names its kind and size and previews its first 32 bytes as
hex. Custom data is opaque; GC layouts and constant expressions remain in the
original bytes. Names are quoted with escaped control characters, keeping each
row on one line so display text cannot shift byte-offset relationships.

`decoded` means an unfiltered traversal reached the module end without
unsupported sections. It does not establish type validity, runtime invocation,
JS/WASM crossings, traps, memory growth, VM semantics, or value provenance.
`partial` names what was not decoded in `omissions`. Malformed binary or
function control structure fails with HTTP 422, preserving original bytes, as
does an unsupported component or version encoding. Because the index decodes
every requested unit before the first window is served, a module that fails
anywhere fails on its first request, never on a later page.

## Section requests and coverage

`sections` is a comma separated list of section names: `custom`, `type`,
`import`, `function`, `table`, `memory`, `global`, `export`, `start`, `element`,
`code`, `data`, `data_count`, `tag`. Omitting it requests the whole module. An
empty value, an unknown name, a repeated parameter, or a value over 128 bytes
fails with HTTP 400 rather than widening to the whole module.

A request narrows which sections produce rows, so a reader of the export, import
or data tables of a large module does not page through its instructions first.
It never narrows the traversal: section framing, the imported-function count,
the function declarations behind every function index, and the function/code
count agreement check hold exactly as they do for an unfiltered request. Section
rows are kept for every section, including excluded ones, so a filtered document
still names the bytes it did not decode.

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
- `truncated_sections` names requested sections this version cannot decode and
  left opaque. `omissions` names which.
- `section_map_complete` is true when traversal reached the module end, so the
  three lists together name every section in these bytes and a requested section
  absent from all three is absent from the module.

A filtered document is always `partial`, even when the request happened to
exclude nothing present in these bytes, and `omissions` names the requested
sections. `defined_functions` counts the code-section bodies the traversal
enumerated; `instructions` counts decoded instructions only, so an excluded code
section reports zero instructions rather than none existing.

## Find

`GET /api/wasm/search?artifact_id=<id>&q=<literal>[&sections=<names>][&match_offset=<n>][&match_limit=<n>]`
returns `wasm-inspection-search-v1`: every nonoverlapping case-insensitive
occurrence of a single-line literal in the `text` of every row of the same
inspection, left to right. Case folds by Unicode simple lowercase, as a
JavaScript `giu` search does. Analyst names and original bytes are not searched.
An empty `q` or one with a line separator fails with 400.

The first request for a query reads every row once, split across the machine's
cores by runs of units, and keeps how many matches each unit holds, keyed by
module SHA-256, section request and folded query (eight queries are kept). `total_matches` is therefore exact, and a later page decodes
only the units it lists. Each match names its `row` (a `row_offset` of the same
inspection), that row's `byte_offset`, and a `column` and `length` in UTF-16 code
units of the row's text. `match_limit` is 1 to 1000 (default 1000);
`match_window.next_offset` continues. A search is cancelled like a window: a
request that goes away is answered 499. The MCP projection lists
`search_wasm_inspection` only with `--allow-content`.

## Ownership

- The backend decodes on its blocking reader pool; each request holds one reader
  for its decode. Native stored-evidence inspection forwards to the same
  backend, and a request WebKit stops is cancelled there.
- The UI verifies identity and coordinates, renders inert text, and pages rows
  as the editor scrolls.

Toolchain, well-known function and constant identification for the same
artifact is a separate report, [WASM identification](wasm-identification-v1.md).

## Function index and block graph

`GET /api/wasm/functions?artifact_id=<id>` returns `wasm-function-index-v1`: each
defined function's index, byte range and type index, and names from the name
section, then exports. It reads section framing and decodes no instruction.
`GET /api/wasm/graph?artifact_id=<id>&function=<index>` returns
`wasm-block-graph-v1` for one defined function, using the same decoder as
inspection. The native app forwards both routes to its bundled backend, and
`origin-trace-wasm --functions` and `--graph-function N` print the same
documents. The OpenAPI schema defines both documents. Any other query
parameter is refused, and an imported or undefined index returns 404. A function
is decoded only when requested; nothing retains a whole-module graph.

A block's `flags` carry `entry`, `reachable` (a declared path from the entry, not
observed execution), `exit`, `trap`, and `rows_cut`. `edges` are
`[from, to, kind, label]`, where `to` is null for an unresolved target: a tail
call, a throw, or a label past the frames that decoded. Kinds are `fallthrough`,
`branch`, `taken`, `not_taken`, `table` (br_table arms with the same target, as
a compact case list), `table_default`, `exception`, and `unresolved`. `rows`
are newline-terminated `offset mnemonic operands` text, and a run of identical
block openers is one row with a count, so `row_count` can be below
`instruction_count`. `complete` is always false.

A module of any size is read whole, and the function index lists every
function. Budgets are byte budgets chosen from real artifacts: the
7,654,321-byte body limit web engines enforce, 16 MiB of row text and 32 MiB of
structure for one function. Anything cut sets `status` to `partial` and is
named in `omissions`; structure is kept before row text, and an edge leaving
the retained prefix stays labeled. Decoding has no deadline: the request is
polled every 4,096 instructions, and one that goes away stops the decode and is
answered 499 `cancelled`. `limits` no longer reports `max_input_bytes`,
`max_index_bytes` or `deadline_ms`; version 1 readers ignore the absent keys.

`GET /api/wasm/pseudocode` lifts one function into readable lines with the
same artifact checks; [WASM pseudocode](wasm-pseudocode-v1.md) defines it.

Sources opens captured WASM in Hex. Inspect switches to the derived listing,
one row per line with its original byte offset in the gutter, read a page at a
time from the backend as the editor moves; Hex returns to original evidence.
An offset button reveals the matching hex row. Find in Inspect searches every
row on the backend and moves to each match's page. Inspection errors provide
Retry inspection, and Hex remains available. A selected instruction row can be
traced with Trace value, described in [WASM value flow](wasm-value-flow-v2.md).
