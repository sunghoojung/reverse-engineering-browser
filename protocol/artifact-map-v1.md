# Artifact map v1

`GET /api/artifact-map?artifact_id=<id>` returns `artifact-map-v1`: a fixed-size
summary of one captured artifact for the Sources **Map** view. The native
`reb://app/api/artifact-map` route and `origin-trace-wasm --artifacts DIR
--artifact-id ID --artifact-map` use the same Rust provider. The CLI prints the
map document or `{error, status}`. A printed provider error is not a map.

The route is read-only. It never executes the artifact, writes nothing, and
needs no confirmation. Request bodies and Canvas images are refused, matching
Sources, which does not open them.

## Memory and coverage

The provider reads the stored blob in 64 KiB chunks and hashes it in the same
pass, so integrity is established by the read that produced the map. Output is
at most 128 by 128 cells of one byte for entropy and one byte for kind, about
16 KB each before base64, whatever the artifact size. Every byte is covered;
nothing is cut to save memory. A read that fails verification is an error, never
a partial map. An abandoned HTTP request stops reading, and the read has a
60-second deadline.

## Windows

Cells are windows of the artifact in byte order. The grid side is the largest
power of two that keeps every window at or above 256 bytes. Windows differ by at
most one byte; `grid.window_bytes` is the whole-byte size.

Shannon entropy over a window of W bytes cannot exceed log2(W). A 4-byte window
tops out at 2 bits per byte, so a color scale reading 0 to 8 would mean nothing
for it. 256 is the smallest window that can contain every byte value once and so
reach the full scale. A short artifact therefore gets a smaller grid rather than
smaller windows. An artifact below 256 bytes is one cell and carries
`grid.below_min_window: true`; it is never marked high-entropy.

Finite windows still underestimate. A 256-byte window of uniform random bytes
averages about 7.2 bits per byte, not 8.

## Entropy cells

`entropy.cells` is one byte per window, base64, in byte order. It holds whole
units of `1/units_per_bit` bits per byte, rounded down, so 7.0 is an exact
level. `mean_bits` (weighted by window bytes) and `max_bits` are computed from
the exact values.

`high_entropy` states the threshold (7.0 bits per byte) and how many windows and
bytes reach it. A window at or above it is high-entropy by that stated test
only. Nothing here concludes that bytes are compressed, packed or encrypted.

## Kinds

`kind_map.cells` is one byte per window: the index of the dominant kind in
`kinds`, plus `mixed_flag` when the window holds more than one kind. Every kind
row states bytes and windows, and its `group` (`code`, `data`, `string`,
`structure`, `custom`, `undecoded`, `unknown`) selects its color.

Kinds use only facts the store already has. `facts.source` names which:

| Source | Artifact | Fact |
| --- | --- | --- |
| `wasm_section_frames` | `wasm` | Section ids and sizes read with the pinned wasmparser reader. Each section costs one small header read, then a seek past its payload. Data segments come from the existing inspection rows when the module is at most 2 MiB, the Inspect input bound. |
| `javascript_lexer` | `javascript` | String and template literal ranges from the existing JavaScript lexer, for scripts of at most 4 MiB, the JavaScript facts bound. |
| `vm_byte_coverage` | `bytecode_buffer` | Published VM byte attributions from `analysis/vm-opcode-workspace-v2.json`, inside the bytes the analyzer retained. |
| `none` | any | No byte-level fact exists for this artifact. |

Bytes no fact names keep the default kind for that source (`undecoded tail` for
Wasm and VM, `script text` for JavaScript, `no recorded fact` otherwise).
`facts.notes` names every limit that applied, and `facts.complete` is false when
any byte is outside the named facts.

## Highest ranges

`highest_ranges` holds at most 8 rows ordered by peak entropy: adjacent windows
at or above the threshold are merged, and the highest remaining single windows
fill the list. `start` is inclusive and `end` exclusive, in original bytes.

## Errors

`400` for a malformed, refused or unsupported request; `404` for an unknown
artifact; `408` when the read exceeds its deadline; `500` when the stored bytes
fail size or hash verification.
