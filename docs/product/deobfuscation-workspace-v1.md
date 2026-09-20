# Deobfuscation Workspace v1

## Purpose

Deobfuscation Workspace adds a bounded, evidence-only reading of captured
JavaScript to the Research UI: a classification with the measurements behind
it, a derived representation with an exact derived-range to original-byte map,
and recovered string tables with a replayable transformation log.

Every derived byte maps back to a source range, so a consumer can always return
to the original evidence. The module never executes analyzed code, resolves
identifiers, or claims semantics the evidence does not support.

## Scope of v1

`apps/research-ui/deobfuscation.py` implements three products over one captured
source body:

1. `classify_source` labels a source `readable`, `minified`, `packed`, or
   `obfuscated` and reports the weighted evidence that produced the label.
2. `derive_representation` renders a re-indented reading view and a segment map
   from derived offsets to original offsets.
3. `recover_string_tables` recovers literal string arrays and code-point arrays
   without running them.

`analyze_source` composes all three into the `deobfuscation-analysis-v1`
document. `verify_deobfuscation_document` revalidates a document before use.

The server exposes this work at `/api/deobfuscation` with `script_id` and
`mode=analysis|derived`. The `analysis` mode returns the document; `derived`
also returns the representation text and segment map.

## Analysis schema

The document is a JSON object with schema identifier
`deobfuscation-analysis-v1`:

- `source`: `url`, `sha256`, `byte_size`, `lines`. The digest is SHA-256 over
  the UTF-8 source bytes unless the caller supplies one.
- `classification`: `label`, `confidence`, `scores`, `evidence`,
  `alternatives`.
- `stats`: the raw metrics used by classification, including byte and character
  counts, line counts, maximum and mean line length, whitespace ratio, escape
  counts, `_0x` identifier count, identifier count and short-identifier ratio,
  base64 and percent blob counts, dynamic-code call count, the packer signature
  flag, and the blob-decoder count.
- `representation`: `status` (`derived` or `unchanged`), `derived_bytes`,
  `segment_count`, `truncated`, and the `transformations` log. The derived text
  and segment map are produced by `derive_representation`, not stored here.
- `string_tables`: recovered tables, sorted by source offset.
- `limits`: the named caps that applied to this analysis.

`verify_deobfuscation_document` accepts a document only when the schema
identifier matches, `source.sha256` is a string, `source.byte_size` is an
integer, `classification` is an object with a known label and a list of
evidence, `representation` is an object with a valid status and a
transformations list, `string_tables` is a list, and `limits` is an object.
Anything else raises `DeobfuscationError`.

## Classification labels and evidence

Each label is backed by weighted evidence entries shaped as
`{id, weight, detail, value}`. `value` carries the measured number or flag, so
a consumer can re-check the claim instead of trusting the label.

| Evidence id | Weight | Recorded when |
| --- | ---: | --- |
| `packer-signature` | 60 | The source matches the classic `eval(function(p,a,c,k,e,...` decoder shape. |
| `packed-blob` | 45 | Dynamic code construction appears next to a base64 blob of 200 or more characters or a percent-escape run of 64 or more triplets. |
| `hex-identifiers` | 40 | Ten or more `_0x`-prefixed hexadecimal identifiers. |
| `hex-escapes` | 35 | Twenty or more `\xNN` escapes. |
| `unicode-escapes` | 35 | Twenty or more `\uNNNN` escapes. |
| `encoded-string-table` | 20 | A blob decoder (`atob`, `fromCharCode`, `decodeURIComponent`, `unescape`) beside escape-encoded strings or `_0x` identifiers. |
| `long-lines` | 35 | Mean non-empty line length of 120 characters or more. |
| `low-whitespace` | 25 | Whitespace ratio of 0.12 or less. |
| `short-identifiers-widespread` | 15 | At least 50 identifiers and at least half of them two characters or shorter. |
| `readable-baseline` | 0 | No weighted evidence reached threshold. |

Packing is evaluated first: `packed` requires a packed score of 45 or more that
is also at least the obfuscation score. Otherwise `obfuscated` requires 35 or
more, then `minified` requires 35 or more, and the fallback label is
`readable`. A readable source always carries the zero-weight baseline entry
with its measured mean line length and whitespace ratio.

`confidence` is 50 for `readable` and otherwise
`min(95, 40 + chosen score - best competing score // 2)`, clamped to 0-100.
`alternatives` lists every other label with a positive score, highest first.
Evidence is capped at 32 entries.

## Derived representation map

`derive_representation` re-indents the token stream; it never rewrites a token.
The returned `text` and `segments` obey these invariants:

- Segments are contiguous and cover the derived text exactly:
  `segments[i].derived_end == segments[i+1].derived_start`,
  `segments[0].derived_start == 0`, and
  `segments[-1].derived_end == len(text)`.
- A `verbatim` segment is an identity slice of the source:
  `source[original_start:original_end] == text[derived_start:derived_end]`.
  Comments, identifiers, numbers, regexps, strings, and templates are always
  copied byte-for-byte.
- A `synthetic` segment is a zero-width insertion point in the original:
  `original_start == original_end`. Only whitespace, a space before an opening
  brace, a space after a comma, and token separators are synthesized.
- `original_offset_for_derived(segments, derived_offset)` maps a derived offset
  to its original offset: an exact source offset inside a verbatim segment, the
  insertion point inside a synthetic segment, and `None` outside the map or for
  an empty segment list.

The `transformations` log records `{id, kind, detail, count, original_start,
reversible}` per applied transformation. Kinds are `format` for whitespace work,
`identity` for the byte-for-byte token copy that is always reported, and `no-op`
when the source needed no formatting. The log is capped at 64 entries. A
`truncated` flag and the effective `limits` are reported whenever the derived
byte budget or the segment cap stopped the derivation; no partial segment is
retained past the budget. The budget counts the UTF-8 bytes of the emitted text,
so `derived_bytes` never exceeds `max_derived_bytes`, even for multi-byte
sources. Segment `derived_start` and `derived_end` remain character offsets into
the derived text.

## String-table recovery

`recover_string_tables` recovers two shapes without evaluating them:

- `string-array`: a bracketed array holding at least eight string literals.
  Each entry reports `index`, `offset`, `raw`, `encoding`, and `value`. Offsets
  index the original source, so `source[offset:offset + len(raw)] == raw` holds
  for every entry. Encodings are `literal`, `escape-sequence`, `base64`, or
  `hex`.
- `code-point-array`: a numeric array holding at least eight integers. Values
  must be in the Unicode range and decode to text that is at least 85 percent
  printable. Each entry reports `index`, `offset`, `raw`, and `value`, with the
  same `source[offset:offset + len(raw)] == raw` invariant as `string-array`.
  The table carries the entry count and a `decoded_preview` of the first 512
  characters.

Escapes are decoded without evaluation. A plain literal is additionally treated
as base64 only when it is at least eight characters, uses the canonical
alphabet, has a length divisible by four, and decodes to at least 85 percent
printable text; even-length hexadecimal literals get the same treatment. Decoded
values are capped at 4,096 characters.

Both table shapes carry a `decoder_hint` built from the 2,000 characters after
the table: the kind (`function-definition-near-table` or `none`), the nearby
function name and offset, whether dynamic code construction appears nearby, and
a confidence of `low` or `none`. The hint carries the note that "A nearby
definition is a hint, not proof, that it decodes this table." Recovered values
are evidence of what the literal bytes decode to, not proof of how the page uses
them.

## Limits and failure behavior

| Resource | Limit |
| --- | ---: |
| Source | 4 MiB |
| Derived text budget | 2 MiB of UTF-8 bytes, minimum 1024 bytes |
| Mapped segments | 250,000 |
| String tables | 64 |
| String entries | 2,048 |
| Transformations | 64 |
| Evidence entries | 32 |
| Decoded literal | 4,096 characters |

`DeobfuscationError` is raised for a non-string, empty, or oversized source, for
a derived budget below 1024, and for an invalid analysis document. The HTTP
layer maps it to a 400 response and debugger failures to 409; an invalid
`mode` is rejected before any source is read.

## Non-goals

- No code execution, sandboxed or otherwise.
- No identifier resolution or de-aliasing.
- No control-flow unflattening.
- No packer unpacking. The classic packer shape is detected and labelled; its
  payload is not extracted.
- No value flow or constant propagation.
- No semantics beyond the recorded evidence.

## Not yet built

- Unpacking the detected packer payload, or decoding base64 and percent blobs
  beyond counting them in `stats`.
- Resolving string-array index access or accessor call sites to recovered
  values.
- A persisted evidence-store artifact for the analysis document; the document is
  returned to the caller only.
- Identifier renaming, control-flow graphs, or any transform that changes the
  source rather than re-indenting it.

## Contracts and tests

`apps/research-ui/server.py` imports `SCHEMA`, `DeobfuscationError`,
`analyze_source`, `derive_representation`, and `ensure_source`, and serves
`/api/deobfuscation`. The Research UI reads `analysis.classification`,
`analysis.representation`, `analysis.source`, and `analysis.evidence`.

`tests/research_ui/test_deobfuscation.py` covers all four classification labels
with their evidence, the derived-map invariants and offset mapping, the derived
budget (including its UTF-8 byte accounting) and source bounds, escape-sequence,
base64, and code-point string-table recovery (including per-entry offsets), and
the acceptance and rejection of analysis documents.
