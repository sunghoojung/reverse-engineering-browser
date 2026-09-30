# Deobfuscation Workspace v1

## Purpose

Deobfuscation Workspace adds a bounded, evidence-only reading of captured
JavaScript to the Research UI: a classification with the measurements behind
it, a derived representation with an exact derived-range to original-source map,
and recovered string tables with a replayable transformation log.

Every derived position maps back to a source range, so a consumer can always return
to the original evidence. The module never executes analyzed code or claims semantics the evidence does
not support. Supported static rewrites have explicit assumptions and omissions.

## Scope of v1

`apps/origin-trace-backend/src/deobfuscation.rs` owns classification, literal
string-table recovery, and validation of the Rust/Oxc worker's static AST
rewrites. It composes the `deobfuscation-analysis-v1` response and verifies the
worker schema, assumptions, rewrite boundaries, and reconstructed output before
returning it. Captured source is never executed.

The server exposes `/api/deobfuscation` with exactly one of `script_id` or
`artifact_id` and `mode=analysis|derived`. Derived mode also returns the
representation text and segment map. The packaged application and development
server use the same Rust backend and analysis worker.

## Sources presentation

Sources keeps semantic rewriting and display formatting as separate controls.
**Deob** selects the mapped representation returned by the analysis engine.
The DevTools-style **{ }** control pretty prints whichever representation is
active. This means a source classified as minified can still be expanded when
the semantic deobfuscator correctly reports that no safe rewrite was found.

Pretty printing detects JavaScript, JSON, CSS, and HTML from the captured kind,
MIME type, and filename. It changes only display whitespace, preserves strings,
comments, regular expressions, and template literals, and produces a UTF-16
segment map back to its input. When pretty print is layered over Deob, Sources
composes both maps so every displayed line can return to original evidence.
Formatting is bounded to 2 MiB of input and 4 MiB of output, cached for the last
eight representations, and never changes the artifact or live runtime source.
The formatter stops at 250,000 lexical tokens or 500,000 mapping segments so a
small but adversarial source cannot create an unbounded display structure.

## Analysis schema

The document is a JSON object with schema identifier
`deobfuscation-analysis-v1`:

- `source`: `url`, `sha256`, `byte_size`, `lines`. The digest is SHA-256 over
  the UTF-8 source bytes.
- `classification`: `label`, `confidence`, `scores`, `evidence`,
  `alternatives`.
- `stats`: the raw metrics used by classification, including byte and character
  counts, line counts, maximum and mean line length, whitespace ratio, escape
  counts, `_0x` identifier count, identifier count and short-identifier ratio,
  base64 and percent blob counts, dynamic-code call count, the packer signature
  flag, and the blob-decoder count.
- `representation`: `status` (`derived` or `unchanged`), `derived_bytes`,
  `segment_count`, `truncated`, and the `transformations` log. The derived text
  and segment map are returned separately in derived mode.
- `string_tables`: recovered tables, sorted by source offset.
- `limits`: the named caps that applied to this analysis.

The HTTP contract and UI validators check the returned schema. The adapter
rejects malformed worker records, overlapping or invalid UTF-8 source ranges,
and output that does not match reconstruction from the declared rewrites.

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

The AST worker emits `verbatim` and `replacement` segments with UTF-8 byte
boundaries. Segments cover the derived text, and verbatim slices match the
original source exactly. A replacement maps to its entire original expression;
positions within it map to that expression's start. The adapter rebuilds the
output from these records and rejects inconsistencies. Safe rewrites and their
limits are documented in [method coverage](deobfuscation-method-coverage.md).

Display pretty printing has a separate UTF-16 map and can introduce synthetic
whitespace. The UI composes that map with the AST map when both controls are
active. Formatting and rewriting never change retained artifact bytes.

## String-table recovery

Literal recovery recognizes two shapes without evaluating them:

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

Sources are capped at 4 MiB, worker output at 32 MiB, rewrites at 4,096, and
worker execution at five seconds. Literal recovery returns at most 64 tables,
2,048 entries, and 4,096 characters per decoded value. The worker preserves
unchanged remainder and reports truncation when its rewrite budget is reached.

Invalid input returns 400, missing artifacts 404, unavailable live debugging or
busy analysis 409, parse failures 422, worker failures 502, and timeouts 408.
A missing packaged worker returns 503. Original evidence survives analysis
failure; the UI retains its previous successful representation on retry failure.

## Contracts and validation

`apps/origin-trace-backend/src/app.rs` composes the analysis service and serves
`/api/deobfuscation`. The UI consumes the classification, measurements, literal
tables, mapped representation, assumptions, and omissions.

`make deob-benchmark` compares original and derived behavior for the bounded
technique corpus. `make check` compiles the Rust worker and runs backend tests;
`make lint` checks the adapter. The live browser fixture verifies analysis over
captured scripts through the HTTP API.

Representation segment offsets use `utf-8-byte`; literal-table offsets retain
Unicode code-point indexing for compatibility. The UI converts representation
boundaries to UTF-16 before performing location arithmetic. Legacy recorded
`python-lexical` responses retain their original code-point maps. The shared
contract lives in [`protocol/deobfuscation-v1.md`](../../protocol/deobfuscation-v1.md).
