# Deobfuscation response v1

`GET /api/deobfuscation` accepts exactly one of `artifact_id` and `script_id`,
plus `mode=analysis|derived` (default analysis). Native stored-evidence mode
accepts artifacts; live scripts require the development debugger server.

Responses contain `schema: deobfuscation-analysis-v1`, `engine`, `mode`, both
source identifiers (unused one null), `source_truncated`, `original_source`, and
`analysis`. Derived mode also includes `representation` with text and segments.
Original source is retained local evidence, never newly captured or executed.

`engine=python-lexical` provides heuristic classification, whitespace formatting,
and literal string tables. `engine=rust-oxc` provides parser-validated finite
numeric folds. Unsupported Rust classification is `unclassified`, confidence
is null, and `analysis.omissions` lists missing capabilities. Empty string tables
in that engine do not establish that the source contains none.

Representations declare `offset_unit`: `unicode-code-point` for Python,
`utf-8-byte` for Rust. Legacy untagged Python maps use code points. Offsets are
half-open ranges in the original or derived string under that encoding, not
line numbers. Consumers convert boundaries to their own string encoding before
adding offsets. The UI uses UTF-16 to match JavaScript and debugger columns.

`verbatim` segments are equal source slices. `synthetic` segments anchor inserted
text to a zero-width original position. Rust `replacement` segments anchor a
folded value to the whole original expression, and a position within one maps
to that expression's start. Transformations never change retained artifact bytes.

Sources are capped at 4 MiB. Native analysis has a five-second deadline, at most
4,096 rewrites, and 64 diagnostics. `truncated` means a derivation or rewrite
budget was reached; unchanged remainder in the Rust engine is preserved. Python
limits remain those in the workspace design. Native temporary input/output files
are private and removed when analysis finishes or fails.

Invalid identifiers/modes or malformed source return 400, missing artifacts 404,
unavailable live debugging or a busy worker 409, native parse failures 422,
and a native timeout 408. A failed UI request is not automatically retried.
The previous successful representation survives an explicit retry failure.
