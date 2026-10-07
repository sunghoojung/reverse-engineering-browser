# Deobfuscation response v1

`GET /api/deobfuscation` accepts exactly one of `artifact_id` and `script_id`,
plus `mode=analysis|derived` (default analysis). Native stored-evidence mode
accepts artifacts; live scripts require the development debugger server.

Responses contain `schema: deobfuscation-analysis-v1`, `engine`, `mode`, both
source identifiers (unused one null), `source_truncated`, `original_source`, and
`analysis`. Derived mode also includes `representation` with text and segments.
Original source is retained local evidence, never newly captured or executed.

`engine=rust-oxc` combines heuristic classification and literal string-table
recovery with parser-validated bounded AST rewrites described in
[method coverage](../docs/product/deobfuscation-method-coverage.md).
`analysis.omissions` lists unresolved transformations. The legacy
`python-lexical` engine identifier remains valid for previously recorded responses;
the application no longer ships that implementation.

Representations declare `offset_unit`: `unicode-code-point` for Python,
`utf-8-byte` for Rust. Legacy untagged Python maps use code points. Offsets are
half-open ranges in the original or derived string under that encoding, not
line numbers. Consumers convert boundaries to their own string encoding before
adding offsets. The UI uses UTF-16 to match JavaScript and debugger columns.

`verbatim` segments are equal source slices. `synthetic` segments anchor inserted
text to a zero-width original position. Rust `replacement` segments anchor a
folded value to the whole original expression, and a position within one maps
to that expression's start. Transformations never change retained artifact bytes.
Sources admits only known Rust/Oxc and legacy Python engines, ordered maps and
complete contiguous derived coverage. Replacement original spans must be
nonempty; synthetic spans must be zero-width. Rust maps must additionally cover
the complete original contiguously and use UTF-8 bytes, and supplied aggregate
transformation counts must sum to the number of mapped replacements (at most
4,096). Original and derived byte sizes, scalar boundaries, and verbatim slices
are checked before a changed span is exposed. Legacy code-point maps may omit
original formatting whitespace and are ineligible for exact-byte change
inspection. Missing optional summaries remain
unknown. Aggregate rule families do not identify individual replacement rules.

Sources are capped at 4 MiB. Worker analysis has a five-second adapter deadline, at most
4,096 rewrites, and 64 diagnostics. `truncated` means a derivation or rewrite
budget was reached; unchanged remainder is preserved. Native temporary input/output files
are private and removed when analysis finishes or fails.

Invalid identifiers/modes or malformed source return 400, missing artifacts 404,
unavailable live debugging or a busy worker 409, native parse failures 422,
an abnormal worker exit 502, and a worker timeout 408. Derived-output validation
failure also returns 422 with a qualified message that the original is preserved;
it is not reported as an original-source parse error. A failed UI request is not automatically retried.
The previous successful representation survives an explicit retry failure.

After rewriting, the worker bounds and reparses the complete candidate using
the original parse goal. A rejected candidate has `ok: false`,
`error_kind: "derived-validation"`, `parsed: true` (the original parsed), original
text in `derived_source`, and an empty `transformations` list. Its diagnostic
uses a zero-width range at zero rather than attributing a generated error to
original bytes. Existing source-parse failures do not carry this error kind.
The candidate check proves syntax acceptance only and never executes the source.

`assume_intrinsics=0|1` defaults to 0. Opt-in responses carry
`analysis.assumptions: ["standard-intrinsics"]`; default responses carry an empty
list. Sources exposes the setting beside its deobfuscation report and includes
it in cache/request identity. The assumption means modeled built-ins have their
standard behavior; it is not a claim that captured code has pristine prototypes.
Missing workers cannot honor this mode and return 503. Worker JSON requests use
the boolean `assume_intrinsics` with the same default.
