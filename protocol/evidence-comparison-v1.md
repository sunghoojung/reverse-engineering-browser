# Supplied evidence comparison v1

`POST /api/evidence/packages/compare` and `reb-api call
compare_evidence_packages` compare two locally supplied
[evidence metadata packages](evidence-package-v1.md). The CLI embeds the full
OpenAPI contract and discovery works without a service:

```sh
reb-api describe compare_evidence_packages
reb-api call compare_evidence_packages --base-url http://127.0.0.1:8765 \
  --body-file comparison.json
```

The request is a JSON object with `left` and `right` package documents,
`normalization_profile: "reb-declared-metadata-v1"`, and a nonempty unique
`facets` array selected from `artifacts`, `coverage`, `events`, `gaps`,
`provenance`, `relationships`, and `selection`. Optional `offset` defaults to 0
and is any nonnegative integer; `limit` defaults to 50 and must be 1–100.
Explicit null is invalid.

## Meaning and identity

The existing strict validator checks both original JSON package object tokens,
including duplicate and escaped duplicate members, supported profiles, closed
metadata fields, semantic digests, scoped references, gaps and coverage.
Malformed, unsupported, contradictory or invalid packages fail the
comparison; a package of any size compares. Rehashing forbidden fields does not authorize them. Unknown original
fields and input values never appear in error messages.

Normalization is the existing package semantic serialization profile: object
member and declared set ordering are normalized without changing values or
removing fields. No whitespace, timing, source, identifier or observer heuristic
is added. Only whole selected facets are supported in v1.

Event records align only on the full declared `(session_id, process_id,
sequence_number)` key; artifacts align on `(session_id, artifact_id)`. These are
supplied scoped declarations, not authenticated ownership of a real capture.
Different sessions with coincident local keys are counted as
`ambiguous_cross_scope` and remain separate left-only/right-only rows. No URL,
sequence proximity, frame position, content hash or shared profile label aligns
records. Local candidate counts do not establish that any candidate is related.

Rows say `equal_declared_metadata`, `changed_declared_metadata`, `left_only`, or
`right_only`. Each has exact input package/facet/key references and a stable row
ID. Changed record fields include their scalar values; nested object/array
changes show their type/count and refer back to the original facet. Those
summaries do not establish nested equality. Every changed field is listed, and
`differences_omitted` is always 0; earlier revisions listed 12 and counted the
rest there.

`selected_metadata_equal` compares only the requested representation, not the
recording. It is null when record-only facets contain no rows. A left/right-only
record makes it false. `package_metadata_equal` compares validated semantic
package IDs, including facets outside the selection. An identical package ID
never establishes raw-byte identity or authentic provenance.

The comparison ID is SHA-256 over the domain
`REB\0evidence-comparison\0v1\0` followed by compact deterministic JSON of
`[profile,left_package_id,right_package_id,sorted_facets]`. Page offset and limit
are intentionally excluded. Row IDs use the domain
`REB\0evidence-comparison-row\0v1\0` and
`[profile,facet,left_reference,right_reference]`. Facets sort lexically; within
record facets, compact full-key JSON sorts lexically. Ordering is deterministic,
not chronological or causal. New input IDs or selected facets change the result
identity; changing pages does not.

A matching artifact `sha256` plus `byte_size` is only a declared descriptor
match. Artifact bytes are absent and are not reverified. Exporter verification
labels remain untrusted assertions. V1 packages preserve null historical builds
and capture configuration, so observer regimes, epoch identity, capture
completeness, timing equivalence and behavioral equivalence remain unknown or
not established even for identical metadata. Unsupported profiles/regimes are
rejected, never silently coerced into a comparable profile. Supplied complete
source scans and selection coverage never become complete-capture claims.

## Resources and effects

- The request and each nested original package object token are of any size,
  with one Content-Length and no Transfer-Encoding; the body deadline grows by
  a second per 16 MiB, and loopback trust checks apply. RawValue borrows each
  token instead of deserializing and reserializing it. No escaped JSON-string
  wrapper or expansion is used.
- Framing depth at most 33 before RawValue scanning, and each original at most
  the validator's 32 levels: the package reader recurses once per level, and
  no valid package nests deeper. Each original has any number of nodes,
  records, references and gaps, and strings of any length.
- Options are checked before materialization: profile token 128 bytes and facet
  token 512 bytes, which their fixed values fit. Unknown/duplicate outer keys
  fail.
- Comparison acquires one of the existing two package permits before reading its
  body, so at most two comparison bodies/work items are retained; active
  validate/export work shares that same capacity. A later request waits for a
  permit, with no admission deadline, and its body is read once it has one.
  Closed admission returns dependency_unavailable. Admission then waits for a
  slot of the four-operation I/O pool, with no deadline. Earlier revisions
  refused a request past 8 MiB + 4 KiB or an original past 4 MiB, and answered
  a third comparison with HTTP 503/resource_limit.
  The reserved package permit transfers into the blocking worker and remains
  owned until it finishes even if the caller disconnects. A body timeout,
  interrupted body or admission failure drops the permit without starting work.
  Comparison has no work deadline: it runs until it is done, and a request
  that goes away stops it between steps with HTTP 499 `cancelled`. Producers
  before this revision stopped it at 10 seconds with HTTP 408.
- Any number of logical rows, at most 100 response rows per page, and every
  changed field of a row. A page past the end is empty, not a missing result.
  Earlier revisions stopped at 2,181 rows, 12 differences per row and 512 KiB
  of output.
- No cross product: maps and a sorted full-key union, O(n log n) matching.
  Indexes borrow validated records. The engine retains only the requested page,
  summary counts and keys, not all result rows. Memory grows with the two
  packages, with at most two comparison bodies/work items held at a time.
  Other routes retain their existing ingestion policies; no global HTTP
  request-concurrency claim is made.

The operation reads no configured evidence stores or raw artifacts, resolves no
URLs, creates no helper, executes no code, changes no capture controls, and does
not persist or automatically export anything. It cannot upgrade D10 supplied
validity into D11 cooperative stopped-store verification. Errors use the shared
code/details envelope. No HTTP success result is produced after cancellation.
Offset paging repeats the inert comparison; it does not create server state.

## Secondary UI integration

Load `evidence_comparison.js` after `evidence_package.js`. Mount an empty host
inside an explicitly opened secondary package-tools disclosure with
`RebEvidenceComparison.mount(host, {fetcher: fetch})`. Mount is idempotent and
returns `close`, `clear`, and `dispose`; closing retires active work without
resubmission. The controller shares the existing package response reader,
which reads a result whole, and sends original valid-UTF-8 file bytes of any
size without JSON normalization. Two nonempty files are required. Selection, cancellation,
closing and disposal invalidate delayed file/body/service results. Failed paging
preserves the last understandable result. Response IDs must match both selected
original package IDs before results can render. Text is inert DOM content.

The host must also call `close()` when leaving Evidence, closing an ancestor
package-tools mode, or returning to observations; hiding an ancestor does not
fire the comparison disclosure toggle.

The parent Evidence workspace owns the secondary host, script tag and mount;
this component does not replace its investigation controller or landing screen.
Stored-evidence native mode retains the existing explicit 503; live workspaces
use the local Rust backend. Native asset/build allowlists include the component.

The former Chromium component path of `tools/check-origin-trace-debugger.mjs`
was removed with CDP browser automation; that script now runs only its offline
model assertions. `make rendered-ui-check` is the packaged-app rendered gate.
