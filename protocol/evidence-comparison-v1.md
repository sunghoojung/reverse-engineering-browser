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
`provenance`, `relationships`, and `selection`. Optional `offset` defaults to 0;
`limit` defaults to 50 and must be 1–100. Explicit null is invalid.

## Meaning and identity

The existing strict validator checks both original JSON package object tokens,
including duplicate and escaped duplicate members, supported profiles, closed
metadata fields, semantic digests, scoped references, gaps and coverage.
Malformed, unsupported, contradictory, oversized or invalid packages fail the
comparison. Rehashing forbidden fields does not authorize them. Unknown original
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
ID. Changed record fields include bounded scalar values; nested object/array
changes show their type/count and refer back to the original facet. Those
summaries do not establish nested equality. At most 12 changed fields are
shown; any omitted changed fields are counted explicitly.

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

## Bounds and effects

- Entire original request: 8 MiB + 4 KiB, one Content-Length and no
  Transfer-Encoding; existing 5-second body deadline and loopback trust checks.
- Each nested original package object token: at most 4 MiB. RawValue borrows the
  token instead of deserializing and reserializing it. No escaped JSON-string
  wrapper or expansion is used. Leading/trailing envelope whitespace is part of
  the outer limit; whitespace inside a package token counts against its limit.
- Framing depth at most 33 before RawValue scanning. Each original independently
  retains the validator's 32-level, 200,000-node, 4,096-byte string, 1,024-event,
  64-artifact, 4,096-reference and 4,096-gap limits and cooperative budget.
- Options are bounded before materialization: profile token 128 bytes, facet
  token 512 bytes, paging token five bytes. Unknown/duplicate outer keys fail.
- Comparison reserves one of the existing two package permits with immediate
  try-admission before reading its body. At most two comparison bodies/work items
  can be retained; active validate/export work shares that same capacity. Full
  capacity returns HTTP 503/resource_limit before ingestion, with no large-body
  queue and no automatic retry. Closed admission returns dependency_unavailable.
  A client still uploading after early rejection can observe a transport error.
  The existing four-operation I/O pool retains its one-second dispatch wait.
  The reserved package permit transfers into the blocking worker and remains
  owned until it finishes even if the caller disconnects. A body timeout,
  interrupted body or admission failure drops the permit without starting work.
  Comparison has a 10-second cooperative work deadline, including blocking
  executor queue time after admission.
- At most 2,181 logical rows, 100 retained response rows, 12 differences per row,
  and 512 KiB encoded output. Output serialization enforces the bound while
  writing. Offset is 0–2,181. A beyond-end page is empty, not a missing result.
- No cross product: bounded maps and sorted full-key union, O(n log n) matching;
  canonicalization/validation operate on independently bounded package trees.
  Indexes borrow validated records. The engine retains only the requested page,
  summary counts and bounded keys, not all result rows. Memory is bounded per
  admitted operation by these input/tree/key/output limits, with at most two
  comparison bodies/work items. Other routes retain their existing ingestion
  policies; no global HTTP request-concurrency claim is made.

The operation reads no configured evidence stores or raw artifacts, resolves no
URLs, creates no helper, executes no code, changes no capture controls, and does
not persist or automatically export anything. It cannot upgrade D10 supplied
validity into D11 cooperative stopped-store verification. Errors use the shared
code/details envelope. No HTTP success result is produced after work/output
budget exhaustion. Offset paging repeats the bounded inert comparison; it does
not create server state.

## Secondary UI integration

Load `evidence_comparison.js` after `evidence_package.js`. Mount an empty host
inside an explicitly opened secondary package-tools disclosure with
`RebEvidenceComparison.mount(host, {fetcher: fetch})`. Mount is idempotent and
returns `close`, `clear`, and `dispose`; closing retires active work without
resubmission. The controller shares the existing bounded response reader and
sends original valid-UTF-8 file bytes without JSON normalization. Two nonempty
files are required, each capped at 4 MiB before reading. Selection, cancellation,
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

The existing debugger fixture has an optional real Chromium component path:
`REB_UI_CHROMIUM=/path/to/chromium node tools/check-origin-trace-debugger.mjs
--evidence-comparison-ui-browser`. It mounts an isolated secondary disclosure
in the existing theme, exercises real file controls, hit-tested Compare,
references, failure retention, cancellation, close/reopen, keyboard Clear and
wide/narrow/phone geometry, and writes screenshots. This fixture does not claim
that the final parent Evidence landing integration has been verified. No
sandbox flags are overridden; unavailable Chromium is a validation gap.
