# Evidence Package v1

The [JSON Schema](evidence-package-v1.schema.json) defines the closed
`reb-evidence-package` metadata contract. The same reachable definitions are
embedded under `EvidencePackage*` components in [OpenAPI](openapi.json).
[SAFETY.md](../SAFETY.md) remains the authorization and capture policy.

Two operations share this contract: explicit selected-source export under
cooperative stopped-writer leases, and inert validation of a supplied document.
Neither imports records into backend state, persists packages on the server,
copies artifact bytes, fetches references, or executes source or analysis helpers.

## Selected stopped-store export

`POST /api/evidence/packages/export` (`export_evidence_package`) takes this closed
request, of any size:

```json
{"protocol_version":1,"profile":"reb-metadata-only-v1","selection":{"events":[{"session_id":"7","process_id":42,"sequence_number":"1"}],"artifacts":[{"session_id":"7","artifact_id":"9"}]}}
```

Only `profile` is optional, with the default shown. Both selector arrays are
required and name any number of events and artifacts. Duplicate keys,
unknown members, unsupported profiles and ambiguous/bare identities are rejected.
There are no paths, URLs, wildcards, latest aliases or caller-supplied evidence.
The normal local-origin checks, no-store and nosniff response headers apply.

```sh
reb-api describe export_evidence_package
reb-api call export_evidence_package --endpoint-file backend.endpoint \
  --body-file selection.json --output selected.reb-evidence.json
reb-api call validate_evidence_package --endpoint-file backend.endpoint \
  --body-file selected.reb-evidence.json
```

Export scans each requested source to exact EOF. Every row, including unselected
rows, must pass its native contract and duplicate-rejecting parser.
Duplicate ordinary scoped keys fail even when the full source records agree;
conflicts in an omitted payload or extension still fail. No neighboring record
substitutes for a missing selection. Only selected records are projected through
the whitelist. All selected unique blobs are streamed completely and their exact
length and SHA-256 verified. Hash deduplication is scoped to this held snapshot.
No body, raw payload, URL, header, MIME text, unknown field or diagnostic escapes.
Unrequested stores are not inspected. An empty selection performs no store read
and says only `empty_selection`, never empty or disabled capture.

The package is normalized, assigned its semantic ID, and checked by the shared
validator while all leases remain held.
Source row order, selector order, source paths and omitted payload-only changes
do not affect metadata identity. The package contains no export clock or source
file hash. Historical nulls, unknown capture state and missing references are
preserved; the backend build and current capture configuration are not substitutes.

### Cooperative leases and safe local files

Updated event brokers own an exclusive nonblocking `flock` on
`<output-basename>.reb-lock-v1` beside every event, trace and signal output before
opening or truncating any of them. ArtifactReceiver owns
`evidence.reb-lock-v1` inside its root at the library ownership boundary, before
manifest/blob scans or changes. Each immutable regular guard is user-owned,
mode 0600, single-linked and contains exactly `REB_EVIDENCE_GUARD_V1\n`.
Guards are never rewritten, deleted or replaced after creation. Writers retain
them through their last buffered flush and close, including while idle on stdin
or a socket. Exiting or process death releases the lease, not the guard inode.

Export acquires shared nonblocking leases in event-then-artifact order, holding
both until all immutable response bytes and final identity checks are complete.
Active writers and clears fail with 409 instead of waiting. The endpoint does
not stop any process. A broker stop request, disconnected socket or current
capture boolean cannot establish the receiver's state or replace either lease.

Backend clear uses the same exclusive guard for every existing configured output,
acquiring all before any truncation. Missing legacy guards fail with 503 for
export and clear; existing read-only tail APIs continue to read legacy stores.
No caller override or automatic guard creation weakens this boundary. Start a
new recording with the updated producers to obtain guarded stores. Do not add
or replace a marker file to make an old or live capture appear consistent.

Configured roots may resolve a symlink once (including macOS temporary-root
aliases). Below those pinned directory handles, all reads and native writes use
`openat`/descriptor I/O without following symlinks. Regular source and guard
files must be owned by the effective user, single-linked and not group/other
writable; store directories must be user-owned and not group/other writable.
A world-writable directory such as `/tmp` cannot itself be a store root; use a
private subdirectory. The exporter rejects FIFOs, devices, directories used as
files, symlink descendants, traversal and mismatched manifest blob names.
Guard filenames and artifact-owned manifest/blob destinations are reserved from
broker output configuration. Broker outputs cannot live in an artifact root.
This prevents a second writer role or filename alias from bypassing a held lease.

File descriptors and anchored entries are checked for device/inode, complete
size, mtime and ctime; root, blob-directory and guard identities are rechecked
before return. A directory is checked for device/inode only: its size and times
move whenever an entry is added or removed, and the backend keeps derived
indexes beside the stores on its own timers. File replacement, append, truncation and ordinary out-of-contract edits
abort instead of returning an old inode as a new snapshot. Advisory leases
coordinate supported REB writers; they do not authenticate evidence or defeat a
malicious same-user/privileged writer restoring metadata. Only ordinary local
regular filesystems are supported. A kernel read can still block: cooperative
cancellation and bounded work are not a hard cancellation guarantee.

### Export resources and errors

- Each source is scanned to EOF, at any length and row count. An event store
  row is at most 4096 bytes, its separator included, and a manifest row at
  most the manifest's record bound, which fits a 2 MiB URL: those are the
  stores' record contracts, not scan bounds.
- Every identity a scan sees is recorded with the SHA-256 of its row in a
  private temporary SQLite database that SQLite deletes when the export ends,
  so duplicate and conflicting identities, missing selections and sequence
  discontinuities are found across a store of any length without one memory
  entry per row.
- Each selected blob is hashed whole, whatever its size or the sum of them, in
  a fixed 64 KiB read buffer. Zero-byte artifacts still require their
  empty-content hash.
- A package holds every selected record and every relationship and gap they
  produce, at any size. Source rows and output nest at most 32 levels, the
  depth the recursive reader parses; no valid row or package nests deeper.
- The export has no deadline. A request that goes away stops it between reads,
  including parse, scans, hashes, projection, canonicalization and final
  validation, and its permits return. Two package operations share the
  existing I/O pool and wait for it without a deadline. Earlier revisions
  stopped an export at ten seconds and a permit wait at one second, and
  refused a request past 256 KiB, a selection past 1024 events or 64
  artifacts, an event store past 64 MiB or 100000 rows, a manifest past 16 MiB
  or 10000 rows, 32 MiB of retained indexes, 4096 relationships or gaps, and a
  package past 4 MiB.

Errors use fixed messages and empty details, with explicit shared reason codes:
400 `invalid_request`; 404 `target_unavailable` for missing selected identities;
409 `state_conflict` for active leases, changed sources or duplicate/conflicting
identities; 413 `resource_limit` for a source row nested deeper than 32 levels;
408 `timeout` for a stalled request body; 499
`cancelled` when the request goes away; 422 `protocol_error` for malformed
source, hash/length mismatch or inconsistent references; and 503
`dependency_unavailable` for missing guards/sources, unsafe files or unsupported
safe-open platforms. Existing request-body transport size statuses are unchanged.
Exports never retry automatically or silently choose newer evidence.

CLI JSON operations now accept optional `--output PATH` or `--output -`.
File output is a complete mode-0600 temporary in the destination directory,
synced and atomically persisted without clobbering an existing entry; the parent
directory is synced too. Export responses must pass the inert validator before
any final file is published. Invalid or incomplete downloads leave no final
package. Default JSON stdout remains pretty printed; explicit stdout preserves
received JSON bytes. Validation can save an explicit invalid-result JSON when
requested. Output paths are never sent to the server.

## Validation operation

`POST /api/evidence/packages/validate` (`validate_evidence_package`) accepts the
package itself, never a path or URL. Use the existing CLI:

```sh
reb-api describe validate_evidence_package
reb-api call validate_evidence_package --endpoint-file backend.endpoint \
  --body-file selected.reb-evidence.json
```

The OpenAPI request schema describes the expected valid v1 document; the
endpoint also accepts out-of-schema JSON objects to report validation
data. Malformed JSON and nonobject outer bodies are HTTP 400. Duplicate JSON
members are rejected before materialization and produce an HTTP 200 `invalid`
result with `duplicate_json_key`. The CLI rejects duplicate keys locally with a
fixed safe error before sending, and preserves original bytes for accepted bodies.
Unsupported version or serialization,
redaction, or semantics profile produces `unsupported`, without best-effort
interpretation. HTTP 200 by itself never means that a package is valid.

A result has `protocol_version: 1`, `status: valid | invalid | unsupported`, a
nullable `package_id`, `checks`, `origin: untrusted_input`,
`authenticity: not_established`, `artifact_bytes: not_present_not_reverified`,
`issues`, and `issues_truncated`. Checks are `structure`, `semantic_digest`,
`references`, and `metadata_profile`, each `passed | failed | not_run`.
`package_id` is nonnull only when the version/profiles are understood and the
semantic digest matches. Issues contain only enum `code`, enum `section`, and
an array `index` from 0 through 4095 or null. The schema enumerates all issue
codes; arbitrary field names, paths, pointers, snippets, and error text are
never returned from supplied input.

`valid` establishes internal consistency of untrusted metadata. It cannot
establish who produced the document, capture authorization, complete capture,
existence of source stores, or validity of artifact bytes. Recomputing the
metadata digest after modifying a package can produce a different valid
package. Neither a digest nor an export-time verification string is a signature.

## Closed projection and identities

Every schema object is closed and every named field is required. Nullable
fields must be present as null when the historical fact is unavailable. The
root fixes `protocol_version: 1`, `serialization_profile: reb-json-semantic-v1`,
`redaction_profile: reb-metadata-only-v1`, and
`semantics_profile: reb-api-marker-v1`.

An EventKey is `(session_id, process_id, sequence_number)`; an ArtifactKey is
`(session_id, artifact_id)`. Key components are nonzero. Session, sequence,
artifact, navigation, frame, request, context, time, and other u64 values are
canonical decimal strings in 0..18446744073709551615. Event process/thread/tab
and initiator IDs are JSON u32 integers; status/error are JSON i32 integers.
Data lengths are canonical signed i64 strings. Floats, exponents, leading
zeros, plus signs, and negative zero are forbidden by the v1 parser or field
contract. Equal keys from different packages do not authorize a global join.

Event metadata preserves only the schema whitelist:

- Native protocol 2 or 3, key, time, navigation/frame/artifact/request IDs,
  category, type, and payload size are nonnull.
- Thread ID, parent event ID, context halves, initiator IDs, status/error,
  resource type, flags, data lengths, and payload-truncated state are nullable
  historical metadata. Tab ID is always null for v2 and a u32 for v3.
- Payload size is 0..128; flags use only the three known native bits (0..7).
  When both are present, flags and payload-truncated state must agree.
  Resource type is u16. Native `gap` records are coverage observations, not
  selectable ordinary events. Native `unknown` category/type values are invalid.
- Payload bytes, encoding, hashes, previews, URLs, headers, captured values,
  local paths, and unknown extensions are forbidden.
- Operation is null or an exact registry constant. Every event has
  `observation: marker_observed`, `outcome: not_recorded`, and
  `placement: unknown`; a marker cannot manufacture execution success.

Artifact metadata contains the schema whitelist, including a nonzero key,
protocol 1, native IDs, nullable execution context, capture origin/kind,
canonical decimal byte size, lowercase SHA-256, sensitivity,
`verification: sha256_verified_at_export`, and `content: omitted`. Byte size is
any canonical unsigned 64-bit decimal; packages up to this revision named at
most 16777216. Legacy absent provenance is null execution context plus
`capture_origin: unknown`. Kind/sensitivity/origin/context combinations must
match the native artifact contract. URL, MIME, content path, arbitrary metadata,
and bytes are forbidden. Verification is only an untrusted exporter assertion.

Provenance fixes `origin: configured_local_stores`, null producer/browser build
and capture configuration, `capture_authorization: not_attested`, and
`origin_scope: unknown`. Consistency is `empty_selection` or the untrusted claim
`cooperative_stopped_store_v1`; inert validation does not verify a lease.

## Marker registry: reb-api-marker-v1

Only exact, untruncated `web_audio/api_call` payload matches under native
protocol 2 or 3 can name these operations. Unknown strings and prefixes remain
null. The registry is source-owned; extending it requires a new semantics
profile and therefore changes package identity.

- `AnalyserNode.getFloatFrequencyData`, `AnalyserNode.getByteFrequencyData`,
  `AnalyserNode.getFloatTimeDomainData`, `AnalyserNode.getByteTimeDomainData`
- `AudioBuffer.getChannelData`, `AudioBuffer.copyFromChannel`
- `BaseAudioContext.createDynamicsCompressor`, `BaseAudioContext.createAnalyser`,
  `BaseAudioContext.createOscillator`
- `AudioNode.connect`, `AudioScheduledSourceNode.start`,
  `OfflineAudioContext.startRendering`

The source locations are
[Chromium Web Audio markers](../browser/integration/brave/patches/chromium/0002-record-web-audio-function-calls.patch)
and [Brave AudioBuffer markers](../browser/integration/brave/patches/0004-observe-native-web-audio-readbacks.patch).
The analyser and creation markers occur before their underlying operations;
connect and startRendering markers occur at later points, and start is guarded
by the local exception check. These source locations explain the registry;
absent a trustworthy historical producer build, all package placements remain
unknown and outcomes remain not recorded.

## References, gaps, and coverage

Selection and records form an exact bijection with no duplicate tuple identity.
References never expand the selected records. Every nonzero parent-event,
event-artifact, parent-artifact, or artifact-creator claim has one relationship.
Keys and source claims must agree. `included` requires an actual selected target;
`outside_selection`, `missing_in_retained_source`, and `not_inspected` remain
distinct and must agree with section scan/selection state. All relationships
must agree on the retained-source existence of the same scoped target key.
Creator sequence
alone cannot establish a process identity: v1 uses `insufficient_identity` with
a null target and preserves the original creator claim. Only parent-event and
parent-artifact dependency graphs must be acyclic, including no self-links.

Missing-source relationships have exact `missing_reference` gaps. Incomplete
creator relationships have exact `creator_identity_incomplete` gaps. Queue-drop
markers preserve only stream, anchor, time, a canonical count or null with
`count_unknown`, and occurrence count. Sequence discontinuities are inclusive
nonempty ranges within a selected stream window, strictly between adjacent
retained events at `first_missing_sequence - 1` and `last_missing_sequence + 1`.
Known-present relationship targets cannot fall in a missing range, and those
retained neighbors cannot be declared missing. Overlapping or adjacent missing
ranges are invalid; they are not inferred from sparse selection. Queue-drop
counts and sequence holes may overlap and are
never added as a unique loss total. Omitted-source absence and sequence-hole
claims can only be checked for internal consistency, not independently proved.

Coverage records exact selected counts and `complete | not_read` source scans.
Capture state is `partial` only for scoped queue-drop or sequence-discontinuity
observations, and otherwise `unknown`; missing references and incomplete creator
identity do not establish capture loss. A complete retained scan never proves
complete capture. Empty selection uses
`not_requested`, zero selected counts, and `not_read` in both sections, with
`coverage.selection: empty` and `provenance.consistency: empty_selection`
exactly when the total selected record count is zero. Every section, including
an unrequested section, has the four baseline limitations
`capture_configuration_unknown`, `metadata_only`, `origin_scope_unknown`, and
`producer_build_unknown`. Outgoing unresolved relationships add their matching
`reference_outside_selection`, `reference_missing`, `reference_not_inspected`,
or `creator_identity_incomplete` limitation. A true payload-truncated field or
a known native truncation flag adds `payload_was_truncated`, even when the other
historical field is null; queue markers add `capture_gap`; sequence holes
add `sequence_discontinuity`. No other limitation is inferred. Limitations and
the fixed set of six excluded sections are schema-owned enums. No empty array,
disconnected socket, or live configuration establishes disabled, expired, evicted, or policy-filtered
capture. Excluded sections are outside this metadata profile.

## Canonical identity and bounds

`reb-json-semantic-v1` is not RFC 8785. Parse without duplicate members and reject
invalid Unicode, floats, and out-of-range integers. Sort object keys by UTF-8
bytes. Escape quote, backslash, and controls with JSON escapes (short escapes
for backspace, tab, newline, formfeed, and carriage return; other controls use
lowercase `\u00xx`). Other Unicode scalars remain UTF-8 without normalization.
Emit shortest decimal integers, lowercase JSON literals, and no whitespace/BOM.

Normalize only declared sets: selection keys and records by numeric identity
tuple; relationships and gaps lexicographically by the complete canonical JSON
bytes of each safe closed object; limitation/exclusion enums lexicographically.
Object keys within relationship/gap sort keys follow the same UTF-8 order.
Duplicate set members are invalid; marker repetition uses `occurrences`. Do not reorder
arbitrary future ordered arrays. Remove only `package_id`, canonicalize, then
SHA-256 the byte concatenation:

```text
ASCII("REB") || NUL || ASCII("evidence-package") || NUL || ASCII("v1") || NUL || canonical_json
```

The ID is `reb-package-v1:sha256:` followed by 64 lowercase hex characters.
Selection, coverage, profiles, safe records, relationships, and gaps all affect
identity. Omitted source payload bytes do not; artifact original-byte SHA-256
remains separate. No timestamp, path, inode, file offset, or random store ID is
added to this semantic document.

Validation reads a body of any size, with any number of parsed nodes, strings
of any length, and any number of events, artifacts, relationships, gaps and
selectors. Nesting is bounded to depth 32, since the reader recurses once per
level and no valid package nests deeper. Results name the first 64 issues,
set `issues_truncated` when more were found, and stay within 64 KiB; the
verdict covers the whole package. Runtime also enforces its bounded
concurrency. There is no CPU budget or deadline: validation, comparison and
export run until done, and a request that goes away stops them with HTTP 499
`cancelled`. Earlier revisions shared a two-second budget across parsing,
validation and canonicalization, and refused a body past 4 MiB, 200000 parsed
nodes, a string past 4096 UTF-8 bytes, and more than 1024 events, 64
artifacts, 4096 relationships or 4096 gaps; an issue index past 4095 was
dropped. The fixed
embedded validation schema is initialized before any supplied package is read.
Nesting past depth 32 produces safe `invalid` result data with
`resource_limit`; a stalled request body remains HTTP 408. Large object-array uniqueness is checked semantically rather than through
quadratic JSON Schema `uniqueItems`. Body framing limits retain the existing
HTTP transport error behavior. All application errors reuse the existing
[HTTP error contract](http-api.md); supplied-package failures are safe result
data wherever parsing permits.
