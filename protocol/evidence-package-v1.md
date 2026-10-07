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
request, at most 256 KiB:

```json
{"protocol_version":1,"profile":"reb-metadata-only-v1","selection":{"events":[{"session_id":"7","process_id":42,"sequence_number":"1"}],"artifacts":[{"session_id":"7","artifact_id":"9"}]}}
```

Only `profile` is optional, with the default shown. Both selector arrays are
required; maximum counts are 1024 events and 64 artifacts. Duplicate keys,
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
rows, must pass its native contract and bounded duplicate-rejecting parser.
Duplicate ordinary scoped keys fail even when the full source records agree;
conflicts in an omitted payload or extension still fail. No neighboring record
substitutes for a missing selection. Only selected records are projected through
the whitelist. All selected unique blobs are streamed completely and their exact
length and SHA-256 verified. Hash deduplication is scoped to this held snapshot.
No body, raw payload, URL, header, MIME text, unknown field or diagnostic escapes.
Unrequested stores are not inspected. An empty selection performs no store read
and says only `empty_selection`, never empty or disabled capture.

The package is normalized, assigned its semantic ID, and checked by the shared
validator while the same whole-operation deadline and all leases remain held.
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

Descriptors and anchored entries are checked for device/inode, complete size,
mtime and ctime; root, blob-directory and guard identities are rechecked before
return. File replacement, append, truncation and ordinary out-of-contract edits
abort instead of returning an old inode as a new snapshot. Advisory leases
coordinate supported REB writers; they do not authenticate evidence or defeat a
malicious same-user/privileged writer restoring metadata. Only ordinary local
regular filesystems are supported. A kernel read can still block: cooperative
deadlines and bounded work are not a hard cancellation guarantee.

### Export limits and errors

- Events: 64 MiB complete scan, 100000 nonempty rows, 4096 bytes per row including
  its separator. Manifest: 16 MiB, 10000 rows, 8192 bytes per row.
- Each selected blob: 16 MiB; distinct verified bytes: 128 MiB; fixed 64 KiB read
  buffer. Zero-byte artifacts still require their empty-content hash.
- Retained source indexes/projections: 32 MiB with conservative preallocation
  accounting. Relationships and gaps: 4096 each. Package bytes: 4 MiB.
- The same parsed-node, depth, string and cardinality bounds apply to source
  rows and output. One ten-second cooperative deadline covers the whole export,
  including parse, scans, hashes, projection, canonicalization and final validation.
  Two package operations share the existing bounded I/O pool; total permit wait
  is separately capped at one second. Disconnects do not release running permits.

Errors use fixed messages and empty details, with explicit shared reason codes:
400 `invalid_request`; 404 `target_unavailable` for missing selected identities;
409 `state_conflict` for active leases, changed sources or duplicate/conflicting
identities; 413 `resource_limit`; 408 `timeout`; 422 `protocol_error` for malformed
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
endpoint also accepts out-of-schema JSON objects to report bounded validation
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
at most 16777216. Legacy absent provenance is null execution context plus
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

Validation is bounded to a 4 MiB body, 200000 parsed nodes, depth 32, and 4096
UTF-8 bytes per string. There are at most 1024 events, 64 artifacts, 4096
relationships, and 4096 gaps, with the same selector bounds. Results contain at
most 64 issues and 64 KiB. Runtime also enforces its bounded concurrency and
two-second cooperative CPU budget; these are not hard process-kill guarantees.
Parsed resource-limit or CPU-budget exhaustion produces safe `invalid` result
data with `resource_limit`; request-body read/admission deadlines remain HTTP
408. Large object-array uniqueness is checked semantically rather than through
quadratic JSON Schema `uniqueItems`. Body framing limits retain the existing
HTTP transport error behavior. All application errors reuse the existing
[HTTP error contract](http-api.md); supplied-package failures are safe result
data wherever parsing permits.
