# Evidence Package v1

The [JSON Schema](evidence-package-v1.schema.json) defines the closed
`reb-evidence-package` metadata contract. The same reachable definitions are
embedded under `EvidencePackage*` components in [OpenAPI](openapi.json).
[SAFETY.md](../SAFETY.md) remains the authorization and capture policy.

This slice provides only inert validation of a supplied document. It does not
export stored evidence, acquire store leases, import records into backend
state, persist packages, copy artifact bytes, fetch references, or execute
analysis helpers. Export requires a separate stopped-store implementation.

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
