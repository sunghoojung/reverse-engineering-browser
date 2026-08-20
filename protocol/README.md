# Shared Protocol

This directory owns contracts shared across the browser, event broker, and
research UI.

## Two representations

1. Native hot paths use the fixed 320-byte C++ `EventRecord` in
   `include/reb/event.hpp`.
2. The browser-process broker expands that record into a versioned transport
   message for local IPC.

The first transport schema is implemented by `EventToJson`. Each JSONL record
preserves protocol version, sequence number, process, thread, frame, navigation,
artifact, parent event, request, browser context, and initiator identifiers,
HTTP status, transfer sizes, resource type, flags, monotonic timestamp,
category, type, payload length, and the bounded inline payload as hexadecimal
bytes. Hex encoding prevents untrusted page bytes from being interpreted as
markup or text by downstream clients.

Protocol v2 encodes every signed or unsigned 64-bit field as a canonical
base-10 JSON string. This preserves exact identifiers, sequence numbers,
timestamps, and byte counts in clients whose JSON number type cannot represent
all 64-bit integers. Smaller integer fields remain JSON numbers. The native
header and record have explicit zero-valued reserved fields and no implicit
padding, so raw record transfer cannot expose indeterminate bytes.

Browser network events carry both 64-bit halves of Chromium's opaque
`BrowserContext::UniqueToken()`. The full token plus the browser-process request
identifier disambiguates independent per-profile Brave request-ID generators.
Non-browser events use zero for both halves. The token is session-local opaque
correlation metadata and does not expose a profile path or captured content.

For network events, `resource_type` carries the integral value from the pinned
Chromium `blink::mojom::ResourceType` contract. Browser adapters must translate
or version this field if upstream changes that enum. Protocol v2 uses value 13
for XMLHttpRequest.

Default network payload prefixes contain only the request method and
destination host. URL paths, queries, fragments, credentials, headers,
cookies, and bodies require a separate visibly enabled sensitive-capture mode.

Renderer-to-browser delivery uses exact 320-byte `EventRecord` objects in a
bounded shared-memory queue. Mojo carries session lifecycle and coalesced
wake-ups, not individual events. The initial configuration carries a nonzero
category bitmask and a monotonic expiration deadline. Both renderer and browser
capture boundaries reject disabled or expired events before enqueueing them.
Browser-to-broker delivery uses the same exact records over a user-only Unix
socket. Before records are accepted, Brave sends
a fixed 64-byte hello containing the IPC magic, version, size, session ID, and
a 256-bit token loaded from a user-owned mode-0600 file. The broker compares the
token in constant time and rejects records whose session differs from the
authenticated connection. The broker independently applies the same category
mask before sequence accounting or storage, and closes the session at its own
monotonic deadline.
When a renderer queue drops records, the browser emits a `gap` record after it
drains the retained batch. Its UTF-8 decimal payload is the number of newly
dropped records. The gap record repeats the last retained sequence number so it
does not hide the missing sequence range from broker accounting.

## Large artifact transfer

Large JavaScript files, WASM modules, source maps, and explicitly approved
response bodies never use `EventRecord`, the renderer ring, or the broker event
queue. They use the separate version 1 artifact stream defined by
`include/reb/artifact.hpp`. Its fixed 128-byte header carries kind, byte count,
correlation identifiers, metadata lengths, and an optional expected SHA-256,
followed by bounded URL, MIME, and original-content byte ranges.

Authenticated socket mode adds a fixed 32-byte acknowledgment after each
frame. The receiver identifies the artifact and reports an accepted, invalid,
too-large, policy, conflict, or I/O status only after storage processing is
complete. Browser capture reports `artifact_captured` after an accepted
acknowledgment and `artifact_capture_failed` for every other local or receiver
outcome. These event types use the `artifact` category in the normal event
stream, so a missing artifact is explicit evidence rather than silent loss.

The receiver defaults to 16 MiB per artifact and 256 MiB per session store. It
streams and hashes content into immutable content-addressed storage. Response
bodies fail closed unless the session receiver is explicitly started with
sensitive capture enabled. See
`docs/architecture/artifact-transfer-channel.md` for the low-level design.

## VM finding payload

VM investigation evidence uses the `vm` category and `vm_finding` event type.
Its version-1 `VmFindingPayload` occupies the existing 128-byte inline payload,
so it adds no allocation, variable-length framing, or side channel to the
native event path. The fixed little-endian record is defined in
`include/reb/vm_finding.hpp`. The tracked Brave overlay mirrors that ABI in
`native_vm_finding.h`, with compile-time size, offset, and enum synchronization
checks in the native test suite.

Each finding has stable finding, investigation, subject, and related-subject
identifiers. Its kind is one of interpreter, guest program, invocation, host
binding, hypothesis, or coverage. Host runtime and confidence are independent
fields because an observed WebAssembly boundary does not prove guest bytecode
semantics. Optional flags identify artifact ranges, partial evidence, dynamic
observations, and nested guest containers. Coverage findings carry bounded
observed and total counts; other finding kinds must leave those counters zero.

Labels are bounded printable ASCII metadata. The decoder rejects unknown enum
values, flags, nonzero reserved bytes, dirty label tails, invalid ranges, and
inconsistent coverage. Artifact bytes remain outside this record and are
referenced by the event header's `artifact_id` plus the optional range.

## Cold-path VM analysis document

Detailed deterministic VM analysis uses the version 1 JSON contract in
`vm-analysis-v1.schema.json`. The stored document is derived, content-addressed
evidence under `artifacts/analysis/vm-analysis-v1.json`; it never replaces the
immutable artifact bytes or the fixed-size timeline summary.

The document names its producer, analyzer version, profile and profile digest,
input digests, limits, rule weights, per-rule observations, separate VM and
anti-bot scores, coverage omissions, residual unknowns, bytecode snapshots,
and evidence graph. Graph edges use only `observed`, `inferred`, `correlated`,
or `unknown`. Request projections add selection metadata but do not change the
stored document or claim exact value provenance.
The schema closes consumer-owned objects to additional properties, requires
canonical decimal identifiers and digest formats, and includes top-level input
coverage for bounded or malformed manifest and event records.

Protocol changes must remain backward-readable for stored research sessions.
