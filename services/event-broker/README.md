# Event Broker

The event broker is the center of the system.

## Responsibilities

- Receive normalized event batches from the browser process over local IPC.
- Assign stable identifiers and connect events to processes, frames, navigations, scripts, WASM modules, requests, and artifacts.
- Apply authorization scope, redaction, retention, and backpressure policy.
- Serve a stable evidence model to the research UI and future authorized clients.
- Record gaps whenever events are dropped or unavailable.

Project-wide authorization, capture, and privacy policy is defined in
[SAFETY.md](../../SAFETY.md); this README describes the broker's
enforcement contract.

## Implemented vertical slice

The broker accepts fixed 320-byte native records on standard input or an
authenticated Unix socket, validates their protocol envelope, enum values,
flags, payload bounds, and reserved
fields, enforces an immutable category allowlist and monotonic expiration,
detects sequence gaps, retains a bounded snapshot, and writes a
versioned JSONL evidence store. Sequence tracking is bounded by the broker
capacity, and tracker evictions are reported explicitly in broker stats.
Retention uses contiguous storage reserved once at construction. Accepted
records fill the slots, then overwrite the oldest slot without allocating or
moving the other records. Snapshots copy the newest requested suffix in arrival
order across at most two contiguous ranges. Stream tracking reserves its hash
buckets up front; newly observed streams still allocate tracking entries.
Standard-input replays buffer store writes until the replay ends. Live socket
captures use bounded reads of up to 256 records and flush after every received
batch. This keeps low-volume evidence visible promptly while reducing socket
and storage calls on high-volume captures. JSON encoding appends integers and
payload hex directly into one reserved output string instead of constructing a
locale-aware stream and an intermediate payload string for every event.
When the tracker reaches capacity, it evicts streams in deterministic insertion
order so repeated evidence replays produce the same gap accounting.
If combined gap counts exceed 64-bit range, the count saturates at its maximum
and a separate saturation flag is reported instead of wrapping silently.
Accepted gap markers also accumulate explicit queue-drop totals across ring
eviction. They may overlap observed sequence jumps. The low-level broker
snapshot is not the Traffic retention policy: the disk-backed HTTP reader owns
independent bounded general and network windows and reports their scan scope.
Protocol v2 stores 64-bit values as canonical decimal strings so opaque IDs and
large counters remain exact in JavaScript clients.
Protocol v3 additionally carries a browser-global, session-local `tab_id` for
network events while preserving the fixed record size.

When `--trace-store` is present, the broker also maintains a bounded cold-path
correlation index and writes a versioned Origin Trace edge sidecar. The index
uses identifiers already in accepted events and never infers value flow. Each
event emits at most three direct edges. Renderer and browser request IDs are
separate namespaces: the exact bridge is the browser event's session ID plus
`initiator_process_id` and `initiator_request_id`, matched only to a retained
renderer `request_initiated` event, not to any equal-numbered request record.
The producer fills those initiator fields only for renderer-issued subresource
factories. Browser-issued loads leave them zero. The browser lifecycle request
id stays in its own namespace.

Independent process queues may deliver the browser lifecycle first. The index
retains at most its configured capacity of pending exact-identity links and
resolves them when the initiation arrives, emitting up to that capacity of
additional edges in deterministic reference order. Both endpoints must remain
retained, and observed duplicate initiation identities fail closed for later
joins. Missing, zero, ambiguous or evicted identities remain unjoined; host,
URL and timestamp similarity never supply a link. Event and edge wire formats
are unchanged, and the original request IDs stay intact. Existing sidecars are
not rewritten. `make native-request-identity-check` exercises the actual broker
with synthetic disjoint IDs, both process arrival orders, reuse ambiguity and
retention limits. `make e2e` additionally reads those same broker stores through
the Rust HTTP API and verifies the repaired edges survive readback. Request signal profiles remain arrival-order snapshots; this
repair does not backfill their separate sidecar.

The renderer queue, browser transport, and disabled capture path are unchanged. Parent and initiator identifiers are
observed relationships; artifact/request joins are visibly correlated.

When `--signal-store` is present, a separate bounded cold-path index writes one
request signal profile for every accepted request start. Profiles summarize
Canvas, WebGL, Web Audio, device and layout, Permissions, Storage, WebRTC, and Runtime activity
using counts and exact event references only. Explicit parent-chain evidence is
observed; earlier events sharing session, process, navigation, and frame are
correlated. The index never records browser API values or request content.

```sh
make e2e
```

The command connects a deterministic native producer to the broker and creates
`build/sessions/demo.jsonl`. Invalid or truncated records fail closed. The
broker reports accepted records, invalid records, gaps, and retention evictions.

Large artifact bytes are intentionally outside this service and its event
queue. `reb-artifact-receiver` owns the independently bounded artifact stream,
immutable blob store, hashing, and manifest. Events reference artifacts by ID;
the event broker never copies their content.

The socket mode requires one session identifier and a user-owned mode-0600
token file. The broker creates the token when needed, creates a mode-0600 Unix
socket, authenticates one Brave connection, rejects records from any other
session, and removes the socket after disconnect.
For a live session, `SIGUSR1` requests a graceful stop. The broker flushes its
stores and closes the authenticated connection; the browser then disables its
native probes. This signal does not delete evidence.

```sh
build/reb-event-broker \
  --store build/sessions/live/events.jsonl \
  --trace-store build/sessions/live/origin-trace.jsonl \
  --signal-store build/sessions/live/request-signals.jsonl \
  --socket /tmp/origin-trace.sock \
  --token-file build/sessions/live/broker.token \
  --session-id 123 \
  --category-mask 261 \
  --duration-seconds 3600
```

Socket sessions require both policy options. Category bits follow the native
category enum: Canvas is `1`, WebGL `2`, Web Audio `4`, Navigator `8`,
Permissions `16`, Storage `32`, WebRTC `64`, WASM `128`, and Network `256`.
Mask `261` enables the currently implemented Canvas, Web Audio, and Network
probes. Mask `257` excludes Web Audio while leaving Canvas and Network enabled.
The broker rejects categories outside the mask before sequence accounting or
storage, and closes its listener or browser connection when the monotonic
deadline expires.

Run `make e2e` to validate deterministic ingestion and evidence storage without
launching Brave. Run `make live` after a complete custom
Brave app build to start the broker, Origin Trace, and Brave as one session.

## Store ownership

Every configured output has an immutable mode-0600 `<basename>.reb-lock-v1`
guard. All exclusive nonblocking leases are acquired before any output is
truncated and retained through the last buffered flush and close. Source files
are opened relative to pinned directories without following symlinks; hardlink
aliases, guard filenames and artifact-owned destinations are rejected. Store
roots must be user-owned and not group/other writable. Use a private directory
below `/tmp`, not `/tmp` itself. A busy guard fails startup without truncation.
The fixed `Event store ready` diagnostic follows successful safe opening.

Do not remove or replace guards. Shared selected-package export and backend
clear use the same guards; stop this writer before either operation. See
[Evidence Package v1](../../protocol/evidence-package-v1.md#cooperative-leases-and-safe-local-files).
