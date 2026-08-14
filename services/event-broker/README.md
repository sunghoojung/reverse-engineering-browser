# Event Broker

The event broker is the center of the system.

## Responsibilities

- Receive normalized event batches from the browser process over local IPC.
- Assign stable identifiers and connect events to processes, frames, navigations, scripts, WASM modules, requests, and artifacts.
- Apply authorization scope, redaction, retention, and backpressure policy.
- Serve a stable evidence model to the research UI and future authorized clients.
- Record gaps whenever events are dropped or unavailable.

## Implemented vertical slice

The broker accepts fixed 320-byte native records on standard input or an
authenticated Unix socket, validates
their protocol envelope, enum values, flags, payload bounds, and reserved
fields, enforces an immutable category allowlist and monotonic expiration,
detects sequence gaps, retains a bounded snapshot, and writes a
versioned JSONL evidence store. Sequence tracking is bounded by the broker
capacity, and tracker evictions are reported explicitly in broker stats.
When the tracker reaches capacity, it evicts streams in deterministic insertion
order so repeated evidence replays produce the same gap accounting.
If combined gap counts exceed 64-bit range, the count saturates at its maximum
and a separate saturation flag is reported instead of wrapping silently.
Protocol v2 stores 64-bit values as canonical decimal strings so opaque IDs and
large counters remain exact in JavaScript clients.

```sh
make e2e
```

The command connects a deterministic native producer to the broker and creates
`build/sessions/demo.jsonl`. Invalid or truncated records fail closed. The
broker reports accepted records, invalid records, gaps, and retention evictions.

The socket mode requires one session identifier and a user-owned mode-0600
token file. The broker creates the token when needed, creates a mode-0600 Unix
socket, authenticates one Brave connection, rejects records from any other
session, and removes the socket after disconnect.

```sh
build/reb-event-broker \
  --store build/sessions/live/events.jsonl \
  --socket /tmp/origin-trace.sock \
  --token-file build/sessions/live/broker.token \
  --session-id 123 \
  --category-mask 257 \
  --duration-seconds 3600
```

Socket sessions require both policy options. Category bits follow the native
category enum: Canvas is `1`, WebGL `2`, Web Audio `4`, Navigator `8`,
Permissions `16`, Storage `32`, WebRTC `64`, WASM `128`, and Network `256`.
Mask `257` enables the currently implemented Canvas and Network probes. The
broker rejects categories outside the mask before sequence accounting or
storage, and closes its listener or browser connection when the monotonic
deadline expires.

Run `make socket-e2e` to validate authentication, permissions, ingestion, and
socket cleanup without launching Brave. Run `make live` after a complete custom
Brave app build to start the broker, Origin Trace, and Brave as one session.
