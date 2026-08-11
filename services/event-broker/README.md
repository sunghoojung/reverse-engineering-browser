# Event Broker

The event broker is the center of the system.

## Responsibilities

- Receive normalized event batches from the browser process over local IPC.
- Assign stable identifiers and connect events to processes, frames, navigations, scripts, WASM modules, requests, and artifacts.
- Apply authorization scope, redaction, retention, and backpressure policy.
- Serve a stable evidence model to the research UI and future authorized clients.
- Record gaps whenever events are dropped or unavailable.

## Implemented vertical slice

The broker accepts fixed 320-byte native records on standard input, validates
their protocol envelope, enum values, flags, payload bounds, and reserved
fields, detects sequence gaps, retains a bounded snapshot, and writes a
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

This is the development transport. The browser-process implementation will
feed the same broker model over authenticated local IPC.
