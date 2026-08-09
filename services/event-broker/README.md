# Event Broker

The event broker is the center of the system.

## Responsibilities

- Receive normalized event batches from the browser process over local IPC.
- Assign stable identifiers and connect events to processes, frames, navigations, scripts, WASM modules, requests, and artifacts.
- Apply authorization scope, redaction, retention, and backpressure policy.
- Serve a stable evidence model to the research UI and future authorized clients.
- Record gaps whenever events are dropped or unavailable.

## Implemented vertical slice

The broker accepts fixed 128-byte native records on standard input, validates
their protocol envelope, detects sequence gaps, retains a bounded snapshot, and
writes a versioned JSONL evidence store.

```sh
make e2e
```

The command connects a deterministic native producer to the broker and creates
`build/sessions/demo.jsonl`. Invalid or truncated records fail closed. The
broker reports accepted records, invalid records, gaps, and retention evictions.

This is the development transport. The browser-process implementation will
feed the same broker model over authenticated local IPC.
