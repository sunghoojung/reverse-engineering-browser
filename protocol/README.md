# Shared Protocol

This directory owns contracts shared across the browser, event broker, and
research UI.

## Two representations

1. The renderer hot path uses the fixed 128-byte C++ `EventRecord` in `include/reb/event.hpp`.
2. The browser-process broker expands that record into a versioned transport message for local IPC.

The first transport schema is implemented by `EventToJson`. Each JSONL record
preserves protocol version, sequence number, process, thread, frame, navigation,
artifact, parent event, monotonic timestamp, category, type, payload length, and
the bounded inline payload as hexadecimal bytes. Hex encoding prevents untrusted
page bytes from being interpreted as markup or text by downstream clients.

The native producer-to-broker boundary currently uses exact 128-byte
`EventRecord` frames over a pipe. The Chromium adapter will replace that
development pipe with shared memory and Mojo without changing the evidence
model consumed by the broker and UI.

Protocol changes must remain backward-readable for stored research sessions.
