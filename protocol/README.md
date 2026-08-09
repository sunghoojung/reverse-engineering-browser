# Shared Protocol

This directory owns contracts shared across the browser, event broker, research UI, and MCP server.

## Two representations

1. The renderer hot path uses the fixed 128-byte C++ `EventRecord` in `include/reb/event.hpp`.
2. The browser-process broker expands that record into a versioned transport message for local IPC.

The transport schema will be added after the first Chromium probe identifies the exact fields needed. It must preserve protocol version, sequence number, process, thread, frame, navigation, artifact, parent event, monotonic timestamp, payload length, and dropped-event gaps.

Protocol changes must remain backward-readable for stored research sessions.
