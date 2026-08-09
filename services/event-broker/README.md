# Event Broker

The event broker is the center of the system.

## Responsibilities

- Receive normalized event batches from the browser process over local IPC.
- Assign stable identifiers and connect events to processes, frames, navigations, scripts, WASM modules, requests, and artifacts.
- Apply authorization scope, redaction, retention, and backpressure policy.
- Serve the same evidence model to the research UI and MCP server.
- Record gaps whenever events are dropped or unavailable.

## First vertical slice

The first implementation should accept one Canvas probe event, connect it to one navigation, and expose it through a small command-line query before adding a database, UI, or MCP tools.
