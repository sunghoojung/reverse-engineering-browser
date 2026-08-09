# Research UI

The research UI is the human-facing investigation workspace.

## Responsibilities

- Show correlated requests, scripts, frames, API probes, WASM modules, and artifacts.
- Start and stop explicitly authorized research sessions.
- Display dropped-event counts and evidence gaps instead of hiding them.
- Work from the event broker's versioned API.

## Boundary

The UI does not inject hooks into a page and does not communicate directly with a renderer. It requests evidence and actions through the local event broker so the UI and MCP server observe the same state.

The application framework will be selected when the first broker API is usable.
