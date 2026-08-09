# Research UI

The research UI is the human-facing investigation workspace.

## Responsibilities

- Show correlated requests, scripts, frames, API probes, WASM modules, and artifacts.
- Start and stop explicitly authorized research sessions.
- Display dropped-event counts and evidence gaps instead of hiding them.
- Work from the event broker's versioned API.

## Boundary

The UI does not inject hooks into a page and does not communicate directly with
a renderer. It reads evidence through the local event broker so capture and
presentation remain separate.

## Run it

```sh
make ui
```

Open `http://127.0.0.1:7319`. The dependency-free local server reads the same
JSONL evidence store written by the native broker. The timeline supports live
refresh, category filtering, text search, and visible sequence-gap accounting.

Evidence values are inserted with DOM text nodes, never HTML, so captured page
content cannot become executable UI markup.
