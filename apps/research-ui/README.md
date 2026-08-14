# Research UI

The research UI is the human-facing investigation workspace.

## Responsibilities

- Start from a captured request and let the researcher choose a header, cookie,
  or body field to investigate.
- Show a backward evidence graph through serialization, transforms, runtime
  values, browser inputs, and native probe evidence.
- Keep confidence visible on every relationship: Exact, Matched, Differential,
  Correlated, or Unknown.
- Show correlated requests, scripts, frames, API probes, WASM modules, and artifacts.
- Start and stop explicitly authorized research sessions.
- Display dropped-event counts and evidence gaps instead of hiding them.
- Work from the event broker's versioned API.

## Boundary

The UI does not inject hooks into a page and does not communicate directly with
a renderer. It reads evidence through the local event broker so capture and
presentation remain separate.

## Run the application

On macOS, build and open the native application window:

```sh
make app
```

The application uses a native WebKit shell and reads its bundled local evidence
store directly. It has no browser address bar and does not require a localhost
server. The build output is `build/Origin Trace.app`.

For development, the same interface can still run in a browser:

```sh
make ui
```

Open `http://127.0.0.1:7319`. The dependency-free local server reads the same
JSONL evidence store written by the native broker. The network workspace groups
lifecycle events by request and provides request filters plus Headers, Payload,
Preview, Response, Initiator, and Timing inspectors. Loading, empty,
disconnected, malformed-event, and sequence-gap states remain visible. The
trace workspace still combines a sample request field backtrace with live broker
events, with sample and live evidence always labeled separately.

The Sources workspace reads the separate artifact manifest and immutable blobs
created by `reb-artifact-receiver`. Its Page navigator follows the DevTools
frame, origin, directory, and file organization. The center editor provides
tabs, line numbers, `Command+P` or `Control+P` open-file navigation,
`Command+F` or `Control+F` search, original and readable-derived views, and WASM
hex display. The right side keeps the familiar debugger pane structure while
runtime controls remain disabled until native debugging is implemented.

Artifact content responses are capped at 2 MiB and use attachment, `nosniff`,
and sandbox headers. The editor renders at most 20,000 lines and inserts all
captured content as text. The catalog keeps original byte size and SHA-256
visible even when the viewer shows a bounded preview.

The UI validates the broker envelope and every event before replacing the last
known-good view. Protocol v2 transports 64-bit identifiers, timestamps, and
transfer sizes as canonical decimal strings so browser-side correlation and
timing calculations remain exact. Browser network events also carry both
64-bit halves of the BrowserContext token, which keeps BrowserContext-local
request identifiers distinct. Development stores written before those token
fields were added remain readable when both fields are absent. Legacy v1
numeric records remain readable when their integer values are within
JavaScript's exact range.

The current broker does not capture structured request fields or arbitrary
JavaScript data flow. The sample backtrace demonstrates the intended workflow,
and its unobserved producer boundary is explicitly marked **Unknown**. The UI
must not promote timing correlation to exact causality.

Evidence values are inserted with DOM text nodes, never HTML, so captured page
content cannot become executable UI markup.
