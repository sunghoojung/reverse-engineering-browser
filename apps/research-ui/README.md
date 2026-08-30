# Research UI

The research UI is the human-facing investigation workspace.

## Responsibilities

- Start from a captured request and let the researcher choose a header, cookie,
  or body field to investigate.
- Show a backward evidence graph through serialization, transforms, runtime
  values, browser inputs, and native probe evidence.
- Keep observed, correlated, and unknown relationships visually distinct.
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

For a live custom-Brave capture, run:

```sh
make live
```

The launcher passes the broker evidence store and Unix-socket path to Origin
Trace. The application continues to show the last valid evidence if the broker
disconnects or the session expires and marks the capture as offline. Raw
browser records stay on the Brave-to-broker socket; the UI reads the broker's
normalized store. Live sessions enable Canvas, Web Audio, Network, and Artifact
for one hour by default with category mask `1285`;
`REB_CAPTURE_CATEGORY_MASK` and `REB_CAPTURE_DURATION_SECONDS` change those
low-level startup limits.

For development, the same interface can still run in a browser:

```sh
make ui
```

Open `http://127.0.0.1:7319`. The dependency-free local server reads the same
JSONL evidence store written by the native broker. The network workspace groups
lifecycle events by request and provides request filters plus Headers, Payload,
Preview, Response, Initiator, Timing, and Signals inspectors. Signals presents
the bounded Canvas, WebGL, Web Audio, Navigator, Permissions, Storage, and
WebRTC evidence profile for one exact live request. Loading, empty,
disconnected, malformed-event, and sequence-gap states remain visible. The
timeline shows each Web Audio event's fixed operation name, while Signals keeps
only its bounded category count, relation, confidence, and event references.
The trace workspace builds a live request-level origin chain from the broker's
versioned edge sidecar. Structured request fields are not required. It selects
one exact request-start event, shows observed and correlated links separately,
and makes missing retained evidence visible as named gaps.

The event endpoint reads backward from the append-only JSONL store and parses
only its requested, bounded tail window. UI refresh cost therefore follows the
visible event count instead of the total capture size. Offline evidence-store
validation still scans the complete file through `tools/validate-evidence-store.py`.
The reader rejects JSONL records larger than 4 KiB, which is safely above the
current fixed event contract and keeps malformed-record work bounded.
Event and artifact polling also sends explicit entity tags. When neither store
nor broker connectivity changed, the server returns an empty `304` response and
the UI skips JSON parsing and DOM reconstruction.

The Sources workspace separates the live Page tree from Captured evidence.
Captured reads the artifact manifest and immutable blobs created by
`reb-artifact-receiver`. Page reads scripts reported by the authorized live
Brave debugger. Both use the DevTools origin, directory, and file organization.
The center editor provides tabs, line numbers, `Command+P` or `Control+P`
open-file navigation, `Command+F` or `Control+F` search, original and
readable-derived views, and WASM display.

During `make live`, the debugger sidebar uses Chromium's Debugger, Runtime,
Log, and DOMDebugger protocol domains. It supports line breakpoints, pause,
resume, step over, step into async continuations, step out, frame restart,
synchronous and async call stacks, bounded local, closure, and global scopes,
watch expressions, pause-on-exception modes, XHR/fetch and selected event
listener breakpoints, multiple page target selection, and a bounded console
drawer. Watch evaluation requests `throwOnSideEffect` with a 500 ms timeout.
Arbitrary protocol commands, interactive console evaluation, variable edits,
and live source edits are not exposed in Baseline mode.

The Memory workspace uses the same authorized live target for bounded,
read-only object discovery. A search can combine an own-property name,
primitive value, class name, regular expression, and JSON structural shape.
Structural matching compares bounded property-and-type tokens and can
optionally include primitive values. Each request examines at most 25,000
candidates for 750 milliseconds, returns at most 50 objects, and previews at
most 16 own properties per result. Accessor properties remain visible as
accessors, but their getters are never invoked. Object references are released
after every search, results remain ephemeral, and the evidence store is not
changed. Candidate, result, and time limits are reported as partial coverage
instead of being hidden.

The live debugger is ephemeral. Brave uses a private profile inside the
session directory and chooses a random loopback debugging port. The research
server validates the browser endpoint, exposes only allowlisted actions,
rejects cross-site requests, caps scripts, frames, properties, messages,
expressions, and source bytes, and never writes runtime scope or console values
to the evidence store. Closing the session stops the bridge.

Debugger state delivery is generation-tagged and change-driven. A conditional
request can wait for up to 25 seconds, and an unchanged request reads only the
generation counter instead of copying the bounded debugger snapshot. The UI
coalesces update bursts, reuses console rows, skips unchanged debugger panes,
and updates source decorations without rebuilding the source editor.

During `make live`, Brave captures authorized JavaScript and WASM response
bodies through the separate authenticated artifact socket. The catalog refreshes
while the session runs, so acknowledged artifacts appear without restarting
Origin Trace. Capture and transfer failures remain inspectable in the evidence
timeline as `artifact_capture_failed` events.

Artifact content responses are capped at 2 MiB and use attachment, `nosniff`,
and sandbox headers. The editor renders at most 20,000 lines and inserts all
captured content as text. The catalog keeps original byte size and SHA-256
visible even when the viewer shows a bounded preview.

Pass `--socket /path/to/broker.sock` to the development server when it should
also report live broker connectivity.

Pass `--devtools-active-port /path/to/DevToolsActivePort` to enable the live
debugger bridge. This path must belong to an explicitly authorized browser
launched with `--remote-debugging-port=0` and an isolated user-data directory.

Pass `--trace-store /path/to/origin-trace.jsonl` when the edge sidecar is not
next to the default demo store. The origin-trace endpoint reads at most 10,000
events, 30,000 edges, and 10,000 artifact records, rejects oversized or
malformed records, traverses at most 32 steps, and supports entity-tag
revalidation. The native application
uses the same limits and contract without a localhost server.

Pass `--signal-store /path/to/request-signals.jsonl` when the request signal
profile sidecar is not next to the default demo store. The endpoint selects an
exact session, request, process, and sequence root, reads at most 10,000
profiles, rejects records larger than 8 KiB, and supports entity-tag
revalidation. Observed parent chains and correlated same-context activity stay
visibly distinct.

Captured JavaScript and WebAssembly artifacts are analyzed automatically on
the cold path. The UI reads `/api/analysis/vm` for the automatic scan and
`/api/analysis/vm?request_id=ID` for request-first correlation. Analysis is
bounded, deterministic, and stored at
`ARTIFACT_STORE/analysis/vm-analysis-v1.json`. A failed or malformed analysis
does not hide the last valid timeline evidence. The native live-session
launcher runs the same analyzer when its event or artifact inputs change.
Manifest and event JSONL reads have explicit line and record limits. Invalid
canonical identifiers, digests, or artifact paths become named failure or
partial-coverage records before content is read. Cached analysis is served only
after its profile and document digests are verified. JavaScript function-region
count and cumulative region work are also bounded; exhausting either limit
produces a named partial-coverage omission.

The WebAssembly frontend decodes bounded function bodies and instruction
immediates. It scores dispatch only when a decoded branch table or indirect
call occurs inside a decoded loop, and reports the function and body range for
each observation. Raw immediate bytes and the data-count section are not
treated as opcodes or guest byte data. JavaScript signals must occur within one
function region before they can combine into a likely-VM result.

The analyzer never runs in the renderer probe, artifact receiver, event broker,
or browser-process capture path.

The VM Lab combines versioned `vm_finding` timeline records with the cold-path
analysis document. It separates interpreter, guest program, invocation, host
binding, hypothesis, and coverage evidence, and shows runtime, two-tier
confidence, decomposed scores, rule evidence, related requests, artifact
ranges, residual unknowns, and partial coverage without inventing missing
semantics. Empty, disconnected, malformed-analysis, malformed-finding, and
sequence-gap states remain visible. Unlike the request backtrace demonstration,
VM Lab does not populate sample findings in standalone preview mode.

The UI validates the broker envelope and every returned event before replacing
the last known-good view. Protocol v2 transports 64-bit identifiers,
timestamps, and transfer sizes as canonical decimal strings so browser-side
correlation and timing calculations remain exact. Browser network events also
carry both 64-bit halves of the BrowserContext token, which keeps
BrowserContext-local request identifiers distinct. Development stores written
before those token fields were added remain readable when both fields are
absent. Legacy v1 numeric records remain readable when their integer values are
within JavaScript's exact range.

The current broker does not capture structured request fields or arbitrary
JavaScript data flow. Request Origin Trace follows event relationships, not
field-level value provenance. The UI must not promote identifier or timing
correlation to exact causality.

Evidence values are inserted with DOM text nodes, never HTML, so captured page
content cannot become executable UI markup.
