# Native Console v2

Origin Trace executes explicit console commands in a separately launched custom
Brave process with a disposable profile. The UI never evaluates against baseline
tabs. This replaces the [v1 transport](native-console-v1.md); helpers, backend,
packaged assets and browser must be rebuilt together. Old wire versions fail
closed. There is no Inspector session or remote debugging endpoint. Native V8
REPL evaluation uses the pinned engine's debug evaluation API. This does not
promise undetectability or zero active cost.

## User operation

Set `REB_BRAVE_BINARY` to a rebuilt custom browser. Open Console, connect an
authorized HTTP(S) URL, then explicitly select a document. Enter runs a complete
expression; Shift+Enter adds a line; Command/Ctrl+Enter submits immediately.
An unmatched bracket continues on Enter. Up/Down recalls bounded history only
at the first/last line. Undo/redo includes completion insertion. The prompt has
no placeholder and the next draft remains editable during evaluation.

Completion combines static hints with native data properties and global lexical
names. Only ASCII identifier chains cross the native completion boundary; no
calls or computed keys are evaluated. Getters, proxies and unsupported host
properties stop native traversal. Static hints describe APIs and do not prove
runtime availability. Completion is debounced and stale replies are discarded.

Objects expand lazily, 16 properties per page. Previous/Next replace the rendered
page; loading and explicit retry preserve the last successful page. A lower
terminal offset with an empty page is valid when the live object has shrunk;
First properties and explicit Reload remain available. A refreshed
or changed document selection invalidates older value actions. Getters/setters remain labeled.
Proxies and host interceptors are opaque; DOM Elements have explicit native
previews. Function source uses V8's intrinsic FunctionProtoToString, bypassing
page overrides. Source locations link to corresponding URLs in the current
read-only evidence workspace; absent source is reported. The console browser
and captured Sources are separate contexts.

Top-level await uses native V8 REPL semantics. Promise settlement is polled and
waiting stops after ten seconds; Await can be requested again. Stop waiting
releases the handle without rolling back effects or canceling page work.
Commands appear immediately, followed by page messages and the return value.
Page logs/errors are delivered independently of evaluation results. For
`console.log("hello")`, the message is `hello` and the result is `undefined`.
Logs carry level, time, location, bounded stack and a visible drop count.

`$_` reads the previous result as a standalone command. Explicit value actions copy bounded previews,
store an own data property as `window.tempN`, or release a handle. Standalone utilities
`copy(value)`, `inspect(value)`, `getEventListeners(element)`,
`monitorEvents(element)` and `unmonitorEvents(element)` evaluate their argument
once. They are console syntax, not globals installed on the page. Listener
inspection returns native registration metadata and existing callbacks; it does
not compile inline event handlers or read a `handleEvent` getter. Explicit event
monitoring observes click/input/keydown/submit for at most 60 seconds.

Command/Ctrl+F filters console text; levels and timestamps are optional. Clearing
output releases values but preserves command history. A separate transcript
generation discards delayed pre-Clear message replies without invalidating the
execution context or newer explicit commands. Forget command history
removes it. Snippets load into the prompt without automatic execution. Disconnect
kills the owned process groups and removes their profile. Closing the dock keeps
the session alive.

## Experiment activity

The browser collects resource-completion metadata only for documents in its
owned profile and current target listing. Experiment activity opens an isolated
Traffic view, retaining prior delivered metadata for that session/document.
Each record has an event ID, document ID, browser resource ID, completion time,
origin, method, HTTP status, network error, cache state and last evaluation
request ID. Paths, query strings, headers and bodies are excluded. Observation
order is not a causal claim. Completed resources before the initial listing,
other documents and evicted records are not reconstructed or replayed. Refresh
discarding undelivered records increments the visible drop count. The view
never merges these ephemeral records into baseline evidence.

## Ownership and bounds

The path is panel -> loopback Rust broker/API -> private C++ pipe bridge ->
authenticated Unix socket -> browser UI dispatch -> associated renderer Mojo.
Renderer code opens no sockets or files. Exact weak-document references and
renderer tokens reject navigation/replacement. IDs are monotonic, canonical u64
strings. Targets describe HTTP(S) top/child frames in the disposable profile;
worker and paused-call-frame evaluation are not provided by this transport.

Everything remains bounded and ephemeral; values can contain sensitive content.
Nothing is automatically exported or persisted as evidence. Clipboard copying
and page temporary variables require explicit researcher actions.

| Resource | Limit |
| --- | --- |
| JavaScript source / legacy result | 8192 UTF-8 bytes |
| Runtime command / response | 65536 bytes |
| Runtime value preview | 2048 UTF-8 bytes |
| Targets | 64; origin 256, label 128, URL 512 bytes |
| Retained renderer values | 128 handles; expire after 60 seconds, swept once per second |
| Property page / depth | 16 properties plus prototype; UI depth 8; first 65536 array indices |
| Completion | 8 path components, 24 suggestions, 1024 lexical names, 4096 names per prototype, 8 prototypes |
| Renderer messages | 32 / 32 KiB serialized JSON; visible saturating drop count |
| Browser activity | 64 events; visible saturating drop count |
| UI transcript / history | Each 128 entries / 256 KiB; transcript also caps 8192 DOM elements; eviction is visible |
| Snippets / activity view | 16 / 64 KiB snippets; 128 metadata records |
| Event monitors | 8 Elements, four event types each, 60 seconds |
| Synchronous watchdog / dispatch / reply | 200 ms / 500 ms / 2 seconds |
| Session / await wait | One hour / ten seconds |

Renderer message accounting includes JSON escaping and record metadata, so a poll
always fits the response limit. Queue pressure evicts the oldest messages with a
visible drop count; polling or clearing releases their encoded storage.

These are transport and retained-state bounds, not a hard page heap quota.
Retained objects can keep reachable page data alive. Key and event-type enumeration can allocate
engine arrays; active work is covered by the synchronous watchdog. Scheduled
async work is page work and can outlive an evaluation. A transport failure can
occur after side effects. Requests are serialized and never automatically
retried. Loss of the control channel exits the disposable browser.

## Wire and API

`common/native_console_protocol.h` owns trivially copyable little-endian ABI.
Magic remains `0x43424552`; version is **2**. Authentication uses the existing
64-byte hello, user-only socket/token and peer UID check. Request/response headers
remain 32 bytes. Operation 1 lists targets, 2 evaluates legacy source, 3 carries
an exact runtime command as bounded UTF-8 JSON. Type 11 carries a JSON runtime
result; types/statuses 0-10 retain the v1 meanings. Error records contain bounded
text. The operation and response type must agree.

A target is 920 bytes: v1's 272-byte prefix, label length u16, URL length u16,
label[128], URL[512], reserved u32. Target flag 1 is truncated and flag 2 is top
frame. Other reserved fields remain zero. Response flag 1 is truncated.

Runtime commands are evaluate, inspect, complete, poll, await, cancel, release,
store, clear, last, source, listeners, monitor, unmonitor and traffic. Handles
never cross document lifetimes. The [OpenAPI contract](openapi.json) specifies
HTTP fields, requiredness and response shapes. Runtime status is ok, error,
exception, pending or rejected, separate from transport status.

The renderer uses the project-owned `v8-native-console.h` public bridge rather
than V8's internal debug headers. Explicit commands retain native REPL evaluation
with debugger breaks disabled. Verified lexical completion uses the same engine
evaluation path with side effects denied and without REPL mode; a failed lexical
lookup stops completion. The bridge also exposes the existing bounded lexical
enumeration without importing V8's internal check macros into Chromium code.

## Verification

`make native-console-check` exercises the actual bridge and HTTP API against an
explicitly synthetic scripted peer. Native packaged UI QA verifies interaction,
rendering and keyboard behavior using that peer. Neither proves Blink/V8.

After rebuilding the pinned browser, run:

```sh
python3 tools/check-native-console.py --binary build/reb-console --browser /absolute/path/to/custom-brave
```

This checks real logs, lexical completion, object getter isolation, promise
settlement, release, watchdog recovery, UTF-8 bounds, navigation rejection and
control-channel disposal. Browser compilation and real execution remain required
before treating runtime behavior or active performance as verified.
