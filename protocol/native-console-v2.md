# Native Console v2

Origin Trace executes explicit mutable main-world console commands through the
native console protocol. **Disposable browser session is the default**, including
when a live capture has documents. It launches a separate custom Brave profile.
Live execution is a separate explicit opt-in: choose **Live capture (explicit
opt-in)**, select one exact captured document, check the selected-document
mutation authorization, then Connect. `connect_live` requires `confirm_live:true`.
Only that document is authorized; no browser is launched for this binding.

Live documents come directly from the native bridge attached to that same
capture browser, not from a URL/CDP join. Native IDs represent exact weak-document
generations, scoped to the nonsecret random `binding_id` in that listing. Connect
must echo that exact binding ID; a backend/browser restart with reused numeric
document IDs still invalidates prior selection and consent. No authentication
token or socket path is exposed by this generation field. Duplicate URLs and truncated titles/URLs are display metadata, not
identity. Refresh preserves an unchanged document. Navigation, reload, closure,
or binding loss revokes authorization, leaves a disabled unavailable selection,
and never chooses another document or falls back to a disposable context.
Disconnect, explicitly select a current document, and authorize again to proceed.

This is **not read-only or side-effect-safe evaluation**. Commands can mutate the
captured page, cookies and storage, initiate network requests, and schedule work.
Disconnect clears retained console values/monitors in reachable selected documents;
stale documents are never remapped for cleanup and retain their bounded native
expiry. Disconnect does not undo mutations or
scheduled work, or kill the capture browser. A command already running during
navigation or disconnect may have had effects; requests are never retried.

The console does not use browser-root `Target.setAutoAttach` or CDP
`Runtime.evaluate`, resume a target it did not pause, set breakpoints, step, or
inspect paused frames. Remote-debugging flags reject only the disposable profile.
Loss of its control channel exits the disposable browser; a live binding leaves
the capture browser running. This replaces [v1](native-console-v1.md); helpers,
backend, packaged assets and browser must be rebuilt together. Wire version is
unchanged from v2, but stable live IDs require this matching browser overlay.
Older v2 browsers that rotate IDs on each listing fail closed, not by URL fallback.
Native V8 REPL evaluation uses the pinned engine's debug evaluation API. This does
not promise undetectability or zero active cost.

## User operation

Set `REB_BRAVE_BINARY` to a rebuilt custom browser. For the default disposable
mode, connect an authorized HTTP(S) URL, then explicitly select a document.
For live mode, follow the separate selected-document opt-in above. Enter runs a
complete expression; Shift+Enter adds a line; Command/Ctrl+Enter submits immediately.
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
read-only evidence workspace; absent source is reported. Disposable Console and captured Sources are separate contexts. Live Console is
bound only to its explicitly selected captured document; source links are not ownership.

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
kills disposable owned process groups and removes their profile. Live disconnect
releases retained values/monitors, revokes consent, and rotates session identity on
the next connection without killing the capture browser. Closing the dock keeps
the session alive.

## Experiment activity

The browser collects resource-completion metadata only for documents in its
bound profile and current native target listing. Experiment activity opens an isolated
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
strings. Targets describe HTTP(S) top/child frames in the disposable profile,
or in the live capture profile when that binding is active. Worker and
paused-call-frame evaluation are not provided by this transport. The console
cannot set breakpoints, step, or inspect paused frames.

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
retried. Loss of the control channel exits the disposable browser. A
live-capture binding does not exit the capture browser.

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
enumeration without importing V8's internal check macros into Chromium code. The
engine's REPL promise wrapper is unwrapped using its private handle provenance:
synchronous commands show their actual result, and pending top-level await
commands expose that result after settlement. Page-supplied promises retain
normal promise identity and are never treated as engine wrappers. Pending REPL
handles cannot be stored in the page; await the result before storing it.

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

### Required live-browser acceptance (not established by synthetic tests)

After rebuilding the matching pinned browser, backend and packaged assets:

1. Start an authorized synthetic capture with two tabs at the same complete URL,
   plus two URLs whose first 512 bytes match. Verify Console stays disposable
   until explicit live opt-in; each native document has its own ID and label.
2. Select the second tab and authorize it. Evaluate a per-document marker and
   confirm only that tab changed. Refresh twice; its ID and selection must persist.
   Change neither page nor selection by CDP/URL inference.
3. Reload that tab at the same URL, navigate it, and close it in separate trials.
   The selected ID becomes unavailable, consent clears, and Run/value inspection/
   completion/poll cannot execute in the replacement. The other tab stays unchanged.
4. Disconnect and explicitly reconnect to another document. Old HTTP session IDs
   and retained handles must fail; native retained values/monitors must be cleared.
   Capture remains running. Scheduled page effects are not promised to be undone.
5. Stop/restart the capture/browser and lose/reconnect the native bridge. Old
   ownership/consent must stay invalid; no second browser/profile may launch.
   Missing/older bindings must fail closed with the matching rebuild explanation.
6. Repeat in the packaged macOS app, including selection/consent visibility,
   narrow layout and keyboard focus. Check native overlays compile against the
   pinned Brave/Chromium/V8 revisions before claiming runtime acceptance.

Rust scripted-peer and DOM fixtures cover backend/UI ownership and zero stale
runtime dispatch. They do not prove weak-document lifetime semantics in Blink,
real browser cleanup, visual rendering, or packaged native acceptance.
