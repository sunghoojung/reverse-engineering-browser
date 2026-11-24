# Native Console v2

[Native Console v3](native-console-v3.md) adds the separately armed
document-start script experiment on top of this contract.
[Native Console v4](native-console-v4.md) carries every source, value, message,
listing and transcript entry whole and ends the connection's lifetime; it owns
the wire layouts and the bounds that remain. Everything else below remains
current.

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
token or socket path is exposed by this generation field. Duplicate URLs and titles are display metadata, not
identity. Refresh preserves an unchanged document. Navigation, reload, closure,
or binding loss revokes authorization, leaves a disabled unavailable selection,
and never chooses another document or falls back to a disposable context.
Disconnect, explicitly select a current document, and authorize again to proceed.

This is **not read-only or side-effect-safe evaluation**. Commands can mutate the
captured page, cookies and storage, initiate network requests, and schedule work.
Disconnect clears retained console values/monitors in reachable selected documents;
stale documents are never remapped for cleanup, and their values and monitors
end when that document's main-world context goes away. Disconnect does not undo mutations or
scheduled work, or kill the capture browser. A command already running during
navigation or disconnect may have had effects; requests are never retried.

The console does not use browser-root `Target.setAutoAttach` or CDP
`Runtime.evaluate`, resume a target it did not pause, set breakpoints, step, or
inspect paused frames. Remote-debugging flags reject only the disposable profile.
Loss of its control channel exits the disposable browser; a live binding leaves
the capture browser running. This replaces [v1](native-console-v1.md); helpers,
backend, packaged assets and browser must be rebuilt together. Stable live IDs
require this matching browser overlay. Older v2 browsers that rotate IDs on each
listing fail closed, not by URL fallback, and a helper or browser of another wire
version refuses the connection (see [Wire and API](#wire-and-api)).
Native V8 REPL evaluation uses the pinned engine's debug evaluation API. This does
not promise undetectability or zero active cost.

## User operation

Set `REB_BRAVE_BINARY` to a rebuilt custom browser. For the default disposable
mode, connect an authorized HTTP(S) URL, then explicitly select a document.
For live mode, follow the separate selected-document opt-in above. Enter runs a
complete expression; Shift+Enter adds a line; Command/Ctrl+Enter submits immediately.
An unmatched bracket continues on Enter. Up/Down recalls history only
at the first/last line. Undo/redo includes completion insertion. The prompt has
no placeholder and the next draft remains editable during evaluation.

A command runs until it returns. While it runs, Run becomes **Stop**, which ends
it in the page at its next interrupt check; the command then reads `Stopped`,
and the changes it made before stopping stay. Input of any size up to the
4 GiB a record names is sent whole, the transcript shows it whole, and history
keeps every command.

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

Top-level await uses native V8 REPL semantics. Promise settlement is polled
until the promise settles or the researcher stops waiting. Stop waiting
releases the handle without rolling back effects or canceling page work.
Commands appear immediately, followed by page messages and the return value.
Page logs/errors are delivered independently of evaluation results. For
`console.log("hello")`, the message is `hello` and the result is `undefined`.
Logs carry level, time, location, their whole stack and a visible drop count.

`$_` reads the previous result as a standalone command. Explicit value actions copy values,
store an own data property as `window.tempN`, or release a handle. Standalone utilities
`copy(value)`, `inspect(value)`, `getEventListeners(element)`,
`monitorEvents(element)` and `unmonitorEvents(element)` evaluate their argument
once. They are console syntax, not globals installed on the page. Listener
inspection returns native registration metadata and existing callbacks; it does
not compile inline event handlers or read a `handleEvent` getter. Explicit event
monitoring observes click/input/keydown/submit until `unmonitorEvents` or the
page navigates.

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
order is not a causal claim. The browser keeps every completion of a current
target until it is read, with no count limit. One `traffic` reply carries the
oldest that fit the 64 KiB runtime response and `more: true` while some
remain; Experiment activity reads on until none remain, up to 64 replies per
read, and says when more wait. Completed resources before the initial listing
and of other documents are not reconstructed or replayed. Only a listing that
can no longer name a document discards its unread records: a refresh without
the live binding renumbers every target, and a document that left the listing
is gone. Each discarded record increments the visible drop count. The view
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

Everything remains ephemeral; values can contain sensitive content.
Nothing is automatically exported or persisted as evidence. Clipboard copying
and page temporary variables require explicit researcher actions.

Sources, values, messages, listings and the transcript are carried and kept
whole; [v4](native-console-v4.md#bounds-that-remain) lists the few bounds that
remain and why. Retained renderer values last until released, Clear,
Disconnect or the end of the document's main-world context. Event monitors
cover any number of Elements, four event types each, until `unmonitorEvents`,
Clear, Disconnect or navigation. A renderer keeps each message whole until it
is polled; for an owner that stops polling, past 64 MiB the oldest messages go
with a visible drop count, and polling or clearing releases their storage.

These are retained-state bounds, not a hard page heap quota.
Retained objects can keep reachable page data alive. Key and event-type enumeration can allocate
engine arrays. A command's own synchronous work runs until it returns or Stop
ends it. Scheduled async work is page work and can outlive an evaluation. A transport failure can
occur after side effects. Requests are serialized and never automatically
retried. Loss of the control channel exits the disposable browser. A
live-capture binding does not exit the capture browser.

## Live binding lifecycle

The capture browser connects to its Console bridge once, at launch, and the
bridge accepts one connection, so nothing re-arms a binding while the capture
runs. `GET /api/native-console` reports it as `binding_state`: `connecting`
until the browser answers its first listing, `ready` while idle, `connected`
while a Console connection holds it, `lost` once it ends, and `absent` when the
capture published none. For `lost`, `message` says why; restart the capture to
recover. No second browser profile is launched.

The backend waits for the first answer in its own handshake, so a state read
never waits for browser startup. A state read waits for a short action, such as
a listing, rather than failing it, then lists the documents again, from the idle
binding or the open connection, so a selected document that navigated reads
stale. While an action runs a command, a read waits for nothing: it reports the
listing from before the command with `command` (`running` or `stopping`, and its
request ID). Console
operations run to completion even when the HTTP client disconnects, so a
dropped request cannot leave a half-written exchange. A failed or timed-out exchange, a record that retires the
connection, unconfirmed Disconnect cleanup, or an exited bridge ends the
binding, because an ambiguous pipe is never reused. A connection has no
lifetime of its own: an idle binding stays bound until one of these or the end
of the capture.

The `binding` file is the launcher's one-time handshake record and stays with
the capture's files; the helper removes its socket as soon as the browser
connects. Each arm leaves exactly one of `binding` and `binding.absent`, even in
a reused directory.

## Wire and API

`common/native_console_protocol.h` owns trivially copyable little-endian ABI.
Magic remains `0x43424552`; version is **4**: 3 added Stop, and
[4](native-console-v4.md#wire) made every record whole. Authentication uses the existing
64-byte hello, user-only socket/token and peer UID check. Request/response headers
remain 32 bytes. Operation 1 lists targets, 2 evaluates legacy source, 3 carries
an exact runtime command as UTF-8 JSON. Type 11 carries a JSON runtime
result; types/statuses 0-10 retain the v1 meanings. Error records contain
text. The operation and response type must agree.

A target is a 24-byte header followed by its origin, label and URL bytes, as
[v4](native-console-v4.md#wire) lays out. Target flag 2 is top frame, and
reserved fields remain zero. Response flags appear only on a listing: flag 1
means the listing is partial.

Runtime commands are evaluate, inspect, complete, poll, await, cancel, release,
store, clear, last, source, listeners, monitor, unmonitor, traffic, watch and
unwatch. `listeners` takes an Element, the `document` or the `window` handle
(`getEventListeners(window)`); `monitor` takes an Element only. `watch` is
[native debugger observation v1](native-debugger-observation-v1.md). Handles
never cross document lifetimes. The [OpenAPI contract](openapi.json) specifies
HTTP fields, requiredness and response shapes. Runtime status is ok, error,
exception, pending or rejected, separate from transport status.

An empty timeout (5) or disconnected (6) record retires the wire connection.
Either status with text is one command's unknown outcome, such as a renderer
that went away mid-command: the connection stays usable, the result carries
`command_outcome_unknown`, and the command is never retried.

### Running and stopping a command

Operations 2 and 3 have no execution budget: the browser waits for the reply
for as long as the command runs. While one is in
flight, the only record the owner may send is Stop, operation 5, naming that
request with no target and no source. The browser forwards it to the
renderer's IO thread, which terminates the running script; the command then
answers status 7, stopped, with the text `Stopped; changes are not rolled
back`, and the connection goes on. A Stop that crosses the answer to the
request it names is ignored. Any other record while a command runs, or a Stop
for another request, ends the connection, because the exchange is then
ambiguous. A Stop that gets no answer within 5 seconds, such as for a command
that never started because the page itself is stuck, ends the connection with
an empty timeout record. A connection that ends while a command runs stops it,
because nobody could read its answer.

Over HTTP, `interrupt` (`session_id`) sends that Stop without waiting for the
session lock the running command holds, and answers `command: stopping`, or
`command: none` when nothing was running. The command's own request answers
`status: stopped` with code `cancelled`. The `reb-console` bridge forwards a Stop
from its owner while a command runs.

The renderer uses the project-owned `v8-native-console.h` public bridge rather
than V8's internal debug headers. Explicit commands retain native REPL evaluation
with debugger breaks disabled. Verified lexical completion uses the same engine
evaluation path with side effects denied and without REPL mode; a failed lexical
lookup stops completion. The bridge also exposes the existing lexical
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
settlement, release, Stop of an endless loop and recovery, input past 64 MiB,
whole UTF-8 results and paged message backlogs, navigation rejection and
control-channel disposal. Browser compilation and real execution remain required
before treating runtime behavior or active performance as verified.

### Required live-browser acceptance (not established by synthetic tests)

After rebuilding the matching pinned browser, backend and packaged assets:

1. Start an authorized synthetic capture with two tabs at the same complete URL,
   plus two long URLs that differ only past their first 512 bytes. Verify Console stays disposable
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
