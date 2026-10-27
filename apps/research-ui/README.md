# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path. The [Rust backend](../origin-trace-backend/)
serves browser development and native evidence sessions, with the same HTTP
contracts and tools. The native Brave broker, artifact receiver, probes, and
wire formats remain C++. See the [backend boundary](../../docs/architecture/origin-trace-backend-boundary.md).

Project-wide authorization, capture, and privacy policy is in
[SAFETY.md](../../SAFETY.md); this guide describes the product's current controls
and limits.

## Native-only capture

Origin Trace reads native evidence only. The packaged app opens stored evidence
or a native live session started by `make live`, and every view is built from
broker events, retained artifacts and analyzer documents:

- **Traffic** lists native network events with exact session, process and
  sequence identities, linked origin traces and local exports.
- **Sources** shows retained artifacts, static facts, decoding and formatting;
  it never fetches or executes source.
- **VM** shows analyzer findings, the opcode workspace, native Wasm dispatch and
  guest observations, the owned native fixture, static bytecode, packs and the
  opcode ledger.
- **Console** drives the native console against a disposable profile or an
  explicitly selected native document.
- **Collection**, **Analyst** and the notebook keep local authoring data that
  never sends requests.

The application does not launch, attach to or emulate a Chrome DevTools
Protocol debugger. Historical `cdp-attached` provenance labels and recorded
event schemas remain readable for old captures; they do not enable an
attachment or any live control.

The Findings **Native observations** tab displays native Wasm module offsets,
function indexes and unsigned selectors/default arms. These are physical Wasm
dispatch observations, not recovered guest-interpreter PCs or guest opcodes.
Guest rows interpreted through an explicit adapter appear beneath them with
their evidence identities. Host causality remains unproven.
`make native-only-check` (part of `make check`) enforces the native-only
contract and `make rendered-ui-check` verifies the rendered packaged app.

## VM desktop workspace

The compact Analysis, Navigation, Search and Window menus invoke the existing
workspaces and handler navigation. Escape closes a menu and returns focus to its
trigger; the toolbar keeps all seven workspace modes directly accessible.

The Findings view uses compact CodeBrowser-style docks: Program Trees holds
captured findings, Symbol Tree lists the selected finding's retained handlers,
the central Handler listing drives the linked evidence inspector, and analysis
tools use a bottom tab strip. The layout keeps the Rosé Pine Moon palette.
Symbols and the up/down toolbar navigate the same selection. The literal handler
filter matches retained source offsets, opcodes and labels; selecting a symbol
clears an excluding filter. Arrow keys, Home and End navigate visible listing
rows. No-match filters keep the selected evidence available and disable stepping.
These docks expose existing evidence, not a native-code decompiler or editable
Ghidra project. The deterministic fixture remains explicitly opt-in.

## Traffic identity and resource filters

Traffic rows come only from native network lifecycle events. A row's exact
identity is the session, process and sequence of its unique retained
`request_started` (or `request_initiated`) event plus its non-zero request ID;
URLs, hosts and timing never substitute for it. Rows whose events carry no
request ID stay visible but cannot open traces, signal profiles or Related VM
candidates. Native network metadata retains the method, URL or host and
lifecycle status only; the inspector states that headers and bodies were not
captured instead of showing empty panes.

Traffic selection updates only the mounted rows and selection summary when the
retained snapshot, filters, ordering and page are unchanged. Keyboard navigation
does not repeat search or sorting and does not rebuild rows or reset ledger
scrolling. A changed snapshot, filter, page or explicit refresh still recomputes
the whole bounded retained window. `node tools/check-traffic-selection-work.mjs` checks production
controller work and selection invariants. Add `--baseline-ref=<commit>` for a
reproducible authored 5,000-record/500-row before-and-after Node benchmark. Those
timings are not rendered browser or native-app latency; the Requests browser
gate separately exercises actual row keyboard selection.

## Connected investigations

**Advanced** is a manually opened workspace chooser. Completed workspace
navigation closes it at every width; choosing an item returns keyboard focus
to its summary. Linked Back/Forward keeps its existing destination-focus
restoration. A refused link leaves the current workspace and chooser intact.

Cross-workspace navigation uses one in-memory Back/Forward trail (at most 24
stops). Alt+Left and Alt+Right work outside editors; visible controls remain
available. Returns validate the exact retained session/event or artifact/hash,
restore selected request/trace/source or Evidence record and visible pane,
original range, focus and bounded pane
scroll positions, and leave owner-managed drafts in place. Expired or ambiguous
links remain visible and do not switch to similarly named evidence. Sources
returns wait for an evicted preview to finish rendering before restoring pane
scroll and focus. Newer interaction cancels that delayed restoration. An evicted
WASM inspection shows an explicit **Retry inspection** action; Back/Forward and
later catalog refreshes do not silently rerun the analysis.
On phones, expanded **Link context** uses a full-width row below Back/Forward;
long explanations stay in the bounded navigation scroller above the workspace.

A captured request opens its recorded Backtrace using its exact session,
process and sequence identity. Reused IDs in other sessions cannot supply its
trace; unsafe numeric identities and ambiguous rows are rejected. **Open retained source** uses
that step's session and artifact identity. A Facts **Original bytes** link
verifies complete retained UTF-8 bytes and SHA-256; **Decode range** copies those
exact bytes, up to 64 KiB, into Decoder. **Open original evidence** retains the
source identity and half-open byte range. Evidence field handoffs distinguish
selected string bytes from unavailable raw HTTP offsets.
Evidence source links use the selected native record’s exact retained artifact
identity. Back restores both observation-list and record-inspector scroll, the
visible trigger and current scope/search without selecting package exports.
Replacing an existing Decoder draft requires confirmation. Input edits mark its
prior origin stale. Navigation never transforms, sends, captures or executes.

The explicit Collection copy action saves only method and a query-free URL
after exact request identity and Collection draft checks. A confirmed recipe ID
is a copied template, never captured evidence; no request is sent.

Console URL links open a bounded, explicitly unverified source search. The
separate disposable browser is not assigned a captured-artifact identity, and
Console line offsets are never applied to search candidates. Host-and-time
matches likewise cannot become exact captured trace links, request-specific
signal profiles, or request-filtered VM candidates.
See [Investigation navigation v1](../../docs/product/investigation-navigation-v1.md)
for the identity boundary, retained limits and integration points.

## Local passive security report

The passive security report is an offline command for one saved exact-request
API response (`tools/report-passive-security.mjs`, library
`tools/passive-security.cjs`). Live native Traffic retains no headers or bodies,
so Origin Trace has no in-app report. See
[Passive security report v1](../../docs/product/passive-security-report-v1.md)
for the schema, rules, bounds and commands.

## Captured request exports

Live native Traffic retains no request or response bodies, so Traffic has no
capture actions. **Export…** in the Traffic toolbar converts a local
introspection JSON file (`__schema` or `data.__schema`, up to 1 MiB) to GraphQL
SDL; duplicate keys, invalid UTF-8, partial/error schemas and unsafe SDL
literals are refused. Export never queries an introspection endpoint or sends a
request. SDL is a raw schema export: descriptions and identifiers can be
sensitive.

Saved `reb-network-request-v1` documents remain usable through offline
commands: `tools/export-captured-client.mjs` (client projects, see
[Client project v1](../../docs/product/client-project-v1.md)),
`tools/export-captured-har.mjs` and `tools/export-graphql-sdl.mjs`. They read
local files only and never send captured requests.
`node tools/check-captured-export-ui.mjs` exercises the dialog handlers with an
in-memory DOM; native Save-panel testing remains a macOS gate.

## Saved investigation notebook

Use **Notebook** in the toolbar to create a named local notebook, then **Pin
selected evidence** from a captured Source, native Request, or selected Evidence
observation. Add a concise name and note and choose **Save pin**. Exact captured
source ranges are preserved when they came from verified original-byte navigation.
Reopening resolves the same retained identity; changed, missing or ambiguous
records remain explicit. Names can repeat without confusing their scoped IDs.

Notebooks survive application reload as non-executable JSON scratchpads in the
existing Analyst library. The dialog clearly discloses its library-wide scope
across sessions. Existing scripts and notes stay unchanged. Pins store reference
metadata and event fingerprints, never copied source/request/console content or
capture permissions. Typed notes may contain private information and remain local.
Cancellation cannot undo an already committed save: unconfirmed writes require
an explicit reload before another save. See the [notebook contract](../../protocol/investigation-notebook-v1.md)
for bounds, identity semantics and validation coverage.

## Native console

The **Console** bottom dock runs explicit mutable main-world JavaScript commands.
Disposable browser session remains the default, even during capture. In Session
settings, live execution requires **Live capture (explicit opt-in)**, an exact
native document selection, and selected-document mutation consent before Connect.
It is not read-only: commands can change the captured page, cookies and storage.
No second profile is launched for live binding. Refresh preserves the exact
document; navigation, reload, closure or binding loss clears authorization and
retains an unavailable selection rather than silently choosing another tab or
falling back to disposable execution. Disconnect before selecting and authorizing
another document. Disconnect does not undo page effects or kill capture.

Set `REB_BRAVE_BINARY` to the matching rebuilt custom browser and use the live
backend. The [native contract](../../protocol/native-console-v2.md) specifies
ownership, rebuild compatibility and the real-browser acceptance gates. No
breakpoints, stepping or paused-frame inspection are supplied by this console.
Workspace tabs sit across the top, with VM between Sources and Console. Commands are
syntax colored while typing and in the transcript; primitive results use colors
for their value types. Coloring uses inert text spans and a bounded tokenizer.
Console keeps a persistent command composer below its independently scrolling
transcript. Its header identifies the selected document and connection state;
Find, Clear and Session settings remain available without leaving the dock.
Each submitted command has a numbered running/completed/error state. A transport
failure marks its outcome unavailable, preserves the next draft and delivered
output, and never automatically retries the command. Use Session settings to
refresh documents explicitly, or disconnect and start a fresh disposable session.
The Run button and Enter both submit; the composer also shows its UTF-8 byte count.
An empty prompt has no placeholder text. Fully typed built-in names do not open
automatic suggestions, so Enter runs them unchanged; Ctrl+Space can still request
their completions explicitly.

New output follows only when already reading the bottom. Otherwise **Latest
output** shows new entries and returns to the end explicitly. Filtering shows
visible/retained counts and a no-match state. Output is bounded to 128 entries,
256 KiB of text and 8,192 DOM elements; eviction counts stay visible without
replacing connection errors. Clear removes output and releases retained values
while preserving command history. Object expansion loads one native property
page at a time; Previous/Next replace that page rather than growing the DOM.
Loading, expired-handle errors and explicit retry remain local to the object;
a failed page request keeps the previous page readable. If the live object shrinks
below the requested page, First properties and explicit Reload remain usable;
paging does not claim a frozen snapshot. Delayed page messages requested before
Clear cannot repopulate the transcript, while newer explicit commands keep their
execution identity. Malformed message batches preserve prior output and visibly
require document refresh. Refreshing or changing
documents invalidates actions on older values. **Value actions** keeps explicit
copy, store, release and other native utilities separate from passive inspection.
Toggle the dock with Console or Command/Ctrl+J while keeping the current workspace visible.
Drag its top divider or use the focused divider's arrow keys to resize; Home resets
the saved height. Enter runs, Shift+Enter adds a line, and Command/Ctrl+Enter also
submits multiline input. Up/Down recalls a separate bounded command history at the first/last line.
Clearing output preserves history; Forget command history removes it. Undo/redo
works for typing and completion insertion. An incomplete bracketed expression
continues on Enter; Command/Ctrl+Enter explicitly submits. The next draft remains
editable while a request runs.

Completion combines built-in hints with bounded native properties and global
lexical bindings. Calls, computed keys, strings and comments never cross the
completion boundary. Native traversal stops at accessors and proxies. Suggestions
include function argument counts where available. Fully typed names submit
unchanged; Ctrl+Space explicitly requests completion.

Results expand into property pages, DOM element previews, function source and
source locations. Getters remain labeled, proxies are opaque, and retained values
expire after 60 seconds. Explicit actions copy bounded property previews, store a
value as `window.tempN`, or release it. `$_` reads the previous result. `copy(value)`,
`inspect(value)`, `getEventListeners(element)`, `monitorEvents(element)` and
`unmonitorEvents(element)` are standalone console utilities. They evaluate their
argument once. Event monitoring is explicit and lasts at most 60 seconds.

Top-level await and promise controls show resolved/rejected values. Stopping a
wait releases its handle; it does not cancel previously scheduled page work.
Page messages appear separately from evaluation results. For example,
`console.log("hello")` shows a `hello` message and an `undefined` return value.
Command/Ctrl+F opens console filtering. Levels, timestamps and session-only
snippets are available without a permanent toolbar expansion.

The document selector identifies top frames, named child frames, titles and
URLs in the owned disposable browser. Navigation rejects old IDs and clears
retained handles. Experiment activity opens a separate Traffic view of bounded
native resource-completion metadata. It contains session/document/resource IDs
and the last evaluation request ID; observation order does not prove causation.
Paths, queries, headers and bodies are excluded. Source links search retained captured URLs with an explicit unverified label.
They do not automatically open a source or claim an exact artifact relationship.

Closing the dock preserves the session; Disconnect removes its browser/profile.
Console values and history remain ephemeral. See [Native Console v2](../../protocol/native-console-v2.md)
for exact operation, bounds, contracts and required post-build verification.
The synthetic wire fixture supplies scripted responses and never executes JS.

### Private cookie import (removed)

The former [cookie import tool](../../protocol/cookie-import-v1.md) is retired.
It refuses before reading private input or launching a browser. There is no
CDP transport, fallback, UI/API import action, or native replacement for cookie
import. Offline export validation tests remain; they do not install cookies.

## Run

```sh
make app
```

This packages `build/Origin Trace.app` and opens a complete live capture
session without a setup dialog. This research launch enables every implemented
native capture category and Canvas image artifacts. Retained credentials are unmasked; evidence stays
local. Use this profile only for authorized targets. The default isolated research
profile uses Chromium's mock Keychain so launch does not stop on a macOS password
prompt; do not save credentials in that profile. An explicit checkbox opts into
macOS Keychain encryption when credential storage is required. The app does not
mark the session live until the launcher publishes its loopback handshake, and the
failure dialog can retry the same privacy mode without restarting Origin Trace.
Startup allows up to 60 seconds for the bounded broker, receiver, backend and
browser readiness stages; individual helper failures are reported sooner.
The failure dialog preserves the launcher's explicit browser/helper diagnosis
when teardown writes later shell messages; the full session log path stays visible.
**New Live Session…** in the application menu offers metadata-only capture and
Keychain controls. `REB_AUTOMATIC_CAPTURE_MODE=metadata` selects metadata-only
automatic launch, and `REB_CAPTURE_CANVAS_IMAGES=0` disables image retention.

The app creates a private evidence directory and isolated browser
profile, starts its bundled broker, artifact receiver,
analysis helpers, and loopback UI, then launches Brave Browser Development with
all native capture categories enabled. Closing Origin Trace stops the session
processes. Evidence remains under `~/Library/Application Support/Origin
Trace/sessions/live/`.

Origin Trace looks beside its app bundle, in the reused browser output recorded
at packaging time, in the local `browser/worktree/`
build output, and among registered applications for Brave Browser Development.
A `REB_BRAVE_BINARY` override takes precedence. The app bundles its Rust backend
and VM analyzer, so Python is not required. A startup problem is shown explicitly
and leaves the stored-evidence interface available offline.
Pass an explicit evidence-store or demo argument, or set
`REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`, when opening the native stored-evidence
interface without starting Brave.

For deterministic localhost QA, set `REB_LOCALHOST_ONLY=1`. This routes external
browser requests to an unused loopback proxy and blocks external DNS while
preserving Chromium's sandbox. Do not wrap live Brave in `sandbox-exec`: nested
macOS sandbox initialization fails. Build commands can still use that wrapper.
If Brave or a required live helper exits, Origin Trace reports the closed
connection and offers retry instead of silently leaving a failed session running.
The coordinator signals all owned helpers together, allows a shared five-second
shutdown grace, then stops remaining children. An active analyzer worker has a
shorter two-second grace so its supervising shell can reap it before exiting.
Console commands still require explicit actions in their disposable contexts. Worker/proxy foundations do not yet have runtime adapters.

For an explicit development session with deterministic sample evidence:

```sh
make app-demo
```

Demo stores and Canvas drawing fixtures are development inputs. They are not
copied into the application bundle or used by `make app`.

For browser development:

```sh
make ui
```

Open `http://127.0.0.1:7319`. For a live capture with the pinned custom Brave
build, use `make live`. Follow the [browser setup](../../browser/README.md)
before starting a live session.

Native probes retain host-level network metadata only. Enabled native artifacts
retain unmasked source URLs in their separate local store. CDP content capture
was removed; historical `reb-traffic-capture-v1` copies are not re-read by the
viewer. Broker gaps, queue drops, and network-window evictions remain visible.
Failed refreshes request a complete validated response on retry, so an unchanged
ETag cannot leave the connection warning stuck after recovery.
Short windows keep at least one request row visible when status warnings wrap.

A healthy live Traffic view leaves the status line hidden. The line appears for
broker failures, malformed evidence, sequence gaps, queue drops, scanned-tail and
window caps, evictions and failed requests.

The live launcher disables Brave background networking, component updates, and
sync for its isolated research profile. Browser diagnostics are retained in the
session's private `brave.log`, separate from coordinator failures. The native
app pre-creates the matching macOS cache sandbox path before launch.

All eight fingerprint metadata families are enabled by the standard live
launcher. To retain the exact data URL returned by Canvas readback for one
authorized session, run:

```sh
REB_CAPTURE_CANVAS_IMAGES=1 make live
```

Canvas image capture is disabled by default because rendered output can contain
page content. Enabled output stays in the local session artifact store, is
limited to 2 MiB per image, and is joined to its exact `toDataURL` event. The UI
continues to show operation names when image capture is off or an image exceeds
the limit.

To make the browser ignore page `debugger;` statements during a live capture:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

Quiet mode keeps native evidence capture and Captured Sources available. It does not guarantee that the custom browser is undetectable.

## Packaged UI resources

The native stored-evidence scheme and the live HTTP backend share exactly one
`Contents/Resources/research-ui/` directory. `index.html` resolves CSS and scripts
relative to that directory; both Analyst adapters pass its `analyst_runner_core.js`
to the bundled native runner. `analyst_runner_node.js` remains available for the
backend's supported Node fallback. The runners are not public UI routes.
`OriginTrace.icns` and `run-live-session.sh` stay at the Resources root.

To package a new UI module, add its filename once to the explicit asset loop in
[`build-research-app.sh`](../../scripts/build-research-app.sh). If it is served by
the UI, also add its HTML reference and the existing native scheme and Rust
`UI_ASSETS` route allowlists. `make javascript-check` compares those lists, checks
the canonical consumer paths and rejects duplicate root copies. It reports bytes
removed from the current source assets; this is an uncompressed payload saving,
not a promised ZIP-size reduction.

After `make check` and `make app-build` on macOS, run:

```sh
ORIGIN_TRACE_TEST_BROWSER="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  node tools/check-origin-trace-package.mjs
```

The check relocates the signed bundle outside the repository, verifies its exact
resource bytes and signature, and runs the real WebKit app in offline, deterministic
demo, failed-live-start/offline fallback, and live HTTP modes. Each exercises
bundled CSS/JS, private-route rejection, native capability markers, API contracts,
Decoder and saved Analyst execution. The existing launcher check runs from an
unrelated directory with bundled helpers and a disposable headless browser; it
also checks shutdown and handshake removal. Logs are saved under `build/package-qa/`,
including bounded coordinator output and process status for browser interruption.
`node tools/check-origin-trace-launcher.mjs --cleanup-only` exercises the same
teardown functions with disposable socket-free helpers, including unresponsive
children and analyzer-worker cleanup; it does not replace native package acceptance.
The macOS CI job runs this check before uploading the app preview.

The failed-start smoke uses a deliberately missing browser and follows the offline
branch without showing a modal dialog. It does not automate the Retry/Continue
Offline buttons. Headless Chrome stands in for the browser to test live session
startup and packaged routing, not custom Brave probe capture. These checks do not replace interactive native
keyboard, resize and visual QA. On other platforms, `--contract-only` checks
source wiring only and does not claim native runtime coverage.

## Workspace layout

Traffic, Collection, Sources, VM, Console and Fingerprinting are available in
the toolbar. Expand **Advanced** for Backtraces, Analyst, and Tools.
Navigation into an advanced tool reveals its group automatically on desktop. On
narrow windows navigation moves above the workspace and closes after selection.

Returning to Traffic immediately redraws retained requests and the selection, even
when the last capture arrived while another workspace was open and the backend
has no newer events.

Traffic uses a compact network ledger with visible resource-type filters and
sortable Name, Status, Type, Method, and Time columns. **Capture order** restores
the evidence order. The selected request opens General, Initiator, Timing,
Signals and Evidence beside the ledger above 1100 px, or below it in narrow
windows. Both panes stay within the available workspace height; the request
ledger and inspector body scroll independently. Captured-tab and domain filters
share a compact row at narrow widths. Native capture records the method, URL or
host, status and lifecycle timing of each request. Request and response headers
and bodies are not captured, so Traffic has no header, body, preview, comparison
or content-search views; General states that coverage. Missing initiators and
timing phases stay explicitly unavailable.
Request signal profiles are owned by the exact selected session, request and root
event. Late responses cannot replace a newer selection or refresh. Malformed or
failed refreshes preserve only the last validated profile for that same identity
and require a full response on retry; changed or ambiguous owners clear it.
No cache, recording, throttling, or invented waterfall controls are implied.
The layout follows familiar [network inspection conventions](https://developer.chrome.com/docs/devtools/network/reference)
while keeping Origin Trace's own controls and Rosé Pine Moon palette.

The ledger mounts at most 500 fixed-height rows. Previous/Next page through the
retained window without changing the evidence: the Rust native-event API returns separate newest general and network lifecycle
windows of up to 5,000 events each from at most the newest 64 MiB. Canvas/WebGL activity does not consume
network slots within that byte budget. Traffic uses the network window, including
redirect, failed, and response-completed outcomes. Notices distinguish a capped
window from the bounded tail and label summary counts by their actual scan scope.
Sequence-gap counts are arrival-order high-water jumps, not a deduplicated count
of still-missing IDs after late arrivals, and queue drops may overlap them.
The Swift stored-evidence reader uses the same newest-general and
newest-network windows, 64 MiB tail, and summary scope as the Rust endpoint.
A response that omits those fields is still labeled visible-window-only, and
no whole-capture count is inferred for it. Filtering
and sorting cover the whole retained window. Rows and capture-tab controls are
reused across refreshes. New arrivals briefly accent the row edge once; pending
requests use a steady label. Reduced-motion disables animation and transitions.
Refresh preserves the reading anchor and keyboard focus and never follows the
bottom automatically. **N new requests** explicitly jumps to the newest capture
window. Selection survives filters and sorting; its absence from the filter is
labeled. An actually evicted selection reports that it left the retained window
instead of silently selecting another request.

Arrow keys select adjacent request rows; inspector tabs use Left/Right and
Home/End. Escape closes the inspector and returns focus to the ledger. The close
button has the same behavior. A dismissed inspector stays closed across
refreshes; selecting a request reopens it. Full URLs remain available in General
and Copy URL, and host-only metadata never implies a captured path or query.

Traffic search is a literal, case-insensitive match over the URL or host,
method and status that native rows carry. Tab, domain, and resource filters
scope it. Search never enables capture or fetches anything.

Collection uses a saved-request library, template editor, and submitted-response
pane. Headers, Body, and Variables are keyboard-accessible request sections;
responses have Body and Headers views with the submitted run identity. Folder
settings and history are expandable. Unsaved edits stay with the selected item
until explicitly saved or discarded, including across refresh failures. Run is
labeled **Save & Run** when it will first persist edits. Selection never sends.
See [API Collection v1](../../docs/product/api-collection-v1.md).

The dark theme uses [Rosé Pine Moon](https://rosepinetheme.com/palette/), with
slightly brighter secondary labels for legibility. Appearance switches to the
existing light theme.

Fingerprinting starts with an Overview of active surfaces and captured Canvas
output. **Show inactive surfaces** reveals the rest of the supported families.
Surface chips open filtered Activity. Each Canvas card keeps replay comparison,
drawing calls, and evidence identifiers in expandable sections; open sections
and summary focus survive evidence refreshes. Activity opens its details pane
when an event is selected, or with **Details**. Decoder processing limits and
result statistics are likewise available in expanders beside their controls.

Advanced workspaces keep the primary task visible and secondary information in
expandable sections. Backtraces groups correlation identifiers separately from
relationship facts. Origin traces expose the recorded location as text; they do
not open a source using only a possibly reused script ID or URL, because the
trace contract lacks the execution-context/source-hash identity needed for that
link. Analyst prioritizes the editor and evidence permissions; folder settings,
storage, variables, execution limits, and history can be expanded as needed.
Tools keeps input and output visible with transformation history available on
demand.

Analyst keeps unsaved file and folder changes with their selected owners. Clicking
the same file, refreshing, or visiting another workspace preserves the draft.
Switching, creating, deleting, or moving a file away from a dirty folder requires
saving or explicitly choosing **Discard changes** first. A changed or deleted
saved owner keeps the draft and its original version visible; copy any edits you
need, discard them, then **Retry load** to review the current saved version. No
background refresh silently rebases a changed draft over another window's work.

A save acknowledgement must match the exact submitted contents and generation.
An interrupted or malformed acknowledgement triggers one readback, never another
write. The editor stays locked during that check. Verified contents are marked
saved; unresolved results retain the draft and block writes until **Retry load**.
If readback still shows the original generation, an explicit retry uses that same
generation check, so a delayed original save conflicts instead of committing
twice. Conflicts and validation reasons remain visible. There is no autosave or
persistent draft copy. Browser reload/close warns while drafts or unresolved saves
exist. The native shell separately checks the current Analyst document before
normal window close or Quit. Its sheet keeps **Stay** as the Return/Escape default;
**Close Anyway** requires a deliberate choice for unsaved or unconfirmed changes,
including when the document cannot report its state. Navigation invalidates an
older close decision. Quit while this guard's sheet is open can reach the
delegate. AppKit aborts the Close sheet before delivering Quit; the guard cancels
that request and checks the current document in a fresh Quit-owned decision.
Callbacks that reach a still-active request coalesce without another query.
Only this guard-owned sheet permits delegation; sudden termination remains
disabled and Stay still cancels the pending Quit.
Closing can interrupt a pending save and cannot undo a save
already committed. Save and verify the result before closing. Neither warning
protects against crashes or a forced process exit.

Native acceptance requires `make app-build`, strict code-signature verification,
and `node tools/check-origin-trace-native-close.mjs` on macOS. The existing macOS
CI job runs a relocated packaged app with synthetic workspaces through actual
window close, application Quit, Stay by Return/Escape, explicit Close Anyway,
save/pending states, coalesced requests, unavailable/untrusted documents, actual
navigation, and injected stale/timeout replies. It verifies draft/owner retention
and the expected warning before shutdown. Ordinary Quit scenarios enqueue
Command-Q through AppKit. The repeated Close/Close/Quit case defers the native
Quit action to default run-loop mode, outside the WebKit callback and any
previous termination modal loop. A smoke-only observer requires actual Quit
delegate receipt before either Stay or Close Anyway; scheduling alone cannot
satisfy the test. Stay must preserve the exact draft snapshot. The repeated case
requires exactly two queries before Stay: one for the aborted Close request and
one for the fresh Quit request. UUID traces require one query per request, the
abort/cancel transition, and fresh requests for the later explicit approved exit.
All 14 scenarios run; the repeated case
runs in five fresh processes and every attempt must pass. Per-attempt logs,
dispatch-mode diagnostics and prompt PNGs are retained in `build/native-close-qa/`
and uploaded by CI. The `--contract-only` mode checks wiring, sheet/sudden-exit
policy and trace assertions; it is not evidence of native lifecycle behavior.

## Code ownership

| Location | Responsibility |
| --- | --- |
| `index.html`, `app.css` | Document structure and visual layout |
| `app_state.js`, `evidence_models.js`, `app.js` | Initial state and DOM bindings, evidence validation and projection, interaction and rendering |
| `pane_layout.js` | Shared pointer and keyboard pane resizing, responsive constraints, and local size preferences |
| `traffic_view.js` | Native request ledger rows, ordering, paging and URL/method/status search, the General coverage view, and the saved-capture export document |
| `captured_client.js`, `captured_export_formats.js` | Saved-capture identity, local export dialog, and the client-project/HAR/SDL generators shared with offline commands |
| `source_syntax.js` | Source names, display formatting, the inert hex view for Wasm and guest bytecode artifacts, and bounded tokenization without DOM or application state |
| `native_console.js`, `native_console_completion.js` | Disposable browser console controls and local built-in API completion |
| `../origin-trace-backend/src/app.rs`, `evidence.rs` | Loopback HTTP routing and bounded evidence reads |
| `../origin-trace-backend/src/workspace.rs`, `analyst.rs`, `workspace_lease.rs` | Workspace contracts, explicit analyst execution, private durable replacement |
| `../origin-trace-backend/src/decoder.rs`, `origin_trace.rs`, `vm.rs` | Native decoder adapter, trace projection, and VM analysis |
| `macos/` | Native shell, evidence readers, and helper processes |

The browser scripts load in the order declared in `index.html`. They use the
same page scope so the native shell and browser development path share one
implementation without a bundler. `evidence_models.js` contains evidence
validation and projections; `source_syntax.js` owns source display algorithms.
Live refresh and DOM updates belong in `app.js`.
The native scheme handler and packaging script explicitly list shipped assets.

Traffic shows every native request row independently; host, method and time
never merge or hide rows. Sources reads retained artifact bytes only. A failed
refresh preserves the last valid catalog, and a detached pending load is
cancelled and cannot restore obsolete source text. Artifact loads have a
10-second deadline, including body reads; a timed-out load can be retried
explicitly.

## Validate

```sh
make lint
make check
make e2e
```

UI changes also require interaction through the native app. Run the complete
[quality gate](../../CONTRIBUTING.md#quality-gate) before handoff, including app
build and signature verification when packaging changes.

See the [Origin Trace reference](../../docs/product/origin-trace-reference.md)
for workspace behavior, limits, command-line options, and evidence guarantees.
Versioned wire and storage contracts belong in [`protocol/`](../../protocol/).

### Rendered UI acceptance

```sh
make rendered-ui-check
```

This runs the packaged app, not a browser. `tools/check-origin-trace-rendered-ui.mjs`
copies `build/Origin Trace.app` to a temporary directory, verifies its signature,
and starts the bundled `OriginTraceBackend` on loopback with a bounded synthetic
session: the `make e2e` demo stores, 72 native network rows, a 400-line retained
source, a synthetic guest bytecode buffer, and Wasm dispatch and guest events
emitted by the real C++ encoders (`build/reb-native-wasm-dispatch-golden` and
`build/reb-native-wasm-guest-golden`). Captured strings and bytecode include
markup that would execute if it were inserted as HTML.

The hosted XCTest bundle in
[`tools/origin-trace-rendered-ui`](../../tools/origin-trace-rendered-ui/) is
injected into that app (`TEST_HOST`) through an `.xctestrun` description. It
drives the production window and WKWebView with native AppKit pointer and key
events, and reads layout only through `probes.js`. At the default 1180×790
window and the enforced 760×560 minimum it checks:

- Traffic: retained rows, list scrolling to the last row, request selection and
  the detail pane;
- Sources: a retained artifact rendered as literal text and scrolled to its end;
- Investigation navigation: Back appears after a screen change, Alt+Left returns
  to the selected request, and Forward reopens Sources;
- VM: the opcode workspace for the guest artifact shows the native guest row
  with its wide instance identity, and the physical artifact never claims a
  guest PC;
- native-only coverage: Traffic offers only General, Initiator, Timing, Signals
  and Evidence with no content search or Compare; Export offers only local-file
  SDL and says why; golden and hostile guest bytecode render as an inert hex
  view with an unclipped kind icon;
- keyboard order and visible focus for 30 stops (Option+Tab when Full Keyboard
  Access is off, as in Safari), and Shift+Tab reversal;
- no removed CDP control or markup anywhere in the shipped screens.

Layout checks reject horizontal page overflow, controls cut off by a
non-scrolling ancestor, controls covered at their hit-test point, overlapping
controls and text clipped without an ellipsis or line clamp. No captured value
may execute or become an element. Screenshots are written to
`build/rendered-ui-qa/screenshots`; inspect them as well as the result. The
check needs macOS and full Xcode (XCTest); it uses `DEVELOPER_DIR` or the
selected Xcode without changing the global selection. Run one case with
`node tools/check-origin-trace-rendered-ui.mjs --only test4VmNativeGuestRows`.
The window becomes active while the check runs. It does not exercise a live
browser capture.

### Interface styling

The shared shell keeps the existing Rosé Pine Moon tokens, thin pane dividers,
and semantic selection accents; Appearance retains the existing light theme.
Traffic uses independently scrolling ledger and inspector panes. Compact
resource filters stay visible below search and wrap within narrow windows. Selected-field actions sit beside the evidence on wide windows
and below it on narrow windows. Session
counts come from loaded requests, and sample evidence stays visibly labeled.
Keep labels at least 10 px and reserve stronger color for selection, connection
state, errors, and evidence confidence.

Tool workspaces put the next action before implementation details. Decoder
controls follow input, transformation, and result order; chain editing stays
beside the step list. JWT test-token creation is an optional disclosure below
inspection. Use the interface font for instructions and labels, and monospace
for captured values, code, and identifiers. Empty states explain how to begin.

Backtraces lets the researcher select a captured request, load its recorded
predecessors, and select a row to inspect event identifiers, values, and source.
Empty traces show a next action rather than a graph or coverage meter. Gaps and
shared-identifier matches remain explicit. Refresh failures retain the previous
trace, and arrow keys move between trace rows.

Fingerprinting is a first-class session workspace for Canvas, WebGL, Web Audio,
device, layout, and WebGPU APIs, Permissions, Storage, WebRTC, and Runtime activity.
Rendering is the primary view: an eight-card surface overview reports event
count, distinct operations, and the most active operation before the Canvas
readback cards.
Each card separates exact captured output, replay availability, ordered drawing
functions, and stable evidence identity. The explicit development demo
reconstructs both images locally from its visible, bounded call sequence; it
does not present those pixels as native capture. A live readback lists up to 128
supported Canvas operation names observed earlier in the same renderer stream.
When the session explicitly enables Canvas image capture, the exact bounded
`toDataURL` result is shown as captured output. The UI keeps the newest 24
readbacks. Only the visible Rendering gallery loads previews, scoped to its
current readbacks. Canvas owns a separate maximum of 24 previews and 8 MiB of
UTF-16 text reservations/retained text; each descriptor reserves twice its
encoded byte size before admission (at most 2 MiB encoded bytes per preview).
Newest previews have priority, and budget omissions remain labeled without
refetching on every refresh. Unchanged polling retains the same cards, native
disclosure controls and admitted image nodes, including across pointer press
and release. Changed render inputs or exact source ownership invalidate that
reuse; updated disclosures preserve their expanded state and focus.
At most two unfinished preview reads are allowed,
including retired reads whose fetch or response-body/reader cancellation has
not settled. Header/body errors remain visible immediately; explicit retries
do not bypass cancellation credits. Their bounded streaming
read buffers total at most 4 MiB; transient text, hashing and image decoding are
separate from the retained-text budget. A ten-second deadline aborts a read;
failed reads expose an explicit Retry preview action.

Activity, leaving Signals, changing the visible readback scope, catalog
replacement/emptying and catalog failures retire obsolete preview ownership,
abort pending reads and remove image sources from the gallery DOM. Late
responses cannot restore retired payloads. Artifact metadata and immutable
files remain available; an empty live catalog still reflects its actual empty
metadata window. Sources previews and verified analysis results keep their
independent budgets and identity checks.

Before assigning any captured image to `img.src`, the UI separately admits a
narrow static PNG profile: non-interlaced 8-bit RGB/RGBA, at most 4096 pixels per
axis and 4 Mi (4,194,304) declared pixels per image. At most 16 Mi (16,777,216)
declared pixels are mounted across the current gallery, with newest captures
first. The UI checks canonical base64, signature, chunk framing/CRC, a single
first IHDR, consecutive nonempty-in-total IDAT data and a final empty IEND with
no trailing bytes. At most 256 chunks are inspected. Only optional fixed-size
sRGB, sBIT and pHYs metadata is admitted, once each and before IDAT. Other chunks,
including animation, compressed profiles/text and unknown extensions, produce
an explicit unsupported-preview reason; the original evidence is unchanged.

The producer retains bounded `data:image/*` output, so this intentionally narrower
preview policy can omit valid captured images, including JPEG, WebP, other PNG
profiles and PNGs carrying embedded color profiles. Unsupported previews retain their exact text
inside the existing text budget and do not cause automatic refetches. Scope
changes release that text normally. A browser decode failure is labeled without
changing stored evidence; errors from detached images or retired owners cannot
poison the current preview. Image admission follows the exact current artifact
owner, and old DOM sources are removed before new sources are assigned.

These checks bound admitted declared dimensions and mounted pixel counts. They
do not inflate IDAT, validate its compressed contents, measure decoder allocations,
or bound JavaScript heap, native decoder caches or process RSS. Removing `src`
does not prove immediate decoder-memory reclamation. Browser/native interaction
and decoder behavior need separate rendered validation; giant-header fixtures
must remain inert. The profile follows the [PNG specification's structure and
chunk rules](https://www.w3.org/TR/png-3/). The native capture still does not retain
drawing arguments or a canvas object identifier, so local replay remains
unavailable and the earlier-call relationship stays renderer-scoped.

The fingerprint workspace scopes Rendering and Activity to a captured browser
tab, all tabs, or explicitly unattributed events. The selected tab is a stable
top-level frame-tree identifier; renderer events without a live frame context
remain unattributed instead of being guessed from process ID. Activity keeps
native probe operations newest first, calls out newly arrived rows, preserves
the reading position while older rows are inspected, and renders at most 500
matching operations. Latest jumps back to the top and marks the scoped new
rows seen. The Stop probes button disables the native session through the
local broker without closing the browser. Clear events is available after
capture stops, requires confirmation, and truncates only this session's event,
trace, and request-profile stores. Canvas artifact files and other saved files
remain on disk. Detailed identifiers stay behind a disclosure. The
captured-tab buttons are historical evidence, not an open-tab count. The footer separates missing per-process sequence IDs from
reported queue drops, since a gap report can describe the same missing IDs.
The custom browser observes generated Web IDL callbacks for a selected native
allowlist across all eight families, in addition to the lower-level Canvas,
WebGL, and Web Audio hooks needed by internal Blink paths and selected V8 Math,
Intl, and timezone hooks. Generic DOM bindings retain only measurement and
capability members, preventing ordinary page rendering from overwhelming the
timeline. Generated non-Canvas and V8 probes retain the first observation per
call site in each capture session, while lower-level Canvas drawing hooks keep
their renderer order for readback inspection. Coverage is broad but
intentionally does not claim every browser API.
Request link view separates observed parent chains from same-context
correlation and exposes zero-count families instead of hiding coverage. The
view never claims that an observed value was transmitted or that a particular
fingerprinting vendor produced the activity.

Sources navigation lists retained Captured artifacts.
File rows reserve their remaining width for the filename, with full URLs in
tooltips and source metadata in Details. Folder rows retain their item counts.
The navigator initially expands branches to keep retained files directly visible.
Click a branch, or press Enter/Space on it, to collapse or expand it. One tree row
is in the Tab order; Up/Down move through visible rows, Right opens a branch or
enters its first child, Left closes it or returns to its parent, and Home/End
reach the first/last visible row. Modified arrows keep their browser/history
meaning. Focus and the open document are separate: collapsing a selected file's
ancestor leaves its editor, Find result and original-byte location unchanged and
never reads source bytes or runs analysis. Ordinary catalog refresh keeps keyed
rows, tree focus and scroll, returning a removed focused row to its closest
surviving ancestor. Branch state is session-only; origins and full path
segments have distinct identities.

The navigator inspects at most 5,000 catalog records, retains 10,000 metadata
nodes and renders at most 1,000 expanded rows. Collapsed descendants have no DOM
rows. It rejects URLs above 4,096 characters and identities above 8,192
characters, shortens directory structure after 16 levels, and visibly discloses
these limits rather than implying omitted sources are absent. Selection markers
are withheld when the catalog cap prevents verifying a unique source. Empty path
segments remain distinct, explicitly labeled folders. Collapse branches
or use **Open file** to reach later catalog choices. Deep indentation is bounded
for narrow sidebars; full source URLs remain available in tooltips. These limits
do not evict open source text, change captured evidence, or relink documents.
Find searches the selected document's owned retained text, independently of
which lines are mounted. It uses a case-insensitive single-line literal of at
most 512 UTF-16 code units. Multiline pastes are refused before the browser can
join their lines. Enter advances and Shift+Enter goes back through the first
1,000 matches, including late matches in minified lines and after line 20,000.
A visible `+` discloses the match cap. Search never fetches more bytes or runs an
analyzer. Complete text, retained prefixes, lossy displays and unavailable or
evicted previews have separate coverage labels; an incomplete negative is never
reported as absence from the complete source. Loading/truncation notices are
excluded. Pretty/Deob Find names the retained display representation, with
transformation completeness separate from search coverage.

The editor mounts at most 1,000 lines. Previous/Next and explicit local Line /
Column controls reach other retained locations. The target line retains at most
16,384 UTF-16 units (one additional unit may preserve a surrogate pair); other
lines retain at most 512 each. Omitted-column markers sit outside source text.
Find and original-byte links reveal an excerpt containing the requested absolute
location, rather than increasing these limits. Later or clipped windows use a
plain-text label because omitted prefixes cannot establish lexical coloring
state. Captured bytes, line endings, BOMs and absolute runtime locations stay
unchanged. The current document has one sparse line anchor per 128 lines, at
most 65,537 anchors for the defensive 8 Mi UTF-16-unit inspection limit. Accepted
preview and verified-original readers retain their existing smaller byte limits.
Derived/Pretty mappings are projected only for mounted lines.

Investigation history retains logical line/column windows with the exact source
and representation owner, then restores pane scroll. A changed derived-analysis
version or intrinsic assumption cannot restore a stale representation window.
Ordinary evidence refresh leaves Find and the current window in place; explicit
original-source pivots choose their own retained location.

The Sources sidebar starts closed. Details opens source metadata, JavaScript
facts and static cleanup; the toggle remains available at narrow window sizes.
Wasm modules and native guest bytecode buffers open as an inert hex view of
their retained bytes (offset, hex and printable columns, labeled **WebAssembly
hex** or **Guest bytecode hex**); bytecode is never decoded as text. Guest
adapter recipes are JSON text.

VM analysis is a secondary Traffic view, reached through Related VM candidates
for a selected native request with a complete root identity. Incomplete native
rows stay in Traffic with an unlinked notice; they never
silently open session-wide analysis. The request-scoped view uses only acknowledged response
creator chains and has a Back to traffic control. Use workspace navigation
explicitly to inspect unfiltered session analysis.

When the selected finding has a validated opcode workspace, VM Lab adds the
handler mapping, runtime typed-array bytecode preview, characterized coverage,
named omissions, and residual unknowns beneath the unchanged detection detail.
Handler rows keep inferred candidates visible even when the runtime sampler is
unavailable, and support Up, Down, Home, and End selection. With no runtime
samples, the Coverage diagnostic leads with the observed absence of retained
samples and the missing automatic guest-interpreter sampler. A caller-fed writer
is not that sampler; static dispatch, Canvas calls and snapshots still do not
prove a guest PC.
Workspace failures retain the last valid workspace and never remove detection
findings.

Traffic remains grouped by captured browser tab with an All tabs scope and a
domain selector. Protocol v3 carries the stable top-level tab identifier; older
evidence remains Unattributed. Evidence retains the original payload and trace
actions; General, Initiator and Timing display only recorded observations.

## Deobfuscation engines

Deobfuscation stays inside **Sources**. Select a JavaScript source and use the
**Static cleanup** control to switch between original evidence and the mapped derived view.
Open **Details > Static cleanup** to inspect the report. Cleanup preserves the
current sidebar visibility so narrow-screen overlays do not hide the code. It
uses REB's existing local Rust/Oxc worker;
it does not call or embed an online deobfuscation service. No input is executed
or uploaded to a third-party service. **Compare original / cleaned** shows
both inert texts with independently labeled 8,192-UTF-16-unit prefix limits,
without splitting a surrogate pair. Full-source SHA-256 values identify the
original and cleaned UTF-8 text; the cleaned hash is computed locally after
source-map admission and is not an equivalence proof. The existing changed-span
inspector retains exact original/derived ranges beyond those previews.
**Original** returns the editor to retained evidence. **Discard cleaned result**
removes the current option's cached derivation, retires a pending retry and
returns to original text; late responses cannot restore it. Another analysis
requires explicit retry. Neither action edits or deletes the original artifact.
Unsupported behavior remains visibly unresolved even if no resource budget was
reached; no safe rewrites is not a claim that source is unobfuscated. This is a
separate ephemeral derived view, not a persisted replacement capture.

The adjacent **{ }** control pretty prints JavaScript, JSON, CSS, and HTML using
the detected source type. It can format either the original evidence or the
active deobfuscated representation, so an unchanged deobfuscation result does
not leave a minified bundle on one line. Pretty printing changes only display
whitespace, keeps source-line mappings back to the captured bytes, and never
rewrites stored evidence. Input is capped at 2 MiB and formatted output at 4
MiB, with 250,000 lexical tokens and 500,000 mapping segments as pathological
input guards.
**Details > Static cleanup** shows analysis, limits, omissions, and retry actions. The native app ships a Rust/Oxc worker for bounded static AST rewriting
over captured artifacts. It needs no Python runtime. Building the app
requires a current stable Rust toolchain (`rustup toolchain install stable`).
The Rust backend preserves classification, formatting, and literal-table
analysis for captured artifacts. The Deobfuscation details
name the engine. Dynamic decoding remains unimplemented and is reported as an omission. Static table substitution is
restricted to non-escaping local tables with proven own-index reads.

Failed analysis remains visible until **Retry analysis** is selected. A failed
retry retains the last successful result. Source selection does not switch the
Sources editor away from original evidence. The UI retains at most eight analysis
documents and distinguishes source hashes and artifact identities in its cache.
The report retains the last successful summary and snippets during a retry or
failure. **Cancel analysis** retires the current request; a worker may still
finish, but its late response cannot replace the report. Cancellation and errors
require an explicit retry.

The report's changed-span inspector shows one validated replacement at a time,
with Previous/Next, exact half-open UTF-8 ranges, and original/derived snippets
limited to 2,048 UTF-16 units each. Snippets scroll independently; truncation is
visible and never splits a surrogate pair. In the HTTP live workspace or browser
development UI, **Reveal original range** verifies captured original bytes
through the existing Facts path. Stored-evidence native mode displays an explicit
unavailable reason for that navigation. Neither path executes source. Pretty printing remains a separate display layer.

Transformation families, heuristic classification signals, recovered table
summaries, and assumptions/limits have explicit counts and four-row paging.
Generic omissions do not hide recovered tables. Raw table entries are not shown;
only bounded admitted summary fields and previews are displayed. Family totals
are whole-report metadata, not invented explanations for a selected replacement.
Classification is labelled as a heuristic, not a probability or equivalence proof.
Missing legacy change metadata is shown as unavailable; code-point maps do not
offer exact UTF-8 change inspection. Small selection/page/disclosure metadata
lives with its bounded cached analysis and disappears on eviction. History does
not restore intrinsic options or the selected change.
The [versioned contract](../../protocol/deobfuscation-v1.md) defines source-map
units and how native replacements map back to their original expressions.

The production Rust AST passes and their ReverseJS comparison are documented in
[method coverage](../../docs/product/deobfuscation-method-coverage.md). The browser
server uses a built worker when available (debug before release), or the explicit
`REB_DEOBFUSCATOR_WORKER` executable. Worker failures remain errors; a missing
worker makes AST operations unavailable with an explicit error. Deob stays inside Sources.

## Captured JavaScript facts

In **Sources**, select a captured JavaScript artifact and choose **Facts**.
The existing Rust/Oxc worker returns bounded lexical scopes, declarations,
callables, regions and operations for that exact session, artifact and SHA-256.
This is an explicit, inert analysis action. Derived text is not accepted. The Details pane shows complete-within-profile, partial,
unavailable and truncated states, diagnostics and unknown-effect frontiers.
Each category displays 100 rows per page; fact details are capped at 4,096
characters. In **Bindings**, search declaration names and choose **Find lexical
operations** to inspect exact-ID references, reads, writes, calls and constructs.
The kind filter and paging keep long reports bounded. Same-name declarations in
different scopes remain distinct; operation rows can return to their declaration
explorer. Ambiguous targets offer an explicit candidate chooser and remain
candidate links. Unresolved/dynamic names and property targets never become
binding links. Counts describe static operations, which can share one source
occurrence, not runtime uses or dataflow. Call targets remain unknown.
**Reveal declaration** and operation **Original bytes** actions use the same
verified UTF-8 reader. Changing the explorer selection cancels its pending
reveal. Source identity changes and successful reanalysis clear selected fact
IDs; a failed retry preserves the existing report and selection. Search supports
Unicode composition and keeps captured labels inert. Nothing executes source,
adds capture, or persists an index. Shadowed declarations retain distinct IDs and ambiguous bindings
remain candidates. Neither is proof of initialized values, dataflow or runtime
call targets; region-local order is conditional on entry and normal completion.

An **Original bytes** link loads the complete original artifact through the
existing verified 2 MiB chunk endpoint (at most 4 MiB total), checks its SHA-256,
and strictly decodes UTF-8 while retaining a byte-order mark. It then switches
the existing editor to original source and reveals the selected half-open byte
range. The start-line span is highlighted when browser highlights are available;
multiline ranges remain explicitly labeled. Links beyond line 20,000 now mount
the corresponding bounded line/column excerpt; a clipped highlight is labeled. A lossy preview,
a different session, changed hash or derived representation is never used as a
byte-coordinate substitute.

Cancel, closing Facts, source changes and leaving Sources discard pending
responses. An already started bounded worker may finish, but its result is not
applied. Response readers own a bounded byte buffer: at most 33 MiB for facts
and 2 MiB per original-source chunk. They reject more than 65,536 stream chunks,
including empty chunks, and yield every 256 chunks so fragmented responses cannot
starve cancellation or deadlines. Cancelling does not wait for producer cleanup.
Requests have a ten-second deadline including response-body reads;
retries are explicit, and a failed retry preserves the last successful report
for the same exact source. Only one report and one verified original source are
retained by this view.

The native app's live workspace loads the bundled Rust HTTP backend and shares
this feature with browser development. The separate `reb://` stored-evidence
native interface does not have the reviewed adapter: Facts is disabled with a
visible explanation in Details, and direct requests return structured HTTP 503
`dependency_unavailable`. No Swift parser or duplicate validator is substituted.
See [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md).

## Programmatic HTTP access

The Rust backend's endpoints are described in the
[OpenAPI 3.1 specification](../../protocol/openapi.json). Run
`apps/origin-trace-backend/target/debug/reb-api list` from the repository root to discover
CLI operations. The `call` command requires an explicit loopback URL or the
server's `--endpoint-file`; see the [HTTP API guide](../../protocol/http-api.md)
for examples, locality checks, and known gaps. The CLI does not start or control
an installed native app session, and the native custom-scheme interface is not
itself an HTTP server.

## Pane sizes

Drag the shared borders in Traffic, Sources navigator, and Tools Decoder to
resize adjacent panes.
The divider shows an accent on hover or keyboard focus. Tab to a divider and use
the arrow keys along its axis; Shift changes the step from 10 to 50 pixels.
Home or double-click restores that split's default. Escape cancels an active
drag. Traffic saves wide column and narrow row splits separately. Sizes persist as
proportions in the local `origin-trace.layout.v1` preference, independently of evidence and backend state.

Minimum pane sizes keep controls and empty states usable. The Sources toolbar
wraps within the editor; its narrow details overlay starts below those controls. Saved widths are suspended when the
responsive layout stacks panes or lacks enough space. Returning to a wide window restores them. Handles follow scrolling and
are clipped to the active workspace. `pane_layout.js` owns the shared layout controller;
no captured evidence is modified by resizing.

Captured WASM opens in Hex. **Inspect** shows bounded sections, types, imports,
exports and function disassembly with byte-offset links back to original bytes.
Function indexes include imports. **Find** searches retained Hex text or
offset-bearing inspection rows with an explicit inspection label. Inspection
headings and omission messages are excluded; partial coverage stays visible. Failures
provide **Retry inspection**. Partial coverage and display limits are explicit.
The native shell ships `WasmService.swift` and `OriginTraceWasmInspector`, using
the same Rust provider as HTTP. See [WASM Inspection v1](../../protocol/wasm-inspection-v1.md).

## Evidence investigation and metadata packages

Open **Evidence → Inspect observations & artifacts** in the Requests inspector,
or **Evidence** from Backtraces. The initial view leads with the selected request,
a bounded recorded-observation list and an independently scrolling record inspector.
It separates native request records, explicit same-process parent links, matching
nonzero session/process/navigation/frame context and unlinked retained records.
The compact request summary keeps the missing-parent count and unknown coverage
visible beside the reading panes.
A context match never establishes causation, value flow or request ownership.

The inspector exposes the operation, original bounded inline payload, recorded
outcome, monotonic time and exact artifact reference. API/property markers do not
supply arguments, return values, exceptions or Promise settlement. Observer,
placement, producer and historical build remain unknown. IDs and original hashes
are available in **Provenance & exact identifiers**; they do not crowd every row.
**Coverage & gaps** separates missing parent references, queue markers, sequence
holes, arrival discontinuities, unavailable request records and the retained-window limit without adding
them into a loss total or inventing capture completeness. Numeric holes are counted
from sorted unique session/process IDs, so a later-arriving record can fill one;
absent numbers alone do not prove capture loss. Long request headings ellipsize
with their full displayed text in a tooltip. Coverage opens a bounded, keyboard-
scrollable disclosure above the workspace and never consumes the pane height;
Escape closes it and restores the summary focus. Records remain in retained
order within relationship groups, not a cross-process execution timeline.

The view inspects at most 5,000 events and 500 artifact descriptors, renders 50
observations per page, bounds each parent lookup to 32 links and does not fetch
missing evidence. Search filters existing observations only. Arrow keys, Home and
End move through the displayed order. At 760 px and below, **Observations / Selected
record** switches between full-width panes. Unchanged refreshes preserve inspector
DOM, disclosures, focus and scroll. Eviction explicitly clears the selected record
without silently substituting its neighbor. Selecting a new valid record clears
that selection notice independently of refresh errors. Inspecting a parent
outside the current filter preserves the search/scope draft and clearly labels
the visible parent details as outside it. Empty and failed-refresh states stay
visible; already retained observations remain inspectable after a refresh failure.

**Open captured source** requires a unique session/artifact descriptor, SHA-256,
original byte size and the approved shared investigation adapter. The adapter opens
original Sources passively and preserves shared Back history; URL matches never
substitute. Builds without that adapter show a visible unavailable explanation.
This tab adds no backend read, capture, analysis or execution. Final composed
release acceptance must exercise the working adapter with the Sources ownership
repairs rather than accepting the unavailable standalone state.

**Metadata package** opens the existing selection/export/validation workflow as a
secondary mode. **Return to observations** retains the observation selection and
scroll. Highlighting an observation never selects it for export. Leaving package
mode retires pending package ownership, just as leaving Evidence does.

Choose individual native event identities
(session, process and sequence) or artifact identities (session and artifact).
The selected-request view uses only that request's attached native records;
synthetic gap rows are not export identities. The other
views expose the current retained windows, at most 5,000 events or 500 artifacts,
with 50 candidates per page. They are not an exhaustive store inventory. The
pager stays above the viewport-bounded list. **Limits & privacy** holds the
longer coverage and disclosure explanation without crowding the selection view.

Nothing is selected automatically. Selection spans pages and views, with limits
of 1,024 events and 64 artifacts. **Selected identities** keeps the exact keys
inspectable if their rows leave the window. **Clear selection** removes all keys;
changing the selected request also clears the selection and any prior result.
Refresh does not silently choose a replacement. A missing selected identity
fails export rather than substituting a neighboring record.

**Export selected metadata** explicitly calls the local guarded exporter and
then validates the returned original bytes. It never stops a writer, changes
capture settings, creates a guard for a legacy store, or retries automatically.
An active writer, changed source, unsupported store, failed integrity check or
bounded-scan limit has a visible error. Supported stores must be quiescent under
the existing cooperative leases; see the [package contract](../../protocol/evidence-package-v1.md).

Alternatively, choose a metadata JSON file up to 4 MiB and click **Validate
original bytes**. Duplicate members, invalid UTF-8, BOMs and whitespace reach the
Rust validator unchanged. The UI parses only an accepted document for display.
Validation neither imports evidence nor runs code, fetches references or uploads
data outside the local service. The 15-second UI deadline includes body and file
reads. Response reads retain one buffer (at most 4 MiB for a package, 64 KiB
for a validation result) and reject more than 65,536 transport chunks. Reads yield
every 256 chunks so cancellation/deadline tasks run; cancellation does not wait
for an underlying producer's cleanup. Cancel, Escape, a changed selection/request or leaving Evidence retires
the pending result. An already started bounded server operation may finish.

A valid package is internally consistent, untrusted metadata, not authenticated
evidence. A supplied file's provenance and export-time verification remain
unverified claims. The view separates selected metadata, retained-source scan,
unknown/partial capture, reference resolution and scoped loss observations.
Queue-drop counts and sequence holes are not added into a unique loss total.
Historical builds, capture settings, authorization, observer regime and epochs
remain unknown. API markers do not prove return, throw, WASM trap, reentry or
Promise settlement. Event-time context does not identify the current live page.
Records, references, gaps and issues are paged; captured strings remain text.

No save or clipboard action is automatic. In the browser development UI,
**Download validated package** requests a download of the exact validated bytes;
check the browser's download UI for completion. The native WKWebView has no
reviewed download adapter, so Download is disabled with a visible explanation.
**Copy validated metadata** is an explicit JSON-text clipboard action and reports
clipboard denial without claiming a save. In `reb://` stored-evidence native
mode, export and validation are unavailable; the live native workspace uses the
bundled Rust HTTP backend.

The browser-free contract and DOM-fixture tests run under `make lint` via
`node tools/check-origin-trace-debugger.mjs --field-provenance-only`. These tests
cover byte preservation, identity, bounds, interruption, focus ownership and
explicit saving; they do not establish rendered, native clipboard or macOS
packaging acceptance. Interactive QA must additionally inspect keyboard use,
50-row paging, independent panel scrolling and controls at desktop and narrow
widths, plus Cancel/Escape, Back/reopen, file replacement and late responses.

All native HTTP entry paths, including an explicit loopback `--ui-url` without a
query, normalize to one `native=1` marker. Unrelated encoded/repeated query
parameters are preserved. Stored native loads also carry the marker; ordinary
browser URLs without it remain browser mode. `make app-build` exercises the
actual compiled Swift normalization helper before signing, without starting an
application window. This helper check does not establish native clipboard or
rendered WebKit behavior.

### Sources document ownership and recovery

Opening a file reads its preview only. **Deob** explicitly starts inert static
analysis; entering Sources from another workspace never starts it. Analyzer
responses must match the submitted artifact, its session, SHA-256, source byte
size, intrinsic assumptions and original-source map. SHA-256 is recomputed over
the returned original text. Missing, loading or truncated previews cannot
authenticate analysis. Replacing the preview owner retires pending results.
Changed or closed owners cannot accept a late response, and analyzer text never
replaces the original preview. A failed explicit retry preserves only the last
successful analysis for the same identity. URLs are display/search hints, not
proof of ownership.

Artifact catalog refreshes preserve an exact pending preview owner. Changing
its session, hash or descriptor retires that read. Preview failures and deadlines
show **Retry source**; they do not silently retry during refresh. Preview bodies
reuse the Facts bounded streaming reader: 2 MiB raw artifact bytes and 33 MiB
for an analyzer envelope, with at most 65,536 chunks. Artifact and analyzer
deadlines are ten seconds, including body reads and SHA-256 work. Cancellation
retires ownership without waiting for a stalled producer's cleanup. Full artifact
previews verify SHA-256 when WebCrypto is available; partial or lossy text is
visibly a preview. Exact byte navigation still belongs to the existing Facts
verified-original reader.

The editor retains at most eight preview owners and 16 MiB of UTF-16 preview
text across captured files. The selected owner is pinned; older preview
bytes can be evicted while their tab and immutable catalog metadata remain.
**Retry source** or reopening the file loads it again. Closing a file cancels its
preview/Deob reads and releases its preview, Deob and formatting cache entries.
Tab, navigator, Quick Open and retry handlers retain descriptors only; obsolete
empty/retry controls are removed when the editor becomes ready. Hidden UI
closures cannot keep evicted preview or analysis payloads alive. This never
deletes captured evidence. Canvas thumbnails and the existing bounded
Facts/WASM inspectors retain their separate ownership contracts. WASM Hex formats
every retained byte whose text fits in the 8 MiB editor index, about 1.6 MiB of
module bytes. A longer module keeps a labeled prefix, and Find covers that prefix.

Deob retains at most eight documents, 16 MiB of original/derived UTF-16 text and
250,000 map segments and 32 MiB of serialized response data in total. Formatting retains at most two documents, 12 MiB
of input/output UTF-16 text and 500,000 segments. These are explicit text/entry
budgets, not JavaScript heap or process-RSS guarantees. The editor DOM and Facts'
independently verified original also use memory; no duplicate history of source
bytes is introduced.

Unchanged source/representation refreshes keep the editor DOM, scroll, Find
occurrence and focus, including enabled original-source map links in pretty or
derived views.

Cross-workspace callers can pass the investigation-navigation v1 tuple to
`selectArtifact(id, line, {identity})`: `{type:'captured-artifact', session,
artifact, sha256, bytes}`. `sourceArtifactIdentityMatches` advertises this guarded
receiving boundary. Selection returns false before any read when that identity
is stale or the artifact ID is globally ambiguous. When shared investigation
navigation is present, callers should continue using its `openInvestigation`
adapter and bounded Back/Forward trail.

### Compare supplied packages

Evidence still opens on recorded observations. Open **Metadata package**, then
**Compare supplied packages**, to choose two local metadata JSON files and click
**Compare metadata**. File selection alone makes no request. This secondary view
uses the same reviewed local API and bounded reader; it does not export selected
observations, capture more data or save files automatically. The two inputs are
independent of the current observation selection.

Comparison keeps declared metadata differences, scoped references and unknown
capture/observer coverage distinct from raw-byte verification or equivalent
behavior. Failed or malformed replies preserve the last accepted result. Close,
Return to observations, leaving Evidence and a changed request retire pending
ownership while preserving the local file drafts. Ordinary refresh does not
remount the controls, change drafts or rerun a comparison. Starting from Compare
or a paging control moves focus to enabled Cancel while that trigger is disabled.
Completion restores the Compare control only if Cancel still owns focus; newer
focus choices remain untouched. Escape cancels active work; a second Escape closes comparison and returns focus to its explicit entry.
A departing document disposes the owned component; BFCache suspension cancels
work without discarding drafts. Navigation history contains only view metadata,
not file objects, exported keys, comparison buffers or approvals.

Comparison works in browser HTTP and the native application's live HTTP
workspace, including the native=1 entry marker. Stored `reb://` mode has an
explicit unsupported explanation and mounts no comparison file inputs. This
restriction does not apply to the whole native app. macOS runtime and packaged
asset acceptance remain separate checks.

## Float32 comparison

Open Tools → Float32 comparison to inspect exact hexadecimal binary32 words,
base64 bytes, or a selected retained artifact. Declare byte order, channels and
frames; optionally enable a reference. Inspect / compare is explicit. Raw bits,
signed zero, NaN/Infinity counts, input digests, finite deltas/ULP and caller
tolerances remain distinct. Sample pages do not narrow full-buffer metrics.
Edits, cancellation and failures keep the last report visibly stale.

This uses the local Rust backend, including live native sessions. Stored-evidence
native mode displays its limitation. No sample capture, audio graph collection,
platform identity, normalization, spoofing or target execution is added. See
[the versioned contract](../../protocol/float32-comparison-v1.md).

The existing VM findings view now includes an explicit local [execution semantics workflow](../../protocol/vm-semantics-v1.md): bounded trace import, state changes, opcode candidates and hypothesis counterexamples. It preserves existing detection findings and does not claim native guest-opcode capture.

In the VM workflow, opcode support and hypothesis counterexamples link to an
exact retained step. Inspect structured PC, register, stack and sparse-memory
before/after cells; Changes only hides unchanged snapshots. Select a location
to page through its retained occurrences (not inferred reads or writes).
Previous/Next visits retained steps, including across explicitly incomplete gaps.
Raw audits remain collapsed. Unknown null, absent cells and known zero remain
distinct.

An optional second local trace supports a deliberately selected two-step
comparison. Choose each step and press Compare selected steps; there is no
alignment by sequence, PC, opcode or hash. Both exact input-file SHA-256 digests
are separate from supplied artifact-hash claims. A supplied native backend label
does not authenticate capture. Equal snapshots never prove semantic equivalence.
Native canonical fixture traces remain a separate format, with no lossy importer.

Structured state and manual-comparison views show at most 64 location rows per
page, with visible ranges, totals and Previous/Next controls. Opcode groups,
support-step links, validation links and hypothesis mismatch rows also use 64-item pages; location
occurrences use 16. Paging keeps the exact step and selected location; page
controls restore keyboard focus after rerendering. A counterexample link reveals
its first mismatching observed location even when it is on a later page, showing
all locations for that explicit navigation. Raw audits and CLI reports retain
all cells, including the maximum 706 state / 1,218 comparison locations.

### Retained execution workspace

Within VM investigation, **Findings / Execution workspace** switches between two
mounted views. Finding selection, detail scroll and source actions remain in the
Findings view; incoming finding navigation returns there. Identical or failed
analyzer refreshes update the status notice without rebuilding retained findings,
so a poll finishing in another VM mode preserves the same nodes, focus and scroll.
Changed findings, selection and source availability still update the view.
Imported traces never bind themselves to a finding by a supplied ID or hash.

Execution uses the remaining workspace height. At 1,100 px usable width it shows
trace/opcode navigation, a dominant **Retained execution listing**, and the
synchronized selected-step inspector. At 760–1,099 px navigation becomes a
closeable drawer; below 760 px **Listing / State / Evidence** selects one pane.
These thresholds use workspace width, including when the surrounding app changes.
The existing Console remains separate. Occurrences, validation, manual comparison
and complete raw audits open in a contextual area that starts closed.

The workspace has one compact action toolbar and three labeled areas: Navigation,
Execution and State. Paging stays below the listing; provenance and advanced
analysis open on demand. Selected instructions have an accent rail, and changed
snapshot cells have a separate tint plus a literal changed label. These cues do
not infer reads or writes. Full instruction bytes remain unavailable; PC units
remain adapter-defined. The short-height layout scrolls rather than shrinking
the listing or text.

Rows preserve increasing exact sequence IDs, including repeated PCs and explicit
retained gaps. The 64-row pages never choose another step. Literal filtering over
supplied sequence/PC/opcode/operand text and opcode filtering preserve selection;
**Reveal selected step** clears a filter that hides it and returns to its page.
Filtered-out retained observations are labeled separately from missing execution.
With a row focused, Up/Down, Home/End and Page Up/Down select exact matching rows
across pages; Enter inspects that row. **Back to selected row** restores it. No
shortcut runs code, and editor/IME and application history shortcuts are unchanged.

**Instruction**, **Registers**, **Stack** and **Memory** use one selected-step
report. Instruction includes a paged complete snapshot overview; other tabs filter
its exact namespaces. Selected locations remain marked and linked to retained
occurrences. The instruction size is supplied in adapter-defined PC units. Opcode
hex is only the supplied 1–8-byte field, not a verified complete instruction
encoding. Full instruction bytes and operand-byte layout are unavailable; the UI
never reconstructs bytes or treats a PC as a source offset. A fitting candidate
remains **Inferred**, multiple candidates **Ambiguous**, and no fit **Unknown**.

**Provenance and limits** exposes complete supplied identity, coverage and hashes.
The selected-step raw audit now contains the complete shared report, including
instruction size, identity, coverage and all cells, plus the exact input-file
hash and the existing observed-changes view. This is UI audit completeness only;
the trace schema and existing offline CLI envelopes are unchanged.

The existing `node tools/check-vm-semantics.mjs` controller suite also covers the
256-row listing, four pages, large exact IDs, repeated PCs, filter/selection
independence, keyboard navigation, namespaces, durable occurrence-close focus and
100 bounded paging actions. The full Requests rendered gate retains its previous
assertions and adds workspace/Findings/source round trips and 1440/1024/760/600/360
layouts through `tools/check-vm-semantics-ui.mjs`. Controller checks do not establish
rendered or native acceptance; run the rendered gate on a sandbox-capable browser
and inspect the packaged macOS app, including desktop 200% zoom.

### Observed execution path

In the Execution workspace toolbar, **Listing / Path** switches the same retained
execution pane between rows and an observed occurrence graph. The right-hand
State inspector, exact selection, filters and 64-item page remain synchronized.
At narrow widths, choosing Path reveals it inside the existing Listing pane;
Enter opens State, and **Back to selected row** returns to the exact path node.
The tab pair supports Left/Right/Home/End. Nodes support the same Up/Down,
Home/End, Page Up/Down and Enter keys as the listing. Switching views never runs
code or changes the selected sequence.

Each node retains sequence, supplied PC/opcode/operands, evidence references,
and candidate meanings. Repeated PCs remain separate occurrences. Arrows join
only consecutive recorded sequence IDs. Missing execution has an explicit gap;
filters and page boundaries label hidden observations without shortcut edges.
Observed PC movement is separate from unknown branch alternatives. The graph
is not a static CFG, and neither supplied continuity nor matching candidate
semantics establishes completeness, causal dependence or equivalence.
Trace identity remains visible in the path summary; **Provenance and limits**
retains the complete supplied identity, coverage and exact import-file digest.

The bounded shared `observedPath` model and the offline `path` command are
specified in the [VM semantics contract](../../protocol/vm-semantics-v1.md#observed-execution-path).
The UI adds no capture adapter or new production asset. Imported traces from
any admitted backend retain their supplied-provenance limits; owned fixtures
are acceptance data, not a requirement on the investigated VM.

### Static bytecode analysis

In the top-level **VM** tab, **Static bytecode** accepts an independent local
`reb-vm-definition-v1` definition and `reb-vm-bytecode-v1` image. Choose both JSON
files, then **Analyze**. The separate **Owned example** loads authored loop/branch
inputs for an explicit analysis; it is not a capture and does not execute a VM.
Findings, supplied Execution workspace traces/observed Path, and Live owned
fixture keep their existing independent inputs and controls. Active live Stop
and Pause controls remain reachable while static bytecode is visible.

The definition declares literal one- or two-byte opcodes, operand widths,
endianness, register/stack architecture, supported fixed semantic operations and
control-flow targets. The image declares entry byte offsets and up to 64 KiB of
hex bytes. Each JSON file is bounded to 1 MiB. Linear decoding stops explicitly
at an unknown opcode, truncated/invalid instruction or the 4,096-instruction
budget. Undecoded bytes have no synthesized instruction or pseudocode. This is
bounded declared-ISA analysis, not arbitrary-VM recovery or general decompilation.
See [Static VM analysis v1](../../protocol/vm-definition-v1.md) for the exact schema,
supported operations, static-CFG assumptions and offline commands.

The main address listing pages at 64 instructions and retains exact byte ranges.
Select a row to synchronize **Instruction**, instruction-linked **Pseudocode**,
and **Static CFG**. CFG cards show instruction-level nodes, declared directed
edges and explicit unresolved targets; they do not claim recovered basic blocks
or observed execution. Unknown semantics stay unavailable. Declared reachability,
full byte decoding and equal hashes cannot prove runtime behavior, completeness
or equivalence. **Inputs and limits** distinguishes exact JSON-file SHA-256,
canonical definition SHA-256 and decoded-image-byte SHA-256, exposes diagnostics,
and keeps complete raw audit text available in bounded pages.

Literal filtering does not change selection. **Reveal selected** returns to its
exact address; CFG and pseudocode links do the same. With a listing row focused,
Up/Down, Home/End and Page Up/Down navigate matching instructions; Enter opens
details. Detail tabs use Left/Right/Home/End. At less than 760 px of actual
workspace width, **Addresses / Details** switches panes and Escape restores the
selected address. Short and narrow layouts scroll the workspace and preserve
live safety controls. Valid replacement inputs invalidate prior analysis;
rejected imports preserve it, and Clear invalidates pending reads and hashes.
Nothing is fetched, uploaded, run, or bound to findings by a supplied ID.

`node tools/check-vm-static-ui.mjs` runs authored controller/DOM checks. Its
exported rendered flow is part of the integrated browser gate, covering the
16-instruction example, at least 12 visible desktop rows, mode round trips,
responsive focus/scroll and authored live-control coexistence without native
commands. DOM checks are not rendered or packaged-app acceptance; run the browser
gate and inspect the macOS app, including actual desktop 200% zoom.

### Live owned fixture controls

Open **VM tab** without a captured finding. The workspace also offers **Live owned fixture** when the Rust backend has the
bundled `OriginTraceOwnedVmFixture` helper (development binary:
`build/reb-native-vm-fixture`). Create explicitly chooses the fixed register or
stack program and starts paused before instruction one. Run, Pause, Step, Stop,
Reset and Close control that actual native helper. Imported execution traces
remain inert. Controls remain reachable across the VM workspace while a session
exists; leaving VM stops status polling but does not pause execution. Runs expire
after 60 seconds including paused time.

The native state inspector preserves full unsigned 64-bit strings, evidence
classification, initial state, separate live/history selection and recorder loss.
Declared fixture opcode names do not imply recovered semantics for captured VMs.
See [the public contract](../../protocol/owned-vm-debugger-v1.md) for identities,
uncertain outcomes, explicit recovery and API discovery. Stored-evidence native
mode reports these controls unavailable; use a live workspace.

`node tools/check-owned-vm-debugger-ui.mjs` exercises authored response/controller
cases. Its exported rendered flow requires the real backend and helper. Neither
an authored browser harness nor a DOM model substitutes for native end-to-end
acceptance, keyboard/focus QA or packaged-app execution.

### Colored VM controls and compatibility example

VM action, selected and changed-state colors have distinct dark/light palettes
with text and focus contrast checks. Labels and explicit change markers remain
visible. See [the owned compatibility example](../../docs/development/vm-compatibility-demo.md)
for a small source-derived 16bitjs ISA example: generate 14 recorded transitions,
import them through the existing trace input, and inspect call/return, multiply,
memory, stack and a taken branch. It is an owned fixed-program fixture, not the
upstream runtime or unknown-code decompilation.

### Per-build contextual VM analysis

**VM → Contextual build** is an independent offline workspace for supplied
`reb-vm-contextual-definition-v1` definitions and hash-bound
`reb-vm-contextual-image-v1` images. Import both JSON files, optionally import
`reb-vm-contextual-evidence-v1` observations, then choose **Analyze build**.
Every input is strict UTF-8 JSON, at most 1 MiB. The image is at most 64 KiB.
No input is executed, fetched, uploaded, or automatically attached to findings.
**Clear** removes these local inputs; **Remove evidence** returns to declared-only
analysis. Invalid imports preserve previous valid inputs; valid replacements
invalidate the previous report and any pending analysis.

The linked workbench keeps a searchable, paged context listing beside an
inspector with **Instruction**, **Pseudocode**, **Edges**, **Evidence**, and
**Inputs and limits** tabs. Filtering does not change the selected context;
**Reveal selected context** clears the filter and returns to its page.
Resolved declared-edge buttons navigate only to an exact supplied PC/state
context. Inputs collapse after successful analysis and remain available in the
input disclosure. The application Search and Navigation menus target this mode.

Contexts are keyed by byte-offset PC and decoder-state identity. The same opcode
or PC can have different supplied meanings in different states. Missing mappings
or state remain explicit unknowns and stop only that context. Select a context
to see ordered macro operations, abstract pseudocode, declared outgoing edges,
separately labelled supplied observed jumps, and event/capture/run/context
references. All context, jump, reference and diagnostic lists are paged. Unlinked
events remain inspectable under **All supplied event links**; they never borrow
a nearby instruction or invent an adjacency edge. Matching a declared edge does
not verify semantics, evidence authenticity, completeness or equivalence.

The supported contract is declarative, hash-bound per-build decoding and linking
explicit supplied observations. It does not recover vendor VM definitions,
decrypt images, extract keys/seeds, capture a vendor runtime, or bypass anti-debug
checks. Vendor compatibility remains unverified. Existing **Static bytecode**,
**Execution workspace**, **Findings** and **Live owned fixture** workflows remain
independent, with live safety controls preserved when switching modes.

Authored examples (not runtime captures) are in `tools/fixtures/vm-contextual/`:

```sh
node tools/vm-agent.mjs analyze-contextual \
  --definition tools/fixtures/vm-contextual/definition.json \
  --input tools/fixtures/vm-contextual/image.json
node tools/vm-agent.mjs link-contextual \
  --definition tools/fixtures/vm-contextual/definition.json \
  --input tools/fixtures/vm-contextual/image.json \
  --evidence tools/fixtures/vm-contextual/evidence.json
```

The CLI enforces regular non-symlink file bounds, preserves exact source hashes,
and makes no network requests. See [contextual decoding](../../protocol/vm-contextual-v1.md)
and [runtime evidence linking](../../protocol/vm-contextual-evidence-v1.md).
`tools/check-vm-contextual-ui.mjs` covers controller/CLI boundaries; its rendered
flow is part of the existing browser gate, not macOS packaged-app acceptance.

## Owned opcode experiments

VM Lab's exact owned-source workspace offers an explicit isolated native
experiment for declared addition and nonzero branch. Enter fixed inputs 7 and 5
and the expected selected value/next PC, then choose Run isolated native
experiment. Read saved results does not execute. Results show tested inputs and
do not generalize; unsupported inputs are retained without execution. See
[the strict contract](../../protocol/owned-opcode-experiments-v1.md).

## VM analysis packs

**VM → Analysis packs** exposes the same data-only ranking and build-comparison
functions as the offline `origin-trace-vm-pack` CLI. Import local JSON, specify
exact interpreter artifact IDs for comparison, then explicitly apply or compare.
No imported code executes. Invalid schema, stale digests and undeclared source
families are rejected. Cancel, Clear, bounded preview and complete report download
are available. The local Rust HTTP backend is required; native stored-evidence
mode explains how to use the backend or CLI. See the
[versioned pack contract](../../protocol/vm-analysis-pack-v1.md) for limits and
agent-facing `vm_pack_apply`/`vm_pack_compare` routes.

Analysis-pack reports use a searchable, paged listing with a linked row and
provenance inspector. All returned rows remain reachable; the complete report
export preserves the exact backend response. UI filters and paging do not
change the analysis or its original evidence.

## Opcode evidence ledger

The VM **Opcode ledger** workspace imports exact definition JSON and a bounded
ledger JSON locally. The JSON editor exposes all researcher fields, including
handler byte locations, operand notes, source/test citations and unresolved
questions. **Create empty ledger** binds a new draft to the exact definition
source SHA-256 without inventing entries. It refuses to replace nonempty work.
**Validate ledger** uses the same schema and identity checks as the agent's
`opcode-ledger` command. **Export validated ledger JSON** downloads only the
validated ledger, with no extra analysis envelope; edits invalidate export.
In the native shell, **Copy validated ledger JSON** explicitly copies that same
validated document to the clipboard instead. Clipboard refusal leaves the draft
intact and displays an error; native Blob downloads are not attempted.
The searchable coverage listing pages through every declared opcode and links
the selected row to its full researcher entry and definition provenance.
The inspector's edit action opens the existing JSON draft; it does not infer
meaning, generate citations or change test outcomes. Filtering and selection
do not modify the draft or the validated export.
Previous coverage remains visible but is explicitly stale after edits or errors.

Coverage counts declared opcodes, never runtime execution or verified meanings.
Observed/inferred labels, citations and test outcomes remain supplied assertions.
Nothing executes imported code, fetches references, runs tests, promotes VM
semantics, persists inputs automatically or uploads data. Review private data
before exporting. See [ledger v1](../../protocol/vm-opcode-ledger-v1.md).

## VM findings workbench

Effects, Reachability, Host links, session sources, byte attributions and selected
retained samples page through all retained data in groups of 32. The Bytes view
offers every retained snapshot; the compact handler listing keeps its four-sample
preview. A workspace with `sampler-unavailable` says static-only: host links keep
`dispatch-samples-unavailable` and `guest_position` null, and that is the missing
sampler rather than an empty workspace. Session sources lists same-session stored
artifacts only. `chrome://` rows are browser-UI noise. Shared session is
correlation, not loader provenance, and never a guest position.
Operand width zero means unknown, matching the producer contract. Source locations
show exact retained byte ranges without guessing a source line number.

Findings opens retained evidence for the selected finding. The handler listing
sits beside explicit Effects, Bytes, Reachability, Coverage, Unknowns, and
Experiment panels. Panel switching only changes the view; the isolated
experiment still requires its separate explicit run action. Handler highlighting
does not establish an opcode binding or filter the finding-wide analysis.
Execution workspace, Live owned fixture, Static bytecode, and Contextual build
remain separate modes with their existing ownership and execution controls.

The collapsed **Explore a deterministic owned VM example** is an authored
fixture demonstration, not the active capture. Its replay only reveals fixed
fixture transitions. Back/Forward, Go to PC, and arrow/Home/End listing navigation
share the selected instruction with State and Evidence & source. PC units are
instruction indexes; gaps, unknown bytes, unconfirmed effects, and refused
source digests remain explicit. The example never supplies capture provenance.

### Full-page VM navigation check

`node tools/check-vm-full-shell-ui.mjs` loads the shipped page contracts with
authored loopback responses and validates its literal parser and HTTP
contracts without a browser. Rendered VM composition is covered by
`make rendered-ui-check`.

The desktop Findings layout keeps the program navigator, handler listing, and
selected-handler inspector together above a bottom analysis dock. Handler click
or arrow-key selection updates the inspector's exact source range, evidence
class, sample count, retained positions, and notes. These are handler candidates,
not invented guest instructions. The bottom analysis panels remain scoped to
the finding; selecting a handler does not narrow or reclassify them. Detection
scores and artifact identity stay in a compact strip; full detection evidence
and provenance are available in a disclosure beneath the workspace. Smaller
windows stack the listing and inspector without removing tools.

### Compact pack and ledger workspaces

Analysis packs and Opcode ledger put local file selection and structured results
first. Expand **Compare two builds** for the comparison workspace inputs and
exact artifact IDs. Pack reports show bounded ranking/comparison tables;
**Inspect raw report JSON** retains the original preview and the export keeps
the complete exact response. Numeric identities too large for exact browser
number display are labeled **See exact JSON**, never silently rounded.

Ledger JSON editors are collapsed beneath coverage. **Create empty ledger**
opens the ledger editor for deliberate authoring. Coverage separates opcode,
evidence status, asserted meaning and supplied test outcome; definition hashes
remain available under **Definition identity**. These presentation changes do
not alter schema checks, research assertions, cancellation or export boundaries.

### Exact request VM candidates

Related VM candidates on a native Traffic row sends the complete request root
(session, process, request ID and sequence). Only findings whose response body
has an acknowledged producer-backed creator chain are shown. Same-frame request
IDs remain labeled correlated context, never exact linkage. Empty or conflicting
chains produce no request findings; a new selection cannot retain findings from
an older request, and late responses cannot replace a newer selection.

Incomplete-root rows remain in Traffic with an explicit unlinked notice.
Use the VM workspace navigation for session-wide analysis. Existing captures
without the new browser artifact-parent event remain unlinked. Generated/runtime
allocating-source artifacts do not gain network ancestry from equal URLs or bytes.
This relation identifies captured source, not executed guest VM instructions.
See [exact request selection](../../protocol/http-api.md#exact-native-traffic-to-vm-selection).
