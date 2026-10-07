# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path. The [Rust backend](../origin-trace-backend/)
serves browser development and live debugger sessions, with the same HTTP
contracts and tools. The native Brave broker, artifact receiver, probes, and
wire formats remain C++. See the [backend boundary](../../docs/architecture/origin-trace-backend-boundary.md).

Project-wide authorization, capture, and privacy policy is in
[SAFETY.md](../../SAFETY.md); this guide describes the product's current controls
and limits.

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
source identity and half-open byte range. Request inspector and Field trace
handoffs distinguish selected string bytes from unavailable raw HTTP offsets.
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
Console line offsets are never applied to search candidates. Debugger/native
host-and-time correlations likewise cannot become exact captured trace links.
See [Investigation navigation v1](../../docs/product/investigation-navigation-v1.md)
for the identity boundary, retained limits and integration points.

## Native console

The **Console** bottom dock starts a separate disposable custom Brave session for
explicit main-world JavaScript commands. Set `REB_BRAVE_BINARY` to a rebuilt
custom browser and use the live backend. Open the connection menu to connect a
disposable browser, then select a document before entering commands.
Workspace tabs sit across the top, with Console beside Sources. Commands are
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
The Sources Logs drawer remains the debugger log viewer. Console values and
history remain ephemeral. See [Native Console v2](../../protocol/native-console-v2.md)
for exact operation, bounds, contracts and required post-build verification.
The synthetic wire fixture supplies scripted responses and never executes JS.

## Run

```sh
make app
```

This packages `build/Origin Trace.app` and opens a complete live capture
session. Before launch, the app asks whether the session should retain metadata
only or bounded request and response content. The default isolated research
profile uses Chromium's mock Keychain so launch does not stop on a macOS password
prompt; do not save credentials in that profile. An explicit checkbox opts into
macOS Keychain encryption when credential storage is required. The app does not
mark the session live until the browser debugger endpoint is ready, and the
failure dialog can retry the same privacy mode without restarting Origin Trace.
**New Live Session…** in the application menu reopens these controls.

The app creates a private evidence directory and isolated browser
profile, starts its bundled broker, artifact receiver, debugger transport,
analysis helpers, and loopback UI, then launches Brave Browser Development with
all safe metadata categories enabled. Closing Origin Trace stops the session
processes. Evidence remains under `~/Library/Application Support/Origin
Trace/sessions/live/`.

Origin Trace looks beside its app bundle, in the local `browser/worktree/`
build output, and among registered applications for Brave Browser Development.
A `REB_BRAVE_BINARY` override takes precedence. The app bundles its Rust live
debugger and VM analyzer, so Python is not required. A startup problem is shown explicitly
and leaves the stored-evidence interface available offline.
Pass an explicit evidence-store or demo argument, or set
`REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`, when opening the native stored-evidence
interface without starting Brave.

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

Native evidence capture retains host-level network metadata by default. Choose
**Full request and response content** in the native launch dialog to enable CDP
Traffic inspection for one live session. Command-line development sessions can
select the same mode with:

```sh
REB_CDP_NETWORK_CAPTURE=1 make live
```

This enables full URLs, request and response headers, available POST data, and
response-body retrieval for the attached tab. Authorization, cookie,
proxy-authorization, and set-cookie values are always redacted. Request and
response bodies are retained only in memory by the local UI bridge, limited to
128 KiB per side, and discarded when the live session ends. The Origin Trace
title bar visibly changes to `Live content` while this mode is active.
The content-capture label remains visible during connection failures. If the
native broker disconnects while CDP capture continues, the shell shows
`Network only`; Traffic reports both the broker failure and ongoing bounded
network capture. Broker gaps, queue drops, and network-window evictions remain
visible across either refresh path. A debugger failure retains recorded requests
and explicitly reports that network capture is unavailable.
Failed refreshes request a complete validated response on retry, so an unchanged
ETag cannot leave the connection warning stuck after recovery.
Rejected debugger actions, including a full Watch list, retain their own error
without marking active network capture or the live tab count disconnected.
Short windows keep at least one request row visible when status warnings wrap.

The live launcher disables Brave background networking, component updates, and
sync for its isolated research profile. Browser diagnostics are retained in the
session's private `brave.log`, separate from coordinator failures. The native
app pre-creates the matching macOS cache sandbox path before launch.

Redirect hops retain their own status, response headers, and elapsed time when
CDP starts the next request. Their response bodies are explicitly unavailable;
the destination's body is never substituted for an earlier hop.

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

For a live capture without a DevTools connection:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

Quiet mode keeps native evidence capture and Captured Sources available.
Live Page sources, breakpoints, stepping, watches, and console controls remain
disconnected. It does not guarantee that the custom browser is undetectable.

If the attached renderer crashes, Sources shows `Crashed`, clears stale paused
frames, and retains captured evidence. Reload the browser tab to resume the
debugger connection. A connected browser socket alone does not imply that its
renderer is still running.

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
also checks shutdown and handshake removal. Logs are saved under `build/package-qa/`.
The macOS CI job runs this check before uploading the app preview.

The failed-start smoke uses a deliberately missing browser and follows the offline
branch without showing a modal dialog. It does not automate the Retry/Continue
Offline buttons. Headless Chrome tests live debugger startup and packaged routing,
not custom Brave probe capture. These checks do not replace interactive native
keyboard, resize and visual QA. On other platforms, `--contract-only` checks
source wiring only and does not claim native runtime coverage.

## Workspace layout

Traffic, Collection, Sources, and Fingerprinting are available in the sidebar.
Expand **Advanced** for Backtraces, Memory, Experiments, Analyst, and Tools.
Navigation into an advanced tool reveals its group automatically on desktop. On
narrow windows navigation moves above the workspace and closes after selection.

Traffic uses a compact network ledger with visible resource-type filters and
sortable Name, Status, Type, Method, and Time columns. **Capture order** restores
the evidence order. The selected request opens Headers, Payload, Preview,
Response, Initiator, and Timing beside the ledger above 1100 px, or below it in
narrow windows. Both panes stay within the available workspace height; the
request ledger and inspector body scroll independently. Captured-tab and domain
filters share a compact row at narrow widths. REB's Signals and Evidence tools remain separate tabs. Missing
headers, bodies, initiators, and timing phases stay explicitly unavailable.
Request signal profiles are owned by the exact selected session, request and root
event. Late responses cannot replace a newer selection or refresh. Malformed or
failed refreshes preserve only the last validated profile for that same identity
and require a full response on retry; changed or ambiguous owners clear it.
No cache, recording, throttling, or invented waterfall controls are implied.
The layout follows familiar [network inspection conventions](https://developer.chrome.com/docs/devtools/network/reference)
while keeping Origin Trace's own controls and Rosé Pine Moon palette.

Traffic’s **Compare** tab pins one exact retained request as a baseline. Select
another request to compare method, URL, status, request/response headers, and
request/response bodies without replaying either request. **Clear baseline**
releases the reference. Concise baseline and selected-request summaries stay
visible; their disclosure expands the full exact capture identifiers. Demo/sample
rows cannot be pinned. Native references use
session/process/event/request IDs; CDP references use target/protocol-request/start
identity and are never promoted to native provenance. Loss of the exact retained
record, duplicate identities, an observed target change or debugger generation
restart expires the baseline permanently until explicitly selected again.

JSON changes use escaped JSON Pointers, preserve number lexemes (including
integers above 2^53), ignore object-key order, and compare arrays by index. The
view separately labels exact retained UTF-8 byte equality and structural equality.
Duplicate keys (including equivalent escaped names), malformed JSON/UTF-8,
binary MIME types, incomplete capture and unavailable content remain explicitly
unsupported or inconclusive. Header names are case-insensitive and duplicate
values retain their order; redacted values never prove equality. Header capture
completeness cannot be established by the current capture contract.

Comparison is a local interpretation of current retained snapshots, not a frozen
capture or an assertion about original wire bytes or causation. It retains no body
copy in navigation, storage, or the baseline reference. Work is capped at 128 KiB
per body, 4,096 JSON nodes and 24 levels. Each section shows at most 64 changed
rows, with a shared 64 Ki-character report budget, bounded value previews, and
explicit omitted counts. Existing bodies are never rewritten. Unchanged refreshes
preserve the result DOM, focus and scroll; changed results preserve section disclosures
and summary focus. At most four 128 KiB byte snapshots detect in-place changes;
leaving the tab releases the result DOM and these snapshots.

The ledger mounts at most 500 fixed-height rows. Previous/Next page through the
retained window without changing the evidence: the native API retains up to
5,000 events; the existing CDP window retains up to 1,000 requests. Filtering
and sorting cover the whole retained window. Rows and capture-tab controls are
reused across refreshes. New arrivals briefly accent the row edge once; pending
requests use a steady label. Reduced-motion disables animation and transitions.
Refresh preserves the reading anchor and keyboard focus and never follows the
bottom automatically. **N new requests** explicitly jumps to the newest capture
window. Selection survives filters and sorting; its absence from the filter is
labeled. An actually evicted selection reports that it left the retained window
instead of silently selecting another request.

Arrow keys select adjacent request rows; inspector tabs use Left/Right and
Home/End. Escape dismisses Find or viewer options first, or closes the inspector and
returns focus to the ledger. The close button has the same behavior. A dismissed
inspector stays closed across refreshes; selecting a request reopens it. Full
URLs remain available in Headers and Copy URL, and host-only metadata never
implies a captured path or query.

Choose **Include headers and bodies** beside Traffic search to find a literal,
case-insensitive value in retained request or response text. Each result names
its first matching location; selecting a content match opens Headers, Payload, or Response
with Find filled in. URL, method, and status remain searchable.
Tab, domain, and resource filters scope the search before content is inspected.
Search never enables capture or fetches missing bodies. Binary and uncaptured
bodies are excluded, and retained prefixes and redacted headers limit coverage.
Large captures use an explicit 8-million UTF-16-unit search budget, newest
requests first. A partial-search notice reports inspected and omitted coverage
and suggests narrowing filters. See the [content search design](../../docs/product/traffic-content-search-v1.md).

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

Field trace can send its original request string through explicit Decoder steps
and search attached sources for the selected result. Original evidence remains
visible beside a derived search value and transformation history; matches are
labeled decoded candidates. The handoff rejects binary or oversized results,
edited inputs, and changed field selections.

Fingerprinting starts with an Overview of active surfaces and captured Canvas
output. **Show inactive surfaces** reveals the rest of the supported families.
Surface chips open filtered Activity. Each Canvas card keeps replay comparison,
drawing calls, and evidence identifiers in expandable sections; open sections
and summary focus survive evidence refreshes. Activity opens its details pane
when an event is selected, or with **Details**. Decoder processing limits and
result statistics are likewise available in expanders beside their controls.

Advanced workspaces keep the primary task visible and secondary information in
expandable sections. Backtraces groups correlation identifiers separately from
relationship facts. Memory places its four modes above the search and results.
Each Memory mode keeps criteria, explicit action, and inspection separate. The
result receipt records the submitted target, time, and criteria; diff receipts
also retain the submitted baseline's native target/time/size metadata. Baselines
are target-scoped; the native contract does not provide document identity. Draft
scope changes do not rewrite an existing result. Captures can briefly pause the
target, and origin tracing explicitly controls debugger stepping until stopped.
Completed debugger polls are reconciled when actions settle, including after a
lost acknowledgement; a matching terminal trace poll can retire an unread
acknowledgement immediately. Memory HTTP waits have explicit headers-and-body
deadlines: 30 seconds for live search, 90 for baseline capture, 120 for snapshot
search, 150 for diff, and 15 for trace controls or baseline reset. These include
margin beyond the existing native command/worker timeouts and do not limit or
cancel an already-running native trace. Target/context/epoch expiry also retires
the wait. Only that HTTP read is aborted; completion stays unconfirmed, no
action is automatically retried, and a retired request cannot release a newer
action's pending latch. Other debugger callers keep their existing request behavior;
an older reply cannot overwrite a newer terminal trace or baseline.
Trace-ID ordering is scoped to the observed native restart epoch.
Acknowledgements require a valid generation before reporting reset or clear.
No action is automatically retried. Lost, malformed, or stale replies report an
unconfirmed outcome: discarding a reply does not stop native work. Target or
observed execution-context changes expire previews without relabeling them as
current. Only the current bounded result is retained, with no heap-file history.

Memory result rows keep their identity during unchanged refreshes, preserving
keyboard selection, focus, detail scroll, and incoming-reference disclosures.
Snapshot paths and incoming references remain separate; heap diffs show retained
owners even when no signature groups changed. Partial results qualify absence
and dominator claims. Origin traces expose the recorded location as text, but do
not open a live source using only a possibly reused script ID or URL: the trace
contract lacks the execution-context/source-hash identity needed for that link.
Request-field pivots only fill criteria and do not run captures; a pending action
keeps its criteria and receipt when the workspace is reopened.

The `--memory-ui-browser` mode of `tools/check-origin-trace-debugger.mjs` uses
the existing installed-Chromium driver and synthetic native API fixtures. It
covers four workflows, race/error/partial states, keyboard/refresh behavior,
inert text, and wide/narrow geometry. It is separate from native macOS validation.

Experiments separates setup, request, and response, with activity logs collapsed.
Analyst prioritizes the editor and evidence permissions; folder settings, storage,
variables, execution limits, and history can be expanded as needed. Tools keeps
input and output visible with transformation history available on demand.

## Code ownership

| Location | Responsibility |
| --- | --- |
| `index.html`, `app.css` | Document structure and visual layout |
| `app_state.js`, `evidence_models.js`, `app.js` | Initial state and DOM bindings, evidence validation and projection, interaction and rendering |
| `field_provenance.js`, `../origin-trace-backend/src/provenance.rs` | Selected request strings, bounded source candidates, replay evidence, source identity checks, and explicit value-flow gaps |
| `request_value_test.js` | Ephemeral request-value capture controls, observation selection, and comparison rendering |
| `pane_layout.js` | Shared pointer and keyboard pane resizing, responsive constraints, and local size preferences |
| `traffic_view.js`, `traffic_comparison.js` | Bounded request/response views, exact retained comparison ownership, lossless structural JSON comparison, explicit missing-data states, and labeled sample exchanges |
| `source_syntax.js` | Source names, display formatting, and bounded tokenization without DOM or application state |
| `native_console.js`, `native_console_completion.js` | Disposable browser console controls and local built-in API completion |
| `../origin-trace-backend/src/app.rs`, `evidence.rs` | Loopback HTTP routing and bounded evidence reads |
| `../origin-trace-backend/src/debugger/` | CDP sessions, transport ownership, request validation, hooks, experiments, and automation |
| `../origin-trace-backend/src/workspace.rs`, `analyst.rs`, `durable.rs` | Workspace contracts, explicit analyst execution, private durable replacement |
| `../origin-trace-backend/src/decoder.rs`, `origin_trace.rs`, `vm.rs` | Native decoder adapter, trace projection, and VM analysis |
| `macos/` | Native shell, evidence readers, and helper processes |

The browser scripts load in the order declared in `index.html`. They use the
same page scope so the native shell and browser development path share one
implementation without a bundler. `evidence_models.js` contains evidence
validation and projections; `source_syntax.js` owns source display algorithms.
Live refresh and DOM updates belong in `app.js`.
The native scheme handler and packaging script explicitly list shipped assets.

Traffic correlates native requests within method/host buckets, preserving native
order for equal-time matches. Decoded binary bodies are reused only while their
request remains in the current network window and its encoded bytes are unchanged;
headers and capture states always come from the latest validated snapshot. Live
source text is retained only for the current validated script catalog and matching
target/hash identity. A failed refresh preserves the last valid cache, and a
detached pending load is cancelled and cannot restore obsolete source text.
Source fetches have a 15-second deadline, including body reads; a timed-out load
can be retried by selecting the source again.

Debugger support modules must not import the session coordinator or the HTTP
server. Pure request validation does not require a browser connection. The
coordinator owns session locks, authorization, cancellation, and feature
lifecycle transitions.

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

### Rendered Requests regression check

The existing debugger checker includes offline DOM/state regressions in
`make javascript-check`. Those checks do not claim browser interaction or pixels.
For a real browser pass, use an installed Chrome/Chromium with its normal sandbox:

```sh
REB_UI_CHROMIUM="$(command -v google-chrome || command -v chromium)" \
  node tools/check-origin-trace-debugger.mjs --traffic-ui-browser
```

The `requests-ui` CI job runs this mode on the existing Ubuntu runner. It serves
only synthetic fixtures on loopback, exercises pointer and keyboard workflows,
checks 500-row paging, synchronized selected-summary lifecycle changes, selection/focus/scroll retention,
content invalidation, empty/malformed/offline states, dismissal, narrow layouts,
and reduced motion. Narrow checks require two visible ledger rows, visible
inspector tabs, at least 80 px of preview height, independent wheel scrolling,
and hit-tested pointer targets without scrolling an offscreen workspace into view.
Genuine rendered PNGs and a success-only `validation.json`
are written under `build/requests-ui-qa` and uploaded as a short-lived CI artifact.
Readiness uses Chrome's `DevToolsActivePort` file with a 30-second deadline,
not a stderr banner. The socket handshake has a separate 10-second deadline.
`browser-startup.json` is written even when startup or interaction fails; it
contains bounded process output, the readiness stage, browser version when
available, exit status and cleanup results. The checker terminates only its own
isolated browser process group, including launcher helpers, with bounded
SIGTERM/SIGKILL waits. No successful validation manifest is written until both
interaction and cleanup complete. Startup process/socket fixtures also run in
`make javascript-check`; they do not claim rendered browser coverage.
A browser startup or sandbox error is a failed/unavailable check, never a pass;
do not disable the sandbox to run it. Native macOS interaction remains a separate
product-path requirement.

### Rendered Sources facts regression check

The same `requests-ui` CI owner also runs a separate Sources facts mode:

```sh
REB_UI_CHROMIUM="$(command -v google-chrome || command -v chromium)" \
  node tools/check-origin-trace-debugger.mjs --source-facts-ui-browser
```

This uses the existing browser lifecycle and strict hit-tested pointer/keyboard
checks with synthetic immutable source artifacts. It covers exact selection,
100-row paging, keyboard categories and disclosure, original UTF-8/BOM byte
navigation, profile-relative coverage, unknown frontiers, unavailable and error
states, retained reports, cancellation and retry, source changes, Hooks dismissal,
Close/Escape focus, and narrow-sidebar navigation. Analyzed source is never
executed. Sources runs even if Requests fails, unless the job is cancelled.

Separate screenshots, bounded startup/failure diagnostics, and a success-only
`validation.json` are written under `build/source-facts-ui-qa` and uploaded as
`source-facts-ui-<run id>`. Inspect these screenshots as well as the interaction
receipt before accepting rendered behavior. A startup error cannot produce a
passing receipt. These browser fixtures do not replace real Rust/Oxc HTTP/CLI
integration, native live WKWebView testing, or macOS package validation. Stored
`reb://` evidence still reports Sources facts as unsupported.

Collection has a separate mode on the same sandbox-preserving browser QA driver:

```sh
REB_UI_CHROMIUM="$(command -v google-chrome || command -v chromium)" \
  node tools/check-origin-trace-debugger.mjs --collection-ui-browser
```

It uses a synthetic loopback collection store and scripted disposable transport,
never a real target request. CI checks pointer/keyboard authoring, dirty draft
ownership, invalid/failed/conflicting saves, explicit Save & Run, late-result
identity, inert response text, independent response scroll, load retry, and
760/360 px layouts. Genuine screenshots and success-only validation are retained
under `build/collection-ui-qa`. The normal JavaScript gate separately exercises
actual controller functions for deterministic failure and stale-result races;
those DOM fixtures do not establish rendered acceptance.

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
refetching on every refresh. At most two unfinished preview reads are allowed,
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

Rendered Canvas regression coverage runs with
`REB_UI_CHROMIUM=/path/to/chrome node tools/check-origin-trace-debugger.mjs --canvas-ui-browser`
and in the installed-Chrome `canvas-ui` CI job. It serves authored artifact
metadata and bytes through the real application routes, decodes a 16 × 16 PNG,
and exercises refusal/error labels, explicit retry, gallery retirement and
reopening, pending-body cancellation, keyboard controls and narrow/wide layouts.
Screenshots, browser diagnostics and fixture receipts are written under
`build/canvas-ui-qa/`. A fail-closed observer at the native image source setter
records assignments and fails the test before any rejected giant-header fixture
can enter decoding; accepted tiny images use Chrome's real decoder. No product
admission or ownership function is replaced. A separate fresh document uses
an authored `img-src 'none'` response policy to trigger real image load errors
and verify the existing error label and cleanup. This is policy/load-error
coverage, not evidence that Chrome rejects corrupt compressed PNG streams.
These receipts do not establish native capture, macOS behavior, decoder-memory
reclamation or process RSS bounds.

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
captured-tab buttons are historical evidence, not an open-tab count. In a live
debugger session, the browser target list supplies a separately labeled current
page-tab count, refreshed as targets open and close. Quiet mode and a lost
debugger connection show that count as unavailable rather than guessing from
captured events. The footer separates missing per-process sequence IDs from
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

Sources navigation exposes Page and Captured collections. Page removes scripts
when their execution context is destroyed or cleared, including removed frames
and full navigations. URL breakpoint definitions and captured evidence remain;
only resolved locations in retired scripts are discarded. Unimplemented
Workspace and Overrides tabs are omitted until they provide a usable workflow.
File rows reserve their remaining width for the filename, with full URLs in
tooltips and source metadata in Details. Folder rows retain their item counts.
Clicking original source records the UTF-16 column across syntax spans, so the
Hooks panel can target a function inside a minified line. Inline script offsets
are included; readable representations cannot change the runtime cursor.
In a connected session, **Hooks** opens the shared Runtime Hooks workspace
beside the Sources editor, with its ephemeral hit trail below the code. The
panel creates and manages the same disposable Experiment context used by
Experiments; its header labels the isolation and links back to Experiments.
Targeting guidance stays in the **Targeting help** disclosure, while armed
status uses a compact hit count.
Selecting a hit returns to the original live source location when that script
is still attached. Captured or pretty-printed sources cannot prefill a runtime
location, and an unavailable script is reported rather than guessed.
Runtime Hooks resolves a selected cursor against the original live JavaScript with
the bundled Rust parser. It chooses the innermost function, including anonymous
callbacks and arrows, and shows its start and V8 entry-search position before
arming. A cursor outside a function is rejected rather than creating a hook at
an unrelated statement. In an isolated Experiment context, Sources also lists
dedicated-worker scripts with a Worker label. The Hooks panel can select one of
those scripts; ordinary page-debugger gutters remain disabled for worker
sources. Runtime Hooks can arm page and worker definitions together, with
commands and hit records identified by target. Live-function-object mode takes
a side-effect-free expression such as `self.onmessage` in the selected target
and captures entry only; it does not discover closure-held functions
automatically. Worker attachment runs off the page-target watcher; a failed
attachment drops its scripts and retries with bounded backoff. The breakpoint
active setting is shared with attached workers. While armed, page and worker requests
appear as bounded, redacted metadata. Links to nearby hits are labeled
temporal/inferred, not causal proof.
Selecting one of these requests opens a separate ephemeral trail in
Traffic, with links back to retained hits. It is not merged into the captured
request ledger or presented as a proven initiator chain.
The optional [Request Value Test](../../docs/product/request-value-test-v2.md)
starts from **Test a request value** in Session or an isolated request's Traffic
trail. Its controls stay with the disposable-page setup, separate from the hit
trail. Select a method, query-free URL, and one JSON, form, query, header, or
raw-text value, confirm capture, then reproduce the request. No hook is needed
for observation. The active capture summary is separate from editable drafts;
changing a draft requires fresh confirmation, and restarting capture erases the
previous observations. Field names and JSON Pointers are used exactly as entered.
The comparison defaults to distinct available observations from the same target,
keeps a selected pair across refreshes, and remains usable while hooks are armed.
For an intervention, first collect a return-hook baseline, then disarm and replace
that hook with a synchronous return override before repeating the same input.
A matched comparison is intervention-associated, never complete value provenance.
The value preview is erased with the disposable context.
[Request Field Provenance v1](../../docs/product/request-field-provenance-v1.md)
connects Traffic's JSON tree and Query selection to that workflow through
**Trace value**. It shows observed request call sites, bounded original-source
text candidates, and equal-string replay hook candidates. **Test value** prefills
the exact selector; **Field trace** returns from the test. Source links require
retained target, script, and source hash identity.
Find counts literal, case-insensitive occurrences within rendered lines, including
multiple matches on one minified line. Enter advances and Shift+Enter goes back,
wrapping through the first 1000 matches with a visible `+` when results are capped.
The selected occurrence scrolls into view and supplies the original-source Hook
location. Formatted search is display-only; captured bytes are never rewritten.

The Sources sidebar starts closed without an attached debugger. Details opens
source metadata and connection status; attached sessions show debugger controls
by default. The toggle remains available at narrow window sizes.

VM analysis is a secondary Traffic view, reached through Related VM candidates
for a selected request. It has a Back to traffic control and no primary tab.

Experiments puts its mode switcher and current connection state in one compact
toolbar above three stable setup, editor, and result panes. Each pane scrolls
independently on wide windows; narrow windows stack the results below the forms.
Scope, session metadata, resource limits, request restrictions, response
comparison, and advanced object search use native disclosures. Switching tools
preserves form drafts and disclosure state. Scope is shown only for Interceptor
and Automation, which support it.

An action is acknowledged only after its `ok: true`, generation and required
result groups validate for the submitted disposable lifetime. A transport success
alone is insufficient. Missing, rejected, stale or malformed receipts leave the
draft available and never trigger an automatic retry or a chained Repeater send.
A newer validated poll is never replaced by an older receipt; changed newer
groups also prevent that receipt from acknowledging the current draft; an already-running
poll cannot undo an accepted receipt. Automation recipe/run aliases must match
the validated records. Additive response fields are bounded to 64 levels, 65,536
values and 4 Mi characters before retention or iterative comparison.

Refreshes within the same lifetime preserve drafts and consent. A changed
creation time, disposable target/session identity or observed generation reset
erases disposable form values, confirmations, selections and hidden result DOM.
Late replies cannot restore them, including an identity that leaves and returns.
Expired in-flight reads release their UI busy controls even if transport stalls;
this does not cancel native work or resend an action.
Ownership is checked again after each awaited receipt, including the gap before
its caller resumes. Repeater keeps the original complete request draft and
selection/edit revision through Apply and Send; changed drafts require a fresh
explicit Send. Collection keeps the original saved recipe and inherited variables,
and rejects a changed lifetime, edited recipe or newer draft before sending.
Changing the Collection selection alone never substitutes the newly selected
recipe. Disposable run ownership is erased on lifetime replacement while saved
Collection definitions and drafts remain intact.
Saved automation definitions remain in authoritative backend state. Disposed
Interceptor results may be inspected until creating another context; that new
lifetime starts with an empty result, audit and rule even if creation fails.
The browser-free production-function regressions run in the existing debugger
checker under `make javascript-check`; they do not establish rendered/native QA.


Repeater keeps method, URL, and Send in one command row above a persistent
request-response split. Compare responses includes a Rust-generated body line diff
with source line numbers, nearby context, newline markers, and explicit limits.
Polling preserves the diff's focus and scroll position. Session actions appear only after a browser target is
connected. Request tabs share the pane header, while idle badges and footers stay
hidden until they contain useful state. Headers and query parameters use compact
key-value rows with per-row enable and remove controls; query rows preserve
duplicate names and update the request URL.

Traffic's Headers tab groups General, Response Headers, and Request Headers.
Payload keeps Query, Body, and Raw request views; Preview shows a safe JSON tree,
formatted retained text, or the existing isolated HTML preview. Response offers
Raw and Formatted text. Find, Wrap, Copy, field selection, Decode, and Trace value
continue to operate on bounded retained content. Equal-length body edits and
header-only refreshes invalidate the selected viewer without replacing its
controls or losing its scroll position. Captured values always remain inert.
Live traffic remains grouped by captured browser tab with an All tabs scope and
a domain selector. Protocol v3 carries the stable top-level tab identifier;
older evidence remains Unattributed. Evidence retains the original payload and
trace actions; Initiator and Timing display only recorded observations.

The viewer distinguishes uncaptured, redacted, loading, failed, explicitly
empty, and truncated bodies. Its local preview is bounded to 128 KiB, 1,000 JSON
nodes, 24 levels, and 2,000 displayed text lines; limits are visible and raw/copy
operate on the retained preview. Sample exchanges are labeled in both panes.
Default native network metadata supplies no request/response header or body
bytes, so the viewer reports them as not captured. Explicit CDP network capture
projects the attached tab's full request lifecycle into Traffic and correlates
it with matching native events when their host, method, and monotonic timing
agree. CDP body retrieval can still report unavailable content for streaming,
evicted, cached, or protocol-internal responses rather than inventing bytes.

Captured `text/html` responses use the inspector's **Preview** tab.
Preview reconstructs a bounded, presentation-only HTML tree inside an opaque
sandboxed frame. It blocks scripts, navigation, submission, network resources,
and external stylesheets; supported inline presentation styles survive.
Short windows scroll the request ledger and inspector instead of collapsing
the preview beneath its controls.
Omitted images appear as text placeholders. Capture truncation and the
1,000-node / 24-level rendering limits remain visible. Preview never fetches
the original URL, changes captured bytes, or enables content capture. Body and
Raw body continue to show inert source text. See
[HTML Response Preview v1](../../docs/product/html-response-preview-v1.md).

## Deobfuscation engines

Deobfuscation stays inside **Sources**. Select a JavaScript source and use the
**Deob** toggle to switch between original evidence and the mapped derived view.
The adjacent **{ }** control pretty prints JavaScript, JSON, CSS, and HTML using
the detected source type. It can format either the original evidence or the
active deobfuscated representation, so an unchanged deobfuscation result does
not leave a minified bundle on one line. Pretty printing changes only display
whitespace, keeps source-line mappings back to the captured bytes, and never
rewrites stored evidence. Input is capped at 2 MiB and formatted output at 4
MiB, with 250,000 lexical tokens and 500,000 mapping segments as pathological
input guards.
**Details > Deobfuscation** shows analysis, limits, omissions, and retry actions. The native app ships a Rust/Oxc worker for bounded static AST rewriting
over captured artifacts. It needs no Python runtime. Building the app
requires a current stable Rust toolchain (`rustup toolchain install stable`).
The Rust backend preserves classification, formatting, and literal-table
analysis for captured artifacts and live scripts. The Deobfuscation details
name the engine. Dynamic decoding remains unimplemented and is reported as an omission. Static table substitution is
restricted to non-escaping local tables with proven own-index reads.

Failed analysis remains visible until **Retry analysis** is selected. A failed
retry retains the last successful result. Source selection does not switch the
Sources editor away from original evidence. The UI retains at most eight analysis
documents and distinguishes source hashes and debugger targets in its cache.
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
unavailable reason for that navigation. Live scripts require
their currently owned complete source text and target identity. Neither path
executes source. Pretty printing remains a separate display layer.

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
This is an explicit, inert analysis action. Live debugger scripts and derived
text are not accepted. The Details pane shows complete-within-profile, partial,
unavailable and truncated states, diagnostics and unknown-effect frontiers.
Each category displays 100 rows per page; fact details are capped at 4,096
characters. Shadowed declarations retain distinct IDs and ambiguous bindings
remain candidates. Neither is proof of initialized values, dataflow or runtime
call targets; region-local order is conditional on entry and normal completion.

An **Original bytes** link loads the complete original artifact through the
existing verified 2 MiB chunk endpoint (at most 4 MiB total), checks its SHA-256,
and strictly decodes UTF-8 while retaining a byte-order mark. It then switches
the existing editor to original source and reveals the selected half-open byte
range. The start-line span is highlighted when browser highlights are available;
multiline ranges remain explicitly labeled. The editor's 20,000-line display
limit remains visible and links beyond it report that limit. A lossy preview,
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

Drag the shared borders in Traffic, Repeater, Sources navigator,
Memory criteria/results/details, and Tools Decoder to resize adjacent panes.
The divider shows an accent on hover or keyboard focus. Tab to a divider and use
the arrow keys along its axis; Shift changes the step from 10 to 50 pixels.
Home or double-click restores that split's default. Escape cancels an active
drag. Traffic saves wide column and narrow row splits separately. Sizes persist as
proportions in the local `origin-trace.layout.v1` preference, independently of evidence and backend state.

Minimum pane sizes keep controls and empty states usable. The Sources toolbar
wraps within the editor; its narrow debugger overlay starts below those controls. Saved widths are suspended when the
responsive layout stacks panes, shows a single exchange side, or lacks enough
space. Returning to a wide window restores them. Handles follow scrolling and
are clipped to the active workspace. `pane_layout.js` owns the shared layout controller;
no captured evidence is modified by resizing.

Captured WASM opens in Hex. **Inspect** shows bounded sections, types, imports,
exports and function disassembly with byte-offset links back to original bytes.
Function indexes include imports. **Find** searches the active view; failures
provide **Retry inspection**. Partial coverage and display limits are explicit.
The native shell ships `WasmService.swift` and `OriginTraceWasmInspector`, using
the same Rust provider as HTTP. See [WASM Inspection v1](../../protocol/wasm-inspection-v1.md).

## Evidence investigation and metadata packages

Open **Evidence → Inspect observations & artifacts** in the Requests inspector,
or **Evidence** from Backtraces. The initial view leads with the selected request,
a bounded recorded-observation list and an independently scrolling record inspector.
It separates native request records, explicit same-process parent links, matching
nonzero session/process/navigation/frame context and unlinked retained records.
For debugger requests, the method/host/time association with native records remains
visibly correlated, including when the native records have exact parent links.
The compact request summary keeps the method/host/time basis, absent exact producer
request key, missing-parent count and unknown coverage visible beside the reading panes.
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
CDP request IDs and synthetic gap rows are not export identities. The other
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

For rendered Evidence QA with an installed browser, run:

```sh
REB_UI_CHROMIUM="$(command -v google-chrome || command -v chromium)" \
  node tools/check-origin-trace-debugger.mjs --evidence-ui-browser
```

The existing browser CI job runs Requests, Sources and Evidence separately and
uploads `build/evidence-ui-qa/`. Evidence includes genuine pointer/keyboard
selection, real file input, explicit download byte comparison, failures,
interruption, scrolling and narrow layouts. Download QA waits for the matching
Chrome frame, filename and download GUID to report completion before checking
exact bytes and the single output file. Cancellation, missing completion or
corrupt completed bytes fail; filename existence alone is not completion.
Its synthetic service tests the UI; the real native-writer/guarded-export/validator
integration is a separate check.
A validation receipt is written only after interactions and cleanup succeed.

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
responses must match the submitted artifact or live script, its session or
actual page/worker target, SHA-256, source byte size, intrinsic assumptions and
original-source map. SHA-256 is recomputed over the returned original text.
Live CDP hashes remain opaque owner/version tokens. The analyzer's original
UTF-8 text must equal the exact complete live text held by that submitted
preview owner, and its UTF-8 SHA-256 is recomputed separately. Missing, loading
or truncated live previews cannot authenticate analysis. Replacing the preview
owner retires pending results; a cached derived result is shown only while its
original text still equals the current complete owned live text. No V8 hash
normalization or pinned-engine implementation is inferred.
Changed or closed owners cannot accept a late response, and analyzer text never
replaces the original preview. A failed explicit retry preserves only the last
successful analysis for the same identity. URLs are display/search hints, not
proof of ownership.

Artifact catalog refreshes preserve an exact pending preview owner. Changing
its session, hash or descriptor retires that read. Preview failures and deadlines
show **Retry source**; they do not silently retry during refresh. Preview bodies
reuse the Facts bounded streaming reader: 2 MiB raw artifact bytes, 13 MiB for
escaped live-source JSON, and 33 MiB for an analyzer envelope, with at most
65,536 chunks. Artifact and analyzer deadlines are ten seconds, including body
reads and SHA-256 work; the live-source deadline is fifteen seconds. Cancellation
retires ownership without waiting for a stalled producer's cleanup. Full artifact
previews verify SHA-256 when WebCrypto is available; partial or lossy text is
visibly a preview. Exact byte navigation still belongs to the existing Facts
verified-original reader.

The editor retains at most eight preview owners and 16 MiB of UTF-16 preview
text across captured and live files. The selected owner is pinned; older preview
bytes can be evicted while their tab and immutable catalog metadata remain.
**Retry source** or reopening the file loads it again. Closing a file cancels its
preview/Deob reads and releases its preview, Deob and formatting cache entries.
Tab, navigator, Quick Open and retry handlers retain descriptors only; obsolete
empty/retry controls are removed when the editor becomes ready. Hidden UI
closures cannot keep evicted preview or analysis payloads alive. This never
deletes captured evidence. Canvas thumbnails and the existing bounded
Facts/WASM inspectors retain their separate ownership contracts. WASM Hex expands
only the first 20,000 display rows, rather than formatting the whole 2 MiB input.

Deob retains at most eight documents, 16 MiB of original/derived UTF-16 text and
250,000 map segments and 32 MiB of serialized response data in total. Formatting retains at most two documents, 12 MiB
of input/output UTF-16 text and 500,000 segments. These are explicit text/entry
budgets, not JavaScript heap or process-RSS guarantees. The editor DOM and Facts'
independently verified original also use memory; no duplicate history of source
bytes is introduced.

Unchanged source/representation refreshes keep the editor DOM, scroll, Find
occurrence and focus, including enabled original-source map links in pretty or
derived views. Runtime decoration refresh never relabels those links as
breakpoints. Runtime cursors and Hook setup are scoped to the exact
script target, hash, context and original representation. Sources and Field trace
use the same identity-checked cursor receiver and honor refused source selection.
Hook-hit jumps require
that exact identity; a legacy URL-only hit remains unavailable. Delayed focus
cannot move to a newer selected source. Open-file tabs support
Left/Right, Home/End and Delete to close, with focus returning to the next tab.
The existing Rosé Pine Moon tokens and editor-first layout are unchanged.

Cross-workspace callers can pass the investigation-navigation v1 tuple to
`selectArtifact(id, line, {identity})`: `{type:'captured-artifact', session,
artifact, sha256, bytes}`. `sourceArtifactIdentityMatches` advertises this guarded
receiving boundary. Selection returns false before any read when that identity
is stale or the artifact ID is globally ambiguous. When shared investigation
navigation is present, callers should continue using its `openInvestigation`
adapter and bounded Back/Forward trail.

The existing `--source-facts-ui-browser` driver additionally covers pending body
plus catalog refresh, passive entry, wrong analyzer identity/preview bytes,
explicit retries, stable Find/scroll, keyboard file tabs and close cleanup at
1440×900, 760×560 and 360×740. Production-function and DOM fixtures run in
`make lint`; they do not replace real browser screenshots or native acceptance.

The dedicated `--sources-history-ui-browser` mode adds real Back after the
production eight-preview cache evicts captured and live documents. Native
pointer, wheel and keyboard input save nonzero editor/navigator offsets and
focus, hold reopen HTTP delivery, and await the actual loader's terminal receipt
before checking restoration. Repeated eviction, Forward, newer input, failed
reopen and explicit Retry are covered at 1440×900 and 760×560. Four other explicit
WASM inspections evict an authored valid module's report through the production
four-report cache. Back and a changed catalog must show the released state
without another analysis; native Enter on Retry, held/error returns and the valid
report are checked separately. The `sources-history-ui` CI job uploads screenshots,
request/operation receipts and validation under `build/sources-history-ui-qa`.
These small synthetic HTTP fixtures do not run a module or analyzed JavaScript,
and this browser gate does not replace native macOS acceptance.

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

`--evidence-comparison-ui-browser` in the shared debugger test now exercises the
actual product host and scripts, rather than the earlier isolated component
fixture. It covers real file inputs, backend-produced equal/changed synthetic
results, error retention, pending ownership, late File reads, Close/Escape,
Return/navigation, page disposal/remount, retained package export/validation,
wide/narrow layouts and the live native HTTP marker. CI uploads
`build/comparison-ui-qa/`. The mock service is UI evidence, not a replacement for
the real API/CLI integrity/admission tests. Shared Source navigation uses the
scoped receiving adapter and bounded Back trail. The strict Evidence browser
mode also requires Source → Back restoration of filters, focus and scroll
without automatic derived analysis. See [the comparison contract and bounds](../../protocol/evidence-comparison-v1.md).

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

The existing driver owns the real browser lifecycle:
`node tools/check-origin-trace-debugger.mjs --float32-ui-browser` with
`REB_UI_CHROMIUM` set and the current backend built. Its domain fixture forwards
requests to the actual backend; only held delivery and a labeled 503 are synthetic.
`--float32-fixture-only` checks the real loopback boundary without rendered claims.
