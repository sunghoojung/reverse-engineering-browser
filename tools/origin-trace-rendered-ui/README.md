# Rendered UI acceptance

This hosted XCTest bundle runs inside the packaged Origin Trace app and drives
its production window and WKWebView. It needs macOS and full Xcode. Run it from
the repository root:

```sh
make rendered-ui-check
```

The driver, [`check-origin-trace-rendered-ui.mjs`](../check-origin-trace-rendered-ui.mjs):

1. copies `build/Origin Trace.app` to a temporary directory and verifies its
   signature, so nothing resolves through source-tree paths;
2. builds a bounded synthetic session with
   [`evidence-fixture.mjs`](evidence-fixture.mjs) (including a synthetic guest
   bytecode buffer with embedded markup and invalid UTF-8) from the `make e2e`
   demo stores and the native Wasm evidence stores that `make native-wasm-golden-check`
   exports under `build/native-golden/`. Those stores are the exact artifacts and
   events the Rust golden tests built from `build/reb-native-wasm-guest-golden`
   and `build/reb-native-wasm-dispatch-golden`, so nothing is mirrored by hand.
   `make vm-observed-evidence` adds the owned two-level interpreter store that
   the observed-claims analyzer test builds under `build/vm-observed-evidence/`.
   Two named `vm` gaps close the store, as a live page wrote them when its Wasm
   `br_table` and `call_indirect` interpreters exhausted their sampling budgets;
3. starts the bundled `OriginTraceBackend` on a loopback port chosen by the OS;
4. builds this bundle with `xcodebuild build-for-testing`, then rewrites the
   generated `.xctestrun` so the bundle is hosted by the copied app
   (`TestHostPath`, `libXCTestBundleInject.dylib`) and the app receives
   `--ui-url` for that backend;
5. runs `xcodebuild test-without-building`, then a second launch pass for
   `testLaunchStartsWithoutStartPanel`, and checks the PNG screenshots.

`xcodebuild` cannot build a hosted bundle for an app that no scheme builds, so
the bundle is built unhosted and the host is supplied only in the `.xctestrun`
description. This is the documented format, not a private launch path.

Inside the app, [`OriginTraceRenderedUITests.swift`](OriginTraceRenderedUITests.swift)
reactivates the same instance through Launch Services, because `xcodebuild`
starts the host in the background and WebKit ignores input to an inactive
window. Clicks and keys both reactivate the host before sending `NSEvent`s to
the window and wait for WebKit's document focus notification. This keeps input
out of the asynchronous gap after native activation. Option+Tab is used when Full Keyboard Access is off,
matching Safari, so every control is a stop. [`probes.js`](probes.js) inspects
the DOM and computed layout and scrolls targets into view. It skips a row its
scroller shows by under 2 px, where hit testing snaps onto the next row, but
still checks a control whose own box is that small. It clips a box only by
the ancestors that contain it, as CSS paints it, so a popover fixed to the
window is not judged cut by the short table it opens from, and a box stuck to
a scroller's top (`position: sticky`) hides what scrolls under it as the
scroller's edge does. Text in a box of a pixel or less, kept for assistive
readers, is not clipped text;
[`check-rendered-ui-probes.mjs`](../check-rendered-ui-probes.mjs), part of
`make lint`, checks these against modelled boxes.

Only those native events give the page user activation, as a researcher's
input does. The harness runs its own JavaScript without a user gesture,
through WebKit's `_evaluateJavaScript:…withUserGesture:` (SPI since macOS 15).
That call evaluates a classic script, so an async harness script is started by
one evaluation and its result read by later ones, and a document that replaced
the one it ran in ends it. WebKit's public `callAsyncJavaScript` and
`evaluateJavaScript` run a script as a user gesture and consume the page's
transient activation when that gesture ends, after any timer or fetch the
script started. A harness script that ended between a native press and its
click took the click's activation, and WebKit refused the clipboard write the
click made with `NotAllowedError`. The driver refuses a harness that calls the
public methods.

No smoke flag or test hook exists in the product, and nothing here uses the
Chrome DevTools Protocol. The evidence is synthetic; this suite does not
establish live browser capture.

`test1TrafficRequests` checks that Traffic mounts only the rows near the view,
that each names its place in the whole list, that the last request mounts once
the list is scrolled to its end, and that End and Home select and focus both
ends. [`probes.js`](probes.js) scrolls an unmounted row into view before a click
finds it. The Response test also checks that pretty print uses the Oxc layout
and that a clicked token reports its raw range.

`test29RendererAnsweredRows` opens a `memory_cache_reuse` row from its own
renderer stream and a request its service worker ended without a response.
At both sizes the first reads `(memory cache)` with its status and a General
note that no request was made (screenshot `traffic-memory-cache-*`), and the
second reads Failed and `(service worker)`, never Pending (screenshot
`traffic-service-worker-failed-*`). A third request, whose end a
`service_worker_end_lost` gap names, reads End lost in the table, General and
the selected strip, though the gap has no request ID and so is not in the
row's store read (screenshot `traffic-service-worker-lost-*`). The narrow
layout drops Size and Status, so it reads the row's accessible label and the
Size tooltip.

`test2SourcesRetainedArtifact` finds tree rows by their `data-artifact-id`,
since file rows show plain names and the ID only in the meta column. It checks
the Dynamic and WebAssembly groups, End/Home/type-ahead with visible focus, and
that **Filter files** keeps only `glue.js` under its origin (screenshot
`sources-tree-filter-*`) until Escape restores the tree.

`test17LiveCaptureDefaultsAreLabeled` checks what an app-started capture
shows by default at both window sizes. The harness URL says the session
retains request content, as the packaged app's Content mode does. The harness
backend serves a stored session with no broker or capture browser, so the
test's own page `fetch` marks the event reads live and answers the two Console
reads as a capture browser launched with document-start permission does. The
titlebar's **Content capture** label must sit beside the session state, name
what is retained and not be clipped. The Console header chip must read
`Doc-start: permitted` in full, stay inside the header, overlap no other header
control, and leave arming disabled. Nothing connects, arms or runs.

`test45ConsoleTranscriptKeepsEveryEntry` connects the Console to a live
capture document that the test's own page `fetch` stands in for. That document
logs twelve thousand messages, every 97th of them two lines tall, in pages of
a thousand, and then one message of 1 MiB. At both window sizes, the
transcript must follow its end, with the 1 MiB message drawn whole. Every
line of that message must stay inside its wrap width: the line count, the last
line's box and the widest line must match a monospace wrap of the message, and
a failure prints them. Fewer than
250 rows may be in the document at the end, a quarter of the way down, and
through forty scroll steps there and back, and those rows must be consecutive
messages that cover the viewport with no gap. PageDown must scroll the focused
transcript through WebKit's own scroll animation, which the layout never
interrupts, with a step in each of at least three frames. Home is then
pressed while a second PageDown still moves. The page reports PageDown's
first step in a script message, and the test presses Home from that report
with no script call between them, so Home goes down before PageDown's next
frame however slow the runner is. A try counts when Home followed fewer steps
than a lone PageDown took, the last of them within a frame. One that does not
count is made again, up to five times, and the test fails if none counts.
Home must reach the first entry, handled by the transcript, and stay there
300 ms later, past the step WebKit's keyboard scroll takes after the
transcript's write. End, Command-Up and Command-Down must reach the last line
of the 1 MiB message, the first entry and the last line again, each handled by
the transcript. A timed-out wait prints each scroll, `scrollend`, key, layout
write and changed frame that led to it, and for each key the steps before it,
the frames since the last of them and the writes after it. Search
must find `rendered message 4242` among rows that are not drawn and draw only
that match, and Escape must restore every entry. Screenshots
`console-transcript-{end,middle,start,search}-*` show each state.

`test18TrackCallsFromSources` opens a synthetic glue script (artifact 330) in
Sources at both window sizes. **Track calls** at the default position must
refuse top-level code; `o.dup`, typed with native keys and Return, must be
refused with both definitions listed and their markup-bearing context lines
inert; `window.hsw` must be saved without matching the decoys in a string and
a comment; and **More** > **Go to line** and **Track calls** must save the
callback around `awb(`. The harness backend follows the saved set as an app
capture does, so saving says the capture tracks the function at once, the set
reports both sites armed, and the titlebar chip must read `Tracking 2
functions` in full, inside the titlebar and over no other label.
`test18bMinifiedSourceOpensPrettyPrinted` opens a one-line source map over
16 KiB (artifact 332). It must open pretty-printed with formatted gutter
numbers and the original location in their tooltips, keep its colors after
line 1,000, open Find with Cmd+F and Go to line with Ctrl+G (Escape closes it),
and show the one captured line after **Show original**, without clipping.
`test19StartPanelListsSavedFunctions` opens **New Live Session…** from the
app menu with two saved sites. The start panel in the bundled workspace must
say `Tracking 2 functions`, name each function and its script, say Content
mode records digests and Metadata mode does not, keep captured labels inert,
and its Remove must rewrite the saved file at once and keep the chosen mode;
the test then continues offline and returns to the harness page. The harness
backend and the app share one temporary saved set through
`--js-invocation-site-store` and `REB_JS_INVOCATION_SITE_STORE`.

`test31DebuggerSidebar` opens the Sources debugger sidebar on the fixture's
observation records: a renderer of its own (process 4747) with records in six
frames, three workers, a watched request and two malformed records, and a
retained compiled script (artifact 360) whose listener, timer and
throw sites the records name. One listener's event type is markup and must
stay text. At both window sizes the sections must be Threads, Watch rules,
Observations and Pausing, Pausing must state the availability the backend
reports with no pausing control, only rows near the view may mount, Threads
must show at least six whole one-line rows with no row's identifiers cut,
both lists must end on a whole
row, every record must read its time as `+M:SS.mmm` and its identifiers as
`P F #` (and `R`), the kind menu must name each kind's count, a scrolled pane
must keep the section's title over its list, Tab from
the focused Threads pane must reach the list with a visible indicator, frame
200 must scope the Sources tree and Observations, a listener record must be
marked selected as soon as it is clicked, its **Open onTap @ handlers.js:2:71**
button must sit wholly inside the sidebar pane once it resolves and must open
`onTap` in Sources at line 2, column 71, and the light theme must pass the
layout checks. In Observations an arrow key must move the active row, the
selection mark and the details, in view, to the next record, and the watched
request (5100) must open its own Traffic row on the Initiator tab both by its
**Open request in Traffic** link and by Enter. With `/api/native-debugger`
failing, and then answering a malformed document, the status must say so
while the last rows stay, marked stale, until a good read clears it. The
record and both stale states are also photographed in the light theme. Escape must return to the toggle, or to
**More** while a docked sidebar has moved the toggle into that menu, and
closing must abort the read under way and start none: the test holds each read
as a loaded backend would, so the thread click's read is in flight at the
close, and it must end aborted, with no read started in the next 4.5 seconds.
A read under way at the close is not a new read: its resource entry lands only
when it ends, after the close, which once failed a count of all entries under
load. `REB_RENDERED_UI_DEBUGGER_RECORDS` (8 to 20,000, default
120) sets how many records the fixture writes; they also count as
Fingerprinting activity. `test6RemovedFeaturesAreAbsent`
reads Sources with the sidebar open, leaving out only the paused-state words
of the availability statement and native pausing sections inside
`#debugger-sidebar`, fails on a native marker anywhere else and on any control
in a native pausing section that is not a really disabled form control while
the debugger is unsupported, and compares that statement with
`/api/native-debugger`.

`test32PausingSections` opens the same sidebar with the pausing debugger's own
five sections registered (`pause`, `breakpoints`, `call-stack`, `scope`,
`watch`, marked `data-debugger-native="pausing"`). The backend reports the
pausing debugger unsupported, so at both window sizes the Pausing statement
must say so and name all five sections, every control those sections draw must
be a form control with `disabled` set, and nothing that cannot be disabled, a
link, a `summary`, a `role`, a `tabindex` or an editable region, may appear.
It photographs them in both themes.

`test41TraceValueInInspect` opens the repository-owned value-flow module
(artifact 440, from `tools/fixtures/wasm-value-flow`) in Inspect at both window
sizes, picks the import call row with the pointer and traces it. The slice must
name the JavaScript crossing as its seed, list at least five sources and the
three joins with their incoming edges, and mark the seed row and other slice
rows in the listing, while the listing keeps at least 90 px above the panel.
Arrow keys must reach the load row and Enter must reveal and focus it in
Inspect, marked as a source, and the import name must be visible whole in the
row at both sizes. It photographs both themes. Opening Graph must hide the
panel while the graph keeps its height, and closing it must bring the same
trace back. Clear must remove the marks, a store row must offer its two
operands before any trace, and Hex must hide the panel.

`test27StartPanelStartRetryAndKeyboard` takes the start panel through a whole
decision at both window sizes. The driver names a `REB_BRAVE_BINARY` that does
not exist, so Start fails at once and no browser launches on any machine. The
panel must sit inside the workspace with nothing clipped, open with Start
Session focused and this run's last choice, with no Keychain choice, reach
every control with Shift+Tab and visible focus (nothing sits between the mode
and the actions in either mode), change the mode with an
arrow key, and start on Return. The failure must name the cause, say Retry uses
the mode chosen by keyboard (so native received it), and focus Retry; Return
on Retry must fail afresh, and Continue Offline must close the panel and return
focus to the workspace.

`test30WorkerInitiatorStack` opens the synthetic request a dedicated worker
started (two synthetic renderer processes, version 3 stack records,
[native network v3](../../protocol/native-network-v3.md)). At both sizes the
Initiator column must name the worker's frame, and the Initiator tab must
resolve that frame and a `Promise.then` registration in the worker's isolate,
a `MessagePort.postMessage` segment in the posting renderer's isolate with its
process named, and the stated end of a task scheduled with no script, then list
the async callers still not shown, with nothing clipped and captured names
inert.

`test37WasmReadableView` opens fixture artifact 400 in Sources, names
`readable_run` (func 1) with the pencil on its Inspect header row and Enter,
as test39 does, using a markup-shaped researcher name, then closes Inspect and
turns on **Readable** (from More when it has moved there). At both sizes the
researcher name must sit beside the module's `readable_run` title as text,
never in its place or in the listing. The folded
load, the loop's `br_if` and the quoted, markup-shaped import name must show as
text with one counted raw line, nothing clipped or overlapping and no captured
markup in the DOM. Clicking a line and then the down arrow and Enter must each
reveal the line's bytes in the linear view with visible focus, and opening
Graph must close Readable.

`test38WasmLibraryIdentification` opens the synthetic Rust and wasm-bindgen
module (artifact 410, built from
[`rust-wasm-bindgen.wat`](../fixtures/wasm-identification/rust-wasm-bindgen.wat))
in Inspect. At both sizes the
[identification](../../protocol/wasm-identification-v1.md) summary must name the
toolchain, the complete SHA-256 and Base64 tables and the labeled count above
the listing without clipping; Enter on Details must list the fetch glue label
and the function that reads the SHA-256 table, a constant chip must reveal its
data segment row, and the Graph's Functions menu must show category badges
while the summary steps aside for the graph. With **Linear** shown (pressed at
narrow, where it starts hidden), no control may meet the graph and linear
divider while the linear view sweeps one row height of scroll offsets, so a
row's sliver cannot pass under it at whatever offset the display height leaves.
The module's functions are single blocks, so the footer must offer no **Key**
and name no edge kind. A native pointer drag then takes the divider to the
graph's minimum, where the Functions menu must open whole, and to the linear
view's minimum, repeating the sweep at each, and Home on the divider forgets
the drag.

`test25bBlockGraphShapes` opens the measured
[block graph shapes](../fixtures/wasm-block-graph/README.md) in Graph, cold at
both sizes and at 1440 by 900: a 1,000-case switch ladder (341), a 256-arm
interpreter loop (342), two nests of eight loops (343), the exception fixture (344)
and a 19,459-block interpreter loop (345). Each must draw without an error state
and without layout defects or clipped text, the exception function's key must
name exception and unresolved edges, and the interpreter loop's must name table
edges. Where the footer folds the key behind **Key**, Space on Key opens it
whole and Escape returns a visible focus ring to Key, with no control on the
graph and linear divider (Linear is shown for that check and hidden again where
the window starts without it). Each shape is photographed at its opening
zoom and fitted whole with `0`, where the graph's canvas must hold only its
background under the overview cue and the minimap. It prints a `RENDERED_UI_GRAPH` line per shape
and size: the time from the native click on Graph to the frame after the first
drawing, which spans decode, transfer, layout and draw, and, while Shift+Arrow
pans once a frame at each zoom (right, down, left and up in turn, so every
frame draws a new view clear of a pan limit), the median, 95th percentile and
slowest frame interval and the time each frame spends drawing the graph. Then
Shift+Arrow pushes the fitted view far past the bottom right, where the canvas
must still draw the graph, not only its background. A median interval
fails over 50 ms, or over twice the slower median of the 25-block exceptions
shape at that size where that is longer (a `RENDERED_UI_GRAPH_BOUND` line per
size). A display without a GPU, as on a CI host, holds even that shape to
30-50 ms a frame while its draw takes 1 ms, so the bound follows the machine.
One long frame does not fail, because a hidden window or a sleeping display
stops frames whatever the page does.

`test35MissingFinalHeaders` opens a content-session request the HTTP cache
answered, which has only a provisional request block that an older browser's
header budget refused ([missing final blocks](../../protocol/native-network-v3.md#missing-final-blocks)).
At both sizes the Traffic footer must show one **2 header gaps** item that adds
no footer line and leaves nothing cut off; Space must open its breakdown with
the refused block and the request without final headers, each with its reason,
and Escape must close it and return focus. The Headers tab must say the HTTP
cache answered without sending a request and that the block was not retained;
and the Cookies tab must list the hop with the same reason in place of a bare
"No cookie list was retained", with nothing clipped and captured text inert.

`test36StartPanelContentWithoutLimits` opens the start panel at both window
sizes and both themes. A Content session keeps every body whole, so the
capture mode must be the panel's only input; Content must name the free-disk
reserve as the only bound and say nothing of a budget, a media switch or
16 MiB, and Metadata must name no reserve. Native must refuse the removed
`request_content_budget_mib`, `response_body_budget_mib` and `response_media`
keys sent past the page as it refuses any other key, and start nothing; a
Content start's failure (the missing Brave) names the mode and no limit. In
Traffic, the fixture's `api.disk-reserve.test` row is a current content-session
POST whose body and response the receiver refused to keep its disk reserve,
and its `api.budget.test` row is a POST whose target past its first 116 bytes,
body and response an older browser's budgets refused. The footer must take its
counts from the session summary (two disk reserve records, three budget
records) and the Request URL row and the Payload and Response tabs must say
why, naming no control to raise and no environment variable. At the narrow
size with the request open the footer must show a one-line button instead of
the line, fully visible, which Return or Space opens to the whole sentence and
Escape closes with focus kept; focus leaving it, a press elsewhere and closing
the request close it too, and a request opened again starts with it closed.
Beside `test35`'s **header gaps** item, the two must not overlap when both are
open, and each Escape must close only its own and not the request. Both themes,
nothing clipped.

`test39WasmFunctionNames` opens the synthetic module artifact 420 (an import,
a helper and an exported caller) in Sources Inspect, renames the helper with
the pencil on its header row and Enter, and requires at both sizes that the
italic name follows the unchanged captured header and the call row that
targets it, and that F2 after a click on the call row opens the callee's
editor. The Graph's **Functions** list must show the name beside `func 1`; the
open popover covers the graph by design, so its layout is checked on its own
and the Graph's once it closes. Choosing that row must put the name beside the
Graph title. The Graph then moves to `func 2` while the last clicked Inspect
row is the call into `func 1`, and F2 after a click on the graph must open the
editor for `func 2`, the function the Graph draws, which Escape closes. Layout and inertness are checked at each step,
and the Graph is photographed in both themes
([Wasm function names v1](../../protocol/wasm-function-names-v1.md)).

`test43LargeSourcesOpenWhole` measures real-size sources and skips unless
`REB_RENDERED_UI_LARGE_SOURCES` names a directory holding `bundle.js` and
`module.wasm`, which the fixture stores as artifacts 950 and 951 (they are read
at test time and never committed). It opens the bundle whole and verified, finds
every `function` in it to an exact count, opens the module as hex and then its
first Inspect window, photographs each, and prints each step's time with the web
content and backend resident sizes as `RENDERED_UI_LARGE_SOURCES` lines. Run it
alone with `node tools/check-origin-trace-rendered-ui.mjs --only
test43LargeSourcesOpenWhole` after `make app-build`.

`test42RunOfflineInSources` opens fixture artifact 450, a hand-built module
whose second export (`stamp<b>`) reads the import `env.now`, and chooses
**More > Run offline…**. At both sizes the dialog must name the local sandbox
above every field, list the export names as text, and keep **Run** disabled
until the confirmation is checked with a pointer click. A run without stubs
must show **Import trapped** with the recorded `env.now` call; a run with
`env.now` stubbed to 1000, a write of `6869` at offset 16 and a two-byte read
there must return `i32 1001` and show `16:2 · read · 6869`, fetched from the
run's stored memory after the record arrives. After each run the outcome
line must be inside the dialog's visible frame and be the topmost element at
its position, since the result follows the fields and starts below the visible
area until the dialog scrolls to it. Nothing may be clipped, captured names stay
inert, and Escape closes the dialog. Screenshots: `run-offline-dialog-*` and
`run-offline-result-*`, each also in the light theme (`*-light-*`).

`testLaunchStartsWithoutStartPanel` runs alone in a second launch pass. That
pass starts the copied app without `--ui-url` or an evidence-store argument,
with automatic live sessions on, `REB_EVENT_STORE` and its siblings naming
stores that do not exist yet (as on a first launch, so the workspace is idle),
an empty saved site set and the same missing `REB_BRAVE_BINARY`. Launch must
start a Content session at once without the start panel; the missing Brave
makes that start fail, so at both sizes the panel must show only that failure,
with Retry focused. A Launch Services reopen while it is open must start
nothing, Return on Retry must start again, and after Continue Offline a reopen
must start nothing. The main pass skips this test and it skips itself outside
the launch pass.
The app also receives the harness's `--api-collection` and `--local-analyst`
stores, so the bundled `reb://` workspace those tests open never reads or
writes Application Support.

`test21StoppedRequestIsNotAnswered` opens the bundled `reb://` workspace, saves
a synthetic script that never returns and runs it, then reloads the page while
the native runner still holds the request. WebKit stops that request, which
must terminate the run, since a run has no deadline, and no answer may reach
the stopped request: answering one raises an exception that ended the app. The
next run, of a script that returns, must get its own `completed` answer, not
409.

`test21bDecoderQueueHasNoDeadline` opens the bundled `reb://` workspace and
sends 160 gzip transforms of 768 KiB each to the packaged decoder at once. The
decoder runs one at a time with no deadline, so every request must be answered
with 200, however long the queue takes; with the old two-second wait most were
refused as busy. It then sends 150 more, aborts them after 300 ms, and the next
request must be answered within 1.5 s, since the abandoned ones would take
seconds to drain if WebKit stopping them did not take them off the queue. It
prints the times as a `decoder queue in the packaged app` line.

`test21cDecoderRunsUntilCancelledAndHoldsLargeInput` converts two million
decimal digits to Base36 in the packaged decoder, which takes seconds now that
no CPU-time or size limit ends it. The notice must count past two seconds with
**Cancel** enabled and the engine busy, in the header badge and the service;
clicking **Cancel** must end the decode, free the engine within two seconds and
leave the input editable. It then runs 3 MiB of different text through
**Run transformation** and expects one 4 MiB Base64 step whose badges name no
cap. WebKit stopped matching the page's former Base64 check past a few MB, so
this step also proves a result that large is accepted. It writes
`decoder-running` and `decoder-large-input` screenshots.

`test22NewLiveSessionAsksAboutUnsavedWork` first opens the bundled workspace
through **New Live Session…** and the start panel's **Continue Offline**, because the close guard
trusts only a document the app loaded itself. When an earlier test left the
harness page in place, that page cannot answer, and the test makes the
deliberate **Start New Session** choice. In the bundled workspace it makes an
API Collection folder edit through its editor's input event and chooses **New
Live Session…** again. The unsaved-work sheet must name the new session, keep
**Stay** as the Return default and photograph complete; Stay must leave the
page and the edit untouched and the start panel closed. Once the edit is
discarded, the start panel opens at once and the test continues offline.

`test0AgentPanel` opens the Agent dock at both window sizes. None of the
researcher's CLIs runs: `REB_AGENT_GROK_CLI` names a missing file, so Grok's
subscription-only account line says to install it, unclipped, and
`REB_AGENT_CLAUDE_CLI` names the stand-in CLI that `make app-build` builds
(`build/check-agent-core`). After the key-mode turns, a Claude subscription
turn runs through the real bridge, that stand-in and the packaged tool server,
and the switch ends the CLI. The dock stays off
until the disclosure names tool results and their URLs and hosts, then a turn
runs through the bundled LangGraph runtime, the native fixed-endpoint proxy, a
local stand-in provider (`REB_AGENT_PROVIDER_BASE_URL`, loopback only, no key)
and the real tool server: the tool call and its result are visible,
hostile model markup stays text, an invented citation is labeled *not verified*,
and a real one opens Sources. An action waits on Allow once or Deny, a 400-row
conversation mounts only nearby rows, the switch stops the tool server, and
`ps` RSS is printed for each state (`RENDERED_UI_AGENT_MEMORY`). The driver
asserts the provider received no key and no captured source, and that the
transcript is user-only.

`test23WorkspaceReloadsAfterContentProcessStops` ends the web content process
with SIGKILL, as a crash would; WebKit's testing selector names its process ID.
The workspace must reload once by itself; a second stop within 30 seconds must
ask, photographed, and **Reload** must restore it. Whether a reload starts is
observed natively, because page JavaScript cannot answer until one does.

At both window sizes, those budget gaps must leave the footer free of queue
drops, Traffic without a loss notice and Fingerprinting at full coverage, while
the VM notice names both reasons as inert text.

The Runtime claims panel is opened on that store at all four sizes: the
contradicting claim expands with native input, and the claims heading, the
contradiction and the nested guest row are each revealed and photographed.

Flow is opened at both window sizes on one synthetic request whose
renderer record no initiator edge reached, 113 µs before `request_started` in
another process; the window shows its Lineage pane (beside the graph in the
normal window, on its own behind the pane switch in the narrow one). The
renderer event keeps its own per-process
sequence stream so it does not invent a browser sequence-gap ID. The trace must
list the selected request, its missing-predecessor gap, then the renderer
record as a time-adjacent row with its own label and style, while the coverage
line stays at 0% and counts the row separately. Arrow keys must reach that row
with visible `:focus-visible` focus and keep it fully in view. The coverage
line sits above the steps scroller so centering the adjacency row cannot
scroll it away or cover rows. Layout is asserted on the Flow head, toolbar,
Lineage pane and, when narrow, the pane switch; the flow graph's tools float
over its own canvas by design.

VM layout assertions check full-width compact evidence, complete footer and
tab-strip visibility, and an exact boundary between the analysis scroller and
its tabs. Native observation checks reveal and photograph each section heading
and retained row separately after exercising the disclosure. They do not require
both targets to fit in one viewport. Native cards and the Dispatch structure
card also assert their 12px content inset at all four sizes. Separate 1180x560
and 760x790 cases exercise the height and width breakpoints, compact trees,
keyboard focus, and the example disclosure independently. Text bounds also
verify that handler opcodes keep a readable gap before their operation labels.
At all four window sizes, every dock tab must leave either a useful analysis
pane with a complete heading and row or a complete collapsed analysis header,
with no change in height between tabs. Compact cases also expand the header,
navigate from the Symbol Tree to a complete handler row, and toggle it with
Space. Retained-site buttons must open that same handler pane; both routes reject
clipped tree fragments above it. Compact Program Trees settle on two complete
finding rows after selection. Empty paragraphs check their text inset as well
as their vertical spacing. A separate geometry check rejects a blank band between the Opcode
workspace header and its evidence notice.

AppKit can clamp requested window sizes to the display. The harness logs the
requested and actual CSS viewport sizes, and responsive assertions use the
actual viewport's media query. Scrolling checks center the specific target and
wait for it to settle before measuring it. Fixed chrome, the analysis pane at
rest, and controls revealed by product navigation are checked without
test-driven scrolling.

Program Trees lists VM findings before the opcode workspace and its host links
arrive, and each arrival rebuilds the finding's detail. A VM test that selects
a finding and reads its Symbol Tree, handler listing or analysis panels first
waits for `#vm-detail` and `#vm-symbol-list` to report `aria-busy="false"`, not
only for the finding rows; reading after the rows alone raced that load and
failed `test4VmNativeGuestRows` with a missing symbol row on a slow runner.

To reproduce smaller CI displays locally, cap all requested heights without
changing the display resolution. The `macos-latest` runner currently clamps
every 790-high request to 677:

```sh
REB_RENDERED_UI_MAX_HEIGHT=677 DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer make rendered-ui-check
```

The limit must be an integer of at least 560 CSS pixels. Normal and narrow-tall
cases then request heights of 677; the 560-high cases stay unchanged. Use 679 or
686 to reproduce the earlier observed CI display sizes. A display that fits the
full 790 changes where scrolled content comes to rest, so a layout check that
depends on a scroll offset sweeps the offsets rather than trusting one. Screenshot names keep their case
names; their pixel dimensions and the viewport log show the actual size.

Environment passed to the hosted bundle through the `.xctestrun`:

- `REB_RENDERED_UI_MAX_HEIGHT`: optional maximum requested viewport height
- `REB_RENDERED_UI_OUTPUT`: screenshot directory
- `REB_RENDERED_UI_PROBES`: absolute path of `probes.js`
- `REB_RENDERED_UI_EXPECT`: JSON with the fixture's hostile markers and counts
- `REB_DISABLE_AUTOMATIC_LIVE_SESSION=1` (`0` in the launch pass, which also
  sets `REB_RENDERED_UI_LAUNCH=1` and the `REB_*_STORE` overrides)
- `REB_BRAVE_BINARY`: a path that does not exist, so a start fails at once
- `REB_RENDERED_UI_FAILURE_URL` and `REB_RENDERED_UI_FAILURE_BINARY`: a separate
  copied backend with synthetic interpreter evidence. Its executable permission
  is removed to reproduce a real worker spawn failure, then restored to verify
  unchanged-input retry. Both window sizes must show the counted failure as text.
