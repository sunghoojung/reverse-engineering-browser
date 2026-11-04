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
5. runs `xcodebuild test-without-building` and checks the PNG screenshots.

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
the DOM and computed layout and scrolls targets into view.

No smoke flag or test hook exists in the product, and nothing here uses the
Chrome DevTools Protocol. The evidence is synthetic; this suite does not
establish live browser capture.

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

`test18TrackCallsFromSources` opens a synthetic glue script (artifact 330) in
Sources at both window sizes. **Track calls** at the default position must
refuse top-level code; `o.dup`, typed with native keys and Return, must be
refused with both definitions listed and their markup-bearing context lines
inert; `window.hsw` must be saved without matching the decoys in a string and
a comment; and **Line**, **Column**, **Go** and **Track calls** must save the
callback around `awb(`. The titlebar chip must read `2 functions saved for the
next capture` in full, inside the titlebar and over no other label.
`test19StartDialogListsSavedFunctions` opens **New Live Session…** from the
app menu with two saved sites. The native dialog must say `Tracking 2
functions`, name each function and its script, say Content mode records
digests and Metadata mode does not, and its Remove must rewrite the saved file
at once; the test then continues offline and returns to the harness page. The
harness backend and the app share one temporary saved set through
`--js-invocation-site-store` and `REB_JS_INVOCATION_SITE_STORE`. Dialog
screenshots are drawn from the native window, which WebKit cannot snapshot.
The app also receives the harness's `--api-collection` and `--local-analyst`
stores, so the bundled `reb://` workspace those tests open never reads or
writes Application Support.

`test20StoppedRequestIsNotAnswered` opens the bundled `reb://` workspace, saves
a synthetic script that never returns and runs it, then reloads the page while
the native runner still holds the request. WebKit stops that request, and the
runner's answer at its 2 second limit must not reach it: answering a stopped
request raises an exception that ended the app. The next run must get its own
`timed_out` answer, not 409.

`test21NewLiveSessionAsksAboutUnsavedWork` makes an API Collection folder edit
through its editor's input event and chooses **New Live Session…** from the app
menu. The unsaved-work sheet must name the new session, keep **Stay** as the
Return default and photograph complete; Stay must leave the page, the edit and
the start dialog untouched. After the edit is discarded the start dialog opens
at once and the test continues offline.

`test22WorkspaceReloadsAfterContentProcessStops` ends the web content process
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

Backtraces is opened at both window sizes on one synthetic request whose
renderer record no initiator edge reached, 113 µs before `request_started` in
another process. The harness opens the Advanced disclosure first so the
Backtraces control is visible. The renderer event keeps its own per-process
sequence stream so it does not invent a browser sequence-gap ID. The trace must
list the selected request, its missing-predecessor gap, then the renderer
record as a time-adjacent row with its own label and style, while the coverage
line stays at 0% and counts the row separately. Arrow keys must reach that row
with visible `:focus-visible` focus and keep it fully in view. The coverage
line sits above the steps scroller so centering the adjacency row cannot
scroll it away or cover rows.

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

To reproduce smaller CI displays locally, cap all requested heights without
changing the display resolution:

```sh
REB_RENDERED_UI_MAX_HEIGHT=679 DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer make rendered-ui-check
```

The limit must be an integer of at least 560 CSS pixels. Normal and narrow-tall
cases then request heights of 679; the 560-high cases stay unchanged. Use 686 to
reproduce the other observed CI display size. Screenshot names keep their case
names; their pixel dimensions and the viewport log show the actual size.

Environment passed to the hosted bundle through the `.xctestrun`:

- `REB_RENDERED_UI_MAX_HEIGHT`: optional maximum requested viewport height
- `REB_RENDERED_UI_OUTPUT`: screenshot directory
- `REB_RENDERED_UI_PROBES`: absolute path of `probes.js`
- `REB_RENDERED_UI_EXPECT`: JSON with the fixture's hostile markers and counts
- `REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`
- `REB_RENDERED_UI_FAILURE_URL` and `REB_RENDERED_UI_FAILURE_BINARY`: a separate
  copied backend with synthetic interpreter evidence. Its executable permission
  is removed to reproduce a real worker spawn failure, then restored to verify
  unchanged-input retry. Both window sizes must show the counted failure as text.
