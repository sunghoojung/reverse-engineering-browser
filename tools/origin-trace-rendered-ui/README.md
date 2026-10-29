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
   and `build/reb-native-wasm-dispatch-golden`, so nothing is mirrored by hand;
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
clipped tree fragments above it. Empty paragraphs check their text inset as well
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
