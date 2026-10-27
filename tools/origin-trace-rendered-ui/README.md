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
window. Clicks and keys are `NSEvent`s sent to the window. Option+Tab is used
when Full Keyboard Access is off, matching Safari, so every control is a stop.
[`probes.js`](probes.js) only reads the DOM and computed layout.

No smoke flag or test hook exists in the product, and nothing here uses the
Chrome DevTools Protocol. The evidence is synthetic; this suite does not
establish live browser capture.

Environment passed to the hosted bundle through the `.xctestrun`:

- `REB_RENDERED_UI_OUTPUT`: screenshot directory
- `REB_RENDERED_UI_PROBES`: absolute path of `probes.js`
- `REB_RENDERED_UI_EXPECT`: JSON with the fixture's hostile markers and counts
- `REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`
