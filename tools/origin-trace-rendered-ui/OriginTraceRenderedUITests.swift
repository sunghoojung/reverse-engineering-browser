import AppKit
import WebKit
import XCTest

// Hosted inside the packaged Origin Trace app (TEST_HOST), so every check runs
// against the production window and WKWebView. Pointer and keyboard input are
// native AppKit events; JavaScript only reads layout and DOM state.
@MainActor
final class Harness {
  let window: NSWindow
  let webView: WKWebView
  let output: URL
  let probes: String

  init() throws {
    let environment = ProcessInfo.processInfo.environment
    guard let window = NSApp.windows.first(where: { $0.contentView is WKWebView }),
      let webView = window.contentView as? WKWebView
    else { throw HarnessError("The packaged app did not create its WKWebView window") }
    self.window = window
    self.webView = webView
    output = URL(fileURLWithPath: try Harness.required(environment, "REB_RENDERED_UI_OUTPUT"), isDirectory: true)
    probes = try String(contentsOfFile: try Harness.required(environment, "REB_RENDERED_UI_PROBES"), encoding: .utf8)
  }

  nonisolated static func required(_ environment: [String: String], _ key: String) throws -> String {
    guard let value = environment[key], !value.isEmpty else { throw HarnessError("Missing \(key)") }
    return value
  }

  // xcodebuild starts the host in the background. Keyboard focus and pointer
  // delivery require the real active key window, so ask Launch Services to
  // reopen and activate this same instance, as a user switching to it would.
  func activate() async throws {
    if !NSApp.isActive {
      let configuration = NSWorkspace.OpenConfiguration()
      configuration.activates = true
      configuration.addsToRecentItems = false
      configuration.createsNewApplicationInstance = false
      _ = try await NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration)
      NSApp.activate(ignoringOtherApps: true)
    }
    window.makeKeyAndOrderFront(nil)
    window.makeFirstResponder(webView)
    let deadline = Date().addingTimeInterval(10)
    while !(NSApp.isActive && window.isKeyWindow) {
      guard Date() < deadline else {
        throw HarnessError("Origin Trace did not become the active key window (active=\(NSApp.isActive), key=\(window.isKeyWindow))")
      }
      try await Task.sleep(nanoseconds: 100_000_000)
    }
  }

  // The app starts loading --ui-url before the injected bundle runs.
  func waitForInitialLoad() async throws {
    let deadline = Date().addingTimeInterval(30)
    while webView.isLoading || webView.url?.scheme != "http" {
      guard Date() < deadline else { throw HarnessError("The packaged app did not load its loopback UI") }
      try await Task.sleep(nanoseconds: 100_000_000)
    }
  }

  func resize(width: CGFloat, height: CGFloat) async throws {
    var frame = window.frame
    let content = window.contentRect(forFrameRect: frame)
    frame.size = window.frameRect(forContentRect: NSRect(x: 0, y: 0, width: width, height: height)).size
    frame.origin.y += content.height - height
    window.setFrame(frame, display: true)
    try await settle()
    let size = try await json("({width: innerWidth, height: innerHeight})")
    guard (size["width"] as? Double).map({ abs($0 - Double(width)) < 1 }) == true else {
      throw HarnessError("Viewport did not follow the native window: \(size)")
    }
  }

  // Waits for two animation frames so layout and paint reflect the last event.
  func settle() async throws {
    _ = try await webView.callAsyncJavaScript(
      """
      await new Promise(done => {
        requestAnimationFrame(() => requestAnimationFrame(done));
        setTimeout(done, 500);
      });
      return true;
      """,
      contentWorld: .page)
  }

  func injectProbes() async throws {
    _ = try await webView.evaluateJavaScript(probes)
  }

  func json(_ expression: String) async throws -> [String: Any] {
    try await injectProbes()
    let raw = try await webView.callAsyncJavaScript(
      "return JSON.stringify(await (async () => (\(expression)))());", contentWorld: .page)
    guard let text = raw as? String, let data = text.data(using: .utf8),
      let value = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw HarnessError("Probe returned no object for \(expression)") }
    return value
  }

  func value(_ expression: String) async throws -> Any? {
    try await injectProbes()
    let raw = try await webView.callAsyncJavaScript(
      "return JSON.stringify({value: await (async () => (\(expression)))()});", contentWorld: .page)
    guard let text = raw as? String, let data = text.data(using: .utf8),
      let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { throw HarnessError("Probe returned nothing for \(expression)") }
    return object["value"]
  }

  func waitUntil(_ expression: String, timeout: TimeInterval = 15, _ message: String) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      if (try? await value(expression)) as? Bool == true { return }
      try await Task.sleep(nanoseconds: 100_000_000)
    }
    throw HarnessError("Timed out: \(message)")
  }

  func reload() async throws {
    try await activate()
    webView.reload()
    try await Task.sleep(nanoseconds: 300_000_000)
    try await waitUntil(
      "document.readyState === 'complete' && typeof state === 'object' && state.requests.length > 0 && !document.querySelector('#screen-traffic').hidden",
      timeout: 30, "the packaged UI did not load retained evidence")
    try await settle()
  }

  // Native pointer input: AppKit routes the event through WKWebView hit testing.
  func click(_ selector: String, containing text: String? = nil) async throws {
    let textArgument = text.map { "'\($0.replacingOccurrences(of: "'", with: "\\'"))'" } ?? "null"
    let point = try await json(
      "__rebUiProbe.center('\(selector.replacingOccurrences(of: "'", with: "\\'"))', \(textArgument)) || {}")
    guard let x = point["x"] as? Double, let y = point["y"] as? Double else {
      throw HarnessError("No visible target for \(selector) \(text ?? "")")
    }
    try await settle()
    // CSS pixels map 1:1 to view points; WKWebView reports a flipped view.
    let location = NSPoint(x: x, y: webView.isFlipped ? y : Double(webView.bounds.height) - y)
    let windowPoint = webView.convert(location, to: nil)
    for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
      guard let event = NSEvent.mouseEvent(
        with: type, location: windowPoint, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
        windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0)
      else { throw HarnessError("Could not create a mouse event") }
      window.sendEvent(event)
    }
    try await settle()
  }

  func key(_ code: UInt16, _ characters: String, modifiers: NSEvent.ModifierFlags = []) async throws {
    for type in [NSEvent.EventType.keyDown, .keyUp] {
      guard let event = NSEvent.keyEvent(
        with: type, location: .zero, modifierFlags: modifiers, timestamp: ProcessInfo.processInfo.systemUptime,
        windowNumber: window.windowNumber, context: nil, characters: characters,
        charactersIgnoringModifiers: characters, isARepeat: false, keyCode: code)
      else { throw HarnessError("Could not create a key event") }
      window.sendEvent(event)
    }
    try await settle()
  }

  // macOS defaults to Tab moving only between text fields and lists; Option+Tab
  // then reaches every control, as in Safari. With Full Keyboard Access on,
  // plain Tab already does. Either way every control must be reachable.
  func tab(shift: Bool = false) async throws {
    var modifiers: NSEvent.ModifierFlags = shift ? [.shift] : []
    if !NSApp.isFullKeyboardAccessEnabled { modifiers.insert(.option) }
    try await key(48, "\t", modifiers: modifiers)
  }

  func screenshot(_ name: String) async throws {
    try await settle()
    let configuration = WKSnapshotConfiguration()
    configuration.afterScreenUpdates = true
    let image = try await webView.takeSnapshot(configuration: configuration)
    guard let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:])
    else { throw HarnessError("Could not encode \(name)") }
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    try png.write(to: output.appendingPathComponent("\(name).png"))
    print("RENDERED_UI_SCREENSHOT \(name) \(Int(webView.bounds.width))x\(Int(webView.bounds.height))")
  }
}

struct HarnessError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

struct Expectations: Decodable {
  let hostileUrlMarker: String
  let hostileSourceMarker: String
  let hostileBytecodeMarkup: String
  let requestCount: Int
  let sourceLines: Int

  static func load() throws -> Expectations {
    let text = try Harness.required(ProcessInfo.processInfo.environment, "REB_RENDERED_UI_EXPECT")
    return try JSONDecoder().decode(Expectations.self, from: Data(text.utf8))
  }
}

// The app's default window and its enforced minimum (narrowest supported).
let windowSizes: [(name: String, width: CGFloat, height: CGFloat)] = [
  ("normal", 1180, 790), ("narrow", 760, 560),
]

// Phrases of controls that belonged to removed CDP features. Native evidence
// must not advertise them anywhere in the shipped UI.
let removedFeaturePhrases = [
  "WebSocket", "Breakpoint", "breakpoint", "Paused frame", "paused frame", "Call stack", "Live scripts",
  "Cookie import", "Import cookies", "Element screenshot", "Marker execution", "Run marker", "Local override",
  "Find in Memory", "Runtime hook", "Resume", "Step over", "Step into", "API catalog", "Passive security report", "Capture actions",
  "Include headers and bodies", "Use selected as baseline", "Clear baseline", "Field trace", "Live Debugger",
]

final class OriginTraceRenderedUITests: XCTestCase {
  override func setUp() {
    continueAfterFailure = true
  }

  @MainActor
  private func prepare(_ size: (name: String, width: CGFloat, height: CGFloat)) async throws -> Harness {
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    try await ui.activate()
    try await ui.resize(width: size.width, height: size.height)
    try await ui.reload()
    return ui
  }

  @MainActor
  private func assertLayout(_ ui: Harness, _ scope: String, _ context: String,
                            file: StaticString = #filePath, line: UInt = #line) async throws {
    let layout = try await ui.json("__rebUiProbe.layoutIssues('\(scope)')")
    let issues = layout["issues"] as? [String] ?? ["probe failed"]
    XCTAssertGreaterThan(layout["inView"] as? Int ?? 0, 0, "\(context): no visible controls in \(scope)", file: file, line: line)
    XCTAssertEqual(issues, [], "\(context): layout defects in \(scope)", file: file, line: line)
    let clipped = try await ui.value("__rebUiProbe.clippedText('\(scope)')") as? [String] ?? ["probe failed"]
    XCTAssertEqual(clipped, [], "\(context): clipped text in \(scope)", file: file, line: line)
  }

  @MainActor
  private func assertInert(_ ui: Harness, _ context: String, file: StaticString = #filePath, line: UInt = #line) async throws {
    let inert = try await ui.json("__rebUiProbe.inertness([])")
    XCTAssertEqual(inert["executed"] as? Bool, false, "\(context): a captured value executed", file: file, line: line)
    XCTAssertEqual(inert["injectedElements"] as? Int, 0, "\(context): captured markup became DOM", file: file, line: line)
  }

  @MainActor
  private func show(_ ui: Harness, _ screen: String) async throws {
    try await ui.click(".primary-nav .nav-button[data-screen='\(screen)']")
    try await ui.waitUntil("!document.querySelector('#screen-\(screen)').hidden", "\(screen) screen did not open")
  }

  @MainActor
  func test1TrafficRequests() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      let rows = try await ui.value("__rebUiProbe.count('#screen-traffic .request-row') > 0 && document.querySelectorAll('#screen-traffic .request-row').length") as? Int ?? 0
      XCTAssertGreaterThanOrEqual(rows, expected.requestCount, "\(size.name): retained native requests are listed")
      // A stored session is a fixed set; none of its requests is new.
      let latestHidden = try await ui.value("document.querySelector('#request-latest').hidden") as? Bool
      XCTAssertEqual(latestHidden, true, "\(size.name): a stored session must not claim new requests")
      try await assertLayout(ui, ".toolbar", "\(size.name) toolbar")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) traffic list")
      try await ui.screenshot("traffic-list-\(size.name)")

      let scroll = try await ui.json("__rebUiProbe.scrollToEnd('#screen-traffic .request-row', '.request-row')")
      XCTAssertEqual(scroll["scrollable"] as? Bool, true, "\(size.name): request list must scroll: \(scroll)")
      XCTAssertEqual(scroll["moved"] as? Bool, true, "\(size.name): request list scroll position must change")
      XCTAssertEqual(scroll["lastVisible"] as? Bool, true, "\(size.name): last request must be reachable: \(scroll)")
      try await ui.screenshot("traffic-list-scrolled-\(size.name)")

      try await ui.click("#screen-traffic .request-row", containing: "inert.test")
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let rowText = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"], #screen-traffic .request-row.selected')?.innerText ?? ''") as? String ?? ""
      XCTAssertTrue(rowText.contains(expected.hostileUrlMarker), "\(size.name): hostile URL renders as literal text: \(rowText)")
      try await assertInert(ui, "\(size.name) traffic detail")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) traffic detail")
      try await ui.screenshot("traffic-detail-\(size.name)")
    }
  }

  @MainActor
  func test2SourcesRetainedArtifact() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      // Native guest artifacts are an adapter JSON recipe and a bytecode buffer, not JavaScript.
      for (artifact, icon, kind) in [("artifact 108", "AD", "guest adapter JSON"), ("artifact 109", "BC", "guest bytecode")] {
        let find = "[...document.querySelectorAll('#source-tree [role=treeitem]')].find(row => row.innerText.includes('\(artifact)'))"
        let shown = try await ui.value("\(find)?.querySelector('.source-file-icon')?.innerText ?? ''") as? String ?? ""
        XCTAssertEqual(shown, icon, "\(size.name): \(artifact) is labeled \(icon), not JS")
        // The kind detail is collapsed in the navigator; it is still the row's text.
        let detail = try await ui.value("\(find)?.textContent ?? ''") as? String ?? ""
        XCTAssertTrue(detail.contains(kind), "\(size.name): \(artifact) names its kind: \(detail)")
      }
      try await ui.click("#source-tree [role=treeitem]", containing: "artifact 303")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('retainedLine')", "retained source did not render")
      let source = try await ui.value("document.querySelector('#source-code').innerText") as? String ?? ""
      XCTAssertTrue(source.contains(expected.hostileSourceMarker), "\(size.name): captured markup shows as source text")
      try await assertInert(ui, "\(size.name) sources")
      try await assertLayout(ui, "#screen-sources", "\(size.name) sources")
      try await ui.screenshot("sources-artifact-\(size.name)")
      let scroll = try await ui.json("__rebUiProbe.scrollToEnd('#source-code', '#source-code > *')")
      XCTAssertEqual(scroll["scrollable"] as? Bool, true, "\(size.name): long source must scroll: \(scroll)")
      XCTAssertEqual(scroll["lastVisible"] as? Bool, true, "\(size.name): last retained line reachable: \(scroll)")
      try await ui.screenshot("sources-artifact-scrolled-\(size.name)")
    }
  }

  @MainActor
  func test3InvestigationNavigation() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: "item-3.scroll.test")
      try await show(ui, "sources")
      try await ui.waitUntil("!document.querySelector('#investigation-navigation').hidden && !document.querySelector('#investigation-back').disabled", "investigation history did not record the request")
      try await assertLayout(ui, "#investigation-navigation", "\(size.name) investigation navigation")
      try await ui.screenshot("investigation-back-available-\(size.name)")
      // Alt+Left is the documented keyboard route back to the previous stop.
      try await ui.key(123, "\u{F702}", modifiers: [.option, .function, .numericPad])
      try await ui.waitUntil("!document.querySelector('#screen-traffic').hidden", "Alt+Left did not return to Traffic")
      let selected = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"], #screen-traffic .request-row.selected')?.innerText ?? ''") as? String ?? ""
      XCTAssertTrue(selected.contains("item-3.scroll.test"), "\(size.name): Back restores the selected request: \(selected)")
      try await ui.screenshot("investigation-returned-\(size.name)")
      try await ui.click("#investigation-forward")
      try await ui.waitUntil("!document.querySelector('#screen-sources').hidden", "Forward did not reopen Sources")
    }
  }

  @MainActor
  func test4VmNativeGuestRows() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await ui.click("#vm-list .vm-row", containing: "artifact 107")
      try await ui.click("[data-vm-panel='native-wasm']")
      let panel = "[data-vm-panel-content='native-wasm']"
      try await ui.waitUntil("!document.querySelector(\"\(panel)\")?.hidden", "native observations panel did not open")
      let text = try await ui.value("document.querySelector(\"\(panel)\").innerText") as? String ?? ""
      XCTAssertTrue(text.contains("Native guest state"), "\(size.name): guest section renders")
      XCTAssertTrue(text.contains("18446744073709551615"), "\(size.name): wide guest instance identity renders exactly: \(text)")
      XCTAssertFalse(text.contains("No native guest samples retained"), "\(size.name): real C++ guest sample is retained")
      try await ui.click("\(panel) details.vm-effect-row summary")
      try await assertInert(ui, "\(size.name) vm")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm native guest")
      try await ui.screenshot("vm-native-guest-\(size.name)")

      try await ui.click("#vm-list .vm-row", containing: "artifact 18446744073709551615")
      try await ui.click("[data-vm-panel='native-wasm']")
      let physical = try await ui.value("document.querySelector(\"\(panel)\").innerText") as? String ?? ""
      XCTAssertTrue(physical.contains("guest PC unknown"), "\(size.name): physical rows never claim a guest PC: \(physical)")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm native physical")
      try await ui.screenshot("vm-native-physical-\(size.name)")
    }
  }

  @MainActor
  func test5KeyboardFocusOrder() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      // Start from the first toolbar control so the order is deterministic.
      try await ui.click(".primary-nav .nav-button[data-screen='traffic']")
      var stops: [[String: Any]] = []
      for _ in 0..<30 {
        try await ui.tab()
        stops.append(try await ui.json("__rebUiProbe.focusState()"))
      }
      let names = stops.map { $0["element"] as? String ?? "?" }
      print("RENDERED_UI_FOCUS \(size.name) \(names)")
      XCTAssertTrue(names.first?.contains("Collection") == true, "\(size.name): Tab follows the toolbar order: \(names.prefix(6))")
      for (index, stop) in stops.enumerated() {
        let name = stop["element"] as? String ?? "?"
        XCTAssertNotEqual(name, "none", "\(size.name): Tab \(index + 1) lost focus")
        XCTAssertEqual(stop["focusVisible"] as? Bool, true, "\(size.name): \(name) matches :focus-visible")
        XCTAssertNotEqual(stop["indicator"] as? String, "none", "\(size.name): \(name) shows a focus indicator")
        XCTAssertEqual(stop["inViewport"] as? Bool, true, "\(size.name): \(name) is scrolled into view")
      }
      try await ui.screenshot("keyboard-focus-\(size.name)")
      let forward = names.last
      try await ui.tab(shift: true)
      let back = try await ui.json("__rebUiProbe.focusState()")["element"] as? String
      XCTAssertEqual(back, names[names.count - 2], "\(size.name): Shift+Tab reverses from \(forward ?? "?")")
    }
  }

  @MainActor
  func test6RemovedFeaturesAreAbsent() async throws {
    let ui = try await prepare(windowSizes[0])
    for screen in ["traffic", "api-collection", "sources", "vm", "signals"] {
      try await show(ui, screen)
      let text = try await ui.value("document.querySelector('#screen-\(screen)').innerText") as? String ?? ""
      for phrase in removedFeaturePhrases {
        XCTAssertFalse(text.contains(phrase), "\(screen) still offers removed CDP feature text: \(phrase)")
      }
    }
    for id in ["websocket-inspector", "runtime-hook-traffic", "request-memory-pivot", "screen-memory", "screen-experiments",
      "open-api-catalog", "api-catalog", "passive-security", "traffic-capture-export", "request-search-scope",
      "inspector-tab-payload", "inspector-tab-preview", "inspector-tab-response", "inspector-tab-compare", "traffic-comparison",
      "screen-field-provenance", "decoder-field-origin"] {
      let count = try await ui.value("document.querySelectorAll('#\(id)').length") as? Int ?? -1
      XCTAssertEqual(count, 0, "#\(id) must be removed, not hidden")
    }
  }

  // Native rows carry no headers or bodies; guest bytecode is binary. Traffic,
  // Export and Sources must offer only what that evidence supports.
  @MainActor
  func test7NativeOnlyTrafficExportAndBytecode() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: "item-3.scroll.test")
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let tabs = try await ui.value("[...document.querySelectorAll('#screen-traffic .inspector-tab')].map(tab => tab.innerText.trim()).join('|')") as? String ?? ""
      XCTAssertEqual(tabs, "General|Initiator|Timing|Signals|Evidence", "\(size.name): Traffic offers no body, Compare or header-pane tabs")
      let search = try await ui.value("document.querySelectorAll('#request-search-scope, #request-search-status, #traffic-comparison').length") as? Int ?? -1
      XCTAssertEqual(search, 0, "\(size.name): content search and comparison are removed, not hidden")
      let general = try await ui.value("document.querySelector('#exchange-inspector').innerText") as? String ?? ""
      XCTAssertTrue(general.contains("Request and response headers and bodies are not captured"), "\(size.name): native coverage is explicit: \(general)")
      let panes = try await ui.value("document.querySelectorAll('#exchange-inspector .exchange-pane').length") as? Int ?? -1
      XCTAssertEqual(panes, 0, "\(size.name): no permanently empty request/response header panes")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) traffic general")
      try await ui.screenshot("traffic-general-\(size.name)")

      try await ui.click("#open-captured-export")
      try await ui.waitUntil("document.querySelector('#captured-export-dialog').open", "export dialog did not open")
      let exportState = try await ui.json("""
        ({formatHidden: document.querySelector('[data-export-format-field]').hidden,
          sourceHidden: document.querySelector('[data-export-source-field]').hidden,
          fileShown: !document.querySelector('[data-export-file-field]').hidden,
          title: document.querySelector('#captured-export-title').innerText,
          context: document.querySelector('#captured-export-context').innerText})
        """)
      XCTAssertEqual(exportState["formatHidden"] as? Bool, true, "\(size.name): no format choice when only one mode works")
      XCTAssertEqual(exportState["sourceHidden"] as? Bool, true, "\(size.name): no schema-source choice")
      XCTAssertEqual(exportState["fileShown"] as? Bool, true, "\(size.name): local introspection file stays available")
      XCTAssertEqual(exportState["title"] as? String, "Export GraphQL schema")
      XCTAssertTrue((exportState["context"] as? String ?? "").contains("HAR exports are unavailable here"), "\(size.name): unavailable modes are explained: \(exportState)")
      try await assertLayout(ui, "#captured-export-dialog", "\(size.name) export dialog")
      try await ui.screenshot("export-native-\(size.name)")
      try await ui.key(53, "\u{1B}")
      try await ui.waitUntil("!document.querySelector('#captured-export-dialog').open", "Escape did not close export")

      try await show(ui, "sources")
      try await ui.click("#source-tree [role=treeitem]", containing: "artifact 109")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('00000000')", "golden guest bytecode did not render as hex")
      let golden = try await ui.value("document.querySelector('#source-code').innerText") as? String ?? ""
      XCTAssertTrue(golden.contains("00000000  00 42 00 00"), "\(size.name): real guest bytecode shows its bytes: \(golden)")
      XCTAssertTrue(golden.contains("|.B..|"), "\(size.name): printable column replaces control bytes")
      XCTAssertFalse(golden.contains("\u{0}"), "\(size.name): NUL bytes are never decoded as text")
      let language = try await ui.value("document.querySelector('#source-language').innerText") as? String
      XCTAssertEqual(language, "Guest bytecode hex", "\(size.name): bytecode is labeled as a hex view")

      try await ui.click("#source-tree [role=treeitem]", containing: "artifact 310")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('3c 69 6d 67')", "hostile bytecode did not render as hex")
      let hostile = try await ui.value("document.querySelector('#source-code').innerText") as? String ?? ""
      let prefix = String(expected.hostileBytecodeMarkup.prefix(16))
      XCTAssertTrue(hostile.contains("|\(prefix)|"), "\(size.name): markup bytes appear only as printable hex-view text: \(hostile)")
      XCTAssertTrue(hostile.contains("ff fe 00 80"), "\(size.name): invalid UTF-8 stays as bytes")
      XCTAssertFalse(hostile.contains("\u{FFFD}"), "\(size.name): no lossy UTF-8 replacement characters")
      try await assertInert(ui, "\(size.name) bytecode hex")
      let icon = try await ui.json("""
        (() => { const icon = document.querySelector('.source-editor-tab[aria-selected="true"] .source-file-icon');
          return {text: icon?.innerText ?? '', clipped: icon ? icon.scrollWidth > icon.clientWidth + 1 : true}; })()
        """)
      XCTAssertEqual(icon["text"] as? String, "BC", "\(size.name): editor tab names the bytecode kind")
      XCTAssertEqual(icon["clipped"] as? Bool, false, "\(size.name): the two-letter kind icon is not clipped")
      try await assertLayout(ui, "#screen-sources", "\(size.name) sources bytecode")
      try await ui.screenshot("sources-bytecode-\(size.name)")
    }
  }
}
