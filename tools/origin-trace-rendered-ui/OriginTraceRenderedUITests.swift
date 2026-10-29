import AppKit
import WebKit
import XCTest

// Hosted inside the packaged Origin Trace app (TEST_HOST), so every check runs
// against the production window and WKWebView. Pointer and keyboard input are
// native AppKit events; JavaScript inspects layout and DOM state and scrolls
// specific targets into view.
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
    // AppKit activation precedes WebKit's asynchronous focus notification.
    // Sending input in that gap can lose a click or suppress :focus-visible.
    try await waitUntil("document.hasFocus()", timeout: 10, "WebKit did not receive native window focus")
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
    // Reproduce a smaller display without changing the machine's resolution.
    let maximumHeight = ProcessInfo.processInfo.environment["REB_RENDERED_UI_MAX_HEIGHT"].flatMap(Double.init)
    let requestedHeight = min(height, CGFloat(maximumHeight ?? Double(height)))
    var frame = window.frame
    let content = window.contentRect(forFrameRect: frame)
    frame.size = window.frameRect(forContentRect: NSRect(x: 0, y: 0, width: width, height: requestedHeight)).size
    frame.origin.y += content.height - requestedHeight
    window.setFrame(frame, display: true)
    try await settle()
    let size = try await json("({width: innerWidth, height: innerHeight})")
    print("RENDERED_UI_VIEWPORT requested \(width)x\(height), height limit \(requestedHeight), actual \(size)")
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
    // Say whether input was lost or the app refused it (for example a stale
    // history entry), so an intermittent timeout is diagnosable from the log.
    let context = (try? await json(
      "({screens: [...document.querySelectorAll('.screen')].filter(screen => !screen.hidden).map(screen => screen.id).join(','), " +
      "focus: __rebUiProbe.describe(document.activeElement), documentFocused: document.hasFocus(), notice: document.querySelector('#investigation-notice')?.textContent ?? '', " +
      "back: document.querySelector('#investigation-back')?.innerText ?? '', forward: document.querySelector('#investigation-forward')?.innerText ?? ''})"
    )).map { "\($0)" } ?? "state unavailable"
    throw HarnessError("Timed out: \(message) [active=\(NSApp.isActive), key=\(window.isKeyWindow), \(context)]")
  }

  // The outgoing document satisfies the same readiness condition as the new
  // one, so a fixed sleep can return before navigation and deliver the next
  // click to a page being torn down. Mark the old document and wait for a
  // document without the mark.
  func reload() async throws {
    try await activate()
    _ = try await webView.callAsyncJavaScript("window.__rebOutgoingDocument = true; return true;", contentWorld: .page)
    webView.reload()
    try await waitUntil(
      "window.__rebOutgoingDocument === undefined && document.readyState === 'complete' && typeof state === 'object' && state.requests.length > 0 && !document.querySelector('#screen-traffic').hidden",
      timeout: 30, "the packaged UI did not load retained evidence")
    try await settle()
  }

  // Reveal just this target and wait for scrolling to settle. A smaller display
  // can clamp the window, so nearby headings and rows need separate reveals.
  @discardableResult
  func reveal(_ selector: String, containing text: String? = nil, block: String = "nearest") async throws -> NSPoint {
    let textArgument = text.map { "'\($0.replacingOccurrences(of: "'", with: "\\'"))'" } ?? "null"
    let probe = "__rebUiProbe.center('\(selector.replacingOccurrences(of: "'", with: "\\'"))', \(textArgument), \(String(reflecting: block))) || {}"
    // center() scrolls the target into view, which can still be moving when
    // it returns. Continue only once two measurements after settling agree, so
    // the event cannot land on the row that scrolled into the old position.
    var x = 0.0, y = 0.0, stable = false
    for _ in 0..<20 {
      let point = try await json(probe)
      guard let nextX = point["x"] as? Double, let nextY = point["y"] as? Double else {
        throw HarnessError("No visible target for \(selector) \(text ?? "")")
      }
      try await settle()
      if nextX == x && nextY == y {
        stable = true
        break
      }
      x = nextX
      y = nextY
    }
    guard stable else { throw HarnessError("Target kept moving: \(selector) \(text ?? "")") }
    return NSPoint(x: x, y: y)
  }

  // Native pointer input: AppKit routes the event through WKWebView hit testing.
  func click(_ selector: String, containing text: String? = nil) async throws {
    try await activate()
    let point = try await reveal(selector, containing: text)
    try await activate()
    // CSS pixels map 1:1 to view points; WKWebView reports a flipped view.
    let location = NSPoint(x: point.x, y: webView.isFlipped ? point.y : webView.bounds.height - point.y)
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
    try await activate()
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

  // Puts a VM card heading at the top of the finding panels, and the panels at
  // the top of the findings workspace. Earlier clicks and scrollIntoView calls
  // otherwise leave both scroll positions arbitrary, so a screenshot could start
  // mid-card or slice through a control of the card above it.
  func revealVmHeading(_ panel: String, _ heading: String) async throws {
    let result = try await json(
      """
      (() => {
        const panel = document.querySelector(\(String(reflecting: panel)));
        const heading = [...(panel?.querySelectorAll('h4') ?? [])].find(item => item.textContent === \(String(reflecting: heading)));
        if (!heading) return {missing: true};
        const panels = heading.closest('.vm-workbench-panels'), workspace = panels.closest('#vm-findings-workspace');
        // Keep the heading's own top margin, and the card's top border when the
        // heading opens the card; a borderless card collapses that margin outside it.
        const card = heading.closest('.vm-workspace-card');
        const gap = parseFloat(getComputedStyle(heading).marginTop) +
          (card.firstElementChild === heading ? parseFloat(getComputedStyle(card).borderTopWidth) : 0);
        workspace.scrollTop += panels.getBoundingClientRect().top - workspace.getBoundingClientRect().top;
        panels.scrollTop += heading.getBoundingClientRect().top - gap - panels.getBoundingClientRect().top;
        const shown = heading.getBoundingClientRect(), frame = panels.getBoundingClientRect();
        return {visible: shown.top >= frame.top && shown.bottom <= frame.bottom};
      })()
      """)
    guard result["missing"] == nil else { throw HarnessError("No VM card heading \(heading) in \(panel)") }
    XCTAssertEqual(result["visible"] as? Bool, true, "VM card heading \(heading) is not fully visible")
    try await settle()
  }

  // Every direct heading, paragraph (notices included) and pager of a VM
  // workspace card in the panel starts 12px inside the card's content edge,
  // the inset of .vm-workspace-heading. Returns each offender.
  func vmCardInsetOffenders(_ panel: String) async throws -> [String] {
    let result = try await json(
      """
      (() => {
        const root = document.querySelector(\(String(reflecting: panel)));
        const cards = [...(root.matches('.vm-workspace-card') ? [root] : []), ...root.querySelectorAll('.vm-workspace-card')];
        const offenders = [];
        for (const card of cards) {
          const edge = card.getBoundingClientRect().left + parseFloat(getComputedStyle(card).borderLeftWidth);
          for (const item of card.querySelectorAll(':scope > h4, :scope > p:not(.vm-effect-detail), :scope > .vm-evidence-pager')) {
            const box = (item.matches('.vm-evidence-pager') ? item.firstElementChild : item).getBoundingClientRect();
            const inset = Math.round(box.left - edge);
            if (box.width > 0 && inset !== 12) offenders.push(`${item.tagName.toLowerCase()} "${item.textContent.slice(0, 40)}" at ${inset}px`);
          }
        }
        return {offenders, cards: cards.length};
      })()
      """)
    guard (result["cards"] as? Int ?? 0) > 0 else { throw HarnessError("No VM workspace card in \(panel)") }
    return result["offenders"] as? [String] ?? ["probe returned no offenders list"]
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
  private func assertFullyVisible(_ ui: Harness, _ selector: String, _ context: String,
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
    let box = try await ui.json("__rebUiProbe.box(\(String(reflecting: selector)))")
    let height = box["height"] as? Double ?? 0
    XCTAssertGreaterThan(height, 0, "\(context): missing \(selector)", file: file, line: line)
    XCTAssertEqual(box["visibleHeight"] as? Double ?? -1, height, accuracy: 1,
      "\(context): vertically clipped \(selector): \(box)", file: file, line: line)
    XCTAssertEqual(box["visibleWidth"] as? Double ?? -1, box["width"] as? Double ?? 0, accuracy: 1,
      "\(context): horizontally clipped \(selector): \(box)", file: file, line: line)
  }

  // Scrolling assertions are explicit. assertFullyVisible must stay passive
  // for fixed chrome, at-rest analysis, and product-driven keyboard navigation.
  @MainActor
  private func revealAndAssertFullyVisible(_ ui: Harness, _ selector: String, _ context: String,
                                          file: StaticString = #filePath, line: UInt = #line) async throws {
    try await ui.reveal(selector, block: "center")
    try await assertFullyVisible(ui, selector, context, file: file, line: line)
    print("RENDERED_UI_REVEALED \(context) \(try await ui.json("__rebUiProbe.box(\(String(reflecting: selector)))"))")
  }

  @MainActor
  private func usesCompactVmLayout(_ ui: Harness) async throws -> Bool {
    // AppKit may clamp a requested window to its display. Test the media query
    // against the actual CSS viewport instead of the requested dimensions.
    let compact = try await ui.value("matchMedia('(max-width: 900px), (max-height: 650px)').matches") as? Bool
    return try XCTUnwrap(compact)
  }

  @MainActor
  private func assertHandlerColumns(_ ui: Harness, _ context: String) async throws {
    let columns = try await ui.json("""
      (() => { const row = document.querySelector('.vm-workbench-listing .vm-handler-row');
        const opcode = row.querySelector('.vm-handler-opcode');
        const text = document.createRange(); text.selectNodeContents(opcode);
        return {textRight: text.getBoundingClientRect().right,
          labelLeft: row.querySelector('.vm-handler-label').getBoundingClientRect().left}; })()
      """)
    print("RENDERED_UI_HANDLER_COLUMNS \(context) \(columns)")
    XCTAssertGreaterThanOrEqual((columns["labelLeft"] as? Double ?? 0) - (columns["textRight"] as? Double ?? .infinity), 5,
      "\(context): opcode text keeps a readable gap before the operation label")
  }

  @MainActor
  private func assertVmDock(_ ui: Harness, _ context: String) async throws {
    let geometry = try await ui.json("""
      (() => { const box = __rebUiProbe.box; return {
        grid: box('#vm-findings-workspace > .vm-grid'), detail: box('#vm-detail'),
        panels: box('.vm-workbench-panels'), tabs: box('.vm-workbench-tabs'),
        footer: box('.vm-program-example > summary'), status: box('.statusbar')}; })()
      """)
    print("RENDERED_UI_VM_DOCK \(context) \(geometry)")
    let grid = geometry["grid"] as? [String: Double] ?? [:]
    let detail = geometry["detail"] as? [String: Double] ?? [:]
    let panels = geometry["panels"] as? [String: Double] ?? [:]
    let tabs = geometry["tabs"] as? [String: Double] ?? [:]
    let footer = geometry["footer"] as? [String: Double] ?? [:]
    let status = geometry["status"] as? [String: Double] ?? [:]
    if try await usesCompactVmLayout(ui) {
      XCTAssertEqual(detail["width"] ?? -1, grid["width"] ?? 0, accuracy: 1,
        "\(context): compact findings give the full column to evidence")
    }
    XCTAssertEqual(panels["bottom"] ?? -1, tabs["top"] ?? 0, accuracy: 1,
      "\(context): analysis scroller ends exactly at the tab strip")
    XCTAssertLessThanOrEqual(footer["bottom"] ?? .infinity, status["top"] ?? 0,
      "\(context): example footer ends before the status bar")
    try await assertFullyVisible(ui, ".vm-program-example > summary", "\(context) example footer")
    try await assertFullyVisible(ui, ".vm-workbench-tabs", "\(context) analysis tabs")
  }

  @MainActor
  private func setVmAnalysisExpanded(_ ui: Harness, _ expanded: Bool) async throws {
    let toggle = try await ui.json("""
      ({...__rebUiProbe.box('#vm-analysis-toggle'),
        expanded: document.querySelector('#vm-analysis-toggle')?.getAttribute('aria-expanded') === 'true'})
      """)
    if (toggle["visibleHeight"] as? Double ?? 0) > 0 && toggle["expanded"] as? Bool != expanded {
      try await ui.click("#vm-analysis-toggle")
    }
  }

  @MainActor
  func test10VmAnalysisPaneAcrossDockTabs() async throws {
    let sizes: [(name: String, width: CGFloat, height: CGFloat)] = [
      ("normal", 1180, 790), ("narrow", 760, 560),
      ("short", 1180, 560), ("narrow-tall", 760, 790),
    ]
    for size in sizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 107")
      try await setVmAnalysisExpanded(ui, false)
      let tabs = try await ui.value("[...document.querySelectorAll('.vm-workbench-tabs [data-vm-panel]')].map(tab => tab.dataset.vmPanel)") as? [String] ?? []
      XCTAssertGreaterThan(tabs.count, 1)
      var initialHeight: Double?
      for tab in tabs {
        try await ui.click("[data-vm-panel='\(tab)']")
        let pane = try await ui.json("""
          (() => { const box = __rebUiProbe.box;
            const toggle = document.querySelector('#vm-analysis-toggle');
            const collapsed = box('#vm-analysis-toggle').visibleHeight > 0 && toggle?.getAttribute('aria-expanded') === 'false';
            const top = collapsed ? box('#vm-analysis-toggle').top : box('#vm-findings-workspace > .vm-grid').top;
            const bottom = box('.vm-workbench-inspector').top;
            return {collapsed, top, bottom, height: bottom - top,
              header: box('#vm-analysis-toggle'), tree: box('.vm-list-pane'), body: box('.vm-workbench-body')}; })()
          """)
        print("RENDERED_UI_ANALYSIS_PANE \(size.name) \(tab) \(pane)")
        let height = pane["height"] as? Double ?? 0
        if pane["collapsed"] as? Bool == true {
          try await assertFullyVisible(ui, "#vm-analysis-toggle", "\(size.name) collapsed analysis header")
          let header = pane["header"] as? [String: Double] ?? [:]
          XCTAssertEqual(height, header["height"] ?? 0, accuracy: 1, "\(size.name): collapsed pane contains only its complete header")
          for key in ["tree", "body"] {
            let hidden = pane[key] as? [String: Double] ?? [:]
            XCTAssertEqual(hidden["visibleHeight"] ?? -1, 0, "\(size.name): collapsed \(key) leaves no text fragments")
          }
        } else {
          // These must fit together at rest, including just above the compact
          // breakpoint. Revealing them here would hide a squeezed-pane defect.
          XCTAssertGreaterThanOrEqual(height, 120, "\(size.name): analysis needs space for its header and a complete row")
          try await assertFullyVisible(ui, ".vm-workbench-listing .vm-workspace-heading", "\(size.name) analysis heading")
          try await assertFullyVisible(ui, ".vm-workbench-listing .vm-handler-row", "\(size.name) analysis row")
        }
        if let initialHeight {
          XCTAssertEqual(height, initialHeight, accuracy: 1, "\(size.name): changing dock tabs must not resize analysis")
        } else { initialHeight = height }
        if ["native-wasm", "host-links"].contains(tab) {
          try await ui.screenshot("vm-analysis-\(tab)-\(size.name)")
        }
      }
      if try await usesCompactVmLayout(ui) {
        let header = try await ui.json("__rebUiProbe.box('#vm-analysis-toggle')")
        XCTAssertGreaterThan(header["visibleHeight"] as? Double ?? 0, 0, "\(size.name): compact analysis has an expandable header")
        if (header["visibleHeight"] as? Double ?? 0) == 0 { continue }
        try await setVmAnalysisExpanded(ui, true)
        try await assertFullyVisible(ui, "#vm-analysis-toggle", "\(size.name) expanded analysis header")
        try await assertFullyVisible(ui, ".vm-list-head", "\(size.name) Program Trees heading")
        try await assertFullyVisible(ui, "#vm-list .vm-row", "\(size.name) first finding")
        try await assertFullyVisible(ui, "#vm-symbol-list .vm-symbol-row", "\(size.name) symbol")
        let viewport = try await ui.json("__rebUiProbe.box('#vm-findings-workspace > .vm-grid')")
        XCTAssertGreaterThanOrEqual(viewport["visibleHeight"] as? Double ?? 0, 120, "\(size.name): expanded analysis has a useful viewport")
        try await ui.click("#vm-symbol-list .vm-symbol-row")
        try await assertFullyVisible(ui, ".vm-workbench-listing .vm-handler-row", "\(size.name) reachable handler")
        try await ui.screenshot("vm-analysis-expanded-\(size.name)")
        try await ui.click("#vm-analysis-toggle")
        // WebKit on macOS does not focus buttons on a pointer click. Reach
        // the disclosure through native keyboard navigation before Space.
        try await ui.tab(shift: true)
        print("RENDERED_UI_ANALYSIS_FOCUS_BEFORE \(size.name) \(try await ui.json("__rebUiProbe.focusState()"))")
        try await ui.tab()
        let focus = try await ui.json("__rebUiProbe.focusState()")
        print("RENDERED_UI_ANALYSIS_FOCUS \(size.name) \(focus)")
        XCTAssertTrue((focus["element"] as? String ?? "").contains("#vm-analysis-toggle"), "\(size.name): keyboard reaches the analysis header")
        XCTAssertEqual(focus["focusVisible"] as? Bool, true, "\(size.name): analysis header has visible keyboard focus")
        try await ui.key(49, " ")
        let expanded = try await ui.value("document.querySelector('#vm-analysis-toggle').getAttribute('aria-expanded')") as? String
        XCTAssertEqual(expanded, "true", "\(size.name): Space expands the analysis header")
        try await ui.key(49, " ")
        try await assertFullyVisible(ui, "#vm-analysis-toggle", "\(size.name) keyboard collapse")
      }
    }
  }

  @MainActor
  func test11VmOpcodeHeaderSpacing() async throws {
    let sizes: [(name: String, width: CGFloat, height: CGFloat)] = [
      ("normal", 1180, 790), ("narrow", 760, 560),
      ("short", 1180, 560), ("narrow-tall", 760, 790),
    ]
    for size in sizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 18446744073709551615")
      try await revealAndAssertFullyVisible(ui, ".vm-workspace-title", "\(size.name) opcode header")
      let spacing = try await ui.json("""
        (() => { const head = document.querySelector('.vm-workspace-title');
          const evidence = head.nextElementSibling;
          return {gap: evidence.getBoundingClientRect().top - head.getBoundingClientRect().bottom,
            head: __rebUiProbe.box('.vm-workspace-title'), evidence: evidence.outerHTML,
            marginTop: getComputedStyle(evidence).marginTop, marginBottom: getComputedStyle(evidence).marginBottom}; })()
        """)
      print("RENDERED_UI_OPCODE_HEADER \(size.name) \(spacing)")
      XCTAssertEqual(spacing["gap"] as? Double ?? .infinity, 0, accuracy: 1,
        "\(size.name): evidence notice follows Opcode workspace without an empty band")
      try await ui.screenshot("vm-opcode-header-\(size.name)")
    }
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
    let sizes: [(name: String, width: CGFloat, height: CGFloat)] = [
      ("normal", 1180, 790), ("narrow", 760, 560),
      ("short", 1180, 560), ("narrow-tall", 760, 790),
    ]
    for size in sizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 107")
      try await assertFullyVisible(ui, "#vm-symbol-list .vm-symbol-row", "\(size.name) symbol tree")
      try await assertHandlerColumns(ui, size.name)
      try await ui.screenshot("vm-navigator-\(size.name)")
      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='native-wasm']")
      let panel = "[data-vm-panel-content='native-wasm']"
      try await ui.waitUntil("!document.querySelector(\"\(panel)\")?.hidden", "native observations panel did not open")
      let text = try await ui.value("document.querySelector(\"\(panel)\").innerText") as? String ?? ""
      XCTAssertTrue(text.contains("Native guest state"), "\(size.name): guest section renders")
      XCTAssertTrue(text.contains("18446744073709551615"), "\(size.name): wide guest instance identity renders exactly: \(text)")
      XCTAssertFalse(text.contains("No native guest samples retained"), "\(size.name): real C++ guest sample is retained")
      try await ui.click("\(panel) details.vm-effect-row summary")
      let expanded = try await ui.value("document.querySelector(\"\(panel) details.vm-effect-row\").open") as? Bool
      XCTAssertEqual(expanded, true, "\(size.name): native input expands retained guest evidence")
      try await ui.click("\(panel) details.vm-effect-row summary")
      // Each target must be reachable in the actual viewport. The heading and
      // row need not fit together when AppKit clamps the window to the display.
      _ = try await ui.value("document.querySelector('.vm-workbench-panels').scrollTop = 0")
      try await revealAndAssertFullyVisible(ui, "\(panel) h4:nth-of-type(2)", "\(size.name) guest heading")
      try await ui.screenshot("vm-native-guest-heading-\(size.name)")
      try await revealAndAssertFullyVisible(ui, "\(panel) details.vm-effect-row summary", "\(size.name) guest row")
      try await assertInert(ui, "\(size.name) vm")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm native guest")
      try await assertVmDock(ui, size.name)
      let guestInset = try await ui.vmCardInsetOffenders(panel)
      XCTAssertEqual(guestInset, [], "\(size.name) vm native guest: card content shares the 12px inset")
      try await ui.screenshot("vm-native-guest-\(size.name)")

      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 18446744073709551615")
      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='native-wasm']")
      let physical = try await ui.value("document.querySelector(\"\(panel)\").innerText") as? String ?? ""
      XCTAssertTrue(physical.contains("guest PC unknown"), "\(size.name): physical rows never claim a guest PC: \(physical)")
      _ = try await ui.value("document.querySelector('.vm-workbench-panels').scrollTop = 0")
      try await revealAndAssertFullyVisible(ui, "\(panel) h4:first-of-type", "\(size.name) native heading")
      try await ui.screenshot("vm-native-physical-heading-\(size.name)")
      try await revealAndAssertFullyVisible(ui, "\(panel) details.vm-effect-row summary", "\(size.name) native row")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm native physical")
      try await assertVmDock(ui, size.name)
      let physicalInset = try await ui.vmCardInsetOffenders(panel)
      XCTAssertEqual(physicalInset, [], "\(size.name) vm native physical: card content shares the 12px inset")
      try await ui.screenshot("vm-native-physical-\(size.name)")

      // The structural classification renders as inert text on the dispatch
      // rows; this golden module's constant selector is not an interpreter.
      try await ui.click("[data-vm-panel='dispatch']")
      let dispatch = "[data-vm-panel-content='dispatch']"
      try await ui.waitUntil("!document.querySelector(\"\(dispatch)\")?.hidden", "dispatch sites panel did not open")
      let structure = try await ui.value("document.querySelector(\"\(dispatch)\").innerText") as? String ?? ""
      XCTAssertTrue(structure.contains("Dispatch structure"), "\(size.name): classification section renders: \(structure)")
      XCTAssertTrue(structure.contains("switch_on_value / constant / unknown · not an interpreter loop"),
        "\(size.name): classification axes render on the dispatch rows: \(structure)")
      XCTAssertFalse(structure.contains("· cursor-loop interpreter candidate"), "\(size.name): no interpreter claim: \(structure)")
      try await assertInert(ui, "\(size.name) vm dispatch")
      try await ui.revealVmHeading(dispatch, "Dispatch structure")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm dispatch structure")
      let dispatchInset = try await ui.vmCardInsetOffenders(dispatch)
      XCTAssertEqual(dispatchInset, [], "\(size.name) vm dispatch structure: card content shares the 12px inset")
      try await ui.screenshot("vm-dispatch-structure-\(size.name)")

      try await ui.click("#vm-list .vm-row", containing: "artifact 311")
      try await ui.click("[data-vm-panel='dispatch']")
      try await ui.waitUntil("document.querySelector(\"\(dispatch)\").innerText.includes('parse-failed')", "parse failure omission did not render")
      let omitted = try await ui.value("document.querySelector(\"\(dispatch)\").innerText") as? String ?? ""
      XCTAssertTrue(omitted.contains("1 record omitted."), "\(size.name): parse failure remains counted: \(omitted)")
      try await assertInert(ui, "\(size.name) vm parse failure")
      try await ui.revealVmHeading(dispatch, "Dispatch structure")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm parse failure")
      try await ui.screenshot("vm-parse-failed-\(size.name)")
    }
  }

  @MainActor
  func test8VmHostLinksSpacing() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 107")
      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='host-links']")
      let spacing = try await ui.json("""
        (() => { const panel = document.querySelector('[data-vm-panel-content="host-links"]');
          const empty = getComputedStyle(panel.querySelector('.vm-workspace-empty'));
          const paragraph = getComputedStyle(panel.querySelector('p'));
          return {emptyTop: parseFloat(empty.paddingTop), emptyBottom: parseFloat(empty.paddingBottom),
            paragraphTop: parseFloat(paragraph.paddingTop), paragraphBottom: parseFloat(paragraph.paddingBottom)}; })()
        """)
      XCTAssertEqual(spacing["emptyTop"] as? Double, spacing["paragraphTop"] as? Double,
        "\(size.name): empty paragraphs use the panel's paragraph spacing")
      XCTAssertEqual(spacing["emptyBottom"] as? Double, spacing["paragraphBottom"] as? Double,
        "\(size.name): empty paragraphs do not add a second vertical inset")
      try await revealAndAssertFullyVisible(ui, "[data-vm-panel-content='host-links'] details.vm-effect-row summary", "\(size.name) host link")
      try await assertVmDock(ui, size.name)
      try await assertLayout(ui, "#screen-vm", "\(size.name) host links")
      try await ui.screenshot("vm-host-links-\(size.name)")
    }
  }

  @MainActor
  func test9VmCompactTreesAndExample() async throws {
    // Exercise both sides of the responsive rule independently of the
    // minimum window, where width and height breakpoints apply together.
    let sizes: [(name: String, width: CGFloat, height: CGFloat)] = [
      ("short", 1180, 560), ("narrow-tall", 760, 790),
    ]
    for size in sizes {
      let ui = try await prepare(size)
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "VM findings did not load")
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 107")
      try await assertFullyVisible(ui, "#vm-symbol-list .vm-symbol-row", "\(size.name) symbol tree")
      let tree = try await ui.json("__rebUiProbe.box('.vm-list-pane')")
      XCTAssertLessThanOrEqual(tree["height"] as? Double ?? .infinity, 141,
        "\(size.name): trees stay in a compact band above the evidence")
      try await assertHandlerColumns(ui, size.name)
      try await ui.screenshot("vm-navigator-\(size.name)")
      try await ui.click("#vm-symbol-list .vm-symbol-row")
      try await ui.tab()
      let focus = try await ui.json("__rebUiProbe.focusState()")
      XCTAssertEqual(focus["inViewport"] as? Bool, true, "\(size.name): keyboard navigation reveals the next control")
      XCTAssertNotEqual(focus["indicator"] as? String, "none", "\(size.name): navigation has visible focus")

      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='host-links']")
      try await assertVmDock(ui, size.name)
      try await ui.click(".vm-program-example > summary")
      try await ui.waitUntil("document.querySelector('.vm-program-example').open", "example did not open")
      try await assertFullyVisible(ui, ".vm-program-example > summary", "\(size.name) expanded example")
      try await assertLayout(ui, ".vm-program-example", "\(size.name) expanded example")
      try await ui.screenshot("vm-example-expanded-\(size.name)")
      try await ui.key(49, " ")
      try await ui.waitUntil("!document.querySelector('.vm-program-example').open", "Space did not close the example")
      try await assertFullyVisible(ui, ".vm-program-example > summary", "\(size.name) collapsed example")
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
