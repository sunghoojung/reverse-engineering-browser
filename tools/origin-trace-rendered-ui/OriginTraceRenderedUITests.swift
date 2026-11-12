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

  // Opens this same running app again through Launch Services, as a Dock
  // click or a second open does, which delivers the application reopen event.
  func reopen() async throws {
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = true
    configuration.addsToRecentItems = false
    configuration.createsNewApplicationInstance = false
    _ = try await NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration)
    try await settle()
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
      "back: document.querySelector('#investigation-back')?.innerText ?? '', forward: document.querySelector('#investigation-forward')?.innerText ?? '', " +
      "location: location.href, readyState: document.readyState, outgoing: window.__rebOutgoingDocument === true, " +
      "requests: typeof state === 'object' ? state.requests.length : -1})"
    )).map { "\($0)" } ?? "state unavailable"
    throw HarnessError("Timed out: \(message) [active=\(NSApp.isActive), key=\(window.isKeyWindow), \(context)]")
  }

  // The outgoing document satisfies the same readiness condition as the new
  // one, so a fixed sleep can return before navigation and deliver the next
  // click to a page being torn down. Mark the old document and wait for a
  // document without the mark.
  func reload(requireRequests: Bool = true, activating: Bool = true) async throws {
    if activating { try await activate() }
    _ = try await webView.callAsyncJavaScript("window.__rebOutgoingDocument = true; return true;", contentWorld: .page)
    webView.reload()
    try await waitUntil(
      "window.__rebOutgoingDocument === undefined && document.readyState === 'complete' && typeof state === 'object' && (\(requireRequests ? "state.requests.length > 0" : "true")) && !document.querySelector('#screen-traffic').hidden",
      timeout: 30, "the packaged UI did not load retained evidence")
    try await settle()
  }

  // Reveal just this target and wait for scrolling to settle. A smaller display
  // can clamp the window, so nearby headings and rows need separate reveals.
  @discardableResult
  func reveal(_ selector: String, containing text: String? = nil, block: String = "nearest") async throws -> NSPoint {
    let textArgument = text.map { "'\($0.replacingOccurrences(of: "'", with: "\\'"))'" } ?? "null"
    let probe = "__rebUiProbe.center('\(selector.replacingOccurrences(of: "'", with: "\\'"))', \(textArgument), \(String(reflecting: block))) || {}"
    // A target can render after an asynchronous response: static VM analysis
    // rows follow runtime evidence rows once a cold analysis worker finishes.
    // Wait for the target itself rather than failing on the first frame.
    try await waitUntil("(\(probe)).x !== undefined", "No visible target for \(selector) \(text ?? "")")
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

  // Types into the focused field with native key events, one character each.
  func type(_ text: String) async throws {
    for character in text {
      try await key(0, String(character))
    }
  }

  // The window AppKit draws, for native dialogs WebKit snapshots cannot see.
  // An on-screen alert draws its text with vibrancy in the window server, so
  // cacheDisplay and layer rendering leave it blank. A process may capture its
  // own window without screen recording permission; the window list API that
  // does so is deprecated, so it is looked up rather than linked.
  func screenshot(window panel: NSWindow, _ name: String) throws {
    typealias Capture = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?
    let defaultHandle = UnsafeMutableRawPointer(bitPattern: -2)
    guard let symbol = dlsym(defaultHandle, "CGWindowListCreateImage") else { throw HarnessError("Window capture is unavailable") }
    let capture = unsafeBitCast(symbol, to: Capture.self)
    // kCGWindowListOptionIncludingWindow; ignore framing, best resolution.
    guard let image = capture(.null, 1 << 3, UInt32(panel.windowNumber), 1 | (1 << 3))?.takeRetainedValue(),
      let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    else { throw HarnessError("Could not capture \(name)") }
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    try png.write(to: output.appendingPathComponent("\(name).png"))
    print("RENDERED_UI_SCREENSHOT \(name) \(image.width)x\(image.height)")
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
  let namedGapReasons: [String]
  let requestBodyHost: String
  let requestBodyTarget: String
  let requestBodyMarker: String
  let metadataBodyHost: String
  let responseBodyHost: String
  let responseBodyMarker: String
  let headerValueMarker: String
  let cookieValueMarker: String
  let invocationArtifactId: String
  let minifiedArtifactId: String
  let memoryCacheHost: String
  let memoryCacheTarget: String
  let serviceWorkerFailedHost: String
  let serviceWorkerLostHost: String
  let invocationSiteStore: String
  let workerStackHost: String
  let workerStackPostingProcess: Int
  let registrantHost: String
  let debuggerProcess: Int
  let debuggerFrame: String
  let debuggerArtifactId: String

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

  // The same state in the light theme, set the way the theme toggle sets it,
  // without a click that could close an overlaid sidebar.
  @MainActor
  private func lightScreenshot(_ ui: Harness, _ name: String, _ size: String) async throws {
    _ = try await ui.value("""
      (async () => { window.__rebDarkTheme = document.documentElement.dataset.theme ?? null;
        document.documentElement.dataset.theme = 'light';
        await new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))); return true; })()
      """)
    try await assertLayout(ui, "#debugger-sidebar", "\(size) \(name) light")
    try await ui.screenshot("\(name)-light-\(size)")
    _ = try await ui.value("""
      (() => { if (window.__rebDarkTheme === null) delete document.documentElement.dataset.theme;
        else document.documentElement.dataset.theme = window.__rebDarkTheme; delete window.__rebDarkTheme; return true; })()
      """)
  }

  @MainActor
  private func assertInert(_ ui: Harness, _ context: String, file: StaticString = #filePath, line: UInt = #line) async throws {
    let inert = try await ui.json("__rebUiProbe.inertness([])")
    XCTAssertEqual(inert["executed"] as? Bool, false, "\(context): a captured value executed", file: file, line: line)
    XCTAssertEqual(inert["injectedElements"] as? Int, 0, "\(context): captured markup became DOM", file: file, line: line)
  }

  @MainActor
  private func show(_ ui: Harness, _ screen: String) async throws {
    // Every workspace, Flow, Analyst and Tools included, is a direct sidebar entry.
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
  private func assertCompleteCompactFindings(_ ui: Harness, _ context: String) async throws {
    guard try await usesCompactVmLayout(ui) else { return }
    let complete = """
      (() => { const list = document.querySelector('#vm-list').getBoundingClientRect();
        const rows = [...document.querySelectorAll('#vm-list .vm-row')].map(row => row.getBoundingClientRect());
        const visible = rows.filter(row => Math.min(row.bottom, list.bottom) - Math.max(row.top, list.top) > 1);
        return visible.length === 2 && visible.every(row => row.top >= list.top - 1 && row.bottom <= list.bottom + 1); })()
      """
    try await ui.waitUntil(complete, "\(context): compact Program Trees must settle on two complete findings")
    try await assertFullyVisible(ui, "#vm-list .vm-row[aria-selected='true']", "\(context) selected finding")
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
        let tree = try await ui.json("__rebUiProbe.box('.vm-list-pane')")
        XCTAssertEqual(tree["visibleHeight"] as? Double ?? -1, 0, accuracy: 1,
          "\(size.name): Symbol Tree navigation leaves no clipped tree fragment above the evidence")
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
  func test12VmRetainedSiteNavigation() async throws {
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
      try await ui.click("[data-vm-panel='dispatch']")
      try await ui.click("[data-vm-panel-content='dispatch'] button", containing: "Select retained site")
      try await assertFullyVisible(ui, ".vm-workbench-listing .vm-handler-row[aria-selected='true']", "\(size.name) retained site navigation")
      if try await usesCompactVmLayout(ui) {
        let tree = try await ui.json("__rebUiProbe.box('.vm-list-pane')")
        XCTAssertEqual(tree["visibleHeight"] as? Double ?? -1, 0, accuracy: 1,
          "\(size.name): navigation starts at the evidence without a clipped tree fragment")
      }
      try await ui.screenshot("vm-retained-site-navigation-\(size.name)")
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
      try await assertCompleteCompactFindings(ui, size.name)
      try await ui.click("#vm-symbol-list .vm-symbol-row")
      try await assertFullyVisible(ui, ".vm-workspace-title", "\(size.name) opcode header")
      try await assertFullyVisible(ui, ".vm-workbench-listing .vm-handler-row[aria-selected='true']", "\(size.name) opcode navigation")
      if try await usesCompactVmLayout(ui) {
        let tree = try await ui.json("__rebUiProbe.box('.vm-list-pane')")
        XCTAssertEqual(tree["visibleHeight"] as? Double ?? -1, 0, accuracy: 1,
          "\(size.name): opcode navigation leaves no partial tree above the evidence")
      }
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

  // Columns fit the table, every cell with text has a tooltip, and Size, the
  // waterfall and the timing strip follow the fixture's recorded lengths and
  // timestamps. The strip and the column menu work from the keyboard.
  @MainActor
  private func assertTrafficColumns(_ ui: Harness, _ context: String) async throws {
    // Only rows near the view are mounted, and item-3 is below the first screen.
    try await ui.reveal("#screen-traffic .request-row", containing: "item-3.scroll.test")
    let table = try await ui.json("""
      (() => { const shown = cell => cell.getBoundingClientRect().width > 0;
        const row = [...document.querySelectorAll('#screen-traffic .request-row')].find(node => node.innerText.includes('item-3.scroll.test'));
        return {visible: [...document.querySelectorAll('#screen-traffic .request-head [data-column]')].filter(shown).map(cell => cell.dataset.column),
          untitled: [...document.querySelectorAll('#screen-traffic .request-row [data-column]')].filter(cell => shown(cell) && cell.textContent.trim() && !cell.title).length,
          footer: document.querySelector('#request-window-status').textContent,
          bars: document.querySelectorAll('#request-overview .overview-bar').length,
          size: row?.querySelector('.size-transfer')?.textContent ?? '', sizeTitle: row?.querySelector('.request-size')?.title ?? '',
          waterfall: row?.querySelector('.waterfall-bar')?.getBoundingClientRect().width ?? -1}; })()
      """)
    print("RENDERED_UI_TRAFFIC_COLUMNS \(context) \(table)")
    _ = try await ui.value("document.querySelector('#request-rows').scrollTop = 0")
    try await ui.waitUntil("document.querySelector('#screen-traffic .request-row')?.getAttribute('aria-posinset') === '1'", "\(context): the list did not return to its first row")
    let visible = table["visible"] as? [String] ?? []
    XCTAssertEqual(visible.first, "name", "\(context): Name always shows")
    XCTAssertTrue(visible.contains("status") && visible.contains("time"), "\(context): narrow tables drop low-priority columns first: \(visible)")
    XCTAssertFalse(visible.contains("protocol"), "\(context): Protocol is hidden by default")
    if context == "normal" {
      XCTAssertEqual(visible, ["name", "status", "type", "method", "initiator", "size", "time", "waterfall"], "\(context): default columns")
      XCTAssertGreaterThan(table["waterfall"] as? Double ?? 0, 0, "\(context): a completed request has a waterfall bar")
    }
    XCTAssertEqual(table["untitled"] as? Int, 0, "\(context): truncated cells have tooltips")
    let footer = table["footer"] as? String ?? ""
    XCTAssertTrue(footer.contains(" transferred · ") && footer.contains(" resources"), "\(context): footer totals: \(footer)")
    XCTAssertEqual(table["bars"] as? Int, 120, "\(context): the timing strip has one bar per bucket")
    // syntheticTransferSize(3) in evidence-fixture.mjs.
    if visible.contains("size") {
      XCTAssertEqual(table["size"] as? String, "1.0 kB", "\(context): Size shows the recorded transfer size")
    }
    XCTAssertTrue((table["sizeTitle"] as? String ?? "").contains("Transferred: 1,030 bytes."), "\(context): Size tooltip is exact: \(table)")
    _ = try await ui.value("document.querySelector('#request-overview .overview-track').focus()")
    try await ui.key(124, "\u{F703}", modifiers: [.function, .numericPad])
    try await ui.waitUntil("state.trafficRange !== null", "\(context): Right Arrow on the timing strip did not select a time range")
    try await assertLayout(ui, "#screen-traffic", "\(context) traffic time range")
    try await ui.screenshot("traffic-time-range-\(context)")
    try await ui.key(53, "\u{1B}")
    try await ui.waitUntil("state.trafficRange === null", "\(context): Escape did not clear the time range")
    _ = try await ui.value("document.querySelector('#screen-traffic .request-head [data-column=\"name\"]').focus()")
    try await ui.key(109, "\u{F70D}", modifiers: [.shift, .function])
    try await ui.waitUntil("document.activeElement?.closest('.column-menu') !== null", "\(context): Shift+F10 did not open the column menu")
    // A column the width dropped is on but not shown, so the menu must not read as simply checked.
    let droppedColumnsRead = try await ui.value("[...document.querySelectorAll('.column-menu [role=menuitemcheckbox]')].filter(item => (document.querySelector('.request-table')?.dataset.hiddenColumns ?? '').split(' ').includes(item.dataset.columnId) && item.getAttribute('aria-checked') === 'true').length") as? Int ?? -1
    XCTAssertEqual(droppedColumnsRead, 0, "\(context): a column the width dropped must not read as shown")
    try await assertLayout(ui, ".column-menu", "\(context) column menu")
    try await ui.screenshot("traffic-column-menu-\(context)")
    try await ui.key(53, "\u{1B}")
    try await ui.waitUntil("document.querySelector('.column-menu') === null && document.activeElement?.dataset.column === 'name'",
      "\(context): Escape did not close the column menu and return focus")
  }

  @MainActor
  func test1TrafficRequests() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.waitUntil("__rebUiProbe.count('#screen-traffic .request-row') > 0", "no request rows rendered")
      // Only rows in view and 8 on each side are mounted; every row names its place in the whole list.
      let list = try await ui.json("""
        (() => { const rows = [...document.querySelectorAll('#screen-traffic .request-row')];
          return {mounted: rows.length, size: Number(rows[0].getAttribute('aria-setsize')),
            view: Math.ceil(document.querySelector('#request-rows').clientHeight / rows[0].offsetHeight)}; })()
        """)
      XCTAssertGreaterThanOrEqual(list["size"] as? Int ?? 0, expected.requestCount, "\(size.name): retained native requests are listed: \(list)")
      XCTAssertLessThanOrEqual(list["mounted"] as? Int ?? .max, (list["view"] as? Int ?? 0) + 17, "\(size.name): only rows near the view are mounted: \(list)")
      // Rows and the footer come from the session request index, not the newest window.
      let indexed = try await ui.value("state.trafficIndex?.answer()?.document.total ?? -1") as? Int ?? -1
      XCTAssertGreaterThanOrEqual(indexed, expected.requestCount, "\(size.name): the request index lists the session")
      let footer = try await ui.json("""
        ({text: document.querySelector('#request-window-status').textContent, total: (\(indexed)).toLocaleString('en-US')})
        """)
      let total = footer["total"] as? String ?? "?"
      XCTAssertTrue((footer["text"] as? String ?? "").hasPrefix("\(total) / \(total) requests"), "\(size.name): footer counts the session: \(footer)")
      try await assertTrafficColumns(ui, size.name)
      // A stored session is a fixed set; none of its requests is new.
      let latestHidden = try await ui.value("document.querySelector('#request-latest').hidden") as? Bool
      XCTAssertEqual(latestHidden, true, "\(size.name): a stored session must not claim new requests")
      try await assertLayout(ui, ".sidebar", "\(size.name) sidebar")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) traffic list")
      try await ui.screenshot("traffic-list-\(size.name)")

      let scroll = try await ui.json("__rebUiProbe.scrollToEnd('#screen-traffic .request-row', '.request-row')")
      XCTAssertEqual(scroll["scrollable"] as? Bool, true, "\(size.name): request list must scroll: \(scroll)")
      XCTAssertEqual(scroll["moved"] as? Bool, true, "\(size.name): request list scroll position must change")
      try await ui.waitUntil("""
        (() => { const last = [...document.querySelectorAll('#screen-traffic .request-row')].at(-1);
          const list = document.querySelector('#request-rows').getBoundingClientRect(), rect = last?.getBoundingClientRect();
          return Boolean(last) && last.getAttribute('aria-posinset') === last.getAttribute('aria-setsize') &&
            rect.height > 0 && rect.top >= list.top - 1 && rect.bottom <= list.bottom + 1; })()
        """, "\(size.name): the last request did not mount at the end of the list")
      try await ui.screenshot("traffic-list-scrolled-\(size.name)")

      try await ui.click("#screen-traffic .request-row", containing: "inert.test")
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let rowText = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"], #screen-traffic .request-row.selected')?.innerText ?? ''") as? String ?? ""
      XCTAssertTrue(rowText.contains(expected.hostileUrlMarker), "\(size.name): hostile URL renders as literal text: \(rowText)")
      try await assertInert(ui, "\(size.name) traffic detail")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) traffic detail")
      try await ui.screenshot("traffic-detail-\(size.name)")

      // End and Home reach the ends of the whole list through unmounted rows; focus follows the selection.
      let ends: [(UInt16, String, String, String)] = [
        (119, "\u{F72B}", "document.activeElement.getAttribute('aria-setsize')", "End"), (115, "\u{F729}", "'1'", "Home")]
      for (code, character, position, name) in ends {
        try await ui.key(code, character, modifiers: [.function])
        try await ui.waitUntil("""
          document.activeElement?.classList.contains('request-row') && document.activeElement.getAttribute('aria-selected') === 'true' &&
            document.activeElement.getAttribute('aria-posinset') === \(position)
          """, "\(size.name): \(name) did not select and focus that end of the list")
      }
    }
  }

  @MainActor
  func test2SourcesRetainedArtifact() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      // Native guest artifacts are an adapter JSON recipe and a bytecode buffer, not JavaScript.
      for (artifact, icon, kind) in [("108", "AD", "guest adapter JSON"), ("109", "BC", "guest bytecode")] {
        let find = "document.querySelector('#source-tree [role=treeitem][data-artifact-id=\"\(artifact)\"]')"
        let shown = try await ui.value("\(find)?.querySelector('.source-file-icon')?.innerText ?? ''") as? String ?? ""
        XCTAssertEqual(shown, icon, "\(size.name): artifact \(artifact) is labeled \(icon), not JS")
        let label = try await ui.value("\(find)?.getAttribute('aria-label') ?? ''") as? String ?? ""
        XCTAssertTrue(label.contains(kind), "\(size.name): artifact \(artifact) names its kind: \(label)")
      }
      // The retained request body, header blocks and cookie lists (artifacts 320 to 324) are Traffic evidence, never source files.
      let tree = try await ui.value("document.querySelector('#source-tree')?.textContent ?? ''") as? String ?? ""
      XCTAssertFalse(tree.contains(expected.requestBodyHost), "\(size.name): Sources lists no request body origin: \(tree)")
      let rows = try await ui.json("""
        (() => { const row = document.querySelector('#source-tree [data-artifact-id="303"]');
          return {name: row?.querySelector('.source-tree-raw')?.textContent ?? 'missing', meta: row?.querySelector('.source-tree-meta')?.textContent ?? '',
            groups: [...document.querySelectorAll('#source-tree [data-source-tree-kind="group"] .source-tree-raw')].map(node => node.textContent),
            body: Boolean(document.querySelector('#source-tree [data-artifact-id="320"]'))}; })()
        """)
      XCTAssertEqual(rows["body"] as? Bool, false, "\(size.name): Sources lists no request body file")
      XCTAssertFalse((rows["name"] as? String ?? "artifact").contains("artifact"), "\(size.name): file rows show plain names: \(rows)")
      XCTAssertEqual(rows["meta"] as? String, "303", "\(size.name): the artifact ID is the muted meta column: \(rows)")
      let groups = rows["groups"] as? [String] ?? []
      XCTAssertTrue(groups.contains("Dynamic (eval / new Function)") && groups.contains("WebAssembly"), "\(size.name): eval and Wasm sources have their own groups: \(groups)")
      // The keyboard reaches the whole tree: End, Home and type-ahead, with visible focus.
      let rowIndex = "Number(document.activeElement?.style.getPropertyValue('--source-row') ?? -1)"
      _ = try await ui.value("document.querySelector('#source-tree [role=treeitem][tabindex=\"0\"]').focus({focusVisible:true})")
      try await ui.key(119, "\u{F72B}", modifiers: [.function])
      let last = try await ui.value("\(rowIndex) === document.querySelector('#source-tree .source-tree-canvas').offsetHeight / 24 - 1") as? Bool
      XCTAssertEqual(last, true, "\(size.name): End reaches the last tree row")
      let endFocus = try await ui.json("__rebUiProbe.focusState()")
      XCTAssertEqual(endFocus["focusVisible"] as? Bool, true, "\(size.name): the focused tree row shows keyboard focus: \(endFocus)")
      XCTAssertEqual(endFocus["inViewport"] as? Bool, true, "\(size.name): End scrolls the last row into view: \(endFocus)")
      try await ui.key(115, "\u{F729}", modifiers: [.function])
      let home = try await ui.value("\(rowIndex)") as? Int
      XCTAssertEqual(home, 0, "\(size.name): Home reaches the first tree row")
      // PageDown moves focus, so the focused row never stays behind out of view.
      try await ui.key(121, "\u{F72D}", modifiers: [.function])
      let paged = try await ui.value("\(rowIndex)") as? Int ?? 0
      XCTAssertGreaterThan(paged, 0, "\(size.name): PageDown moves focus down the tree")
      let pageFocus = try await ui.json("__rebUiProbe.focusState()")
      XCTAssertEqual(pageFocus["inViewport"] as? Bool, true, "\(size.name): PageDown keeps the focused row in view: \(pageFocus)")
      try await ui.key(115, "\u{F729}", modifiers: [.function])
      try await ui.type("w")
      let typed = try await ui.value("document.activeElement?.querySelector('.source-tree-raw')?.textContent ?? ''") as? String ?? ""
      XCTAssertTrue(typed.lowercased().hasPrefix("w"), "\(size.name): type-ahead moves to a row starting with w: \(typed)")
      // The filter keeps matching files and their folders; Escape restores the tree.
      try await ui.click("#source-tree-filter")
      try await ui.type("glue")
      let filtered = try await ui.json("""
        ({files: [...document.querySelectorAll('#source-tree [data-artifact-id]')].map(row => row.dataset.artifactId),
          origin: [...document.querySelectorAll('#source-tree [data-source-tree-kind="origin"] .source-tree-raw')].map(node => node.textContent)})
        """)
      XCTAssertEqual(filtered["files"] as? [String], [expected.invocationArtifactId], "\(size.name): the filter keeps only matching files: \(filtered)")
      XCTAssertEqual(filtered["origin"] as? [String], ["hcaptcha.test"], "\(size.name): a match keeps its origin: \(filtered)")
      try await assertLayout(ui, "#screen-sources", "\(size.name) sources filter")
      try await ui.screenshot("sources-tree-filter-\(size.name)")
      try await ui.key(53, "\u{1B}")
      let cleared = try await ui.value("document.querySelector('#source-tree-filter').value === '' && document.querySelectorAll('#source-tree [data-artifact-id]').length > 1") as? Bool
      XCTAssertEqual(cleared, true, "\(size.name): Escape clears the filter and restores the tree")
      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"303\"]")
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
      try await assertCompleteCompactFindings(ui, size.name)
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

      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 311")
      let emptyInspector = try await ui.json("""
        (() => { const panel = document.querySelector('.vm-selection-inspector');
          const text = document.createRange(); text.selectNodeContents(panel.querySelector('.vm-selection-empty'));
          return {inset: text.getBoundingClientRect().left - panel.getBoundingClientRect().left - parseFloat(getComputedStyle(panel).borderLeftWidth)}; })()
        """)
      XCTAssertEqual(emptyInspector["inset"] as? Double ?? -1, 10, accuracy: 1,
        "\(size.name): empty selected-handler text keeps the inspector's content inset")
      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='dispatch']")
      try await ui.waitUntil("document.querySelector(\"\(dispatch)\").innerText.includes('parse-failed')", "parse failure omission did not render")
      let omitted = try await ui.value("document.querySelector(\"\(dispatch)\").innerText") as? String ?? ""
      XCTAssertTrue(omitted.contains("1 record omitted."), "\(size.name): parse failure remains counted: \(omitted)")
      try await assertInert(ui, "\(size.name) vm parse failure")
      try await ui.revealVmHeading(dispatch, "Dispatch structure")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm parse failure")
      try await ui.screenshot("vm-parse-failed-\(size.name)")

      // Observed claims sit beside the static handlers. The owned two-level
      // interpreter keeps one contradiction and one inner interpreter.
      try await setVmAnalysisExpanded(ui, true)
      try await ui.click("#vm-list .vm-row", containing: "artifact 401")
      try await setVmAnalysisExpanded(ui, false)
      try await ui.click("[data-vm-panel='runtime']")
      let runtime = "[data-vm-panel-content='runtime']"
      try await ui.waitUntil("!document.querySelector(\"\(runtime)\")?.hidden", "runtime claims panel did not open")
      let claims = try await ui.value("document.querySelector(\"\(runtime)\").innerText") as? String ?? ""
      XCTAssertTrue(claims.contains("of 5 observed claims"), "\(size.name): every observed claim is listed: \(claims)")
      XCTAssertTrue(claims.contains("Driven by outer f1"), "\(size.name): the nested guest names its outer site: \(claims)")
      let contradiction = "\(runtime) details[data-static-claim='disagrees']"
      try await ui.click("\(contradiction) summary")
      let opened = try await ui.value("document.querySelector(\"\(contradiction)\").open") as? Bool
      XCTAssertEqual(opened, true, "\(size.name): native input expands the contradicting claim")
      let comparison = try await ui.value("document.querySelector(\"\(contradiction) .vm-observed-static\").textContent") as? String ?? ""
      XCTAssertTrue(comparison.contains("labeled opcode 2, but guest opcode 6 ran here"), "\(size.name): disagreement is explicit: \(comparison)")
      try await assertInert(ui, "\(size.name) vm runtime claims")
      try await ui.revealVmHeading(runtime, "Observed dispatch claims")
      try await assertLayout(ui, "#screen-vm", "\(size.name) vm runtime claims")
      try await assertVmDock(ui, size.name)
      let runtimeInset = try await ui.vmCardInsetOffenders(runtime)
      XCTAssertEqual(runtimeInset, [], "\(size.name) vm runtime claims: card content shares the 12px inset")
      try await ui.screenshot("vm-runtime-claims-\(size.name)")
      try await revealAndAssertFullyVisible(ui, "\(contradiction) .vm-observed-static", "\(size.name) contradiction")
      try await ui.screenshot("vm-runtime-contradiction-\(size.name)")
      try await ui.revealVmHeading(runtime, "Nested guests")
      try await revealAndAssertFullyVisible(ui, "\(runtime) [data-vm-paged-rows='nested guests'] summary", "\(size.name) nested guest")
      try await ui.screenshot("vm-nested-guest-\(size.name)")
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
          const text = document.createRange(); text.selectNodeContents(panel.querySelector('.vm-workspace-empty'));
          return {emptyTop: parseFloat(empty.paddingTop), emptyBottom: parseFloat(empty.paddingBottom),
            textInset: text.getBoundingClientRect().left - panel.getBoundingClientRect().left,
            paragraphTop: parseFloat(paragraph.paddingTop), paragraphBottom: parseFloat(paragraph.paddingBottom)}; })()
        """)
      XCTAssertEqual(spacing["emptyTop"] as? Double, spacing["paragraphTop"] as? Double,
        "\(size.name): empty paragraphs use the panel's paragraph spacing")
      XCTAssertEqual(spacing["emptyBottom"] as? Double, spacing["paragraphBottom"] as? Double,
        "\(size.name): empty paragraphs do not add a second vertical inset")
      XCTAssertEqual(spacing["textInset"] as? Double ?? -1, 12, accuracy: 1,
        "\(size.name): empty paragraph text shares the card's 12px content edge")
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
      try await assertCompleteCompactFindings(ui, size.name)
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
  func test13WorkerFailureDetailsAndRetry() async throws {
    let environment = ProcessInfo.processInfo.environment
    let endpoint = try Harness.required(environment, "REB_RENDERED_UI_FAILURE_URL")
    let binary = try Harness.required(environment, "REB_RENDERED_UI_FAILURE_BINARY")
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    let originalURL = ui.webView.url!
    try await ui.activate()
    defer {
      try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary)
      ui.webView.load(URLRequest(url: originalURL))
    }
    for size in windowSizes {
      try await ui.resize(width: size.width, height: size.height)
      ui.webView.load(URLRequest(url: URL(string: endpoint)!))
      try await ui.waitForInitialLoad()
      try await show(ui, "vm")
      try await ui.waitUntil("document.querySelector('#vm-notice').textContent.includes('analysis-worker-failed: spawn')", "Worker failure detail did not render")
      let notice = try await ui.value("document.querySelector('#vm-notice').textContent") as? String ?? ""
      XCTAssertTrue(notice.contains("1 omitted artifacts"), notice)
      XCTAssertTrue(notice.contains("retry the request"), notice)
      try await assertInert(ui, "\(size.name) worker failure")
      try await assertLayout(ui, "#screen-vm", "\(size.name) worker failure")
      try await ui.screenshot("vm-worker-failure-\(size.name)")
    }
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary)
    try await ui.reload(requireRequests: false)
    try await show(ui, "vm")
    try await ui.waitUntil("document.querySelectorAll('#vm-list .vm-row').length > 0", "Unchanged-input retry did not recover")
    let notice = try await ui.value("document.querySelector('#vm-notice').hidden") as? Bool ?? false
    XCTAssertTrue(notice, "Recovered analysis clears the failure banner")
    try await ui.screenshot("vm-worker-recovered")
  }

  // A live Wasm page exhausted two 16-observation budgets. Those named vm gaps
  // are sampling limits: the footer counts no queue drops, Traffic and
  // Fingerprinting keep their coverage, and VM Lab names both reasons as text.
  @MainActor
  func test14NamedBudgetGapsStayInVmScope() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      let footer = try await ui.value("document.querySelector('#gap-status').textContent") as? String ?? ""
      XCTAssertTrue(footer.contains("· \(expected.namedGapReasons.count) sampling budgets reached (vm)"), "\(size.name): footer names the vm budgets: \(footer)")
      XCTAssertFalse(footer.contains("queue drop"), "\(size.name): budgets are not queue drops: \(footer)")
      let traffic = try await ui.value("(notice => notice.hidden ? '' : notice.textContent)(document.querySelector('#network-notice'))") as? String ?? ""
      XCTAssertFalse(traffic.contains("dropped"), "\(size.name): Traffic reports no queue loss: \(traffic)")
      XCTAssertFalse(traffic.contains("native_"), "\(size.name): vm reasons stay out of Traffic: \(traffic)")

      try await show(ui, "signals")
      let signal = try await ui.json("({kind: document.querySelector('#signal-notice').dataset.kind, text: document.querySelector('#signal-notice').textContent})")
      XCTAssertNotEqual(signal["kind"] as? String, "partial", "\(size.name): a vm budget leaves fingerprint coverage complete: \(signal)")
      XCTAssertFalse((signal["text"] as? String ?? "").contains("queue drop"), "\(size.name): \(signal)")

      try await show(ui, "vm")
      try await ui.waitUntil("!document.querySelector('#vm-notice').hidden", "VM capture limits did not render")
      let vm = try await ui.json("({kind: document.querySelector('#vm-notice').dataset.kind, text: document.querySelector('#vm-notice').textContent})")
      let text = vm["text"] as? String ?? ""
      XCTAssertEqual(vm["kind"] as? String, "gap", "\(size.name): budgets mark VM coverage incomplete: \(vm)")
      XCTAssertTrue(text.contains("Sampling budget reached"), "\(size.name): \(text)")
      XCTAssertFalse(text.contains("queue"), "\(size.name): \(text)")
      for reason in expected.namedGapReasons {
        XCTAssertTrue(text.contains(reason), "\(size.name): VM Lab names \(reason): \(text)")
      }
      try await assertFullyVisible(ui, "#vm-notice", "\(size.name) VM capture limits")
      try await assertInert(ui, "\(size.name) VM capture limits")
      try await assertLayout(ui, "#screen-vm", "\(size.name) VM capture limits")
      try await ui.screenshot("vm-capture-limits-\(size.name)")
    }
  }

  // The dock follows the selection, lists recorded links only and is keyboard
  // reachable. Long values stay inert text and truncate with an ellipsis.
  @MainActor
  func test24CrossReferencesDock() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: "adjacent.trace.test")
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      try await ui.key(7, "x")
      try await ui.waitUntil("document.querySelector('#xrefs-counts').textContent.includes(' in')", "cross-references did not load")
      let loaded = try await ui.json("""
        ({counts: document.querySelector('#xrefs-counts').textContent, active: document.activeElement.id,
          open: document.querySelector('#workspace').dataset.xrefsOpen ?? '',
          rows: [...document.querySelectorAll('#xrefs-rows .xrefs-row')].map(row => row.innerText),
          selected: document.querySelector('#xrefs-rows .xrefs-row[aria-selected="true"]')?.innerText ?? ''})
        """)
      XCTAssertEqual(loaded["open"] as? String, "true", "\(size.name): X opens the dock")
      XCTAssertEqual(loaded["active"] as? String, "xrefs-rows", "\(size.name): X moves focus to the list")
      XCTAssertEqual(loaded["counts"] as? String, "1 in · 2 out", "\(size.name): the request's recorded links: \(loaded)")
      let firstRows = loaded["rows"] as? [String] ?? []
      XCTAssertTrue(firstRows.first?.contains("initiator") == true, "\(size.name): the renderer initiator is listed: \(firstRows)")
      try await assertLayout(ui, "#xrefs-dock", "\(size.name) dock")
      // The toggle lives in the title bar so the sidebar rail fits the minimum window.
      try await assertLayout(ui, ".titlebar", "\(size.name) title bar")
      try await assertLayout(ui, ".sidebar", "\(size.name) sidebar beside the dock")
      try await assertInert(ui, "\(size.name) dock")
      try await ui.screenshot("xrefs-dock-\(size.name)")

      try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad])
      try await ui.waitUntil("document.querySelector('#xrefs-rows .xrefs-row[aria-selected=\"true\"]')?.innerText.includes('lifecycle')", "ArrowDown did not reach the next row")
      let identity = try await ui.value("document.querySelector('#xrefs-detail code').textContent") as? String ?? ""
      XCTAssertTrue(identity.contains("session") && identity.contains("seq"), "\(size.name): correlation identifiers stay reachable: \(identity)")

      try await ui.key(44, "/")
      try await ui.waitUntil("document.activeElement.id === 'xrefs-filter'", "/ did not focus the filter")
      try await ui.screenshot("xrefs-filter-\(size.name)")
      try await ui.key(53, "\u{1B}")
      try await ui.waitUntil("document.activeElement.id === 'xrefs-rows'", "Escape did not return to the list")

      try await ui.click("#theme-toggle")
      try await ui.waitUntil("document.documentElement.dataset.theme === 'light'", "light theme did not apply")
      try await assertLayout(ui, "#xrefs-dock", "\(size.name) dock light")
      try await ui.screenshot("xrefs-dock-light-\(size.name)")
      try await ui.click("#theme-toggle")

      try await ui.click("#screen-traffic .request-row", containing: "scroll.test")
      try await ui.waitUntil("document.querySelector('#xrefs-target').textContent.includes('scroll.test')", "the dock did not follow the selection")

      try await ui.click("#xrefs-close")
      try await ui.waitUntil("document.querySelector('#xrefs-dock').hidden && !document.querySelector('#workspace').dataset.xrefsOpen", "the dock did not close")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) traffic after dock")
    }
  }

  @MainActor
  func test5KeyboardFocusOrder() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      // Start from the first sidebar entry so the order is deterministic.
      try await ui.click(".primary-nav .nav-button[data-screen='traffic']")
      var stops: [[String: Any]] = []
      for _ in 0..<30 {
        try await ui.tab()
        stops.append(try await ui.json("__rebUiProbe.focusState()"))
      }
      let names = stops.map { $0["element"] as? String ?? "?" }
      print("RENDERED_UI_FOCUS \(size.name) \(names)")
      XCTAssertTrue(names.first?.contains("Sources") == true, "\(size.name): Tab follows the sidebar order: \(names.prefix(6))")
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
      if screen == "sources" {
        // The debugger sidebar is open so its sections are read too.
        try await ui.click("#source-debugger-toggle")
        try await ui.waitUntil("Boolean(document.querySelector('#debugger-sidebar [data-debugger-native=\"availability\"]'))", "the debugger sidebar did not read its state")
      }
      // The pausing words have a native meaning only inside the debugger
      // sidebar: the statement of the availability get_native_debugger
      // reports, read here and compared, and sections registered as native
      // pausing ones. Inside those two markers only the paused-state words are
      // left out of the text; every other removed phrase still fails there, and
      // a marker anywhere else is a failure. While the backend reports the
      // debugger unsupported or the sidebar's last read is not ready, every
      // control in a native pausing section is a really disabled form control.
      let read = try await ui.json("""
        (async () => {
          const root = document.querySelector('#screen-\(screen)');
          const exempt = '#debugger-sidebar [data-debugger-native="availability"], #debugger-sidebar [data-debugger-native="pausing"]';
          const statement = root.querySelector('#debugger-sidebar [data-debugger-native="availability"]');
          const allowed = new Set(document.querySelectorAll(exempt));
          const stray = [...document.querySelectorAll('[data-debugger-native]')].filter(node => !allowed.has(node)).map(node => node.outerHTML.slice(0, 80));
          const native = [...root.querySelectorAll(exempt)];
          const pausedFree = text => text.replace(/breakpoint|paused frame|call stack|step over|step into|resume/gi, ' ');
          const nativeText = native.map(node => pausedFree(node.innerText)).join(' ');
          native.forEach(node => { node.hidden = true; });
          const text = `${root.innerText} ${nativeText}`;
          native.forEach(node => { node.hidden = false; });
          const reported = statement ? (await (await fetch('/api/native-debugger', {cache: 'no-store'})).json()).availability : null;
          const controls = 'button, input, select, textarea, a[href], summary, [tabindex], [role="button"], [role="option"], [role="checkbox"], [role="tab"], [contenteditable]:not([contenteditable="false"])';
          const disabled = control => ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'].includes(control.tagName) && control.matches(':disabled');
          const enabled = [...root.querySelectorAll('#debugger-sidebar .debugger-section[data-debugger-native="pausing"] > .debugger-section-body')]
            .flatMap(body => [...body.querySelectorAll(controls)]).filter(control => !disabled(control)).map(control => control.innerText || control.tagName);
          const ready = document.querySelector('#debugger-sidebar')?.dataset.state === 'ready';
          return {text, stray, statement: statement?.dataset.availability ?? null, reported, enabled, ready,
            controls: statement ? statement.querySelectorAll('button, input, select, textarea, a, summary, [tabindex]').length : 0};
        })()
        """)
      XCTAssertEqual(read["stray"] as? [String], [], "\(screen): native debugger markers appear only inside the sidebar, with a known value")
      let text = read["text"] as? String ?? ""
      for phrase in removedFeaturePhrases {
        XCTAssertFalse(text.contains(phrase), "\(screen) still offers removed CDP feature text: \(phrase)")
      }
      if screen == "sources" {
        XCTAssertEqual(read["statement"] as? String, read["reported"] as? String, "the pausing state is the reported availability: \(read)")
        XCTAssertEqual(read["controls"] as? Int, 0, "the pausing state offers no control")
        if read["reported"] as? String != "available" || read["ready"] as? Bool != true {
          XCTAssertEqual(read["enabled"] as? [String], [], "no pausing control is enabled while the debugger is unsupported or unread")
        }
        // Docked, the sidebar narrows the editor and Debugger may move into More.
        try await ui.click("#debugger-sidebar .debugger-sidebar-close")
      }
    }
    for id in ["websocket-inspector", "runtime-hook-traffic", "request-memory-pivot", "screen-memory", "screen-experiments",
      "open-api-catalog", "api-catalog", "passive-security", "traffic-capture-export", "request-search-scope",
      "inspector-tab-compare", "traffic-comparison",
      "screen-field-provenance", "decoder-field-origin"] {
      let count = try await ui.value("document.querySelectorAll('#\(id)').length") as? Int ?? -1
      XCTAssertEqual(count, 0, "#\(id) must be removed, not hidden")
    }
  }

  // The Sources debugger sidebar (#434 phase 1) on the fixture's observation
  // records: sections from get_native_debugger, rows mounted by view, inert
  // captured names, an observed frame scoping the Sources tree, a listener
  // opening its site in Sources, keyboard focus, and both themes.
  @MainActor
  func test31DebuggerSidebar() async throws {
    let expected = try Expectations.load()
    let frameKey = ":\(expected.debuggerProcess):\(expected.debuggerFrame)"
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      try await ui.click("#source-debugger-toggle")
      try await ui.waitUntil("document.querySelectorAll('#debugger-observations .debugger-list-row').length > 0 && document.querySelectorAll('#debugger-threads .debugger-list-row').length > 0",
        "\(size.name): the debugger sidebar did not list threads and observations")
      let opened = try await ui.json("""
        ({sections: [...document.querySelectorAll('#debugger-sidebar .debugger-section')].map(node => node.dataset.debuggerSection),
          focus: document.activeElement?.closest('summary') ? document.activeElement.closest('.debugger-section').dataset.debuggerSection : document.activeElement?.id,
          rows: document.querySelectorAll('#debugger-observations .debugger-list-row').length,
          size: Number(document.querySelector('#debugger-observations .debugger-list-row').getAttribute('aria-setsize')),
          view: Math.ceil(document.querySelector('#debugger-observations').clientHeight / 44),
          threads: [...document.querySelectorAll('#debugger-threads .debugger-list-group')].map(node => node.innerText.replace(/\\s+/g, ' ')),
          pausing: document.querySelector('#debugger-sidebar [data-debugger-native="availability"]')?.dataset.availability ?? null,
          buttons: [...document.querySelectorAll('#debugger-sidebar button')].filter(button => !button.closest('#debugger-sidebar [data-debugger-native="pausing"]'))
            .map(button => button.innerText).filter(text => /pause|resume|step|breakpoint/i.test(text)),
          details: document.querySelector('#source-sidebar').hidden})
        """)
      print("RENDERED_UI_DEBUGGER \(size.name) \(opened)")
      XCTAssertEqual(Array((opened["sections"] as? [String] ?? []).prefix(4)), ["threads", "watch-rules", "observations", "pausing"],
        "\(size.name): the phase 1 sections come first: \(opened)")
      XCTAssertEqual(opened["focus"] as? String, "threads", "\(size.name): opening focuses the first section")
      XCTAssertGreaterThanOrEqual(opened["size"] as? Int ?? 0, 100, "\(size.name): the newest page is listed: \(opened)")
      XCTAssertLessThanOrEqual(opened["rows"] as? Int ?? .max, (opened["view"] as? Int ?? 0) + 13, "\(size.name): only rows near the view mount: \(opened)")
      XCTAssertEqual(opened["pausing"] as? String, "unsupported", "\(size.name): pausing states the reported availability")
      XCTAssertEqual(opened["buttons"] as? [String], [], "\(size.name): no pausing control outside a native pausing section")
      XCTAssertEqual(opened["details"] as? Bool, true, "\(size.name): Details and the debugger share one column")
      XCTAssertTrue((opened["threads"] as? [String] ?? []).contains { $0.hasPrefix("Workers") }, "\(size.name): recorded workers are threads: \(opened)")
      try await assertInert(ui, "\(size.name) debugger sidebar")
      try await assertLayout(ui, "#debugger-sidebar", "\(size.name) debugger sidebar")
      try await ui.screenshot("debugger-sidebar-\(size.name)")

      // Keyboard: the next stop is the Threads list, with a visible indicator.
      try await ui.tab()
      let stop = try await ui.json("__rebUiProbe.focusState()")
      XCTAssertEqual(stop["id"] as? String, "debugger-threads", "\(size.name): Tab reaches the Threads list: \(stop)")
      XCTAssertEqual(stop["focusVisible"] as? Bool, true, "\(size.name): \(stop)")
      XCTAssertNotEqual(stop["indicator"] as? String, "none", "\(size.name): the list shows its focus")

      // An observed frame scopes Observations and the Sources tree exactly.
      try await ui.click("#debugger-threads .debugger-list-row[data-key$='\(frameKey)']")
      try await ui.waitUntil("""
        (document.querySelector('#source-tree')?.innerText ?? '').includes('selected in Debugger Threads') &&
          [...document.querySelectorAll('#debugger-observations .debugger-list-row')].every(row => row.innerText.includes(' F\(expected.debuggerFrame) '))
        """, "\(size.name): the observed frame did not scope the tree and the observations")
      let scoped = try await ui.json("""
        ({files: [...document.querySelectorAll('#source-tree [role=treeitem][data-artifact-id]')].map(row => row.dataset.artifactId),
          selected: document.querySelector('#debugger-threads .debugger-list-row[aria-selected="true"]')?.dataset.key ?? ''})
        """)
      XCTAssertTrue((scoped["files"] as? [String] ?? []).contains(expected.debuggerArtifactId), "\(size.name): the frame's script is listed: \(scoped)")
      // The scope notice above listed rows is a disclosure, without the empty state's band above it.
      let notice = try await ui.json("""
        (() => { const node = document.querySelector('#source-tree .source-tree-empty');
          return {padding: node ? parseFloat(getComputedStyle(node).paddingTop) : -1,
            gap: node ? node.getBoundingClientRect().top - document.querySelector('#source-tree').getBoundingClientRect().top : -1}; })()
        """)
      XCTAssertLessThanOrEqual(notice["padding"] as? Double ?? 99, 8, "\(size.name): the scope notice has disclosure padding: \(notice)")
      XCTAssertLessThanOrEqual(notice["gap"] as? Double ?? 99, 8, "\(size.name): no blank band above the scope notice: \(notice)")
      XCTAssertTrue((scoped["selected"] as? String ?? "").hasSuffix(frameKey), "\(size.name): \(scoped)")
      // Below 1,112 px the sidebar overlays the editor by design, so the
      // navigator and the sidebar are checked, not the covered editor.
      try await assertLayout(ui, ".sources-navigator", "\(size.name) debugger scoped tree")
      try await assertLayout(ui, "#debugger-sidebar", "\(size.name) debugger scoped")
      try await ui.screenshot("debugger-sidebar-scoped-\(size.name)")

      // A listener record opens its own resolved frame in Sources.
      try await ui.click(".debugger-kind[data-kind='listener_dispatch']")
      try await ui.waitUntil("[...document.querySelectorAll('#debugger-observations .debugger-list-row')].every(row => row.dataset.kind === 'listener_dispatch')",
        "\(size.name): the Listeners filter did not apply")
      try await ui.click("#debugger-observations .debugger-list-row", containing: "click listener")
      // The chosen row is marked at once, not at the next read.
      let marked = try await ui.json("""
        ({selected: [...document.querySelectorAll('#debugger-observations .debugger-list-row[aria-selected="true"]')].map(row => row.innerText)})
        """)
      XCTAssertEqual((marked["selected"] as? [String] ?? []).count, 1, "\(size.name): the chosen row is marked at once: \(marked)")
      XCTAssertTrue((marked["selected"] as? [String] ?? []).first?.contains("click listener") == true, "\(size.name): \(marked)")
      try await ui.waitUntil("(document.querySelector('.debugger-open-source')?.innerText ?? '').includes('onTap @ handlers.js:2:71')",
        "\(size.name): the listener's site did not resolve")
      // Once resolved, the action row is brought into view: the button sits wholly inside the pane.
      try await ui.waitUntil("""
        (() => { const button = document.querySelector('.debugger-open-source').getBoundingClientRect();
          const pane = document.querySelector('#debugger-sidebar .debugger-sidebar-sections').getBoundingClientRect();
          return button.top >= pane.top - 0.5 && button.bottom <= pane.bottom + 0.5; })()
        """, timeout: 3, "\(size.name): the Open button is not wholly inside the sidebar pane")
      try await assertLayout(ui, "#debugger-sidebar", "\(size.name) debugger record")
      try await ui.screenshot("debugger-sidebar-record-\(size.name)")
      try await lightScreenshot(ui, "debugger-sidebar-record", size.name)
      try await ui.click(".debugger-open-source")
      try await ui.waitUntil("(document.querySelector('#source-position')?.textContent ?? '').includes('line 2, Column 71')",
        "\(size.name): Sources did not open at the listener")

      try await ui.click("#theme-toggle")
      try await ui.waitUntil("document.documentElement.dataset.theme === 'light'", "light theme did not apply")
      if try await ui.value("document.querySelector('#debugger-sidebar').hidden") as? Bool == true {
        try await ui.click("#source-debugger-toggle")
      }
      try await ui.waitUntil("document.querySelectorAll('#debugger-observations .debugger-list-row').length > 0", "\(size.name): the light sidebar did not list records")
      try await assertLayout(ui, "#debugger-sidebar", "\(size.name) debugger light")
      try await ui.screenshot("debugger-sidebar-light-\(size.name)")
      try await ui.click("#theme-toggle")

      // Keyboard in Observations: an arrow moves the active row and brings
      // its details into view.
      try await ui.click(".debugger-kind[data-kind='all']")
      try await ui.waitUntil("[...document.querySelectorAll('#debugger-observations .debugger-list-row')].some(row => row.dataset.kind !== 'listener_dispatch')",
        "\(size.name): the All filter did not apply")
      try await ui.click("#debugger-observations .debugger-list-row")
      try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad])
      try await ui.waitUntil("""
        (() => { const list = document.querySelector('#debugger-observations'), rows = [...list.querySelectorAll('.debugger-list-row')];
          const active = list.querySelector('.debugger-list-row[data-active="true"]'), detail = document.querySelector('.debugger-detail');
          if (document.activeElement !== list || !active || rows.indexOf(active) !== 1 || !detail || detail.hidden) return false;
          const marked = list.querySelectorAll('.debugger-list-row[aria-selected="true"]');
          if (marked.length !== 1 || marked[0] !== active) return false;
          const box = detail.getBoundingClientRect(), view = document.querySelector('.debugger-sidebar-sections').getBoundingClientRect();
          return detail.innerText.includes(`sequence ${active.dataset.key.split(':').at(-1)}`) && box.top < view.bottom - 24 && box.bottom > view.top; })()
        """, "\(size.name): the arrow did not move to the next record with its details in view")

      // A watched request opens its own Traffic row on the Initiator tab, by
      // the detail's link and by Enter, through Traffic's row selection.
      let watched = """
        !document.querySelector('#screen-traffic').hidden && (state.selectedRequestId ?? '').endsWith(':R\(expected.debuggerProcess):5100') &&
          document.querySelector('#screen-traffic .inspector-tab[aria-selected="true"]')?.dataset.inspectorTab === 'initiator'
        """
      for how in ["link", "Enter"] {
        try await ui.click(".debugger-kind[data-kind='request_watch_match']")
        try await ui.waitUntil("(() => { const rows = [...document.querySelectorAll('#debugger-observations .debugger-list-row')]; return rows.length === 1 && rows[0].dataset.kind === 'request_watch_match'; })()",
          "\(size.name): the Requests filter did not apply")
        try await ui.click("#debugger-observations .debugger-list-row")
        if how == "link" {
          try await ui.waitUntil("Boolean(document.querySelector('.debugger-open-request'))", "\(size.name): the watched request offers its Traffic row")
          try await ui.click(".debugger-open-request")
        } else {
          try await ui.key(36, "\r")
        }
        try await ui.waitUntil(watched, "\(size.name): \(how) did not open the watched request in Traffic")
        if how == "link" {
          try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) watched request")
          try await ui.screenshot("debugger-watched-request-\(size.name)")
        }
        try await show(ui, "sources")
        if try await ui.value("document.querySelector('#debugger-sidebar').hidden") as? Bool == true {
          try await ui.click("#source-debugger-toggle")
        }
        try await ui.waitUntil("document.querySelectorAll('#debugger-observations .debugger-list-row').length > 0", "\(size.name): the sidebar did not list records again")
      }
      try await ui.click(".debugger-kind[data-kind='all']")

      // A failed read and a malformed answer keep the last rows, marked stale;
      // the next good read clears it.
      for (body, status) in [("Promise.reject(new TypeError('Load failed'))", "Disconnected: Load failed"),
                             ("Promise.resolve(new Response('{\"contract_version\":2}', {status: 200}))", "The last answer was malformed (an unknown contract version)")] {
        _ = try await ui.value("""
          (() => { window.__rebDebuggerFetch ??= window.fetch;
            window.fetch = (input, init) => String(input).startsWith('/api/native-debugger') ? \(body) : window.__rebDebuggerFetch(input, init); return true; })()
          """)
        try await ui.waitUntil("""
          (document.querySelector('#debugger-sidebar .debugger-status-state')?.textContent ?? '').startsWith('\(status)') &&
            document.querySelector('#debugger-sidebar [data-debugger-section="observations"]').dataset.stale === 'true' &&
            document.querySelectorAll('#debugger-observations .debugger-list-row').length > 0
          """, "\(size.name): the sidebar did not keep stale rows after: \(status)")
        try await assertLayout(ui, "#debugger-sidebar", "\(size.name) debugger stale")
        let stale = "debugger-sidebar-stale-\(status.hasPrefix("Disconnected") ? "disconnected" : "malformed")"
        try await ui.screenshot("\(stale)-\(size.name)")
        try await lightScreenshot(ui, stale, size.name)
      }
      _ = try await ui.value("(() => { window.fetch = window.__rebDebuggerFetch; delete window.__rebDebuggerFetch; return true; })()")
      try await ui.waitUntil("""
        (document.querySelector('#debugger-sidebar .debugger-status-state')?.textContent ?? '').startsWith('Live:') &&
          document.querySelector('#debugger-sidebar [data-debugger-section="observations"]').dataset.stale === 'false'
        """, "\(size.name): a good read did not clear the stale state")

      // Escape returns to the toggle, or to More while the toggle sits in its
      // menu (a docked sidebar narrows the toolbar); closing stops every read.
      try await ui.click("#debugger-threads .debugger-list-row[data-key$='\(frameKey)']")
      try await ui.key(53, "\u{1B}")
      try await ui.waitUntil("""
        (() => { const toggle = document.querySelector('#source-debugger-toggle'), menu = toggle.closest('details');
          return document.activeElement === toggle || Boolean(menu) && document.activeElement === menu.querySelector('summary'); })()
        """, "\(size.name): Escape did not return to the toggle")
      if try await ui.value("document.querySelector('#debugger-sidebar').hidden") as? Bool == false {
        try await ui.click("#debugger-sidebar .debugger-sidebar-close")
      }
      let reads = "performance.getEntriesByType('resource').filter(entry => entry.name.includes('/api/native-debugger')).length"
      let before = try await ui.value(reads) as? Int ?? -1
      try await Task.sleep(nanoseconds: 4_500_000_000)
      let after = try await ui.value(reads) as? Int ?? -2
      XCTAssertEqual(after, before, "\(size.name): a closed sidebar must not read")
      let closed = try await ui.value("(document.querySelector('#source-tree')?.innerText ?? '').includes('selected in Debugger Threads')") as? Bool
      XCTAssertEqual(closed, false, "\(size.name): closing the sidebar lifts the tree scope")
    }
  }

  // Native rows carry header, cookie and response body records; guest bytecode
  // is binary. Traffic, Export and Sources offer only what that evidence supports.
  @MainActor
  func test7NativeOnlyTrafficExportAndBytecode() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: "item-3.scroll.test")
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let tabs = try await ui.value("[...document.querySelectorAll('#screen-traffic .inspector-tab')].map(tab => tab.innerText.trim()).join('|')") as? String ?? ""
      XCTAssertEqual(tabs, "General|Headers|Payload|Preview|Response|Cookies|Initiator|Timing|Signals|Evidence", "\(size.name): Traffic offers native header, payload, response and cookie tabs, no Compare tab")
      let search = try await ui.value("document.querySelectorAll('#request-search-scope, #request-search-status, #traffic-comparison').length") as? Int ?? -1
      XCTAssertEqual(search, 0, "\(size.name): content search and comparison are removed, not hidden")
      let general = try await ui.value("document.querySelector('#exchange-inspector').innerText") as? String ?? ""
      XCTAssertTrue(general.contains("Response bodies are on the Response tab."), "\(size.name): native coverage is explicit: \(general)")
      let panes = try await ui.value("document.querySelectorAll('#exchange-inspector .exchange-pane').length") as? Int ?? -1
      XCTAssertEqual(panes, 0, "\(size.name): no permanently empty request/response header panes")
      // A horizontal scrollbar takes height from the strip and covers the tabs.
      let strip = try await ui.json("(() => { const strip = document.querySelector('#screen-traffic .inspector-tabs'); return {client: strip.clientHeight, content: strip.querySelector('.inspector-tab').offsetHeight}; })()")
      XCTAssertGreaterThanOrEqual(strip["client"] as? Int ?? 0, strip["content"] as? Int ?? 1, "\(size.name): the inspector tabs are not clipped: \(strip)")
      let hiddenTabs = try await ui.value("(() => { const box = document.querySelector('#screen-traffic .inspector-tabs').getBoundingClientRect(); return [...document.querySelectorAll('#screen-traffic .inspector-tab')].filter(tab => { const rect = tab.getBoundingClientRect(); return rect.left < box.left || rect.right > box.right + 1 || rect.bottom > box.bottom + 1; }).map(tab => tab.innerText.trim()).join('|'); })()") as? String ?? "unknown"
      XCTAssertEqual(hiddenTabs, "", "\(size.name): every inspector tab is inside the strip")
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
      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"109\"]")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('00000000')", "golden guest bytecode did not render as hex")
      let golden = try await ui.value("document.querySelector('#source-code').innerText") as? String ?? ""
      XCTAssertTrue(golden.contains("00000000  00 42 00 00"), "\(size.name): real guest bytecode shows its bytes: \(golden)")
      XCTAssertTrue(golden.contains("|.B..|"), "\(size.name): printable column replaces control bytes")
      XCTAssertFalse(golden.contains("\u{0}"), "\(size.name): NUL bytes are never decoded as text")
      let language = try await ui.value("document.querySelector('#source-language').innerText") as? String
      XCTAssertEqual(language, "Guest bytecode hex", "\(size.name): bytecode is labeled as a hex view")

      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"310\"]")
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

  // protocol/native-network-v3.md: a service worker's install-time fetch sits in
  // the tab that registered it, marked as such, and requests no page caused are
  // named in the footer instead of listed.
  @MainActor
  func test28ServiceWorkerRegistrantAndNoPageCounts() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      _ = try await ui.value("""
        (() => { const filter = document.querySelector('#request-filter'); filter.value = '\(expected.registrantHost)';
          filter.dispatchEvent(new Event('input', {bubbles: true})); })()
        """)
      try await ui.reveal("#screen-traffic .request-row", containing: expected.registrantHost)
      let state = try await ui.json("""
        (() => { const row = [...document.querySelectorAll('#screen-traffic .request-row')]
            .find(node => node.innerText.includes('\(expected.registrantHost)'));
          return {marker: row?.querySelector('.request-tab-link')?.textContent ?? '',
            footer: document.querySelector('#request-window-status').textContent,
            unresolvedHidden: document.querySelector('#request-unresolved').hidden}; })()
        """)
      XCTAssertTrue((state["marker"] as? String ?? "").contains("Service worker · installed from 1 tab"),
                    "\(size.name): the registrant link is marked on its row: \(state)")
      XCTAssertTrue((state["footer"] as? String ?? "").contains("2 service worker requests no page caused not recorded"),
                    "\(size.name): the footer names the counted no-page requests: \(state)")
      XCTAssertEqual(state["unresolvedHidden"] as? Bool, true, "\(size.name): the linked row is no capture error")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) service worker registrant")
      try await ui.screenshot("traffic-registrant-\(size.name)")
    }
  }

  // A renderer record that no initiator edge reached reads as its own, weaker
  // class: after the gap it did not close, named as having no recorded link,
  // and reported beside coverage rather than inside it.
  // A content-session POST shows its query and retained JSON body on Payload as
  // a keyboard tree and as source; a metadata-only POST says why no bytes
  // exist. Markup in either never runs.
  @MainActor
  func test16RequestTargetAndBody() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.requestBodyHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let rowText = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"]')?.innerText ?? ''") as? String ?? ""
      // The row names the last path segment and the query; the tooltip has the full URL.
      let path = expected.requestBodyTarget.split(separator: "?", maxSplits: 1).first.map(String.init) ?? ""
      let shortName = (path.split(separator: "/").last.map(String.init) ?? "") + expected.requestBodyTarget.dropFirst(path.count)
      XCTAssertTrue(rowText.contains(shortName), "\(size.name): the row shows the captured last segment and query: \(rowText)")
      let nameTitle = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"] .request-name')?.title ?? ''") as? String ?? ""
      XCTAssertTrue(nameTitle.contains(expected.requestBodyTarget), "\(size.name): the name tooltip has the full URL: \(nameTitle)")
      try await ui.click("#inspector-tab-payload")
      try await ui.waitUntil("document.querySelector('#payload-inspector .traffic-payload-tree [role=\"treeitem\"]') !== null", "retained body did not load")
      let payload = try await ui.json("""
        ({tree: document.querySelector('#payload-inspector .traffic-payload-tree').innerText,
          query: document.querySelector('#payload-inspector [data-section="query"]').innerText,
          state: document.querySelector('#payload-inspector [data-section="payload"]').dataset.state,
          detailsOpen: document.querySelector('#payload-inspector .traffic-payload-details').open})
        """)
      XCTAssertEqual(payload["state"] as? String, "captured", "\(size.name): body record state")
      let tree = payload["tree"] as? String ?? ""
      let markup = expected.requestBodyMarker.components(separatedBy: "\"").first ?? expected.requestBodyMarker
      XCTAssertTrue(tree.contains("sitekey") && tree.contains(markup), "\(size.name): captured markup is literal text: \(tree)")
      let query = payload["query"] as? String ?? ""
      let marker = expected.requestBodyTarget.split(separator: "=", maxSplits: 1).last.map(String.init) ?? ""
      XCTAssertTrue(query.contains(marker), "\(size.name): the decoded query parameter is literal text: \(query)")
      XCTAssertEqual(payload["detailsOpen"] as? Bool, false, "\(size.name): Capture details starts collapsed")
      try await assertInert(ui, "\(size.name) request payload")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) request payload")
      try await ui.screenshot("traffic-payload-parsed-\(size.name)")

      // The tree is one Tab stop; arrow keys collapse, expand and move with a visible ring.
      _ = try await ui.value("document.querySelector('#payload-inspector .traffic-payload-tree [tabindex=\"0\"]').focus({focusVisible:true})")
      let expanded = "document.activeElement?.getAttribute('aria-expanded') ?? ''"
      try await ui.key(123, "\u{F702}", modifiers: [.function, .numericPad])
      let collapsed = try await ui.value(expanded) as? String
      XCTAssertEqual(collapsed, "false", "\(size.name): Left collapses the root")
      try await ui.key(124, "\u{F703}", modifiers: [.function, .numericPad])
      let reopened = try await ui.value(expanded) as? String
      XCTAssertEqual(reopened, "true", "\(size.name): Right expands the root")
      try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad])
      let focus = try await ui.json("__rebUiProbe.focusState()")
      let selected = try await ui.value("document.activeElement?.getAttribute('aria-selected') ?? ''") as? String
      XCTAssertEqual(selected, "true", "\(size.name): Down selects the next row: \(focus)")
      XCTAssertTrue((focus["element"] as? String ?? "").contains("sitekey"), "\(size.name): Down moves to the first key: \(focus)")
      XCTAssertEqual(focus["focusVisible"] as? Bool, true, "\(size.name): the tree row shows keyboard focus: \(focus)")
      XCTAssertNotEqual(focus["indicator"] as? String, "none", "\(size.name): \(focus)")
      try await ui.screenshot("traffic-payload-keyboard-\(size.name)")

      try await ui.click("#payload-inspector .traffic-payload-details > summary")
      let details = try await ui.value("document.querySelector('#payload-inspector .traffic-payload-details').innerText") as? String ?? ""
      for phrase in ["Retained in full", "application/json", "SHA-256", "In-memory bytes", "Artifact ID"] {
        XCTAssertTrue(details.contains(phrase), "\(size.name): Capture details names \(phrase): \(details)")
      }
      XCTAssertFalse(details.contains("artifact URL"), "\(size.name): the duplicate URL row is gone: \(details)")
      try await ui.click("#payload-inspector button", containing: "Source")
      try await ui.waitUntil("document.querySelector('#payload-inspector .traffic-payload-lines .traffic-payload-line') !== null", "payload source did not render")
      // Raw text shows until the backend's layout arrives.
      try await ui.waitUntil("document.querySelector('#payload-inspector .traffic-payload-lines').innerText.includes('\"sitekey\": \"site-key\"')", "\(size.name): payload source was not laid out")
      let source = try await ui.value("document.querySelector('#payload-inspector .traffic-payload-lines').innerText") as? String ?? ""
      XCTAssertTrue(source.contains("\"sitekey\": \"site-key\""), "\(size.name): Source is pretty-printed: \(source.prefix(200))")
      try await assertInert(ui, "\(size.name) request payload source")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) request payload source")
      try await ui.screenshot("traffic-payload-source-\(size.name)")
      try await ui.click("#payload-inspector button", containing: "Parsed")

      try await ui.click("#screen-traffic .request-row", containing: expected.metadataBodyHost)
      try await ui.waitUntil(
        "(document.querySelector('#payload-inspector [data-section=\"payload\"]')?.innerText ?? '').includes('content capture was off')",
        "metadata-only body state did not render")
      let metadata = try await ui.value("document.querySelector('#payload-inspector').innerText") as? String ?? ""
      XCTAssertTrue(metadata.contains("application/x-www-form-urlencoded"), "\(size.name): metadata session keeps the type: \(metadata)")
      XCTAssertTrue(metadata.contains("recorded only in content capture sessions"), "\(size.name): metadata session stays host-only: \(metadata)")
      let views = try await ui.value("document.querySelectorAll('#payload-inspector .traffic-payload-view').length") as? Int ?? -1
      XCTAssertEqual(views, 0, "\(size.name): no payload view exists for a metadata-only request")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) metadata-only payload")
      try await ui.screenshot("traffic-payload-metadata-\(size.name)")
    }
  }

  // A retained response body reads as inert, colored text on Response and as a
  // JSON tree on Preview, with the keyboard reaching both tabs.
  @MainActor
  func test24ResponseAndPreviewTabs() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.responseBodyHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      try await ui.click("#inspector-tab-response")
      try await ui.waitUntil("document.querySelector('#response-inspector .traffic-response-code') !== null", "retained response did not load")
      let response = try await ui.json("""
        ({text: document.querySelector('#response-inspector .traffic-response-code').innerText,
          panel: document.querySelector('#response-inspector').innerText,
          state: document.querySelector('#response-inspector').dataset.state,
          colored: document.querySelectorAll('#response-inspector .traffic-response-code .syntax-string').length,
          labelled: document.querySelector('#response-inspector').getAttribute('aria-labelledby')})
        """)
      XCTAssertEqual(response["state"] as? String, "captured", "\(size.name): response body record state")
      XCTAssertEqual(response["labelled"] as? String, "inspector-tab-response")
      // Response shows the JSON source and Preview quotes strings, so the marker's quotes stay escaped.
      let escapedMarker = expected.responseBodyMarker.replacingOccurrences(of: "\"", with: "\\\"")
      XCTAssertTrue((response["text"] as? String ?? "").contains(escapedMarker), "\(size.name): captured markup is literal text")
      XCTAssertGreaterThan(response["colored"] as? Int ?? 0, 0, "\(size.name): JSON strings are colored")
      for phrase in ["Retained in full", "application/json", "SHA-256", "Pretty print", "Wrap", "Hex", "Copy"] {
        XCTAssertTrue((response["panel"] as? String ?? "").contains(phrase), "\(size.name): Response names \(phrase)")
      }
      try await assertInert(ui, "\(size.name) response body")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) response body")
      try await ui.screenshot("traffic-response-\(size.name)")

      try await ui.click("#response-inspector [data-control='pretty']")
      try await ui.waitUntil("document.querySelectorAll('#response-inspector .traffic-response-line').length > 3", "pretty print did not split the body")
      // The shared code view: the backend Oxc layout, and a clicked token names its exact raw range.
      let notes = try await ui.value("document.querySelector('#response-inspector').innerText") as? String ?? ""
      XCTAssertFalse(notes.contains("Whitespace layout"), "\(size.name): JSON responses use the Oxc layout: \(notes)")
      try await ui.click("#response-inspector .traffic-response-code .syntax-key")
      try await ui.waitUntil("/ · raw \\d+:\\d+–\\d+:\\d+ \\(offsets \\d+–\\d+\\)$/.test(document.querySelector('#response-inspector .code-view-raw')?.textContent ?? '')",
        "\(size.name): a laid-out token did not report its raw range")
      try await assertInert(ui, "\(size.name) pretty response")

      // Left arrow from Response moves to Preview, as on every inspector tab.
      _ = try await ui.value("(document.querySelector('#inspector-tab-response').focus(), true)")
      try await ui.key(123, "\u{F702}", modifiers: [.function, .numericPad])
      try await ui.waitUntil("document.activeElement?.id === 'inspector-tab-preview'", "arrow key did not reach Preview")
      try await ui.waitUntil("document.querySelector('#response-inspector .traffic-payload-tree') !== null", "JSON preview did not render")
      // The tree opens at the root; the captured string is two levels down.
      for key in ["tasks:", "0:"] {
        try await ui.click("#response-inspector .traffic-payload-tree [role=\"treeitem\"]", containing: key)
      }
      try await ui.waitUntil("document.querySelector('#response-inspector .traffic-payload-tree').textContent.includes('note')", "\(size.name): the nested preview row did not open")
      let preview = try await ui.value("document.querySelector('#response-inspector .traffic-payload-tree').textContent") as? String ?? ""
      XCTAssertTrue(preview.contains("challenge"), "\(size.name): the tree names its keys: \(preview)")
      XCTAssertTrue(preview.contains(escapedMarker), "\(size.name): tree strings are literal text")
      try await assertInert(ui, "\(size.name) response preview")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) response preview")
      try await ui.screenshot("traffic-preview-\(size.name)")
      try await ui.click("#inspector-tab-general")
    }
  }

  // protocol/native-network-v3.md "Requests answered in the renderer": a
  // memory-cache reuse is a complete row labelled (memory cache), and a request
  // its service worker ended without a response is Failed, never Pending.
  @MainActor
  func test29RendererAnsweredRows() async throws {
    let expected = try Expectations.load()
    // The narrow layout drops Size and Status, so the row's label and the Size
    // tooltip carry what the cells show.
    let selected = """
      (() => {
        const row = document.querySelector('#screen-traffic .request-row[aria-selected="true"]');
        return {label: row?.getAttribute('aria-label') ?? '', size: row?.querySelector('[data-column="size"]')?.title ?? '',
          general: document.querySelector('#exchange-inspector').innerText};
      })()
      """
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.memoryCacheHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let reused = try await ui.json(selected)
      let label = reused["label"] as? String ?? ""
      XCTAssertTrue(label.contains("(memory cache)") && label.contains(", 200,"),
        "\(size.name): a reuse is a complete (memory cache) row with its status: \(label)")
      XCTAssertTrue((reused["size"] as? String ?? "").contains("Served from the memory cache"),
        "\(size.name): the Size tooltip says no request was made")
      let general = reused["general"] as? String ?? ""
      XCTAssertTrue(general.contains("https://\(expected.memoryCacheHost)\(expected.memoryCacheTarget)"),
        "\(size.name): General shows the reused URL: \(general)")
      XCTAssertTrue(general.contains("(the memory cache) and made no request"), "\(size.name): General says no request was made")
      XCTAssertFalse(general.contains("Headers tab shows retained headers"), "\(size.name): no request record is promised")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) memory-cache row")
      try await ui.screenshot("traffic-memory-cache-\(size.name)")

      try await ui.click("#screen-traffic .request-row", containing: expected.serviceWorkerFailedHost)
      try await ui.waitUntil("document.querySelector('#exchange-inspector').innerText.includes('\(expected.serviceWorkerFailedHost)')",
        "the service-worker row did not open")
      let failed = (try await ui.json(selected))["label"] as? String ?? ""
      XCTAssertTrue(failed.contains("Failed") && failed.contains("(service worker)") && !failed.contains("Pending"),
        "\(size.name): the service worker's end is Failed, never Pending: \(failed)")
      try await ui.screenshot("traffic-service-worker-failed-\(size.name)")

      // The lost-end gap names its row without a request ID, so the row's
      // store read lacks it; the inspector keeps what the index row says.
      try await ui.click("#screen-traffic .request-row", containing: expected.serviceWorkerLostHost)
      try await ui.waitUntil("document.querySelector('#exchange-inspector').innerText.includes('\(expected.serviceWorkerLostHost)')",
        "the lost-end row did not open")
      let lost = try await ui.json(selected)
      let lostLabel = lost["label"] as? String ?? ""
      XCTAssertTrue(lostLabel.contains("End lost") && !lostLabel.contains("Pending") && !lostLabel.contains("No loader"),
        "\(size.name): the table reads End lost: \(lostLabel)")
      let lostGeneral = lost["general"] as? String ?? ""
      XCTAssertTrue(lostGeneral.contains("End lost") && lostGeneral.contains("its outcome was not recorded"),
        "\(size.name): the inspector agrees with the table: \(lostGeneral)")
      XCTAssertFalse(lostGeneral.contains("Pending") || lostGeneral.contains("No loader"),
        "\(size.name): the inspector does not read Pending: \(lostGeneral)")
      let strip = try await ui.value("document.querySelector('#selected-status').textContent") as? String ?? ""
      XCTAssertEqual(strip, "end lost", "\(size.name): the selected strip agrees")
      try await ui.screenshot("traffic-service-worker-lost-\(size.name)")
    }
  }

  // protocol/native-network-v3.md: the Headers tab of a content-session request
  // shows General, response and request headers read from retained blocks;
  // markup in a value is literal text. A metadata-only request says why none exist.
  @MainActor
  func test25RequestHeaders() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.requestBodyHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      try await ui.click("#inspector-tab-headers")
      try await ui.waitUntil("document.querySelectorAll('#headers-inspector .traffic-header-row').length === 6", "retained header blocks did not load")
      let headers = try await ui.json("""
        ({titles: [...document.querySelectorAll('#headers-inspector summary')].map(node => node.firstChild.textContent),
          text: document.querySelector('#headers-inspector').innerText,
          selected: document.querySelector('#inspector-tab-headers').getAttribute('aria-selected'),
          clipped: [...document.querySelectorAll('#headers-inspector .traffic-header-row')].some(row => row.scrollWidth > row.clientWidth + 1)})
        """)
      XCTAssertEqual(headers["titles"] as? [String] ?? [], ["General", "Response headers (200)", "Request headers"], "\(size.name): \(headers)")
      XCTAssertEqual(headers["selected"] as? String, "true", "\(size.name): the Headers tab is selected")
      XCTAssertEqual(headers["clipped"] as? Bool, false, "\(size.name): header rows are not clipped")
      let text = headers["text"] as? String ?? ""
      for phrase in ["127.0.0.1:8443", "set-cookie", ":method", expected.headerValueMarker] {
        XCTAssertTrue(text.contains(phrase), "\(size.name): Headers shows \(phrase): \(text)")
      }
      XCTAssertFalse(text.contains("Provisional headers are shown"), "\(size.name): the network block replaces provisional headers")
      try await assertInert(ui, "\(size.name) request headers")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) request headers")
      try await ui.screenshot("traffic-request-headers-\(size.name)")

      try await ui.click("#headers-inspector .traffic-headers-tools button", containing: "Raw")
      try await ui.waitUntil("document.querySelector('#headers-inspector .traffic-headers-raw') !== null", "Raw view did not open")
      let raw = try await ui.value("document.querySelector('#headers-inspector .traffic-headers-raw').innerText") as? String ?? ""
      XCTAssertTrue(raw.contains("set-cookie: hc=1; Secure; HttpOnly"), "\(size.name): Raw shows the exact block: \(raw)")
      try await ui.screenshot("traffic-request-headers-raw-\(size.name)")

      try await ui.click("#screen-traffic .request-row", containing: expected.metadataBodyHost)
      try await ui.waitUntil(
        "(document.querySelector('#headers-inspector')?.innerText ?? '').includes('recorded only in content capture sessions')",
        "metadata-only headers state did not render")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) metadata-only headers")
      try await ui.click("#inspector-tab-general")
    }
  }

  // "Cookies" in protocol/native-network-v3.md: the Cookies tab shows the
  // response and request cookies of retained lists, filtered-out request
  // cookies on request, a blocked Set-Cookie's reason, and a name's
  // provenance to the script that wrote it. Markup in a value is literal text.
  @MainActor
  func test26RequestCookies() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.requestBodyHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      try await ui.click("#inspector-tab-cookies")
      try await ui.waitUntil("document.querySelectorAll('#cookies-inspector .traffic-cookie-table tbody tr').length === 3", "retained cookie lists did not load")
      let cookies = try await ui.json("""
        ({titles: [...document.querySelectorAll('#cookies-inspector summary')].map(node => node.firstChild.textContent),
          text: document.querySelector('#cookies-inspector').innerText,
          selected: document.querySelector('#inspector-tab-cookies').getAttribute('aria-selected'),
          blocked: document.querySelector('#cookies-inspector .traffic-cookie-blocked .traffic-cookie-col-blocked')?.title ?? '',
          tooltip: document.querySelector('#cookies-inspector .traffic-cookie-blocked .traffic-cookie-col-value')?.title ?? ''})
        """)
      XCTAssertEqual(cookies["titles"] as? [String] ?? [], ["Response cookies", "Request cookies"], "\(size.name): \(cookies)")
      XCTAssertEqual(cookies["selected"] as? String, "true", "\(size.name): the Cookies tab is selected")
      let text = cookies["text"] as? String ?? ""
      for phrase in ["hc", "sid", "track", "Show filtered out request cookies (1)", "Partition Key Site"] {
        XCTAssertTrue(text.contains(phrase), "\(size.name): Cookies shows \(phrase): \(text)")
      }
      XCTAssertFalse(text.contains("pref"), "\(size.name): filtered-out cookies stay hidden until asked for")
      XCTAssertTrue((cookies["blocked"] as? String ?? "").contains("SameSite=None without Secure"), "\(size.name): \(cookies)")
      XCTAssertEqual(cookies["tooltip"] as? String, expected.cookieValueMarker, "\(size.name): the full value is the tooltip")
      try await assertInert(ui, "\(size.name) request cookies")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) request cookies")
      try await ui.screenshot("traffic-request-cookies-\(size.name)")

      try await ui.click("#cookies-inspector .traffic-cookie-filter input")
      try await ui.waitUntil("(document.querySelector('#cookies-inspector')?.innerText ?? '').includes('samesite_strict')", "filtered-out cookies did not show")
      try await ui.click("#cookies-inspector .traffic-cookie-name", containing: "sid")
      try await ui.waitUntil("(document.querySelector('#cookies-inspector .traffic-cookie-provenance')?.innerText ?? '').includes('the value document.cookie set wrote')", "provenance did not link the script write")
      let provenance = try await ui.value("document.querySelector('#cookies-inspector .traffic-cookie-provenance').innerText") as? String ?? ""
      XCTAssertTrue(provenance.contains("script 77 at character 1234"), "\(size.name): \(provenance)")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) cookie provenance")
      try await ui.screenshot("traffic-cookie-provenance-\(size.name)")
      try await ui.click("#cookies-inspector .traffic-cookie-provenance button", containing: "Close")

      try await ui.click("#screen-traffic .request-row", containing: expected.metadataBodyHost)
      try await ui.waitUntil(
        "(document.querySelector('#cookies-inspector')?.innerText ?? '').includes('recorded only in content capture sessions')",
        "metadata-only cookies state did not render")
      try await ui.click("#inspector-tab-general")
    }
  }

  @MainActor
  func test15BacktraceTimeAdjacentRow() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: "adjacent.trace.test")
      try await ui.waitUntil(
        "(document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"]')?.innerText ?? '').includes('adjacent.trace.test')",
        "\(size.name): adjacent.trace.test was not selected")
      try await show(ui, "backtrace")
      try await ui.waitUntil("document.querySelectorAll('#backtrace-steps .trace-row').length === 3",
        "\(size.name): the time-adjacent trace did not load")
      let rows = try await ui.value("""
        [...document.querySelectorAll('#backtrace-steps .trace-row')].map(row => ({
          gap: row.parentElement.classList.contains('gap'),
          title: row.querySelector('.step-title')?.textContent ?? '',
          kind: row.querySelector('.step-kind')?.textContent ?? '',
          label: row.querySelector('.trace-link-type')?.textContent ?? '',
          style: row.querySelector('.trace-link-type')?.className ?? ''}))
        """) as? [[String: Any]] ?? []
      XCTAssertEqual(rows.count, 3, "\(size.name): target, gap and adjacency rows: \(rows)")
      guard rows.count == 3 else { continue }
      XCTAssertEqual(rows[0]["kind"] as? String, "Selected request", "\(size.name): \(rows[0])")
      XCTAssertEqual(rows[1]["gap"] as? Bool, true, "\(size.name): the missing-predecessor gap stays in place: \(rows[1])")
      XCTAssertEqual(rows[2]["title"] as? String, "network · request_initiated", "\(size.name): \(rows[2])")
      XCTAssertEqual(rows[2]["kind"] as? String, "Time-adjacent record · no recorded link", "\(size.name): \(rows[2])")
      XCTAssertEqual(rows[2]["label"] as? String, "Time-adjacent only", "\(size.name): \(rows[2])")
      XCTAssertTrue((rows[2]["style"] as? String ?? "").contains("adjacency"), "\(size.name): weaker class styling: \(rows[2])")
      let coverage = try await ui.value("document.querySelector('#coverage-value').textContent") as? String ?? ""
      XCTAssertTrue(coverage.hasPrefix("0% trace coverage"), "\(size.name): proximity does not raise coverage: \(coverage)")
      XCTAssertTrue(coverage.contains("1 time-adjacent record, excluded from coverage"), "\(size.name): \(coverage)")

      // Arrow keys move from the selected request through the gap to the
      // adjacency row, which then owns visible focus and the inspector. WebKit
      // does not focus a button on click; enter the list the way a loaded
      // trace focuses its selected row, with focusVisible so ArrowDown keeps
      // the keyboard ring. Product focus scrolls the row into view.
      _ = try await ui.value("document.querySelector('#backtrace-steps .trace-row').focus({focusVisible:true})")
      for _ in 0..<2 { try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad]) }
      try await assertFullyVisible(ui, "#backtrace-steps .trace-step:last-child .trace-row", "\(size.name) arrow-focused row")
      let focus = try await ui.json("__rebUiProbe.focusState()")
      let selected = try await ui.value("document.activeElement?.closest('.trace-row')?.getAttribute('aria-pressed') ?? ''") as? String
      XCTAssertEqual(selected, "true", "\(size.name): ArrowDown selects the adjacency row: \(focus)")
      XCTAssertEqual(focus["focusVisible"] as? Bool, true, "\(size.name): adjacency row shows keyboard focus: \(focus)")
      XCTAssertNotEqual(focus["indicator"] as? String, "none", "\(size.name): \(focus)")
      let details = try await ui.value("document.querySelector('#trace-step-details').innerText") as? String ?? ""
      XCTAssertTrue(details.contains("Not a predecessor and not value flow"), "\(size.name): inspector names the class: \(details)")
      try await revealAndAssertFullyVisible(ui, "#backtrace-steps .trace-step:last-child .trace-row", "\(size.name) adjacency row")
      // Coverage lives above the steps scroller, so centering the last row
      // cannot scroll it away or cover earlier rows.
      try await assertFullyVisible(ui, "#coverage-value", "\(size.name) coverage line")
      try await assertInert(ui, "\(size.name) flow lineage")
      // The flow graph's tools float over its own canvas by design, so the
      // layout probe covers the Flow head, toolbar and Lineage, and the pane
      // switch where the narrow window shows one pane at a time.
      let scopes = ["#screen-backtrace > .flow-head", "#screen-backtrace > .flow-toolbar", "#flow-pane-lineage"] + (size.name == "narrow" ? ["#flow-tabs"] : [])
      for scope in scopes {
        try await assertLayout(ui, scope, "\(size.name) time-adjacent lineage \(scope)")
      }
      try await ui.screenshot("flow-lineage-time-adjacent-\(size.name)")
    }
  }

  // An app-started capture retains content and carries document-start Console
  // permission by default; the titlebar and the Console header say so. The
  // harness backend serves a stored session with no broker or capture browser,
  // so this test's own page fetch marks the event reads live and answers the
  // two Console reads as a permitted capture browser does. Nothing is
  // connected, armed or executed.
  @MainActor
  func test17LiveCaptureDefaultsAreLabeled() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      _ = try await ui.webView.callAsyncJavaScript(
        """
        const original = window.fetch.bind(window);
        const reply = value => new Response(JSON.stringify(value), {status: 200, headers: {'Content-Type': 'application/json'}});
        state.eventEtag = null;
        window.fetch = async (input, init) => {
          const path = typeof input === 'string' ? input : input.url;
          if (path === '/api/events?limit=5000') {
            const body = await (await original(path, {cache: 'no-store'})).json();
            return reply({...body, capture_mode: 'live', broker_connected: true});
          }
          if (path === '/api/native-console') return Promise.resolve(reply({contract_version: 2, state: 'idle', session_id: null,
            available: true, live_available: true, document_source: 'live_capture', binding_id: '5', truncated: false,
            selected_target_id: null, document_start_supported: true, message: 'live capture',
            targets: [{id: '21', origin: 'https://authorized.test', label: 'top #21', url: 'https://authorized.test/', main_frame: true, truncated: false}]}));
          if (path.startsWith('/api/native-console/document-start')) return Promise.resolve(reply({contract_version: 3, available: true,
            state: 'idle', session_id: null, document_start: {status: 'idle', permitted: false, scripts: [],
              message: 'Connect the Console with document-start scripts enabled, then arm a rule.'}}));
          return original(input, init);
        };
        return true;
        """, contentWorld: .page)
      // Content capture is labeled for the session in the titlebar, beside and
      // never over the session state, and readable at the narrowest window.
      try await ui.waitUntil("state.sessionMode === 'live' && __rebUiProbe.count('#session-content') === 1",
        "\(size.name): the live session did not label content capture")
      let titlebar = try await ui.json(
        """
        (() => {
          const label = document.querySelector('#session-content'), mode = document.querySelector('#session-mode');
          const a = label.getBoundingClientRect(), b = mode.getBoundingClientRect(), bar = document.querySelector('.titlebar').getBoundingClientRect();
          return {text: label.innerText, title: label.title, mode: mode.innerText,
            separate: a.left >= b.right || b.left >= a.right, inside: a.left >= bar.left && a.right <= bar.right && a.top >= bar.top && a.bottom <= bar.bottom,
            clipped: __rebUiProbe.clippedText('.titlebar')};
        })()
        """)
      XCTAssertEqual(titlebar["text"] as? String, "Content capture", "\(size.name): content label text: \(titlebar)")
      XCTAssertTrue((titlebar["title"] as? String ?? "").contains("request paths, queries and bodies"), "\(size.name): the label names what is retained")
      XCTAssertEqual(titlebar["separate"] as? Bool, true, "\(size.name): the content label overlaps the session state: \(titlebar)")
      XCTAssertEqual(titlebar["inside"] as? Bool, true, "\(size.name): the content label leaves the titlebar: \(titlebar)")
      XCTAssertEqual(titlebar["clipped"] as? [String], [], "\(size.name): clipped titlebar text")

      try await ui.click("#native-console-toggle")
      try await ui.waitUntil(
        "__rebUiProbe.count('#native-console-ds-badge') === 1 && document.querySelector('#native-console-ds-badge').dataset.state === 'permitted'",
        "\(size.name): the Console header did not show the live capture's permission")
      let badge = try await ui.json(
        """
        (() => {
          const badge = document.querySelector('#native-console-ds-badge'), rect = badge.getBoundingClientRect();
          const head = document.querySelector('.native-console-head').getBoundingClientRect();
          const neighbors = ['.native-console-title', '.native-console-context', '#native-console-search', '#native-console-clear',
            '#native-console-connection > summary', '#native-console-close'].map(selector => document.querySelector(selector))
            .filter(node => node && node.getBoundingClientRect().width > 0);
          const overlaps = neighbors.filter(node => { const other = node.getBoundingClientRect();
            return rect.left < other.right - 1 && other.left < rect.right - 1 && rect.top < other.bottom - 1 && other.top < rect.bottom - 1; })
            .map(node => __rebUiProbe.describe(node));
          return {text: badge.innerText, title: badge.title, complete: badge.scrollWidth <= badge.clientWidth + 1,
            inside: rect.left >= head.left && rect.right <= head.right && rect.top >= head.top && rect.bottom <= head.bottom, overlaps,
            armDisabled: document.querySelector('#native-console-ds-arm').disabled};
        })()
        """)
      XCTAssertEqual(badge["text"] as? String, "Doc-start: permitted", "\(size.name): badge text: \(badge)")
      XCTAssertTrue((badge["title"] as? String ?? "").contains("permitted for this live capture"), "\(size.name): the hover title names the state")
      XCTAssertEqual(badge["complete"] as? Bool, true, "\(size.name): the badge text is truncated: \(badge)")
      XCTAssertEqual(badge["inside"] as? Bool, true, "\(size.name): the badge leaves the Console header: \(badge)")
      XCTAssertEqual(badge["overlaps"] as? [String], [], "\(size.name): the badge overlaps a header control")
      XCTAssertEqual(badge["armDisabled"] as? Bool, true, "\(size.name): permission alone must not enable arming")
      let clipped = try await ui.value("__rebUiProbe.clippedText('.native-console-head')") as? [String] ?? ["probe failed"]
      XCTAssertEqual(clipped, [], "\(size.name): clipped Console header text")
      try await ui.screenshot("live-capture-defaults-\(size.name)")
    }
  }
  @MainActor
  private func savedSiteCount(_ ui: Harness) async throws -> Int {
    try await ui.value("fetch('/api/js-invocation-sites', {cache: 'no-store'}).then(response => response.json()).then(set => set.count)") as? Int ?? -1
  }

  @MainActor
  private func clearSavedSites(_ ui: Harness) async throws {
    let status = try await ui.value(
      "fetch('/api/js-invocation-sites/actions', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action: 'clear', confirm: true})}).then(response => response.status)")
    XCTAssertEqual(status as? Int, 200, "the saved set could not be cleared")
  }

  // Sources saves functions for the next capture by position and by name,
  // refuses what it cannot name exactly, and the titlebar says what is saved.
  @MainActor
  func test18TrackCallsFromSources() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await clearSavedSites(ui)
      try await show(ui, "sources")
      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"\(expected.invocationArtifactId)\"]")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('Mk().then')", "\(size.name): glue.js did not render")
      try await ui.waitUntil("!document.querySelector('#source-track-calls').disabled", "\(size.name): Track calls stayed disabled on an original JavaScript artifact")
      // The default position is top-level code, which is refused with its reason.
      // Track calls and Go to line are in the toolbar's More menu.
      try await ui.click("#source-more > summary")
      try await ui.click("#source-track-calls")
      try await ui.waitUntil("!document.querySelector('#source-more').open", "\(size.name): the More menu stayed open after an action")
      try await ui.waitUntil("(document.querySelector('#invocation-site-status')?.innerText ?? '').includes('top-level script code')",
        "\(size.name): top-level code was not refused")
      // A name typed and submitted with the keyboard; two definitions are refused.
      try await ui.click("#invocation-site-name")
      try await ui.type("o.dup")
      try await ui.key(36, "\r")
      try await ui.waitUntil("(document.querySelector('#invocation-site-status')?.innerText ?? '').includes('2 function definitions bind o.dup')",
        "\(size.name): an ambiguous name was not refused")
      let candidates = try await ui.json(
        "({count: document.querySelectorAll('.invocation-site-candidate').length, contexts: [...document.querySelectorAll('.invocation-site-context')].map(node => node.innerText)})")
      XCTAssertEqual(candidates["count"] as? Int, 2, "\(size.name): both definitions listed: \(candidates)")
      XCTAssertTrue((candidates["contexts"] as? [String] ?? []).contains { $0.contains("<img src=x onerror") }, "\(size.name): captured markup is a context line")
      try await assertInert(ui, "\(size.name) track calls candidates")
      try await assertLayout(ui, "#source-sidebar", "\(size.name) track calls candidates")
      try await revealAndAssertFullyVisible(ui, ".invocation-sites-candidates", "\(size.name) candidate list")
      try await ui.screenshot("sources-track-calls-candidates-\(size.name)")
      // The real binder is saved; the decoys in a string and a comment are not candidates.
      try await ui.click("#invocation-site-name")
      try await ui.key(0, "a", modifiers: [.command])
      try await ui.type("window.hsw")
      try await ui.key(36, "\r")
      try await ui.waitUntil("(document.querySelector('#invocation-site-status')?.innerText ?? '').includes('Saved window.hsw')",
        "\(size.name): window.hsw was not saved")
      let savedStatus = try await ui.value("document.querySelector('#invocation-site-status').innerText") as? String ?? ""
      XCTAssertTrue(savedStatus.contains("not the open page"), "\(size.name): saving says tracking starts with the next capture")
      // Line 2 at the awb( call names the then-callback around it.
      try await ui.click("#source-more > summary")
      try await ui.click("#source-goto")
      try await ui.waitUntil("document.activeElement?.id === 'source-window-line'", "\(size.name): Go to line did not focus its line field")
      _ = try await ui.webView.callAsyncJavaScript(
        """
        const line = document.querySelector('#source-window-line'), column = document.querySelector('#source-window-column');
        line.value = '2'; column.value = String(document.querySelector('.source-line[data-line="2"] .source-text').textContent.indexOf('awb') + 1);
        return true;
        """, contentWorld: .page)
      try await ui.click("#source-window button[type=submit]")
      try await ui.waitUntil("document.querySelector('#source-window').hidden", "\(size.name): Go to line stayed open after Go")
      try await ui.click("#source-more > summary")
      try await ui.click("#source-track-calls")
      try await ui.waitUntil("(document.querySelector('#invocation-site-status')?.innerText ?? '').includes('Saved the function at line 2')",
        "\(size.name): the function at the position was not saved")
      let savedCount = try await savedSiteCount(ui)
      XCTAssertEqual(savedCount, 2, "\(size.name): two sites saved")
      try await ui.waitUntil("!document.querySelector('#invocation-tracking').hidden", "\(size.name): the titlebar did not show the saved functions")
      let chip = try await ui.json(
        """
        (() => {
          const chip = document.querySelector('#invocation-tracking'), rect = chip.getBoundingClientRect(), bar = document.querySelector('.titlebar').getBoundingClientRect();
          const others = ['#session-mode', '#session-content', '.brand-name'].map(selector => document.querySelector(selector)).filter(node => node && node.getBoundingClientRect().width > 0);
          const overlaps = others.filter(node => { const other = node.getBoundingClientRect();
            return rect.left < other.right - 1 && other.left < rect.right - 1 && rect.top < other.bottom - 1 && other.top < rect.bottom - 1; }).map(node => __rebUiProbe.describe(node));
          return {text: chip.innerText, inside: rect.left >= bar.left && rect.right <= bar.right && rect.top >= bar.top && rect.bottom <= bar.bottom,
            complete: chip.scrollWidth <= chip.clientWidth + 1, overlaps};
        })()
        """)
      XCTAssertEqual(chip["text"] as? String, "2 functions saved for the next capture", "\(size.name): chip text: \(chip)")
      XCTAssertEqual(chip["inside"] as? Bool, true, "\(size.name): the chip leaves the titlebar: \(chip)")
      XCTAssertEqual(chip["complete"] as? Bool, true, "\(size.name): the chip text is truncated: \(chip)")
      XCTAssertEqual(chip["overlaps"] as? [String], [], "\(size.name): the chip overlaps the titlebar")
      try await assertInert(ui, "\(size.name) track calls saved")
      try await assertLayout(ui, "#source-sidebar", "\(size.name) track calls saved")
      try await revealAndAssertFullyVisible(ui, ".invocation-sites-list", "\(size.name) saved list")
      try await ui.screenshot("sources-track-calls-saved-\(size.name)")
    }
  }

  // A one-line source map opens pretty-printed: the gutter numbers formatted
  // lines, a later window keeps its colors, Cmd+F and Ctrl+G reach Find and
  // Go to line, and the status-bar toggle shows the captured line (#433).
  @MainActor
  func test18bMinifiedSourceOpensPrettyPrinted() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"\(expected.minifiedArtifactId)\"]")
      let settled = "!/Formatting|coloring/.test(document.querySelector('#source-pretty').innerText + document.querySelector('#source-language').innerText)"
      // A narrow status bar shows only "{ }", so read the toggle's pressed state.
      try await ui.waitUntil("document.querySelector('#source-pretty').getAttribute('aria-pressed') === 'true' && \(settled)", timeout: 30,
        "\(size.name): the one-line source map did not open pretty-printed")
      let first = try await ui.json(
        """
        ({gutters: [...document.querySelectorAll('.source-gutter')].slice(0, 3).map(node => node.textContent),
          title: document.querySelectorAll('.source-gutter')[1].title, keys: document.querySelectorAll('#source-code .syntax-key').length,
          pressed: document.querySelector('#source-pretty').getAttribute('aria-pressed')})
        """)
      XCTAssertEqual(first["gutters"] as? [String], ["1", "2", "3"], "\(size.name): the gutter numbers formatted lines: \(first)")
      XCTAssertTrue((first["title"] as? String ?? "").hasPrefix("Original 1:"), "\(size.name): the gutter tooltip names the original location: \(first)")
      XCTAssertGreaterThan(first["keys"] as? Int ?? 0, 0, "\(size.name): JSON keys are colored: \(first)")
      XCTAssertEqual(first["pressed"] as? String, "true")
      try await assertInert(ui, "\(size.name) pretty-printed source map")
      try await assertLayout(ui, "#screen-sources", "\(size.name) pretty-printed source map")
      try await ui.screenshot("sources-pretty-printed-\(size.name)")
      // A file past the preview limit states it above the code. The record is marked rather than
      // retained at 16 MiB, which would dominate this suite; the loader has its own check.
      _ = try await ui.value("(() => { state.artifacts.find(item => item.artifact_id === state.selectedArtifactId).contentTruncated = true; renderSources(); return true; })()")
      try await ui.waitUntil("!document.querySelector('#source-limit-notice').hidden", "\(size.name): the limit notice did not appear")
      let limit = try await ui.value("document.querySelector('#source-limit-notice').innerText") as? String ?? ""
      XCTAssertTrue(limit.contains("first 16 MiB"), "\(size.name): the notice states the limit: \(limit)")
      try await assertLayout(ui, "#screen-sources", "\(size.name) source past the preview limit")
      try await ui.screenshot("sources-limit-notice-\(size.name)")
      _ = try await ui.value("(() => { state.artifacts.find(item => item.artifact_id === state.selectedArtifactId).contentTruncated = false; renderSources(); return true; })()")
      try await ui.waitUntil("document.querySelector('#source-limit-notice').hidden", "\(size.name): the limit notice stayed after the record changed")
      try await ui.click("#source-window-next")
      try await ui.waitUntil("document.querySelector('.source-line[data-line=\"1001\"]') && \(settled) && document.querySelectorAll('#source-code .syntax-string').length > 0",
        "\(size.name): the window after line 1,000 lost its colors")
      let rowHeight = (try await ui.value("document.querySelector('#source-code .source-line').getBoundingClientRect().height") as? NSNumber)?.doubleValue ?? 0
      XCTAssertEqual(rowHeight, 18, "\(size.name): Sources rows use the editor's 18 px line height")
      try await assertLayout(ui, "#screen-sources", "\(size.name) pretty-printed later window")
      try await ui.screenshot("sources-pretty-printed-later-\(size.name)")
      try await ui.key(3, "f", modifiers: [.command])
      try await ui.waitUntil("document.activeElement?.id === 'source-search'", "\(size.name): Cmd+F did not focus Find")
      try await ui.key(5, "g", modifiers: [.control])
      try await ui.waitUntil("!document.querySelector('#source-window').hidden && document.activeElement?.id === 'source-window-line'",
        "\(size.name): Ctrl+G did not open Go to line")
      try await ui.screenshot("sources-go-to-line-\(size.name)")
      try await ui.key(53, "\u{1b}")
      try await ui.waitUntil("document.querySelector('#source-window').hidden", "\(size.name): Escape did not close Go to line")
      try await ui.click("#source-pretty")
      try await ui.waitUntil("document.querySelector('#source-pretty').getAttribute('aria-pressed') === 'false' && document.querySelectorAll('.source-line').length === 1 && \(settled)",
        "\(size.name): Show original did not show the captured line")
      try await assertLayout(ui, "#screen-sources", "\(size.name) original one-line source map")
      try await ui.screenshot("sources-original-line-\(size.name)")
    }
  }

  // The start panel lists what the capture about to start will track, says
  // digests follow the mode, and removes a site. It is opened from the New
  // Live Session menu item, as a researcher opens it, and left offline.
  @MainActor
  func test19StartPanelListsSavedFunctions() async throws {
    let ui = try await prepare(windowSizes[0])
    let harnessURL = try XCTUnwrap(ui.webView.url)
    let expected = try Expectations.load()
    try await clearSavedSites(ui)
    // window.hsw by name and the then-callback around awb( by its byte offset.
    _ = try await ui.value(
      "fetch('/api/js-invocation-sites/actions', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({action: 'add', session_id: '1', artifact_id: '\(expected.invocationArtifactId)', name: 'window.hsw'})}).then(response => response.status)")
    _ = try await ui.value(
      """
      fetch('/api/artifacts/\(expected.invocationArtifactId)/content', {cache: 'no-store'}).then(response => response.text()).then(text =>
        fetch('/api/js-invocation-sites/actions', {method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({action: 'add', session_id: '1', artifact_id: '\(expected.invocationArtifactId)', byte_offset: new TextEncoder().encode(text.slice(0, text.indexOf('awb'))).length})}))
        .then(response => response.status)
      """)
    let seeded = try await savedSiteCount(ui)
    XCTAssertEqual(seeded, 2, "two sites are saved before the panel opens")
    do {
      try await openStartPanel(ui)
      var text = try await panelText(ui)
      XCTAssertTrue(text.contains("Tracking 2 functions"), "the panel counts the saved functions: \(text)")
      XCTAssertTrue(text.contains("window.hsw"), "the panel names each saved function")
      XCTAssertTrue(text.contains("Content mode also records settled-value digests"), "Content mode names its digests")
      XCTAssertTrue(text.contains("https://hcaptcha.test/glue.js"), "each site names its script")
      try await assertLayout(ui, "#session-panel", "start panel with saved functions")
      try await assertInert(ui, "start panel with saved functions")
      try await ui.reveal("#session-panel .session-panel-site-list", block: "end")
      try await ui.screenshot("start-panel-tracking")
      try await ui.click("#session-panel .session-panel-mode[data-mode='metadata']")
      text = try await panelText(ui)
      XCTAssertTrue(text.contains("Metadata mode records no settled-value digests"), "Metadata mode records no digests: \(text)")
      try await ui.click("#session-panel button[aria-label=\"Remove window.hsw\"]")
      try await ui.waitUntil("document.querySelector('#session-panel').innerText.includes('Tracking 1 function')", "Remove updates the count")
      text = try await panelText(ui)
      XCTAssertFalse(text.contains("window.hsw"), "the removed site is gone: \(text)")
      XCTAssertTrue(text.contains("Metadata mode records no settled-value digests"), "Remove keeps the chosen mode: \(text)")
      let file = try String(contentsOfFile: expected.invocationSiteStore, encoding: .utf8)
      let sites = (try JSONSerialization.jsonObject(with: Data(file.utf8)) as? [String: Any])?["sites"] as? [Any]
      XCTAssertEqual(sites?.count, 1, "Remove rewrites the saved site file at once")
      try await assertLayout(ui, "#session-panel", "start panel after Remove")
      try await ui.reveal("#session-panel .session-panel-site-list", block: "end")
      try await ui.screenshot("start-panel-tracking-removed")
      try await ui.click("#session-panel .session-panel-mode[data-mode='content']")
      try await ui.click("#session-panel-offline")
      try await ui.waitUntil("document.querySelector('#session-panel').hidden", "Continue Offline closes the panel")
    } catch {
      try? await returnToHarness(ui, harnessURL)
      throw error
    }
    // New Live Session loaded the offline workspace; return to the harness.
    ui.webView.load(URLRequest(url: harnessURL))
    try await ui.waitForInitialLoad()
    try await ui.reload()
    let remaining = try await savedSiteCount(ui)
    XCTAssertEqual(remaining, 1, "the backend reads the set the panel wrote")
    try await clearSavedSites(ui)
  }

  // A backend that stops answering: the bounded poll reports it, keeps the
  // last evidence and withdraws Stop and Clear. A capture action stays in
  // progress across polls, which could otherwise re-enable its button.
  @MainActor
  func test20EventPollTimeoutAndCaptureActions() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      _ = try await ui.webView.callAsyncJavaScript(
        """
        const original = window.fetch.bind(window);
        const reply = value => new Response(JSON.stringify(value), {status: 200, headers: {'Content-Type': 'application/json'}});
        const shim = window.__rebPollShim = {hang: false, stopped: false, eventPolls: 0, actions: [], answer: null};
        state.eventEtag = null;
        window.fetch = async (input, init = {}) => {
          const path = typeof input === 'string' ? input : input.url;
          if (path === '/api/events?limit=5000') {
            shim.eventPolls += 1;
            if (shim.hang) return new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(init.signal.reason), {once: true}));
            const body = await (await original(path, {cache: 'no-store'})).json();
            return reply({...body, capture_mode: 'live', broker_connected: !shim.stopped, capture_stopped: shim.stopped, capture_controls_available: true});
          }
          if (path === '/api/capture/actions') {
            shim.actions.push(JSON.parse(init.body));
            return new Promise(resolve => { shim.answer = value => resolve(reply(value)); });
          }
          return original(input, init);
        };
        return true;
        """, contentWorld: .page)
      try await show(ui, "signals")
      try await ui.waitUntil("state.connection === 'connected' && !document.querySelector('#signal-stop-capture').disabled",
        "\(size.name): the live capture did not offer Stop")
      let retained = try await ui.value("state.requests.length") as? Int ?? 0
      XCTAssertGreaterThan(retained, 0, "\(size.name): fixture requests are loaded")

      try await ui.click("#signal-stop-capture")
      try await ui.waitUntil("document.querySelector('#signal-notice').textContent === 'Stopping native probes…'",
        "\(size.name): the in-flight stop was not announced")
      let polls = try await ui.value("__rebPollShim.eventPolls") as? Int ?? 0
      try await ui.waitUntil("__rebPollShim.eventPolls >= \(polls + 2)", "\(size.name): polling stopped during the action")
      let inFlight = try await ui.json(
        "({stop: document.querySelector('#signal-stop-capture').disabled, clear: document.querySelector('#signal-clear-events').disabled, actions: __rebPollShim.actions.length, stopped: state.captureStopped})")
      XCTAssertEqual(inFlight["stop"] as? Bool, true, "\(size.name): a poll re-enabled Stop during its action: \(inFlight)")
      XCTAssertEqual(inFlight["clear"] as? Bool, true, "\(size.name): Clear is offered during an action: \(inFlight)")
      XCTAssertEqual(inFlight["actions"] as? Int, 1, "\(size.name): \(inFlight)")
      XCTAssertEqual(inFlight["stopped"] as? Bool, false, "\(size.name): \(inFlight)")
      try await assertLayout(ui, "#screen-signals", "\(size.name) capture action in flight")
      try await ui.screenshot("capture-action-in-flight-\(size.name)")

      _ = try await ui.value("(__rebPollShim.stopped = true, __rebPollShim.answer({ok: true, capture_stopped: true, broker_connected: false}), true)")
      try await ui.waitUntil(
        "document.querySelector('#signal-session-badge').textContent === 'Probes stopped' && !document.querySelector('#signal-clear-events').disabled",
        "\(size.name): the stop did not settle")

      _ = try await ui.value("(__rebPollShim.hang = true, true)")
      try await ui.waitUntil("state.connection === 'unresponsive'", timeout: 20, "\(size.name): a hung backend was never reported")
      let hung = try await ui.json(
        """
        ({footer: document.querySelector('#broker-status').textContent, updated: document.querySelector('#updated-status').textContent,
          badge: document.querySelector('#signal-session-badge').textContent, notice: document.querySelector('#signal-notice').textContent,
          stop: document.querySelector('#signal-stop-capture').disabled, clear: document.querySelector('#signal-clear-events').disabled,
          requests: state.requests.length})
        """)
      XCTAssertEqual(hung["footer"] as? String, "broker not responding", "\(size.name): \(hung)")
      XCTAssertEqual(hung["updated"] as? String, "last valid evidence retained", "\(size.name): \(hung)")
      XCTAssertNotEqual(hung["badge"] as? String, "Probes stopped", "\(size.name): an unknown capture state outranks the stale stop: \(hung)")
      XCTAssertTrue((hung["notice"] as? String ?? "").contains("did not answer within 10 seconds"), "\(size.name): \(hung)")
      XCTAssertEqual(hung["stop"] as? Bool, true, "\(size.name): \(hung)")
      XCTAssertEqual(hung["clear"] as? Bool, true, "\(size.name): Clear is offered against an unresponsive backend: \(hung)")
      XCTAssertEqual(hung["requests"] as? Int, retained, "\(size.name): the last valid evidence was not kept: \(hung)")
      try await assertLayout(ui, "#screen-signals", "\(size.name) unresponsive Fingerprinting")
      try await ui.screenshot("event-poll-unresponsive-signals-\(size.name)")
      try await show(ui, "traffic")
      let notice = try await ui.value("document.querySelector('#network-notice').hidden ? '' : document.querySelector('#network-notice').textContent") as? String ?? ""
      XCTAssertTrue(notice.contains("did not answer within 10 seconds"), "\(size.name): Traffic names the timeout: \(notice)")
      try await assertInert(ui, "\(size.name) unresponsive Traffic")
      try await assertLayout(ui, "#screen-traffic", "\(size.name) unresponsive Traffic")
      try await ui.screenshot("event-poll-unresponsive-traffic-\(size.name)")

      _ = try await ui.value("(__rebPollShim.hang = false, true)")
      try await ui.waitUntil("state.connection === 'broker-offline' && document.querySelector('#broker-status').textContent === 'broker unavailable'",
        timeout: 20, "\(size.name): the poll did not recover")
    }
  }

  private func views(_ root: NSView) -> [NSView] { [root] + root.subviews.flatMap(views) }

  private func texts(_ panel: NSWindow) -> [String] {
    views(panel.contentView!).compactMap { ($0 as? NSTextField)?.stringValue }
  }

  private func button(_ panel: NSWindow, _ title: String) -> NSButton? {
    views(panel.contentView!).compactMap { $0 as? NSButton }.first { $0.title == title }
  }

  // Runs an app menu action from the run loop, as AppKit runs a chosen item, so
  // a modal it opens does not block this main-actor test. A backstop ends any
  // modal the test leaves open.
  @MainActor
  private func chooseMenuItem(_ action: String) throws -> Timer {
    let item = NSApp.mainMenu?.items.compactMap(\.submenu).flatMap(\.items).first { $0.action == Selector((action)) }
    let menu = try XCTUnwrap(item?.menu, "the \(action) menu item")
    let index = menu.index(of: try XCTUnwrap(item))
    RunLoop.main.add(Timer(timeInterval: 0, repeats: false) { _ in menu.performActionForItem(at: index) }, forMode: .default)
    let backstop = Timer(timeInterval: 60, repeats: false) { _ in if NSApp.modalWindow != nil { NSApp.abortModal() } }
    RunLoop.main.add(backstop, forMode: .modalPanel)
    return backstop
  }

  @MainActor
  private func waitFor(_ label: String, timeout: TimeInterval = 20, _ condition: () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() {
      guard Date() < deadline else { throw HarnessError("Timed out: \(label)") }
      try await Task.sleep(nanoseconds: 100_000_000)
    }
  }

  @MainActor
  private func returnToHarness(_ ui: Harness, _ url: URL) async throws {
    if let sheet = ui.window.attachedSheet { ui.window.endSheet(sheet, returnCode: .abort) }
    if ui.webView.url != url {
      ui.webView.load(URLRequest(url: url))
      try await ui.waitForInitialLoad()
    }
    try await ui.reload(activating: false)
  }

  // The bundled reb:// workspace answers its requests natively. A request the
  // page no longer owns, because the page reloaded while the analyst runner
  // held it for its 2 second limit, must not be answered: WebKit raises on a
  // reply to a stopped request, which ended the app. The runner slot must also
  // come back, so the next run gets its own answer instead of 409.
  @MainActor
  func test21StoppedRequestIsNotAnswered() async throws {
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    let harnessURL = try XCTUnwrap(ui.webView.url)
    let arguments = ProcessInfo.processInfo.arguments
    let store = arguments.firstIndex(of: "--local-analyst").flatMap { arguments.indices.contains($0 + 1) ? arguments[$0 + 1] : nil }
    guard let store, store.contains("reb-rendered-ui-") else {
      throw HarnessError("The bundled workspace must use the harness Analyst store, not Application Support: \(arguments)")
    }
    ui.webView.load(URLRequest(url: try XCTUnwrap(URL(string: "reb://app/index.html?native=1"))))
    try await ui.waitUntil("location.protocol === 'reb:' && document.readyState === 'complete' && typeof state === 'object' && state.localAnalystLoaded",
      timeout: 30, "the bundled workspace did not load")
    let runner = "fetch('/api/local-analyst/runner', {cache: 'no-store'}).then(response => response.json())"
    let post = "{method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}"
    // Save a script that never returns, then run it without awaiting its answer.
    let saved = try await ui.json(
      """
      (async () => {
        const current = await fetch('/api/local-analyst', {cache: 'no-store'}).then(response => response.json());
        const files = current.files.map(({content_bytes, created_at_ms, updated_at_ms, ...file}) => file);
        const id = Math.max(0, ...files.map(file => file.id)) + 1, source = 'for (;;) {}';
        let body = {action: 'replace_local_analyst_workspace', expected_generation: current.generation, folders: current.folders,
          files: [...files, {id, folder_id: 1, name: '__stopped-request.js', kind: 'analyst-script', language: 'javascript', content: source}]};
        const library = await fetch('/api/local-analyst/actions', \(post)).then(response => response.json());
        window.__rebRun = {action: 'run_local_analyst_script', protocol_version: 1, run_id: 1, script_id: id,
          library_generation: library.generation, source, variables: {}, evidence: {events: [], artifacts: [], trace_edges: [],
          signal_profiles: [], vm_analysis: null, selected_artifact: null, summary: {}}, confirmed: true, confirmed_sensitive: false};
        body = window.__rebRun;
        fetch('/api/local-analyst/actions', \(post)).catch(() => {});
        return {run: JSON.stringify(window.__rebRun), files: JSON.stringify(files), generation: library.generation};
      })()
      """)
    let run = try XCTUnwrap(saved["run"] as? String)
    try await ui.waitUntil("\(runner).then(state => state.active_run_id === 1)", timeout: 10, "the analyst runner did not start")
    _ = try await ui.webView.callAsyncJavaScript("window.__rebOutgoingDocument = true; return true;", contentWorld: .page)
    ui.webView.reload()
    try await ui.waitUntil("window.__rebOutgoingDocument === undefined && document.readyState === 'complete' && typeof state === 'object'",
      timeout: 30, "the bundled workspace did not reload")
    // The runner gives up after 2 seconds and replies to the request the reload stopped.
    try await ui.waitUntil("\(runner).then(state => state.active_run_id === null)", timeout: 10, "the analyst runner slot was not released")
    try await Task.sleep(nanoseconds: 1_000_000_000)
    let second = try await ui.json(
      "(async () => { const body = {...JSON.parse(\(String(reflecting: run))), run_id: 2}; " +
      "const response = await fetch('/api/local-analyst/actions', \(post)); return {status: response.status, outcome: (await response.json()).outcome}; })()")
    XCTAssertEqual(second["status"] as? Int, 200, "the next run gets its own answer: \(second)")
    XCTAssertEqual(second["outcome"] as? String, "timed_out", "the next run reaches the runner: \(second)")
    let files = try XCTUnwrap(saved["files"] as? String)
    let generation = try XCTUnwrap(saved["generation"] as? Int)
    _ = try await ui.value(
      "(async () => { const body = {action: 'replace_local_analyst_workspace', expected_generation: \(generation), " +
      "folders: (await fetch('/api/local-analyst', {cache: 'no-store'}).then(response => response.json())).folders, files: JSON.parse(\(String(reflecting: files)))}; " +
      "return (await fetch('/api/local-analyst/actions', \(post))).status; })()")
    try await returnToHarness(ui, harnessURL)
  }

  @MainActor
  private func panelText(_ ui: Harness) async throws -> String {
    try await ui.value("document.querySelector('#session-panel')?.innerText ?? ''") as? String ?? ""
  }

  // Chooses New Live Session, as a researcher does, and waits for the start
  // panel in the bundled workspace. The close guard trusts only a document
  // the app loaded itself; earlier tests return to the harness page directly,
  // which then cannot answer, so that question is answered deliberately.
  @MainActor
  private func openStartPanel(_ ui: Harness) async throws {
    // New Live Session always loads the bundled workspace again, so wait for
    // a document other than this one.
    _ = try? await ui.webView.callAsyncJavaScript("window.__rebOutgoingDocument = true; return true;", contentWorld: .page)
    let backstop = try chooseMenuItem("newLiveSession:")
    defer { backstop.invalidate() }
    let ready = "window.__rebOutgoingDocument === undefined && location.protocol === 'reb:' && document.readyState === 'complete' "
      + "&& typeof state === 'object' && state.apiCollectionLoaded && document.querySelector('#session-panel')?.dataset.state === 'choose'"
    let deadline = Date().addingTimeInterval(30)
    var answered = false
    while (try? await ui.value(ready)) as? Bool != true {
      if !answered, let sheet = ui.window.attachedSheet, let start = button(sheet, "Start New Session"), start.isEnabled {
        XCTAssertTrue(texts(sheet).contains("Couldn’t check for unsaved work"), "\(texts(sheet))")
        start.performClick(nil)
        answered = true
      }
      guard Date() < deadline else {
        if let sheet = ui.window.attachedSheet { button(sheet, "Stay")?.performClick(nil) }
        throw HarnessError("the start panel did not open in the bundled workspace")
      }
      try await Task.sleep(nanoseconds: 100_000_000)
    }
    try await ui.settle()
  }

  // Opens the bundled workspace through New Live Session and Continue Offline.
  @MainActor
  private func openOfflineWorkspace(_ ui: Harness) async throws {
    try await openStartPanel(ui)
    try await ui.click("#session-panel-offline")
    try await ui.waitUntil("document.querySelector('#session-panel').hidden", "Continue Offline did not close the start panel")
  }

  // New Live Session replaces the window's document. An unsaved API Collection
  // edit must be asked about first, Stay must keep the edit, the page and any
  // session, and a clean document must go straight to the start panel.
  @MainActor
  func test22NewLiveSessionAsksAboutUnsavedWork() async throws {
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    try await ui.resize(width: windowSizes[0].width, height: windowSizes[0].height)
    let harnessURL = try XCTUnwrap(ui.webView.url)
    try await openOfflineWorkspace(ui)
    let workspaceURL = try XCTUnwrap(ui.webView.url)
    let dirty = try await ui.value(
      """
      (() => {
        showScreen('api-collection');
        const field = elements.collectionFolderVariables;
        field.value = '{"unsaved_rendered_check": "1"}';
        field.dispatchEvent(new Event('input', {bubbles: true}));
        return state.collectionFolderDirty;
      })()
      """)
    XCTAssertEqual(dirty as? Bool, true, "the folder editor marked its edit unsaved")
    let asked = try? await ui.value("hasUnsavedWork()")
    XCTAssertEqual(asked as? Bool, true, "the native shell's question counts an API Collection edit")
    let backstop = try chooseMenuItem("newLiveSession:")
    do {
      try await waitFor("the unsaved-work decision") {
        ui.window.attachedSheet.flatMap { button($0, "Start New Session") }?.isEnabled == true || ui.webView.url != workspaceURL
      }
      guard ui.webView.url == workspaceURL else {
        throw HarnessError("New Live Session replaced the page over unsaved work without asking")
      }
      let sheet = try XCTUnwrap(ui.window.attachedSheet)
      XCTAssertTrue(texts(sheet).contains("Start a new live session with unsaved or unconfirmed changes?"), "\(texts(sheet))")
      let waiting = try await ui.value("document.querySelector('#session-panel').hidden")
      XCTAssertEqual(waiting as? Bool, true, "the start panel waits for the decision")
      let stay = try XCTUnwrap(button(sheet, "Stay"))
      XCTAssertTrue(sheet.defaultButtonCell === (stay.cell as? NSButtonCell), "Stay is the Return default")
      XCTAssertEqual(button(sheet, "Start New Session")?.keyEquivalent, "", "the destructive choice has no key equivalent")
      try await Task.sleep(nanoseconds: 1_500_000_000)
      try ui.screenshot(window: sheet, "new-session-unsaved-prompt")
      stay.performClick(nil)
      try await waitFor("Stay dismissal") { ui.window.attachedSheet == nil }
      try await Task.sleep(nanoseconds: 1_000_000_000)
      let closed = try await ui.value("document.querySelector('#session-panel').hidden")
      XCTAssertEqual(closed as? Bool, true, "Stay does not open the start panel")
      XCTAssertEqual(ui.webView.url, workspaceURL, "Stay keeps the page")
      let kept = try await ui.value("state.collectionFolderDirty === true && elements.collectionFolderVariables.value.includes('unsaved_rendered_check')")
      XCTAssertEqual(kept as? Bool, true, "Stay keeps the unsaved edit")
      try await ui.screenshot("new-session-stay-keeps-edit")
    } catch {
      if let sheet = ui.window.attachedSheet { button(sheet, "Stay")?.performClick(nil) }
      backstop.invalidate()
      try? await returnToHarness(ui, harnessURL)
      throw error
    }
    backstop.invalidate()
    let clean = try await ui.value("(() => { elements.collectionDiscardFolder.click(); return hasUnsavedWork(); })()")
    XCTAssertEqual(clean as? Bool, false, "discarding the edit leaves no unsaved work")
    // A clean document the app loaded goes straight to the start panel.
    try await openOfflineWorkspace(ui)
    try await returnToHarness(ui, harnessURL)
  }

  // Ends the page's web content process with SIGKILL, as a crash would. Its
  // process ID comes from WebKit's testing interface; WebKit's own kill request
  // is not reported to the app as a stop. Page JavaScript cannot run until
  // something reloads the page, so whether a reload starts is observed natively.
  @MainActor
  private func stopContentProcess(_ ui: Harness) async throws -> NSKeyValueObservation {
    guard ui.webView.responds(to: Selector(("_webProcessIdentifier"))),
      let pid = (ui.webView.value(forKey: "_webProcessIdentifier") as? NSNumber)?.int32Value, pid > 0
    else { throw XCTSkip("This WebKit does not name its content process") }
    _ = try await ui.webView.callAsyncJavaScript("window.__rebOutgoingDocument = true; return true;", contentWorld: .page)
    reloadStarted = false
    let observation = ui.webView.observe(\.isLoading, options: [.new]) { [weak self] view, _ in
      if view.isLoading { self?.reloadStarted = true }
    }
    guard kill(pid, SIGKILL) == 0 else { throw HarnessError("Could not stop web content process \(pid): errno \(errno)") }
    return observation
  }

  private var reloadStarted = false

  // A captured dispatcher draws as a block graph with its limits on screen, and
  // the keyboard moves through blocks and reveals the linear view.
  @MainActor
  func test25BlockGraphInSources() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      try await ui.click("#source-tree [role=treeitem][data-artifact-id=\"340\"]")
      try await ui.waitUntil("!document.querySelector('#source-graph').hidden", "Graph is offered for a captured WASM artifact")
      try await ui.click("#source-graph")
      try await ui.waitUntil("(document.querySelector('#source-graph-host .block-graph-stats')?.textContent ?? '').includes('blocks')", timeout: 30, "the block graph did not finish laying out")
      let evidence = try await ui.value("document.querySelector('#source-graph-host .block-graph-evidence').textContent") as? String ?? ""
      XCTAssertEqual(evidence, "declared", "\(size.name): the header says declared")
      let limits = try await ui.value("(() => { const box = document.querySelector('#source-graph-host .block-graph-limits'); const rect = box.getBoundingClientRect(); return {text: box.textContent, w: rect.width, right: rect.right, windowWidth: innerWidth}; })()") as? [String: Any] ?? [:]
      XCTAssertTrue((limits["text"] as? String ?? "").contains("not a proof"), "\(size.name): the limit stays on screen: \(limits)")
      XCTAssertGreaterThan(limits["w"] as? Double ?? 0, 40, "\(size.name): limits are not clipped away: \(limits)")
      XCTAssertLessThanOrEqual(limits["right"] as? Double ?? 0, limits["windowWidth"] as? Double ?? 0, "\(size.name): limits stay on screen: \(limits)")
      let view = try await ui.value("(() => { const q = s => document.querySelector(s), box = e => e.getBoundingClientRect(); const stage = box(q('#source-graph-host .block-graph-stage')), mini = box(q('#source-graph-host .block-graph-minimap')), foot = box(q('#source-graph-host .block-graph-foot')); return {zoom: parseInt(q('#source-graph-host .block-graph-zoom').textContent, 10), stageHeight: stage.height, miniInside: mini.width > 0 && mini.left >= stage.left && mini.right <= stage.right + 1 && mini.bottom <= stage.bottom + 1, footHeight: foot.height, textWindow: getComputedStyle(q('#source-window')).display}; })()") as? [String: Any] ?? [:]
      XCTAssertGreaterThanOrEqual(view["zoom"] as? Int ?? 0, 90, "\(size.name): the graph opens at a readable zoom: \(view)")
      XCTAssertEqual(view["miniInside"] as? Bool, true, "\(size.name): the minimap is visible inside the stage: \(view)")
      XCTAssertLessThanOrEqual(view["footHeight"] as? Double ?? 99, 30, "\(size.name): the limits footer is one line: \(view)")
      XCTAssertEqual(view["textWindow"] as? String, "none", "\(size.name): text-window rows are hidden in Graph mode: \(view)")
      XCTAssertGreaterThanOrEqual(view["stageHeight"] as? Double ?? 0, 200, "\(size.name): the graph gets most of the height: \(view)")
      try await assertLayout(ui, "#screen-sources", "\(size.name) block graph")
      try await assertInert(ui, "\(size.name) block graph")
      try await ui.screenshot("block-graph-\(size.name)")
      try await ui.click("#source-graph-host .block-graph-canvas")
      try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad])
      try await ui.waitUntil("(document.querySelector('#source-graph-host .block-graph-selection')?.textContent ?? '').includes('loc_')", "arrow keys select a block")
      try await ui.key(36, "\r")
      try await ui.waitUntil("document.querySelector('#source-code [data-graph-reveal]') !== null", "Enter reveals the block offset in the linear view")
      _ = try await ui.value("(document.documentElement.dataset.theme = 'light', 1)")
      try await Task.sleep(nanoseconds: 600_000_000)
      try await ui.screenshot("block-graph-light-\(size.name)")
      _ = try await ui.value("(document.documentElement.dataset.theme = 'dark', 1)")
      try await ui.click("#source-graph")
    }
  }

  // One resident-size sample from `ps`: the app, its web content process, the
  // backend and the agent's tool server. Values are KiB.
  @MainActor
  private func memorySample(_ ui: Harness, _ label: String) throws -> [String: Int] {
    guard let web = (ui.webView.value(forKey: "_webProcessIdentifier") as? NSNumber)?.int32Value else {
      throw HarnessError("WebKit did not name its web content process")
    }
    let app = ProcessInfo.processInfo.processIdentifier
    let backend = Int32(try Harness.required(ProcessInfo.processInfo.environment, "REB_RENDERED_UI_BACKEND_PID")) ?? 0
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/ps")
    process.arguments = ["-axo", "pid=,ppid=,rss=,comm="]
    let pipe = Pipe()
    process.standardOutput = pipe
    try process.run()
    let text = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    var rss: [String: Int] = [:]
    for line in text.split(separator: "\n") {
      let fields = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
      guard fields.count == 4, let pid = Int32(fields[0]), let parent = Int32(fields[1]), let value = Int(fields[2]) else { continue }
      if pid == app { rss["app"] = value }
      if pid == web { rss["web"] = value }
      if pid == backend { rss["backend"] = value }
      if parent == app && fields[3].hasSuffix("OriginTraceAPI") { rss["tool_server", default: 0] += value }
    }
    print("RENDERED_UI_AGENT_MEMORY \(label) app=\(rss["app"] ?? 0) web=\(rss["web"] ?? 0) backend=\(rss["backend"] ?? 0) tool_server=\(rss["tool_server"] ?? 0)")
    return rss
  }

  @MainActor
  private func agentTurnOff(_ ui: Harness) async throws {
    try await ui.click("#agent-more")
    try await ui.waitUntil("!document.getElementById('agent-menu').hidden", "the agent menu did not open")
    try await ui.click("#agent-turn-off")
  }

  // The confirm step is the only confirmation, so its box and the button that
  // names the level are in view together, whole, when it is photographed. A
  // short window scrolls them in when the level is chosen.
  @MainActor
  private func agentConsentShowsLevel(_ ui: Harness, _ label: String, _ size: String) async throws {
    let named = try await ui.value("document.getElementById('agent-consent-accept').textContent") as? String
    XCTAssertEqual(named, "Turn on \(label)", "\(size): the button names the level")
    let shown = try await ui.json("""
      (() => {
        const view = document.getElementById('agent-surface').getBoundingClientRect();
        const box = document.getElementById('agent-consent-details').getBoundingClientRect();
        const button = document.getElementById('agent-consent-accept').getBoundingClientRect();
        return {box: box.top >= view.top - 0.5 && box.bottom <= view.bottom + 0.5,
          button: button.top >= view.top - 0.5 && button.bottom <= view.bottom + 0.5};
      })()
      """)
    XCTAssertEqual(shown["box"] as? Bool, true, "\(size): the whole \(label) box is in view: \(shown)")
    XCTAssertEqual(shown["button"] as? Bool, true, "\(size): the named button is in view: \(shown)")
  }

  @MainActor
  private func agentLayoutIsClean(_ ui: Harness, _ state: String) async throws {
    let issues = try await ui.value("__rebUiProbe.clippedText('#agent-dock')") as? [String] ?? ["no probe result"]
    XCTAssertEqual(issues, [], "\(state): clipped text in the agent dock")
    // No control in the dock is cut off, covered or overlapping another.
    let layout = try await ui.json("__rebUiProbe.layoutIssues('#agent-dock')")
    XCTAssertEqual(layout["issues"] as? [String] ?? ["no probe result"], [], "\(state): agent dock layout")
    let box = try await ui.json("__rebUiProbe.box('#agent-dock')")
    let width = (box["width"] as? Double) ?? 0
    XCTAssert(width >= 280, "\(state): the dock is too narrow: \(box)")
  }

  // The dock's whole path through the packaged app: closed by default, explicit
  // consent, a turn through a local stand-in provider and the real tool server,
  // inert model text, collapsed tool results and the model picker by keyboard,
  // a verified citation that opens Sources, and a full stop.
  // It runs first: later tests load pages the app did not load itself, and the
  // agent bridge, like client-project export, answers only the app's document.
  @MainActor
  func test0AgentPanel() async throws {
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    let on = "['ready', 'running', 'stopped'].includes(document.getElementById('agent-dock').dataset.state)"
    for size in windowSizes {
      try await ui.resize(width: size.width, height: size.height)
      try await ui.reload()
      _ = try memorySample(ui, "closed-\(size.name)")
      let closedByDefault = try await ui.value("document.getElementById('agent-dock').hidden") as? Bool
      XCTAssertEqual(closedByDefault, true, "closed by default")
      try await ui.click("#agent-toggle")
      try await ui.waitUntil("__rebUiProbe.text('#agent-surface').includes('The agent is off')", "the off state did not show")
      _ = try memorySample(ui, "open-off-\(size.name)")
      try await agentLayoutIsClean(ui, "off")
      try await ui.screenshot("agent-off-\(size.name)")
      // Grok is subscription only; without its CLI the account line says so.
      try await ui.click("[data-provider=\"grok\"]")
      try await ui.waitUntil("__rebUiProbe.text('#agent-account-text').includes('Install the Grok CLI')", "the Grok account line did not show")
      let grokLine = try await ui.value("document.querySelector('[data-auth=\"key\"]') === null") as? Bool
      XCTAssertEqual(grokLine, true, "Grok offers no API key path")
      // The whole instruction is readable: the line wraps instead of cutting.
      let grokTextFits = try await ui.value("(() => { const node = document.querySelector('#agent-account-text'); const box = node.getBoundingClientRect(); return node.scrollWidth <= node.clientWidth && box.right <= document.querySelector('#agent-account').getBoundingClientRect().right + 0.5 && getComputedStyle(node).textOverflow !== 'ellipsis'; })()") as? Bool
      XCTAssertEqual(grokTextFits, true, "the Grok account line is cut off at \(size.name)")
      try await agentLayoutIsClean(ui, "grok subscription")
      try await ui.screenshot("agent-grok-\(size.name)")
      try await ui.click("[data-provider=\"claude\"]")
      try await ui.waitUntil("__rebUiProbe.text('#agent-account-text').length > 0 && document.querySelector('[data-provider=\"claude\"]').getAttribute('aria-pressed') === 'true'", "Claude was not selected again")
      // Consent before anything starts.
      try await ui.click("#agent-turn-on")
      try await ui.waitUntil("__rebUiProbe.count('#agent-consent-accept') === 1", "the consent step did not show")
      let consent = try await ui.value("__rebUiProbe.text('#agent-surface')") as? String ?? ""
      XCTAssert(consent.contains("tool result"), "the disclosure names tool results: \(consent)")
      XCTAssert(consent.contains("URLs, hosts"), "the disclosure says results can include URLs and hosts: \(consent)")
      // Four levels, lowest first, with Read only chosen and no warning.
      let levels = try await ui.value("[...document.querySelectorAll('input[name=\"agent-permission\"]')].map(radio => radio.value + (radio.checked ? '*' : '')).join(',')") as? String
      XCTAssertEqual(levels, "read-only*,ask,auto,full", "four levels with Read only chosen")
      let noWarning = try await ui.value("__rebUiProbe.count('#agent-permission-warning')") as? Int
      XCTAssertEqual(noWarning, 0, "Read only needs no warning")
      try await agentLayoutIsClean(ui, "consent")
      try await ui.screenshot("agent-consent-\(size.name)")
      // Auto-approve warns; Full access lists what more leaves the Mac and
      // offers the separate sensitive capture box.
      try await ui.click("#agent-level-auto")
      try await ui.waitUntil("__rebUiProbe.count('#agent-permission-warning') === 1 && __rebUiProbe.count('#agent-sensitive') === 0", "the Auto-approve warning did not show")
      try await agentConsentShowsLevel(ui, "Auto-approve actions", size.name)
      try await agentLayoutIsClean(ui, "consent auto")
      try await ui.screenshot("agent-consent-auto-\(size.name)")
      try await ui.click("#agent-level-full")
      try await ui.waitUntil("__rebUiProbe.count('#agent-sensitive') === 1", "the Full access warning did not show")
      let fullWarning = try await ui.value("__rebUiProbe.text('#agent-permission-warning')") as? String ?? ""
      for item in ["JavaScript and other source text", "Request and response bodies", "Also allow sensitive capture options"] {
        XCTAssert(fullWarning.contains(item), "Full access names \(item): \(fullWarning)")
      }
      try await agentConsentShowsLevel(ui, "Full access", size.name)
      try await agentLayoutIsClean(ui, "consent full")
      try await ui.screenshot("agent-consent-full-\(size.name)")
      try await ui.click("#agent-level-read-only")
      try await ui.waitUntil("__rebUiProbe.count('#agent-permission-warning') === 0", "Read only did not take the warning away")
      try await ui.click("#agent-consent-accept")
      // Earlier rows from this session replace the empty state after a window change.
      try await ui.waitUntil("\(on) && __rebUiProbe.count('#agent-consent-accept') === 0", timeout: 20, "the agent did not turn on")
      let badge = try await ui.value("!document.getElementById('agent-permission').hidden && __rebUiProbe.text('#agent-permission')") as? String
      XCTAssertEqual(badge, "Read only", "the header names the running level")
      try await ui.settle()
      _ = try memorySample(ui, "on-idle-\(size.name)")
      try await ui.screenshot("agent-empty-\(size.name)")
      // Keyboard path: the composer takes focus, Return sends.
      try await ui.click("#agent-input")
      try await ui.type("What loaded?")
      try await ui.key(36, "\r")
      // Each citation is checked on its own, so wait until both have settled:
      // the real one as a link and the invented one labeled, before reading or clicking.
      try await ui.waitUntil(settled("What loaded?"), timeout: 20, "the answer and its citations did not settle")
      let log = try await ui.value("__rebUiProbe.text('#agent-log')") as? String ?? ""
      XCTAssert(log.contains("get_artifacts"), "the tool call is visible: \(log)")
      XCTAssert(log.contains("not verified"), "the invented citation stays labeled: \(log)")
      XCTAssert(log.contains("<img src=x"), "model markup is literal text: \(log)")
      let inert = try await ui.json("__rebUiProbe.inertness([])")
      XCTAssertEqual(inert["executed"] as? Bool, false, "model output must not execute: \(inert)")
      XCTAssertEqual(inert["injectedElements"] as? Int, 0, "model output must not create elements: \(inert)")
      try await agentLayoutIsClean(ui, "conversation")
      try await ui.screenshot("agent-conversation-\(size.name)")
      // Every result the provider received is one key press away, collapsed
      // to a single line until then.
      let collapsed = try await ui.value("document.querySelector('.agent-tool-summary').getAttribute('aria-expanded') === 'false' && __rebUiProbe.exists('.agent-tool-detail') === 0") as? Bool
      XCTAssertEqual(collapsed, true, "tool results start collapsed")
      _ = try await ui.value("(document.querySelector('.agent-tool-summary').focus(), 1)")
      try await ui.key(49, " ")
      try await ui.waitUntil("__rebUiProbe.count('.agent-tool-detail') === 1 && document.activeElement === document.querySelector('.agent-tool-summary')", "Space did not open the tool result")
      // An open result is drawn once and stays mounted. A log rebuilt every
      // frame drops the next click in it, as the citation click below did.
      try await ui.settle()
      let steady = try await ui.value("(async () => { const row = document.querySelector('.agent-tool'); await new Promise(done => { requestAnimationFrame(() => requestAnimationFrame(done)); setTimeout(done, 500); }); return document.querySelector('.agent-tool') === row && __rebUiProbe.count('.agent-tool-detail') === 1; })()") as? Bool
      XCTAssertEqual(steady, true, "an open tool result must not be rebuilt each frame")
      try await agentLayoutIsClean(ui, "tool result")
      try await ui.screenshot("agent-tool-result-\(size.name)")
      try await ui.key(36, "\r")
      try await ui.waitUntil("__rebUiProbe.exists('.agent-tool-detail') === 0", "Return did not close the tool result")
      // The model picker opens, moves and closes from the keyboard.
      _ = try await ui.value("(document.getElementById('agent-model').focus(), 1)")
      try await ui.key(36, "\r")
      try await ui.waitUntil("!document.getElementById('agent-picker').hidden && document.getElementById('agent-picker').contains(document.activeElement)", "Return did not open the model picker")
      let firstItem = try await ui.value("document.activeElement.dataset.focusKey") as? String
      try await ui.key(125, "\u{F701}", modifiers: [.function, .numericPad])
      let movedItem = try await ui.value("document.activeElement.dataset.focusKey") as? String
      XCTAssertNotEqual(firstItem, movedItem, "Down moves through the picker")
      let pickerClipped = try await ui.value("__rebUiProbe.clippedText('#agent-picker')") as? [String] ?? ["no probe result"]
      XCTAssertEqual(pickerClipped, [], "the model picker fits at \(size.name)")
      try await ui.screenshot("agent-picker-\(size.name)")
      try await ui.key(53, "\u{1B}")
      try await ui.waitUntil("document.getElementById('agent-picker').hidden && document.activeElement.id === 'agent-model'", "Escape did not close the picker back to its button")
      // A verified citation opens the existing row.
      try await ui.click(".agent-cite")
      try await ui.waitUntil("!document.getElementById('screen-sources').hidden", timeout: 10, "the citation did not open Sources")
      // An action waits on an explicit decision, and the request takes focus
      // when the researcher is in the dock.
      try await ui.click("#agent-input")
      _ = try await ui.webView.callAsyncJavaScript(#"__rebAgentEvent({type:'approval',turnId:'t',callId:'rendered',name:'capture_action',arguments:'{"action":"pause"}'}); return true;"#, contentWorld: .page)
      try await ui.waitUntil("__rebUiProbe.count('[data-approve]') === 1", "the approval row did not show")
      try await ui.waitUntil("document.activeElement?.classList.contains('agent-approval')", "the approval did not take focus")
      let approval = try await ui.value("__rebUiProbe.text('.agent-approval')") as? String ?? ""
      XCTAssert(approval.contains("Allow once") && !approval.contains("Always"), "only Allow once and Deny are offered: \(approval)")
      try await agentLayoutIsClean(ui, "approval")
      try await ui.screenshot("agent-approval-\(size.name)")
      // A long conversation keeps only nearby rows mounted.
      _ = try await ui.webView.callAsyncJavaScript("""
        for (let index = 0; index < 400; index += 1) {
          __rebAgentEvent({type: 'tool', id: 'long-' + index, turnId: 't', name: 'get_events', arguments: '{"limit":50}', state: 'done',
            result: JSON.stringify({events: Array.from({length: 80}, (_, row) => ({session_id: '1', process_id: '2', sequence_number: String(row), type: 'request_started'}))}),
            resultBytes: 8000, isError: false});
          __rebAgentEvent({type: 'text', rowId: 'long-text-' + index, turnId: 't', delta: 'Observation ' + index + ': ' + 'word '.repeat(120)});
        }
        return true;
        """, contentWorld: .page)
      try await ui.settle()
      try await ui.waitUntil("__rebUiProbe.exists('.agent-rows .agent-row') > 0", "the long transcript did not render")
      let mounted = try await ui.value("__rebUiProbe.exists('.agent-rows .agent-row')") as? Int ?? 0
      XCTAssert(mounted < 200, "a long conversation mounts only nearby rows (\(mounted))")
      _ = try memorySample(ui, "long-conversation-\(size.name)")
      try await agentLayoutIsClean(ui, "long conversation")
      try await ui.screenshot("agent-long-\(size.name)")
      // Turn off, in the header menu, is a full stop.
      try await agentTurnOff(ui)
      try await ui.waitUntil("!\(on) && __rebUiProbe.text('#agent-surface').includes('The agent is off')", timeout: 15, "the agent did not turn off")
      let stopped = try await ui.value("webkit.messageHandlers.rebAgent.postMessage({op: 'status'}).then(status => status.engine.childRunning)") as? Bool
      XCTAssertEqual(stopped, false, "turning off stops the tool server")
      try await ui.click("#agent-close")
      try await ui.waitUntil("document.getElementById('agent-dock').hidden", "the dock did not close")
      _ = try memorySample(ui, "closed-after-\(size.name)")
    }
    // Both themes, at the default size. The saved theme goes back to dark even
    // when a step fails, so later tests start from the theme they expect.
    try await ui.resize(width: windowSizes[0].width, height: windowSizes[0].height)
    try await ui.reload()
    try await ui.click("#theme-toggle")
    do {
      try await ui.waitUntil("document.documentElement.dataset.theme === 'light'", "the light theme did not apply")
      try await ui.click("#agent-toggle")
      try await ui.waitUntil("__rebUiProbe.count('#agent-turn-on') === 1 && !document.getElementById('agent-turn-on').disabled", "the setup state did not show")
      try await ui.screenshot("agent-off-light")
      try await ui.click("#agent-turn-on")
      try await ui.waitUntil("__rebUiProbe.count('#agent-consent-accept') === 1", "the consent step did not show")
      try await ui.screenshot("agent-consent-light")
      try await ui.click("#agent-consent-accept")
      try await ui.waitUntil(on, timeout: 20, "the agent did not turn on")
      try await ui.click("#agent-input")
      try await ui.type("Again")
      try await ui.key(36, "\r")
      try await ui.waitUntil(settled("Again"), timeout: 20, "the light theme answer did not settle")
      try await agentLayoutIsClean(ui, "light")
      try await ui.screenshot("agent-conversation-light")
      try await agentTurnOff(ui)
      try await ui.click("#agent-close")
    } catch {
      try? await restoreDarkTheme(ui)
      throw error
    }
    try await restoreDarkTheme(ui)
    // Full access: consent turns it on with nothing asked after it, the
    // header says Full access, and More lowers it at once without turning
    // the agent off.
    try await ui.reload()
    try await ui.click("#agent-toggle")
    try await ui.waitUntil("__rebUiProbe.count('#agent-turn-on') === 1 && !document.getElementById('agent-turn-on').disabled", "the setup state did not show")
    try await ui.click("#agent-turn-on")
    try await ui.waitUntil("__rebUiProbe.count('#agent-consent-accept') === 1", "the consent step did not show")
    try await ui.click("#agent-level-full")
    try await ui.waitUntil("__rebUiProbe.count('#agent-sensitive') === 1", "the Full access warning did not show")
    try await agentConsentShowsLevel(ui, "Full access", "default")
    try await ui.click("#agent-consent-accept")
    try await ui.waitUntil("\(on) && __rebUiProbe.text('#agent-permission') === 'Full access'", timeout: 20, "Full access did not turn on")
    XCTAssertNil(ui.window.attachedSheet, "consent is the only confirmation: no sheet opens")
    let fullTools = try await ui.value("webkit.messageHandlers.rebAgent.postMessage({op: 'status'}).then(status => [status.engine.permission, status.tools.some(tool => tool.name === 'get_artifact_text')].join(','))") as? String
    XCTAssertEqual(fullTools, "full,true", "native runs Full access with the content reads")
    try await agentLayoutIsClean(ui, "full access")
    try await ui.screenshot("agent-badge-full")
    try await ui.click("#agent-more")
    try await ui.waitUntil("!document.getElementById('agent-menu').hidden && !document.getElementById('agent-lower-read-only').hidden", "the lower choices did not show")
    // The menu is a popover over the log, so only its own text is checked.
    let menuClipped = try await ui.value("__rebUiProbe.clippedText('#agent-menu')") as? [String] ?? ["no probe result"]
    XCTAssertEqual(menuClipped, [], "the lower choices fit in the menu")
    try await ui.screenshot("agent-menu-lower")
    try await ui.click("#agent-lower-read-only")
    try await ui.waitUntil("__rebUiProbe.text('#agent-permission') === 'Read only' && __rebUiProbe.text('#agent-log').includes('Permission lowered to Read only')", timeout: 15, "lowering did not apply")
    let lowered = try await ui.value("webkit.messageHandlers.rebAgent.postMessage({op: 'status'}).then(status => [status.engine.phase, status.engine.permission, status.tools.some(tool => tool.name === 'get_artifact_text')].join(','))") as? String
    XCTAssertEqual(lowered, "ready,read-only,false", "native lowered the level and kept the agent on")
    try await ui.screenshot("agent-badge-lowered")
    try await agentTurnOff(ui)
    try await ui.click("#agent-close")
    // A Claude subscription turn through the real bridge, the stand-in claude
    // CLI and the packaged tool server, then a full stop of the CLI.
    try await ui.reload()
    try await ui.click("#agent-toggle")
    try await ui.click("[data-provider=\"claude\"]")
    try await ui.click("[data-auth=\"subscription\"]")
    try await ui.waitUntil("__rebUiProbe.text('#agent-account-text').includes('through your Claude CLI')", timeout: 20,
      "the Claude CLI did not report its sign-in")
    try await agentLayoutIsClean(ui, "claude subscription")
    try await ui.screenshot("agent-claude-subscription")
    try await ui.click("#agent-turn-on")
    try await ui.waitUntil("__rebUiProbe.count('#agent-consent-accept') === 1", "the subscription consent did not show")
    let disclosure = try await ui.value("__rebUiProbe.text('#agent-surface')") as? String ?? ""
    XCTAssert(disclosure.contains("Claude CLI installed and signed in on this Mac") && disclosure.contains("own local use"),
      "the disclosure names the researcher's own CLI: \(disclosure)")
    try await ui.click("#agent-consent-accept")
    try await ui.waitUntil(on, timeout: 20, "the subscription agent did not turn on")
    try await ui.click("#agent-input")
    try await ui.type("What did the CLI read? SCENARIO:read")
    try await ui.key(36, "\r")
    // "Looking at the session." and get_session_summary come only from the stand-in CLI.
    try await ui.waitUntil("__rebUiProbe.text('#agent-log').includes('Looking at the session.') " +
      "&& [...document.querySelectorAll('.agent-tool-summary')].some(row => row.textContent.includes('get_session_summary') && row.querySelector('.agent-tool-state-done')) " +
      "&& document.getElementById('agent-send').getAttribute('aria-label') === 'Send'", timeout: 30, "the CLI turn did not finish")
    let cliLog = try await ui.value("__rebUiProbe.text('#agent-log')") as? String ?? ""
    XCTAssert(cliLog.contains("get_session_summary"), "the CLI's tool call is visible: \(cliLog)")
    try await agentLayoutIsClean(ui, "claude subscription turn")
    try await ui.screenshot("agent-claude-cli-turn")
    try await agentTurnOff(ui)
    try await ui.waitUntil("!\(on)", timeout: 15, "the subscription agent did not turn off")
    let cliStopped = try await ui.value("webkit.messageHandlers.rebAgent.postMessage({op: 'status'}).then(status => status.engine.cliRunning)") as? Bool
    XCTAssertEqual(cliStopped, false, "turning off ends the CLI")
    try await ui.click("[data-auth=\"key\"]")
    try await ui.click("#agent-close")
  }

  // Earlier rows of this session come back after a reload, citations included,
  // so an answer is the cited row after the latest matching question.
  private func answered(_ question: String) -> String {
    "(() => { const rows = [...document.querySelectorAll('#agent-log .agent-row')]; " +
      "const asked = rows.findLastIndex(row => row.classList.contains('agent-row-user') && row.textContent.includes(\(String(reflecting: question)))); " +
      "return asked >= 0 && rows.slice(asked + 1).some(row => row.querySelector('.agent-cite')); })()"
  }

  private func settled(_ question: String) -> String {
    "(\(answered(question)) && (() => { const rows = [...document.querySelectorAll('#agent-log .agent-row')]; " +
      "const asked = rows.findLastIndex(row => row.classList.contains('agent-row-user') && row.textContent.includes(\(String(reflecting: question)))); " +
      "return rows.slice(asked + 1).some(row => row.querySelector('.agent-cite-note')); })())"
  }

  @MainActor
  private func restoreDarkTheme(_ ui: Harness) async throws {
    _ = try await ui.webView.callAsyncJavaScript(
      "if (document.documentElement.dataset.theme === 'light') document.querySelector('#theme-toggle').click(); return true;", contentWorld: .page)
    try await ui.waitUntil("document.documentElement.dataset.theme === 'dark'", "the dark theme did not come back")
  }

  // A web content process that stops leaves an empty window. The app reloads
  // its workspace once; if it stops again soon after, it asks before reloading.
  @MainActor
  func test23WorkspaceReloadsAfterContentProcessStops() async throws {
    let ui = try Harness()
    try await ui.waitForInitialLoad()
    try await ui.resize(width: windowSizes[0].width, height: windowSizes[0].height)
    try await ui.reload(activating: false)
    let harnessURL = try XCTUnwrap(ui.webView.url)
    let reloaded = "window.__rebOutgoingDocument === undefined && document.readyState === 'complete' && typeof state === 'object' && state.requests.length > 0"
    var observation = try await stopContentProcess(ui)
    try await waitFor("the workspace to reload after its content process stopped", timeout: 10) { reloadStarted }
    observation.invalidate()
    try await ui.waitUntil(reloaded, timeout: 30, "the reloaded workspace did not show its evidence")
    XCTAssertEqual(ui.webView.url, harnessURL, "the same workspace reloads")
    try await ui.screenshot("content-process-reloaded")
    let backstop = Timer(timeInterval: 60, repeats: false) { _ in if NSApp.modalWindow != nil { NSApp.abortModal() } }
    RunLoop.main.add(backstop, forMode: .modalPanel)
    defer { backstop.invalidate() }
    observation = try await stopContentProcess(ui)
    defer { observation.invalidate() }
    do {
      try await waitFor("the repeated-stop decision") { NSApp.modalWindow != nil || reloadStarted }
      XCTAssertFalse(reloadStarted, "a second stop within 30 seconds must ask before reloading")
      let panel = try XCTUnwrap(NSApp.modalWindow)
      XCTAssertTrue(texts(panel).contains("The workspace stopped again"), "\(texts(panel))")
      try await Task.sleep(nanoseconds: 1_500_000_000)
      try ui.screenshot(window: panel, "content-process-stopped-again")
      try XCTUnwrap(button(panel, "Reload")).performClick(nil)
    } catch {
      if NSApp.modalWindow != nil { NSApp.abortModal() }
      throw error
    }
    try await waitFor("Reload to start", timeout: 10) { reloadStarted }
    try await ui.waitUntil(reloaded, timeout: 30, "Reload did not restore the workspace")
    XCTAssertEqual(ui.webView.url, harnessURL)
  }

  // Resident size of this view's WebContent process, from ps. It is a noisy
  // whole-process figure, reported beside the bounded allocations it contains.
  @MainActor
  private func webContentResidentKilobytes(_ ui: Harness) -> Int {
    guard let pid = ui.webView.value(forKey: "_webProcessIdentifier") as? Int32, pid > 0 else { return -1 }
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/ps")
    process.arguments = ["-o", "rss=", "-p", String(pid)]
    process.standardOutput = pipe
    guard (try? process.run()) != nil else { return -1 }
    process.waitUntilExit()
    let text = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    return Int(text.trimmingCharacters(in: .whitespacesAndNewlines)) ?? -1
  }

  // The Sources Map paints one canvas for a whole artifact: a segmented mode
  // control, hover and keyboard cells, a thin summary, and the hex row it opens.
  @MainActor
  func test24SourcesMap() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      try await ui.click("#source-tree [role=treeitem]", containing: "map-module")
      try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('00000000')", "the fixture module did not open as hex")
      let idleRSS = webContentResidentKilobytes(ui)
      try await ui.click("#source-map")
      try await ui.waitUntil("!document.querySelector('.map-body').hidden && document.querySelector('.map-canvas').width > 0", timeout: 90, "the map did not load")
      let side = try await ui.value("document.querySelector('.map-canvas').width") as? Int ?? 0
      let openRSS = webContentResidentKilobytes(ui)
      let pressed = try await ui.value("document.querySelector('#source-map').getAttribute('aria-pressed')") as? String
      XCTAssertEqual(pressed, "true")
      let codeHidden = try await ui.value("document.querySelector('#source-code-wrap').hidden") as? Bool
      XCTAssertEqual(codeHidden, true, "\(size.name): the map replaces the code view")
      let stats = try await ui.value("document.querySelector('.map-stats').innerText") as? String ?? ""
      XCTAssertTrue(stats.contains("Hilbert \(side)×\(side)"), "\(size.name): the header states the grid: \(stats)")
      XCTAssertTrue(stats.contains("per cell"), "\(size.name): the header states the cell size: \(stats)")
      let summary = try await ui.value("document.querySelector('.map-summary').textContent") as? String ?? ""
      XCTAssertTrue(summary.contains("≥ 7.0"), "\(size.name): the threshold is stated: \(summary)")
      XCTAssertTrue(summary.contains("Segments"), "\(size.name): data segments are counted: \(summary)")
      let body = try await ui.value("document.querySelector('#source-map-view').innerText") as? String ?? ""
      for word in ["packed", "Packed", "encrypted", "Encrypted"] {
        XCTAssertFalse(body.contains(word), "\(size.name): the map draws no conclusion about \(word)")
      }
      let square = try await ui.json("(() => { const box = document.querySelector('.map-canvas').getBoundingClientRect(); return {width: box.width, height: box.height}; })()")
      XCTAssertEqual(square["width"] as? Double ?? 0, square["height"] as? Double ?? -1, accuracy: 1, "\(size.name): the map is square: \(square)")
      XCTAssertGreaterThan(square["width"] as? Double ?? 0, 150, "\(size.name): the map stays readable: \(square)")
      // The square and its legend sit inside the view, not clipped by it.
      try await assertFullyVisible(ui, ".map-frame", "\(size.name) map square")
      try await assertFullyVisible(ui, ".map-ramp", "\(size.name) map legend")
      try await assertLayout(ui, "#source-map-view", "\(size.name) sources map")
      try await assertInert(ui, "\(size.name) sources map")
      try await ui.screenshot("sources-map-entropy-\(size.name)")

      try await ui.click(".map-modes [data-map-mode='kind']")
      try await ui.waitUntil("document.querySelector(\".map-modes [data-map-mode='kind']\").getAttribute('aria-pressed') === 'true' && !document.querySelector('.map-kind-legend').hidden", "kind mode did not apply")
      let legend = try await ui.value("document.querySelector('.map-kind-legend').textContent") as? String ?? ""
      XCTAssertTrue(legend.contains("data"), "\(size.name): the legend names present kinds: \(legend)")
      try await assertLayout(ui, "#source-map-view", "\(size.name) sources map kind")
      try await ui.screenshot("sources-map-kind-\(size.name)")
      try await ui.click(".map-modes [data-map-mode='entropy']")

      _ = try await ui.value("document.documentElement.dataset.theme = 'light'")
      try await ui.waitUntil("document.documentElement.dataset.theme === 'light'", "light theme did not apply")
      try await ui.screenshot("sources-map-light-\(size.name)")
      try await assertLayout(ui, "#source-map-view", "\(size.name) sources map light")
      _ = try await ui.value("document.documentElement.dataset.theme = 'dark'")

      _ = try await ui.value("document.querySelector('.map-canvas').focus()")
      let before = try await ui.value("document.querySelector('.map-cell-focus').hidden") as? Bool
      try await ui.key(124, "\u{F703}") // Right arrow moves the visible focused cell.
      try await ui.waitUntil("!document.querySelector('.map-cell-focus').hidden", "the keyboard cell did not appear (was hidden: \(String(describing: before)))")
      let announced = try await ui.value("document.querySelector('#source-map-view .map-announce').textContent") as? String ?? ""
      XCTAssertTrue(announced.contains("entropy"), "\(size.name): the focused cell is announced: \(announced)")
      try await ui.screenshot("sources-map-focus-\(size.name)")
      try await ui.key(36, "\r") // Enter opens the bytes.
      try await ui.waitUntil("document.querySelector('#source-map-view').hidden && !document.querySelector('#source-code-wrap').hidden", "Enter did not open the bytes")
      let position = try await ui.value("document.querySelector('#source-position').innerText") as? String ?? ""
      XCTAssertTrue(position.contains("hex row"), "\(size.name): Sources lands at the byte: \(position)")
      let releasedWidth = try await ui.value("document.querySelector('.map-canvas').width") as? Int
      XCTAssertEqual(releasedWidth, 0, "\(size.name): the bitmap is released")
      print("RENDERED_UI_MAP_RSS \(size.name) idle_kb=\(idleRSS) open_kb=\(openRSS) released_kb=\(webContentResidentKilobytes(ui)) side=\(side)")
    }
  }

  // Narrowing the window with a Wasm module open keeps Inspect, Graph, Map and
  // More on one toolbar row that the code view never covers; widening it back
  // leaves no blank band. The toolbar's grid row once kept its old height after
  // a width change, so a wrapped second row slid under the code.
  @MainActor
  func test24bSourcesToolbarAfterResize() async throws {
    let ui = try await prepare(windowSizes[0])
    try await show(ui, "sources")
    try await ui.click("#source-tree [role=treeitem]", containing: "map-module")
    try await ui.waitUntil("(document.querySelector('#source-code')?.innerText ?? '').includes('00000000')", "the fixture module did not open as hex")
    let measure = """
      (() => {
        const bar = document.querySelector('.source-editor-toolbar'), menu = document.querySelector('.source-more-menu');
        const top = bar.getBoundingClientRect().top;
        const rows = [...bar.querySelectorAll(':scope > *')].filter(c => c.getClientRects().length && getComputedStyle(c).position !== 'absolute');
        const tools = ['#source-wasm', '#source-graph', '#source-map', '#source-more'].map(s => document.querySelector(s)).filter(t => !menu.contains(t));
        return {height: bar.getBoundingClientRect().height, content: Math.max(...rows.map(c => c.getBoundingClientRect().bottom)) - top,
          rowTops: new Set(tools.map(t => Math.round(t.getBoundingClientRect().top))).size};
      })()
      """
    for (step, size) in [("narrowed", windowSizes[1]), ("widened", windowSizes[0])] {
      try await ui.resize(width: size.width, height: size.height)
      let toolbar = try await ui.json(measure)
      XCTAssertEqual(toolbar["rowTops"] as? Int, 1, "\(step): the toolbar commands share one row: \(toolbar)")
      // The row holds its content and 4 px of padding plus the 1 px border, nothing more.
      let spare = (toolbar["height"] as? Double ?? 0) - (toolbar["content"] as? Double ?? 0)
      XCTAssertEqual(spare, 5, accuracy: 2, "\(step): the toolbar row matches its content: \(toolbar)")
      try await assertLayout(ui, "#screen-sources", "\(step) sources toolbar with a Wasm module")
      try await ui.screenshot("sources-toolbar-wasm-\(step)")
    }
  }

  // The panel sits inside the workspace beside the sidebar and under the
  // titlebar, with nothing clipped, its actions in view and its focus shown.
  @MainActor
  private func assertStartPanelFits(_ ui: Harness, _ context: String) async throws {
    try await assertLayout(ui, "#session-panel", context)
    let geometry = try await ui.json("""
      (() => { const box = selector => document.querySelector(selector).getBoundingClientRect().toJSON();
        return {panel: box('#session-panel'), workspace: box('#workspace'), titlebar: box('.titlebar'), sidebar: box('#sidebar')}; })()
      """)
    print("RENDERED_UI_START_PANEL \(context) \(geometry)")
    let panel = geometry["panel"] as? [String: Double] ?? [:]
    let workspace = geometry["workspace"] as? [String: Double] ?? [:]
    XCTAssertGreaterThanOrEqual(panel["left"] ?? -1, (workspace["left"] ?? 0) - 1, "\(context): the panel stays in the workspace: \(geometry)")
    XCTAssertLessThanOrEqual(panel["right"] ?? .infinity, (workspace["right"] ?? 0) + 1, "\(context): \(geometry)")
    XCTAssertGreaterThanOrEqual(panel["top"] ?? -1, (geometry["titlebar"] as? [String: Double])?["bottom"] ?? 0, "\(context): under the titlebar: \(geometry)")
    XCTAssertLessThanOrEqual(panel["bottom"] ?? .infinity, (workspace["bottom"] ?? 0) + 1, "\(context): \(geometry)")
    XCTAssertGreaterThanOrEqual(panel["left"] ?? -1, (geometry["sidebar"] as? [String: Double])?["right"] ?? 0, "\(context): clear of the sidebar: \(geometry)")
    for selector in ["#session-panel .session-panel-title", "#session-panel .session-panel-action-row"] {
      let exists = try await ui.value("Boolean(document.querySelector(\(String(reflecting: selector))))") as? Bool
      if exists == true { try await assertFullyVisible(ui, selector, "\(context) \(selector)") }
    }
  }

  // A dedicated worker's request stack and its async callers resolve in their
  // own isolates (protocol/native-network-v3.md): a Promise.then registration
  // in the worker, a MessagePort post from another renderer, and a task
  // scheduled with no script, with the callers still not shown listed.
  @MainActor
  func test30WorkerInitiatorStack() async throws {
    let expected = try Expectations.load()
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "traffic")
      try await ui.click("#screen-traffic .request-row", containing: expected.workerStackHost)
      try await ui.waitUntil("!document.querySelector('#screen-traffic .detail-pane').hidden", "request detail did not open")
      let initiatorCell = try await ui.value("document.querySelector('#screen-traffic .request-row[aria-selected=\"true\"] .request-initiator')?.innerText ?? ''") as? String ?? ""
      XCTAssertTrue(initiatorCell.contains("worker.js:2"), "\(size.name): the Initiator column names the worker frame: \(initiatorCell)")
      try await ui.click("#inspector-tab-initiator")
      try await ui.waitUntil("(document.querySelector('#request-inspector')?.innerText ?? '').includes('MessagePort.postMessage')", "the worker stack did not resolve")
      let panel = try await ui.value("document.querySelector('#request-inspector').innerText") as? String ?? ""
      for phrase in ["Started in a dedicated worker.", "work @ worker.js:2:", "Promise.then", "start @ worker.js:5:",
                     "MessagePort.postMessage · on the document main thread in process \(expected.workerStackPostingProcess)",
                     "post @ page.js:2:", "scheduled while no script ran",
                     "Async callers not shown: ServiceWorker.postMessage and Client.postMessage"] {
        XCTAssertTrue(panel.contains(phrase), "\(size.name): Initiator shows \(phrase): \(panel)")
      }
      XCTAssertFalse(panel.contains("Earlier async callers were not recorded"), "\(size.name): a no-script end is not a cut chain")
      try await assertInert(ui, "\(size.name) worker initiator stack")
      try await assertLayout(ui, "#screen-traffic .detail-pane", "\(size.name) worker initiator stack")
      try await ui.screenshot("traffic-initiator-worker-\(size.name)")
    }
  }

  // The start panel through a whole decision at both window sizes. The harness
  // names a REB_BRAVE_BINARY that does not exist, so Start fails at once and
  // nothing launches. The panel must fit, reach every control by keyboard with
  // visible focus, offer no Keychain choice, start with the mode chosen by
  // keyboard, come back as a failure with Retry focused and that same mode,
  // fail afresh on Retry, and leave the offline workspace on Continue Offline.
  @MainActor
  func test27StartPanelStartRetryAndKeyboard() async throws {
    let ui = try await prepare(windowSizes[0])
    let harnessURL = try XCTUnwrap(ui.webView.url)
    // No saved sites, so the panel's controls are the same whatever ran before.
    try await clearSavedSites(ui)
    let focus = { try await ui.json("__rebUiProbe.focusState()") }
    // Normal chooses Metadata; narrow, opened with that mode remembered for
    // the run, chooses Content again.
    let plans: [(size: (name: String, width: CGFloat, height: CGFloat), from: String, to: String, arrow: UInt16)] = [
      (windowSizes[0], "content", "metadata", 125), (windowSizes[1], "metadata", "content", 126),
    ]
    do {
      for plan in plans {
        let name = plan.size.name
        try await ui.resize(width: plan.size.width, height: plan.size.height)
        try await openStartPanel(ui)
        try await ui.activate()
        let opened = try await ui.json(
          "({mode: document.querySelector('#session-panel input[name=\"session-panel-mode\"]:checked')?.value, checkboxes: document.querySelectorAll('#session-panel input[type=checkbox]').length, keychain: /keychain/i.test(document.querySelector('#session-panel').innerText)})")
        XCTAssertEqual(opened["mode"] as? String, plan.from, "\(name): the panel opens with this run's last mode: \(opened)")
        XCTAssertEqual(opened["checkboxes"] as? Int, 0, "\(name): the panel has no Keychain checkbox: \(opened)")
        XCTAssertEqual(opened["keychain"] as? Bool, false, "\(name): the panel says nothing about the Keychain: \(opened)")
        let initial = try await focus()
        XCTAssertEqual(initial["id"] as? String, "session-panel-start", "\(name): Start Session is focused, as the alert's default was: \(initial)")
        try await assertStartPanelFits(ui, "\(name) start panel")
        try await ui.screenshot("start-panel-\(name)")

        // Shift+Tab walks back through every control to the chosen mode.
        var stops: [String] = []
        for _ in 0..<8 {
          try await ui.tab(shift: true)
          let stop = try await focus()
          stops.append(stop["id"] as? String ?? "\(stop["element"] ?? "?")")
          XCTAssertEqual(stop["focusVisible"] as? Bool, true, "\(name): \(stop)")
          // A mode input draws its ring on the whole option card.
          let ring = try await ui.value("""
            (() => { const focused = document.activeElement;
              const shown = getComputedStyle(focused.closest('.session-panel-mode') ?? focused);
              return shown.outlineStyle !== 'none' && parseFloat(shown.outlineWidth) > 0; })()
            """) as? Bool
          XCTAssertEqual(ring, true, "\(name): a focus ring shows around \(stop)")
          XCTAssertEqual(stop["inViewport"] as? Bool, true, "\(name): \(stop)")
          if stops.last?.hasPrefix("session-panel-mode-") == true { break }
        }
        print("RENDERED_UI_START_PANEL_FOCUS \(name) \(stops)")
        XCTAssertEqual(stops, ["session-panel-offline", "session-panel-mode-\(plan.from)"],
          "\(name): the panel's controls in reverse order")
        try await ui.screenshot("start-panel-focus-\(name)")
        // Arrow keys choose within the mode group.
        try await ui.key(plan.arrow, plan.arrow == 125 ? "\u{F701}" : "\u{F700}")
        let moved = try await ui.json(
          "({focus: document.activeElement?.id, text: document.querySelector('#session-panel').innerText})")
        XCTAssertEqual(moved["focus"] as? String, "session-panel-mode-\(plan.to)", "\(name): the arrow moved the choice: \(moved)")
        try await ui.tab()
        try await ui.tab()
        let start = try await focus()
        XCTAssertEqual(start["id"] as? String, "session-panel-start", "\(name): Tab returns to Start Session: \(start)")
        try await ui.screenshot("start-panel-chosen-\(name)")

        // Return starts; the named Brave does not exist, so the start fails.
        try await ui.key(36, "\r")
        try await ui.waitUntil("document.querySelector('#session-panel')?.dataset.state === 'failed'", "\(name): Start did not report its failure")
        let failure = try await panelText(ui)
        let chosen = "\(plan.to == "metadata" ? "Metadata only" : "Content (default)")."
        XCTAssertTrue(failure.contains("Live session unavailable"), "\(name): \(failure)")
        XCTAssertTrue(failure.contains("REB_BRAVE_BINARY names"), "\(name): the failure names the cause: \(failure)")
        XCTAssertTrue(failure.contains("Retry starts a new session with the same capture mode: \(chosen)"),
          "\(name): native started with the mode chosen in the panel: \(failure)")
        let retryFocus = try await focus()
        XCTAssertEqual(retryFocus["id"] as? String, "session-panel-retry", "\(name): Retry is focused: \(retryFocus)")
        try await assertStartPanelFits(ui, "\(name) start failure")
        try await ui.screenshot("start-panel-failure-\(name)")

        // Return on Retry starts again and reports a fresh failure.
        _ = try await ui.value("(document.querySelector('#session-panel-failure').dataset.earlier = 'true', true)")
        try await ui.key(36, "\r")
        try await ui.waitUntil(
          "document.querySelector('#session-panel')?.dataset.state === 'failed' && document.querySelector('#session-panel-failure')?.dataset.earlier === undefined",
          "\(name): Retry did not start again")
        let retried = try await panelText(ui)
        XCTAssertTrue(retried.contains("Retry starts a new session with the same capture mode: \(chosen)"), "\(name): Retry keeps the mode: \(retried)")
        let again = try await focus()
        XCTAssertEqual(again["id"] as? String, "session-panel-retry", "\(name): Retry is focused again: \(again)")

        try await ui.click("#session-panel-offline")
        try await ui.waitUntil("document.querySelector('#session-panel').hidden", "\(name): Continue Offline did not close the panel")
        let after = try await ui.json("({protocol: location.protocol, focus: __rebUiProbe.focusState().element})")
        XCTAssertEqual(after["protocol"] as? String, "reb:", "\(name): the offline workspace stays: \(after)")
        XCTAssertNotEqual(after["focus"] as? String, "body", "\(name): focus returns to the workspace: \(after)")
        try await ui.screenshot("start-panel-offline-\(name)")
      }
    } catch {
      try? await returnToHarness(ui, harnessURL)
      throw error
    }
    try await returnToHarness(ui, harnessURL)
  }

  // Runs only in the driver's launch pass, where the app starts as a
  // researcher opens it: no --ui-url, automatic live sessions on, stores that
  // do not exist yet and a REB_BRAVE_BINARY that does not exist. Launch must
  // start a Content session at once, without the start panel. The missing
  // Brave makes that start fail, so the panel shows only the failure, which
  // proves the start ran. A reopen while the failure is open starts nothing,
  // Return on Retry starts again, and after Continue Offline a reopen starts
  // nothing for the rest of the run.
  @MainActor
  func testLaunchStartsWithoutStartPanel() async throws {
    guard ProcessInfo.processInfo.environment["REB_RENDERED_UI_LAUNCH"] == "1" else {
      throw XCTSkip("Runs in the driver's launch pass, where the app starts without --ui-url")
    }
    let ui = try Harness()
    let failed = "location.protocol === 'reb:' && document.readyState === 'complete' && typeof state === 'object' "
      + "&& document.querySelector('#session-panel')?.dataset.state === 'failed'"
    try await ui.waitUntil(failed, timeout: 30, "launch did not start a session (its failure never showed)")
    let workspaceURL = ui.webView.url
    try await ui.activate()
    for size in windowSizes {
      try await ui.resize(width: size.width, height: size.height)
      let text = try await panelText(ui)
      XCTAssertFalse(text.contains("Start a live research session"), "\(size.name): launch does not ask first: \(text)")
      let noStart = try await ui.value("document.querySelector('#session-panel-start') === null") as? Bool
      XCTAssertEqual(noStart, true, "\(size.name): launch shows no Start Session")
      XCTAssertTrue(text.contains("Live session unavailable"), "\(size.name): \(text)")
      XCTAssertTrue(text.contains("REB_BRAVE_BINARY names"), "\(size.name): the failure names the cause: \(text)")
      XCTAssertTrue(text.contains("Content (default)"), "\(size.name): launch started the default Content mode: \(text)")
      let shown = try await ui.json("({traffic: !document.querySelector('#screen-traffic').hidden, focus: document.activeElement?.id})")
      XCTAssertEqual(shown["traffic"] as? Bool, true, "\(size.name): the workspace is open beside the failure: \(shown)")
      XCTAssertEqual(shown["focus"] as? String, "session-panel-retry", "\(size.name): Retry is focused: \(shown)")
      try await assertStartPanelFits(ui, "\(size.name) launch failure")
      try await ui.screenshot("launch-failure-\(size.name)")
    }
    // A start would fail at once on the missing Brave and redraw the failure.
    _ = try await ui.value("(document.querySelector('#session-panel-failure').dataset.earlier = 'true', true)")
    try await ui.reopen()
    try await Task.sleep(nanoseconds: 2_000_000_000)
    let reopened = try await ui.json(
      "({state: document.querySelector('#session-panel')?.dataset.state, earlier: document.querySelector('#session-panel-failure')?.dataset.earlier})")
    XCTAssertEqual(reopened["state"] as? String, "failed", "a reopen keeps the open failure: \(reopened)")
    XCTAssertEqual(reopened["earlier"] as? String, "true", "a reopen while the failure is open starts nothing: \(reopened)")
    XCTAssertEqual(ui.webView.url, workspaceURL, "a reopen keeps the document")

    try await ui.key(36, "\r")
    try await ui.waitUntil(
      "document.querySelector('#session-panel')?.dataset.state === 'failed' && document.querySelector('#session-panel-failure')?.dataset.earlier === undefined",
      "Return on Retry did not start again")
    try await ui.click("#session-panel-offline")
    try await ui.waitUntil("document.querySelector('#session-panel').hidden", "Continue Offline did not close the panel")
    try await ui.reopen()
    try await Task.sleep(nanoseconds: 2_000_000_000)
    let offline = try await ui.value("document.querySelector('#session-panel').hidden") as? Bool
    XCTAssertEqual(offline, true, "after Continue Offline a reopen starts nothing for the run")
    try await ui.screenshot("launch-offline-after-reopen")
  }

  // The paused-state sections in the sidebar while no browser serves the
  // pausing debugger: the statement names them, and every control they draw
  // is really disabled, so nothing here can be operated against a debugger
  // that is not there.
  func test32PausingSections() async throws {
    for size in windowSizes {
      let ui = try await prepare(size)
      try await show(ui, "sources")
      try await ui.click("#source-debugger-toggle")
      try await ui.waitUntil("document.querySelector('#debugger-sidebar [data-debugger-native=\"availability\"]') !== null",
        "\(size.name): the Pausing statement did not render")
      // Every pausing section starts expanded; a closed one is opened the way
      // a researcher would, through its own disclosure.
      for id in ["pause", "breakpoints", "call-stack", "scope", "watch"] {
        let closed = try await ui.value("""
          (() => { const node = document.querySelector('#debugger-sidebar [data-debugger-section="\(id)"]');
            return Boolean(node) && node.tagName === 'DETAILS' && !node.open; })()
          """) as? Bool
        if closed == true { try await ui.click("#debugger-sidebar [data-debugger-section=\"\(id)\"] summary") }
      }
      try await ui.waitUntil("document.querySelectorAll('#debugger-sidebar [data-debugger-native=\"pausing\"] button, #debugger-sidebar [data-debugger-native=\"pausing\"] input').length > 0",
        "\(size.name): the pausing sections drew no controls")
      let state = try await ui.json("""
        (() => {
          const sidebar = document.querySelector('#debugger-sidebar');
          const sections = [...sidebar.querySelectorAll('[data-debugger-section]')].map(node => node.dataset.debuggerSection);
          const pausing = [...sidebar.querySelectorAll('[data-debugger-native="pausing"]')].map(node => node.dataset.debuggerSection);
          const controls = [...sidebar.querySelectorAll('[data-debugger-native="pausing"] button, [data-debugger-native="pausing"] input, [data-debugger-native="pausing"] select, [data-debugger-native="pausing"] textarea')];
          const reachable = [...sidebar.querySelectorAll('[data-debugger-native="pausing"] a[href], [data-debugger-native="pausing"] [tabindex], [data-debugger-native="pausing"] summary, [data-debugger-native="pausing"] [role=button], [data-debugger-native="pausing"] [contenteditable]')];
          return {sections, pausing, controls: controls.length,
            enabled: controls.filter(control => !control.disabled).map(control => control.innerText || control.placeholder || control.type),
            reachable: reachable.length,
            statement: document.querySelector('[data-debugger-native="availability"]').innerText.replace(/\\s+/g, ' '),
            availability: document.querySelector('[data-debugger-native="availability"]').dataset.availability};
        })()
        """)
      print("RENDERED_UI_PAUSING \(size.name) \(state)")
      XCTAssertEqual(state["availability"] as? String, "unsupported", "\(size.name): \(state)")
      XCTAssertEqual(state["pausing"] as? [String], ["pause", "breakpoints", "call-stack", "scope", "watch"],
        "\(size.name): the five pausing sections are registered and marked: \(state)")
      XCTAssertEqual(Array((state["sections"] as? [String] ?? []).prefix(4)), ["threads", "watch-rules", "observations", "pausing"],
        "\(size.name): they follow the phase 1 sections: \(state)")
      XCTAssertGreaterThan(state["controls"] as? Int ?? 0, 5, "\(size.name): the sections draw their controls: \(state)")
      XCTAssertEqual(state["enabled"] as? [String], [],
        "\(size.name): every control is disabled while the debugger is unsupported: \(state)")
      XCTAssertEqual(state["reachable"] as? Int, 0,
        "\(size.name): nothing that cannot be disabled is drawn: \(state)")
      let statement = state["statement"] as? String ?? ""
      XCTAssertTrue(statement.contains("No Brave build serves the pausing debugger"), "\(size.name): \(statement)")
      XCTAssertTrue(statement.contains("stay disabled"), "\(size.name): the statement says the controls are disabled: \(statement)")
      for title in ["Pause", "Breakpoints", "Call stack", "Scope", "Watch"] {
        XCTAssertTrue(statement.contains(title), "\(size.name): the statement names \(title): \(statement)")
      }
      try await assertInert(ui, "\(size.name) pausing sections")
      try await assertLayout(ui, "#debugger-sidebar", "\(size.name) pausing sections")
      try await ui.screenshot("debugger-pausing-sections-\(size.name)")
      try await lightScreenshot(ui, "debugger-pausing-sections", size.name)
    }
  }
}
