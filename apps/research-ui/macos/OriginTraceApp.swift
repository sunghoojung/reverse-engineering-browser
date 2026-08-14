import Cocoa
import Foundation
import WebKit

private final class LocalContentHandler: NSObject, WKURLSchemeHandler {
  private let indexURL: URL
  private let eventStoreURL: URL
  private let artifactStoreURL: URL
  private let brokerSocketURL: URL?

  init(indexURL: URL, eventStoreURL: URL, artifactStoreURL: URL, brokerSocketURL: URL?) {
    self.indexURL = indexURL
    self.eventStoreURL = eventStoreURL
    self.artifactStoreURL = artifactStoreURL
    self.brokerSocketURL = brokerSocketURL
  }

  func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
    if ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1" {
      print("SMOKE_RESOURCE \(urlSchemeTask.request.url?.absoluteString ?? "invalid")")
    }
    guard let requestURL = urlSchemeTask.request.url else {
      sendError("Invalid application URL", status: 400, to: urlSchemeTask)
      return
    }

    do {
      let response: (Data, String, [String: String])
      switch requestURL.path {
      case "", "/", "/index.html":
        response = (try Data(contentsOf: indexURL), "text/html; charset=utf-8", [:])
      case "/api/health":
        response = (try healthResponse(), "application/json; charset=utf-8", [:])
      case "/api/events":
        response = (try eventsResponse(for: requestURL), "application/json; charset=utf-8", [:])
      case "/api/artifacts":
        response = (try artifactsResponse(for: requestURL), "application/json; charset=utf-8", [:])
      default:
        if requestURL.path.hasPrefix("/api/artifacts/") && requestURL.path.hasSuffix("/content") {
          let content = try artifactContentResponse(for: requestURL)
          response = (content.0, "application/octet-stream", content.1)
        } else {
          sendError("Application resource not found", status: 404, to: urlSchemeTask)
          return
        }
      }
      send(response.0, contentType: response.1, status: 200, headers: response.2, to: urlSchemeTask)
    } catch {
      sendError(error.localizedDescription, status: 500, to: urlSchemeTask)
    }
  }

  func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}

  private func healthResponse() throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "status": "ok",
        "store": eventStoreURL.path,
        "store_exists": FileManager.default.fileExists(atPath: eventStoreURL.path),
        "artifact_store": artifactStoreURL.path,
        "artifact_store_exists": FileManager.default.fileExists(atPath: artifactStoreURL.path),
        "broker_connected": brokerConnected(),
      ],
      options: []
    )
  }

  private func eventsResponse(for requestURL: URL) throws -> Data {
    let requestedLimit = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?
      .queryItems?
      .first(where: { $0.name == "limit" })?
      .value
      .flatMap(Int.init) ?? 500
    let limit = min(max(requestedLimit, 1), 5000)

    guard FileManager.default.fileExists(atPath: eventStoreURL.path) else {
      return try JSONSerialization.data(
        withJSONObject: ["count": 0, "events": [], "broker_connected": brokerConnected()],
        options: []
      )
    }

    let contents = try String(contentsOf: eventStoreURL, encoding: .utf8)
    let lines = contents.split(whereSeparator: \Character.isNewline).suffix(limit)
    var events: [[String: Any]] = []
    events.reserveCapacity(lines.count)
    for line in lines {
      let value = try JSONSerialization.jsonObject(with: Data(line.utf8), options: [])
      guard let event = value as? [String: Any] else {
        throw NSError(
          domain: "OriginTrace",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "The evidence store contains a malformed event"]
        )
      }
      events.append(event)
    }
    return try JSONSerialization.data(
      withJSONObject: [
        "count": events.count,
        "events": events,
        "broker_connected": brokerConnected(),
      ],
      options: []
    )
  }

  private func artifactEntries() throws -> [[String: Any]] {
    let manifestURL = artifactStoreURL.appendingPathComponent("manifest.jsonl")
    guard FileManager.default.fileExists(atPath: manifestURL.path) else {
      return []
    }
    let contents = try String(contentsOf: manifestURL, encoding: .utf8)
    var artifacts: [[String: Any]] = []
    var artifactIDs = Set<String>()
    for line in contents.split(whereSeparator: \Character.isNewline) {
      let value = try JSONSerialization.jsonObject(with: Data(line.utf8), options: [])
      guard let artifact = value as? [String: Any], isValidArtifact(artifact) else {
        throw artifactError("The artifact manifest contains a malformed record")
      }
      guard let artifactID = artifact["artifact_id"] as? String,
        artifactIDs.insert(artifactID).inserted
      else {
        throw artifactError("The artifact manifest contains a duplicate artifact ID")
      }
      artifacts.append(artifact)
    }
    return artifacts
  }

  private func isValidArtifact(_ artifact: [String: Any]) -> Bool {
    guard let protocolVersion = artifact["protocol_version"] as? NSNumber,
      CFGetTypeID(protocolVersion) != CFBooleanGetTypeID(),
      protocolVersion.stringValue == "1",
      let kind = artifact["kind"] as? String,
      Set(["javascript", "wasm", "source_map", "response_body"]).contains(kind),
      let url = artifact["url"] as? String,
      !url.isEmpty,
      let mimeType = artifact["mime_type"] as? String,
      !mimeType.isEmpty,
      let byteSize = artifact["byte_size"] as? NSNumber,
      CFGetTypeID(byteSize) != CFBooleanGetTypeID(),
      byteSize.stringValue.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      Int(byteSize.stringValue) != nil,
      let sha256 = artifact["sha256"] as? String,
      sha256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
      let sensitive = artifact["sensitive"] as? Bool,
      sensitive == (kind == "response_body"),
      artifact["content_path"] as? String == "blobs/\(sha256).bin"
    else {
      return false
    }
    return [
      "artifact_id", "session_id", "navigation_id", "frame_id", "parent_artifact_id",
      "creator_event_id",
    ].allSatisfy { field in
      guard let value = artifact[field] as? String,
        value.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil
      else {
        return false
      }
      return UInt64(value) != nil
    }
  }

  private func artifactError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace",
      code: 3,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }

  private func artifactsResponse(for requestURL: URL) throws -> Data {
    let requestedLimit = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?
      .queryItems?
      .first(where: { $0.name == "limit" })?
      .value
      .flatMap(Int.init) ?? 500
    let limit = min(max(requestedLimit, 1), 5000)
    let privateFields = Set(["content_path"])
    let artifacts = try artifactEntries().suffix(limit).map { artifact in
      artifact.filter { !privateFields.contains($0.key) }
    }
    return try JSONSerialization.data(
      withJSONObject: ["count": artifacts.count, "artifacts": artifacts],
      options: []
    )
  }

  private func artifactContentResponse(for requestURL: URL) throws -> (Data, [String: String]) {
    let components = requestURL.path.split(separator: "/")
    guard components.count == 4,
      components[0] == "api",
      components[1] == "artifacts",
      components[3] == "content"
    else {
      throw NSError(
        domain: "OriginTrace",
        code: 4,
        userInfo: [NSLocalizedDescriptionKey: "Invalid artifact content path"]
      )
    }
    let artifactID = String(components[2])
    guard artifactID.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      let artifact = try artifactEntries().first(where: { ($0["artifact_id"] as? String) == artifactID }),
      let relativePath = artifact["content_path"] as? String,
      let byteSize = artifact["byte_size"] as? Int,
      byteSize >= 0
    else {
      throw NSError(
        domain: "OriginTrace",
        code: 5,
        userInfo: [NSLocalizedDescriptionKey: "Artifact not found"]
      )
    }

    let root = artifactStoreURL.resolvingSymlinksInPath().standardizedFileURL
    let contentURL = root.appendingPathComponent(relativePath).resolvingSymlinksInPath().standardizedFileURL
    guard contentURL.path.hasPrefix(root.path + "/") else {
      throw NSError(
        domain: "OriginTrace",
        code: 6,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content path escapes the artifact store"]
      )
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: contentURL.path)
    guard let storedSize = attributes[.size] as? NSNumber, storedSize.intValue == byteSize else {
      throw NSError(
        domain: "OriginTrace",
        code: 7,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content does not match its manifest"]
      )
    }

    let query = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
    let requestedOffset = query.first(where: { $0.name == "offset" })?.value.flatMap(Int.init) ?? 0
    let requestedLimit = query.first(where: { $0.name == "limit" })?.value.flatMap(Int.init) ?? 2 * 1024 * 1024
    let offset = max(0, requestedOffset)
    let limit = min(max(requestedLimit, 1), 2 * 1024 * 1024)
    guard offset <= byteSize else {
      throw NSError(
        domain: "OriginTrace",
        code: 8,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content offset exceeds byte size"]
      )
    }
    let handle = try FileHandle(forReadingFrom: contentURL)
    defer { try? handle.close() }
    try handle.seek(toOffset: UInt64(offset))
    let data = try handle.read(upToCount: limit) ?? Data()
    return (
      data,
      [
        "Content-Security-Policy": "sandbox",
        "Content-Disposition": "attachment; filename=artifact.bin",
        "X-Content-Type-Options": "nosniff",
        "X-Artifact-Total-Bytes": String(byteSize),
        "X-Artifact-Offset": String(offset),
        "X-Artifact-Truncated": offset + data.count < byteSize ? "1" : "0",
      ]
    )
  }

  private func brokerConnected() -> Bool {
    guard let brokerSocketURL else { return true }
    guard
      let attributes = try? FileManager.default.attributesOfItem(atPath: brokerSocketURL.path),
      let type = attributes[.type] as? FileAttributeType
    else { return false }
    return type == .typeSocket
  }

  private func sendError(_ message: String, status: Int, to task: WKURLSchemeTask) {
    let body = (try? JSONSerialization.data(withJSONObject: ["error": message], options: []))
      ?? Data("{\"error\":\"Application error\"}".utf8)
    send(body, contentType: "application/json; charset=utf-8", status: status, headers: [:], to: task)
  }

  private func send(
    _ body: Data,
    contentType: String,
    status: Int,
    headers: [String: String],
    to task: WKURLSchemeTask
  ) {
    guard let requestURL = task.request.url,
      let response = HTTPURLResponse(
        url: requestURL,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: [
          "Content-Type": contentType,
          "Content-Length": String(body.count),
          "Cache-Control": "no-store",
        ].merging(headers) { _, requested in requested }
      )
    else {
      task.didFailWithError(
        NSError(
          domain: "OriginTrace",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "Could not create an application response"]
        )
      )
      return
    }
    task.didReceive(response)
    task.didReceive(body)
    task.didFinish()
  }
}

private final class OriginTraceApp: NSObject, NSApplicationDelegate, WKNavigationDelegate {
  private var window: NSWindow?
  private var contentHandler: LocalContentHandler?
  private let smokeTest = ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1"

  func applicationDidFinishLaunching(_ notification: Notification) {
    if smokeTest {
      print("SMOKE_LAUNCH")
    }
    guard let resourcesURL = Bundle.main.resourceURL else {
      presentFatalError("Application resources are missing")
      return
    }

    configureApplicationMenu()
    configureApplicationIcon(resourcesURL: resourcesURL)

    let indexURL = resourcesURL.appendingPathComponent("index.html")
    let eventStoreURL = configuredEventStore(resourcesURL: resourcesURL)
    let artifactStoreURL = configuredArtifactStore(eventStoreURL: eventStoreURL)
    let handler = LocalContentHandler(
      indexURL: indexURL,
      eventStoreURL: eventStoreURL,
      artifactStoreURL: artifactStoreURL,
      brokerSocketURL: configuredBrokerSocket()
    )
    contentHandler = handler

    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    configuration.setURLSchemeHandler(handler, forURLScheme: "reb")

    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = self
    webView.setValue(false, forKey: "drawsBackground")

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 1180, height: 790),
      styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
      backing: .buffered,
      defer: false
    )
    window.title = "Origin Trace"
    window.titleVisibility = .hidden
    window.titlebarAppearsTransparent = true
    window.isMovableByWindowBackground = true
    window.minSize = NSSize(width: 760, height: 560)
    window.contentView = webView
    window.center()
    window.makeKeyAndOrderFront(nil)
    self.window = window

    NSApp.setActivationPolicy(.regular)
    if !smokeTest {
      NSApp.activate(ignoringOtherApps: true)
    }
    webView.load(URLRequest(url: URL(string: "reb://app/index.html?native=1")!))
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    true
  }

  func webView(
    _ webView: WKWebView,
    didFailProvisionalNavigation navigation: WKNavigation!,
    withError error: Error
  ) {
    presentFatalError(error.localizedDescription)
  }

  private func configuredEventStore(resourcesURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--store"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_EVENT_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return resourcesURL.appendingPathComponent("demo.jsonl")
  }

  private func configuredArtifactStore(eventStoreURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--artifacts"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_ARTIFACT_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return eventStoreURL.deletingLastPathComponent().appendingPathComponent("artifacts")
  }

  private func configuredBrokerSocket() -> URL? {
    let arguments = CommandLine.arguments
    if let socketFlag = arguments.firstIndex(of: "--broker-socket"),
      socketFlag + 1 < arguments.count
    {
      return URL(fileURLWithPath: arguments[socketFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_BROKER_SOCKET"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return nil
  }

  private func configureApplicationMenu() {
    let mainMenu = NSMenu()

    let applicationMenuItem = NSMenuItem()
    let applicationMenu = NSMenu(title: "Origin Trace")
    applicationMenu.addItem(
      withTitle: "About Origin Trace",
      action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
      keyEquivalent: ""
    )
    applicationMenu.addItem(.separator())
    applicationMenu.addItem(
      withTitle: "Hide Origin Trace",
      action: #selector(NSApplication.hide(_:)),
      keyEquivalent: "h"
    )
    applicationMenu.addItem(.separator())
    applicationMenu.addItem(
      withTitle: "Quit Origin Trace",
      action: #selector(NSApplication.terminate(_:)),
      keyEquivalent: "q"
    )
    applicationMenuItem.submenu = applicationMenu
    mainMenu.addItem(applicationMenuItem)

    let editMenuItem = NSMenuItem()
    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.addItem(.separator())
    editMenu.addItem(
      withTitle: "Select All",
      action: #selector(NSText.selectAll(_:)),
      keyEquivalent: "a"
    )
    editMenuItem.submenu = editMenu
    mainMenu.addItem(editMenuItem)

    let windowMenuItem = NSMenuItem()
    let windowMenu = NSMenu(title: "Window")
    windowMenu.addItem(
      withTitle: "Minimize",
      action: #selector(NSWindow.performMiniaturize(_:)),
      keyEquivalent: "m"
    )
    windowMenu.addItem(
      withTitle: "Zoom",
      action: #selector(NSWindow.performZoom(_:)),
      keyEquivalent: ""
    )
    windowMenuItem.submenu = windowMenu
    mainMenu.addItem(windowMenuItem)
    NSApp.windowsMenu = windowMenu
    NSApp.mainMenu = mainMenu
  }

  private func configureApplicationIcon(resourcesURL: URL) {
    let iconURL = resourcesURL.appendingPathComponent("OriginTrace.icns")
    guard let icon = NSImage(contentsOf: iconURL) else {
      return
    }
    NSApp.applicationIconImage = icon
  }

  private func presentFatalError(_ message: String) {
    let alert = NSAlert()
    alert.alertStyle = .critical
    alert.messageText = "Origin Trace could not start"
    alert.informativeText = message
    alert.runModal()
    NSApp.terminate(nil)
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    guard smokeTest else { return }
    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
      let script = """
        JSON.stringify({
          title: document.title,
          nativeShell: document.documentElement.classList.contains('native-shell'),
          requests: document.querySelectorAll('.request-row').length,
          fields: document.querySelectorAll('.field-row').length,
          artifacts: document.querySelectorAll('.source-tree-row[data-artifact-id]').length,
          sourceLines: document.querySelectorAll('.source-line').length,
          broker: document.querySelector('#broker-status')?.textContent,
          traceEnabled: !document.querySelector('#trace-origin')?.disabled,
          viewport: [window.innerWidth, window.innerHeight, window.devicePixelRatio],
          trafficColumns: getComputedStyle(document.querySelector('.traffic-grid')).gridTemplateColumns
        })
        """
      webView.evaluateJavaScript(script) { result, error in
        if let error {
          print("SMOKE_ERROR \(error.localizedDescription)")
        } else {
          print("SMOKE_OK \(result ?? "no result")")
        }
        NSApp.terminate(nil)
      }
    }
  }
}

@main
private enum OriginTraceMain {
  static func main() {
    let application = NSApplication.shared
    let delegate = OriginTraceApp()
    application.delegate = delegate
    application.run()
  }
}
