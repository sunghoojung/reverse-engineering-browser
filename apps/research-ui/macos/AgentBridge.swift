import Cocoa
import Security
import WebKit

// The web view runs the LangGraph loop; native holds what it must not: keys,
// the tool server and the transcript file. Keys stay in the Keychain and in the
// one outgoing request that needs them. The page can reach this bridge only
// from the exact main document the app loaded, as with client-project export.
@MainActor
final class NativeAgentBridge: NSObject, WKScriptMessageHandlerWithReply {
  static let handlerName = "rebAgent"

  private weak var webView: WKWebView?
  private weak var window: NSWindow?
  private var trustedURL: URL?
  private var documentReady = false
  private var sessionKey: String?
  private let environment = ProcessInfo.processInfo.environment
  private lazy var urlSession: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.httpCookieStorage = nil
    // Quiet reasoning is normal. This only ends a connection that sends nothing.
    configuration.timeoutIntervalForRequest = 300
    configuration.timeoutIntervalForResource = 3600
    return URLSession(configuration: configuration)
  }()
  private lazy var engine: AgentSession = {
    let session = AgentSession(emit: { [weak self] event in self?.deliver(event) })
    session.busy = { [weak self] in (self?.proxy.inFlight ?? 0) > 0 }
    return session
  }()
  private lazy var proxy = AgentProviderProxy(session: urlSession)

  private var standIn: URL? { agentStandInBaseURL(environment) }

  init(webView: WKWebView, window: NSWindow) {
    self.webView = webView
    self.window = window
    super.init()
  }

  func prepareForLoad(_ url: URL) {
    navigationWillStart()
    trustedURL = url
  }

  // A navigation is a session boundary: the conversation, tool server and any
  // in-flight request end with the document that started them.
  func navigationWillStart() {
    documentReady = false
    sessionKey = nil
    proxy.cancelAll()
    engine.disable()
  }

  func navigationDidFinish(_ view: WKWebView) {
    documentReady = view === webView && trustedURL != nil && view.url == trustedURL
  }

  func userContentController(
    _ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
    replyHandler: @escaping (Any?, String?) -> Void
  ) {
    guard message.name == Self.handlerName,
      message.webView === webView, message.frameInfo.isMainFrame,
      documentReady, let trustedURL, webView?.url == trustedURL,
      message.frameInfo.request.url == trustedURL, originMatches(message, trustedURL),
      let body = message.body as? [String: Any], let op = body["op"] as? String
    else {
      replyHandler(nil, "The agent is unavailable outside the application document.")
      return
    }
    Task { @MainActor in
      do { replyHandler(try await self.handle(op, body), nil) }
      catch { replyHandler(nil, agentRedactedError(error.localizedDescription)) }
    }
  }

  // The custom app scheme is already scoped by the exact URL above.
  private func originMatches(_ message: WKScriptMessage, _ trusted: URL) -> Bool {
    guard trusted.scheme == "http" else { return true }
    let origin = message.frameInfo.securityOrigin
    let brackets = CharacterSet(charactersIn: "[]")
    return origin.protocol == "http"
      && origin.host.trimmingCharacters(in: brackets) == trusted.host?.trimmingCharacters(in: brackets)
      && origin.port == trusted.port
  }

  private func provider(_ body: [String: Any]) throws -> AgentProviderKind {
    guard let raw = body["provider"] as? String, let kind = AgentProviderKind(rawValue: raw) else {
      throw AgentFailure(message: "Unknown provider.")
    }
    return kind
  }

  private func handle(_ op: String, _ body: [String: Any]) async throws -> Any? {
    switch op {
    case "status": return status()
    case "models":
      let kind = try provider(body)
      let result = await models(kind)
      return ["models": result.models, "defaultModel": kind.defaultModel, "fromProvider": result.fromProvider]
    case "setKey":
      let kind = try provider(body)
      return ["stored": try await promptForKey(kind)]
    case "clearKey":
      let kind = try provider(body)
      if try await confirmRemoveKey(kind) { AgentKeychain.delete(kind) }
      return status()
    case "enable": return try await enable(body)
    case "disable":
      proxy.cancelAll()
      engine.disable()
      return status()
    case "providerFetch": return try await providerFetch(body)
    case "fetchCancel":
      if let id = body["id"] as? String { proxy.cancel(id) }
      return ["ok": true]
    case "toolCall":
      guard let name = body["name"] as? String, let arguments = body["arguments"] as? [String: Any] else {
        throw AgentFailure(message: "Malformed tool call.")
      }
      return try await engine.callTool(name: name, arguments: arguments, approved: body["approved"] as? Bool == true)
    case "turn":
      engine.setTurnRunning(body["running"] as? Bool == true)
      return ["ok": true]
    case "transcriptAppend":
      guard let row = body["row"] as? [String: Any] else { throw AgentFailure(message: "Malformed transcript row.") }
      try engine.appendTranscript(row)
      return ["ok": true]
    case "panel":
      engine.setPanelVisible(body["visible"] as? Bool == true)
      return ["ok": true]
    case "transcript":
      return engine.loadTranscript(before: body["before"] as? Int)
    case "clearTranscript":
      engine.clearTranscript()
      return ["ok": true]
    default:
      throw AgentFailure(message: "Unknown agent operation.")
    }
  }

  private func status() -> [String: Any] {
    let live = trustedURL?.scheme == "http"
    return [
      "available": live && apiExecutable != nil,
      "reason": live ? (apiExecutable == nil ? "tool-server-missing" : "") : "offline-workspace",
      "standIn": standIn != nil,
      "providers": AgentProviderKind.allCases.map { kind -> [String: Any] in
        [
          "id": kind.rawValue, "label": kind.label, "vendor": kind.vendor, "defaultModel": kind.defaultModel,
          "hasKey": standIn != nil || AgentKeychain.contains(kind),
        ]
      },
      "engine": engine.statusPayload(),
      "tools": engine.toolDefinitions(),
    ]
  }

  private var apiExecutable: URL? {
    let url = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/OriginTraceAPI")
    return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
  }

  private func baseURL(for kind: AgentProviderKind) -> URL { standIn ?? kind.defaultBaseURL }

  private var apiBaseURL: URL? {
    guard let trustedURL, var components = URLComponents(url: trustedURL, resolvingAgainstBaseURL: false),
      trustedURL.scheme == "http"
    else { return nil }
    components.path = ""
    components.query = nil
    return components.url
  }

  private var transcriptDirectory: URL {
    if let override = environment["REB_AGENT_TRANSCRIPT_DIR"], override.hasPrefix("/") {
      return URL(fileURLWithPath: override, isDirectory: true)
    }
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
    return support.appendingPathComponent("Origin Trace/agent-transcripts", isDirectory: true)
  }

  private func enable(_ body: [String: Any]) async throws -> [String: Any] {
    let kind = try provider(body)
    guard let apiExecutable, let apiBaseURL else {
      throw AgentFailure(message: "This workspace has no local evidence API for the agent to read.")
    }
    guard let rawKey = body["sessionKey"] as? String,
      rawKey.range(of: "^[0-9:]{1,64}$", options: .regularExpression) != nil
    else { throw AgentFailure(message: "The current capture session has no identity yet.") }
    guard standIn != nil || AgentKeychain.contains(kind) else { throw AgentFailure(message: "Add a \(kind.label) key first.") }
    if engine.isOn { proxy.cancelAll(); engine.disable() }
    let model = (body["model"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? kind.defaultModel
    let configuration = AgentSession.Configuration(
      provider: kind, model: model, apiExecutable: apiExecutable, apiBaseURL: apiBaseURL,
      allowEffects: body["effects"] as? Bool == true, transcriptDirectory: transcriptDirectory)
    sessionKey = rawKey
    try await engine.enable(configuration, sessionKey: rawKey.replacingOccurrences(of: ":", with: "-"))
    return status()
  }

  // Forwards one SDK request to the enabled provider's model endpoint only. The
  // page's credentials are dropped; the Keychain key is added here.
  private func providerFetch(_ body: [String: Any]) async throws -> [String: Any] {
    guard let configuration = engine.configuration else { throw AgentFailure(message: "The agent is off.") }
    guard let id = body["id"] as? String, id.count <= 64, let url = body["url"] as? String,
      let method = body["method"] as? String, let text = body["body"] as? String
    else { throw AgentFailure(message: "Malformed model request.") }
    guard let route = AgentProviderRoute.resolve(url, method: method, standIn: standIn),
      route.provider == configuration.provider
    else { throw AgentFailure(message: "Model requests go only to the selected provider's model endpoint.") }
    let key = standIn == nil ? AgentKeychain.read(route.provider) : nil
    guard standIn != nil || key != nil else {
      throw AgentFailure(message: "The \(route.provider.label) key is no longer available. Add it again.")
    }
    let headers = (body["headers"] as? [String: String]) ?? [:]
    let request = try route.request(headers: headers, body: Data(text.utf8), key: key)
    let sink = AgentEventSink(self)
    return try await proxy.start(id: id, request: request) { event in await sink.send(event) }
  }

  private func models(_ kind: AgentProviderKind) async -> (models: [String], fromProvider: Bool) {
    let key = standIn == nil ? AgentKeychain.read(kind) : nil
    do {
      let (data, response) = try await urlSession.data(for: kind.modelsRequest(baseURL: baseURL(for: kind), key: key))
      guard (response as? HTTPURLResponse)?.statusCode == 200,
        let document = (try JSONSerialization.jsonObject(with: data)) as? [String: Any]
      else { return ([kind.defaultModel], false) }
      let ids = kind.models(from: document)
      return ids.isEmpty ? ([kind.defaultModel], false) : (ids, true)
    } catch {
      return ([kind.defaultModel], false)
    }
  }

  // Captured values and model text move as JSON arguments, never as script text.
  func deliver(_ event: [String: Any]) {
    guard documentReady, let webView, JSONSerialization.isValidJSONObject(event),
      let data = try? JSONSerialization.data(withJSONObject: event)
    else { return }
    let payload = String(decoding: data, as: UTF8.self)
    webView.callAsyncJavaScript(
      "window.__rebAgentEvent && window.__rebAgentEvent(JSON.parse(payload));",
      arguments: ["payload": payload], in: nil, in: .page, completionHandler: nil)
  }

  private func confirmRemoveKey(_ kind: AgentProviderKind) async throws -> Bool {
    guard let window, window.isVisible, window.attachedSheet == nil else {
      throw AgentFailure(message: "Finish the current dialog first.")
    }
    let alert = NSAlert()
    alert.messageText = "Remove the \(kind.vendor) key?"
    alert.informativeText = "It is deleted from your Keychain. Add it again to use \(kind.label)."
    alert.addButton(withTitle: "Remove")
    alert.addButton(withTitle: "Cancel")
    let response = await withCheckedContinuation { continuation in
      alert.beginSheetModal(for: window) { continuation.resume(returning: $0) }
    }
    return response == .alertFirstButtonReturn
  }

  // The field is a native secure field, so the key never enters the web view.
  private func promptForKey(_ kind: AgentProviderKind) async throws -> Bool {
    guard let window, window.isVisible, window.attachedSheet == nil else {
      throw AgentFailure(message: "Finish the current dialog first.")
    }
    let alert = NSAlert()
    alert.messageText = "\(kind.vendor) API key"
    alert.informativeText = "Stored in your macOS Keychain and sent only to \(kind.vendor). Origin Trace never writes it to disk, logs or the session store."
    let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    field.placeholderString = "Paste your key"
    alert.accessoryView = field
    alert.addButton(withTitle: "Save")
    alert.addButton(withTitle: "Cancel")
    alert.window.initialFirstResponder = field
    let response = await withCheckedContinuation { continuation in
      alert.beginSheetModal(for: window) { continuation.resume(returning: $0) }
    }
    guard response == .alertFirstButtonReturn else { return false }
    let key = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !key.isEmpty else { return false }
    return AgentKeychain.write(key, for: kind)
  }
}

// Carries streamed provider chunks from the proxy's task to the main actor.
// Events are JSON-shaped values created for this delivery and never shared.
final class AgentEventSink: @unchecked Sendable {
  private weak var bridge: NativeAgentBridge?
  @MainActor init(_ bridge: NativeAgentBridge) { self.bridge = bridge }
  func send(_ event: [String: Any]) async {
    nonisolated(unsafe) let payload = event
    await MainActor.run { self.bridge?.deliver(payload) }
  }
}

// Generic-password items in the login Keychain, one per provider. The app is
// ad-hoc signed and unsandboxed, so no entitlement is needed; macOS may ask
// once per rebuilt binary before reading the item.
enum AgentKeychain {
  private static let service = "com.reverseengineeringbrowser.origintrace.agent"

  private static func query(_ kind: AgentProviderKind) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: kind.keychainAccount,
    ]
  }

  static func contains(_ kind: AgentProviderKind) -> Bool {
    var attributes = query(kind)
    attributes[kSecReturnAttributes as String] = true
    return SecItemCopyMatching(attributes as CFDictionary, nil) == errSecSuccess
  }

  static func read(_ kind: AgentProviderKind) -> String? {
    var attributes = query(kind)
    attributes[kSecReturnData as String] = true
    attributes[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    guard SecItemCopyMatching(attributes as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }

  static func write(_ key: String, for kind: AgentProviderKind) -> Bool {
    let attributes: [String: Any] = [kSecValueData as String: Data(key.utf8)]
    let status = SecItemUpdate(query(kind) as CFDictionary, attributes as CFDictionary)
    if status == errSecSuccess { return true }
    guard status == errSecItemNotFound else { return false }
    var added = query(kind)
    added[kSecValueData as String] = Data(key.utf8)
    added[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
    return SecItemAdd(added as CFDictionary, nil) == errSecSuccess
  }

  static func delete(_ kind: AgentProviderKind) {
    SecItemDelete(query(kind) as CFDictionary)
  }
}
