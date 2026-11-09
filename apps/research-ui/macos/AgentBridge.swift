import Cocoa
import Security
import WebKit

// The web view asks; native decides. Keys stay in the Keychain and in the one
// outgoing request that needs them. The page can reach this bridge only from the
// exact main document the app loaded, as with client-project export.
@MainActor
final class NativeAgentBridge: NSObject, WKScriptMessageHandlerWithReply {
  static let handlerName = "rebAgent"
  // Composer text plus pins, as the panel limits them, with room for encoding.
  private static let turnByteLimit = 1024 * 1024

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
  private lazy var engine = AgentEngine(
    session: urlSession,
    keyProvider: { [weak self] kind in self?.standIn == nil ? AgentKeychain.read(kind) : nil },
    emit: { [weak self] event in self?.deliver(event) })

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
      let result = await engine.models(kind, baseURL: baseURL(for: kind))
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
      engine.disable()
      return status()
    case "send":
      try send(body)
      return ["accepted": true]
    case "cancel":
      engine.cancelTurn()
      return ["cancelled": true]
    case "decide":
      guard let callID = body["callId"] as? String, let allow = body["allow"] as? Bool else {
        throw AgentFailure(message: "Malformed approval.")
      }
      engine.decide(callID: callID, allow: allow)
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
    if engine.isOn { engine.disable() }
    let model = (body["model"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? kind.defaultModel
    let configuration = AgentEngine.Configuration(
      provider: kind, model: model, apiExecutable: apiExecutable, apiBaseURL: apiBaseURL,
      allowEffects: body["effects"] as? Bool == true, baseURL: baseURL(for: kind),
      needsKey: standIn == nil, transcriptDirectory: transcriptDirectory)
    sessionKey = rawKey
    try await engine.enable(configuration, sessionKey: rawKey.replacingOccurrences(of: ":", with: "-"))
    return status()
  }

  private func send(_ body: [String: Any]) throws {
    guard let turnID = body["turnId"] as? String, turnID.count <= 64,
      let text = body["text"] as? String, !text.isEmpty
    else { throw AgentFailure(message: "Malformed message.") }
    let context = body["context"] as? String
    let pins = (body["pins"] as? [[String: Any]]) ?? []
    var size = text.utf8.count + (context?.utf8.count ?? 0)
    for pin in pins { size += (pin["text"] as? String)?.utf8.count ?? 0 }
    guard size <= Self.turnByteLimit else {
      throw AgentFailure(message: "This turn is larger than 1 MiB. Remove a pin or shorten the question.")
    }
    try engine.send(turnID: turnID, text: text, context: context, pins: pins)
  }

  // Captured values and model text move as JSON arguments, never as script text.
  private func deliver(_ event: [String: Any]) {
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
