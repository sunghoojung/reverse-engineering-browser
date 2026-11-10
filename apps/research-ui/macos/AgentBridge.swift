import Cocoa
import Security
import WebKit

// The web view runs the LangGraph loop for keys and the ChatGPT subscription;
// native holds what it must not: keys and tokens, the tool server, the Claude
// and Grok CLI drivers and the transcript file. Keys and tokens stay in the
// Keychain and in the one outgoing request that needs them; CLI logins stay
// with the CLI. The page can reach this bridge only from the exact main
// document the app loaded, as with client-project export.
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
    session.cliRunning = { [weak self] in self?.cli?.isRunning ?? false }
    return session
  }()
  private lazy var proxy = AgentProviderProxy(session: urlSession)
  // The Claude or Grok CLI for the enabled session, started at its first turn.
  private var cli: AgentCLIDriver?
  private var claudeModels: [String]?
  private lazy var chatgpt: AgentChatGPTAuth = {
    let standIn = AgentChatGPTAuth.standInDiscovery(environment)
    return AgentChatGPTAuth(
      session: urlSession, store: standIn == nil ? AgentKeychainSecretStore() : AgentMemorySecretStore(),
      discovery: standIn ?? AgentChatGPTAuth.discoveryURL, isStandIn: standIn != nil,
      openURL: { url in await MainActor.run { NSWorkspace.shared.open(url) } })
  }()

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
    stopCLI()
    engine.disable()
  }

  private func stopCLI() {
    cli?.shutdown()
    cli = nil
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

  private func auth(_ body: [String: Any], _ kind: AgentProviderKind) throws -> AgentAuthMode {
    let mode = (body["auth"] as? String).flatMap(AgentAuthMode.init(rawValue:)) ?? (kind.supportsKey ? .key : .subscription)
    guard mode == .subscription || kind.supportsKey else { throw AgentFailure(message: "\(kind.label) runs only with your subscription.") }
    return mode
  }

  private func handle(_ op: String, _ body: [String: Any]) async throws -> Any? {
    switch op {
    case "status": return status()
    case "models":
      let kind = try provider(body)
      let mode = try auth(body, kind)
      let result = await models(kind, mode)
      return ["models": result.models, "defaultModel": result.defaultModel ?? kind.defaultModel(mode), "fromProvider": result.fromProvider]
    case "subscriptionStatus":
      return await subscriptionStatus(try provider(body))
    case "subscriptionSignIn":
      let kind = try provider(body)
      guard kind == .chatgpt else {
        throw AgentFailure(message: "Sign in with the \(AgentCLILocator.name(kind)) CLI in Terminal, then check again.")
      }
      return try await chatgpt.signIn()
    case "subscriptionCancel":
      chatgpt.cancelSignIn()
      return ["ok": true]
    case "subscriptionSignOut":
      guard try provider(body) == .chatgpt else { throw AgentFailure(message: "Sign out with the CLI in Terminal.") }
      guard try await confirmSignOut() else { return chatgpt.status() }
      if engine.configuration?.provider == .chatgpt && engine.configuration?.auth == .subscription {
        proxy.cancelAll()
        engine.disable()
      }
      var result = chatgpt.status()
      if let message = await chatgpt.signOut() { result["notice"] = message }
      result.merge(chatgpt.status()) { _, new in new }
      return result
    case "cliSend":
      guard let cli, let turnId = body["turnId"] as? String, turnId.count <= 128, let text = body["text"] as? String else {
        throw AgentFailure(message: "The agent is off.")
      }
      let pins = (body["pins"] as? [[String: Any]] ?? []).prefix(16).map { $0 }
      let message = agentComposeUserMessage(text: text, context: body["context"] as? String, pins: pins)
      try await cli.send(turnId: turnId, text: message)
      return ["ok": true]
    case "cliDecide":
      guard let callId = body["callId"] as? String else { throw AgentFailure(message: "Malformed decision.") }
      return ["waiting": cli?.decide(callId: callId, allow: body["allow"] as? Bool == true) ?? false]
    case "cliCancel":
      cli?.cancel()
      return ["ok": true]
    case "setKey":
      let kind = try provider(body)
      return ["stored": try await promptForKey(kind)]
    case "clearKey":
      let kind = try provider(body)
      if try await confirmRemoveKey(kind) { AgentKeychain.delete(kind) }
      return status()
    case "enable": return try await enable(body)
    case "lowerPermission":
      guard let raw = body["permission"] as? String, let level = AgentPermission(rawValue: raw) else {
        throw AgentFailure(message: "Unknown permission level.")
      }
      try engine.lower(to: level)
      cli?.lower(to: level)
      return status()
    case "disable":
      proxy.cancelAll()
      stopCLI()
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
          "subscriptionModel": kind.defaultModel(.subscription), "supportsKey": kind.supportsKey,
          "hasKey": kind.supportsKey && (standIn != nil || AgentKeychain.contains(kind)),
          "subscription": subscriptionSummary(kind),
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

  private var cliRoot: URL {
    if let override = environment["REB_AGENT_CLI_DIR"], override.hasPrefix("/") {
      return URL(fileURLWithPath: override, isDirectory: true)
    }
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
    return support.appendingPathComponent("Origin Trace/agent-cli", isDirectory: true)
  }

  // What the page may show without running anything: where the CLI is, or
  // whether a ChatGPT sign-in is stored. Sign-in state for a CLI needs
  // subscriptionStatus, which asks the CLI.
  private func subscriptionSummary(_ kind: AgentProviderKind) -> [String: Any] {
    if kind == .chatgpt { return ["kind": "oauth", "available": true, "standIn": chatgpt.isStandIn].merging(chatgpt.status()) { a, _ in a } }
    let executable = AgentCLILocator.find(kind, environment: environment)
    return ["kind": "cli", "available": executable != nil, "cli": AgentCLILocator.name(kind)]
  }

  private func subscriptionStatus(_ kind: AgentProviderKind) async -> [String: Any] {
    if kind == .chatgpt { return subscriptionSummary(kind) }
    guard let executable = AgentCLILocator.find(kind, environment: environment) else {
      let name = AgentCLILocator.name(kind)
      return ["kind": "cli", "available": false, "signedIn": false, "cli": name,
        "reason": kind == .claude ? "Install Claude Code (the claude command) to use your subscription." : "Install the Grok CLI (the grok command) to use your subscription."]
    }
    guard let directory = try? AgentCLILocator.workingDirectory(kind, root: cliRoot) else {
      return ["kind": "cli", "available": false, "signedIn": false, "reason": "Origin Trace could not prepare a folder for the CLI."]
    }
    var status = kind == .claude
      ? await AgentCLIStatus.claude(executable, environment: environment, directory: directory)
      : await AgentCLIStatus.grok(executable, environment: environment, directory: directory)
    status["kind"] = "cli"
    status["available"] = true
    status["cli"] = AgentCLILocator.name(kind)
    return status
  }

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
    let mode = try auth(body, kind)
    guard let apiExecutable, let apiBaseURL else {
      throw AgentFailure(message: "This workspace has no local evidence API for the agent to read.")
    }
    guard let rawKey = body["sessionKey"] as? String,
      rawKey.range(of: "^[0-9:]{1,64}$", options: .regularExpression) != nil
    else { throw AgentFailure(message: "The current capture session has no identity yet.") }
    var executable: URL?
    switch (mode, kind) {
    case (.key, _):
      guard standIn != nil || AgentKeychain.contains(kind) else { throw AgentFailure(message: "Add a \(kind.label) key first.") }
    case (.subscription, .chatgpt):
      guard chatgpt.status()["signedIn"] as? Bool == true else { throw AgentFailure(message: "Sign in with ChatGPT first.") }
    case (.subscription, _):
      executable = AgentCLILocator.find(kind, environment: environment)
      guard executable != nil else {
        throw AgentFailure(message: "The \(AgentCLILocator.name(kind)) command was not found on this Mac.")
      }
    }
    // Consent in the dock chose this level. Native checks it before anything
    // changes, then holds it: only lowerPermission changes it afterwards.
    let (permission, sensitive) = try AgentPermission.requested(by: body)
    if engine.isOn { proxy.cancelAll(); stopCLI(); engine.disable() }
    let requested = (body["model"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? kind.defaultModel(mode)
    guard requested.range(of: "^[A-Za-z0-9._:\\[\\]-]{1,80}$", options: .regularExpression) != nil else {
      throw AgentFailure(message: "That model name is not valid.")
    }
    let configuration = AgentSession.Configuration(
      provider: kind, auth: mode, model: requested, apiExecutable: apiExecutable, apiBaseURL: apiBaseURL,
      permission: permission, sensitiveCapture: sensitive, transcriptDirectory: transcriptDirectory,
      appEnvironment: environment)
    let directory = executable == nil ? nil : try AgentCLILocator.workingDirectory(kind, root: cliRoot)
    sessionKey = rawKey
    try await engine.enable(configuration, sessionKey: rawKey.replacingOccurrences(of: ":", with: "-"))
    if let executable, let directory {
      let type: AgentCLIDriver.Type = kind == .grok ? AgentGrokDriver.self : AgentClaudeDriver.self
      let driver = type.init(
        provider: kind, executable: executable, workingDirectory: directory, configuration: configuration, tools: engine.tools,
        listedToolNames: engine.listedToolNames, environment: environment, emit: { [weak self] event in self?.deliver(event) })
      driver.onStateChange = { [weak self] in self?.engine.publishStatus() }
      cli = driver
    }
    return status()
  }

  // Forwards one SDK request to the enabled provider's model endpoint only. The
  // page's credentials are dropped; the Keychain key is added here.
  private func providerFetch(_ body: [String: Any]) async throws -> [String: Any] {
    guard let configuration = engine.configuration else { throw AgentFailure(message: "The agent is off.") }
    guard let id = body["id"] as? String, id.count <= 64, let url = body["url"] as? String,
      let method = body["method"] as? String, let text = body["body"] as? String
    else { throw AgentFailure(message: "Malformed model request.") }
    guard configuration.loop == .langgraph, let route = AgentProviderRoute.resolve(url, method: method, standIn: standIn),
      route.provider == configuration.provider
    else { throw AgentFailure(message: "Model requests go only to the selected provider's model endpoint.") }
    let key: String?
    if configuration.auth == .subscription {
      key = try await subscriptionToken()
    } else {
      key = standIn == nil ? AgentKeychain.read(route.provider) : nil
      guard standIn != nil || key != nil else {
        throw AgentFailure(message: "The \(route.provider.label) key is no longer available. Add it again.")
      }
    }
    let headers = (body["headers"] as? [String: String]) ?? [:]
    let request = try route.request(headers: headers, body: Data(text.utf8), key: key)
    let sink = AgentEventSink(self)
    return try await proxy.start(id: id, request: request) { event in await sink.send(event) }
  }

  // The ChatGPT access token, renewed when needed. A real token goes only to
  // OpenAI and a stand-in issuer's token only to the stand-in provider.
  private func subscriptionToken() async throws -> String {
    guard (standIn != nil) == chatgpt.isStandIn else {
      throw AgentFailure(message: "A stand-in provider needs a stand-in ChatGPT sign-in, and the reverse.")
    }
    return try await chatgpt.accessToken()
  }

  private func models(_ kind: AgentProviderKind, _ mode: AgentAuthMode) async -> (models: [String], defaultModel: String?, fromProvider: Bool) {
    let fallback = kind.defaultModel(mode)
    if mode == .subscription && kind != .chatgpt {
      guard let executable = AgentCLILocator.find(kind, environment: environment),
        let directory = try? AgentCLILocator.workingDirectory(kind, root: cliRoot)
      else { return ([fallback], nil, false) }
      if kind == .grok {
        let status = await AgentCLIStatus.grok(executable, environment: environment, directory: directory)
        let ids = status["models"] as? [String] ?? []
        return ids.isEmpty ? ([fallback], nil, false) : (["default"] + ids, "default", true)
      }
      if claudeModels == nil {
        let ids = await AgentCLIStatus.claudeModels(executable, environment: environment, directory: directory)
        if !ids.isEmpty { claudeModels = ids }
      }
      guard let ids = claudeModels else { return ([fallback], nil, false) }
      return (ids.contains("default") ? ids : ["default"] + ids, "default", true)
    }
    let key: String?
    if mode == .subscription {
      guard let token = try? await subscriptionToken() else { return ([fallback], nil, false) }
      key = token
    } else {
      key = standIn == nil ? AgentKeychain.read(kind) : nil
    }
    do {
      let (data, response) = try await urlSession.data(for: kind.modelsRequest(baseURL: baseURL(for: kind), key: key))
      guard (response as? HTTPURLResponse)?.statusCode == 200,
        let document = (try JSONSerialization.jsonObject(with: data)) as? [String: Any]
      else { return ([fallback], nil, false) }
      let ids = kind.models(from: document)
      return ids.isEmpty ? ([fallback], nil, false) : (ids, nil, true)
    } catch {
      return ([fallback], nil, false)
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

  private func confirmSignOut() async throws -> Bool {
    guard let window, window.isVisible, window.attachedSheet == nil else {
      throw AgentFailure(message: "Finish the current dialog first.")
    }
    let alert = NSAlert()
    alert.messageText = "Sign out of ChatGPT?"
    alert.informativeText = "Origin Trace forgets its ChatGPT token and asks OpenAI to revoke it. Sign in again to use your subscription."
    alert.addButton(withTitle: "Sign Out")
    alert.addButton(withTitle: "Cancel")
    let response = await withCheckedContinuation { continuation in
      alert.beginSheetModal(for: window) { continuation.resume(returning: $0) }
    }
    return response == .alertFirstButtonReturn
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
