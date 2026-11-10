import Darwin
import Foundation

// Native half of the in-app agent. The agent loop itself is LangGraph in the web
// view (apps/research-ui/agent-runtime); this file owns only what must not live
// there. Foundation only, so it compiles into tools/check-agent-core.swift.
//
// Boundaries this file owns:
// - Keys. The web view never sees one. The proxy below forwards a model request
//   only to the fixed provider endpoint, drops every credential the page sent,
//   and adds the Keychain key itself.
// - The only tool surface: the `reb-api mcp` child, started without
//   `--allow-effects` by default and always with `--omit-content`, so captured
//   source, bytecode and bodies cannot reach a provider through a tool result.
// - The local transcript file. Captured content and model output are data here.

enum AgentProviderKind: String, CaseIterable, Sendable {
  case claude
  case chatgpt

  var label: String { self == .claude ? "Claude" : "ChatGPT" }
  var vendor: String { self == .claude ? "Anthropic" : "OpenAI" }
  // Current defaults when the account's model list cannot be read. The list
  // from the provider wins; these are not a catalog.
  var defaultModel: String { self == .claude ? "claude-opus-5-5" : "gpt-6-astra" }
  var host: String { self == .claude ? "api.anthropic.com" : "api.openai.com" }
  var defaultBaseURL: URL { URL(string: "https://\(host)")! }
  // The one model endpoint the proxy forwards to for this provider.
  var modelPath: String { self == .claude ? "/v1/messages" : "/v1/responses" }
  var keychainAccount: String { rawValue }

  func authorize(_ request: inout URLRequest, key: String?) {
    if self == .claude {
      if let key { request.setValue(key, forHTTPHeaderField: "x-api-key") }
    } else if let key {
      request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
    }
  }

  // Native lists the account's models directly; it is not part of the loop.
  func modelsRequest(baseURL: URL, key: String?) -> URLRequest {
    var request = URLRequest(url: baseURL.appendingPathComponent("v1/models"))
    if self == .claude { request.setValue("2026-10-21", forHTTPHeaderField: "anthropic-version") }
    authorize(&request, key: key)
    return request
  }

  // Keeps ids a chat turn can use. The OpenAI list also carries embedding,
  // audio and image models the Responses API rejects.
  func models(from document: [String: Any]) -> [String] {
    let ids = (document["data"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String }
    guard self == .chatgpt else { return ids }
    return ids.filter { id in
      (id.hasPrefix("gpt-") || id.hasPrefix("o")) && !id.contains("audio") && !id.contains("realtime")
        && !id.contains("embedding") && !id.contains("image") && !id.contains("tts")
        && !id.contains("transcribe") && !id.contains("search")
    }
  }
}

struct AgentFailure: Error, LocalizedError {
  let message: String
  var errorDescription: String? { message }
}

// Provider error text can echo a masked key back, so nothing shaped like one
// reaches the transcript or the web view.
func agentRedactedError(_ text: String) -> String {
  let bounded = String(text.prefix(2048))
  return agentRedactedKeys(bounded)
}

func agentRedactedKeys(_ text: String) -> String {
  guard let pattern = try? NSRegularExpression(pattern: "sk-[A-Za-z0-9_*.-]{4,}") else { return text }
  let range = NSRange(text.startIndex..., in: text)
  return pattern.stringByReplacingMatches(in: text, range: range, withTemplate: "[key]")
}

// A loopback stand-in lets tests exercise the whole loop with no key and no
// network. Anything else is ignored, so an environment value can never redirect
// a real key to another host.
func agentStandInBaseURL(_ environment: [String: String]) -> URL? {
  guard let raw = environment["REB_AGENT_PROVIDER_BASE_URL"], let url = URL(string: raw),
    url.scheme == "http", ["127.0.0.1", "localhost", "::1"].contains(url.host ?? ""), url.port != nil,
    url.user == nil, url.password == nil, url.query == nil, url.fragment == nil
  else { return nil }
  return url
}

struct AgentToolDefinition: @unchecked Sendable {
  let name: String
  let description: String
  let schema: [String: Any]
  let readOnly: Bool
}

// Where a model request from the page may go. Exactly one endpoint per
// provider, POST only, over HTTPS to the provider's own host: this is a
// transport for the two chat models, not a general proxy.
struct AgentProviderRoute: Equatable {
  let provider: AgentProviderKind
  let target: URL

  // The SDKs send these; nothing else from the page is forwarded. Credentials
  // and cookies are never on this list, so a key the page sent is dropped.
  static let forwardedRequestHeaders: Set<String> = [
    "content-type", "accept", "anthropic-version", "anthropic-beta", "idempotency-key", "openai-beta",
  ]
  // Enough for the SDKs to report errors and honor retry hints.
  static let returnedResponseHeaders: Set<String> = [
    "content-type", "request-id", "x-request-id", "retry-after", "retry-after-ms", "x-should-retry",
  ]
  // The largest request a turn can make: 8 MiB of retained context, encoded.
  static let bodyLimit = 32 * 1024 * 1024

  static func resolve(_ raw: String, method: String, standIn: URL?) -> AgentProviderRoute? {
    guard method.uppercased() == "POST", let components = URLComponents(string: raw),
      components.scheme == "https", components.user == nil, components.password == nil,
      components.port == nil, components.fragment == nil,
      let provider = AgentProviderKind.allCases.first(where: { $0.host == components.host }),
      components.path == provider.modelPath
    else { return nil }
    // The Anthropic SDK marks beta requests with exactly this query.
    let query = components.percentEncodedQuery
    guard query == nil || (provider == .claude && query == "beta=true") else { return nil }
    var target = URLComponents()
    if let standIn, var local = URLComponents(url: standIn, resolvingAgainstBaseURL: false) {
      local.path = provider.modelPath
      local.percentEncodedQuery = query
      target = local
    } else {
      target.scheme = "https"
      target.host = provider.host
      target.path = provider.modelPath
      target.percentEncodedQuery = query
    }
    guard let url = target.url else { return nil }
    return AgentProviderRoute(provider: provider, target: url)
  }

  static func forwarded(_ headers: [String: String]) -> [String: String] {
    var result: [String: String] = [:]
    for (name, value) in headers where forwardedRequestHeaders.contains(name.lowercased()) {
      result[name.lowercased()] = value
    }
    return result
  }

  func request(headers: [String: String], body: Data, key: String?) throws -> URLRequest {
    guard body.count <= Self.bodyLimit else { throw AgentFailure(message: "The model request is larger than 32 MiB.") }
    guard (try? JSONSerialization.jsonObject(with: body)) is [String: Any] else {
      throw AgentFailure(message: "The model request body is not a JSON object.")
    }
    var request = URLRequest(url: target)
    request.httpMethod = "POST"
    for (name, value) in Self.forwarded(headers) { request.setValue(value, forHTTPHeaderField: name) }
    provider.authorize(&request, key: key)
    request.httpBody = body
    return request
  }
}

// Streams one provider response back to the page as base64 chunks on SSE event
// boundaries, so token streaming reaches the SDK's parser unchanged.
final class AgentProviderProxy: @unchecked Sendable {
  private let session: URLSession
  private let lock = NSLock()
  private var tasks: [String: Task<Void, Never>] = [:]
  // Coalesces bytes to about one SSE event per message to the page.
  private static let chunkBytes = 16 * 1024

  init(session: URLSession) { self.session = session }

  var inFlight: Int { lock.lock(); defer { lock.unlock() }; return tasks.count }

  func start(id: String, request: URLRequest, emit: @escaping @Sendable ([String: Any]) async -> Void) async throws -> [String: Any] {
    try await withCheckedThrowingContinuation { continuation in
      let task = Task.detached { [session] in
        var answered = false
        defer { self.finish(id) }
        do {
          let (bytes, response) = try await session.bytes(for: request)
          guard let http = response as? HTTPURLResponse else { throw AgentFailure(message: "The provider returned an invalid response.") }
          var headers: [String: String] = [:]
          for (name, value) in http.allHeaderFields {
            guard let name = (name as? String)?.lowercased(), Self.isReturned(name) else { continue }
            headers[name] = "\(value)"
          }
          answered = true
          continuation.resume(returning: ["status": http.statusCode, "headers": headers])
          if !(200..<300).contains(http.statusCode) {
            // Error bodies can echo a masked key, so they are bounded and scrubbed.
            var collected = Data()
            for try await byte in bytes {
              collected.append(byte)
              if collected.count >= 64 * 1024 { break }
            }
            let text = agentRedactedKeys(String(decoding: collected, as: UTF8.self))
            await emit(["type": "fetchChunk", "id": id, "data": Data(text.utf8).base64EncodedString()])
            await emit(["type": "fetchEnd", "id": id])
            return
          }
          var buffer = Data()
          buffer.reserveCapacity(Self.chunkBytes)
          var newline = false
          for try await byte in bytes {
            buffer.append(byte)
            let boundary = byte == 0x0A && newline
            newline = byte == 0x0A
            if boundary || buffer.count >= Self.chunkBytes {
              await emit(["type": "fetchChunk", "id": id, "data": buffer.base64EncodedString()])
              buffer.removeAll(keepingCapacity: true)
            }
          }
          if !buffer.isEmpty { await emit(["type": "fetchChunk", "id": id, "data": buffer.base64EncodedString()]) }
          await emit(["type": "fetchEnd", "id": id])
        } catch {
          let message = Task.isCancelled ? "The request was cancelled." : agentRedactedError(error.localizedDescription)
          if answered { await emit(["type": "fetchError", "id": id, "message": message]) }
          else { continuation.resume(throwing: AgentFailure(message: message)) }
        }
      }
      lock.lock()
      tasks[id] = task
      lock.unlock()
    }
  }

  private static func isReturned(_ name: String) -> Bool {
    AgentProviderRoute.returnedResponseHeaders.contains(name) || name.hasPrefix("anthropic-ratelimit-")
  }

  private func finish(_ id: String) {
    lock.lock()
    tasks.removeValue(forKey: id)
    lock.unlock()
  }

  func cancel(_ id: String) {
    lock.lock()
    let task = tasks.removeValue(forKey: id)
    lock.unlock()
    task?.cancel()
  }

  func cancelAll() {
    lock.lock()
    let all = tasks.values
    tasks.removeAll()
    lock.unlock()
    all.forEach { $0.cancel() }
  }
}

// Newline-delimited JSON-RPC to the one `reb-api mcp` child. The child is spawned
// only while the agent is on and never receives a key in its arguments or
// environment.
final class AgentMCPClient: @unchecked Sendable {
  // One stdio line holds a JSON-RPC envelope around the projection's
  // message_limit_bytes (33,554,432); anything longer is refused.
  private static let lineLimit = 33 * 1024 * 1024
  private let process = Process()
  private let input = Pipe()
  private let output = Pipe()
  private let errors = Pipe()
  private let lock = NSLock()
  private let onExit: @Sendable (Int32, String) -> Void
  private var buffer = Data()
  private var errorTail = Data()
  private var pending: [Int: CheckedContinuation<[String: Any], Error>] = [:]
  private var nextID = 1
  private var exited = false

  init(executable: URL, arguments: [String], onExit: @escaping @Sendable (Int32, String) -> Void) {
    self.onExit = onExit
    process.executableURL = executable
    process.arguments = arguments
    process.standardInput = input
    process.standardOutput = output
    process.standardError = errors
    process.environment = ["LANG": "C", "LC_ALL": "C"]
  }

  func start() throws {
    // A child that has exited must surface as a failed call, not as SIGPIPE
    // ending the app. The flag is per descriptor.
    _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
    output.fileHandleForReading.readabilityHandler = { [weak self] handle in
      let chunk = handle.availableData
      if chunk.isEmpty { handle.readabilityHandler = nil; return }
      self?.receive(chunk)
    }
    errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
      let chunk = handle.availableData
      if chunk.isEmpty { handle.readabilityHandler = nil; return }
      self?.receiveError(chunk)
    }
    process.terminationHandler = { [weak self] process in self?.handleExit(process.terminationStatus) }
    try process.run()
  }

  private func receiveError(_ chunk: Data) {
    lock.lock(); defer { lock.unlock() }
    errorTail.append(chunk)
    if errorTail.count > 4096 { errorTail = errorTail.suffix(4096) }
  }

  private func receive(_ chunk: Data) {
    lock.lock()
    buffer.append(chunk)
    var messages: [Data] = []
    while let newline = buffer.firstIndex(of: 0x0A) {
      messages.append(Data(buffer[buffer.startIndex..<newline]))
      buffer.removeSubrange(buffer.startIndex...newline)
    }
    let overflow = buffer.count > Self.lineLimit
    if overflow { buffer.removeAll() }
    lock.unlock()
    for message in messages where !message.isEmpty { deliver(message) }
    if overflow { terminate() }
  }

  private func deliver(_ message: Data) {
    guard let object = (try? JSONSerialization.jsonObject(with: message)) as? [String: Any],
      let id = object["id"] as? Int
    else { return }
    lock.lock()
    let continuation = pending.removeValue(forKey: id)
    lock.unlock()
    guard let continuation else { return }
    if let error = object["error"] as? [String: Any] {
      continuation.resume(throwing: AgentFailure(message: error["message"] as? String ?? "The tool server returned an error."))
    } else {
      continuation.resume(returning: object["result"] as? [String: Any] ?? [:])
    }
  }

  private func handleExit(_ status: Int32) {
    lock.lock()
    guard !exited else { lock.unlock(); return }
    exited = true
    let waiting = pending
    pending.removeAll()
    let tail = String(decoding: errorTail, as: UTF8.self)
    lock.unlock()
    output.fileHandleForReading.readabilityHandler = nil
    errors.fileHandleForReading.readabilityHandler = nil
    for (_, continuation) in waiting {
      continuation.resume(throwing: AgentFailure(message: "The local tool server stopped before answering."))
    }
    onExit(status, agentRedactedError(tail.trimmingCharacters(in: .whitespacesAndNewlines)))
  }

  func request(_ method: String, params: [String: Any]) async throws -> [String: Any] {
    try await withCheckedThrowingContinuation { continuation in
      lock.lock()
      guard !exited else {
        lock.unlock()
        continuation.resume(throwing: AgentFailure(message: "The local tool server is not running."))
        return
      }
      let id = nextID
      nextID += 1
      pending[id] = continuation
      lock.unlock()
      do {
        var line = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        line.append(0x0A)
        try input.fileHandleForWriting.write(contentsOf: line)
      } catch {
        lock.lock()
        let waiting = pending.removeValue(forKey: id)
        lock.unlock()
        waiting?.resume(throwing: AgentFailure(message: "The local tool server is not accepting requests."))
      }
    }
  }

  func notify(_ method: String) throws {
    var line = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "method": method])
    line.append(0x0A)
    try input.fileHandleForWriting.write(contentsOf: line)
  }

  // Asks politely, then guarantees the child is gone: a half-closed tool server
  // must not outlive the switch that started it.
  func terminate() {
    guard process.isRunning else { return }
    process.terminate()
    let pid = process.processIdentifier
    DispatchQueue.global().asyncAfter(deadline: .now() + 1) { kill(pid, SIGKILL) }
  }
}

// The local record of a conversation: one JSON row per line, user-only, outside
// the evidence store. It is interpretation, so it never mixes with capture.
final class AgentTranscript {
  // A row holds at most a 128 KiB tool result. 32 MiB keeps hundreds of the
  // largest rows; older rows are cut and a gap row says so.
  static let fileBudget = 32 * 1024 * 1024
  private let url: URL
  private var size: Int

  init(directory: URL, sessionKey: String) throws {
    let manager = FileManager.default
    try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    url = directory.appendingPathComponent("session-\(sessionKey).jsonl")
    if !manager.fileExists(atPath: url.path) {
      manager.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
    }
    try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    size = (try? manager.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
  }

  func append(_ row: [String: Any]) {
    guard var line = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) else { return }
    line.append(0x0A)
    if size + line.count > Self.fileBudget { compact() }
    guard let handle = try? FileHandle(forWritingTo: url) else { return }
    defer { try? handle.close() }
    do {
      try handle.seekToEnd()
      try handle.write(contentsOf: line)
      size += line.count
    } catch {}
  }

  // Keeps the newest half whole, on a row boundary, behind a labeled gap row.
  private func compact() {
    guard let data = try? Data(contentsOf: url) else { return }
    let keep = data.suffix(Self.fileBudget / 2)
    guard let newline = keep.firstIndex(of: 0x0A) else { return }
    var retained = (try? JSONSerialization.data(withJSONObject: [
      "role": "notice", "text": "Older transcript rows were removed to keep this file within its size budget.",
    ])) ?? Data()
    retained.append(0x0A)
    retained.append(keep[keep.index(after: newline)...])
    guard (try? retained.write(to: url, options: .atomic)) != nil else { return }
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    size = retained.count
  }

  // Reads backwards from `before` in one bounded chunk, on row boundaries.
  func page(before: Int?, chunk: Int = 1024 * 1024) -> (rows: [[String: Any]], before: Int?) {
    guard let handle = try? FileHandle(forReadingFrom: url) else { return ([], nil) }
    defer { try? handle.close() }
    let end = min(before ?? size, size)
    let start = max(0, end - chunk)
    guard end > 0, (try? handle.seek(toOffset: UInt64(start))) != nil,
      var data = try? handle.read(upToCount: end - start)
    else { return ([], nil) }
    var consumed = start
    if start > 0 {
      guard let newline = data.firstIndex(of: 0x0A) else { return ([], nil) }
      consumed = start + data.distance(from: data.startIndex, to: newline) + 1
      data = Data(data[data.index(after: newline)...])
    }
    let rows = data.split(separator: 0x0A).compactMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] }
    return (rows, consumed > 0 ? consumed : nil)
  }

  func clear() {
    try? Data().write(to: url, options: .atomic)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    size = 0
  }
}

// The tool server's lifecycle and the calls the graph makes through it, on
// the main actor so nothing here blocks the window.
@MainActor
final class AgentSession {
  // Structural reads the model may call without asking. Results still pass
  // through --omit-content; this list keeps out reads whose purpose is content
  // or that expose local store paths and researcher drafts. The OpenAPI policy
  // marks analysis routes that start a worker as not read-only, so they appear
  // only when actions are on and then ask each time.
  static let structuralTools: Set<String> = [
    "get_session_context", "get_session_summary", "get_events", "get_artifacts", "get_origin_trace",
    "get_request_signal_profile", "get_analysis_catalog", "get_js_invocation_sites", "inspect_wasm",
  ]
  static let idleSeconds: TimeInterval = 300

  struct Configuration {
    let provider: AgentProviderKind
    let model: String
    let apiExecutable: URL
    let apiBaseURL: URL
    let allowEffects: Bool
    let transcriptDirectory: URL
  }

  enum Phase: String {
    case off, starting, ready, stopped
  }

  private let emit: ([String: Any]) -> Void
  private(set) var configuration: Configuration?
  private(set) var phase = Phase.off
  private var client: AgentMCPClient?
  private(set) var tools: [AgentToolDefinition] = []
  private var transcript: AgentTranscript?
  private var panelVisible = false
  private var turnRunning = false
  private var callsInFlight = 0
  private var idleWork: DispatchWorkItem?
  var busy: () -> Bool = { false }

  init(emit: @escaping ([String: Any]) -> Void) { self.emit = emit }

  var isOn: Bool { phase != .off }
  var childIsRunning: Bool { client != nil }
  var toolNames: [String] { tools.map(\.name) }

  func statusPayload() -> [String: Any] {
    [
      "type": "status", "phase": phase.rawValue, "running": turnRunning, "childRunning": childIsRunning,
      "provider": configuration?.provider.rawValue as Any, "model": configuration?.model as Any,
      "effects": configuration?.allowEffects ?? false,
      "tools": tools.map { ["name": $0.name, "readOnly": $0.readOnly] },
    ]
  }

  // What the graph needs to build one LangChain tool per MCP tool.
  func toolDefinitions() -> [[String: Any]] {
    tools.map { ["name": $0.name, "description": $0.description, "schema": $0.schema, "readOnly": $0.readOnly] }
  }

  private func publishStatus() { emit(statusPayload()) }

  // Enabling never touches a provider. It starts only the local tool server, so
  // a researcher sees the tool surface before any question is sent.
  func enable(_ configuration: Configuration, sessionKey: String) async throws {
    guard phase == .off else { throw AgentFailure(message: "The agent is already on.") }
    self.configuration = configuration
    phase = .starting
    publishStatus()
    do {
      transcript = try AgentTranscript(directory: configuration.transcriptDirectory, sessionKey: sessionKey)
      try await startChild()
      phase = .ready
      publishStatus()
      armIdleTimer()
    } catch {
      stopChild()
      self.configuration = nil
      transcript = nil
      phase = .off
      publishStatus()
      throw error
    }
  }

  private func startChild() async throws {
    guard client == nil, let configuration else { return }
    var arguments = ["mcp", "--base-url", configuration.apiBaseURL.absoluteString, "--omit-content"]
    if configuration.allowEffects { arguments.append("--allow-effects") }
    let mcp = AgentMCPClient(executable: configuration.apiExecutable, arguments: arguments) { [weak self] status, message in
      Task { @MainActor in self?.childDidExit(status, message: message, of: nil) }
    }
    client = mcp
    do {
      try mcp.start()
    } catch {
      client = nil
      throw AgentFailure(message: "The local tool server could not start. Rebuild the app so OriginTraceAPI is present.")
    }
    _ = try await mcp.request("initialize", params: [
      "protocolVersion": "2025-06-18", "capabilities": [:] as [String: Any],
      "clientInfo": ["name": "origin-trace-agent", "version": "1"],
    ])
    try mcp.notify("notifications/initialized")
    let listed = try await mcp.request("tools/list", params: [:])
    tools = (listed["tools"] as? [[String: Any]] ?? []).compactMap { tool -> AgentToolDefinition? in
      guard let name = tool["name"] as? String else { return nil }
      let annotations = tool["annotations"] as? [String: Any]
      let readOnly = annotations?["readOnlyHint"] as? Bool ?? false
      guard readOnly ? Self.structuralTools.contains(name) : configuration.allowEffects else { return nil }
      return AgentToolDefinition(
        name: name, description: tool["description"] as? String ?? "",
        schema: tool["inputSchema"] as? [String: Any] ?? ["type": "object"], readOnly: readOnly)
    }
  }

  private func stopChild() {
    idleWork?.cancel()
    idleWork = nil
    client?.terminate()
    client = nil
  }

  private func childDidExit(_ status: Int32, message: String, of _: AgentMCPClient?) {
    guard client != nil, phase != .off else { return }
    client = nil
    let retired = status == 3 ? "The capture this connection was bound to has ended or changed. " : ""
    let reason = "\(retired)The local tool server stopped\(message.isEmpty ? "." : ": \(message)")"
    phase = .stopped
    publishStatus()
    emit(["type": "toolServer", "state": "stopped", "reason": reason])
  }

  // One timer only while the dock is open and nothing runs; a closed dock
  // stops an idle tool server at once.
  private func armIdleTimer() {
    idleWork?.cancel()
    idleWork = nil
    guard phase != .off, client != nil, !turnRunning, callsInFlight == 0, !busy() else { return }
    guard panelVisible else { stopChild(); publishStatus(); return }
    let work = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        guard let self, !self.turnRunning, self.callsInFlight == 0, !self.busy() else { return }
        self.stopChild()
        self.publishStatus()
      }
    }
    idleWork = work
    DispatchQueue.main.asyncAfter(deadline: .now() + Self.idleSeconds, execute: work)
  }

  func setPanelVisible(_ visible: Bool) {
    panelVisible = visible
    armIdleTimer()
  }

  func setTurnRunning(_ running: Bool) {
    turnRunning = running
    if running { idleWork?.cancel(); idleWork = nil } else { armIdleTimer() }
    publishStatus()
  }

  func disable() {
    guard phase != .off else { return }
    stopChild()
    configuration = nil
    tools = []
    transcript = nil
    turnRunning = false
    phase = .off
    publishStatus()
  }

  // Runs one tool for the graph. Actions need the panel's Allow once for this
  // call; the graph pauses for it, and this check refuses a call without it.
  func callTool(name: String, arguments: [String: Any], approved: Bool) async throws -> [String: Any] {
    guard phase != .off else { throw AgentFailure(message: "The agent is off.") }
    guard let definition = tools.first(where: { $0.name == name }) else {
      return ["text": "This tool is not available to the agent. No request was sent.", "isError": true]
    }
    guard definition.readOnly || approved else {
      return ["text": "This action needs Allow once. It did not run.", "isError": true]
    }
    if client == nil {
      try await startChild()
      if phase == .stopped { phase = .ready }
      publishStatus()
    }
    guard let client else { throw AgentFailure(message: "The local tool server is not running.") }
    callsInFlight += 1
    idleWork?.cancel()
    defer {
      callsInFlight -= 1
      armIdleTimer()
    }
    do {
      let result = try await client.request("tools/call", params: ["name": name, "arguments": arguments])
      let text = (result["content"] as? [[String: Any]] ?? []).compactMap { $0["text"] as? String }.joined(separator: "\n")
      return ["text": text, "isError": result["isError"] as? Bool ?? false]
    } catch {
      return ["text": agentRedactedError(error.localizedDescription), "isError": true]
    }
  }

  // Rows the panel shows, written as it shows them. 512 KiB fits the largest
  // row: a 128 KiB tool result with its arguments, escaped.
  func appendTranscript(_ row: [String: Any]) throws {
    guard let data = try? JSONSerialization.data(withJSONObject: row), data.count <= 512 * 1024 else {
      throw AgentFailure(message: "This transcript row is malformed or larger than 512 KiB.")
    }
    transcript?.append(row)
  }

  func loadTranscript(before: Int?) -> [String: Any] {
    guard let transcript else { return ["rows": [], "before": NSNull()] }
    let page = transcript.page(before: before)
    return ["rows": page.rows, "before": page.before as Any? ?? NSNull()]
  }

  func clearTranscript() { transcript?.clear() }
}
