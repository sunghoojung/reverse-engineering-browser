import Darwin
import Foundation

// Compiled with the production native core. The agent loop is LangGraph in the
// web view (tools/check-agent-runtime.mjs runs it); this checks what native
// keeps: the restricted provider proxy, key handling, the real `reb-api mcp`
// tool server and its gates, and the user-only transcript.

final class StandIn: @unchecked Sendable {
  struct Received { let path: String; let headers: [String: String]; let body: [String: Any] }
  private let lock = NSLock()
  private var received: [Received] = []
  private var script: [(status: Int, lines: [String], hold: Bool)] = []
  private let listenFD: Int32
  let port: UInt16

  init() {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    address.sin_port = 0
    withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { precondition(bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0) }
    }
    precondition(listen(fd, 8) == 0)
    var bound = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &bound) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &length) }
    }
    port = UInt16(bigEndian: bound.sin_port)
    listenFD = fd
    Thread.detachNewThread { [weak self] in self?.loop() }
  }

  var url: URL { URL(string: "http://127.0.0.1:\(port)")! }
  var requests: [Received] { lock.lock(); defer { lock.unlock() }; return received }

  func enqueue(status: Int = 200, lines: [String], hold: Bool = false) {
    lock.lock(); script.append((status, lines, hold)); lock.unlock()
  }

  private func loop() {
    while true {
      let client = accept(listenFD, nil, nil)
      if client < 0 { return }
      Thread.detachNewThread { [weak self] in self?.serve(client) }
    }
  }

  private func serve(_ client: Int32) {
    defer { close(client) }
    var buffer = Data()
    var chunk = [UInt8](repeating: 0, count: 65536)
    while buffer.range(of: Data("\r\n\r\n".utf8)) == nil {
      let count = read(client, &chunk, chunk.count)
      if count <= 0 { return }
      buffer.append(contentsOf: chunk[0..<count])
    }
    let split = buffer.range(of: Data("\r\n\r\n".utf8))!
    let head = String(decoding: buffer[buffer.startIndex..<split.lowerBound], as: UTF8.self).components(separatedBy: "\r\n")
    let path = head[0].components(separatedBy: " ")[1]
    var headers: [String: String] = [:]
    for line in head.dropFirst() {
      guard let colon = line.firstIndex(of: ":") else { continue }
      headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    }
    var body = Data(buffer[split.upperBound...])
    let length = Int(headers["content-length"] ?? "0") ?? 0
    while body.count < length {
      let count = read(client, &chunk, chunk.count)
      if count <= 0 { return }
      body.append(contentsOf: chunk[0..<count])
    }
    let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
    lock.lock()
    received.append(Received(path: path, headers: headers, body: object))
    let reply = script.isEmpty ? (status: 500, lines: [String](), hold: false) : script.removeFirst()
    lock.unlock()
    let statusLine = reply.status == 200 ? "200 OK" : "\(reply.status) Error"
    let contentType = reply.status == 200 ? "text/event-stream" : "application/json"
    send(client, Data("HTTP/1.1 \(statusLine)\r\nContent-Type: \(contentType)\r\nConnection: close\r\n\r\n".utf8))
    send(client, Data(reply.lines.joined(separator: "\n").utf8 + [0x0A]))
    if reply.hold { Thread.sleep(forTimeInterval: 30) }
  }

  private func send(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { raw in
      var offset = 0
      while offset < raw.count {
        let sent = Darwin.write(fd, raw.baseAddress! + offset, raw.count - offset)
        if sent <= 0 { return }
        offset += sent
      }
    }
  }
}

func json(_ object: Any) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self) }

nonisolated(unsafe) var backendProcessForFailure: Process?

func check(_ condition: Bool, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
  if !condition {
    print("FAIL \(message) (\(file):\(line))")
    backendProcessForFailure?.terminate()
    exit(1)
  }
}

final class Collected: @unchecked Sendable {
  private let lock = NSLock()
  private var events: [[String: Any]] = []
  func add(_ event: [String: Any]) { lock.lock(); events.append(event); lock.unlock() }
  var all: [[String: Any]] { lock.lock(); defer { lock.unlock() }; return events }
  var body: Data {
    all.filter { $0["type"] as? String == "fetchChunk" }.reduce(into: Data()) { $0.append(Data(base64Encoded: $1["data"] as! String)!) }
  }
  var ended: Bool { all.contains { ["fetchEnd", "fetchError"].contains($0["type"] as? String ?? "") } }
}

@main
enum AgentCoreChecks {
  @MainActor static func main() async {
    let arguments = CommandLine.arguments
    precondition(arguments.count == 2, "usage: check-agent-core <reb-api>")
    let api = URL(fileURLWithPath: arguments[1])
    let backend = api.deletingLastPathComponent().appendingPathComponent("origin-trace-backend")
    checkRoutes()

    // The proxy against a loopback stand-in: the key is added natively, the
    // page's credentials are dropped, and the stream arrives on event boundaries.
    let standIn = StandIn()
    let session = URLSession(configuration: .ephemeral)
    let proxy = AgentProviderProxy(session: session)
    let route = AgentProviderRoute.resolve("https://api.anthropic.com/v1/messages?beta=true", method: "POST", standIn: standIn.url)!
    check(route.target.absoluteString == "\(standIn.url.absoluteString)/v1/messages?beta=true", "a stand-in keeps the fixed path")
    let stream = ["event: message_start\ndata: {\"type\":\"message_start\"}\n", "event: message_stop\ndata: {\"type\":\"message_stop\"}\n"]
    standIn.enqueue(lines: stream)
    let request = try! route.request(
      headers: ["content-type": "application/json", "x-api-key": "page-supplied", "authorization": "Bearer page", "cookie": "a=b",
        "anthropic-version": "2023-06-01", "x-unknown": "dropped"],
      body: Data(#"{"model":"m","messages":[]}"#.utf8), key: "sk-native-0123456789")
    let collected = Collected()
    let head = try! await proxy.start(id: "f1", request: request) { collected.add($0) }
    check(head["status"] as? Int == 200, "the response head reaches the page")
    for _ in 0..<200 where !collected.ended { try? await Task.sleep(nanoseconds: 10_000_000) }
    check(String(decoding: collected.body, as: UTF8.self).contains("message_stop"), "the streamed body reaches the page whole")
    check(collected.all.filter { $0["type"] as? String == "fetchChunk" }.count >= 2, "chunks follow SSE event boundaries")
    let sent = standIn.requests.last!
    check(sent.headers["x-api-key"] == "sk-native-0123456789", "native adds the Keychain key")
    check(sent.headers["authorization"] == nil && sent.headers["cookie"] == nil, "the page's credentials are dropped")
    check(sent.headers["x-unknown"] == nil, "only listed headers are forwarded")
    check(sent.headers["anthropic-version"] == "2023-06-01", "the SDK's API version is forwarded")
    check(!json(collected.all).contains("sk-native"), "the key never comes back to the page")

    // An error body is bounded and scrubbed of anything shaped like a key.
    standIn.enqueue(status: 401, lines: [json(["error": ["message": "Invalid key sk-native-0123456789"]])])
    let failed = Collected()
    let errorHead = try! await proxy.start(id: "f2", request: request) { failed.add($0) }
    for _ in 0..<200 where !failed.ended { try? await Task.sleep(nanoseconds: 10_000_000) }
    check(errorHead["status"] as? Int == 401, "provider errors keep their status")
    let errorText = String(decoding: failed.body, as: UTF8.self)
    check(errorText.contains("[key]") && !errorText.contains("sk-native"), "error bodies are redacted")

    // Cancel ends a held stream.
    standIn.enqueue(lines: ["event: message_start\ndata: {\"type\":\"message_start\"}\n"], hold: true)
    let held = Collected()
    _ = try! await proxy.start(id: "f3", request: request) { held.add($0) }
    check(proxy.inFlight == 1, "a held stream is in flight")
    proxy.cancel("f3")
    for _ in 0..<200 where proxy.inFlight > 0 { try? await Task.sleep(nanoseconds: 10_000_000) }
    check(proxy.inFlight == 0, "cancel stops the stream")

    // The real tool server on a real backend, with --omit-content.
    let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("reb-agent-core-\(UUID().uuidString)")
    try! FileManager.default.createDirectory(at: root.appendingPathComponent("blobs"), withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let source = Data("console.log('SECRET_SOURCE_BODY');\n".utf8)
    let sha = sha256Hex(source)
    try! source.write(to: root.appendingPathComponent("blobs/\(sha).bin"))
    let manifest: [String: Any] = ["protocol_version": 1, "artifact_id": "5", "session_id": "9", "navigation_id": "1", "frame_id": "1",
      "parent_artifact_id": "0", "creator_event_id": "0", "execution_context_id": "1", "capture_origin": "dynamic_javascript",
      "kind": "javascript", "url": "https://owned.example/app.js", "mime_type": "text/javascript", "byte_size": source.count,
      "sha256": sha, "sensitive": false, "content_path": "blobs/\(sha).bin"]
    try! (json(manifest) + "\n").write(to: root.appendingPathComponent("manifest.jsonl"), atomically: true, encoding: .utf8)
    FileManager.default.createFile(atPath: root.appendingPathComponent("events.jsonl").path, contents: Data())
    let endpointFile = root.appendingPathComponent("endpoint")
    let backendProcess = Process()
    backendProcess.executableURL = backend
    backendProcess.currentDirectoryURL = root
    backendProcess.arguments = ["--port", "0", "--endpoint-file", endpointFile.path, "--store", root.appendingPathComponent("events.jsonl").path, "--artifacts", root.path]
    backendProcess.standardOutput = FileHandle.nullDevice
    backendProcess.standardError = FileHandle.nullDevice
    try! backendProcess.run()
    backendProcessForFailure = backendProcess
    var endpoint = ""
    for _ in 0..<400 where endpoint.isEmpty {
      endpoint = ((try? String(contentsOf: endpointFile, encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
      try? await Task.sleep(nanoseconds: 25_000_000)
    }
    check(!endpoint.isEmpty, "the backend published its endpoint")
    let transcripts = root.appendingPathComponent("transcripts", isDirectory: true)
    func configuration(effects: Bool) -> AgentSession.Configuration {
      AgentSession.Configuration(provider: .claude, model: "claude-opus-5-5", apiExecutable: api, apiBaseURL: URL(string: endpoint)!,
        allowEffects: effects, transcriptDirectory: transcripts)
    }
    let events = Collected()
    let agent = AgentSession(emit: { events.add($0) })
    agent.setPanelVisible(true)
    try! await agent.enable(configuration(effects: false), sessionKey: "test-1")
    check(agent.childIsRunning, "the tool server runs while the agent is on")
    check(agent.toolNames.contains("get_artifacts") && !agent.toolNames.contains("get_artifact_content"), "structural reads only")
    check(!agent.toolNames.contains("capture_action"), "actions are hidden by default")
    let artifacts = try! await agent.callTool(name: "get_artifacts", arguments: ["limit": 5], approved: false)
    let artifactText = artifacts["text"] as? String ?? ""
    check(artifactText.contains("artifact_id") && !artifactText.contains("SECRET_SOURCE_BODY"), "the real server answers without content")
    let unlisted = try! await agent.callTool(name: "capture_action", arguments: ["action": "pause"], approved: true)
    check(unlisted["isError"] as? Bool == true, "an unlisted tool is refused")
    try! agent.appendTranscript(["role": "user", "text": "What was captured?"])
    let file = transcripts.appendingPathComponent("session-test-1.jsonl")
    check(((try? String(contentsOf: file, encoding: .utf8)) ?? "").contains("What was captured?"), "rows reach the transcript")
    check((try! FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as! NSNumber).intValue == 0o600, "the transcript is user-only")
    check((try! FileManager.default.attributesOfItem(atPath: transcripts.path)[.posixPermissions] as! NSNumber).intValue == 0o700, "its directory is user-only")
    agent.setPanelVisible(false)
    check(!agent.childIsRunning, "an idle tool server stops when the panel closes")
    let restarted = try! await agent.callTool(name: "get_session_summary", arguments: [:], approved: false)
    check(restarted["isError"] as? Bool == false, "the next call restarts it")
    check(!agent.childIsRunning, "with the panel closed and no turn running, it stops again after the call")
    agent.setTurnRunning(true)
    _ = try! await agent.callTool(name: "get_session_summary", arguments: [:], approved: false)
    check(agent.childIsRunning, "a running turn keeps it while the panel is closed")
    agent.setTurnRunning(false)
    check(!agent.childIsRunning, "the end of that turn stops it")
    agent.disable()
    check(!agent.isOn && !agent.childIsRunning, "turning off stops the tool server")

    // Actions: listed only when enabled, and never run without Allow once.
    let actions = AgentSession(emit: { events.add($0) })
    actions.setPanelVisible(true)
    try! await actions.enable(configuration(effects: true), sessionKey: "test-2")
    check(actions.toolNames.contains("capture_action"), "actions can be enabled")
    let unapproved = try! await actions.callTool(name: "capture_action", arguments: ["action": "pause"], approved: false)
    check((unapproved["text"] as? String ?? "").contains("needs Allow once"), "an action without approval does not run")
    let approved = try! await actions.callTool(name: "capture_action", arguments: ["action": "not-a-real-action"], approved: true)
    check(!(approved["text"] as? String ?? "").contains("needs Allow once"), "Allow once runs that one call")
    actions.disable()

    backendProcess.terminate()
    backendProcess.waitUntilExit()
    print("PASS agent native: fixed-endpoint proxy, native key, dropped page credentials, redacted errors, cancel, real reb-api gates and user-only transcript")
    exit(0)
  }

  static func checkRoutes() {
    check(agentStandInBaseURL(["REB_AGENT_PROVIDER_BASE_URL": "http://127.0.0.1:9"]) != nil, "loopback stand-in accepted")
    check(agentStandInBaseURL(["REB_AGENT_PROVIDER_BASE_URL": "https://evil.example:443"]) == nil, "remote stand-in refused")
    check(agentRedactedError("key sk-abcd1234 failed") == "key [key] failed", "keys are scrubbed")
    let anthropic = AgentProviderRoute.resolve("https://api.anthropic.com/v1/messages", method: "POST", standIn: nil)
    check(anthropic?.provider == .claude && anthropic?.target.absoluteString == "https://api.anthropic.com/v1/messages", "Anthropic messages")
    check(AgentProviderRoute.resolve("https://api.openai.com/v1/responses", method: "post", standIn: nil)?.provider == .chatgpt, "OpenAI responses")
    for (url, method) in [
      ("https://api.anthropic.com/v1/messages", "GET"), ("https://api.anthropic.com/v1/files", "POST"),
      ("https://api.anthropic.com/v1/messages/batches", "POST"), ("https://api.anthropic.com/v1/messages?x=1", "POST"),
      ("https://api.openai.com/v1/responses?beta=true", "POST"), ("https://api.openai.com/v1/chat/completions", "POST"),
      ("https://evil.example/v1/messages", "POST"), ("http://api.anthropic.com/v1/messages", "POST"),
      ("https://api.anthropic.com:8443/v1/messages", "POST"), ("https://user:pass@api.anthropic.com/v1/messages", "POST"),
      ("https://api.anthropic.com.evil.example/v1/messages", "POST"), ("https://api.openai.com/v1/messages", "POST"),
      ("https://127.0.0.1/v1/messages", "POST"), ("not a url", "POST"),
    ] {
      check(AgentProviderRoute.resolve(url, method: method, standIn: nil) == nil, "refused: \(method) \(url)")
    }
    let headers = AgentProviderRoute.forwarded(["X-Api-Key": "k", "Authorization": "a", "Cookie": "c", "Content-Type": "application/json", "Anthropic-Beta": "b"])
    check(headers == ["content-type": "application/json", "anthropic-beta": "b"], "credentials are never forwarded from the page")
    let oversized = Data(count: AgentProviderRoute.bodyLimit + 1)
    check((try? AgentProviderRoute.resolve("https://api.openai.com/v1/responses", method: "POST", standIn: nil)!.request(headers: [:], body: oversized, key: nil)) == nil, "oversized bodies are refused")
    check((try? AgentProviderRoute.resolve("https://api.openai.com/v1/responses", method: "POST", standIn: nil)!.request(headers: [:], body: Data("[]".utf8), key: nil)) == nil, "non-object bodies are refused")
    print("PASS agent native: routes, headers and stand-in rules")
  }

  static func sha256Hex(_ data: Data) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
    process.arguments = ["-a", "256"]
    let input = Pipe(), output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    try! process.run()
    input.fileHandleForWriting.write(data)
    input.fileHandleForWriting.closeFile()
    process.waitUntilExit()
    return String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).components(separatedBy: " ")[0]
  }
}
