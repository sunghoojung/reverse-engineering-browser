import Darwin
import Foundation

// Compiled with the production core. Drives the real conversation loop against a
// local stand-in provider and the real `reb-api mcp` on a real backend, so no
// test needs a key or network. A real provider is not exercised here.

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
func claudeLines(_ events: [[String: Any]]) -> [String] { events.map { "event: \($0["type"] as! String)\ndata: \(json($0))\n" } }
func openAILines(_ events: [[String: Any]]) -> [String] { events.map { "data: \(json($0))\n" } }

func claudeToolUse(name: String, input: [String: Any]) -> [String] {
  claudeLines([
    ["type": "message_start", "message": ["usage": ["input_tokens": 10]]],
    ["type": "content_block_start", "index": 0, "content_block": ["type": "thinking", "thinking": ""]],
    ["type": "content_block_delta", "index": 0, "delta": ["type": "thinking_delta", "thinking": "reasoning"]],
    ["type": "content_block_delta", "index": 0, "delta": ["type": "signature_delta", "signature": "sig-abc"]],
    ["type": "content_block_stop", "index": 0],
    ["type": "content_block_start", "index": 1, "content_block": ["type": "tool_use", "id": "toolu_1", "name": name, "input": [:] as [String: Any]]],
    ["type": "content_block_delta", "index": 1, "delta": ["type": "input_json_delta", "partial_json": json(input)]],
    ["type": "content_block_stop", "index": 1],
    ["type": "message_delta", "delta": ["stop_reason": "tool_use"], "usage": ["output_tokens": 5]],
    ["type": "message_stop"],
  ])
}

func claudeText(_ text: String) -> [String] {
  claudeLines([
    ["type": "message_start", "message": ["usage": ["input_tokens": 20]]],
    ["type": "content_block_start", "index": 0, "content_block": ["type": "text", "text": ""]],
    ["type": "content_block_delta", "index": 0, "delta": ["type": "text_delta", "text": text]],
    ["type": "content_block_stop", "index": 0],
    ["type": "message_delta", "delta": ["stop_reason": "end_turn"], "usage": ["output_tokens": 7]],
    ["type": "message_stop"],
  ])
}

func check(_ condition: Bool, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
  if !condition { print("FAIL \(message) (\(file):\(line))"); exit(1) }
}

@MainActor
final class Recorder {
  var events: [[String: Any]] = []
  var approvals: Bool?
  weak var engine: AgentEngine?
  func handle(_ event: [String: Any]) {
    events.append(event)
    if event["type"] as? String == "approval", let allow = approvals, let id = event["callId"] as? String {
      engine?.decide(callID: id, allow: allow)
    }
  }
  func until(_ condition: () -> Bool, _ message: String) async {
    let deadline = Date().addingTimeInterval(20)
    while Date() < deadline {
      if condition() { return }
      try? await Task.sleep(nanoseconds: 20_000_000)
    }
    print("Events: \(events.suffix(8))")
    check(false, "timed out: \(message)")
  }
  func text() -> String { events.filter { $0["type"] as? String == "text" }.compactMap { $0["delta"] as? String }.joined() }
  func ended(_ turn: String) -> Bool { events.contains { $0["type"] as? String == "turnEnd" && $0["turnId"] as? String == turn } }
  func erred(_ turn: String) -> Bool { events.contains { $0["type"] as? String == "error" && $0["turnId"] as? String == turn } }
}

@main
enum AgentCoreChecks {
  @MainActor static func main() async {
    let arguments = CommandLine.arguments
    precondition(arguments.count == 2, "usage: check-agent-core <reb-api>")
    let api = URL(fileURLWithPath: arguments[1])
    let backend = api.deletingLastPathComponent().appendingPathComponent("origin-trace-backend")
    checkPureRules()

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
    defer { backendProcess.terminate() }
    var endpoint = ""
    for _ in 0..<200 where endpoint.isEmpty {
      endpoint = ((try? String(contentsOf: endpointFile, encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
      try? await Task.sleep(nanoseconds: 25_000_000)
    }
    check(!endpoint.isEmpty, "the backend published its endpoint")
    let apiBase = URL(string: endpoint)!

    let standIn = StandIn()
    let transcriptDirectory = root.appendingPathComponent("transcripts", isDirectory: true)
    let sessionConfiguration = URLSessionConfiguration.ephemeral
    let session = URLSession(configuration: sessionConfiguration)
    let testKey = "sk-test-secret-key-0123456789"

    func make(_ provider: AgentProviderKind, effects: Bool = false, needsKey: Bool = false) -> (AgentEngine, Recorder, AgentEngine.Configuration) {
      let recorder = Recorder()
      let engine = AgentEngine(session: session, keyProvider: { _ in testKey }, emit: { recorder.handle($0) })
      recorder.engine = engine
      engine.setPanelVisible(true)
      let configuration = AgentEngine.Configuration(
        provider: provider, model: provider.defaultModel, apiExecutable: api, apiBaseURL: apiBase, allowEffects: effects,
        baseURL: standIn.url, needsKey: needsKey, transcriptDirectory: transcriptDirectory)
      return (engine, recorder, configuration)
    }

    // Claude: a tool round through the real tool server, thinking replayed verbatim.
    let (claude, claudeEvents, claudeConfig) = make(.claude, needsKey: true)
    try! await claude.enable(claudeConfig, sessionKey: "test-1")
    check(claude.toolNames.contains("get_artifacts"), "structural reads are advertised")
    check(!claude.toolNames.contains("get_artifact_content"), "raw content reads stay hidden")
    check(claude.childIsRunning, "the tool server runs while the agent is on")
    standIn.enqueue(lines: claudeToolUse(name: "get_artifacts", input: ["limit": 5]))
    standIn.enqueue(lines: claudeText("Found one [cite session=9 artifact=5]."))
    try! claude.send(turnID: "t1", text: "What was captured?", context: "kind=script session=9 artifact=5", pins: [])
    await claudeEvents.until({ claudeEvents.ended("t1") || claudeEvents.erred("t1") }, "claude turn")
    check(claudeEvents.ended("t1"), "the Claude turn finishes")
    check(claudeEvents.text().contains("Found one"), "text deltas reach the view")
    let firstClaude = standIn.requests[0]
    check(firstClaude.path == "/v1/messages", "Claude uses the Messages API")
    check(firstClaude.headers["x-api-key"] == testKey, "the key is sent as a header")
    check(firstClaude.headers["anthropic-version"] == "2026-10-21", "the API version is pinned")
    check(firstClaude.body["fallbacks"] as? String == "default", "refusal fallback is requested for this model")
    let firstMessages = firstClaude.body["messages"] as! [[String: Any]]
    check(json(firstMessages).contains("kind=script session=9 artifact=5"), "selection identifiers are in the turn")
    let secondClaude = standIn.requests[1]
    let messages = secondClaude.body["messages"] as! [[String: Any]]
    let resent = json(messages)
    check(resent.contains("sig-abc"), "signed thinking is replayed unchanged")
    check(resent.contains("tool_result"), "the tool result is sent back")
    check(resent.contains("\\\"artifact_id\\\": \\\"5\\\"") || resent.contains("artifact_id"), "the real tool server answered")
    check(!resent.contains("SECRET_SOURCE_BODY"), "captured source does not reach the provider")
    let row = claudeEvents.events.first { $0["type"] as? String == "tool" && $0["state"] as? String == "done" }
    check(row != nil && (row?["result"] as? String ?? "").contains("artifact_id"), "the tool result is visible to the researcher")
    // Key and capture privacy of the local record.
    let transcriptFile = transcriptDirectory.appendingPathComponent("session-test-1.jsonl")
    let transcript = (try? String(contentsOf: transcriptFile, encoding: .utf8)) ?? ""
    check(transcript.contains("What was captured?") && transcript.contains("artifact_id"), "the transcript keeps the conversation")
    check(!transcript.contains(testKey), "the key never reaches the transcript")
    let attributes = try! FileManager.default.attributesOfItem(atPath: transcriptFile.path)
    check((attributes[.posixPermissions] as! NSNumber).intValue == 0o600, "the transcript is user-only")
    let directoryAttributes = try! FileManager.default.attributesOfItem(atPath: transcriptDirectory.path)
    check((directoryAttributes[.posixPermissions] as! NSNumber).intValue == 0o700, "the transcript directory is user-only")
    // Fully stopping: the switch ends the conversation and the child.
    claude.disable()
    check(!claude.isOn && !claude.childIsRunning, "turning off stops the tool server")

    // Provider failure text, with a key-shaped value scrubbed.
    let (failing, failingEvents, failingConfig) = make(.claude, needsKey: true)
    try! await failing.enable(failingConfig, sessionKey: "test-1b")
    standIn.enqueue(status: 401, lines: [json(["error": ["message": "Invalid x-api-key sk-abcd1234efgh"]])])
    try! failing.send(turnID: "tf", text: "Hello", context: nil, pins: [])
    await failingEvents.until({ failingEvents.erred("tf") }, "provider error")
    let failure = failingEvents.events.first { $0["type"] as? String == "error" }?["message"] as? String ?? ""
    check(failure.contains("rejected the key"), "a rejected key is explained")
    check(!failure.contains("sk-abcd1234efgh"), "provider error text is redacted")
    failing.disable()

    // ChatGPT: stateless Responses history with reasoning replayed.
    let (chatgpt, chatEvents, chatConfig) = make(.chatgpt)
    try! await chatgpt.enable(chatConfig, sessionKey: "test-2")
    standIn.enqueue(lines: openAILines([
      ["type": "response.output_item.done", "item": ["type": "reasoning", "id": "rs_1", "encrypted_content": "ENC", "summary": [] as [Any]]],
      ["type": "response.output_item.done", "item": ["type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "get_session_summary", "arguments": "{}"]],
      ["type": "response.completed", "response": ["usage": ["input_tokens": 11, "output_tokens": 3]]],
    ]))
    standIn.enqueue(lines: openAILines([
      ["type": "response.output_text.delta", "delta": "Done"],
      ["type": "response.output_item.done", "item": ["type": "message", "role": "assistant", "content": [["type": "output_text", "text": "Done"]]]],
      ["type": "response.completed", "response": ["usage": ["input_tokens": 12, "output_tokens": 1]]],
    ]))
    let beforeChat = standIn.requests.count
    try! chatgpt.send(turnID: "t2", text: "Summarize", context: nil, pins: [])
    await chatEvents.until({ chatEvents.ended("t2") || chatEvents.erred("t2") }, "chatgpt turn")
    check(chatEvents.ended("t2"), "the ChatGPT turn finishes")
    let firstChat = standIn.requests[beforeChat]
    check(firstChat.path == "/v1/responses", "ChatGPT uses the Responses API")
    check(firstChat.body["store"] as? Bool == false, "responses are not stored by the provider")
    check(firstChat.headers["authorization"] == nil, "no key is sent to a stand-in")
    let toolsField = firstChat.body["tools"] as! [[String: Any]]
    check(toolsField.first?["type"] as? String == "function", "tools use the function shape")
    let input = json(standIn.requests[beforeChat + 1].body["input"] as! [[String: Any]])
    check(input.contains("ENC") && input.contains("function_call_output"), "reasoning and results are replayed")
    chatgpt.disable()

    // Effects are not advertised by default, and a call to one is refused.
    let (readOnly, readEvents, readConfig) = make(.claude)
    try! await readOnly.enable(readConfig, sessionKey: "test-3")
    check(!readOnly.toolNames.contains("capture_action"), "effects are hidden by default")
    standIn.enqueue(lines: claudeToolUse(name: "capture_action", input: ["action": "pause"]))
    standIn.enqueue(lines: claudeText("Could not."))
    try! readOnly.send(turnID: "t3", text: "Pause", context: nil, pins: [])
    await readEvents.until({ readEvents.ended("t3") }, "refused effect")
    check(readEvents.events.contains { $0["type"] as? String == "tool" && $0["state"] as? String == "refused" }, "an unlisted tool is refused without running")
    check(!readEvents.events.contains { $0["type"] as? String == "approval" }, "no approval is offered for an unlisted tool")
    readOnly.disable()

    // With effects on, every call waits for its own decision.
    let (effects, effectEvents, effectConfig) = make(.claude, effects: true)
    try! await effects.enable(effectConfig, sessionKey: "test-4")
    check(effects.toolNames.contains("capture_action"), "effects can be enabled")
    effectEvents.approvals = false
    standIn.enqueue(lines: claudeToolUse(name: "capture_action", input: ["action": "pause"]))
    standIn.enqueue(lines: claudeText("Denied, noted."))
    try! effects.send(turnID: "t4", text: "Pause", context: nil, pins: [])
    await effectEvents.until({ effectEvents.ended("t4") }, "denied effect")
    check(effectEvents.events.contains { $0["type"] as? String == "approval" && $0["name"] as? String == "capture_action" }, "the call asks first")
    check(effectEvents.events.contains { $0["type"] as? String == "tool" && $0["state"] as? String == "denied" }, "a denial is recorded and does not run")
    let denied = json(standIn.requests.last!.body["messages"] as! [[String: Any]])
    check(denied.contains("denied this call"), "the model is told the call was denied")
    effectEvents.approvals = true
    standIn.enqueue(lines: claudeToolUse(name: "capture_action", input: ["action": "not-a-real-action"]))
    standIn.enqueue(lines: claudeText("Ran."))
    try! effects.send(turnID: "t5", text: "Again", context: nil, pins: [])
    await effectEvents.until({ effectEvents.ended("t5") }, "allowed effect")
    let ran = effectEvents.events.filter { $0["type"] as? String == "tool" && $0["state"] as? String != "running" }.last
    check(ran?["state"] as? String != "denied", "Allow once runs that one call")
    effects.disable()

    // Stop ends the request; the next turn still works.
    let (cancel, cancelEvents, cancelConfig) = make(.claude)
    try! await cancel.enable(cancelConfig, sessionKey: "test-5")
    standIn.enqueue(lines: claudeLines([["type": "message_start", "message": ["usage": ["input_tokens": 1]]]]), hold: true)
    try! cancel.send(turnID: "t6", text: "Long", context: nil, pins: [])
    try? await Task.sleep(nanoseconds: 150_000_000)
    cancel.cancelTurn()
    await cancelEvents.until({ cancelEvents.events.contains { $0["type"] as? String == "turnEnd" && $0["stopped"] as? Bool == true } }, "stop")
    check(!cancel.isRunning, "stop ends the turn")

    // Closing the panel stops an idle child; sending again restarts it.
    cancel.setPanelVisible(true)
    check(cancel.childIsRunning, "the child stays while the panel is open")
    cancel.setPanelVisible(false)
    check(!cancel.childIsRunning, "an idle child stops when the panel closes")
    standIn.enqueue(lines: claudeText("Back."))
    try! cancel.send(turnID: "t7", text: "Again", context: nil, pins: [])
    await cancelEvents.until({ cancelEvents.ended("t7") }, "restart")
    cancel.disable()
    print("PASS agent core: Claude and ChatGPT loops, real reb-api tool results, no content or key leakage, effects, stop, idle")
    exit(0)
  }

  static func checkPureRules() {
    check(agentStandInBaseURL(["REB_AGENT_PROVIDER_BASE_URL": "http://127.0.0.1:9"]) != nil, "loopback stand-in accepted")
    check(agentStandInBaseURL(["REB_AGENT_PROVIDER_BASE_URL": "https://evil.example:443"]) == nil, "remote hosts refused")
    check(agentStandInBaseURL(["REB_AGENT_PROVIDER_BASE_URL": "http://169.254.169.254:80"]) == nil, "non-loopback refused")
    check(agentRedactedError("key sk-abcd1234 failed") == "key [key] failed", "keys are scrubbed")

    // Oldest whole turns leave first; thinking goes with them.
    var history = AgentHistory()
    let thinking: [String: Any] = ["role": "assistant", "content": [["type": "thinking", "thinking": "x", "signature": "s"], ["type": "text", "text": "ok"]]]
    try! history.append(thinking, turn: 2)
    try! history.append(["role": "user", "content": String(repeating: "x", count: AgentHistory.retainBytes)], turn: 1)
    try! history.append(["role": "user", "content": "current"], turn: 3)
    let trimmed = history.trim(keeping: 3, removeThinking: true)
    check(trimmed != nil && history.items.allSatisfy { $0.turn != 1 }, "the oldest turn is removed")
    check(!history.items.contains { String(decoding: $0.json, as: UTF8.self).contains("signature") }, "signed thinking leaves with the trim")

    // A truncated eager tool input is not treated as complete JSON.
    let parser = AgentStreamParser(kind: .claude)
    for line in claudeLines([
      ["type": "content_block_start", "index": 0, "content_block": ["type": "tool_use", "id": "t", "name": "get_events", "input": [:] as [String: Any]]],
      ["type": "content_block_delta", "index": 0, "delta": ["type": "input_json_delta", "partial_json": "{\"limit\":"]],
      ["type": "content_block_stop", "index": 0],
      ["type": "message_delta", "delta": ["stop_reason": "max_tokens"]],
      ["type": "message_stop"],
    ]) { line.split(separator: "\n").forEach { parser.consume(line: String($0)) { _ in } } }
    let step = try! parser.finish()
    check(step.toolCalls.first?.arguments == "", "a truncated tool input is marked incomplete")
    check(step.truncated, "max_tokens is reported")
    print("PASS agent core: pure rules")
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
