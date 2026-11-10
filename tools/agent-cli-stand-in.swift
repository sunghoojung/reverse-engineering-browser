import Darwin
import Foundation

// Stand-ins for the `claude` and `grok` CLIs, built into check-agent-core and
// run by re-executing that binary with the CLI's own arguments. Each one plays
// recorded stream-json or ACP traffic, makes its tool calls through the real
// `reb-api mcp` command the driver configured, and records what it was started
// with in its working folder so the check can verify the isolation.
// The prompt text picks a scenario: read, action, foreign, malformed, hold,
// init-foreign, api-key, builtin, foreign-permission.

enum AgentCLIStandIn {
  // The real check is started with an absolute reb-api path; a CLI never is.
  static func runIfRequested() {
    let arguments = CommandLine.arguments
    guard arguments.count >= 2, !arguments[1].hasPrefix("/") else { return }
    record(arguments)
    if arguments[1] == "auth", arguments.count >= 3, arguments[2] == "status" {
      print(#"{"loggedIn":true,"authMethod":"claude.ai","subscriptionType":"max","email":"researcher@example.test"}"#)
    } else if arguments[1] == "-p" {
      claude(arguments)
    } else if arguments.contains("inspect") {
      inspect()
    } else if arguments[1] == "models" {
      print("You are logged in with grok.com.\n\nDefault model: grok-test\n\nAvailable models:\n  * grok-test (default)\n  - grok-other")
    } else if arguments.last == "stdio" {
      grok()
    }
    fflush(stdout)
    exit(0)
  }

  // MARK: Recording

  static var directory: URL { URL(fileURLWithPath: FileManager.default.currentDirectoryPath) }

  static func record(_ arguments: [String]) {
    let environment = ProcessInfo.processInfo.environment
    let name = arguments[1] == "-p" ? (arguments.contains("--permission-prompt-tool") ? "claude" : "claude-models")
      : arguments.last == "stdio" ? "grok" : arguments[1]
    let entry: [String: Any] = [
      "arguments": Array(arguments.dropFirst()), "environment": environment,
      "ownGroup": getpgrp() == getpid(),
    ]
    let url = directory.appendingPathComponent("stand-in-\(name).json")
    if let data = try? JSONSerialization.data(withJSONObject: entry) { try? data.write(to: url) }
  }

  static func emit(_ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
    FileHandle.standardOutput.write(data + Data([0x0A]))
  }

  static func readObject() -> [String: Any]? {
    while let line = readLine(strippingNewline: true) {
      if let object = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] { return object }
    }
    return nil
  }

  // Helpers a CLI might start: one in its group, one that left it. Stop must
  // end both.
  static func startHelpers() {
    var pids: [Int32] = []
    for ownGroup in [false, true] {
      var attributes: posix_spawnattr_t?
      posix_spawnattr_init(&attributes)
      if ownGroup {
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&attributes, 0)
      }
      var pid: pid_t = 0
      let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/bin/sleep"), strdup("300"), nil]
      if posix_spawn(&pid, "/bin/sleep", nil, &attributes, argv, environ) == 0 { pids.append(pid) }
      argv.forEach { free($0) }
      posix_spawnattr_destroy(&attributes)
    }
    try? pids.map(String.init).joined(separator: " ").write(
      to: directory.appendingPathComponent("stand-in-helpers"), atomically: true, encoding: .utf8)
  }

  // MARK: The tool server, used the way the CLI would

  final class ToolServer {
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    var buffer = Data()
    var next = 1

    init?(command: String, arguments: [String]) {
      process.executableURL = URL(fileURLWithPath: command)
      process.arguments = arguments
      process.standardInput = input
      process.standardOutput = output
      process.standardError = FileHandle.nullDevice
      guard (try? process.run()) != nil else { return nil }
      _ = request("initialize", ["protocolVersion": "2025-06-18", "capabilities": [:] as [String: Any],
        "clientInfo": ["name": "stand-in", "version": "1"]])
      send(["jsonrpc": "2.0", "method": "notifications/initialized"])
    }

    func send(_ object: [String: Any]) {
      guard let data = try? JSONSerialization.data(withJSONObject: object) else { return }
      input.fileHandleForWriting.write(data + Data([0x0A]))
    }

    func request(_ method: String, _ params: [String: Any]) -> [String: Any] {
      let id = next
      next += 1
      send(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
      while true {
        while let newline = buffer.firstIndex(of: 0x0A) {
          let line = buffer[buffer.startIndex..<newline]
          buffer.removeSubrange(buffer.startIndex...newline)
          if let object = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any], object["id"] as? Int == id {
            return object
          }
        }
        let chunk = output.fileHandleForReading.availableData
        if chunk.isEmpty { return [:] }
        buffer.append(chunk)
      }
    }

    func call(_ name: String, _ arguments: [String: Any]) -> String {
      let response = request("tools/call", ["name": name, "arguments": arguments])
      let content = ((response["result"] as? [String: Any])?["content"] as? [[String: Any]]) ?? []
      return content.compactMap { $0["text"] as? String }.joined(separator: "\n")
    }

    deinit { process.terminate() }
  }

  // MARK: claude -p

  static func claude(_ arguments: [String]) {
    let mcp = arguments.firstIndex(of: "--mcp-config").map { arguments[$0 + 1] } ?? "{}"
    let reb = (((try? JSONSerialization.jsonObject(with: Data(mcp.utf8))) as? [String: Any])?["mcpServers"] as? [String: Any])?["reb"]
      as? [String: Any]
    var server: ToolServer?
    var request = 0
    while let message = readObject() {
      if message["type"] as? String == "control_request" {
        emit(["type": "control_response", "response": ["subtype": "success", "request_id": message["request_id"] ?? "",
          "response": ["models": [["value": "default", "displayName": "Default"], ["value": "claude-test", "displayName": "Test"]]]]])
        continue
      }
      guard message["type"] as? String == "user" else { continue }
      let content = ((message["message"] as? [String: Any])?["content"] as? [[String: Any]]) ?? []
      let text = content.compactMap { $0["text"] as? String }.joined()
      let scenario = ["init-foreign", "api-key", "foreign", "action", "malformed", "hold"].first { text.contains("SCENARIO:\($0)") } ?? "read"
      var tools = ["mcp__reb__get_session_summary", "mcp__reb__get_events"]
      if scenario == "init-foreign" { tools.append("Bash") }
      emit(["type": "system", "subtype": "init", "tools": tools, "mcp_servers": [["name": "reb", "status": "connected"]],
        "apiKeySource": scenario == "api-key" ? "ANTHROPIC_API_KEY" : "none"])
      let message = "msg-\(request)"
      emit(["type": "stream_event", "event": ["type": "message_start", "message": ["id": message]]])
      emit(["type": "stream_event", "event": ["type": "content_block_start", "index": 0, "content_block": ["type": "text", "text": ""]]])
      for piece in ["Looking ", "at the session."] {
        emit(["type": "stream_event", "event": ["type": "content_block_delta", "index": 0, "delta": ["type": "text_delta", "text": piece]]])
      }
      emit(["type": "stream_event", "event": ["type": "content_block_stop", "index": 0]])
      if scenario == "malformed" {
        print("this is not json")
        print("{\"half\": ")
        fflush(stdout)
      }
      if scenario == "hold" {
        startHelpers()
        while readLine() != nil {}
        return
      }
      if ["read", "action", "foreign"].contains(scenario) {
        let tool = scenario == "read" ? "mcp__reb__get_session_summary" : scenario == "action" ? "mcp__reb__capture_action" : "Bash"
        let input: [String: Any] = scenario == "action" ? ["action": "not-a-real-action"] : scenario == "foreign" ? ["command": "id"] : [:]
        request += 1
        let toolUse = "toolu_\(request)"
        emit(["type": "control_request", "request_id": "perm-\(request)",
          "request": ["subtype": "can_use_tool", "tool_name": tool, "input": input, "tool_use_id": toolUse]])
        var decision: [String: Any] = [:]
        while let reply = readObject() {
          if reply["type"] as? String == "control_response" { decision = (reply["response"] as? [String: Any])?["response"] as? [String: Any] ?? [:]; break }
        }
        try? JSONSerialization.data(withJSONObject: decision).write(to: directory.appendingPathComponent("stand-in-decision-\(request).json"))
        if decision["behavior"] as? String == "allow" {
          if server == nil, let reb, let command = reb["command"] as? String {
            server = ToolServer(command: command, arguments: reb["args"] as? [String] ?? [])
          }
          let name = String(tool.dropFirst("mcp__reb__".count))
          let result = server?.call(name, decision["updatedInput"] as? [String: Any] ?? input) ?? "no tool server"
          emit(["type": "user", "message": ["role": "user", "content": [["type": "tool_result", "tool_use_id": toolUse,
            "content": [["type": "text", "text": result]]]]]])
        } else {
          emit(["type": "user", "message": ["role": "user", "content": [["type": "tool_result", "tool_use_id": toolUse,
            "content": decision["message"] as? String ?? "denied", "is_error": true]]]])
        }
        emit(["type": "stream_event", "event": ["type": "message_start", "message": ["id": "\(message)-b"]]])
        emit(["type": "stream_event", "event": ["type": "content_block_delta", "index": 0, "delta": ["type": "text_delta",
          "text": "Answer [cite session=9 artifact=5]."]]])
        emit(["type": "stream_event", "event": ["type": "message_stop"]])
      }
      emit(["type": "result", "subtype": "success", "is_error": false, "result": "done",
        "usage": ["input_tokens": 11, "cache_read_input_tokens": 4, "output_tokens": 7]])
    }
  }

  // MARK: grok inspect and grok agent stdio

  static func inspect() {
    let config = (try? String(contentsOf: directory.appendingPathComponent(".grok/config.toml"), encoding: .utf8)) ?? ""
    let sticky = FileManager.default.fileExists(atPath: directory.appendingPathComponent("stand-in-sticky").path)
    var servers: [[String: Any]] = []
    if sticky || !config.contains("[mcp_servers.\"user-server\"]") {
      servers.append(["name": "user-server", "transport": "stdio", "target": "/usr/bin/true"])
    }
    servers.append(["name": "claude-compat", "disabled": true])
    emit(["mcpServers": servers, "hooks": [], "plugins": []])
  }

  static func grok() {
    var server: ToolServer?
    var requests = 100
    while let message = readObject() {
      let id = message["id"] ?? 0
      let params = message["params"] as? [String: Any] ?? [:]
      switch message["method"] as? String {
      case "initialize":
        emit(["jsonrpc": "2.0", "id": id, "result": ["protocolVersion": 1, "authMethods": [["id": "cached_token"], ["id": "grok.com"]]]])
      case "authenticate":
        emit(["jsonrpc": "2.0", "id": id, "result": ["_meta": ["subscription_tier": "Test"]]])
      case "session/new":
        let servers = params["mcpServers"] as? [[String: Any]] ?? []
        if let reb = servers.first(where: { $0["name"] as? String == "reb" }), let command = reb["command"] as? String {
          server = ToolServer(command: command, arguments: reb["args"] as? [String] ?? [])
        }
        let leak = FileManager.default.fileExists(atPath: directory.appendingPathComponent("stand-in-leak").path)
        emit(["jsonrpc": "2.0", "method": "_x.ai/mcp/servers_updated",
          "params": ["mcpServers": leak ? [["name": "user-server"]] : [] as [[String: Any]]]])
        emit(["jsonrpc": "2.0", "id": id, "result": ["sessionId": "session-1"]])
        emit(["jsonrpc": "2.0", "method": "_x.ai/mcp_initialized", "params": ["sessionId": "session-1", "mcpToolCount": 2]])
      case "session/prompt":
        let text = (params["prompt"] as? [[String: Any]] ?? []).compactMap { $0["text"] as? String }.joined()
        let scenario = ["builtin", "foreign-permission", "action", "hold"].first { text.contains("SCENARIO:\($0)") } ?? "read"
        let update = { (body: [String: Any]) in
          emit(["jsonrpc": "2.0", "method": "session/update", "params": ["sessionId": "session-1", "update": body]])
        }
        update(["sessionUpdate": "agent_message_chunk", "content": ["type": "text", "text": "Checking the session."]])
        if scenario == "hold" {
          startHelpers()
          while readLine() != nil {}
          return
        }
        if scenario == "builtin" {
          update(["sessionUpdate": "tool_call", "toolCallId": "c-shell", "title": "run_terminal_command",
            "rawInput": ["command": "id"], "_meta": ["x.ai/tool": ["name": "run_terminal_command"]]])
          while readLine() != nil {}
          return
        }
        let tool = scenario == "action" ? "reb__capture_action" : "reb__get_session_summary"
        let input: [String: Any] = scenario == "action" ? ["action": "not-a-real-action"] : [:]
        let call = "c-\(requests)"
        update(["sessionUpdate": "tool_call", "toolCallId": call, "title": "use_tool",
          "rawInput": ["tool_name": tool, "tool_input": input], "_meta": ["x.ai/tool": ["name": "use_tool"]]])
        requests += 1
        let rawInput: [String: Any] = scenario == "foreign-permission"
          ? ["variant": "Bash", "command": "id"] : ["variant": "UseTool", "tool_name": tool, "tool_input": input]
        emit(["jsonrpc": "2.0", "id": requests, "method": "session/request_permission", "params": [
          "sessionId": "session-1", "toolCall": ["toolCallId": call, "title": tool, "rawInput": rawInput],
          "options": [["optionId": "always-allow", "kind": "allow_always"], ["optionId": "allow-once", "kind": "allow_once"],
            ["optionId": "reject-once", "kind": "reject_once"]],
        ]])
        var outcome: [String: Any] = [:]
        while let reply = readObject() {
          if (reply["id"] as? Int) == requests { outcome = (reply["result"] as? [String: Any])?["outcome"] as? [String: Any] ?? [:]; break }
        }
        try? JSONSerialization.data(withJSONObject: outcome).write(to: directory.appendingPathComponent("stand-in-outcome-\(requests).json"))
        if outcome["optionId"] as? String == "allow-once" {
          let result = server?.call(String(tool.dropFirst(5)), input) ?? "no tool server"
          update(["sessionUpdate": "tool_call_update", "toolCallId": call, "status": "completed",
            "rawOutput": ["type": "MCP", "tool_name": tool, "server_name": "reb", "output": ["OkayOutput": result]]])
        } else {
          update(["sessionUpdate": "tool_call_update", "toolCallId": call, "status": "failed",
            "rawOutput": ["output": ["ErrorOutput": "The user rejected this call."]]])
        }
        update(["sessionUpdate": "agent_message_chunk", "content": ["type": "text", "text": "Answer [cite session=9 artifact=5]."]])
        emit(["jsonrpc": "2.0", "method": "_x.ai/session_notification", "params": ["sessionId": "session-1",
          "update": ["sessionUpdate": "turn_completed", "usage": ["inputTokens": 21, "outputTokens": 9]]]])
        emit(["jsonrpc": "2.0", "id": id, "result": ["stopReason": "end_turn"]])
      default:
        if message["method"] != nil, message["id"] != nil { emit(["jsonrpc": "2.0", "id": id, "result": [:] as [String: Any]]) }
      }
    }
  }
}
