import Darwin
import Foundation

// Subscription loops for Claude and Grok. With these, the researcher's own
// installed and signed-in CLI runs the agent loop, and this file drives it:
// `claude -p` over stream-json, and `grok agent stdio` over ACP JSON-RPC. The
// panel stays a renderer of the same rows the LangGraph graph emits.
//
// Boundaries this file owns:
// - Credentials stay with the CLI. Origin Trace never reads the CLI's token
//   files or Keychain items; it only runs `claude auth status` and
//   `grok models` to say whether the CLI is signed in. The child environment is
//   an allowlist, so an ANTHROPIC_API_KEY or XAI_API_KEY in the app's
//   environment cannot switch the CLI from the subscription to a key.
// - The only tools are reb-api tools. Each CLI starts with built-in tools,
//   user settings, hooks, memory and the researcher's own MCP servers removed,
//   and with one `reb-api mcp` server using the same gates as the graph's.
//   Every tool call still asks here first, and AgentToolGate decides it by
//   the native permission level: what the level runs, runs; at Ask for
//   actions an action waits for Allow once or Deny in the panel; anything
//   else is refused.
//   A built-in tool or a foreign server that appears anyway ends the CLI.
// - The child's lifetime. Each CLI runs in its own process group, only while
//   the agent is on and a conversation is open. Stop, switching off, a
//   navigation, an idle conversation and app exit kill the whole group.
// Foundation only, so it compiles into tools/check-agent-core.swift.

// MARK: - A child in its own process group

final class AgentChildProcess: @unchecked Sendable {
  // A stream-json or ACP line carries one message: at most a 128 KiB tool
  // result echoed back, or a turn of a few MiB. A longer line is refused.
  static let lineLimit = 16 * 1024 * 1024
  let pid: pid_t
  private let inputFD: Int32
  private let lock = NSLock()
  private let writes = DispatchQueue(label: "origin-trace.agent.cli-input")
  private let readerDone = DispatchSemaphore(value: 0)
  private var finished = false
  private var inputClosed = false
  private var errorTail = Data()
  private var overflowed = false

  init(
    executable: URL, arguments: [String], environment: [String: String], directory: URL,
    lineLimit: Int = AgentChildProcess.lineLimit,
    onLine: @escaping @Sendable (Data) -> Void,
    onExit: @escaping @Sendable (_ status: Int32, _ errors: String, _ overflowed: Bool) -> Void
  ) throws {
    let spawned = try Self.spawn(executable, arguments, environment, directory)
    pid = spawned.pid
    inputFD = spawned.input
    let output = spawned.output, errors = spawned.errors
    Thread.detachNewThread { [self] in
      readLines(output, limit: lineLimit, onLine: onLine)
      readerDone.signal()
    }
    Thread.detachNewThread { [self] in readErrors(errors) }
    Thread.detachNewThread { [self] in
      var status: Int32 = 0
      while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
      // A grandchild that kept stdout open must not hold the exit back.
      _ = readerDone.wait(timeout: .now() + 2)
      lock.lock()
      finished = true
      let tail = String(decoding: errorTail, as: UTF8.self)
      let overflow = overflowed
      lock.unlock()
      closeInput()
      let code = status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
      onExit(code, tail, overflow)
    }
  }

  var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return finished }

  private static func spawn(_ executable: URL, _ arguments: [String], _ environment: [String: String], _ directory: URL)
    throws -> (pid: pid_t, input: Int32, output: Int32, errors: Int32)
  {
    var input: [Int32] = [-1, -1], output: [Int32] = [-1, -1], errors: [Int32] = [-1, -1]
    guard pipe(&input) == 0 else { throw AgentFailure(message: "Could not create a pipe for the CLI.") }
    guard pipe(&output) == 0 else {
      input.forEach { close($0) }
      throw AgentFailure(message: "Could not create a pipe for the CLI.")
    }
    guard pipe(&errors) == 0 else {
      (input + output).forEach { close($0) }
      throw AgentFailure(message: "Could not create a pipe for the CLI.")
    }
    // The parent's ends must not leak into other children, or their EOF never comes.
    for fd in [input[1], output[0], errors[0]] { _ = fcntl(fd, F_SETFD, FD_CLOEXEC) }
    // A child that has exited must surface as a failed write, not SIGPIPE.
    _ = fcntl(input[1], F_SETNOSIGPIPE, 1)
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    defer { posix_spawn_file_actions_destroy(&actions) }
    posix_spawn_file_actions_adddup2(&actions, input[0], 0)
    posix_spawn_file_actions_adddup2(&actions, output[1], 1)
    posix_spawn_file_actions_adddup2(&actions, errors[1], 2)
    // The _np form, because the app supports macOS 13; the other is macOS 26 only.
    posix_spawn_file_actions_addchdir_np(&actions, directory.path)
    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    defer { posix_spawnattr_destroy(&attributes) }
    // Its own group, so one signal reaches the CLI and every helper it starts;
    // CLOEXEC_DEFAULT leaves it no descriptor but the three pipes.
    let flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
    posix_spawnattr_setflags(&attributes, Int16(flags))
    posix_spawnattr_setpgroup(&attributes, 0)
    var mask = sigset_t()
    sigemptyset(&mask)
    posix_spawnattr_setsigmask(&attributes, &mask)
    var defaults = sigset_t()
    sigemptyset(&defaults)
    for signal in [SIGPIPE, SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD] { sigaddset(&defaults, signal) }
    posix_spawnattr_setsigdefault(&attributes, &defaults)
    let argv: [UnsafeMutablePointer<CChar>?] = ([executable.path] + arguments).map { strdup($0) } + [nil]
    let envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
    defer {
      argv.forEach { free($0) }
      envp.forEach { free($0) }
    }
    var pid: pid_t = 0
    let status = posix_spawn(&pid, executable.path, &actions, &attributes, argv, envp)
    close(input[0])
    close(output[1])
    close(errors[1])
    guard status == 0 else {
      close(input[1])
      close(output[0])
      close(errors[0])
      throw AgentFailure(message: "\(executable.lastPathComponent) could not start: \(String(cString: strerror(status))).")
    }
    return (pid, input[1], output[0], errors[0])
  }

  private func readLines(_ fd: Int32, limit: Int, onLine: @Sendable (Data) -> Void) {
    defer { close(fd) }
    var buffer = Data()
    var chunk = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
      let count = read(fd, &chunk, chunk.count)
      if count < 0 && errno == EINTR { continue }
      if count <= 0 { break }
      buffer.append(contentsOf: chunk[0..<count])
      var start = buffer.startIndex
      while let newline = buffer[start...].firstIndex(of: 0x0A) {
        if newline > start { onLine(Data(buffer[start..<newline])) }
        start = buffer.index(after: newline)
      }
      buffer.removeSubrange(buffer.startIndex..<start)
      if buffer.count > limit {
        lock.lock()
        overflowed = true
        lock.unlock()
        terminate()
        return
      }
    }
    if !buffer.isEmpty { onLine(buffer) }
  }

  private func readErrors(_ fd: Int32) {
    defer { close(fd) }
    var chunk = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
      let count = read(fd, &chunk, chunk.count)
      if count < 0 && errno == EINTR { continue }
      if count <= 0 { return }
      lock.lock()
      errorTail.append(contentsOf: chunk[0..<count])
      if errorTail.count > 4096 { errorTail = errorTail.suffix(4096) }
      lock.unlock()
    }
  }

  // Writes stay off the main thread: a full pipe must not stall the window.
  func write(_ data: Data) {
    writes.async { [self] in
      lock.lock()
      let closed = inputClosed || finished
      lock.unlock()
      guard !closed else { return }
      data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
          let written = Darwin.write(inputFD, raw.baseAddress! + offset, raw.count - offset)
          if written < 0 && errno == EINTR { continue }
          if written <= 0 { return }
          offset += written
        }
      }
    }
  }

  func closeInput() {
    writes.async { [self] in
      lock.lock()
      let closed = inputClosed
      inputClosed = true
      lock.unlock()
      if !closed { close(inputFD) }
    }
  }

  // Asks politely, then guarantees the group and anything it started is gone.
  // Helpers a CLI moved to another group are found by parentage first.
  // A reaped leader's id may be reused, so its group is signaled only while it
  // has not been reaped. `force` is for app exit, which cannot wait a second.
  func terminate(force: Bool = false) {
    let family = Self.descendants(of: pid)
    let pid = self.pid
    let leaderAlive = !isFinished
    let signal = force ? SIGKILL : SIGTERM
    if leaderAlive { killpg(pid, signal) }
    for child in family { kill(child, signal) }
    guard !force, leaderAlive || !family.isEmpty else { return }
    DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
      if leaderAlive { killpg(pid, SIGKILL) }
      for child in family { kill(child, SIGKILL) }
    }
  }

  static func descendants(of root: pid_t) -> [pid_t] {
    var result: [pid_t] = []
    var queue = [root]
    while let parent = queue.popLast(), result.count < 512 {
      var buffer = [pid_t](repeating: 0, count: 256)
      let count = Int(proc_listchildpids(parent, &buffer, Int32(buffer.count * MemoryLayout<pid_t>.size)))
      guard count > 0 else { continue }
      for child in buffer.prefix(min(count, buffer.count)) where child > 0 && !result.contains(child) {
        result.append(child)
        queue.append(child)
      }
    }
    return result
  }

  // A short command (`claude auth status`, `grok models`, `grok inspect`):
  // bounded output, closed stdin, killed at the deadline.
  static func run(
    _ executable: URL, _ arguments: [String], environment: [String: String], directory: URL, timeout: TimeInterval,
    input: Data? = nil, until: (@Sendable (Data) -> Bool)? = nil, outputLimit: Int = 4 * 1024 * 1024
  ) async -> (status: Int32, output: Data, errors: String)? {
    final class Collected: @unchecked Sendable {
      let lock = NSLock()
      var output = Data()
      var resumed = false
      var process: AgentChildProcess?
    }
    let collected = Collected()
    return await withCheckedContinuation { continuation in
      let finish: @Sendable (Int32, String) -> Void = { status, errors in
        collected.lock.lock()
        guard !collected.resumed else { collected.lock.unlock(); return }
        collected.resumed = true
        let output = collected.output
        collected.lock.unlock()
        continuation.resume(returning: status < 0 ? nil : (status, output, errors))
      }
      do {
        let process = try AgentChildProcess(
          executable: executable, arguments: arguments, environment: environment, directory: directory,
          onLine: { line in
            collected.lock.lock()
            if collected.output.count + line.count < outputLimit {
              collected.output.append(line)
              collected.output.append(0x0A)
            }
            collected.lock.unlock()
            if until?(line) == true {
              collected.lock.lock()
              let process = collected.process
              collected.lock.unlock()
              finish(0, "")
              process?.terminate()
            }
          },
          onExit: { status, errors, _ in finish(status, errors) })
        collected.lock.lock()
        collected.process = process
        collected.lock.unlock()
        if let input { process.write(input) }
        if until == nil { process.closeInput() }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
          finish(-1, "")
          process.terminate()
        }
      } catch {
        finish(-1, "")
      }
    }
  }
}

// MARK: - Finding the CLI and its environment

enum AgentCLILocator {
  static func name(_ provider: AgentProviderKind) -> String { provider == .grok ? "grok" : "claude" }

  // An app opened from Finder has a minimal PATH, so the usual install
  // locations are searched too. REB_AGENT_CLAUDE_CLI and REB_AGENT_GROK_CLI
  // name an absolute executable instead (tests use stand-ins this way).
  static func find(_ provider: AgentProviderKind, environment: [String: String]) -> URL? {
    let name = name(provider)
    let manager = FileManager.default
    let override = provider == .grok ? "REB_AGENT_GROK_CLI" : "REB_AGENT_CLAUDE_CLI"
    if let raw = environment[override] {
      return raw.hasPrefix("/") && manager.isExecutableFile(atPath: raw) ? URL(fileURLWithPath: raw) : nil
    }
    let home = environment["HOME"] ?? NSHomeDirectory()
    var candidates = ["\(home)/.local/bin/\(name)", "\(home)/.\(name)/bin/\(name)"]
    if provider == .claude { candidates.append("\(home)/.claude/local/claude") }
    candidates += ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)"]
    candidates += (environment["PATH"] ?? "").split(separator: ":").filter { $0.hasPrefix("/") }.map { "\($0)/\(name)" }
    return candidates.first(where: { manager.isExecutableFile(atPath: $0) }).map { URL(fileURLWithPath: $0) }
  }

  // An allowlist, not a copy of the app's environment: no provider key,
  // base URL or nested-agent variable reaches the CLI.
  static let passed: Set<String> = ["HOME", "USER", "LOGNAME", "TMPDIR", "SHELL", "LANG", "__CF_USER_TEXT_ENCODING"]

  static func environment(_ base: [String: String], executable: URL, extra: [String: String] = [:]) -> [String: String] {
    var environment = base.filter { passed.contains($0.key) }
    environment["PATH"] = ([executable.deletingLastPathComponent().path] + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]).joined(separator: ":")
    environment["TERM"] = "dumb"
    environment["NO_COLOR"] = "1"
    for (name, value) in extra { environment[name] = value }
    return environment
  }

  // Each CLI runs in a private folder of its own, so no project file, rule or
  // configuration from the researcher's checkouts applies to it.
  static func workingDirectory(_ provider: AgentProviderKind, root: URL) throws -> URL {
    let directory = root.appendingPathComponent(name(provider), isDirectory: true)
    let manager = FileManager.default
    try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    return directory
  }
}

// MARK: - Sign-in status and model lists, read from the CLI itself

enum AgentCLIStatus {
  // `claude auth status` reports the login without revealing a token. Only the
  // method and plan leave this function; the account's email stays here.
  static func claude(_ executable: URL, environment: [String: String], directory: URL) async -> [String: Any] {
    let env = AgentCLILocator.environment(environment, executable: executable)
    guard let result = await AgentChildProcess.run(executable, ["auth", "status"], environment: env, directory: directory, timeout: 20),
      let document = (try? JSONSerialization.jsonObject(with: result.output)) as? [String: Any]
    else { return ["signedIn": false, "reason": "The Claude CLI did not report its sign-in status."] }
    let method = document["authMethod"] as? String ?? ""
    let signedIn = document["loggedIn"] as? Bool == true && method == "claude.ai"
    var status: [String: Any] = ["signedIn": signedIn, "method": method]
    if let plan = document["subscriptionType"] as? String { status["plan"] = plan }
    if !signedIn {
      status["reason"] = document["loggedIn"] as? Bool == true
        ? "The Claude CLI is signed in with \(method.isEmpty ? "another method" : method), not a claude.ai subscription."
        : "The Claude CLI is not signed in."
    }
    return status
  }

  // The models the CLI offers this account, from its initialize response. No
  // turn is sent, so this uses no subscription quota.
  static func claudeModels(_ executable: URL, environment: [String: String], directory: URL) async -> [String] {
    let env = AgentCLILocator.environment(environment, executable: executable)
    let request = Data(#"{"type":"control_request","request_id":"models","request":{"subtype":"initialize"}}"#.utf8 + [0x0A])
    let arguments = ["-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--strict-mcp-config",
      "--tools", "", "--setting-sources", "", "--disable-slash-commands", "--no-session-persistence"]
    guard let result = await AgentChildProcess.run(executable, arguments, environment: env, directory: directory, timeout: 20,
      input: request, until: { $0.range(of: Data(#""request_id":"models""#.utf8)) != nil })
    else { return [] }
    for line in result.output.split(separator: 0x0A) {
      guard let object = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
        let response = (object["response"] as? [String: Any])?["response"] as? [String: Any],
        let models = response["models"] as? [[String: Any]]
      else { continue }
      return models.compactMap { $0["value"] as? String }
    }
    return []
  }

  // `grok models` names the login and lists the plan's models.
  static func grok(_ executable: URL, environment: [String: String], directory: URL) async -> [String: Any] {
    let env = AgentCLILocator.environment(environment, executable: executable, extra: AgentGrokDriver.isolation)
    guard let result = await AgentChildProcess.run(executable, ["models"], environment: env, directory: directory, timeout: 20)
    else { return ["signedIn": false, "reason": "The Grok CLI did not answer."] }
    let text = String(decoding: result.output, as: UTF8.self)
    let signedIn = result.status == 0 && text.range(of: "logged in", options: .caseInsensitive) != nil
    var models: [String] = []
    var defaultModel: String?
    for line in text.split(separator: "\n") {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      guard trimmed.hasPrefix("* ") || trimmed.hasPrefix("- ") else { continue }
      guard let id = trimmed.dropFirst(2).split(separator: " ").first.map(String.init),
        id.range(of: "^[A-Za-z0-9._:-]{1,64}$", options: .regularExpression) != nil
      else { continue }
      models.append(id)
      if trimmed.hasPrefix("* ") { defaultModel = id }
    }
    var status: [String: Any] = ["signedIn": signedIn, "models": models]
    if let defaultModel { status["defaultModel"] = defaultModel }
    if !signedIn { status["reason"] = "The Grok CLI is not signed in." }
    return status
  }
}

// MARK: - Shared turn handling

// One running turn as the panel sees it.
@MainActor
final class AgentCLITurn {
  let id: String
  var textRow: (id: String, text: String)?
  var rowCounter = 0
  var rounds = 0
  var malformed = 0
  var inputTokens = 0
  var outputTokens = 0
  var tools: [String: (name: String, arguments: String, readOnly: Bool, running: Bool)] = [:]
  var approvals: [String: (name: String, arguments: String, respond: (Bool) -> Void)] = [:]
  var denied = 0
  init(id: String) { self.id = id }
}

@MainActor
class AgentCLIDriver {
  // Matches the graph's TOOL_ROUND_LIMIT.
  nonisolated static let toolRoundLimit = 128
  nonisolated static let malformedLimit = 16
  // The panel's transcript keeps rows under 512 KiB; a reb-api result is at
  // most the 128 KiB inline limit, so this cut is a guard, never routine.
  nonisolated static let resultLimit = 256 * 1024
  // A conversation the CLI holds is ended after this long without a turn.
  nonisolated static let idleSeconds: TimeInterval = 15 * 60

  let provider: AgentProviderKind
  let executable: URL
  let workingDirectory: URL
  private(set) var configuration: AgentSession.Configuration
  private(set) var tools: [AgentToolDefinition]
  // The next question carries a lowered level to a CLI that keeps running.
  private var permissionNote: String?
  let listedToolNames: [String]
  let baseEnvironment: [String: String]
  let emit: ([String: Any]) -> Void
  var onStateChange: () -> Void = {}
  var process: AgentChildProcess?
  var turn: AgentCLITurn?
  // Lines and exits from an earlier child carry its generation and are dropped.
  private var generation = 0
  private var idleWork: DispatchWorkItem?

  var cliName: String { provider == .grok ? "Grok CLI" : "Claude CLI" }
  var isRunning: Bool { process != nil }
  var turnRunning: Bool { turn != nil }

  required init(
    provider: AgentProviderKind, executable: URL, workingDirectory: URL, configuration: AgentSession.Configuration,
    tools: [AgentToolDefinition], listedToolNames: [String], environment: [String: String],
    emit: @escaping ([String: Any]) -> Void
  ) {
    self.provider = provider
    self.executable = executable
    self.workingDirectory = workingDirectory
    self.configuration = configuration
    self.tools = tools
    self.listedToolNames = listedToolNames
    self.baseEnvironment = environment
    self.emit = emit
  }

  // MARK: Subclass hooks

  func launchArguments() throws -> [String] { [] }
  func launchEnvironment() -> [String: String] { AgentCLILocator.environment(baseEnvironment, executable: executable) }
  func prepareLaunch() async throws {}
  func didLaunch() async throws {}
  func deliver(_ text: String) throws {}
  func handle(_ line: [String: Any]) {}
  // The child is gone or going: fail whatever waits on it.
  func cliStopped() {}
  // The CLI's tool name for a reb-api tool, or nil for anything else.
  func rebToolName(_ cliName: String) -> String? { nil }

  // MARK: Lifecycle

  func send(turnId: String, text: String) async throws {
    guard turn == nil else { throw AgentFailure(message: "The agent is still answering. Stop it first.") }
    guard text.utf8.count <= 2 * 1024 * 1024 else { throw AgentFailure(message: "This turn is larger than 2 MiB.") }
    let current = AgentCLITurn(id: turnId)
    turn = current
    idleWork?.cancel()
    do {
      if process == nil {
        permissionNote = nil
        try await launch()
        guard turn === current else { return }
      }
      if let note = permissionNote {
        permissionNote = nil
        try deliver("\(note)\n\n\(text)")
      } else {
        try deliver(text)
      }
    } catch {
      guard turn === current else { return }
      abort(agentRedactedError(error.localizedDescription))
    }
  }

  private func launch() async throws {
    try await prepareLaunch()
    let arguments = try launchArguments()
    generation += 1
    let current = generation
    let child = try AgentChildProcess(
      executable: executable, arguments: arguments, environment: launchEnvironment(), directory: workingDirectory,
      onLine: { [weak self] line in
        DispatchQueue.main.async { MainActor.assumeIsolated { self?.receive(line, generation: current) } }
      },
      onExit: { [weak self] status, errors, overflowed in
        DispatchQueue.main.async {
          MainActor.assumeIsolated { self?.childExited(status, errors: errors, overflowed: overflowed, generation: current) }
        }
      })
    process = child
    if current > 1 {
      notice("A new \(cliName) conversation started. Earlier turns in this view are not part of it.")
    }
    onStateChange()
    do {
      try await didLaunch()
    } catch {
      terminate()
      throw error
    }
  }

  func write(_ object: [String: Any]) throws {
    guard let process else { throw AgentFailure(message: "The \(cliName) is not running.") }
    var line = try JSONSerialization.data(withJSONObject: object)
    line.append(0x0A)
    process.write(line)
  }

  private func receive(_ line: Data, generation: Int) {
    guard generation == self.generation, process != nil else { return }
    guard let object = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else {
      guard let turn else { return }
      turn.malformed += 1
      if turn.malformed == 1 { error("The \(cliName) sent output Origin Trace could not read. It was skipped.") }
      if turn.malformed > Self.malformedLimit { abort("The \(cliName) kept sending output Origin Trace could not read, so it was stopped.") }
      return
    }
    handle(object)
  }

  private func childExited(_ status: Int32, errors: String, overflowed: Bool, generation: Int) {
    guard generation == self.generation, process != nil else { return }
    process = nil
    idleWork?.cancel()
    cliStopped()
    let detail = agentRedactedError(errors.trimmingCharacters(in: .whitespacesAndNewlines).suffix(600).description)
    let reason = overflowed
      ? "The \(cliName) sent a line longer than 16 MiB, so it was stopped."
      : "The \(cliName) stopped (status \(status))\(detail.isEmpty ? "." : ": \(detail)")"
    if turn != nil { endTurn(error: reason) } else { notice("\(reason) The next question starts it again.") }
    onStateChange()
  }

  // Ends the CLI and anything it started. Its conversation ends with it.
  func terminate(force: Bool = false) {
    idleWork?.cancel()
    guard let process else { return }
    self.process = nil
    cliStopped()
    process.closeInput()
    process.terminate(force: force)
    onStateChange()
  }

  // Stop in the panel: the turn ends now and so does the CLI process group.
  func cancel() {
    guard turn != nil else { terminate(); return }
    terminate()
    endTurn(stopped: true, notice: "Stopped. The \(cliName) was ended; the next question starts a new conversation.")
  }

  // Switching off, navigation or exit: no rows, the view is going away.
  func shutdown() {
    turn = nil
    terminate(force: true)
  }

  func abort(_ message: String) {
    terminate()
    endTurn(error: message)
  }

  // A lowered level applies to the very next call: waiting decisions it no
  // longer allows are denied, and below Full access a running CLI is ended,
  // because its own tool server was started at Full access and returns
  // content. The next question starts it again at the lower level.
  func lower(to level: AgentPermission) {
    guard level < configuration.permission else { return }
    let wasFull = configuration.permission == .full
    configuration.permission = level
    if level != .full { configuration.sensitiveCapture = false }
    tools = tools.filter { AgentToolGate.lists($0.name, readOnly: $0.readOnly, level: level) }
    if let turn {
      for (callId, approval) in turn.approvals {
        let readOnly = tools.first { $0.name == approval.name }?.readOnly ?? false
        if case .refuse = AgentToolGate.decide(approval.name, readOnly: readOnly, arguments: [:], level: level, sensitive: false) {
          _ = decide(callId: callId, allow: false)
        }
      }
    }
    if wasFull && process != nil {
      if turn != nil {
        cancel()
      } else {
        terminate()
      }
      notice("The \(cliName) was ended so its tool server restarts at \(level.label). The next question starts a new conversation.")
    } else if process != nil {
      permissionNote = agentPermissionChangeNote(level)
    }
  }

  private func armIdle() {
    idleWork?.cancel()
    guard process != nil, turn == nil else { return }
    let work = DispatchWorkItem { [weak self] in
      MainActor.assumeIsolated {
        guard let self, self.turn == nil, self.process != nil else { return }
        self.terminate()
        self.notice("The \(self.cliName) was ended after \(Int(Self.idleSeconds / 60)) idle minutes. The next question starts a new conversation.")
      }
    }
    idleWork = work
    DispatchQueue.main.asyncAfter(deadline: .now() + Self.idleSeconds, execute: work)
  }

  // MARK: Rows, in the shapes the graph emits

  func row(_ event: [String: Any]) {
    var event = event
    event["cli"] = true
    if event["turnId"] == nil, let turn { event["turnId"] = turn.id }
    emit(event)
  }

  func text(_ delta: String) {
    guard let turn, !delta.isEmpty else { return }
    if turn.textRow == nil {
      turn.rowCounter += 1
      turn.textRow = ("assistant-\(turn.id)-\(turn.rowCounter)", "")
    }
    turn.textRow!.text += delta
    row(["type": "text", "rowId": turn.textRow!.id, "delta": delta])
  }

  func finishText() {
    guard let turn, let current = turn.textRow else { return }
    turn.textRow = nil
    row(["type": "assistantDone", "rowId": current.id, "text": current.text])
  }

  func notice(_ text: String) { row(["type": "notice", "text": text]) }
  func error(_ message: String) { row(["type": "error", "message": agentRedactedError(message)]) }

  nonisolated static func argumentText(_ value: Any?) -> String {
    guard let value, JSONSerialization.isValidJSONObject(value),
      let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    else { return "{}" }
    return String(decoding: data, as: UTF8.self)
  }

  func toolStarted(_ callId: String, name: String, arguments: String, readOnly: Bool) {
    guard let turn else { return }
    finishText()
    turn.tools[callId] = (name, arguments, readOnly, true)
    row(["type": "tool", "id": "tool-\(callId)", "name": name, "arguments": arguments, "state": "running", "readOnly": readOnly])
  }

  func toolFinished(_ callId: String, text: String, isError: Bool) {
    guard let turn, let tool = turn.tools[callId], tool.running else { return }
    turn.tools[callId]?.running = false
    var result = text
    if result.utf8.count > Self.resultLimit {
      result = String(decoding: Data(result.utf8.prefix(Self.resultLimit)), as: UTF8.self) + "\n[cut at 256 KiB]"
    }
    result = agentRedactedKeys(result)
    row(["type": "tool", "id": "tool-\(callId)", "name": tool.name, "arguments": tool.arguments, "state": isError ? "error" : "done",
      "result": result, "isError": isError, "resultBytes": result.utf8.count, "readOnly": tool.readOnly])
  }

  private func toolClosed(_ callId: String, name: String, arguments: String, state: String, text: String) {
    turn?.tools[callId] = (name, arguments, false, false)
    row(["type": "tool", "id": "tool-\(callId)", "name": name, "arguments": arguments, "state": state, "result": text,
      "isError": true, "resultBytes": text.utf8.count])
  }

  // Every tool call the CLI wants to make comes here before it runs.
  func permission(callId: String, cliName raw: String, input: Any?, respond: @escaping (Bool, String?) -> Void) {
    guard let turn else { respond(false, "No turn is running."); return }
    guard let name = rebToolName(raw) else {
      respond(false, "Origin Trace allows only reb-api tools.")
      abort("The \(cliName) asked to run \(raw.prefix(80)), which is not a reb-api tool, so it was stopped.")
      return
    }
    let arguments = Self.argumentText(input)
    turn.rounds += 1
    if turn.rounds > Self.toolRoundLimit {
      respond(false, "Stopped after \(Self.toolRoundLimit) tool calls.")
      terminate()
      endTurn(notice: "Stopped after \(Self.toolRoundLimit) rounds of tool calls.")
      return
    }
    let decision = tools.first(where: { $0.name == name }).map {
      AgentToolGate.decide(name, readOnly: $0.readOnly, arguments: input as? [String: Any] ?? [:],
        level: configuration.permission, sensitive: configuration.sensitive)
    } ?? .refuse("This tool is not available at \(configuration.permission.label). No request was sent.")
    if case .refuse(let text) = decision {
      respond(false, text)
      finishText()
      toolClosed(callId, name: name, arguments: arguments, state: "refused", text: text)
      return
    }
    if decision == .run {
      let readOnly = tools.first { $0.name == name }?.readOnly ?? false
      respond(true, nil)
      toolStarted(callId, name: name, arguments: arguments, readOnly: readOnly)
      return
    }
    finishText()
    turn.approvals[callId] = (name, arguments, { allow in respond(allow, allow ? nil : "The researcher denied this call. It did not run.") })
    row(["type": "approval", "callId": callId, "name": name, "arguments": arguments])
  }

  // Allow once or Deny from the panel, for one waiting call only.
  func decide(callId: String, allow: Bool) -> Bool {
    guard let turn, let approval = turn.approvals.removeValue(forKey: callId) else { return false }
    approval.respond(allow)
    if !allow { turn.denied += 1 }
    if allow {
      toolStarted(callId, name: approval.name, arguments: approval.arguments, readOnly: false)
    } else {
      toolClosed(callId, name: approval.name, arguments: approval.arguments, state: "denied",
        text: "The researcher denied this call. It did not run.")
    }
    return true
  }

  func endTurn(stopped: Bool = false, error message: String? = nil, notice text: String? = nil) {
    guard let current = turn else { return }
    finishText()
    for (callId, tool) in current.tools where tool.running {
      row(["type": "tool", "id": "tool-\(callId)", "name": tool.name, "arguments": tool.arguments, "state": "error",
        "result": "Stopped before this call finished.", "isError": true, "resultBytes": 33])
    }
    for (callId, approval) in current.approvals {
      row(["type": "tool", "id": "tool-\(callId)", "name": approval.name, "arguments": approval.arguments, "state": "denied",
        "result": "Stopped before a decision.", "isError": true, "resultBytes": 26])
    }
    if let text { notice(text) }
    if let message { error(message) }
    row(["type": "turnEnd", "stopped": stopped, "inputTokens": current.inputTokens, "outputTokens": current.outputTokens])
    turn = nil
    armIdle()
  }
}

// MARK: - Claude: `claude -p` over stream-json

@MainActor
final class AgentClaudeDriver: AgentCLIDriver {
  private var verified = false
  private var currentMessage = ""

  override func rebToolName(_ cliName: String) -> String? {
    cliName.hasPrefix("mcp__reb__") && cliName.count > 10 ? String(cliName.dropFirst(10)) : nil
  }

  // Each flag removes something the CLI would otherwise bring: built-in tools
  // (`--tools ""`), every other MCP server (`--strict-mcp-config`), user and
  // project settings, hooks and CLAUDE.md (`--setting-sources ""`), skills and
  // slash commands, and the on-disk session. `--bare` is not used: it ignores
  // the claude.ai login and accepts only an API key.
  override func launchArguments() throws -> [String] {
    let server: [String: Any] = [
      "type": "stdio", "command": configuration.apiExecutable.path, "args": configuration.mcpArguments,
      "env": configuration.mcpEnvironment,
    ]
    let mcp = String(decoding: try JSONSerialization.data(withJSONObject: ["mcpServers": ["reb": server]]), as: UTF8.self)
    var arguments = [
      "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
      "--permission-prompt-tool", "stdio", "--permission-mode", "default", "--strict-mcp-config", "--mcp-config", mcp,
      "--tools", "", "--setting-sources", "", "--settings", #"{"disableAllHooks":true}"#, "--disable-slash-commands",
      "--no-session-persistence", "--system-prompt", agentSystemPrompt(configuration.permission, sensitive: configuration.sensitive),
    ]
    if !configuration.model.isEmpty && configuration.model != "default" { arguments += ["--model", configuration.model] }
    // Tools the graph would not list are hidden from the model, not just refused.
    let hidden = listedToolNames.filter { name in !tools.contains { $0.name == name } }.map { "mcp__reb__\($0)" }
    if !hidden.isEmpty { arguments += ["--disallowed-tools", hidden.joined(separator: ",")] }
    return arguments
  }

  override func didLaunch() async throws {
    verified = false
    try write(["type": "control_request", "request_id": "origin-trace-initialize", "request": ["subtype": "initialize"]])
  }

  override func deliver(_ text: String) throws {
    try write([
      "type": "user", "message": ["role": "user", "content": [["type": "text", "text": text]]],
      "parent_tool_use_id": NSNull(), "session_id": "",
    ])
  }

  override func handle(_ line: [String: Any]) {
    switch line["type"] as? String {
    case "system":
      if line["subtype"] as? String == "init" { verify(line) }
    case "stream_event":
      guard let event = line["event"] as? [String: Any] else { return }
      streamEvent(event)
    case "user":
      let content = (line["message"] as? [String: Any])?["content"] as? [[String: Any]] ?? []
      for block in content where block["type"] as? String == "tool_result" {
        guard let id = block["tool_use_id"] as? String else { continue }
        toolFinished(id, text: Self.resultText(block["content"]), isError: block["is_error"] as? Bool == true)
      }
    case "control_request":
      controlRequest(line)
    case "result":
      result(line)
    case "rate_limit_event":
      let info = line["rate_limit_info"] as? [String: Any]
      if info?["status"] as? String == "rejected" { notice("Your Claude plan's usage limit was reached for now.") }
    default:
      return
    }
  }

  // The CLI reports what it loaded before the first request. Anything beyond
  // the one reb-api server, or an API key in place of the login, ends it.
  private func verify(_ line: [String: Any]) {
    let tools = line["tools"] as? [String] ?? []
    let servers = (line["mcp_servers"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
    let foreign = tools.filter { rebToolName($0) == nil } + servers.filter { $0 != "reb" }.map { "server \($0)" }
    if !foreign.isEmpty {
      abort("The Claude CLI loaded more than the reb-api tools (\(foreign.prefix(6).joined(separator: ", "))), so it was stopped.")
      return
    }
    if let source = line["apiKeySource"] as? String, source != "none" {
      abort("The Claude CLI is set to use an API key (\(source)) instead of your claude.ai login, so it was stopped.")
      return
    }
    verified = true
  }

  private func streamEvent(_ event: [String: Any]) {
    switch event["type"] as? String {
    case "message_start":
      currentMessage = (event["message"] as? [String: Any])?["id"] as? String ?? ""
    case "content_block_delta":
      let delta = event["delta"] as? [String: Any]
      if delta?["type"] as? String == "text_delta", let piece = delta?["text"] as? String { text(piece) }
    case "content_block_stop", "message_stop":
      finishText()
    default:
      return
    }
  }

  private func controlRequest(_ line: [String: Any]) {
    guard let requestId = line["request_id"] as? String else { return }
    let request = line["request"] as? [String: Any] ?? [:]
    guard request["subtype"] as? String == "can_use_tool" else {
      try? write(["type": "control_response", "response": ["subtype": "error", "request_id": requestId,
        "error": "Origin Trace does not answer this request."]])
      return
    }
    let input = request["input"] as? [String: Any] ?? [:]
    let callId = request["tool_use_id"] as? String ?? requestId
    guard verified else {
      try? write(["type": "control_response", "response": ["subtype": "success", "request_id": requestId,
        "response": ["behavior": "deny", "message": "The CLI's tool surface was not verified."]]])
      abort("The Claude CLI asked to run a tool before reporting what it loaded, so it was stopped.")
      return
    }
    permission(callId: callId, cliName: request["tool_name"] as? String ?? "", input: input) { [weak self] allow, message in
      let response: [String: Any] = allow
        ? ["behavior": "allow", "updatedInput": input]
        : ["behavior": "deny", "message": message ?? "Denied."]
      try? self?.write(["type": "control_response", "response": ["subtype": "success", "request_id": requestId, "response": response]])
    }
  }

  private func result(_ line: [String: Any]) {
    guard let turn else { return }
    let usage = line["usage"] as? [String: Any] ?? [:]
    let count = { (key: String) in (usage[key] as? NSNumber)?.intValue ?? 0 }
    turn.inputTokens = count("input_tokens") + count("cache_read_input_tokens") + count("cache_creation_input_tokens")
    turn.outputTokens = count("output_tokens")
    let failed = line["is_error"] as? Bool == true || (line["subtype"] as? String ?? "success") != "success"
    if failed {
      let detail = line["result"] as? String ?? (line["errors"] as? [String])?.joined(separator: " ") ?? (line["subtype"] as? String ?? "")
      endTurn(error: "The Claude CLI ended the turn with an error\(detail.isEmpty ? "." : ": \(detail.prefix(600))")")
    } else {
      endTurn(notice: line["stop_reason"] as? String == "refusal" ? "The provider declined this request." : nil)
    }
  }

  nonisolated static func resultText(_ content: Any?) -> String {
    if let text = content as? String { return text }
    return (content as? [[String: Any]] ?? []).compactMap { $0["text"] as? String }.joined(separator: "\n")
  }
}

// MARK: - Grok: `grok agent stdio` over ACP

@MainActor
final class AgentGrokDriver: AgentCLIDriver {
  // Process-scoped switches that keep the researcher's Grok setup out of this
  // session: no cross-session memory, subagents or web fetch, no Claude,
  // Cursor or Codex skills, rules, agents, MCP servers, hooks or sessions, no
  // update check. Folder trust is off so the private folder's own MCP stubs
  // (below) apply without a prompt; that folder holds nothing else.
  nonisolated static let isolation: [String: String] = {
    var values = [
      "GROK_FOLDER_TRUST": "0", "GROK_MEMORY": "0", "GROK_SUBAGENTS": "0", "GROK_WEB_FETCH": "0",
      "GROK_DISABLE_AUTOUPDATER": "1",
    ]
    for vendor in ["CLAUDE", "CURSOR", "CODEX"] {
      for surface in ["SKILLS", "RULES", "AGENTS", "MCPS", "HOOKS", "SESSIONS"] { values["GROK_\(vendor)_\(surface)_ENABLED"] = "0" }
    }
    return values
  }()
  // The model sees only these two: Grok reaches MCP tools through them.
  nonisolated static let allowedTools: Set<String> = ["search_tool", "use_tool"]
  private var nextId = 1
  private var pending: [Int: (Result<[String: Any], AgentFailure>) -> Void] = [:]
  private var sessionId: String?
  private var promptId: Int?
  // session/new answers before the tool server has connected; a first prompt
  // sent then finds no reb-api tools.
  private var toolsReady: Bool?
  private var toolsWaiter: CheckedContinuation<Void, Never>?
  private var toolsWait = 0

  override func rebToolName(_ cliName: String) -> String? {
    cliName.hasPrefix("reb__") && cliName.count > 5 ? String(cliName.dropFirst(5)) : nil
  }

  var profileURL: URL { workingDirectory.appendingPathComponent("origin-trace-agent.md") }
  var configURL: URL { workingDirectory.appendingPathComponent(".grok/config.toml") }

  override func launchEnvironment() -> [String: String] {
    AgentCLILocator.environment(baseEnvironment, executable: executable, extra: Self.isolation)
  }

  override func launchArguments() throws -> [String] {
    var arguments = ["--permission-mode", "default", "--disable-web-search", "--no-subagents", "agent", "--agent-profile",
      profileURL.path, "--no-leader"]
    if !configuration.model.isEmpty && configuration.model != "default" { arguments += ["-m", configuration.model] }
    return arguments + ["stdio"]
  }

  // An agent profile with only the two MCP tools and the shared system prompt.
  nonisolated static func profile(_ level: AgentPermission, sensitive: Bool) -> String {
    """
    ---
    name: origin-trace-agent
    description: Origin Trace research assistant with only the reb-api tools.
    prompt_mode: minimal
    permission_mode: default
    agents_md: false
    tools:
      - search_tool
      - use_tool
    ---

    \(agentSystemPrompt(level, sensitive: sensitive))

    The reb-api tools are reached through search_tool and use_tool. Their names start with reb__.

    """
  }

  // Grok merges MCP servers from the researcher's own configuration into
  // every ACP session, whatever the client sends. A server of the same name
  // in this folder's .grok/config.toml replaces it, so each one is replaced
  // by a disabled stub. `grok inspect` then has to show none left.
  override func prepareLaunch() async throws {
    let manager = FileManager.default
    try manager.createDirectory(at: configURL.deletingLastPathComponent(), withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    try Data(Self.profile(configuration.permission, sensitive: configuration.sensitive).utf8).write(to: profileURL, options: .atomic)
    var stubs = Self.stubbedNames(in: (try? String(contentsOf: configURL, encoding: .utf8)) ?? "")
    try Self.writeStubs(stubs, to: configURL)
    var report = try await inspect()
    let enabled = Self.enabledServers(report)
    if !enabled.isEmpty {
      guard enabled.allSatisfy(Self.isStubbable) else {
        throw AgentFailure(message: "Your Grok configuration has an MCP server Origin Trace cannot turn off for this session, so Grok was not started.")
      }
      stubs.formUnion(enabled)
      try Self.writeStubs(stubs, to: configURL)
      report = try await inspect()
    }
    let left = Self.enabledServers(report)
    let hooks = (report["hooks"] as? [Any])?.count ?? 0
    let plugins = (report["plugins"] as? [Any])?.count ?? 0
    guard left.isEmpty, hooks == 0, plugins == 0 else {
      var loaded = left.map { "MCP server \($0)" }
      if hooks > 0 { loaded.append("\(hooks) hook\(hooks == 1 ? "" : "s")") }
      if plugins > 0 { loaded.append("\(plugins) plugin\(plugins == 1 ? "" : "s")") }
      throw AgentFailure(message: "Grok would load \(loaded.prefix(4).joined(separator: ", ")) from your settings, so it was not started.")
    }
  }

  private func inspect() async throws -> [String: Any] {
    guard let result = await AgentChildProcess.run(executable, ["inspect", "--json"], environment: launchEnvironment(),
      directory: workingDirectory, timeout: 30),
      result.status == 0, let report = (try? JSONSerialization.jsonObject(with: result.output)) as? [String: Any]
    else { throw AgentFailure(message: "Origin Trace could not check what the Grok CLI loads, so it was not started.") }
    return report
  }

  nonisolated static func enabledServers(_ report: [String: Any]) -> Set<String> {
    Set((report["mcpServers"] as? [[String: Any]] ?? []).compactMap { server in
      server["disabled"] as? Bool == true ? nil : (server["name"] as? String ?? "?")
    })
  }

  nonisolated static func isStubbable(_ name: String) -> Bool {
    name.range(of: "^[A-Za-z0-9 _.@:/+-]{1,128}$", options: .regularExpression) != nil
  }

  nonisolated static func stubbedNames(in config: String) -> Set<String> {
    Set(config.split(separator: "\n").compactMap { line -> String? in
      guard line.hasPrefix("[mcp_servers.\""), line.hasSuffix("\"]") else { return nil }
      let name = String(line.dropFirst(14).dropLast(2))
      return isStubbable(name) ? name : nil
    })
  }

  nonisolated static func writeStubs(_ names: Set<String>, to url: URL) throws {
    var text = "# Written by Origin Trace. Its agent's Grok session runs with only the reb-api\n"
    text += "# tool server, so each MCP server from your Grok settings is replaced here by a\n# disabled stub.\n"
    for name in names.sorted() where isStubbable(name) {
      text += "\n[mcp_servers.\"\(name)\"]\ncommand = \"/usr/bin/false\"\nenabled = false\n"
    }
    try Data(text.utf8).write(to: url, options: .atomic)
  }

  override func didLaunch() async throws {
    sessionId = nil
    let initialized = try await request("initialize", [
      "protocolVersion": 1,
      "clientCapabilities": ["fs": ["readTextFile": false, "writeTextFile": false], "terminal": false],
      "clientInfo": ["name": "origin-trace", "version": "1"],
    ])
    let methods = (initialized["authMethods"] as? [[String: Any]] ?? []).compactMap { $0["id"] as? String }
    guard methods.contains("cached_token") else {
      throw AgentFailure(message: "This Grok CLI does not offer its saved sign-in to other apps. Update Grok, then try again.")
    }
    do {
      _ = try await request("authenticate", ["methodId": "cached_token"])
    } catch {
      throw AgentFailure(message: "The Grok CLI is not signed in. Run grok login in Terminal, then ask again.")
    }
    let server: [String: Any] = [
      "name": "reb", "command": configuration.apiExecutable.path, "args": configuration.mcpArguments,
      "env": configuration.mcpEnvironment.sorted { $0.key < $1.key }.map { ["name": $0.key, "value": $0.value] },
    ]
    let session = try await request("session/new", ["cwd": workingDirectory.path, "mcpServers": [server]], timeout: 90)
    guard let id = session["sessionId"] as? String, !id.isEmpty else {
      throw AgentFailure(message: "The Grok CLI did not open a session.")
    }
    sessionId = id
    if toolsReady == nil {
      toolsWait += 1
      let wait = toolsWait
      await withCheckedContinuation { continuation in
        toolsWaiter = continuation
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
          MainActor.assumeIsolated { if self?.toolsWait == wait { self?.toolsSettled(nil) } }
        }
      }
    }
    guard toolsReady != false else { throw AgentFailure(message: "The reb-api tool server did not start inside the Grok CLI.") }
  }

  private func toolsSettled(_ ready: Bool?) {
    if let ready, toolsReady == nil { toolsReady = ready }
    toolsWaiter?.resume()
    toolsWaiter = nil
  }

  override func deliver(_ text: String) throws {
    guard let sessionId else { throw AgentFailure(message: "The Grok CLI has no open session.") }
    let id = nextId
    nextId += 1
    promptId = id
    pending[id] = { [weak self] outcome in self?.promptEnded(outcome) }
    try write(["jsonrpc": "2.0", "id": id, "method": "session/prompt",
      "params": ["sessionId": sessionId, "prompt": [["type": "text", "text": text]]]])
  }

  private func request(_ method: String, _ params: [String: Any], timeout: TimeInterval = 60) async throws -> [String: Any] {
    let id = nextId
    nextId += 1
    return try await withCheckedThrowingContinuation { continuation in
      pending[id] = { outcome in
        switch outcome {
        case .success(let value): continuation.resume(returning: value)
        case .failure(let failure): continuation.resume(throwing: failure)
        }
      }
      do {
        try write(["jsonrpc": "2.0", "id": id, "method": method, "params": params])
      } catch {
        pending.removeValue(forKey: id)?(.failure(AgentFailure(message: "The Grok CLI is not accepting requests.")))
        return
      }
      DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
        MainActor.assumeIsolated {
          self?.pending.removeValue(forKey: id)?(.failure(AgentFailure(message: "The Grok CLI did not answer \(method) in time.")))
        }
      }
    }
  }

  override func cliStopped() {
    let waiting = pending
    pending.removeAll()
    sessionId = nil
    toolsReady = nil
    toolsSettled(nil)
    // The turn's own ending is decided by whoever stopped the CLI.
    for (id, callback) in waiting where id != promptId {
      callback(.failure(AgentFailure(message: "The Grok CLI stopped.")))
    }
    promptId = nil
  }

  override func handle(_ line: [String: Any]) {
    let method = (line["method"] as? String).map { $0.hasPrefix("_") ? String($0.dropFirst()) : $0 }
    if let method {
      if let id = line["id"] { agentRequest(method, id: id, params: line["params"] as? [String: Any] ?? [:]) }
      else { notification(method, params: line["params"] as? [String: Any] ?? [:]) }
      return
    }
    guard let id = (line["id"] as? NSNumber)?.intValue, let callback = pending.removeValue(forKey: id) else { return }
    if let failure = line["error"] as? [String: Any] {
      callback(.failure(AgentFailure(message: failure["message"] as? String ?? "The Grok CLI returned an error.")))
    } else {
      callback(.success(line["result"] as? [String: Any] ?? [:]))
    }
  }

  private func agentRequest(_ method: String, id: Any, params: [String: Any]) {
    guard method == "session/request_permission" else {
      try? write(["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "Origin Trace does not offer \(method)."]])
      return
    }
    let call = params["toolCall"] as? [String: Any] ?? [:]
    let raw = call["rawInput"] as? [String: Any] ?? [:]
    let callId = call["toolCallId"] as? String ?? UUID().uuidString
    let options = params["options"] as? [[String: Any]] ?? []
    let option = { (kind: String) in options.first { $0["kind"] as? String == kind }?["optionId"] as? String }
    let reply = { [weak self] (choice: String?) in
      let outcome: [String: Any] = choice.map { ["outcome": "selected", "optionId": $0] } ?? ["outcome": "cancelled"]
      try? self?.write(["jsonrpc": "2.0", "id": id, "result": ["outcome": outcome]])
    }
    let allowOnce = option("allow_once"), rejectOnce = option("reject_once")
    // Only a use_tool call names a reb-api tool. Never answer allow_always.
    guard raw["variant"] as? String == "UseTool", let name = raw["tool_name"] as? String, allowOnce != nil else {
      reply(rejectOnce)
      abort("The Grok CLI asked to run \(String(describing: call["title"] ?? "a tool").prefix(80)), which is not a reb-api tool, so it was stopped.")
      return
    }
    permission(callId: callId, cliName: name, input: raw["tool_input"]) { allow, _ in reply(allow ? allowOnce : rejectOnce) }
  }

  private func notification(_ method: String, params: [String: Any]) {
    switch method {
    case "session/update":
      sessionUpdate(params["update"] as? [String: Any] ?? [:])
    case "x.ai/mcp/servers_updated":
      let names = (params["mcpServers"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
      if !names.isEmpty {
        let message = "Grok loaded MCP servers from your settings (\(names.prefix(4).joined(separator: ", "))), so it was stopped."
        if turn != nil { abort(message) } else { terminate(); error(message) }
      }
    case "x.ai/mcp_initialized":
      toolsSettled(true)
    case "x.ai/mcp/server_status" where params["name"] as? String == "reb":
      if params["status"] as? String == "ready" { toolsSettled(true) }
      else if params["status"] as? String == "failed" { toolsSettled(false) }
    case "x.ai/session_notification":
      let update = params["update"] as? [String: Any] ?? [:]
      if update["sessionUpdate"] as? String == "turn_completed", let usage = update["usage"] as? [String: Any], let turn {
        turn.inputTokens = (usage["inputTokens"] as? NSNumber)?.intValue ?? turn.inputTokens
        turn.outputTokens = (usage["outputTokens"] as? NSNumber)?.intValue ?? turn.outputTokens
      }
    default:
      return
    }
  }

  private func sessionUpdate(_ update: [String: Any]) {
    switch update["sessionUpdate"] as? String {
    case "agent_message_chunk":
      let content = update["content"] as? [String: Any]
      if content?["type"] as? String == "text", let piece = content?["text"] as? String { text(piece) }
    case "tool_call":
      let meta = (update["_meta"] as? [String: Any])?["x.ai/tool"] as? [String: Any]
      let kind = meta?["name"] as? String ?? update["title"] as? String ?? ""
      guard Self.allowedTools.contains(kind) else {
        abort("The Grok CLI started a built-in tool (\(kind.prefix(60))), so it was stopped.")
        return
      }
      finishText()
      // Discovery lists only this session's reb-api tools and runs without a
      // prompt, so it is shown as a read.
      if kind == "search_tool", let id = update["toolCallId"] as? String {
        toolStarted(id, name: "search_tool", arguments: Self.argumentText(update["rawInput"]), readOnly: true)
      }
    case "tool_call_update":
      guard let id = update["toolCallId"] as? String, let status = update["status"] as? String,
        status == "completed" || status == "failed"
      else { return }
      let output = Self.outputText(update)
      toolFinished(id, text: output.text, isError: status == "failed" || output.isError)
    default:
      return
    }
  }

  nonisolated static func outputText(_ update: [String: Any]) -> (text: String, isError: Bool) {
    if let raw = update["rawOutput"] as? [String: Any] {
      if let output = raw["output"] as? [String: Any], output.count == 1, let entry = output.first, let text = entry.value as? String {
        return (text, entry.key.localizedCaseInsensitiveContains("error"))
      }
      if let text = raw["output"] as? String { return (text, false) }
      return (argumentText(raw), false)
    }
    let blocks = update["content"] as? [[String: Any]] ?? []
    let text = blocks.compactMap { ($0["content"] as? [String: Any])?["text"] as? String }.joined(separator: "\n")
    return (text, false)
  }

  private func promptEnded(_ outcome: Result<[String: Any], AgentFailure>) {
    promptId = nil
    guard turn != nil else { return }
    switch outcome {
    case .failure(let failure):
      endTurn(error: "The Grok CLI ended the turn with an error: \(failure.message.prefix(600))")
    case .success(let result):
      switch result["stopReason"] as? String {
      // Grok ends the whole turn when a call is rejected; that is not a Stop.
      case "cancelled" where (turn?.denied ?? 0) > 0: endTurn(notice: "Grok ended this turn after the denied call.")
      case "cancelled": endTurn(stopped: true)
      case "refusal": endTurn(notice: "The provider declined this request.")
      case "max_tokens", "max_turn_requests": endTurn(notice: "The Grok CLI stopped this turn at its own limit.")
      default: endTurn()
      }
    }
  }
}
