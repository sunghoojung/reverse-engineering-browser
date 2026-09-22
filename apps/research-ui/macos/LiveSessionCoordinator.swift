import Foundation

final class LiveSessionCoordinator {
  private let lock = NSLock()
  private var process: Process?
  private var logHandle: FileHandle?
  private var generation = UUID()
  private var becameReady = false

  var isRunning: Bool {
    lock.lock()
    defer { lock.unlock() }
    return process?.isRunning == true
  }

  func start(
    braveExecutableURL: URL,
    ready: @escaping (URL) -> Void,
    failed: @escaping (String) -> Void
  ) {
    lock.lock()
    if process?.isRunning == true {
      lock.unlock()
      return
    }
    let currentGeneration = UUID()
    generation = currentGeneration
    becameReady = false
    lock.unlock()

    do {
      let configuration = try makeConfiguration(braveExecutableURL: braveExecutableURL)
      let child = Process()
      child.executableURL = URL(fileURLWithPath: "/bin/bash")
      child.arguments = [configuration.scriptURL.path]
      child.environment = configuration.environment
      child.currentDirectoryURL = configuration.researchUIURL
      child.standardOutput = configuration.logHandle
      child.standardError = configuration.logHandle
      child.terminationHandler = { [weak self] terminated in
        self?.handleTermination(
          process: terminated,
          generation: currentGeneration,
          logURL: configuration.logURL,
          failed: failed
        )
      }

      lock.lock()
      process = child
      logHandle = configuration.logHandle
      lock.unlock()
      try child.run()

      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        self?.waitForReadiness(
          process: child,
          generation: currentGeneration,
          handshakeURL: configuration.handshakeURL,
          logURL: configuration.logURL,
          ready: ready,
          failed: failed
        )
      }
    } catch {
      stop()
      DispatchQueue.main.async {
        failed(error.localizedDescription)
      }
    }
  }

  func stop() {
    lock.lock()
    let child = process
    process = nil
    let handle = logHandle
    logHandle = nil
    generation = UUID()
    lock.unlock()

    if child?.isRunning == true {
      child?.terminate()
    }
    try? handle?.close()
  }

  deinit {
    stop()
  }

  private struct Configuration {
    let scriptURL: URL
    let researchUIURL: URL
    let handshakeURL: URL
    let logURL: URL
    let logHandle: FileHandle
    let environment: [String: String]
  }

  private func makeConfiguration(braveExecutableURL: URL) throws -> Configuration {
    guard let resourcesURL = Bundle.main.resourceURL else {
      throw sessionError("Application resources are missing")
    }
    let macOSURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS")
    let researchUIURL = resourcesURL.appendingPathComponent("research-ui", isDirectory: true)
    let scriptURL = resourcesURL.appendingPathComponent("run-live-session.sh")
    let requiredFiles = [
      scriptURL,
      researchUIURL.appendingPathComponent("server.py"),
      researchUIURL.appendingPathComponent("vm_analyzer.py"),
      macOSURL.appendingPathComponent("OriginTraceEventBroker"),
      macOSURL.appendingPathComponent("OriginTraceArtifactReceiver"),
      macOSURL.appendingPathComponent("OriginTraceDebuggerTransport"),
      macOSURL.appendingPathComponent("OriginTraceHeapSnapshot"),
      macOSURL.appendingPathComponent("OriginTraceDecoder"),
      macOSURL.appendingPathComponent("OriginTraceDeobfuscator"),
    ]
    guard requiredFiles.allSatisfy({ FileManager.default.fileExists(atPath: $0.path) }) else {
      throw sessionError("The application bundle is missing a live capture helper")
    }
    guard FileManager.default.isExecutableFile(atPath: braveExecutableURL.path) else {
      throw sessionError("Brave Browser Development is not executable")
    }
    guard let pythonURL = pythonExecutableURL() else {
      throw sessionError(
        "Python 3 is required for the live debugger. Install Python 3 and reopen Origin Trace."
      )
    }

    let applicationSupportURL =
      FileManager.default.urls(
        for: .applicationSupportDirectory,
        in: .userDomainMask
      ).first
      ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
        "Library/Application Support"
      )
    let originTraceURL = applicationSupportURL.appendingPathComponent(
      "Origin Trace",
      isDirectory: true
    )
    let sessionRootURL = originTraceURL.appendingPathComponent("sessions/live", isDirectory: true)
    let logsURL = originTraceURL.appendingPathComponent("logs", isDirectory: true)
    try FileManager.default.createDirectory(
      at: sessionRootURL,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.createDirectory(
      at: logsURL,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )

    let identifier = UUID().uuidString
    let handshakeURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "origin-trace-live-\(identifier).endpoint"
    )
    let logURL = logsURL.appendingPathComponent("live-session-\(identifier).log")
    FileManager.default.createFile(
      atPath: logURL.path,
      contents: Data(),
      attributes: [.posixPermissions: 0o600]
    )
    let logHandle = try FileHandle(forWritingTo: logURL)

    var environment = ProcessInfo.processInfo.environment
    environment["REB_EMBEDDED_SESSION"] = "1"
    environment["REB_SESSION_HANDSHAKE"] = handshakeURL.path
    environment["REB_SESSION_OWNER_PID"] = String(ProcessInfo.processInfo.processIdentifier)
    environment["REB_LIVE_SESSION_ROOT"] = sessionRootURL.path
    environment["REB_BRAVE_BINARY"] = braveExecutableURL.path
    environment["REB_PYTHON_BINARY"] = pythonURL.path
    environment["REB_BROKER_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceEventBroker"
      ).path
    environment["REB_ARTIFACT_RECEIVER_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceArtifactReceiver"
      ).path
    environment["REB_DEBUGGER_TRANSPORT_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceDebuggerTransport"
      ).path
    environment["REB_HEAP_SNAPSHOT_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceHeapSnapshot"
      ).path
    environment["REB_DECODER_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceDecoder"
      ).path
    environment["REB_DEOBFUSCATOR_WORKER"] =
      macOSURL.appendingPathComponent(
        "OriginTraceDeobfuscator"
      ).path
    environment["REB_RESEARCH_UI_SERVER"] =
      researchUIURL.appendingPathComponent(
        "server.py"
      ).path
    environment["REB_VM_ANALYZER"] =
      researchUIURL.appendingPathComponent(
        "vm_analyzer.py"
      ).path
    environment["REB_API_COLLECTION_STORE"] =
      originTraceURL.appendingPathComponent(
        "api-collection-v1.json"
      ).path
    environment["REB_LOCAL_ANALYST_STORE"] =
      originTraceURL.appendingPathComponent(
        "local-analyst-workspace-v1.json"
      ).path

    return Configuration(
      scriptURL: scriptURL,
      researchUIURL: researchUIURL,
      handshakeURL: handshakeURL,
      logURL: logURL,
      logHandle: logHandle,
      environment: environment
    )
  }

  private func waitForReadiness(
    process child: Process,
    generation currentGeneration: UUID,
    handshakeURL: URL,
    logURL: URL,
    ready: @escaping (URL) -> Void,
    failed: @escaping (String) -> Void
  ) {
    for _ in 0..<300 {
      if !isCurrent(currentGeneration) { return }
      if let text = try? String(contentsOf: handshakeURL, encoding: .utf8),
        let url = validatedLoopbackURL(text.trimmingCharacters(in: .whitespacesAndNewlines))
      {
        lock.lock()
        if generation == currentGeneration {
          becameReady = true
        }
        lock.unlock()
        DispatchQueue.main.async {
          ready(url)
        }
        return
      }
      if !child.isRunning {
        reportFailureOnce(
          generation: currentGeneration,
          message: failureMessage(logURL: logURL),
          failed: failed
        )
        return
      }
      Thread.sleep(forTimeInterval: 0.05)
    }
    if child.isRunning {
      child.terminate()
    }
    reportFailureOnce(
      generation: currentGeneration,
      message: "Live capture did not become ready within 15 seconds. "
        + failureMessage(logURL: logURL),
      failed: failed
    )
  }

  private func handleTermination(
    process child: Process,
    generation currentGeneration: UUID,
    logURL: URL,
    failed: @escaping (String) -> Void
  ) {
    lock.lock()
    let shouldReport = generation == currentGeneration && !becameReady
    if process === child {
      process = nil
      try? logHandle?.close()
      logHandle = nil
    }
    lock.unlock()
    if shouldReport {
      reportFailureOnce(
        generation: currentGeneration,
        message: failureMessage(logURL: logURL),
        failed: failed
      )
    }
  }

  private func reportFailureOnce(
    generation currentGeneration: UUID,
    message: String,
    failed: @escaping (String) -> Void
  ) {
    lock.lock()
    guard generation == currentGeneration, !becameReady else {
      lock.unlock()
      return
    }
    becameReady = true
    lock.unlock()
    DispatchQueue.main.async {
      failed(message)
    }
  }

  private func isCurrent(_ currentGeneration: UUID) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return generation == currentGeneration
  }

  private func pythonExecutableURL() -> URL? {
    var candidates: [String] = []
    if let configured = ProcessInfo.processInfo.environment["REB_PYTHON_BINARY"],
      !configured.isEmpty
    {
      candidates.append(configured)
    }
    candidates.append(contentsOf: [
      "/usr/bin/python3",
      "/opt/homebrew/bin/python3",
      "/usr/local/bin/python3",
    ])
    return candidates.lazy.map(URL.init(fileURLWithPath:)).first {
      FileManager.default.isExecutableFile(atPath: $0.path)
    }
  }

  private func validatedLoopbackURL(_ value: String) -> URL? {
    guard let url = URL(string: value),
      let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
      components.scheme == "http",
      Set(["127.0.0.1", "localhost", "::1"]).contains(components.host ?? ""),
      components.port != nil,
      components.user == nil,
      components.password == nil,
      components.fragment == nil
    else { return nil }
    return url
  }

  private func failureMessage(logURL: URL) -> String {
    guard let data = try? Data(contentsOf: logURL), !data.isEmpty else {
      return "The live capture coordinator stopped before startup completed."
    }
    let tail = data.suffix(4 * 1_024)
    let text = String(decoding: tail, as: UTF8.self).trimmingCharacters(
      in: .whitespacesAndNewlines
    )
    return text.isEmpty ? "The live capture coordinator stopped before startup completed." : text
  }

  private func sessionError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace.LiveSession",
      code: 1,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}
