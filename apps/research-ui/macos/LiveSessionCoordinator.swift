import Foundation

// The evidence boundary of an app-started capture. Content is the default;
// Metadata is the opt-out.
enum LiveCaptureMode: String {
  case content
  case metadata

  var capturesNetworkContent: Bool { self == .content }

  var title: String {
    switch self {
    case .content:
      return "Content (default)"
    case .metadata:
      return "Metadata only"
    }
  }

  // The app saves no choice between launches, so REB_AUTOMATIC_CAPTURE_MODE is
  // the only durable one. Unset or empty means the default. Any other value but
  // "content" selects Metadata, so a misspelled opt-out never turns on content.
  static func configured(_ environment: [String: String]) -> LiveCaptureMode {
    guard let value = environment["REB_AUTOMATIC_CAPTURE_MODE"], !value.isEmpty else {
      return .content
    }
    return LiveCaptureMode(rawValue: value) ?? .metadata
  }
}

// The app's saved native JavaScript invocation sites, which every capture it
// starts arms (protocol/native-js-invocation-v1.md#site-file). The site file
// is exactly the browser's native-js-invocation-sites-v1 form with 1 to 8
// sites; a sidecar the browser never reads keeps each label, source URL and
// session. The backend's routes add sites from Sources, the start dialog lists
// and removes them, and each capture arms a private copy, because the browser
// rereads the file it was given and refuses a session whose file changed.
struct InvocationSiteSet: Equatable {
  struct Site: Equatable {
    let anchorOffset: UInt32
    let artifactID: String
    let artifactSHA256: String
    let byteOffset: UInt32
    let sourceLength: UInt32
    let sourceSHA256: String
    var label = "Unlabeled function"
    var sourceURL: String?
    var sessionID: String?

    // Sorted keys, compact. Every string is ASCII digits or lowercase hex.
    var canonical: String {
      "{\"anchor_offset\":\(anchorOffset),\"artifact_id\":\"\(artifactID)\",\"artifact_sha256\":\"\(artifactSHA256)\","
        + "\"byte_offset\":\(byteOffset),\"shape\":\"function-entry\",\"source_length\":\(sourceLength),"
        + "\"source_sha256\":\"\(sourceSHA256)\"}"
    }

    func sameFunction(_ other: Site) -> Bool {
      sourceSHA256 == other.sourceSHA256 && anchorOffset == other.anchorOffset
    }
  }

  enum State: Equatable {
    case empty
    case saved([Site])
    // A file the browser would refuse is never armed; the dialog offers Clear.
    case unreadable
  }

  static let limit = 8
  static let fileLimit = 4096
  static let fileName = "js-invocation-sites-v1.json"

  // An explicit REB_JS_INVOCATION_SITE_STORE wins, as for the other app stores.
  static func storeURL(environment: [String: String], applicationSupport: URL) -> URL {
    if let path = environment["REB_JS_INVOCATION_SITE_STORE"], !path.isEmpty {
      return URL(fileURLWithPath: path).standardizedFileURL
    }
    return applicationSupport.appendingPathComponent(fileName)
  }

  static func labelsURL(_ url: URL) -> URL {
    url.deletingLastPathComponent().appendingPathComponent(
      url.deletingPathExtension().lastPathComponent + ".labels.json")
  }

  static func file(_ sites: [Site]) -> String? {
    guard (1...limit).contains(sites.count) else { return nil }
    for (index, site) in sites.enumerated() where sites[..<index].contains(where: { $0.sameFunction(site) }) {
      return nil
    }
    let text = "{\"sites\":[" + sites.map(\.canonical).joined(separator: ",") + "],\"version\":1}"
    return text.utf8.count <= fileLimit ? text : nil
  }

  // Accepts exactly what the browser accepts: the canonical text of 1 to 8
  // distinct valid sites. Rebuilding the text rejects every other spelling.
  static func parse(_ text: String) -> [Site]? {
    guard !text.isEmpty, text.utf8.count <= fileLimit,
      let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
      Set(object.keys) == ["sites", "version"], let entries = object["sites"] as? [[String: Any]]
    else { return nil }
    let keys: Set<String> = ["anchor_offset", "artifact_id", "artifact_sha256", "byte_offset", "shape", "source_length", "source_sha256"]
    let number = { (value: Any?) in (value as? NSNumber).flatMap { UInt32(exactly: $0.int64Value) } }
    let hex = { (value: Any?) -> String? in
      guard let text = value as? String, text.utf8.count == 64,
        text.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
      else { return nil }
      return text
    }
    var sites: [Site] = []
    for entry in entries {
      guard Set(entry.keys) == keys, entry["shape"] as? String == "function-entry",
        let anchor = number(entry["anchor_offset"]), let byteOffset = number(entry["byte_offset"]),
        let length = number(entry["source_length"]), length > 0, anchor < length,
        let artifactID = entry["artifact_id"] as? String, canonicalID(artifactID),
        let artifactSHA256 = hex(entry["artifact_sha256"]), let sourceSHA256 = hex(entry["source_sha256"])
      else { return nil }
      sites.append(Site(anchorOffset: anchor, artifactID: artifactID, artifactSHA256: artifactSHA256,
        byteOffset: byteOffset, sourceLength: length, sourceSHA256: sourceSHA256))
    }
    return file(sites) == text ? sites : nil
  }

  static func canonicalID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    return (1...20).contains(bytes.count) && bytes.allSatisfy({ (48...57).contains($0) })
      && (bytes.count == 1 || bytes[0] != 48) && UInt64(value) != nil
  }

  static func load(_ url: URL) -> State {
    guard let data = try? Data(contentsOf: url) else {
      return FileManager.default.fileExists(atPath: url.path) ? .unreadable : .empty
    }
    guard let text = String(data: data, encoding: .utf8), var sites = parse(text) else { return .unreadable }
    let labels = (try? Data(contentsOf: labelsURL(url)))
      .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
      .flatMap { ($0["version"] as? NSNumber)?.intValue == 1 ? $0["sites"] as? [[String: Any]] : nil } ?? []
    for index in sites.indices {
      let site = sites[index]
      guard let entry = labels.first(where: {
        $0["source_sha256"] as? String == site.sourceSHA256
          && ($0["anchor_offset"] as? NSNumber)?.int64Value == Int64(site.anchorOffset)
      }) else { continue }
      if let label = entry["label"] as? String, !label.isEmpty, label.count <= 128,
        !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
      {
        sites[index].label = label
      }
      sites[index].sourceURL = (entry["source_url"] as? String).flatMap { $0.isEmpty || $0.utf8.count > 8192 ? nil : $0 }
      sites[index].sessionID = (entry["session_id"] as? String).flatMap { canonicalID($0) ? $0 : nil }
    }
    return .saved(sites)
  }

  // Labels first, then the site file, as the backend writes them, so the site
  // file never names a site whose label was lost. An empty set has no file.
  static func write(_ sites: [Site], to url: URL) throws {
    if sites.isEmpty {
      for path in [url, labelsURL(url)] where FileManager.default.fileExists(atPath: path.path) {
        try FileManager.default.removeItem(at: path)
      }
      return
    }
    guard let text = file(sites) else { throw siteError("The saved invocation sites cannot be written") }
    let labels: [String: Any] = ["version": 1, "sites": sites.map { site -> [String: Any] in
      ["anchor_offset": site.anchorOffset, "label": site.label, "source_sha256": site.sourceSHA256,
       "source_url": site.sourceURL ?? NSNull(), "session_id": site.sessionID ?? NSNull()]
    }]
    try writePrivate(try JSONSerialization.data(withJSONObject: labels, options: [.sortedKeys]), to: labelsURL(url))
    try writePrivate(Data(text.utf8), to: url)
  }

  // Atomic and user-only from the first byte: a 0600 temporary in the same
  // folder, synced, then renamed over the destination.
  static func writePrivate(_ data: Data, to url: URL) throws {
    let folder = url.deletingLastPathComponent()
    if !FileManager.default.fileExists(atPath: folder.path) {
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    }
    let temporary = folder.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
    let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else { throw siteError("Cannot create \(temporary.path)") }
    let written = data.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
    let synced = fsync(descriptor) == 0
    close(descriptor)
    guard written == data.count, synced, rename(temporary.path, url.path) == 0 else {
      unlink(temporary.path)
      throw siteError("Cannot write \(url.path)")
    }
  }

  private static func siteError(_ message: String) -> NSError {
    NSError(domain: "OriginTrace.InvocationSites", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
  }
}

final class LiveSessionCoordinator {
  private let lock = NSLock()
  private var process: Process?
  private var logHandle: FileHandle?
  // This launch's copy of the saved invocation sites, removed when it ends.
  private var invocationSitesCopy: URL?
  private var generation = UUID()
  private var failureReported = false

  var isRunning: Bool {
    lock.lock()
    defer { lock.unlock() }
    return process?.isRunning == true
  }

  func start(
    braveExecutableURL: URL,
    captureNetworkContent: Bool,
    useSystemKeychain: Bool,
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
    failureReported = false
    lock.unlock()

    do {
      let configuration = try makeConfiguration(
        braveExecutableURL: braveExecutableURL,
        captureNetworkContent: captureNetworkContent,
        useSystemKeychain: useSystemKeychain
      )
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
      invocationSitesCopy = configuration.invocationSitesURL
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
    let copy = invocationSitesCopy
    invocationSitesCopy = nil
    generation = UUID()
    lock.unlock()

    if child?.isRunning == true {
      child?.terminate()
    }
    try? handle?.close()
    if let copy { try? FileManager.default.removeItem(at: copy) }
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
    let invocationSitesURL: URL?
  }

  private func makeConfiguration(
    braveExecutableURL: URL,
    captureNetworkContent: Bool,
    useSystemKeychain: Bool
  ) throws -> Configuration {
    guard let resourcesURL = Bundle.main.resourceURL else {
      throw sessionError("Application resources are missing")
    }
    let macOSURL = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS")
    let researchUIURL = resourcesURL.appendingPathComponent("research-ui", isDirectory: true)
    let scriptURL = resourcesURL.appendingPathComponent("run-live-session.sh")
    let requiredFiles = [
      scriptURL,
      macOSURL.appendingPathComponent("OriginTraceBackend"),
      macOSURL.appendingPathComponent("OriginTraceVMAnalyzer"),
      macOSURL.appendingPathComponent("OriginTraceEventBroker"),
      macOSURL.appendingPathComponent("OriginTraceArtifactReceiver"),
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
    let cachesURL =
      FileManager.default.urls(
        for: .cachesDirectory,
        in: .userDomainMask
      ).first
      ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches")
    let browserCacheRootURL = cachesURL.appendingPathComponent(
      "Origin Trace/sessions/live",
      isDirectory: true
    )
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
    try FileManager.default.createDirectory(
      at: browserCacheRootURL,
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
    environment["REB_BRAVE_CACHE_ROOT"] = browserCacheRootURL.path
    environment["REB_BRAVE_BINARY"] = braveExecutableURL.path
    // Sources can save sites while this capture runs; the browser keeps
    // reading the copy it was given, which nothing changes.
    let siteStoreURL = InvocationSiteSet.storeURL(environment: environment, applicationSupport: originTraceURL)
    environment["REB_JS_INVOCATION_SITE_STORE"] = siteStoreURL.path
    var invocationSitesURL: URL?
    if environment["REB_NATIVE_JS_INVOCATION_SITES"] == nil,
      case .saved(let sites) = InvocationSiteSet.load(siteStoreURL), let text = InvocationSiteSet.file(sites)
    {
      let copy = FileManager.default.temporaryDirectory.appendingPathComponent(
        "origin-trace-live-\(identifier)-js-invocation-sites.json")
      try InvocationSiteSet.writePrivate(Data(text.utf8), to: copy)
      invocationSitesURL = copy
    }
    environment = Self.captureDefaults(
      environment: environment, captureNetworkContent: captureNetworkContent,
      savedInvocationSites: invocationSitesURL)
    // A mask without VM leaves the copy unused.
    if let copy = invocationSitesURL, environment["REB_NATIVE_JS_INVOCATION_SITES"] != copy.path {
      try? FileManager.default.removeItem(at: copy)
      invocationSitesURL = nil
    }
    environment["REB_USE_SYSTEM_KEYCHAIN"] = useSystemKeychain ? "1" : "0"
    environment["REB_BROKER_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceEventBroker"
      ).path
    environment["REB_ARTIFACT_RECEIVER_BINARY"] =
      macOSURL.appendingPathComponent(
        "OriginTraceArtifactReceiver"
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
    environment["REB_ORIGIN_TRACE_BACKEND"] = macOSURL.appendingPathComponent("OriginTraceBackend").path
    environment["REB_VM_ANALYZER"] = macOSURL.appendingPathComponent("OriginTraceVMAnalyzer").path
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
      environment: environment,
      invocationSitesURL: invocationSitesURL
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
    // Broker and receiver each allow 5 seconds, backend 15, and Brave 30.
    // Let those helpers report their own failure before the outer deadline.
    for _ in 0..<1200 {
      if !isCurrent(currentGeneration) { return }
      if let text = try? String(contentsOf: handshakeURL, encoding: .utf8),
        let url = validatedLoopbackURL(text.trimmingCharacters(in: .whitespacesAndNewlines))
      {
        lock.lock()
        guard generation == currentGeneration, !failureReported else {
          lock.unlock()
          return
        }
        lock.unlock()
        DispatchQueue.main.async { [weak self] in
          guard self?.isCurrent(currentGeneration) == true else { return }
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
      message: "Live capture did not become ready within 60 seconds. "
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
    let shouldReport = generation == currentGeneration && !failureReported
    var copy: URL?
    if process === child {
      process = nil
      try? logHandle?.close()
      logHandle = nil
      copy = invocationSitesCopy
      invocationSitesCopy = nil
    }
    lock.unlock()
    if let copy { try? FileManager.default.removeItem(at: copy) }
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
    guard generation == currentGeneration, !failureReported else {
      lock.unlock()
      return
    }
    failureReported = true
    lock.unlock()
    DispatchQueue.main.async {
      failed(message)
    }
  }

  private func isCurrent(_ currentGeneration: UUID) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return generation == currentGeneration && !failureReported
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

  // The launcher's REB_CAPTURE_CATEGORY_MASK grammar (scripts/run-live-session.sh):
  // up to 10 decimal digits, or 0x and up to 8 hex digits, naming a mask from 1
  // to 4095. Unset or empty is the launcher default, 4095. Anything else is nil;
  // the launcher refuses it, and it must never read as every category.
  static func categoryMask(_ value: String?) -> UInt32? {
    guard let value, !value.isEmpty else { return 4095 }
    let bytes = Array(value.utf8)
    let hex = bytes.count > 2 && bytes[0] == UInt8(ascii: "0")
      && (bytes[1] == UInt8(ascii: "x") || bytes[1] == UInt8(ascii: "X"))
    let digits = hex ? bytes[2...] : bytes[...]
    // Explicit ASCII: Swift's integer parser also takes a sign, Character
    // digit tests take non-ASCII digits, and Bash takes neither.
    let isDigit: (UInt8) -> Bool = { byte in
      (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        || (hex && ((UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
          || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)))
    }
    guard (1...(hex ? 8 : 10)).contains(digits.count), digits.allSatisfy(isDigit),
      let mask = UInt64(String(decoding: digits, as: UTF8.self), radix: hex ? 16 : 10),
      (1...4095).contains(mask)
    else { return nil }
    return UInt32(mask)
  }

  // Defaults the packaged app adds for a live session. An explicit environment
  // value always wins. Each default capture also needs its categories in the
  // mask, read with the launcher's grammar, so a narrower mask leaves it off
  // rather than failing the launch, and an unreadable mask turns nothing on.
  //
  // `savedInvocationSites` is this launch's private copy of the app's saved
  // site set, or nil when the set is empty. The sites need the VM category
  // (512). The launcher arms them only if this Brave defines invocation
  // capture, and otherwise starts without them and says so. Their settled-value
  // digests are sensitive capture: on in Content mode, off in Metadata mode.
  static func captureDefaults(
    environment: [String: String], captureNetworkContent: Bool, savedInvocationSites: URL? = nil
  ) -> [String: String] {
    var environment = environment
    let mask = categoryMask(environment["REB_CAPTURE_CATEGORY_MASK"]) ?? 0
    let allows = { (required: UInt32) in mask & required == required }
    // Canvas images need Canvas (1) and Artifact (1024).
    environment["REB_CAPTURE_CANVAS_IMAGES"] =
      environment["REB_CAPTURE_CANVAS_IMAGES"]
      ?? (captureNetworkContent && allows(1025) ? "1" : "0")
    // The content mode's request paths, queries and bounded bodies need both
    // Network (256) and Artifact (1024); a narrower mask keeps hosts only.
    environment["REB_CAPTURE_REQUEST_CONTENT"] =
      environment["REB_CAPTURE_REQUEST_CONTENT"]
      ?? (captureNetworkContent && allows(1280) ? "1" : "0")
    // The packaged app turns on every native switch that needs no per-target input
    // file. Guest-state and JavaScript dispatch-site capture stay off because they
    // need a researcher-supplied adapter or site file. An explicit "0" still opts
    // out: Wasm dispatch forces Liftoff-only compilation. Both Wasm switches need
    // the VM (512) and Artifact (1024) categories, so a narrower mask leaves them off.
    environment["REB_NATIVE_QUIET_MODE"] = environment["REB_NATIVE_QUIET_MODE"] ?? "1"
    for name in ["REB_NATIVE_WASM_DISPATCH", "REB_NATIVE_WASM_CALL_INDIRECT"] {
      environment[name] = environment[name] ?? (allows(1536) ? "1" : "0")
    }
    // Permission only: the capture browser may later arm a document-start
    // Console script, which still needs a live Console connection to a selected
    // document and a separate confirmed arm. Nothing runs until then. A browser
    // without the v3 overlay ignores the switch and the Console reports it
    // unavailable. An explicit "0" opts out.
    environment["REB_CONSOLE_DOCUMENT_START"] = environment["REB_CONSOLE_DOCUMENT_START"] ?? "1"
    // An explicit REB_NATIVE_JS_INVOCATION_SITES, even an empty one, wins, and
    // then the environment alone decides digests, as for make live.
    if environment["REB_NATIVE_JS_INVOCATION_SITES"] == nil, let saved = savedInvocationSites, allows(512) {
      environment["REB_NATIVE_JS_INVOCATION_SITES"] = saved.path
      environment["REB_NATIVE_JS_INVOCATION_IF_SUPPORTED"] = environment["REB_NATIVE_JS_INVOCATION_IF_SUPPORTED"] ?? "1"
      environment["REB_NATIVE_JS_INVOCATION_DIGESTS"] =
        environment["REB_NATIVE_JS_INVOCATION_DIGESTS"] ?? (captureNetworkContent ? "1" : "0")
    }
    return environment
  }

  static func failureCause(in data: Data?) -> String {
    let fallback = "The live capture coordinator stopped before startup completed."
    guard let data, !data.isEmpty else { return fallback }
    let prefix = "REB_LIVE_SESSION_FAILURE: "
    let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
    // Read the explicit launcher cause, not whichever teardown or Bash job
    // diagnostic happened to arrive last. Child output lives in separate logs.
    guard let marked = lines.last(where: {
      $0.hasPrefix(prefix) && !$0.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces).isEmpty
    }) else { return fallback }
    return String(marked.dropFirst(prefix.count).prefix(4 * 1_024))
  }

  private func failureMessage(logURL: URL) -> String {
    let cause = Self.failureCause(in: try? Data(contentsOf: logURL))
    return cause + "\n\nSession log: " + logURL.path
  }

  private func sessionError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace.LiveSession",
      code: 1,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}
