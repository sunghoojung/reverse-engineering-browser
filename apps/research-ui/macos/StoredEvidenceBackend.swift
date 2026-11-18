import Darwin
import Foundation

// Rust-only stored-evidence reads, answered by the bundled backend run idle over the same stores for this app alone.
final class StoredEvidenceBackend {
  static let getRoutes: Set<String> = [
    "/api/requests", "/api/request-headers", "/api/request-cookies", "/api/cookie-provenance",
    "/api/request-stack", "/api/native-debugger", "/api/source-format", "/api/origin-trace",
  ]
  static let postRoutes: Set<String> = ["/api/native-debugger/actions"]
  static let maximumBodyBytes = 64 * 1024
  static let startSeconds = 15.0
  static let retrySeconds = 10.0

  struct Failure: Error {
    let status: Int
    let code: String
    let message: String
  }

  // Fields the app owns in a forwarded JSON object, such as the broker state of
  // the bare event poll: the backend runs idle and cannot know them. `tag` names
  // their values inside the ETag, so a change in either is a new answer.
  struct Overlay {
    let fields: [String: Any]
    let tag: String

    func etag(_ backend: String) -> String {
      backend.hasSuffix("\"") ? "\(backend.dropLast())-\(tag)\"" : "\(backend)-\(tag)"
    }

    // The backend's own tag, or nil when the app's fields changed since.
    func backendTag(_ etag: String) -> String? {
      for suffix in ["-\(tag)\"", "-\(tag)"] where etag.hasSuffix(suffix) {
        return String(etag.dropLast(suffix.count)) + (suffix.hasSuffix("\"") ? "\"" : "")
      }
      return nil
    }

    func apply(_ body: Data) -> Data? {
      guard var object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else { return nil }
      object.merge(fields) { _, app in app }
      return try? JSONSerialization.data(withJSONObject: object)
    }
  }

  // The bare event poll: GET /api/events with at most a limit.
  static func isEventPoll(_ request: URLRequest) -> Bool {
    guard (request.httpMethod ?? "GET") == "GET", let url = request.url, url.path == "/api/events" else { return false }
    let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
    return items.allSatisfy { $0.name == "limit" }
  }

  // Every event read goes to Rust, whose event index counts gaps and drops over
  // the whole store. The bare artifact list stays with the scheme handler;
  // filtered and cursor-paged reads of it go to Rust, which pages the manifest
  // by record boundary off the main thread.
  static func serves(_ request: URLRequest) -> Bool {
    guard let url = request.url else { return false }
    switch request.httpMethod ?? "GET" {
    case "GET":
      if url.path == "/api/events" { return true }
      if url.path == "/api/artifacts" {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return items.contains { $0.name != "limit" }
      }
      return getRoutes.contains(url.path)
    case "POST":
      return postRoutes.contains(url.path)
    default:
      return false
    }
  }

  private let executableURL: URL
  private let arguments: [String]
  private let launches = DispatchQueue(label: "origin-trace.stored-evidence-backend")
  private let session: URLSession
  private let lock = NSLock()
  private var process: Process?
  private var directory: URL?
  private var origin: URL?
  private var retryAfter = Date.distantPast

  init(executableURL: URL, arguments: [String]) {
    self.executableURL = executableURL
    self.arguments = arguments
    let configuration = URLSessionConfiguration.ephemeral
    configuration.connectionProxyDictionary = [:]
    configuration.urlCache = nil
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.timeoutIntervalForRequest = 180
    session = URLSession(configuration: configuration)
  }

  deinit {
    session.invalidateAndCancel()
    release()
  }

  var running: Bool {
    lock.lock()
    defer { lock.unlock() }
    return process?.isRunning == true
  }

  func stop() {
    lock.lock()
    defer { lock.unlock() }
    release()
    retryAfter = .distantPast
  }

  func forward(
    _ request: URLRequest, overlay: Overlay? = nil, reply: @escaping (Data, Int, String, [String: String]) -> Void
  ) {
    let json = "application/json; charset=utf-8"
    launches.async {
      let forwarded: URLRequest
      do {
        forwarded = try self.backendRequest(for: request, origin: try self.start(), overlay: overlay)
      } catch let failure as Failure {
        reply(Self.body(failure), failure.status, json, [:])
        return
      } catch {
        reply(Self.body(Failure(status: 503, code: "dependency_unavailable", message: "The bundled backend is unavailable")), 503, json, [:])
        return
      }
      self.session.dataTask(with: forwarded) { data, response, _ in
        guard let response = response as? HTTPURLResponse else {
          reply(Self.body(Failure(status: 502, code: "dependency_unavailable", message: "The bundled backend did not answer")), 502, json, [:])
          return
        }
        var headers: [String: String] = [:]
        if let tag = response.value(forHTTPHeaderField: "ETag") { headers["ETag"] = overlay?.etag(tag) ?? tag }
        var body = data ?? Data()
        if let overlay, response.statusCode == 200 {
          guard let applied = overlay.apply(body) else {
            reply(Self.body(Failure(status: 502, code: "dependency_unavailable", message: "The bundled backend returned malformed JSON")), 502, json, [:])
            return
          }
          body = applied
        }
        reply(body, response.statusCode, response.value(forHTTPHeaderField: "Content-Type") ?? json, headers)
      }.resume()
    }
  }

  private func backendRequest(for request: URLRequest, origin: URL, overlay: Overlay?) throws -> URLRequest {
    let invalid = Failure(status: 400, code: "invalid_request", message: "Invalid application URL")
    guard let url = request.url, let source = URLComponents(url: url, resolvingAgainstBaseURL: false),
      var target = URLComponents(url: origin, resolvingAgainstBaseURL: false)
    else { throw invalid }
    target.percentEncodedPath = source.percentEncodedPath
    target.percentEncodedQuery = source.percentEncodedQuery
    guard let targetURL = target.url else { throw invalid }
    var forwarded = URLRequest(url: targetURL)
    forwarded.httpMethod = request.httpMethod ?? "GET"
    // A tag from before the app's fields changed matches nothing.
    if let tag = request.value(forHTTPHeaderField: "If-None-Match"),
      let backend = overlay == nil ? tag : overlay?.backendTag(tag)
    {
      forwarded.setValue(backend, forHTTPHeaderField: "If-None-Match")
    }
    if forwarded.httpMethod == "POST" {
      forwarded.httpBody = try Self.body(of: request)
      forwarded.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    return forwarded
  }

  // Runs on the launch queue, so one start serves every waiting request.
  private func start() throws -> URL {
    lock.lock()
    if let origin, process?.isRunning == true {
      lock.unlock()
      return origin
    }
    release()
    let backingOff = Date() < retryAfter
    lock.unlock()
    guard !backingOff else {
      throw Failure(status: 503, code: "dependency_unavailable", message: "The bundled backend did not start; retry shortly")
    }
    guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
      throw Failure(status: 503, code: "dependency_unavailable", message: "The bundled backend is unavailable")
    }
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("origin-trace-stored-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let endpoint = directory.appendingPathComponent("endpoint")
    let child = Process()
    child.executableURL = executableURL
    child.arguments = [
      "--host", "127.0.0.1", "--port", "0", "--endpoint-file", endpoint.path, "--owner-pid", String(getpid()),
    ] + arguments
    child.currentDirectoryURL = directory
    child.standardInput = FileHandle.nullDevice
    child.standardOutput = FileHandle.nullDevice
    child.standardError = FileHandle.nullDevice
    var environment = ["LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"]
    for name in ["HOME", "TMPDIR"] { environment[name] = ProcessInfo.processInfo.environment[name] }
    child.environment = environment
    lock.lock()
    do {
      try child.run()
    } catch {
      lock.unlock()
      try? FileManager.default.removeItem(at: directory)
      throw error
    }
    process = child
    self.directory = directory
    lock.unlock()
    let deadline = Date().addingTimeInterval(Self.startSeconds)
    while Date() < deadline && child.isRunning {
      if let text = try? String(contentsOf: endpoint, encoding: .utf8), let url = Self.loopback(text) {
        lock.lock()
        defer { lock.unlock() }
        guard process === child else { break }
        origin = url
        return url
      }
      Thread.sleep(forTimeInterval: 0.05)
    }
    lock.lock()
    defer { lock.unlock() }
    if process === child {
      release()
      retryAfter = Date().addingTimeInterval(Self.retrySeconds)
    }
    throw Failure(status: 503, code: "dependency_unavailable", message: "The bundled backend did not start")
  }

  // Caller holds the lock.
  private func release() {
    if let process, process.isRunning { process.terminate() }
    process = nil
    origin = nil
    if let directory { try? FileManager.default.removeItem(at: directory) }
    directory = nil
  }

  private static func loopback(_ text: String) -> URL? {
    guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
      components.scheme == "http", components.host == "127.0.0.1", components.port != nil,
      components.path.isEmpty, components.query == nil, components.user == nil
    else { return nil }
    return components.url
  }

  private static func body(of request: URLRequest) throws -> Data {
    let oversized = Failure(status: 413, code: "resource_limit", message: "The request body is oversized")
    if let body = request.httpBody {
      guard body.count <= maximumBodyBytes else { throw oversized }
      return body
    }
    guard let stream = request.httpBodyStream else { return Data() }
    stream.open()
    defer { stream.close() }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
      let count = stream.read(&buffer, maxLength: buffer.count)
      if count < 0 { throw Failure(status: 400, code: "invalid_request", message: "The request body could not be read") }
      if count == 0 { break }
      data.append(buffer, count: count)
      guard data.count <= maximumBodyBytes else { throw oversized }
    }
    return data
  }

  private static func body(_ failure: Failure) -> Data {
    (try? JSONSerialization.data(withJSONObject: [
      "error": failure.message, "code": failure.code, "details": [String: Any](),
    ])) ?? Data("{\"error\":\"The bundled backend is unavailable\"}".utf8)
  }
}
