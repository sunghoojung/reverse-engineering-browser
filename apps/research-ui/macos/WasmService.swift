import Darwin
import Foundation

// The same Rust provider serves native and HTTP inspection. No WASM execution
// engine is instantiated; artifact integrity is checked inside the helper.
final class NativeWasmService {
  private let executableURL: URL
  private let lock = NSLock()
  private let mapLock = NSLock()
  private var activeMap: Process?
  private let graphQueue = DispatchSemaphore(value: 1)
  init(executableURL: URL) { self.executableURL = executableURL }

  // At most one map helper runs. A newer selection retires the older read
  // rather than letting it finish for a view that no longer wants it.
  func artifactMap(root: URL, artifactID: String) throws -> Data {
    guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
      throw NativeDecoderError(status: 503, message: "The packaged artifact map helper is unavailable")
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let outputURL = directory.appendingPathComponent("output")
    FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let output = try FileHandle(forWritingTo: outputURL)
    defer { try? output.close() }
    let process = Process()
    process.executableURL = executableURL
    process.arguments = ["--artifacts", root.path, "--artifact-id", artifactID, "--artifact-map"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    process.environment = ["LANG": "C", "LC_ALL": "C"]
    let done = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in done.signal() }
    mapLock.lock()
    if let previous = activeMap, previous.isRunning { previous.terminate() }
    activeMap = process
    do {
      try process.run()
    } catch {
      activeMap = nil
      mapLock.unlock()
      throw error
    }
    mapLock.unlock()
    defer {
      mapLock.lock()
      if activeMap === process { activeMap = nil }
      mapLock.unlock()
    }
    if done.wait(timeout: .now() + 75) == .timedOut {
      process.terminate()
      if done.wait(timeout: .now() + 0.25) == .timedOut {
        kill(process.processIdentifier, SIGKILL)
        process.waitUntilExit()
      }
      throw NativeDecoderError(status: 408, message: "The artifact map exceeded its deadline; the stored artifact is unchanged")
    }
    if process.terminationReason == .uncaughtSignal {
      throw NativeDecoderError(status: 499, message: "A newer artifact map replaced this one")
    }
    let file = try FileHandle(forReadingFrom: outputURL)
    defer { try? file.close() }
    let bytes = try file.read(upToCount: 1024 * 1024 + 1) ?? Data()
    guard process.terminationStatus == 0, bytes.count <= 1024 * 1024,
      let result = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
      throw NativeDecoderError(status: 502, message: "The artifact map helper returned an invalid response")
    }
    if let error = result["error"] as? String {
      throw NativeDecoderError(status: result["status"] as? Int ?? 500, message: error)
    }
    guard result["schema"] as? String == "artifact-map-v1", result["artifact_id"] as? String == artifactID else {
      throw NativeDecoderError(status: 502, message: "The artifact map helper returned an invalid document")
    }
    return bytes
  }

  func inspect(root: URL, artifactID: String) throws -> Data {
    guard lock.try() else { throw NativeDecoderError(status: 409, message: "WASM inspector is busy; retry when the current inspection finishes") }
    defer { lock.unlock() }
    return try run(
      arguments: ["--artifacts", root.path, "--artifact-id", artifactID],
      outputLimit: 8 * 1024 * 1024,
      schema: "wasm-inspection-v1",
      artifactID: artifactID,
      timeout: "WASM inspection exceeded five seconds; original bytes are preserved")
  }

  /// A graph helper is short-lived, so a stale one waits its turn instead of
  /// failing the selection that replaced it. Documents pass through unparsed:
  /// a large function must never build a JSON tree in this process.
  func graphDocument(root: URL, artifactID: String, extraArguments: [String], schema: String) throws -> Data {
    guard graphQueue.wait(timeout: .now() + 10) == .success else {
      throw NativeDecoderError(status: 409, message: "The WASM graph helper is busy; retry when the current request finishes")
    }
    defer { graphQueue.signal() }
    return try run(
      arguments: ["--artifacts", root.path, "--artifact-id", artifactID] + extraArguments,
      outputLimit: 64 * 1024 * 1024,
      schema: schema,
      artifactID: artifactID,
      timeout: "WASM graph decoding exceeded five seconds; original bytes are preserved")
  }

  private func run(arguments: [String], outputLimit: Int, schema: String, artifactID: String, timeout timeoutMessage: String) throws -> Data {
    guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
      throw NativeDecoderError(status: 503, message: "The packaged WASM inspector is unavailable")
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let outputURL = directory.appendingPathComponent("output")
    FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let output = try FileHandle(forWritingTo: outputURL)
    defer { try? output.close() }
    let process = Process()
    process.executableURL = executableURL
    process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    process.environment = ["LANG": "C", "LC_ALL": "C"]
    let done = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in done.signal() }
    try process.run()
    if done.wait(timeout: .now() + 5) == .timedOut {
      process.terminate()
      if done.wait(timeout: .now() + 0.25) == .timedOut {
        kill(process.processIdentifier, SIGKILL)
        process.waitUntilExit()
      }
      throw NativeDecoderError(status: 408, message: timeoutMessage)
    }
    let file = try FileHandle(forReadingFrom: outputURL)
    defer { try? file.close() }
    let bytes = try file.read(upToCount: outputLimit + 1) ?? Data()
    guard process.terminationStatus == 0, bytes.count <= outputLimit else {
      throw NativeDecoderError(status: 502, message: "WASM inspector returned an invalid response")
    }
    // A graph document starts with its schema and reaches the page unparsed.
    // Errors are short objects and fall through to the JSON path below.
    if schema != "wasm-inspection-v1", bytes.starts(with: Data("{\"schema\":\"\(schema)\"".utf8)) {
      return bytes
    }
    guard let result = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
      throw NativeDecoderError(status: 502, message: "WASM inspector returned an invalid response")
    }
    if let error = result["error"] as? String {
      throw NativeDecoderError(status: result["status"] as? Int ?? 500, message: error)
    }
    guard result["schema"] as? String == schema, result["artifact_id"] as? String == artifactID else {
      throw NativeDecoderError(status: 502, message: "WASM inspector returned an invalid document")
    }
    return bytes
  }
}
