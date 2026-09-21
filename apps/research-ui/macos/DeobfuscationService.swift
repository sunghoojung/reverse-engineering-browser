import CryptoKit
import Darwin
import Foundation

// Cold-path analysis runs outside WebKit. Private temporary files avoid pipe
// deadlocks; the worker has bounded input/output and is killed after five seconds.
final class NativeDeobfuscationService {
  private let executableURL: URL
  private let lock = NSLock()
  static let maximumSourceBytes = 4 * 1024 * 1024

  init(executableURL: URL) { self.executableURL = executableURL }

  func analyze(source: Data, artifactID: String, mode: String, assumeIntrinsics: Bool = false) throws -> Data {
    guard !source.isEmpty, source.count <= Self.maximumSourceBytes,
      let text = String(data: source, encoding: .utf8)
    else { throw NativeDecoderError(status: 400, message: "Source must be nonempty UTF-8 JavaScript of at most 4 MiB") }
    guard lock.try() else { throw NativeDecoderError(status: 409, message: "Deobfuscation worker is busy; retry when the current analysis finishes") }
    defer { lock.unlock() }
    guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
      throw NativeDecoderError(status: 503, message: "The packaged deobfuscation worker is unavailable")
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let inputURL = directory.appendingPathComponent("input")
    let outputURL = directory.appendingPathComponent("output")
    let inputObject: [String: Any] = ["source": text, "assume_intrinsics": assumeIntrinsics]
    var request = try JSONSerialization.data(withJSONObject: inputObject)
    request.append(10)
    FileManager.default.createFile(atPath: inputURL.path, contents: request, attributes: [.posixPermissions: 0o600])
    FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    let input = try FileHandle(forReadingFrom: inputURL)
    let output = try FileHandle(forWritingTo: outputURL)
    defer { try? input.close(); try? output.close() }
    let process = Process()
    process.executableURL = executableURL
    process.standardInput = input
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
      throw NativeDecoderError(status: 408, message: "Deobfuscation exceeded five seconds")
    }
    let resultFile = try FileHandle(forReadingFrom: outputURL)
    defer { try? resultFile.close() }
    let bytes = try resultFile.read(upToCount: 32 * 1024 * 1024 + 1) ?? Data()
    guard process.terminationStatus == 0 else {
      throw NativeDecoderError(status: 502, message: "JavaScript analysis worker terminated unexpectedly; original source is preserved")
    }
    guard bytes.count <= 32 * 1024 * 1024,
      let result = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
      result["schema"] as? String == "reb-deobfuscator-worker-v1",
      let derived = result["derived_source"] as? String,
      let rewrites = result["transformations"] as? [[String: Any]],
      rewrites.count <= 4096
    else { throw NativeDecoderError(status: 502, message: "Deobfuscation worker returned an invalid response") }
    guard result["ok"] as? Bool == true else {
      let diagnostics = result["syntax_errors"] as? [[String: Any]] ?? []
      throw NativeDecoderError(status: 422, message: diagnostics.first?["message"] as? String ?? "JavaScript could not be parsed")
    }
    let assumptions = result["assumptions"] as? [String] ?? []
    guard assumptions == (assumeIntrinsics ? ["standard-intrinsics"] : []) else {
      throw NativeDecoderError(status: 502, message: "Worker does not support the requested assumption mode")
    }
    var segments: [[String: Any]] = []
    var originalOffset = 0
    var derivedOffset = 0
    func appendSegment(_ kind: String, _ end: Int, _ length: Int) {
      guard length > 0 else { return }
      segments.append(["kind": kind, "original_start": originalOffset, "original_end": end,
        "derived_start": derivedOffset, "derived_end": derivedOffset + length])
      derivedOffset += length
      originalOffset = end
    }
    for rewrite in rewrites {
      guard let start = rewrite["original_start"] as? Int,
        let end = rewrite["original_end"] as? Int,
        let replacement = rewrite["replacement"] as? String,
        start >= originalOffset, end > start, end <= source.count
      else { throw NativeDecoderError(status: 502, message: "Deobfuscation worker returned invalid source ranges") }
      appendSegment("verbatim", start, start - originalOffset)
      appendSegment("replacement", end, replacement.utf8.count)
    }
    appendSegment("verbatim", source.count, source.count - originalOffset)
    guard derivedOffset == derived.utf8.count else {
      throw NativeDecoderError(status: 502, message: "Deobfuscation worker returned an inconsistent source map")
    }
    let truncated = result["transformations_truncated"] as? Bool ?? false
    let counts = Dictionary(grouping: rewrites, by: { $0["kind"] as? String ?? "unknown" })
    let transformations: [[String: Any]] = counts.keys.sorted().map { kind in
      ["id": kind, "kind": "rewrite", "count": counts[kind]?.count ?? 0,
        "detail": "Static AST rewrite with original-source mapping; no JavaScript execution."]
    }
    let summary: [String: Any] = ["status": derived == text ? "unchanged" : "derived",
      "derived_bytes": derived.utf8.count, "segment_count": segments.count,
      "truncated": truncated, "transformations": transformations]
    let analysis: [String: Any] = ["schema": "deobfuscation-analysis-v1",
      "source": ["sha256": SHA256.hash(data: source).map { String(format: "%02x", $0) }.joined(),
        "byte_size": source.count, "lines": text.components(separatedBy: "\n").count],
      "classification": ["label": "unclassified", "confidence": NSNull(), "evidence": [],
        "scores": [:], "alternatives": []],
      "assumptions": assumptions, "stats": result["evidence"] ?? [:], "representation": summary, "string_tables": [],
      "limits": ["max_source_bytes": Self.maximumSourceBytes, "max_transformations": 4096],
      "omissions": ["Classification is unavailable. Unsupported decoder operations, object/array coercion, sparse indices, mutable or escaping tables, and cross-scope propagation remain unresolved."]]
    var response: [String: Any] = ["schema": "deobfuscation-analysis-v1",
      "engine": "rust-oxc", "artifact_id": artifactID, "script_id": NSNull(), "mode": mode,
      "source_truncated": false, "original_source": text, "analysis": analysis]
    if mode == "derived" {
      response["representation"] = ["text": derived, "offset_unit": "utf-8-byte",
        "segments": segments, "truncated": truncated, "transformations": transformations]
    }
    return try JSONSerialization.data(withJSONObject: response)
  }
}
