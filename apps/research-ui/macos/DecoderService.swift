import CoreFoundation
import Darwin
import Foundation

struct NativeDecoderError: Error {
  let status: Int
  let message: String
}

final class NativeDecoderService {
  private static let inputBytes = 1 << 20
  private static let outputBytes = 1 << 20
  private static let jwtBytes = 64 << 10
  private static let secretBytes = 4 << 10
  private static let timeoutSeconds = 2.0
  private static let operations = [
    "base64-encode", "base64-decode", "base64url-encode", "base64url-decode",
    "hex-encode", "hex-decode", "url-encode", "url-decode", "base36-encode",
    "base36-decode", "gzip-compress", "gzip-decompress", "zlib-compress",
    "zlib-decompress", "deflate-compress", "deflate-decompress", "json-pretty",
    "json-minify",
  ]
  private static let algorithms = ["HS256", "HS384", "HS512", "none"]

  private let executableURL: URL
  private let lock = NSLock()

  init(executableURL: URL) {
    self.executableURL = executableURL
  }

  func state() throws -> Data {
    let idle = lock.try()
    if idle { lock.unlock() }
    return try JSONSerialization.data(
      withJSONObject: [
        "protocol_version": 1,
        "available": available,
        "busy": !idle,
        "limits": Self.limits,
      ]
    )
  }

  var available: Bool {
    FileManager.default.isExecutableFile(atPath: executableURL.path)
  }

  func action(_ request: [String: Any]) throws -> Data {
    guard integer(request["protocol_version"]) == 1, let action = request["action"] as? String else {
      throw NativeDecoderError(status: 400, message: "Decoder protocol version is unsupported")
    }
    switch action {
      case "transform":
        return try transform(request)
      case "jwt_inspect":
        return try inspectJWT(request)
      case "jwt_verify":
        return try verifyJWT(request)
      case "jwt_create":
        return try createJWT(request)
      default:
        throw NativeDecoderError(status: 400, message: "Decoder action is unsupported")
    }
  }

  private static var limits: [String: Any] {
    [
      "input_bytes": inputBytes,
      "output_bytes": outputBytes,
      "pipeline_steps": 16,
      "retained_bytes": 4 << 20,
      "jwt_bytes": jwtBytes,
      "secret_bytes": secretBytes,
      "json_depth": 64,
      "json_tokens": 100_000,
      "timeout_ms": 2_000,
      "operations": operations,
      "jwt_algorithms": algorithms,
    ]
  }

  private func transform(_ request: [String: Any]) throws -> Data {
    guard exactKeys(
      request,
      ["protocol_version", "action", "operation_id", "operation", "input_base64"]
    ), let operationID = integer(request["operation_id"]), operationID >= 1,
      let operation = request["operation"] as? String, Self.operations.contains(operation),
      let input = canonicalBase64(request["input_base64"], maximumBytes: Self.inputBytes)
    else {
      throw NativeDecoderError(status: 400, message: "Decoder transform shape is invalid")
    }
    let result = try run(arguments: ["transform", operation], input: input)
    guard result.status == 0 else {
      let error = boundedUTF8(result.error, maximumBytes: 4_096)
      throw NativeDecoderError(
        status: result.status == 3 ? 422 : 400,
        message: error.isEmpty ? "Native decoder rejected the transform" : error
      )
    }
    guard result.output.count <= Self.outputBytes else {
      throw NativeDecoderError(status: 422, message: "Native decoder returned oversized output")
    }
    let text = String(data: result.output, encoding: .utf8)
    return try JSONSerialization.data(
      withJSONObject: [
        "protocol_version": 1,
        "ok": true,
        "operation_id": operationID,
        "operation": operation,
        "input_bytes": input.count,
        "output_bytes": result.output.count,
        "output_base64": result.output.base64EncodedString(),
        "utf8_text": text ?? NSNull(),
        "hex_preview": result.output.prefix(256).map { String(format: "%02x", $0) }.joined(),
        "preview_truncated": result.output.count > 256,
        "duration_us": result.durationMicroseconds,
      ]
    )
  }

  private func inspectJWT(_ request: [String: Any]) throws -> Data {
    guard exactKeys(request, ["protocol_version", "action", "token"]),
      let token = boundedText(request["token"], maximumBytes: Self.jwtBytes)
    else {
      throw NativeDecoderError(status: 400, message: "JWT inspection shape is invalid")
    }
    return try jwtResponse(
      run(arguments: ["jwt-inspect"], input: Data(token.utf8)),
      creation: false
    )
  }

  private func verifyJWT(_ request: [String: Any]) throws -> Data {
    guard exactKeys(request, ["protocol_version", "action", "token", "secret"]),
      let token = boundedText(request["token"], maximumBytes: Self.jwtBytes),
      let secret = boundedText(request["secret"], maximumBytes: Self.secretBytes),
      !secret.isEmpty
    else {
      throw NativeDecoderError(status: 400, message: "JWT verification shape is invalid")
    }
    return try jwtResponse(
      run(
        arguments: ["jwt-verify"],
        input: frame([Data(token.utf8), Data(secret.utf8)])
      ),
      creation: false
    )
  }

  private func createJWT(_ request: [String: Any]) throws -> Data {
    guard exactKeys(
      request,
      [
        "protocol_version", "action", "payload_json", "algorithm", "secret",
        "expires_in_seconds", "allow_unsigned_confirmed",
      ]
    ), let payload = boundedText(request["payload_json"], maximumBytes: 56 << 10),
      let algorithm = request["algorithm"] as? String, Self.algorithms.contains(algorithm),
      let secret = boundedText(request["secret"], maximumBytes: Self.secretBytes),
      let unsignedConfirmed = request["allow_unsigned_confirmed"] as? Bool
    else {
      throw NativeDecoderError(status: 400, message: "JWT creation shape is invalid")
    }
    if algorithm == "none" {
      guard unsignedConfirmed, secret.isEmpty else {
        throw NativeDecoderError(
          status: 400,
          message: "Creating an unsigned JWT requires confirmation and no secret"
        )
      }
    } else if secret.isEmpty {
      throw NativeDecoderError(status: 400, message: "Signed JWT creation requires a secret")
    }
    let expiration: String
    if request["expires_in_seconds"] is NSNull {
      expiration = "none"
    } else {
      guard let seconds = integer(request["expires_in_seconds"]), (1...604_800).contains(seconds) else {
        throw NativeDecoderError(
          status: 400,
          message: "JWT expiry must be between one second and seven days"
        )
      }
      expiration = String(Int(Date().timeIntervalSince1970) + seconds)
    }
    return try jwtResponse(
      run(
        arguments: ["jwt-create", algorithm, expiration],
        input: frame([Data(payload.utf8), Data(secret.utf8)])
      ),
      creation: true
    )
  }

  private func jwtResponse(_ result: ProcessResult, creation: Bool) throws -> Data {
    guard result.status == 0, result.output.count <= 256 << 10,
      var response = try JSONSerialization.jsonObject(with: result.output) as? [String: Any]
    else {
      throw NativeDecoderError(status: 422, message: "Native JWT decoder returned an invalid response")
    }
    let expected: Set<String> = creation
      ? ["protocol_version", "ok", "token", "error"]
      : [
          "protocol_version", "ok", "algorithm", "signature_status", "header_json",
          "payload_json", "token_bytes", "signature_bytes", "error",
        ]
    guard Set(response.keys) == expected, integer(response["protocol_version"]) == 1,
      response["ok"] is Bool
    else {
      throw NativeDecoderError(status: 422, message: "Native JWT decoder contract is invalid")
    }
    response["duration_us"] = result.durationMicroseconds
    return try JSONSerialization.data(withJSONObject: response)
  }

  private struct ProcessResult {
    let output: Data
    let error: Data
    let status: Int32
    let durationMicroseconds: Int
  }

  private func run(arguments: [String], input: Data) throws -> ProcessResult {
    guard available else {
      throw NativeDecoderError(status: 503, message: "The packaged native decoder is unavailable")
    }
    guard lock.lock(before: Date().addingTimeInterval(Self.timeoutSeconds)) else {
      throw NativeDecoderError(status: 408, message: "The packaged native decoder is busy")
    }
    defer { lock.unlock() }
    let process = Process()
    process.executableURL = executableURL
    process.arguments = arguments
    process.environment = ["LANG": "C", "LC_ALL": "C", "TZ": "UTC"]
    let inputPipe = Pipe()
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outputPipe
    process.standardError = errorPipe
    let terminated = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in terminated.signal() }
    do {
      try process.run()
    } catch {
      throw NativeDecoderError(status: 500, message: "Could not start the packaged native decoder")
    }
    let outputGroup = DispatchGroup()
    let outputLock = NSLock()
    var output = Data()
    var error = Data()
    outputGroup.enter()
    DispatchQueue.global(qos: .userInitiated).async {
      let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
      outputLock.lock()
      output = data
      outputLock.unlock()
      outputGroup.leave()
    }
    outputGroup.enter()
    DispatchQueue.global(qos: .utility).async {
      let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
      outputLock.lock()
      error = data
      outputLock.unlock()
      outputGroup.leave()
    }
    let started = DispatchTime.now().uptimeNanoseconds
    inputPipe.fileHandleForWriting.write(input)
    try? inputPipe.fileHandleForWriting.close()
    let timedOut = terminated.wait(timeout: .now() + Self.timeoutSeconds) == .timedOut
    if timedOut {
      process.terminate()
      if terminated.wait(timeout: .now() + 0.25) == .timedOut {
        kill(process.processIdentifier, SIGKILL)
        _ = terminated.wait(timeout: .now() + 0.25)
      }
    }
    outputGroup.wait()
    if timedOut {
      throw NativeDecoderError(status: 408, message: "Decoder operation exceeded two seconds")
    }
    let elapsed = DispatchTime.now().uptimeNanoseconds - started
    return ProcessResult(
      output: output,
      error: error,
      status: process.terminationStatus,
      durationMicroseconds: max(1, Int(elapsed / 1_000))
    )
  }

  private func canonicalBase64(_ value: Any?, maximumBytes: Int) -> Data? {
    guard let text = boundedText(value, maximumBytes: ((maximumBytes + 2) / 3) * 4 + 4),
      let data = Data(base64Encoded: text), data.count <= maximumBytes,
      data.base64EncodedString() == text
    else { return nil }
    return data
  }

  private func frame(_ values: [Data]) -> Data {
    var result = Data()
    for value in values {
      var size = UInt32(value.count).bigEndian
      withUnsafeBytes(of: &size) { result.append(contentsOf: $0) }
      result.append(value)
    }
    return result
  }

  private func exactKeys(_ value: [String: Any], _ keys: Set<String>) -> Bool {
    Set(value.keys) == keys
  }

  private func integer(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let double = number.doubleValue
    guard double.isFinite, double.rounded() == double,
      double >= Double(Int.min), double <= Double(Int.max)
    else { return nil }
    return number.intValue
  }

  private func boundedText(_ value: Any?, maximumBytes: Int) -> String? {
    guard let text = value as? String, text.utf8.count <= maximumBytes else { return nil }
    return text
  }

  private func boundedUTF8(_ value: Data, maximumBytes: Int) -> String {
    String(data: Data(value.prefix(maximumBytes)), encoding: .utf8)?
      .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
  }
}
