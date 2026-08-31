import Darwin
import Foundation
import JavaScriptCore

private let maximumInputBytes = 800 * 1_024
private let maximumSourceBytes = 32 * 1_024
private let maximumOutputBytes = 128 * 1_024

private func setLimit(_ resource: Int32, _ value: rlim_t) {
  var limit = rlimit(rlim_cur: value, rlim_max: value)
  _ = setrlimit(resource, &limit)
}

private func boundedText(_ value: Any, bytes: Int) -> String {
  let text = String(describing: value)
  if text.utf8.count <= bytes { return text }
  var result = ""
  var count = 0
  for character in text {
    let width = String(character).utf8.count
    if count + width > bytes { break }
    result.append(character)
    count += width
  }
  return result
}

private func failure(
  input: [String: Any]?,
  outcome: String = "failed",
  message: Any
) -> [String: Any] {
  [
    "protocol_version": 1,
    "run_id": input?["run_id"] as? Int ?? 0,
    "script_id": input?["script_id"] as? Int ?? 0,
    "library_generation": input?["library_generation"] as? Int ?? 0,
    "ok": false,
    "outcome": outcome,
    "result_type": "error",
    "result_text": "",
    "result_truncated": false,
    "logs": [],
    "logs_truncated": false,
    "duration_ms": 0,
    "error": boundedText(message, bytes: 512),
  ]
}

private func writeDocument(_ value: [String: Any]) {
  do {
    let data = try JSONSerialization.data(withJSONObject: value, options: [])
    guard data.count <= maximumOutputBytes else {
      throw NSError(
        domain: "REBAnalystRunner",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Analyst runner response exceeds 128 KiB"]
      )
    }
    FileHandle.standardOutput.write(data)
  } catch {
    let fallback = failure(input: value, message: error.localizedDescription)
    if let data = try? JSONSerialization.data(withJSONObject: fallback, options: []) {
      FileHandle.standardOutput.write(data)
    }
  }
}

@main
private struct AnalystRunner {
  static func main() {
    setLimit(RLIMIT_CORE, 0)
    setLimit(RLIMIT_CPU, 3)
    setLimit(RLIMIT_FSIZE, 0)
    setLimit(RLIMIT_NOFILE, 32)
    setLimit(RLIMIT_DATA, 192 * 1_024 * 1_024)

    var input: [String: Any]?
    do {
      guard CommandLine.arguments.count == 2 else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "Analyst runner core path is required"]
        )
      }
      let data = FileHandle.standardInput.readDataToEndOfFile()
      guard data.count <= maximumInputBytes,
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let source = parsed["source"] as? String,
        !source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
        source.utf8.count <= maximumSourceBytes
      else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 3,
          userInfo: [NSLocalizedDescriptionKey: "Analyst runner input is malformed or oversized"]
        )
      }
      input = parsed
      var configuration = parsed
      configuration.removeValue(forKey: "source")
      let configurationData = try JSONSerialization.data(
        withJSONObject: configuration,
        options: []
      )
      guard let configurationText = String(data: configurationData, encoding: .utf8) else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 4,
          userInfo: [NSLocalizedDescriptionKey: "Analyst runner input is not UTF-8"]
        )
      }
      let core = try String(
        contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]),
        encoding: .utf8
      )
      let program = """
        \(core)
        (() => {
          const denyCodeGeneration = () => {
            throw new TypeError("Dynamic code generation is disabled");
          };
          const constructors = [
            Object.getPrototypeOf(function() {}),
            Object.getPrototypeOf(async function() {}),
            Object.getPrototypeOf(function*() {}),
            Object.getPrototypeOf(async function*() {}),
          ];
          for (const prototype of constructors) {
            Object.defineProperty(prototype, "constructor", {
              value: denyCodeGeneration,
              writable: false,
              configurable: false,
            });
          }
          for (const name of ["eval", "Function", "WebAssembly"]) {
            Object.defineProperty(globalThis, name, {
              value: denyCodeGeneration,
              writable: false,
              configurable: false,
            });
          }
        })();
        REBExecuteAnalyst(\(configurationText), async function(WB, Utils, console) {
        "use strict";
        \(source)
        });
        //# sourceURL=reb-local-analyst.js
        """
      guard let context = JSContext() else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 5,
          userInfo: [NSLocalizedDescriptionKey: "Could not create the analyst JavaScript context"]
        )
      }
      var contextException: String?
      context.exceptionHandler = { _, exception in
        contextException = exception?.toString() ?? "Unknown JavaScript exception"
      }
      guard let promise = context.evaluateScript(
        program,
        withSourceURL: URL(string: "reb-local-analyst.js")
      ) else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 6,
          userInfo: [
            NSLocalizedDescriptionKey: contextException ?? "Analyst JavaScript compilation failed"
          ]
        )
      }
      var resolved: JSValue?
      var rejected: JSValue?
      let onResolved: @convention(block) (JSValue) -> Void = { value in
        resolved = value
      }
      let onRejected: @convention(block) (JSValue) -> Void = { value in
        rejected = value
      }
      promise.invokeMethod("then", withArguments: [onResolved, onRejected])
      let deadline = Date().addingTimeInterval(2.2)
      while resolved == nil && rejected == nil && Date() < deadline {
        RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.005))
      }
      if let rejected {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 7,
          userInfo: [NSLocalizedDescriptionKey: rejected.toString() ?? "Analyst script failed"]
        )
      }
      guard let result = resolved?.toObject() as? [String: Any] else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 8,
          userInfo: [
            NSLocalizedDescriptionKey: resolved == nil
              ? "Analyst script exceeded the 2 second execution limit"
              : "Analyst runner returned a malformed result"
          ]
        )
      }
      writeDocument(result)
    } catch {
      let message = error.localizedDescription
      let timedOut = message.localizedCaseInsensitiveContains("execution limit")
      writeDocument(
        failure(
          input: input,
          outcome: timedOut ? "timed_out" : "failed",
          message: timedOut
            ? "Analyst script exceeded the 2 second execution limit"
            : message
        )
      )
    }
  }
}
