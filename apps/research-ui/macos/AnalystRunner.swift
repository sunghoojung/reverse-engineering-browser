import Darwin
import Foundation
import JavaScriptCore

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
    // No CPU or memory limit: a run lasts until it settles or its host
    // cancels it, and holds what its evidence needs.
    setLimit(RLIMIT_CORE, 0)
    setLimit(RLIMIT_FSIZE, 0)
    setLimit(RLIMIT_NOFILE, 32)

    var input: [String: Any]?
    do {
      guard CommandLine.arguments.count == 2 else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "Analyst runner core path is required"]
        )
      }
      // Runner input v2: one JSON line, then the selected artifact's bytes.
      let data = FileHandle.standardInput.readDataToEndOfFile()
      guard let end = data.firstIndex(of: 0x0a),
        let parsed = try JSONSerialization.jsonObject(with: data[data.startIndex..<end])
          as? [String: Any],
        parsed["protocol_version"] as? Int == 2,
        let source = parsed["source"] as? String,
        !source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 3,
          userInfo: [NSLocalizedDescriptionKey: "Analyst runner input is malformed"]
        )
      }
      input = parsed
      let bytes = data[data.index(after: end)...]
      let selected = (parsed["evidence"] as? [String: Any])?["selected_artifact"] as? [String: Any]
      guard selected.map({ $0["byte_size"] as? Int == bytes.count }) ?? bytes.isEmpty else {
        throw NSError(
          domain: "REBAnalystRunner",
          code: 3,
          userInfo: [
            NSLocalizedDescriptionKey:
              "Analyst runner input does not match the selected artifact's byte size"
          ]
        )
      }
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
        REBExecuteAnalyst(...REBTakeInput(), async function(WB, Utils, console) {
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
      // The core takes these globals and removes them before the script runs.
      context.setObject(configurationText, forKeyedSubscript: "REBInput" as NSString)
      if selected != nil {
        context.setObject(
          String(data: bytes, encoding: .utf8) ?? NSNull(),
          forKeyedSubscript: "REBSelectedText" as NSString
        )
        let storage = UnsafeMutableRawPointer.allocate(byteCount: max(bytes.count, 1), alignment: 1)
        bytes.copyBytes(to: storage.assumingMemoryBound(to: UInt8.self), count: bytes.count)
        var exception: JSValueRef?
        guard
          let array = JSObjectMakeTypedArrayWithBytesNoCopy(
            context.jsGlobalContextRef, kJSTypedArrayTypeUint8Array, storage, bytes.count,
            { storage, _ in storage?.deallocate() }, nil, &exception
          )
        else {
          storage.deallocate()
          throw NSError(
            domain: "REBAnalystRunner",
            code: 5,
            userInfo: [NSLocalizedDescriptionKey: "Could not hand the selected artifact to the script"]
          )
        }
        context.setObject(
          JSValue(jsValueRef: array, in: context),
          forKeyedSubscript: "REBSelectedBytes" as NSString
        )
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
      // JavaScriptCore drains its job queue as each call returns, and the
      // script's realm has no timers or I/O, so a promise still pending here
      // can never settle.
      promise.invokeMethod("then", withArguments: [onResolved, onRejected])
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
              ? "The analyst script awaited a promise that nothing can settle"
              : "Analyst runner returned a malformed result"
          ]
        )
      }
      writeDocument(result)
    } catch {
      writeDocument(failure(input: input, message: error.localizedDescription))
    }
  }
}
