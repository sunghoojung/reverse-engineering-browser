import CryptoKit
import Foundation

// Compiled with the production forwarder by scripts/build-research-app.sh and run against the backend it packages.
@main
enum StoredEvidenceBackendChecks {
  static func main() throws {
    precondition(CommandLine.arguments.count == 2, "usage: check-stored-evidence-backend BACKEND")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("reb-stored-backend-\(UUID().uuidString)")
    let artifacts = root.appendingPathComponent("artifacts/blobs", isDirectory: true)
    try FileManager.default.createDirectory(at: artifacts, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    func request(_ path: String, method: String = "GET", body: String? = nil, etag: String? = nil) -> URLRequest {
      var request = URLRequest(url: URL(string: "reb://app\(path)")!)
      request.httpMethod = method
      request.httpBody = body.map { Data($0.utf8) }
      if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
      return request
    }
    for route in StoredEvidenceBackend.getRoutes { precondition(StoredEvidenceBackend.serves(request(route)), route) }
    precondition(StoredEvidenceBackend.serves(request("/api/events?request_id=1&limit=5")))
    precondition(StoredEvidenceBackend.serves(request("/api/native-debugger/actions", method: "POST")))
    // The workspace pages the whole catalog; a read the scheme handler answered would hold only its newest record.
    precondition(StoredEvidenceBackend.serves(request("/api/artifacts?after=0&limit=1")))
    precondition(StoredEvidenceBackend.serves(request("/api/artifacts?artifact_id=1&limit=1")))
    for path in ["/api/events", "/api/events?limit=5000"] {
      precondition(StoredEvidenceBackend.serves(request(path)) && StoredEvidenceBackend.isEventPoll(request(path)), path)
    }
    precondition(!StoredEvidenceBackend.isEventPoll(request("/api/events?request_id=1&limit=5")))
    for path in ["/api/artifacts?limit=500", "/api/artifacts/1/content", "/api/health",
      "/api/native-debugger/actions", "/api/session/summary"] {
      precondition(!StoredEvidenceBackend.serves(request(path)), "\(path) stays native")
    }

    var lines = ""
    for (sequence, (request, type, status)) in [(1, "request_started", 0), (1, "request_completed", 200),
      (2, "request_started", 0), (3, "request_started", 0)].enumerated() {
      let payload = type == "request_started" ? "GET fixture.test" : "completed"
      let hex = payload.utf8.map { String(format: "%02x", $0) }.joined()
      lines += #"{"protocol_version":3,"session_id":"1","sequence_number":"\#(sequence + 1)","monotonic_time_ns":"\#((sequence + 1) * 1000)","navigation_id":"0","frame_id":"9","artifact_id":"0","parent_event_id":"0","request_id":"\#(request)","process_id":7,"thread_id":1,"tab_id":1,"category":"network","type":"\#(type)","flags":0,"status_code":\#(status),"error_code":0,"encoded_data_length":"0","decoded_body_length":"0","resource_type":11,"initiator_process_id":0,"initiator_request_id":0,"payload_encoding":"hex","payload":"\#(hex)","payload_size":\#(payload.utf8.count),"payload_truncated":false}"# + "\n"
    }
    try Data(lines.utf8).write(to: root.appendingPathComponent("events.jsonl"))
    let source = Data("function f(a,b){return a+b}".utf8)
    let digest = SHA256.hash(data: source).map { String(format: "%02x", $0) }.joined()
    try source.write(to: artifacts.appendingPathComponent("\(digest).bin"))
    try Data((#"{"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"2","frame_id":"9","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://fixture.test/a.js","mime_type":"text/javascript","byte_size":\#(source.count),"sha256":"\#(digest)","sensitive":false,"content_path":"blobs/\#(digest).bin"}"# + "\n").utf8)
      .write(to: root.appendingPathComponent("artifacts/manifest.jsonl"))

    var stores: [String] = []
    for (flag, name) in [("--store", "events.jsonl"), ("--trace-store", "trace.jsonl"), ("--signal-store", "signals.jsonl"),
      ("--artifacts", "artifacts"), ("--api-collection", "collection.json"), ("--local-analyst", "analyst.json"),
      ("--js-invocation-site-store", "sites.json")] {
      stores += [flag, root.appendingPathComponent(name).path]
    }
    let backend = StoredEvidenceBackend(executableURL: URL(fileURLWithPath: CommandLine.arguments[1]), arguments: stores)
    func call(_ request: URLRequest, on service: StoredEvidenceBackend? = nil) -> (status: Int, tag: String?, json: [String: Any]) {
      let done = DispatchSemaphore(value: 0)
      var result: (Int, String?, [String: Any]) = (0, nil, [:])
      (service ?? backend).forward(request) { body, status, _, headers in
        result = (status, headers["ETag"], (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:])
        done.signal()
      }
      precondition(done.wait(timeout: .now() + 60) == .success, "no reply for \(request.url!)")
      return result
    }

    let catalog = call(request("/api/artifacts?after=0&limit=1"))
    let catalogQuery = catalog.json["query"] as? [String: Any]
    precondition(catalog.status == 200 && catalogQuery?["next_after"] != nil, "the probe answers with a paged query: \(catalog)")
    precondition((catalog.json["artifacts"] as? [[String: Any]])?.first?["content_path"] == nil, "manifest paths stay private: \(catalog.json)")

    let index = call(request("/api/requests?limit=10"))
    precondition(index.status == 200 && index.json["format"] as? String == "reb-request-index-v2", "\(index)")
    precondition(index.json["total"] as? Int == 3, "every stored request is indexed: \(index.json)")
    guard let tag = index.tag else { preconditionFailure("the index answer carries its ETag") }
    precondition(call(request("/api/requests?limit=10", etag: tag)).status == 304)
    let events = call(request("/api/events?session_id=1&process_id=7&request_id=1&category=network&after=0&limit=2"))
    precondition(events.status == 200, "\(events)")
    precondition((events.json["events"] as? [[String: Any]])?.compactMap { $0["type"] as? String }
      == ["request_started", "request_completed"], "a filtered read returns only that request: \(events.json)")
    precondition(call(request("/api/events?limit=5&misspelled=1")).status == 400, "an unknown filter fails")
    // The bare poll counts over the whole store and carries the app's broker
    // state; the tag changes with it, so a stale broker state is never a 304.
    func poll(_ overlay: StoredEvidenceBackend.Overlay, etag: String? = nil) -> (status: Int, tag: String?, json: [String: Any]) {
      let done = DispatchSemaphore(value: 0)
      var result: (Int, String?, [String: Any]) = (0, nil, [:])
      backend.forward(request("/api/events?limit=5000", etag: etag), overlay: overlay) { body, status, _, headers in
        result = (status, headers["ETag"], (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:])
        done.signal()
      }
      precondition(done.wait(timeout: .now() + 60) == .success, "no reply for the event poll")
      return result
    }
    let stored = StoredEvidenceBackend.Overlay(fields: ["broker_connected": true, "capture_mode": "live"], tag: "live-1")
    var window = poll(stored)
    for _ in 0..<50 where (window.json["event_window"] as? [String: Any])?["scope"] as? String != "store" {
      Thread.sleep(forTimeInterval: 0.1)
      window = poll(stored)
    }
    precondition(window.status == 200 && window.json["count"] as? Int == 4, "\(window)")
    precondition(window.json["capture_mode"] as? String == "live" && window.json["broker_connected"] as? Bool == true, "\(window.json)")
    precondition((window.json["event_window"] as? [String: Any])?["scope"] as? String == "store", "\(window.json)")
    precondition(window.json["sequence_gaps"] as? String == "0", "\(window.json)")
    guard let pollTag = window.tag, pollTag.hasSuffix("-live-1\"") else { preconditionFailure("the poll tag names the overlay: \(window)") }
    precondition(poll(stored, etag: pollTag).status == 304, "an unchanged poll is not modified")
    let disconnected = StoredEvidenceBackend.Overlay(fields: ["broker_connected": false, "capture_mode": "live"], tag: "live-0")
    let changed = poll(disconnected, etag: pollTag)
    precondition(changed.status == 200 && changed.json["broker_connected"] as? Bool == false, "\(changed)")
    let stack = call(request("/api/request-stack?process_id=7&request_id=1"))
    precondition(stack.status == 200 && stack.json["status"] as? String == "not_recorded", "\(stack)")
    for path in ["/api/request-headers?session_id=1&request_id=1", "/api/request-cookies?session_id=1&request_id=1",
      "/api/cookie-provenance?session_id=1&name=sid"] {
      precondition(call(request(path)).status == 200, path)
    }
    let layout = call(request("/api/source-format?session_id=1&artifact_id=1"))
    precondition(layout.status == 200 && layout.json["schema"] as? String == "source-format-v2"
      && layout.json["status"] as? String == "formatted", "\(layout)")
    // The HAR save streams the backend's answer to a file; an error answer writes nothing.
    guard let firstRow = (index.json["requests"] as? [[String: Any]])?.first?["id"] as? String else {
      preconditionFailure("the index lists a row: \(index.json)")
    }
    precondition(call(request("/api/requests/har?rows=\(firstRow)")).status == 200, "the page's one-row HAR read is forwarded")
    let har = root.appendingPathComponent("saved.har")
    func save(_ query: String) -> StoredEvidenceBackend.Failure? {
      let done = DispatchSemaphore(value: 0)
      var failure: StoredEvidenceBackend.Failure?
      backend.download(path: "/api/requests/har", query: query, to: har) { failure = $0; done.signal() }
      precondition(done.wait(timeout: .now() + 60) == .success, "no answer for the HAR save")
      return failure
    }
    for query in ["sort=capture&order=asc", "rows=\(firstRow)&credential_values=1"] {
      precondition(save(query) == nil, query)
      let archive = (try JSONSerialization.jsonObject(with: Data(contentsOf: har)) as? [String: Any])?["log"] as? [String: Any]
      let summary = archive?["_reb"] as? [String: Any]
      precondition(summary?["complete"] as? Bool == true && (archive?["entries"] as? [Any])?.isEmpty == false, "\(query): \(String(describing: archive))")
    }
    let before = try Data(contentsOf: har)
    let missingRow = save("rows=missing-row")
    precondition(missingRow?.status == 404 && missingRow?.message.contains("missing-row") == true, "\(String(describing: missingRow))")
    let after = try Data(contentsOf: har)
    precondition(after == before, "an error answer leaves the saved file as it was")
    // Analyses of an artifact are forwarded too, and the packaged backend runs
    // its sibling worker for them.
    let facts = call(request("/api/source-facts?session_id=1&artifact_id=1"))
    precondition(facts.status == 200 && facts.json["schema"] as? String == "reb-javascript-source-facts-v2", "\(facts)")
    let bindings = call(request("/api/source-facts/rows?session_id=1&artifact_id=1&table=bindings"))
    precondition(bindings.status == 200 && bindings.json["schema"] as? String == "reb-javascript-source-fact-rows-v2"
      && (bindings.json["total"] as? Int ?? 0) > 0, "\(bindings)")
    let cleanup = call(request("/api/deobfuscation?artifact_id=1&mode=derived"))
    precondition(cleanup.status == 200 && cleanup.json["engine"] as? String == "rust-oxc"
      && cleanup.json["representation"] != nil, "\(cleanup)")
    let map = call(request("/api/artifact-map?artifact_id=1"))
    precondition(map.status == 200 && map.json["schema"] as? String == "artifact-map-v1", "\(map)")
    let notWasm = call(request("/api/wasm?artifact_id=1"))
    precondition(notWasm.status == 400, "the Rust provider refuses a JavaScript artifact as Wasm: \(notWasm)")
    let debugger = call(request("/api/native-debugger"))
    precondition(debugger.status == 200 && debugger.json["availability"] as? String == "unsupported", "\(debugger)")
    let action = call(request("/api/native-debugger/actions", method: "POST",
      body: #"{"action":"resume","target_id":"22","lease_id":"1"}"#))
    precondition(action.status == 503 && action.json["code"] as? String == "dependency_unavailable", "\(action)")

    precondition(backend.running)
    backend.stop()
    precondition(!backend.running, "stop ends the backend")
    precondition(call(request("/api/requests?limit=1")).status == 200, "the next read starts it again")
    backend.stop()

    // Forwards start in order on one queue. One cancelled while an earlier one
    // starts the backend never reaches it, and still replies exactly once.
    let starting = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
    var startingStatus = 0, cancelledStatus = 0, cancelledReplies = 0
    backend.forward(request("/api/requests?limit=1")) { _, status, _, _ in startingStatus = status; starting.signal() }
    backend.forward(request("/api/deobfuscation?artifact_id=1&mode=derived")) { _, status, _, _ in
      cancelledStatus = status
      cancelledReplies += 1
      cancelled.signal()
    }.cancel()
    precondition(starting.wait(timeout: .now() + 60) == .success && startingStatus == 200, "the first forward is answered")
    precondition(cancelled.wait(timeout: .now() + 60) == .success && cancelledStatus == 499, "a cancelled forward is not sent")
    Thread.sleep(forTimeInterval: 0.2)
    precondition(cancelledReplies == 1, "a cancelled forward replies once")
    backend.stop()

    let missing = StoredEvidenceBackend(executableURL: root.appendingPathComponent("missing"), arguments: stores)
    let refused = call(request("/api/requests"), on: missing)
    precondition(refused.status == 503 && refused.json["code"] as? String == "dependency_unavailable", "\(refused)")
    print("PASS stored-evidence reb:// reads of the request index, the event poll with the app's broker state, filtered events, headers, cookies, HAR exports and saves, stacks, source format, Facts, static cleanup, artifact map, Wasm inspection and debugger state come from the bundled backend, which stops and restarts on demand and never sends a cancelled forward")
  }
}
