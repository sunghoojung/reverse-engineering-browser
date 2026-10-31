import Foundation

// Compiled with the production reader by scripts/build-research-app.sh.
// Linux CI does not have swiftc; this is the macOS acceptance for the stored tail.
@main
enum StoredEventWindowChecks {
  static func main() throws {
    precondition(StoredEventWindowCache.scanBytes == 64 * 1024 * 1024)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("reb-stored-window-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("events.jsonl")

    let missing = try StoredEventWindowCache().read(path: path.path, limit: 5)
    precondition(missing.events.isEmpty && missing.networkEvents.isEmpty)
    precondition(missing.coverage["scope"] as? String == "store")
    precondition(missing.coverage["scan_limit"] as? Int == StoredEventWindowCache.scanBytes)

    func event(sequence: Int, category: String, type: String, payload: String = "") -> Data {
      let hex = payload.utf8.map { String(format: "%02x", $0) }.joined()
      let json = #"{"session_id":"1","process_id":7,"sequence_number":"\#(sequence)","category":"\#(category)","type":"\#(type)","payload":"\#(hex)"}"#
      return Data(json.utf8) + Data([0x0a])
    }
    func sequences(_ events: [[String: Any]]) -> [Int] {
      events.map { Int(($0["sequence_number"] as? String) ?? "") ?? -1 }
    }
    func write(_ events: [Data]) throws {
      var data = Data()
      for event in events { data.append(event) }
      try data.write(to: path)
    }

    var bytes = event(sequence: 1, category: "network", type: "request_started")
    bytes += event(sequence: 2, category: "network", type: "request_failed")
    for sequence in 3...6 { bytes += event(sequence: sequence, category: "webgl", type: "api_call") }
    bytes += event(sequence: 7, category: "canvas", type: "api_call")
    try bytes.write(to: path)
    let cache = StoredEventWindowCache()
    var window = try cache.read(path: path.path, limit: 1)
    precondition(sequences(window.events) == [7])
    precondition(sequences(window.networkEvents) == [2])
    precondition(window.coverage["network_events_limited"] as? Bool == true)
    for sequence in 8...30 { bytes += event(sequence: sequence, category: "canvas", type: "gap", payload: "4") }
    try bytes.write(to: path)
    window = try cache.read(path: path.path, limit: 2)
    precondition(sequences(window.networkEvents) == [1, 2], "canvas gaps must not consume the network window")
    precondition(window.queueDrops == 23 * 4)
    precondition(window.coverage["scope"] as? String == "store")

    let canvas = (10...19).map { event(sequence: $0, category: "canvas", type: "api_call") }
    try write(canvas)
    let size = canvas[0].count
    let bounded = StoredEventWindowCache(maximumBytes: 5 * size)
    window = try bounded.read(path: path.path, limit: 10)
    precondition(sequences(window.events) == [15, 16, 17, 18, 19])
    precondition(bounded.parsedRecords == 5)
    precondition(window.coverage["scope"] as? String == "bounded_tail")
    precondition(window.coverage["scan_start"] as? String == String(5 * size))
    let handle = try FileHandle(forWritingTo: path)
    try handle.seekToEnd()
    try handle.write(contentsOf: event(sequence: 20, category: "canvas", type: "api_call"))
    try handle.close()
    window = try bounded.read(path: path.path, limit: 10)
    precondition(sequences(window.events) == [16, 17, 18, 19, 20])
    precondition(bounded.parsedRecords == 1, "a full tail slide reuses overlap summaries")

    var shifted = try Data(contentsOf: path)
    let tailStart = shifted.count - 5 * size
    shifted[tailStart - 1] = 0x20
    try shifted.write(to: path)
    let partial = StoredEventWindowCache(maximumBytes: 5 * size)
    window = try partial.read(path: path.path, limit: 10)
    precondition(sequences(window.events) == [17, 18, 19, 20])
    precondition(partial.parsedRecords == 4)

    let saturated = StoredEventWindowCache()
    var flood = Data()
    for sequence in [1, 3] { flood += event(sequence: sequence, category: "canvas", type: "api_call") }
    flood += Data(#"{"session_id":"1","process_id":8,"sequence_number":"900","category":"canvas","type":"api_call","payload":""}"#.utf8) + Data([0x0a])
    for sequence in [2, 5] { flood += event(sequence: sequence, category: "canvas", type: "api_call") }
    flood += event(sequence: 6, category: "webgl", type: "gap", payload: "18446744073709551615")
    flood += event(sequence: 7, category: "webgl", type: "gap", payload: "1")
    try flood.write(to: path)
    window = try saturated.read(path: path.path, limit: 1)
    precondition(window.sequenceGaps == 1, "late arrivals close observed holes")
    precondition(window.queueDrops == UInt64.max && window.queueDropsSaturated)
    precondition(window.namedGaps.isEmpty, "numeric drop counts never name a reason")

    // The live Wasm budgets keep their queue_drops weight and are listed by category.
    var named = event(sequence: 1, category: "vm", type: "gap", payload: "native_wasm_dispatch_budget_incomplete")
    named += event(sequence: 2, category: "vm", type: "gap", payload: "native_wasm_indirect_budget_incomplete")
    named += event(sequence: 3, category: "canvas", type: "gap", payload: "5")
    named += event(sequence: 4, category: "vm", type: "gap", payload: "native_wasm_dispatch_budget_incomplete")
    named += event(sequence: 5, category: "vm", type: "gap", payload: "native_wasm_dispatch_transport_unavailable")
    try named.write(to: path)
    window = try StoredEventWindowCache().read(path: path.path, limit: 1)
    precondition(window.queueDrops == 5 + 4 && window.sequenceGaps == 0)
    precondition(window.namedGaps == [
      NamedGap(category: "vm", reason: "native_wasm_dispatch_budget_incomplete", count: 2),
      NamedGap(category: "vm", reason: "native_wasm_indirect_budget_incomplete", count: 1),
      NamedGap(category: "vm", reason: "native_wasm_dispatch_transport_unavailable", count: 1),
    ], "\(window.namedGaps)")
    for payload in ["", "0", "01", "-1", "7", " 2", "Native_gap", "native-gap", "1native", "_native", "native gap", "<b>gap</b>"] {
      try event(sequence: 1, category: "vm", type: "gap", payload: payload).write(to: path)
      window = try StoredEventWindowCache().read(path: path.path, limit: 1)
      precondition(window.namedGaps.isEmpty, "\(payload) is not a reason")
      precondition(window.queueDrops == (payload == "7" ? 7 : 1))
    }
    let reasonHex = "native_wasm_dispatch_budget".utf8.map { String(format: "%02x", $0) }.joined()
    try Data(#"{"session_id":"1","process_id":7,"sequence_number":"1","category":"vm","type":"gap","payload_truncated":true,"payload":"\#(reasonHex)"}"#.utf8).write(to: path)
    window = try StoredEventWindowCache().read(path: path.path, limit: 1)
    precondition(window.namedGaps.isEmpty && window.queueDrops == 1, "a truncated reason is not a named reason")
    var reasons = Data()
    for index in 0...StoredEventWindowCache.maxNamedGaps {
      reasons += event(sequence: index + 1, category: "vm", type: "gap", payload: "native_reason_\(index)")
    }
    try reasons.write(to: path)
    window = try StoredEventWindowCache().read(path: path.path, limit: 1)
    precondition(window.namedGaps.count == StoredEventWindowCache.maxNamedGaps)
    precondition(window.queueDrops == UInt64(StoredEventWindowCache.maxNamedGaps + 1), "an unlisted pair stays a queue drop")

    for sequences in [[3, 1, 2], [1, 4, 2, 3], [3, 1, 2, 2]] {
      var delayed = Data()
      for sequence in sequences {
        delayed += event(sequence: sequence, category: "canvas", type: "api_call")
      }
      try delayed.write(to: path)
      let ordered = try StoredEventWindowCache().read(path: path.path, limit: 10)
      precondition(ordered.sequenceGaps == 0, "late ACKs close holes; duplicates are neutral")
      precondition(ordered.events.compactMap { Int($0["sequence_number"] as? String ?? "") } == sequences)
    }

    let openRecord = Data(#"{"session_id":"1","process_id":7,"sequence_number":"1","category":"webgl","type":"gap","payload":"323830"}"#.utf8)
    try openRecord.write(to: path)
    let reopen = StoredEventWindowCache()
    window = try reopen.read(path: path.path, limit: 2)
    precondition(window.queueDrops == 280)
    let append = try FileHandle(forWritingTo: path)
    try append.seekToEnd()
    try append.write(contentsOf: Data([0x0a]))
    try append.write(contentsOf: event(sequence: 2, category: "network", type: "request_failed"))
    try append.close()
    window = try reopen.read(path: path.path, limit: 1)
    precondition(window.queueDrops == 280)
    precondition(reopen.parsedRecords == 2)
    precondition(sequences(window.networkEvents) == [2])

    try Data(#"{"protocol_version":"#.utf8).write(to: path)
    do {
      _ = try reopen.read(path: path.path, limit: 2)
      preconditionFailure("malformed tail must fail the refresh")
    } catch {}
    precondition(reopen.parsedRecords == 0)
    try write([event(sequence: 10, category: "network", type: "request_started")])
    window = try reopen.read(path: path.path, limit: 2)
    precondition(sequences(window.events) == [10])
    precondition(sequences(window.networkEvents) == [10])
    print("PASS stored evidence windows keep network rows under a canvas tail, with bounded scan, overlap reuse, saturated summaries, and named gap reasons beside queue drops")
  }
}
