import Foundation

// Compile with the production builder; share the Rust HTTP regression cases.
@main
enum OriginTraceGapChecks {
  static func main() throws {
    let bytes = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
    let fixture = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
    let events = fixture["events"] as! [String: [String: Any]]
    let edges = fixture["edges"] as! [String: [String: Any]]
    for item in fixture["cases"] as! [[String: Any]] {
      let name = item["name"] as! String
      let query = item["query"] as! [String: Any]
      let expectedError = item["http_status"] as! Int == 400
      let result: [String: Any]
      do {
        result = try OriginTraceDocumentBuilder.build(
          events: (item["events"] as! [String]).map { events[$0]! },
          edges: (item["edges"] as! [String]).map { edges[$0]! },
          artifacts: [],
          requestID: query["request_id"] as! String,
          sessionID: query["session_id"] as? String,
          rootProcessID: (query["root_process_id"] as? Int).map { UInt32($0) },
          rootSequenceNumber: query["root_sequence_number"] as? String
        )
      } catch {
        precondition(expectedError, "\(name): unexpected error \(error)")
        continue
      }
      precondition(!expectedError, "\(name): malformed or duplicate evidence was accepted")
      precondition(result["status"] as! String == item["status"] as! String, name)
      let steps = result["steps"] as! [[String: Any]]
      let sequences = steps.map { ($0["event"] as! [String: Any])["sequence_number"] as! String }
      precondition(sequences == item["step_sequences"] as! [String], name)
      precondition(steps.allSatisfy { $0["operation"] as? String != "gap" }, name)
      if let root = steps.first {
        precondition(root["request_id"] as! String == "9007199254740995", name)
        if item["step_values"] == nil {
          precondition(root["value"] as! String == "synthetic request", name)
        }
      }
      // Request target and body records are binary layouts: each reader names
      // the record with the same summary text and never decodes it.
      if let values = item["step_values"] as? [String] {
        precondition(steps.map { $0["value"] as! String } == values, "\(name) values")
      }
      if let sessions = item["step_sessions"] as? [String] {
        precondition(steps.map { ($0["event"] as! [String: Any])["session_id"] as! String } == sessions, name)
      }
      if let confidences = item["step_confidences"] as? [String] {
        precondition(steps.map { $0["confidence"] as! String } == confidences, name)
      }
      if let relations = item["step_relations"] as? [String] {
        precondition(steps.map { $0["relation"] as! String } == relations, name)
      }
      let gaps = result["gaps"] as! [[String: Any]]
      precondition(gaps.map { $0["reason"] as! String } == item["gap_reasons"] as! [String], name)
      precondition((result["coverage"] as! [String: Any])["gap_count"] as! Int == gaps.count, name)
      // `monotonic_time_ns` proximity is its own confidence class: it occupies a
      // step without becoming an observed or correlated link, it never replaces
      // the missing-predecessor gap, and it never moves the reported percentage.
      if let expected = item["coverage"] as? [String: Int] {
        let coverage = result["coverage"] as! [String: Any]
        precondition(Set(coverage.keys) == Set(expected.keys), name)
        for (field, value) in expected {
          precondition(coverage[field] as! Int == value, "\(name) \(field)")
        }
        let adjacent = steps.filter { $0["confidence"] as! String == "time_adjacent" }.count
        precondition(adjacent == expected["time_adjacent_links"]!, name)
        if adjacent > 0 {
          precondition(steps.last!["confidence"] as! String == "time_adjacent", name)
          precondition(gaps.contains { $0["reason"] as! String == "no_predecessor" }, name)
        }
      }
      if let gap = gaps.first(where: { $0["reason"] as? String == "capture_gap" }) {
        let count = item["marker_count"] as! Int
        let detail = gap["detail"] as! String
        precondition(detail.contains("\(count) native queue-drop markers"), name)
        precondition(detail.contains("Counts may overlap"), name)
        precondition(detail.contains("do not identify a missing predecessor"), name)
      }
    }
    let bounded = try OriginTraceDocumentBuilder.build(
      events: [events["root"]!, events["gap"]!], edges: [], artifacts: [],
      requestID: "9007199254740995", rootProcessID: 42,
      rootSequenceNumber: "9007199254740993", maxSteps: 1
    )
    let reasons = (bounded["gaps"] as! [[String: Any]]).map { $0["reason"] as! String }
    precondition(reasons == ["step_limit", "capture_gap"])
    // A time-adjacent row may fill the last step slot. That must not be
    // reported as the traversal having reached its limit.
    let budget = try OriginTraceDocumentBuilder.build(
      events: [events["adjacent_root"]!, events["adjacent_initiated"]!], edges: [], artifacts: [],
      requestID: "9007199254740995", rootProcessID: 42,
      rootSequenceNumber: "9007199254740999", maxSteps: 2
    )
    precondition((budget["steps"] as! [[String: Any]]).count == 2)
    precondition((budget["gaps"] as! [[String: Any]]).map { $0["reason"] as! String }
      == ["no_predecessor"])
    print("PASS native Origin Trace shared gap/session regressions, step-limit coverage and time-adjacent confidence class")
    if CommandLine.arguments.count > 2 {
      try checkInvocationCases(CommandLine.arguments[2])
    }
  }

  // The fixture origin_trace.rs runs too: invocation identity relations and the
  // exact value-flow join must produce the same rows, gaps and coverage.
  static func checkInvocationCases(_ path: String) throws {
    let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
    let fixture = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
    let events = fixture["events"] as! [String: [String: Any]]
    let edges = fixture["edges"] as! [String: [String: Any]]
    let bodies = fixture["bodies"] as! [String: [String: String]]
    for item in fixture["cases"] as! [[String: Any]] {
      let name = item["name"] as! String
      let query = item["query"] as! [String: Any]
      var requestBodies: [String: [UInt8]] = [:]
      for key in item["bodies"] as! [String] {
        let body = bodies[key]!
        let hex = Array(body["hex"]!.utf8)
        requestBodies[body["event"]!] = stride(from: 0, to: hex.count, by: 2).map {
          UInt8(String(decoding: hex[$0..<$0 + 2], as: UTF8.self), radix: 16)!
        }
      }
      let result = try OriginTraceDocumentBuilder.build(
        events: (item["events"] as! [String]).map { events[$0]! },
        edges: (item["edges"] as! [String]).map { edges[$0]! },
        artifacts: [],
        requestID: query["request_id"] as! String,
        sessionID: query["session_id"] as? String,
        rootProcessID: (query["root_process_id"] as? Int).map { UInt32($0) },
        rootSequenceNumber: query["root_sequence_number"] as? String,
        requestBodies: requestBodies
      )
      let steps = result["steps"] as! [[String: Any]]
      precondition(
        steps.map { ($0["event"] as! [String: Any])["sequence_number"] as! String }
          == item["step_sequences"] as! [String], name)
      precondition(steps.map { $0["relation"] as! String } == item["step_relations"] as! [String], name)
      precondition(
        steps.map { $0["confidence"] as! String } == item["step_confidences"] as! [String], name)
      let gaps = result["gaps"] as! [[String: Any]]
      precondition(gaps.map { $0["reason"] as! String } == item["gap_reasons"] as! [String], name)
      let coverage = result["coverage"] as! [String: Any]
      for (field, value) in item["coverage"] as! [String: Int] {
        precondition(coverage[field] as! Int == value, "\(name) \(field)")
      }
      if let values = item["step_values"] as? [Any] {
        for (expected, step) in zip(values, steps) {
          if let expected = expected as? String {
            precondition(step["value"] as! String == expected, name)
          }
        }
      }
    }
    // The request-body pairing: the traced request's request_body child record
    // and its one matching sensitive artifact.
    let record: [String: Any] = [
      "type": "request_body", "category": "network", "request_id": "900", "artifact_id": "31",
      "parent_event_id": "1", "session_id": "7", "process_id": 84, "sequence_number": "2",
    ]
    let artifact: [String: Any] = [
      "artifact_id": "31", "kind": "request_body", "capture_origin": "network_request",
      "creator_event_id": "2", "session_id": "7",
    ]
    let body: [UInt8] = Array("n=token".utf8)
    let found = OriginTraceDocumentBuilder.retainedRequestBodies(
      events: [record], artifacts: [artifact], requestID: "900", read: { _ in body })
    precondition(found == ["7:84:1": body])
    for (field, value) in [("creator_event_id", "3"), ("kind", "response_body"), ("capture_origin", "unknown")] {
      var wrong = artifact
      wrong[field] = value
      precondition(OriginTraceDocumentBuilder.retainedRequestBodies(
        events: [record], artifacts: [wrong], requestID: "900", read: { _ in body }).isEmpty, field)
    }
    precondition(OriginTraceDocumentBuilder.retainedRequestBodies(
      events: [record], artifacts: [artifact, artifact], requestID: "900", read: { _ in body }).isEmpty)
    precondition(OriginTraceDocumentBuilder.retainedRequestBodies(
      events: [record], artifacts: [artifact], requestID: "900", read: { _ in nil }).isEmpty)
    print("PASS native Origin Trace invocation identity and exact value-flow cases match the Rust builder")
  }
}
