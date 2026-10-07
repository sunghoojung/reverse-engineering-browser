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
        precondition(root["value"] as! String == "synthetic request", name)
      }
      let gaps = result["gaps"] as! [[String: Any]]
      precondition(gaps.map { $0["reason"] as! String } == item["gap_reasons"] as! [String], name)
      precondition((result["coverage"] as! [String: Any])["gap_count"] as! Int == gaps.count, name)
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
    print("PASS native Origin Trace shared gap regressions and step-limit coverage")
  }
}
