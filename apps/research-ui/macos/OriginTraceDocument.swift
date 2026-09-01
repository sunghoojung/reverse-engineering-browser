import Foundation

enum OriginTraceDocumentBuilder {
  private static let relationPriority = [
    "parent_event": 0,
    "request_initiator": 1,
    "request_lifecycle": 2,
    "artifact_request": 3,
  ]
  private static let sourceBoundaries = Set([
    "canvas", "webgl", "web_audio", "navigator", "permissions", "storage", "webrtc",
  ])
  private static let eventCategories = sourceBoundaries.union([
    "artifact", "network", "vm", "wasm",
  ])
  private static let publicArtifactFields = Set([
    "artifact_id", "kind", "url", "sha256", "byte_size", "creator_event_id",
    "parent_artifact_id", "execution_context_id", "capture_origin",
  ])

  static func build(
    events: [[String: Any]],
    edges: [[String: Any]],
    artifacts: [[String: Any]],
    requestID: String,
    rootProcessID: UInt32?,
    rootSequenceNumber: String?,
    maxSteps: Int = 32
  ) throws -> [String: Any] {
    guard canonicalUInt64(requestID) != nil else {
      throw traceError("Request ID must be a canonical unsigned 64-bit integer")
    }
    guard (rootProcessID == nil) == (rootSequenceNumber == nil) else {
      throw traceError("Root process ID and sequence number must be supplied together")
    }
    if let rootSequenceNumber, canonicalUInt64(rootSequenceNumber) == nil {
      throw traceError("Root sequence number must be a canonical unsigned 64-bit integer")
    }
    guard (1...32).contains(maxSteps) else {
      throw traceError("Origin trace step limit is outside the supported range")
    }

    var eventsByReference: [String: [String: Any]] = [:]
    for event in events {
      let reference = try eventReference(event)
      guard eventsByReference[reference] == nil else {
        throw traceError("Origin trace input contains a duplicate event reference")
      }
      eventsByReference[reference] = event
    }

    var edgesBySource: [String: [[String: Any]]] = [:]
    for edge in edges {
      guard isValidEdge(edge), let source = edgeReference(edge, prefix: "from") else {
        throw traceError("Origin trace store contains a malformed edge")
      }
      edgesBySource[source, default: []].append(edge)
    }

    let candidates = events.filter {
      $0["category"] as? String == "network" && $0["request_id"] as? String == requestID
    }
    let root: [String: Any]?
    if let rootProcessID, let rootSequenceNumber {
      let exact = candidates.filter {
        processID($0["process_id"]) == rootProcessID
          && $0["sequence_number"] as? String == rootSequenceNumber
      }
      root = exact.count == 1 ? exact[0] : nil
    } else {
      let started = candidates.filter { $0["type"] as? String == "request_started" }
      let initiated = candidates.filter { $0["type"] as? String == "request_initiated" }
      let preferred = !started.isEmpty ? started : (!initiated.isEmpty ? initiated : candidates)
      if preferred.count > 1 {
        return emptyDocument(
          requestID: requestID,
          status: "ambiguous",
          gaps: [[
            "reason": "ambiguous_request",
            "after_step": 0,
            "detail": "More than one request start uses this identifier. Select a concrete request row.",
          ]]
        )
      }
      root = preferred.first
    }
    guard let root else {
      return emptyDocument(requestID: requestID, status: "empty", gaps: [])
    }

    var steps = [try eventStep(root, relation: "trace_target", confidence: "observed")]
    var gaps: [[String: Any]] = []
    var visited = Set([try eventReference(root)])
    var current = root
    var observedLinks = 0
    var correlatedLinks = 0

    while steps.count < maxSteps {
      let currentReference = try eventReference(current)
      let candidates = (edgesBySource[currentReference] ?? []).sorted { left, right in
        let leftPriority = relationPriority[left["relation"] as? String ?? ""] ?? Int.max
        let rightPriority = relationPriority[right["relation"] as? String ?? ""] ?? Int.max
        if leftPriority != rightPriority { return leftPriority < rightPriority }
        let leftSequence = UInt64(left["to_sequence_number"] as? String ?? "") ?? 0
        let rightSequence = UInt64(right["to_sequence_number"] as? String ?? "") ?? 0
        return leftSequence > rightSequence
      }
      guard let selectedEdge = candidates.first else {
        if !sourceBoundaries.contains(current["category"] as? String ?? "") {
          gaps.append([
            "reason": "no_predecessor",
            "after_step": steps.count - 1,
            "detail": "No earlier observed relationship reaches this event.",
          ])
        }
        break
      }
      guard let target = edgeReference(selectedEdge, prefix: "to"),
        let selectedEvent = eventsByReference[target]
      else {
        gaps.append([
          "reason": "missing_event",
          "after_step": steps.count - 1,
          "detail": "The highest-priority predecessor is outside the retained evidence window.",
        ])
        break
      }
      let targetReference = try eventReference(selectedEvent)
      guard visited.insert(targetReference).inserted else {
        gaps.append([
          "reason": "cycle",
          "after_step": steps.count - 1,
          "detail": "The correlation index contains a cycle, so traversal stopped safely.",
        ])
        break
      }
      let confidence = selectedEdge["confidence"] as? String ?? "correlated"
      steps.append(
        try eventStep(
          selectedEvent,
          relation: selectedEdge["relation"] as? String ?? "unknown",
          confidence: confidence
        )
      )
      if confidence == "observed" { observedLinks += 1 } else { correlatedLinks += 1 }
      current = selectedEvent
    }
    if steps.count == maxSteps {
      gaps.append([
        "reason": "step_limit",
        "after_step": steps.count - 1,
        "detail": "The bounded trace step limit was reached.",
      ])
    }

    let linkedSteps = max(0, steps.count - 1)
    let denominator = linkedSteps + gaps.count
    let percent = denominator == 0 ? 0 : Int((Double(linkedSteps) * 100 / Double(denominator)).rounded())
    let artifactIDs = Set(steps.compactMap { step -> String? in
      guard let artifactID = step["artifact_id"] as? String, artifactID != "0" else { return nil }
      return artifactID
    })
    let publicArtifacts = artifacts.compactMap { artifact -> [String: Any]? in
      guard let artifactID = artifact["artifact_id"] as? String,
        artifactIDs.contains(artifactID)
      else { return nil }
      return artifact.filter { publicArtifactFields.contains($0.key) }
    }
    return [
      "contract_version": 1,
      "document_kind": "origin-trace",
      "request_id": requestID,
      "status": gaps.isEmpty ? "complete" : "partial",
      "steps": steps,
      "gaps": gaps,
      "coverage": [
        "linked_steps": linkedSteps,
        "observed_links": observedLinks,
        "correlated_links": correlatedLinks,
        "gap_count": gaps.count,
        "percent": percent,
      ],
      "artifacts": publicArtifacts,
    ]
  }

  private static func emptyDocument(
    requestID: String, status: String, gaps: [[String: Any]]
  ) -> [String: Any] {
    [
      "contract_version": 1,
      "document_kind": "origin-trace",
      "request_id": requestID,
      "status": status,
      "steps": [],
      "gaps": gaps,
      "coverage": [
        "linked_steps": 0,
        "observed_links": 0,
        "correlated_links": 0,
        "gap_count": gaps.count,
        "percent": 0,
      ],
      "artifacts": [],
    ]
  }

  private static func eventStep(
    _ event: [String: Any], relation: String, confidence: String
  ) throws -> [String: Any] {
    guard exactInteger(event["protocol_version"], equals: 2),
      let category = event["category"] as? String,
      eventCategories.contains(category),
      let operation = event["type"] as? String,
      !operation.isEmpty,
      let payload = decodedPayload(event),
      let sessionID = canonicalUInt64(event["session_id"]),
      let processID = processID(event["process_id"]),
      let sequenceNumber = canonicalUInt64(event["sequence_number"]),
      let monotonicTime = canonicalUInt64(event["monotonic_time_ns"]),
      let frameID = canonicalUInt64(event["frame_id"]),
      let artifactID = canonicalUInt64(event["artifact_id"]),
      let requestID = canonicalUInt64(event["request_id"])
    else {
      throw traceError("Origin trace input contains a malformed event")
    }
    return [
      "event": [
        "session_id": sessionID,
        "process_id": Int(processID),
        "sequence_number": sequenceNumber,
      ],
      "monotonic_time_ns": monotonicTime,
      "category": category,
      "operation": operation,
      "frame_id": frameID,
      "artifact_id": artifactID,
      "request_id": requestID,
      "relation": relation,
      "confidence": confidence,
      "value": payload,
    ]
  }

  private static func eventReference(_ event: [String: Any]) throws -> String {
    guard let sessionID = nonzeroUInt64(event["session_id"]),
      let processID = processID(event["process_id"]),
      let sequence = nonzeroUInt64(event["sequence_number"])
    else {
      throw traceError("Origin trace input contains a malformed event")
    }
    return "\(sessionID):\(processID):\(sequence)"
  }

  private static func edgeReference(_ edge: [String: Any], prefix: String) -> String? {
    guard let sessionID = nonzeroUInt64(edge["session_id"]),
      let processID = processID(edge["\(prefix)_process_id"]),
      let sequence = nonzeroUInt64(edge["\(prefix)_sequence_number"])
    else { return nil }
    return "\(sessionID):\(processID):\(sequence)"
  }

  private static func isValidEdge(_ edge: [String: Any]) -> Bool {
    let expectedKeys = Set([
      "protocol_version", "session_id", "from_process_id", "from_sequence_number",
      "to_process_id", "to_sequence_number", "relation", "confidence", "request_id",
      "artifact_id",
    ])
    guard Set(edge.keys) == expectedKeys,
      exactInteger(edge["protocol_version"], equals: 1),
      relationPriority[edge["relation"] as? String ?? ""] != nil,
      Set(["observed", "correlated"]).contains(edge["confidence"] as? String ?? ""),
      canonicalUInt64(edge["request_id"]) != nil,
      canonicalUInt64(edge["artifact_id"]) != nil,
      let source = edgeReference(edge, prefix: "from"),
      let target = edgeReference(edge, prefix: "to"),
      source != target
    else { return false }
    return true
  }

  private static func canonicalUInt64(_ value: Any?) -> String? {
    guard let text = value as? String,
      text.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      UInt64(text) != nil
    else { return nil }
    return text
  }

  private static func nonzeroUInt64(_ value: Any?) -> String? {
    guard let text = canonicalUInt64(value), text != "0" else { return nil }
    return text
  }

  private static func processID(_ value: Any?) -> UInt32? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      let parsed = UInt32(number.stringValue)
    else { return nil }
    return parsed
  }

  private static func exactInteger(_ value: Any?, equals expected: Int) -> Bool {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return false }
    return number.stringValue == String(expected)
  }

  private static func decodedPayload(_ event: [String: Any]) -> String? {
    guard let payload = event["payload"] as? String,
      payload.count.isMultiple(of: 2),
      payload.count <= 256,
      event["payload_encoding"] as? String == "hex",
      exactInteger(event["payload_size"], equals: payload.count / 2)
    else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(min(payload.count / 2, 256))
    var index = payload.startIndex
    while index < payload.endIndex && bytes.count < 256 {
      let next = payload.index(index, offsetBy: 2)
      guard let byte = UInt8(payload[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    return String(decoding: bytes, as: UTF8.self)
  }

  private static func traceError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace",
      code: 20,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}
