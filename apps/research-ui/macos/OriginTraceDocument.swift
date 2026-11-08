import CryptoKit
import Foundation

enum OriginTraceDocumentBuilder {
  private static let relationPriority = [
    "parent_event": 0,
    "request_initiator": 1,
    "request_lifecycle": 2,
    "artifact_request": 3,
    // Exact invocation identities drawn by the broker's index; see
    // protocol/native-js-invocation-v1.md.
    "issued_during_invocation": 4,
    "invocation_settlement": 5,
  ]
  private static let sourceBoundaries = Set([
    "canvas", "webgl", "web_audio", "navigator", "permissions", "storage", "webrtc", "runtime",
  ])
  private static let eventCategories = sourceBoundaries.union([
    "artifact", "network", "vm", "wasm",
  ])
  private static let publicArtifactFields = Set([
    "artifact_id", "kind", "url", "sha256", "byte_size", "creator_event_id",
    "parent_artifact_id", "execution_context_id", "capture_origin",
  ])
  // `monotonic_time_ns` proximity is a declared correlation input in its own
  // right, and a weaker one than the identity keys the edge index joins on. It
  // is consulted only where the identity chain has already ended, and only for
  // a cross-process record of the same retained request: the renderer-to-browser
  // hop that initiator resolution failed to close. Mirrors ADJACENCY_WINDOW_NS
  // in apps/origin-trace-backend/src/origin_trace.rs.
  private static let adjacencyWindowNanoseconds: UInt64 = 1_000_000

  static func build(
    events: [[String: Any]],
    edges: [[String: Any]],
    artifacts: [[String: Any]],
    requestID: String,
    sessionID: String? = nil,
    rootProcessID: UInt32?,
    rootSequenceNumber: String?,
    maxSteps: Int = 32,
    // Raw request bodies retained under sensitive capture, keyed by
    // "session:process:sequence" of the event carrying each. Integration point:
    // the request path and body capture contract supplies them; until it is
    // merged callers pass none and invocation_value_flow is never reported.
    requestBodies: [String: [UInt8]] = [:]
  ) throws -> [String: Any] {
    guard canonicalUInt64(requestID) != nil else {
      throw traceError("Request ID must be a canonical unsigned 64-bit integer")
    }
    if let sessionID, nonzeroUInt64(sessionID) == nil {
      throw traceError("Session ID must be a canonical nonzero unsigned 64-bit integer")
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
    var captureGapStreams: [String] = []
    for event in events {
      let reference = try eventReference(event)
      // Queue-loss metadata shares its anchor's reference, but is not an
      // addressable event and cannot satisfy a retained predecessor edge.
      if event["type"] as? String == "gap" {
        let marker = try eventStep(event, relation: "trace_target", confidence: "observed")
        // A named capture-limit gap carries its reason, not a drop count, in
        // its own sequence slot. It is a sampling limit of its own category
        // that Traffic already leaves out, so a request trace neither counts it
        // as queue loss nor refuses the window over it.
        if isNamedCaptureLimit(event, reason: marker["value"] as? String) { continue }
        guard nonzeroUInt64(marker["value"]) != nil,
          let truncated = event["payload_truncated"] as? NSNumber,
          CFGetTypeID(truncated) == CFBooleanGetTypeID(), !truncated.boolValue
        else {
          throw traceError("Origin trace input contains a malformed gap")
        }
        captureGapStreams.append(streamReference(event))
        continue
      }
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
      $0["type"] as? String != "gap"
        && $0["category"] as? String == "network" && $0["request_id"] as? String == requestID
        && (sessionID == nil || $0["session_id"] as? String == sessionID)
        && (rootProcessID == nil || processID($0["process_id"]) == rootProcessID)
        && (rootSequenceNumber == nil || $0["sequence_number"] as? String == rootSequenceNumber)
    }
    // Lifecycle preference cannot select between different captured sessions.
    let ambiguousSession = Set(candidates.compactMap { $0["session_id"] as? String }).count > 1
    let preferred: [[String: Any]]
    if rootProcessID != nil {
      preferred = candidates
    } else {
      let started = candidates.filter { $0["type"] as? String == "request_started" }
      let initiated = candidates.filter { $0["type"] as? String == "request_initiated" }
      preferred = !started.isEmpty ? started : (!initiated.isEmpty ? initiated : candidates)
    }
    if ambiguousSession || preferred.count > 1 {
      return emptyDocument(
        requestID: requestID,
        status: "ambiguous",
        gaps: [[
          "reason": "ambiguous_request",
          "after_step": 0,
          "detail": "More than one retained request matches these selectors. Supply session_id and a concrete root process/sequence pair.",
        ]]
      )
    }
    let root = preferred.first
    guard let root else {
      return emptyDocument(requestID: requestID, status: "empty", gaps: [])
    }

    var steps = [try eventStep(root, relation: "trace_target", confidence: "observed")]
    var gaps: [[String: Any]] = []
    var visited = Set([try eventReference(root)])
    var current = root
    var observedLinks = 0
    var correlatedLinks = 0
    var timeAdjacentLinks = 0

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
        // Where identity ends at the renderer's own request record, an exact
        // returned value found in a retained body of this request is a
        // correlated link. It is never a time window.
        if current["category"] as? String == "network",
          current["type"] as? String == "request_initiated",
          let body = steps.reversed().lazy.compactMap({ step -> [UInt8]? in
            guard let event = step["event"] as? [String: Any] else { return nil }
            return requestBodies[
              "\(event["session_id"] as? String ?? ""):\(event["process_id"] as? Int ?? -1):\(event["sequence_number"] as? String ?? "")"
            ]
          }).first
        {
          var refused = false
          switch valueFlow(retained: eventsByReference, visited: visited, request: current, body: body) {
          case .linked(let settle):
            visited.insert(try eventReference(settle))
            steps.append(
              try eventStep(settle, relation: "invocation_value_flow", confidence: "correlated"))
            correlatedLinks += 1
            current = settle
            continue
          case .refused(let reason, let detail):
            gaps.append(["reason": reason, "after_step": steps.count - 1, "detail": detail])
            refused = true
          case .none:
            refused = false
          }
          if refused { break }
        }
        if !sourceBoundaries.contains(current["category"] as? String ?? "") {
          // Proximity never closes the gap. The identity chain really did end
          // here, so the gap stays and the adjacency row is reported beside it
          // rather than in place of it.
          let adjacent = adjacentCandidate(
            retained: eventsByReference, visited: visited, current: current
          ).flatMap {
            try? eventStep($0, relation: "temporal_adjacency", confidence: "time_adjacent")
          }
          gaps.append([
            "reason": "no_predecessor",
            "after_step": steps.count - 1,
            "detail": adjacent == nil
              ? "No earlier observed relationship reaches this event."
              : "No earlier observed relationship reaches this event. The next row is time-adjacent only: it shares this request identity in another process within a bounded timestamp window, which is not a predecessor and not value flow.",
          ])
          // Adjacency is terminal. Walking on from a timestamp match would hang
          // identity edges off a guess and count them as correlated links, so
          // traversal always stops here.
          if let adjacent {
            steps.append(adjacent)
            timeAdjacentLinks += 1
          }
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
    // A time-adjacent row is only ever appended where traversal broke, so it can
    // fill the step budget without the limit being the reason the walk stopped.
    if steps.count - timeAdjacentLinks == maxSteps {
      gaps.append([
        "reason": "step_limit",
        "after_step": steps.count - 1,
        "detail": "The bounded trace step limit was reached.",
      ])
    }
    let streams = Set(steps.compactMap { step -> String? in
      guard let event = step["event"] as? [String: Any] else { return nil }
      return streamReference(event)
    })
    let markerCount = captureGapStreams.filter { streams.contains($0) }.count
    if markerCount > 0 {
      gaps.append([
        "reason": "capture_gap",
        "after_step": 0,
        "detail": "The retained window contains \(markerCount) native queue-drop markers in this trace's session/process streams. Counts may overlap; these markers do not identify a missing predecessor or prove value flow.",
      ])
    }

    // Coverage stays an identity measure. A time-adjacent row is a step but not
    // a link, so it moves neither the denominator nor the reported percentage.
    let linkedSteps = max(0, steps.count - 1 - timeAdjacentLinks)
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
        "time_adjacent_links": timeAdjacentLinks,
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
        "time_adjacent_links": 0,
        "gap_count": gaps.count,
        "percent": 0,
      ],
      "artifacts": [],
    ]
  }

  private static func eventStep(
    _ event: [String: Any], relation: String, confidence: String
  ) throws -> [String: Any] {
    guard let protocolVersion = event["protocol_version"] as? Int,
      Set([2, 3]).contains(protocolVersion),
      let category = event["category"] as? String,
      eventCategories.contains(category),
      let operation = event["type"] as? String,
      !operation.isEmpty,
      let payload = stepValue(event),
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
      "value": binaryRecordSummary(category: category, operation: operation, event: event) ?? payload,
    ]
  }

  // Request target and body records are fixed binary layouts
  // (protocol/native-network-v2.md), not text. A step names the record instead
  // of decoding it, so no NUL or control byte reads as captured text; Traffic
  // decodes their fields. Mirrors binary_record_summary in
  // apps/origin-trace-backend/src/origin_trace.rs.
  private static func binaryRecordSummary(
    category: String, operation: String, event: [String: Any]
  ) -> String? {
    let network = [
      "request_target", "request_body", "request_initiator_stack", "script_identity",
      "request_watch_match",
    ]
    let observation = [
      "listener_dispatch", "timer_observation", "csp_violation", "exception_observation",
      "dom_mutation",
    ]
    let isNetwork = category == "network" && network.contains(operation)
    guard
      isNetwork || (category == "runtime" && observation.contains(operation)),
      let payload = event["payload"] as? String
    else { return nil }
    let whereShown = isNetwork ? "Traffic shows its fields" : "decoded on read"
    return "Binary \(operation) record, \(payload.count / 2) bytes, not shown as text; \(whereShown)"
  }

  // Exactly one surviving candidate, or none. Two adjacent records are a tie
  // this function must not break; reporting the nearer one would present a
  // choice between guesses as evidence. A candidate must also sit at or before
  // the current event, so cross-process clock skew can drop a real pair but can
  // never invent an order.
  private static func adjacentCandidate(
    retained: [String: [String: Any]], visited: Set<String>, current: [String: Any]
  ) -> [String: Any]? {
    // Scoped to the network lifecycle record this class was measured on. An
    // artifact, VM or Wasm head keeps the bare gap rather than a claim no lane
    // has characterised.
    guard current["category"] as? String == "network",
      let nowText = canonicalUInt64(current["monotonic_time_ns"]), let now = UInt64(nowText),
      let request = nonzeroUInt64(current["request_id"]),
      let session = current["session_id"] as? String,
      let process = processID(current["process_id"])
    else { return nil }
    var found: [String: Any]?
    for (reference, event) in retained where !visited.contains(reference) {
      guard event["session_id"] as? String == session,
        event["category"] as? String == "network",
        canonicalUInt64(event["request_id"]) == request,
        processID(event["process_id"]) != process,
        let thenText = canonicalUInt64(event["monotonic_time_ns"]),
        let then = UInt64(thenText),
        then <= now,
        now - then <= adjacencyWindowNanoseconds
      else { continue }
      if found != nil { return nil }
      found = event
    }
    return found
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

  private static func streamReference(_ event: [String: Any]) -> String {
    // Called only after validating an event reference or projecting a step.
    "\(event["session_id"] as! String):\(processID(event["process_id"])!)"
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

  // Compact identity past a 16-record Wasm budget. The same wording as
  // overflow_summary in origin_trace.rs. Nil rejects the record.
  private static func wasmOverflowSummary(_ event: [String: Any]) -> String? {
    guard let operation = event["type"] as? String,
      operation == "wasm_dispatch_overflow" || operation == "wasm_indirect_overflow",
      event["artifact_id"] as? String == "0", event["parent_event_id"] as? String == "0",
      let payload = event["payload"] as? String,
      payload.count.isMultiple(of: 2),
      event["payload_encoding"] as? String == "hex",
      exactInteger(event["payload_size"], equals: payload.count / 2)
    else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(payload.count / 2)
    var index = payload.startIndex
    while index < payload.endIndex {
      let next = payload.index(index, offsetBy: 2)
      guard let byte = UInt8(payload[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    let indirect = operation == "wasm_indirect_overflow"
    let size = indirect ? 40 : 32
    guard bytes.count == size else { return nil }
    func u16(_ at: Int) -> UInt16 { UInt16(bytes[at]) | (UInt16(bytes[at + 1]) << 8) }
    func u32(_ at: Int) -> UInt32 {
      UInt32(bytes[at]) | (UInt32(bytes[at + 1]) << 8) | (UInt32(bytes[at + 2]) << 16)
        | (UInt32(bytes[at + 3]) << 24)
    }
    guard u16(0) == 1, u16(2) == UInt16(size), bytes[5] == 0 else { return nil }
    if indirect {
      var reserved: UInt64 = 0
      for shift in 0..<8 { reserved |= UInt64(bytes[32 + shift]) << (8 * shift) }
      guard reserved == 0 else { return nil }
    } else if u32(28) != 0 {
      return nil
    }
    let omittedAt = indirect ? 28 : 24
    let omitted = u32(omittedAt)
    let ring = u16(6)
    let label = indirect ? "call_indirect" : "br_table"
    if bytes[4] == 2 {
      guard ring == 0, omitted >= 1, bytes[8..<omittedAt].allSatisfy({ $0 == 0 }) else { return nil }
      return
        "Wasm \(label) overflow omitted \(omitted) identities past the ring. Not a full observation."
    }
    let limit: UInt32 = 16 * 1024 * 1024
    let function = u32(8)
    let offset = u32(12)
    guard bytes[4] == 1, omitted == 0, ring < 32, function < limit, offset >= 8, offset < limit
    else { return nil }
    if !indirect {
      let selector = u32(16)
      let arms = u32(20)
      guard arms < limit else { return nil }
      return
        "Wasm br_table overflow identity: function \(function), byte \(offset), selector \(selector), arms \(arms), ring \(ring). Not a full observation."
    }
    let table = u32(16)
    let slot = u32(20)
    let resolution = u32(24)
    let names = ["resolved", "null", "out-of-bounds", "foreign", "unresolved"]
    guard table < limit, resolution < names.count else { return nil }
    return
      "Wasm call_indirect overflow identity: caller \(function), byte \(offset), table \(table), slot \(slot), resolution \(names[Int(resolution)]), ring \(ring). Not a full observation."
  }

  // A JavaScript invocation record reads as text, never as its binary payload:
  // the same wording as invocation_value in origin_trace.rs.
  private static func stepValue(_ event: [String: Any]) -> String? {
    if let operation = event["type"] as? String,
      operation == "wasm_dispatch_overflow" || operation == "wasm_indirect_overflow"
    {
      return wasmOverflowSummary(event)
    }
    guard let operation = event["type"] as? String, operation.hasPrefix("js_invocation_") else {
      return decodedPayload(event)
    }
    let kinds = [
      "integer", "number", "string", "symbol", "undefined", "null", "boolean", "BigInt",
      "object", "function", "array", "ArrayBuffer", "view", "promise",
    ]
    switch operation {
    case "js_invocation_start":
      guard let start = invocationStart(event) else { return nil }
      let parent =
        start.parent != 0
        ? ", inside invocation \(start.parent)" : (start.parentUnknown ? ", parent unknown" : "")
      return "invocation \(start.id) started at site \(start.slot) with \(start.arguments) argument(s)\(parent)"
    case "js_invocation_settle":
      guard let settle = invocationSettle(event), (1...14).contains(Int(settle.kind)) else {
        return nil
      }
      return "invocation \(settle.id) \(settle.fulfilled ? "fulfilled" : "rejected"): \(kinds[Int(settle.kind) - 1])"
        + (settle.length != 0 ? ", length \(settle.length)" : "")
        + (settle.digest != nil ? ", digest retained" : "")
    case "js_invocation_request":
      guard let request = invocationRequest(event) else { return nil }
      return request.inside
        ? "request started inside invocation \(request.id)"
        : "request started outside script while an invocation was open"
    default:
      return nil
    }
  }

  private struct InvocationDigest {
    let sha256: [UInt8]
    let rolling: UInt64
    let byteLength: Int
  }

  private enum ValueFlow {
    case none
    case linked([String: Any])
    case refused(String, String)
  }

  // retained_request_bodies in origin_trace.rs: the request-body capture
  // contract's `request_body` child record of the traced request and its one
  // sensitive artifact, keyed by the parent request record. `read` returns
  // verified bytes or nil; anything else is no body, never a guess.
  static func retainedRequestBodies(
    events: [[String: Any]], artifacts: [[String: Any]], requestID: String,
    read: ([String: Any]) -> [UInt8]?
  ) -> [String: [UInt8]] {
    var bodies: [String: [UInt8]] = [:]
    for event in events {
      guard event["type"] as? String == "request_body",
        event["category"] as? String == "network",
        event["request_id"] as? String == requestID,
        let artifactID = event["artifact_id"] as? String, artifactID != "0",
        let parent = event["parent_event_id"] as? String, parent != "0",
        let session = event["session_id"] as? String,
        let process = processID(event["process_id"])
      else { continue }
      let matching = artifacts.filter {
        $0["artifact_id"] as? String == artifactID && $0["kind"] as? String == "request_body"
          && $0["capture_origin"] as? String == "network_request"
          && $0["creator_event_id"] as? String == event["sequence_number"] as? String
          && $0["session_id"] as? String == session
      }
      guard matching.count == 1, let bytes = read(matching[0]) else { continue }
      bodies["\(session):\(process):\(parent)"] = bytes
    }
    return bodies
  }

  private static let rollingBase: UInt64 = 0x100_0000_01b3
  private static let searchByteLimit = 16 << 20

  private static func payloadBytes(_ event: [String: Any]) -> [UInt8]? {
    guard let text = event["payload"] as? String, text.count == 256 else { return nil }
    var bytes: [UInt8] = []
    var index = text.startIndex
    while index < text.endIndex {
      let next = text.index(index, offsetBy: 2)
      guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    return bytes
  }

  private static func le(_ p: [UInt8], _ at: Int, _ width: Int) -> UInt64 {
    (0..<width).reduce(UInt64(0)) { $0 | (UInt64(p[at + $1]) << (8 * UInt64($1))) }
  }

  // The checks of payload() in js_invocation.rs: a version 1 invocation record
  // in a valid vm envelope.
  private static func invocationPayload(_ event: [String: Any], _ kind: String) -> [UInt8]? {
    guard event["type"] as? String == kind, event["category"] as? String == "vm",
      exactInteger(event["protocol_version"], equals: 3), exactInteger(event["flags"], equals: 0),
      (event["payload_truncated"] as? Bool) == false, exactInteger(event["payload_size"], equals: 128),
      event["payload_encoding"] as? String == "hex",
      ["session_id", "sequence_number", "monotonic_time_ns"].allSatisfy({ nonzeroUInt64(event[$0]) != nil }),
      ["artifact_id", "parent_event_id", "navigation_id"].allSatisfy({ event[$0] as? String == "0" }),
      canonicalUInt64(event["frame_id"]) != nil, canonicalUInt64(event["request_id"]) != nil,
      let process = processID(event["process_id"]), process != 0,
      let thread = processID(event["thread_id"]), thread != 0,
      let p = payloadBytes(event), le(p, 0, 2) == 1, le(p, 2, 2) == 128
    else { return nil }
    return p
  }

  private static func validKind(_ kind: UInt8, _ low: UInt64) -> Bool {
    (1...14).contains(kind) && (kind == 1 || (kind == 7 ? low <= 1 : low == 0))
  }

  private static func invocationStart(_ event: [String: Any])
    -> (slot: UInt8, id: UInt64, parent: UInt64, parentUnknown: Bool, arguments: UInt64)?
  {
    guard let p = invocationPayload(event, "js_invocation_start"),
      event["frame_id"] as? String != "0", event["request_id"] as? String == "0"
    else { return nil }
    let (slot, flags, argc, id, parent) = (p[4], p[5], le(p, 6, 2), le(p, 20, 4), le(p, 24, 4))
    guard slot < 8, flags & ~0x03 == 0, le(p, 8, 4) != 0, le(p, 16, 4) != 0,
      le(p, 12, 4) < le(p, 16, 4), id != 0, le(p, 28, 2) < 64, le(p, 30, 2) < 256,
      le(p, 104, 8) != 0, p[112...].allSatisfy({ $0 == 0 }),
      parent == 0 || (parent < id && flags & 0x01 == 0), (flags & 0x02 != 0) == (argc > 8)
    else { return nil }
    for index in 0..<8 {
      let (kind, low) = (p[32 + index], le(p, 40 + 4 * index, 4))
      guard UInt64(index) < argc ? validKind(kind, low) : (kind == 0 && low == 0) else { return nil }
    }
    return (slot, id, parent, flags & 0x01 != 0, argc)
  }

  private static func invocationSettle(_ event: [String: Any])
    -> (id: UInt64, fulfilled: Bool, kind: UInt8, length: UInt64, digest: InvocationDigest?)?
  {
    guard let p = invocationPayload(event, "js_invocation_settle"),
      event["frame_id"] as? String != "0", event["request_id"] as? String == "0"
    else { return nil }
    let (slot, outcome, via, kind) = (p[4], p[5], p[6], p[7])
    let (length, state, encoding, flags) = (le(p, 12, 4), p[16], p[17], p[18])
    let (byteLength, rolling) = (le(p, 20, 4), le(p, 24, 8))
    let (fulfilled, rejected) = (outcome == 1, outcome == 2)
    let (string, bytes) = (kind == 3, kind == 12 || kind == 13)
    guard slot < 8, fulfilled || rejected, (1...14).contains(kind), le(p, 8, 4) != 0,
      le(p, 64, 8) != 0, p[19] == 0, flags & ~0x01 == 0, p[72...].allSatisfy({ $0 == 0 }),
      (via == 1 && fulfilled) || (via == 2 && rejected) || via == 3,
      length == 0 || string || bytes || kind == 11
    else { return nil }
    var digest: InvocationDigest?
    if state == 1 {
      guard fulfilled, byteLength <= 1 << 20, (string && encoding == 1) || (bytes && encoding == 2),
        string || flags & 0x01 == 0, !string || byteLength >= length, !bytes || byteLength == length,
        byteLength != 0 || rolling == 0
      else { return nil }
      digest = InvocationDigest(sha256: Array(p[32..<64]), rolling: rolling, byteLength: Int(byteLength))
    } else {
      let consistent: Bool
      switch state {
      case 0: consistent = true
      case 2: consistent = !(fulfilled && (string || bytes))
      case 3: consistent = fulfilled && (string || bytes)
      case 4: consistent = fulfilled && bytes
      default: consistent = false
      }
      guard consistent, encoding == 0, byteLength == 0, rolling == 0, flags == 0,
        p[32..<64].allSatisfy({ $0 == 0 })
      else { return nil }
    }
    return (le(p, 8, 4), fulfilled, kind, length, digest)
  }

  private static func invocationRequest(_ event: [String: Any]) -> (inside: Bool, id: UInt64)? {
    guard let p = invocationPayload(event, "js_invocation_request"),
      let request = nonzeroUInt64(event["request_id"]), let requestID = UInt64(request),
      requestID <= UInt64(UInt32.max)
    else { return nil }
    let (state, id) = (p[4], le(p, 8, 4))
    guard state == 2 || state == 3, (state == 2) == (id != 0), le(p, 12, 2) < 256,
      p[5..<8].allSatisfy({ $0 == 0 }), le(p, 14, 2) == 0, p[16...].allSatisfy({ $0 == 0 })
    else { return nil }
    return (state == 2, id)
  }

  // body_contains in js_invocation.rs: the rolling hash selects candidate
  // windows of exactly the stated length, and SHA-256 alone confirms one.
  private static func bodyContains(_ body: [UInt8], _ digest: InvocationDigest) -> Bool? {
    let length = digest.byteLength
    guard length > 0, length <= body.count else { return false }
    var power: UInt64 = 1
    for _ in 1..<max(length, 1) { power = power &* rollingBase }
    var hash = body[0..<length].reduce(UInt64(0)) { $0 &* rollingBase &+ UInt64($1) }
    var hashed = 0
    for start in 0...(body.count - length) {
      if start > 0 {
        hash = (hash &- UInt64(body[start - 1]) &* power) &* rollingBase
          &+ UInt64(body[start + length - 1])
      }
      if hash == digest.rolling {
        hashed += length
        if hashed > searchByteLimit { return nil }
        if Array(SHA256.hash(data: Data(body[start..<(start + length)]))) == digest.sha256 {
          return true
        }
      }
    }
    return false
  }

  // value_flow in origin_trace.rs: the one settle record of the request's
  // session and renderer process, earlier in that process's sequence, whose
  // exact digested value occurs in the body.
  private static func valueFlow(
    retained: [String: [String: Any]], visited: Set<String>, request: [String: Any], body: [UInt8]
  ) -> ValueFlow {
    guard let limitText = request["sequence_number"] as? String, let limit = UInt64(limitText) else {
      return .none
    }
    var found: [[String: Any]] = []
    for (key, event) in retained.sorted(by: { $0.key < $1.key }) {
      guard !visited.contains(key), event["type"] as? String == "js_invocation_settle",
        event["session_id"] as? String == request["session_id"] as? String,
        processID(event["process_id"]) == processID(request["process_id"]),
        let sequence = UInt64(event["sequence_number"] as? String ?? ""), sequence < limit,
        let digest = invocationSettle(event)?.digest
      else { continue }
      switch bodyContains(body, digest) {
      case .some(true): found.append(event)
      case .some(false): break
      case .none:
        return .refused(
          "value_flow_unsearched",
          "A retained returned value could not be searched in this request body within the bounded search, so no value-flow link is reported.")
      }
    }
    switch found.count {
    case 0: return .none
    case 1: return .linked(found[0])
    default:
      return .refused(
        "value_flow_ambiguous",
        "\(found.count) returned values with retained digests occur in this request body. None is chosen.")
    }
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

  // The rule namedGap in StoredEventWindow.swift and named_gap in
  // event_window.rs apply: an untruncated lowercase identifier reason in a
  // lowercase identifier category. A decimal drop count never matches. This
  // file is compiled alone by the gap checker, so the rule is restated here.
  private static func isNamedCaptureLimit(_ event: [String: Any], reason: String?) -> Bool {
    guard (event["payload_truncated"] as? Bool) != true,
      let category = event["category"] as? String, let reason
    else { return false }
    return isIdentifier(Array(category.utf8), maximum: 32) && isIdentifier(Array(reason.utf8), maximum: 128)
  }

  private static func isIdentifier(_ bytes: [UInt8], maximum: Int) -> Bool {
    let lower = UInt8(ascii: "a")...UInt8(ascii: "z"), digit = UInt8(ascii: "0")...UInt8(ascii: "9")
    guard (1...maximum).contains(bytes.count), let first = bytes.first, lower.contains(first) else { return false }
    return bytes.allSatisfy { lower.contains($0) || digit.contains($0) || $0 == UInt8(ascii: "_") }
  }

  private static func traceError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace",
      code: 20,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }
}
