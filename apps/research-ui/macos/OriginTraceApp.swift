import Cocoa
import Foundation
import WebKit

private struct LocalHTTPError: Error {
  let status: Int
  let message: String
}

private final class LocalContentHandler: NSObject, WKURLSchemeHandler {
  private let indexURL: URL
  private let eventStoreURL: URL
  private let traceStoreURL: URL
  private let signalStoreURL: URL
  private let artifactStoreURL: URL
  private let brokerSocketURL: URL?

  init(
    indexURL: URL,
    eventStoreURL: URL,
    traceStoreURL: URL,
    signalStoreURL: URL,
    artifactStoreURL: URL,
    brokerSocketURL: URL?
  ) {
    self.indexURL = indexURL
    self.eventStoreURL = eventStoreURL
    self.traceStoreURL = traceStoreURL
    self.signalStoreURL = signalStoreURL
    self.artifactStoreURL = artifactStoreURL
    self.brokerSocketURL = brokerSocketURL
  }

  func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
    if ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1" {
      print("SMOKE_RESOURCE \(urlSchemeTask.request.url?.absoluteString ?? "invalid")")
    }
    guard let requestURL = urlSchemeTask.request.url else {
      sendError("Invalid application URL", status: 400, to: urlSchemeTask)
      return
    }

    do {
      let response: (Data, String, Int, [String: String])
      switch requestURL.path {
      case "", "/", "/index.html":
        response = (try Data(contentsOf: indexURL), "text/html; charset=utf-8", 200, [:])
      case "/api/health":
        response = (try healthResponse(), "application/json; charset=utf-8", 200, [:])
      case "/api/debugger":
        let debuggerResponse = try debuggerUnavailableResponse(
          ifNoneMatch: urlSchemeTask.request.value(forHTTPHeaderField: "If-None-Match")
        )
        response = (
          debuggerResponse.0,
          "application/json; charset=utf-8",
          debuggerResponse.1,
          debuggerResponse.2
        )
      case "/api/events":
        response = (try eventsResponse(for: requestURL), "application/json; charset=utf-8", 200, [:])
      case "/api/origin-trace":
        response = (try originTraceResponse(for: requestURL), "application/json; charset=utf-8", 200, [:])
      case "/api/request-signal-profile":
        let profileResponse = try requestSignalProfileResponse(
          for: requestURL,
          ifNoneMatch: urlSchemeTask.request.value(forHTTPHeaderField: "If-None-Match")
        )
        response = (
          profileResponse.0,
          "application/json; charset=utf-8",
          profileResponse.1,
          profileResponse.2
        )
      case "/api/artifacts":
        response = (try artifactsResponse(for: requestURL), "application/json; charset=utf-8", 200, [:])
      case "/api/analysis/vm":
        response = (try vmAnalysisResponse(for: requestURL), "application/json; charset=utf-8", 200, [:])
      default:
        if requestURL.path.hasPrefix("/api/artifacts/") && requestURL.path.hasSuffix("/content") {
          let content = try artifactContentResponse(for: requestURL)
          response = (content.0, "application/octet-stream", 200, content.1)
        } else {
          sendError("Application resource not found", status: 404, to: urlSchemeTask)
          return
        }
      }
      send(
        response.0,
        contentType: response.1,
        status: response.2,
        headers: response.3,
        to: urlSchemeTask
      )
    } catch let error as LocalHTTPError {
      sendError(error.message, status: error.status, to: urlSchemeTask)
    } catch {
      sendError(error.localizedDescription, status: 500, to: urlSchemeTask)
    }
  }

  func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}

  private func healthResponse() throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "status": "ok",
        "store": eventStoreURL.path,
        "store_exists": FileManager.default.fileExists(atPath: eventStoreURL.path),
        "trace_store": traceStoreURL.path,
        "trace_store_exists": FileManager.default.fileExists(atPath: traceStoreURL.path),
        "signal_store": signalStoreURL.path,
        "signal_store_exists": FileManager.default.fileExists(atPath: signalStoreURL.path),
        "artifact_store": artifactStoreURL.path,
        "artifact_store_exists": FileManager.default.fileExists(atPath: artifactStoreURL.path),
        "broker_connected": brokerConnected(),
      ],
      options: []
    )
  }

  private func debuggerUnavailableResponse(
    ifNoneMatch: String?
  ) throws -> (Data, Int, [String: String]) {
    let etag = "\"debugger-unavailable-v1\""
    if ifNoneMatch == etag {
      return (Data(), 304, ["ETag": etag])
    }
    let body = try JSONSerialization.data(
      withJSONObject: [
        "protocol_version": 1,
        "state": "unavailable",
        "generation": 0,
        "error": NSNull(),
        "target": NSNull(),
        "targets": [],
        "scripts": [],
        "paused": NSNull(),
        "breakpoints": [],
        "watches": [],
        "console": [],
        "settings": [
          "breakpoints_active": true,
          "pause_on_exceptions": "none",
          "xhr_breakpoints": [],
          "event_breakpoints": [],
        ],
        "limits": [
          "scripts": 5_000,
          "call_frames": 64,
          "scope_properties": 2_000,
          "console_entries": 500,
          "source_bytes": 2 * 1_024 * 1_024,
        ],
      ],
      options: []
    )
    return (body, 200, ["ETag": etag])
  }

  private func eventsResponse(for requestURL: URL) throws -> Data {
    let requestedLimit = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?
      .queryItems?
      .first(where: { $0.name == "limit" })?
      .value
      .flatMap(Int.init) ?? 500
    let limit = min(max(requestedLimit, 1), 5000)

    guard FileManager.default.fileExists(atPath: eventStoreURL.path) else {
      return try JSONSerialization.data(
        withJSONObject: ["count": 0, "events": [], "broker_connected": brokerConnected()],
        options: []
      )
    }

    let contents = try String(contentsOf: eventStoreURL, encoding: .utf8)
    let lines = contents.split(whereSeparator: \Character.isNewline).suffix(limit)
    var events: [[String: Any]] = []
    events.reserveCapacity(lines.count)
    for line in lines {
      let value = try JSONSerialization.jsonObject(with: Data(line.utf8), options: [])
      guard let event = value as? [String: Any] else {
        throw NSError(
          domain: "OriginTrace",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "The evidence store contains a malformed event"]
        )
      }
      events.append(event)
    }
    return try JSONSerialization.data(
      withJSONObject: [
        "count": events.count,
        "events": events,
        "broker_connected": brokerConnected(),
      ],
      options: []
    )
  }

  private func artifactEntries() throws -> [[String: Any]] {
    let manifestURL = artifactStoreURL.appendingPathComponent("manifest.jsonl")
    guard FileManager.default.fileExists(atPath: manifestURL.path) else {
      return []
    }
    let contents = try String(contentsOf: manifestURL, encoding: .utf8)
    var artifacts: [[String: Any]] = []
    var artifactIDs = Set<String>()
    for line in contents.split(whereSeparator: \Character.isNewline) {
      let value = try JSONSerialization.jsonObject(with: Data(line.utf8), options: [])
      guard let artifact = value as? [String: Any], isValidArtifact(artifact) else {
        throw artifactError("The artifact manifest contains a malformed record")
      }
      guard let artifactID = artifact["artifact_id"] as? String,
        artifactIDs.insert(artifactID).inserted
      else {
        throw artifactError("The artifact manifest contains a duplicate artifact ID")
      }
      artifacts.append(artifact)
    }
    return artifacts
  }

  private func isValidArtifact(_ artifact: [String: Any]) -> Bool {
    guard let protocolVersion = artifact["protocol_version"] as? NSNumber,
      CFGetTypeID(protocolVersion) != CFBooleanGetTypeID(),
      protocolVersion.stringValue == "1",
      let kind = artifact["kind"] as? String,
      Set(["javascript", "wasm", "source_map", "response_body"]).contains(kind),
      let url = artifact["url"] as? String,
      !url.isEmpty,
      let mimeType = artifact["mime_type"] as? String,
      !mimeType.isEmpty,
      let byteSize = artifact["byte_size"] as? NSNumber,
      CFGetTypeID(byteSize) != CFBooleanGetTypeID(),
      byteSize.stringValue.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      Int(byteSize.stringValue) != nil,
      let sha256 = artifact["sha256"] as? String,
      sha256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
      let sensitive = artifact["sensitive"] as? Bool,
      sensitive == (kind == "response_body"),
      artifact["content_path"] as? String == "blobs/\(sha256).bin"
    else {
      return false
    }
    return [
      "artifact_id", "session_id", "navigation_id", "frame_id", "parent_artifact_id",
      "creator_event_id",
    ].allSatisfy { field in
      guard let value = artifact[field] as? String,
        value.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil
      else {
        return false
      }
      return UInt64(value) != nil
    }
  }

  private func artifactError(_ message: String) -> NSError {
    NSError(
      domain: "OriginTrace",
      code: 3,
      userInfo: [NSLocalizedDescriptionKey: message]
    )
  }

  private func artifactsResponse(for requestURL: URL) throws -> Data {
    let requestedLimit = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?
      .queryItems?
      .first(where: { $0.name == "limit" })?
      .value
      .flatMap(Int.init) ?? 500
    let limit = min(max(requestedLimit, 1), 5000)
    let privateFields = Set(["content_path"])
    let artifacts = try artifactEntries().suffix(limit).map { artifact in
      artifact.filter { !privateFields.contains($0.key) }
    }
    return try JSONSerialization.data(
      withJSONObject: ["count": artifacts.count, "artifacts": artifacts],
      options: []
    )
  }

  private func artifactContentResponse(for requestURL: URL) throws -> (Data, [String: String]) {
    let components = requestURL.path.split(separator: "/")
    guard components.count == 4,
      components[0] == "api",
      components[1] == "artifacts",
      components[3] == "content"
    else {
      throw NSError(
        domain: "OriginTrace",
        code: 4,
        userInfo: [NSLocalizedDescriptionKey: "Invalid artifact content path"]
      )
    }
    let artifactID = String(components[2])
    guard artifactID.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      let artifact = try artifactEntries().first(where: { ($0["artifact_id"] as? String) == artifactID }),
      let relativePath = artifact["content_path"] as? String,
      let byteSize = artifact["byte_size"] as? Int,
      byteSize >= 0
    else {
      throw NSError(
        domain: "OriginTrace",
        code: 5,
        userInfo: [NSLocalizedDescriptionKey: "Artifact not found"]
      )
    }

    let root = artifactStoreURL.resolvingSymlinksInPath().standardizedFileURL
    let contentURL = root.appendingPathComponent(relativePath).resolvingSymlinksInPath().standardizedFileURL
    guard contentURL.path.hasPrefix(root.path + "/") else {
      throw NSError(
        domain: "OriginTrace",
        code: 6,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content path escapes the artifact store"]
      )
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: contentURL.path)
    guard let storedSize = attributes[.size] as? NSNumber, storedSize.intValue == byteSize else {
      throw NSError(
        domain: "OriginTrace",
        code: 7,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content does not match its manifest"]
      )
    }

    let query = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
    let requestedOffset = query.first(where: { $0.name == "offset" })?.value.flatMap(Int.init) ?? 0
    let requestedLimit = query.first(where: { $0.name == "limit" })?.value.flatMap(Int.init) ?? 2 * 1024 * 1024
    let offset = max(0, requestedOffset)
    let limit = min(max(requestedLimit, 1), 2 * 1024 * 1024)
    guard offset <= byteSize else {
      throw NSError(
        domain: "OriginTrace",
        code: 8,
        userInfo: [NSLocalizedDescriptionKey: "Artifact content offset exceeds byte size"]
      )
    }
    let handle = try FileHandle(forReadingFrom: contentURL)
    defer { try? handle.close() }
    try handle.seek(toOffset: UInt64(offset))
    let data = try handle.read(upToCount: limit) ?? Data()
    return (
      data,
      [
        "Content-Security-Policy": "sandbox",
        "Content-Disposition": "attachment; filename=artifact.bin",
        "X-Content-Type-Options": "nosniff",
        "X-Artifact-Total-Bytes": String(byteSize),
        "X-Artifact-Offset": String(offset),
        "X-Artifact-Truncated": offset + data.count < byteSize ? "1" : "0",
      ]
    )
  }

  private func vmAnalysisResponse(for requestURL: URL) throws -> Data {
    let analysisURL = artifactStoreURL
      .appendingPathComponent("analysis")
      .appendingPathComponent("vm-analysis-v1.json")
    let data = try Data(contentsOf: analysisURL)
    guard var document = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      (document["contract_version"] as? NSNumber)?.intValue == 1,
      document["document_kind"] as? String == "vm-analysis",
      var results = document["results"] as? [[String: Any]],
      var mixedFindings = document["mixed_findings"] as? [[String: Any]]
    else {
      throw artifactError("The VM analysis store contains a malformed document")
    }
    let requestID = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?
      .queryItems?
      .first(where: { $0.name == "request_id" })?
      .value
    if let requestID {
      guard requestID.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
        UInt64(requestID) != nil
      else {
        throw artifactError("Request ID must be a canonical unsigned 64-bit integer")
      }
      results = results.filter { result in
        (result["related_request_ids"] as? [String])?.contains(requestID) == true
      }
      let visibleArtifactIDs = Set(results.compactMap { $0["artifact_id"] as? String })
      mixedFindings = mixedFindings.filter { finding in
        guard let artifactIDs = finding["artifact_ids"] as? [String] else { return false }
        return !visibleArtifactIDs.isDisjoint(with: artifactIDs)
      }
      document["selection"] = [
        "kind": "request",
        "request_id": requestID,
        "edge_semantics": "correlated-not-causal",
      ]
    }
    document["results"] = results
    document["mixed_findings"] = mixedFindings
    return try JSONSerialization.data(withJSONObject: document, options: [])
  }

  private func originTraceResponse(for requestURL: URL) throws -> Data {
    let items = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
    guard let requestID = items.first(where: { $0.name == "request_id" })?.value,
      requestID.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      UInt64(requestID) != nil
    else {
      throw artifactError("Request ID must be a canonical unsigned 64-bit integer")
    }
    let processText = items.first(where: { $0.name == "root_process_id" })?.value
    let rootSequence = items.first(where: { $0.name == "root_sequence_number" })?.value
    let rootProcessID: UInt32?
    if let processText {
      guard processText.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
        let value = UInt32(processText)
      else {
        throw artifactError("Root process ID must be a canonical unsigned 32-bit integer")
      }
      rootProcessID = value
    } else {
      rootProcessID = nil
    }

    let events = try recentJSONObjects(
      at: eventStoreURL,
      limit: 10_000,
      maxRecordBytes: 4 * 1024,
      recordName: "event"
    )
    let edges = try recentJSONObjects(
      at: traceStoreURL,
      limit: 30_000,
      maxRecordBytes: 2 * 1024,
      recordName: "origin trace edge"
    )
    let document = try OriginTraceDocumentBuilder.build(
      events: events,
      edges: edges,
      artifacts: recentArtifactEntries(),
      requestID: requestID,
      rootProcessID: rootProcessID,
      rootSequenceNumber: rootSequence
    )
    return try JSONSerialization.data(withJSONObject: document, options: [])
  }

  private func requestSignalProfileResponse(
    for requestURL: URL,
    ifNoneMatch: String?
  ) throws -> (Data, Int, [String: String]) {
    let items = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
    guard let sessionID = items.first(where: { $0.name == "session_id" })?.value,
      isCanonicalUInt64(sessionID, nonzero: true),
      let requestID = items.first(where: { $0.name == "request_id" })?.value,
      isCanonicalUInt64(requestID, nonzero: true),
      let processText = items.first(where: { $0.name == "root_process_id" })?.value,
      processText.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      let processID = UInt32(processText),
      let sequenceNumber = items.first(where: { $0.name == "root_sequence_number" })?.value,
      isCanonicalUInt64(sequenceNumber, nonzero: true)
    else {
      throw LocalHTTPError(
        status: 400,
        message: "Complete canonical request signal profile identity is required"
      )
    }
    let etag = resourceETag(
      at: signalStoreURL,
      state: "\(sessionID):\(requestID):\(processID):\(sequenceNumber)"
    )
    if ifNoneMatch == etag {
      return (Data(), 304, ["ETag": etag])
    }
    let profiles = try recentJSONObjects(
      at: signalStoreURL,
      limit: 10_000,
      maxRecordBytes: 8 * 1024,
      recordName: "request signal profile"
    )
    guard profiles.allSatisfy(isValidRequestSignalProfile) else {
      throw artifactError("The request signal profile store contains a malformed record")
    }
    guard let document = profiles.reversed().first(where: { profile in
      guard let root = profile["root_event"] as? [String: Any],
        let rootProcessID = root["process_id"] as? NSNumber,
        CFGetTypeID(rootProcessID) != CFBooleanGetTypeID()
      else { return false }
      return profile["session_id"] as? String == sessionID
        && profile["request_id"] as? String == requestID
        && rootProcessID.stringValue == String(processID)
        && root["sequence_number"] as? String == sequenceNumber
    }) else {
      let body = try JSONSerialization.data(
        withJSONObject: [
          "error": "No request signal profile matches the selected request"
        ],
        options: []
      )
      return (body, 404, ["ETag": etag])
    }
    let body = try JSONSerialization.data(withJSONObject: document, options: [])
    return (body, 200, ["ETag": etag])
  }

  private func resourceETag(at url: URL, state: String) -> String {
    guard
      let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
      let size = attributes[.size] as? NSNumber,
      let modified = attributes[.modificationDate] as? Date
    else {
      return "\"missing-\(state)\""
    }
    let fileNumber = (attributes[.systemFileNumber] as? NSNumber)?.uint64Value ?? 0
    return "\"\(fileNumber)-\(size.uint64Value)-\(modified.timeIntervalSince1970.bitPattern)-\(state)\""
  }

  private func isCanonicalUInt64(_ value: String, nonzero: Bool = false) -> Bool {
    guard value.range(of: #"^(?:0|[1-9][0-9]*)$"#, options: .regularExpression) != nil,
      let parsed = UInt64(value)
    else { return false }
    return !nonzero || parsed != 0
  }

  private func isSignalEventReference(_ value: Any?) -> Bool {
    guard let reference = value as? [String: Any],
      Set(reference.keys) == Set(["process_id", "sequence_number"]),
      let processID = reference["process_id"] as? NSNumber,
      CFGetTypeID(processID) != CFBooleanGetTypeID(),
      processID.stringValue.range(
        of: #"^(?:0|[1-9][0-9]*)$"#,
        options: .regularExpression
      ) != nil,
      UInt32(processID.stringValue) != nil,
      let sequenceNumber = reference["sequence_number"] as? String
    else { return false }
    return isCanonicalUInt64(sequenceNumber, nonzero: true)
  }

  private func isValidRequestSignalProfile(_ profile: [String: Any]) -> Bool {
    let expectedKeys = Set([
      "protocol_version", "document_kind", "session_id", "request_id", "root_event",
      "initiator_event", "navigation_id", "frame_id", "signals", "coverage",
    ])
    let categories = Set([
      "canvas", "webgl", "web_audio", "navigator", "permissions", "storage", "webrtc",
    ])
    guard Set(profile.keys) == expectedKeys,
      let protocolVersion = profile["protocol_version"] as? NSNumber,
      CFGetTypeID(protocolVersion) != CFBooleanGetTypeID(),
      protocolVersion.stringValue == "1",
      profile["document_kind"] as? String == "request-signal-profile",
      let sessionID = profile["session_id"] as? String,
      isCanonicalUInt64(sessionID, nonzero: true),
      let requestID = profile["request_id"] as? String,
      isCanonicalUInt64(requestID, nonzero: true),
      let navigationID = profile["navigation_id"] as? String,
      isCanonicalUInt64(navigationID),
      let frameID = profile["frame_id"] as? String,
      isCanonicalUInt64(frameID),
      isSignalEventReference(profile["root_event"]),
      profile["initiator_event"] is NSNull || isSignalEventReference(profile["initiator_event"]),
      let signals = profile["signals"] as? [[String: Any]],
      signals.count <= categories.count,
      let coverage = profile["coverage"] as? [String: Any]
    else { return false }

    var seenCategories = Set<String>()
    guard let rootEvent = profile["root_event"] as? [String: Any],
      let rootProcessID = rootEvent["process_id"] as? NSNumber
    else { return false }
    let expectedProcessID: String
    if let initiator = profile["initiator_event"] as? [String: Any],
      let initiatorProcessID = initiator["process_id"] as? NSNumber
    {
      expectedProcessID = initiatorProcessID.stringValue
    } else {
      expectedProcessID = rootProcessID.stringValue
    }
    var hasSaturatedCount = false
    for signal in signals {
      let expectedSignalKeys = Set([
        "category", "relation", "confidence", "event_count", "first_event", "last_event",
      ])
      guard Set(signal.keys) == expectedSignalKeys,
        let category = signal["category"] as? String,
        categories.contains(category),
        seenCategories.insert(category).inserted,
        let relation = signal["relation"] as? String,
        Set(["parent_chain", "same_context"]).contains(relation),
        signal["confidence"] as? String == (relation == "parent_chain" ? "observed" : "correlated"),
        let eventCount = signal["event_count"] as? String,
        isCanonicalUInt64(eventCount, nonzero: true),
        isSignalEventReference(signal["first_event"]),
        isSignalEventReference(signal["last_event"]),
        let firstEvent = signal["first_event"] as? [String: Any],
        let firstProcessID = firstEvent["process_id"] as? NSNumber,
        firstProcessID.stringValue == expectedProcessID,
        let lastEvent = signal["last_event"] as? [String: Any],
        let lastProcessID = lastEvent["process_id"] as? NSNumber,
        lastProcessID.stringValue == expectedProcessID
      else { return false }
      hasSaturatedCount = hasSaturatedCount || eventCount == String(UInt64.max)
    }

    let expectedCoverageKeys = Set([
      "parent_depth", "parent_depth_limit", "copied_from_initiator", "retention_truncated",
      "parent_depth_limited", "count_saturated",
    ])
    guard Set(coverage.keys) == expectedCoverageKeys,
      let parentDepth = coverage["parent_depth"] as? NSNumber,
      CFGetTypeID(parentDepth) != CFBooleanGetTypeID(),
      parentDepth.stringValue.range(
        of: #"^(?:0|[1-9][0-9]*)$"#,
        options: .regularExpression
      ) != nil,
      let parsedParentDepth = Int(parentDepth.stringValue),
      parsedParentDepth <= 32,
      let parentDepthLimit = coverage["parent_depth_limit"] as? NSNumber,
      CFGetTypeID(parentDepthLimit) != CFBooleanGetTypeID(),
      parentDepthLimit.stringValue == "32",
      let copied = coverage["copied_from_initiator"] as? Bool,
      coverage["retention_truncated"] is Bool,
      let parentDepthLimited = coverage["parent_depth_limited"] as? Bool,
      let countSaturated = coverage["count_saturated"] as? Bool,
      copied == !(profile["initiator_event"] is NSNull),
      !countSaturated || hasSaturatedCount,
      !parentDepthLimited || parsedParentDepth == 32
    else { return false }
    return true
  }

  private func recentArtifactEntries() throws -> [[String: Any]] {
    let artifacts = try recentJSONObjects(
      at: artifactStoreURL.appendingPathComponent("manifest.jsonl"),
      limit: 10_000,
      maxRecordBytes: 8 * 1024,
      recordName: "artifact"
    )
    guard artifacts.allSatisfy(isValidArtifact) else {
      throw artifactError("The artifact manifest contains a malformed record")
    }
    let identifiers = artifacts.compactMap { $0["artifact_id"] as? String }
    guard identifiers.count == artifacts.count, Set(identifiers).count == identifiers.count else {
      throw artifactError("The artifact manifest contains a duplicate artifact ID")
    }
    return artifacts
  }

  private func recentJSONObjects(
    at url: URL,
    limit: Int,
    maxRecordBytes: Int,
    recordName: String
  ) throws -> [[String: Any]] {
    guard FileManager.default.fileExists(atPath: url.path), limit > 0 else { return [] }
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard let fileSize = (attributes[.size] as? NSNumber)?.uint64Value else {
      throw artifactError("The evidence store size is unavailable")
    }

    var position = fileSize
    var suffix = Data()
    var lines: [Data] = []
    let chunkBytes = UInt64(64 * 1024)
    while position > 0 && lines.count < limit {
      let count = min(position, chunkBytes)
      position -= count
      try handle.seek(toOffset: position)
      guard var block = try handle.read(upToCount: Int(count)) else { break }
      block.append(suffix)
      let parts = block.split(separator: 10, omittingEmptySubsequences: false)
      for part in parts.dropFirst().reversed() where !isBlank(part) {
        guard part.count <= maxRecordBytes else {
          throw artifactError("The evidence store contains an oversized \(recordName)")
        }
        lines.append(Data(part))
        if lines.count == limit { break }
      }
      suffix = parts.first.map { Data($0) } ?? Data()
      if suffix.count > maxRecordBytes {
        throw artifactError("The evidence store contains an oversized \(recordName)")
      }
    }
    if position == 0 && lines.count < limit && !isBlank(suffix) {
      lines.append(suffix)
    }
    lines.reverse()
    return try lines.map { line in
      let value = try JSONSerialization.jsonObject(with: line, options: [])
      guard let object = value as? [String: Any] else {
        throw artifactError("The evidence store contains a malformed \(recordName)")
      }
      return object
    }
  }

  private func isBlank<T: DataProtocol>(_ data: T) -> Bool {
    data.allSatisfy { byte in byte == 9 || byte == 10 || byte == 13 || byte == 32 }
  }

  private func brokerConnected() -> Bool {
    guard let brokerSocketURL else { return true }
    guard
      let attributes = try? FileManager.default.attributesOfItem(atPath: brokerSocketURL.path),
      let type = attributes[.type] as? FileAttributeType
    else { return false }
    return type == .typeSocket
  }

  private func sendError(_ message: String, status: Int, to task: WKURLSchemeTask) {
    let body = (try? JSONSerialization.data(withJSONObject: ["error": message], options: []))
      ?? Data("{\"error\":\"Application error\"}".utf8)
    send(body, contentType: "application/json; charset=utf-8", status: status, headers: [:], to: task)
  }

  private func send(
    _ body: Data,
    contentType: String,
    status: Int,
    headers: [String: String],
    to task: WKURLSchemeTask
  ) {
    guard let requestURL = task.request.url,
      let response = HTTPURLResponse(
        url: requestURL,
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: [
          "Content-Type": contentType,
          "Content-Length": String(body.count),
          "Cache-Control": "no-store",
        ].merging(headers) { _, requested in requested }
      )
    else {
      task.didFailWithError(
        NSError(
          domain: "OriginTrace",
          code: 2,
          userInfo: [NSLocalizedDescriptionKey: "Could not create an application response"]
        )
      )
      return
    }
    task.didReceive(response)
    task.didReceive(body)
    task.didFinish()
  }
}

private final class OriginTraceApp: NSObject, NSApplicationDelegate, WKNavigationDelegate {
  private var window: NSWindow?
  private var contentHandler: LocalContentHandler?
  private let smokeTest = ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1"

  func applicationDidFinishLaunching(_ notification: Notification) {
    if smokeTest {
      print("SMOKE_LAUNCH")
    }
    guard let resourcesURL = Bundle.main.resourceURL else {
      presentFatalError("Application resources are missing")
      return
    }

    configureApplicationMenu()
    configureApplicationIcon(resourcesURL: resourcesURL)

    let indexURL = resourcesURL.appendingPathComponent("index.html")
    let eventStoreURL = configuredEventStore(resourcesURL: resourcesURL)
    let traceStoreURL = configuredTraceStore(eventStoreURL: eventStoreURL)
    let signalStoreURL = configuredSignalStore(eventStoreURL: eventStoreURL)
    let artifactStoreURL = configuredArtifactStore(eventStoreURL: eventStoreURL)
    let handler = LocalContentHandler(
      indexURL: indexURL,
      eventStoreURL: eventStoreURL,
      traceStoreURL: traceStoreURL,
      signalStoreURL: signalStoreURL,
      artifactStoreURL: artifactStoreURL,
      brokerSocketURL: configuredBrokerSocket()
    )
    contentHandler = handler

    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    configuration.setURLSchemeHandler(handler, forURLScheme: "reb")

    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = self
    webView.setValue(false, forKey: "drawsBackground")

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 1180, height: 790),
      styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
      backing: .buffered,
      defer: false
    )
    window.title = "Origin Trace"
    window.titleVisibility = .hidden
    window.titlebarAppearsTransparent = true
    window.isMovableByWindowBackground = true
    window.minSize = NSSize(width: 760, height: 560)
    window.contentView = webView
    window.center()
    window.makeKeyAndOrderFront(nil)
    self.window = window

    NSApp.setActivationPolicy(.regular)
    if !smokeTest {
      NSApp.activate(ignoringOtherApps: true)
    }
    let localApplicationURL = URL(string: "reb://app/index.html?native=1")!
    let requestedUIURL = configuredUIURL()
    if CommandLine.arguments.contains("--ui-url"), requestedUIURL == nil {
      presentFatalError("The live UI URL must be an explicit loopback HTTP address")
      return
    }
    webView.load(URLRequest(url: requestedUIURL ?? localApplicationURL))
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    true
  }

  func webView(
    _ webView: WKWebView,
    didFailProvisionalNavigation navigation: WKNavigation!,
    withError error: Error
  ) {
    presentFatalError(error.localizedDescription)
  }

  private func configuredEventStore(resourcesURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--store"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_EVENT_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return resourcesURL.appendingPathComponent("demo.jsonl")
  }

  private func configuredArtifactStore(eventStoreURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--artifacts"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_ARTIFACT_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return eventStoreURL.deletingLastPathComponent().appendingPathComponent("artifacts")
  }

  private func configuredTraceStore(eventStoreURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--trace-store"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_ORIGIN_TRACE_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return eventStoreURL.deletingLastPathComponent().appendingPathComponent("origin-trace.jsonl")
  }

  private func configuredSignalStore(eventStoreURL: URL) -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--signal-store"), storeFlag + 1 < arguments.count {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_REQUEST_SIGNAL_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return eventStoreURL.deletingLastPathComponent().appendingPathComponent("request-signals.jsonl")
  }

  private func configuredBrokerSocket() -> URL? {
    let arguments = CommandLine.arguments
    if let socketFlag = arguments.firstIndex(of: "--broker-socket"),
      socketFlag + 1 < arguments.count
    {
      return URL(fileURLWithPath: arguments[socketFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_BROKER_SOCKET"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    return nil
  }

  private func configuredUIURL() -> URL? {
    let arguments = CommandLine.arguments
    guard let urlFlag = arguments.firstIndex(of: "--ui-url"), urlFlag + 1 < arguments.count,
      let url = URL(string: arguments[urlFlag + 1]),
      let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
      components.scheme == "http",
      Set(["127.0.0.1", "localhost", "::1"]).contains(components.host ?? ""),
      components.port != nil,
      components.user == nil,
      components.password == nil,
      components.fragment == nil
    else {
      return nil
    }
    return url
  }

  private func configureApplicationMenu() {
    let mainMenu = NSMenu()

    let applicationMenuItem = NSMenuItem()
    let applicationMenu = NSMenu(title: "Origin Trace")
    applicationMenu.addItem(
      withTitle: "About Origin Trace",
      action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
      keyEquivalent: ""
    )
    applicationMenu.addItem(.separator())
    applicationMenu.addItem(
      withTitle: "Hide Origin Trace",
      action: #selector(NSApplication.hide(_:)),
      keyEquivalent: "h"
    )
    applicationMenu.addItem(.separator())
    applicationMenu.addItem(
      withTitle: "Quit Origin Trace",
      action: #selector(NSApplication.terminate(_:)),
      keyEquivalent: "q"
    )
    applicationMenuItem.submenu = applicationMenu
    mainMenu.addItem(applicationMenuItem)

    let editMenuItem = NSMenuItem()
    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.addItem(.separator())
    editMenu.addItem(
      withTitle: "Select All",
      action: #selector(NSText.selectAll(_:)),
      keyEquivalent: "a"
    )
    editMenuItem.submenu = editMenu
    mainMenu.addItem(editMenuItem)

    let windowMenuItem = NSMenuItem()
    let windowMenu = NSMenu(title: "Window")
    windowMenu.addItem(
      withTitle: "Minimize",
      action: #selector(NSWindow.performMiniaturize(_:)),
      keyEquivalent: "m"
    )
    windowMenu.addItem(
      withTitle: "Zoom",
      action: #selector(NSWindow.performZoom(_:)),
      keyEquivalent: ""
    )
    windowMenuItem.submenu = windowMenu
    mainMenu.addItem(windowMenuItem)
    NSApp.windowsMenu = windowMenu
    NSApp.mainMenu = mainMenu
  }

  private func configureApplicationIcon(resourcesURL: URL) {
    let iconURL = resourcesURL.appendingPathComponent("OriginTrace.icns")
    guard let icon = NSImage(contentsOf: iconURL) else {
      return
    }
    NSApp.applicationIconImage = icon
  }

  private func presentFatalError(_ message: String) {
    let alert = NSAlert()
    alert.alertStyle = .critical
    alert.messageText = "Origin Trace could not start"
    alert.informativeText = message
    alert.runModal()
    NSApp.terminate(nil)
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    guard smokeTest else { return }
    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
      let exercise = """
        [...document.querySelectorAll('.request-row')]
          .find(row => row.textContent.includes('live'))?.click();
        document.querySelector('#trace-origin')?.click();
        """
      webView.evaluateJavaScript(exercise) { _, exerciseError in
        if let exerciseError {
          print("SMOKE_ERROR \(exerciseError.localizedDescription)")
          NSApp.terminate(nil)
          return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
          let inspection = """
            JSON.stringify({
              title: document.title,
              nativeShell: document.documentElement.classList.contains('native-shell'),
              requests: document.querySelectorAll('.request-row').length,
              fields: document.querySelectorAll('.field-row').length,
              artifacts: document.querySelectorAll('.source-tree-row[data-artifact-id]').length,
              sourceLines: document.querySelectorAll('.source-line').length,
              broker: document.querySelector('#broker-status')?.textContent,
              debuggerState: document.querySelector('#debug-state strong')?.textContent,
              traceEnabled: !document.querySelector('#trace-origin')?.disabled,
              traceSteps: document.querySelectorAll('#backtrace-steps .trace-step').length,
              traceCoverage: document.querySelector('#coverage-value')?.textContent,
              traceReachedCanvas: [...document.querySelectorAll('.step-title')]
                .some(step => step.textContent === 'canvas · api_call'),
              viewport: [window.innerWidth, window.innerHeight, window.devicePixelRatio],
              trafficColumns: getComputedStyle(document.querySelector('.traffic-grid')).gridTemplateColumns
            })
            """
          webView.evaluateJavaScript(inspection) { result, error in
            if let error {
              print("SMOKE_ERROR \(error.localizedDescription)")
            } else {
              print("SMOKE_OK \(result ?? "no result")")
            }
            NSApp.terminate(nil)
          }
        }
      }
    }
  }
}

@main
private enum OriginTraceMain {
  static func main() {
    let application = NSApplication.shared
    let delegate = OriginTraceApp()
    application.delegate = delegate
    application.run()
  }
}
