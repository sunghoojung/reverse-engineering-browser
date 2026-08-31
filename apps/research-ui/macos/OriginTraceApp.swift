import Cocoa
import CoreFoundation
import Darwin
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
  private let apiCollectionStoreURL: URL
  private let brokerSocketURL: URL?
  private let apiCollectionLock = NSLock()

  init(
    indexURL: URL,
    eventStoreURL: URL,
    traceStoreURL: URL,
    signalStoreURL: URL,
    artifactStoreURL: URL,
    apiCollectionStoreURL: URL,
    brokerSocketURL: URL?
  ) {
    self.indexURL = indexURL
    self.eventStoreURL = eventStoreURL
    self.traceStoreURL = traceStoreURL
    self.signalStoreURL = signalStoreURL
    self.artifactStoreURL = artifactStoreURL
    self.apiCollectionStoreURL = apiCollectionStoreURL
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
      case "/api/api-collection":
        guard urlSchemeTask.request.httpMethod == nil || urlSchemeTask.request.httpMethod == "GET" else {
          throw LocalHTTPError(status: 405, message: "API Collection only supports GET on this route")
        }
        let collectionResponse = try apiCollectionResponse(
          ifNoneMatch: urlSchemeTask.request.value(forHTTPHeaderField: "If-None-Match")
        )
        response = (
          collectionResponse.0,
          "application/json; charset=utf-8",
          collectionResponse.1,
          collectionResponse.2
        )
      case "/api/api-collection/actions":
        guard urlSchemeTask.request.httpMethod == "POST" else {
          throw LocalHTTPError(status: 405, message: "API Collection actions require POST")
        }
        let collectionResponse = try replaceApiCollection(request: urlSchemeTask.request)
        response = (
          collectionResponse.0,
          "application/json; charset=utf-8",
          collectionResponse.1,
          collectionResponse.2
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
        "api_collection_store": apiCollectionStoreURL.path,
        "api_collection_store_exists": FileManager.default.fileExists(
          atPath: apiCollectionStoreURL.path
        ),
        "broker_connected": brokerConnected(),
      ],
      options: []
    )
  }

  private func apiCollectionLimits() -> [String: Int] {
    [
      "folders": 32,
      "requests": 128,
      "folder_depth": 4,
      "variables_per_scope": 32,
      "variable_bytes_per_scope": 32 * 1_024,
      "request_body_bytes": 64 * 1_024,
      "document_bytes": 2 * 1_024 * 1_024,
    ]
  }

  private func emptyApiCollection() -> [String: Any] {
    [
      "contract_version": 1,
      "document_kind": "api-collection",
      "generation": 0,
      "updated_at_ms": 0,
      "folders": [[
        "id": 1,
        "name": "API Collection",
        "parent_id": NSNull(),
        "variables": [],
      ]],
      "requests": [],
      "limits": apiCollectionLimits(),
    ]
  }

  private func apiCollectionExactKeys(_ value: [String: Any], _ keys: Set<String>) -> Bool {
    Set(value.keys) == keys
  }

  private func apiCollectionInteger(
    _ value: Any?,
    label: String,
    minimum: Int = 0
  ) throws -> Int {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.doubleValue.isFinite,
      number.doubleValue.rounded(.towardZero) == number.doubleValue,
      number.doubleValue >= Double(minimum),
      number.doubleValue <= 9_007_199_254_740_991
    else {
      throw LocalHTTPError(status: 400, message: "\(label) is invalid")
    }
    return number.intValue
  }

  private func apiCollectionText(
    _ value: Any?,
    label: String,
    maximumBytes: Int,
    allowEmpty: Bool = false,
    trim: Bool = false
  ) throws -> String {
    guard let raw = value as? String else {
      throw LocalHTTPError(status: 400, message: "\(label) must be text")
    }
    let result = trim ? raw.trimmingCharacters(in: .whitespacesAndNewlines) : raw
    let containsControls = result.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7f }
    guard (allowEmpty || !result.isEmpty), result.utf8.count <= maximumBytes, !containsControls
    else {
      throw LocalHTTPError(
        status: 400,
        message: "\(label) is empty, oversized, or contains controls"
      )
    }
    return result
  }

  private func normalizeApiCollectionVariables(_ value: Any?) throws -> [[String: Any]] {
    guard let values = value as? [[String: Any]], values.count <= 32 else {
      throw LocalHTTPError(status: 400, message: "API Collection variables are invalid")
    }
    var names = Set<String>()
    var totalBytes = 0
    var normalized: [[String: Any]] = []
    normalized.reserveCapacity(values.count)
    for variable in values {
      guard apiCollectionExactKeys(variable, ["name", "value"]) else {
        throw LocalHTTPError(status: 400, message: "API Collection variable shape is invalid")
      }
      let name = try apiCollectionText(
        variable["name"],
        label: "API Collection variable name",
        maximumBytes: 64
      )
      let variableValue = try apiCollectionText(
        variable["value"],
        label: "API Collection variable value",
        maximumBytes: 4 * 1_024,
        allowEmpty: true
      )
      guard name.range(of: #"^[A-Za-z_][A-Za-z0-9_.-]*$"#, options: .regularExpression) != nil,
        names.insert(name).inserted
      else {
        throw LocalHTTPError(
          status: 400,
          message: "API Collection variable name is invalid or duplicated"
        )
      }
      totalBytes += name.utf8.count + variableValue.utf8.count
      guard totalBytes <= 32 * 1_024 else {
        throw LocalHTTPError(status: 400, message: "API Collection variable scope exceeds 32 KiB")
      }
      normalized.append(["name": name, "value": variableValue])
    }
    return normalized.sorted { ($0["name"] as? String ?? "") < ($1["name"] as? String ?? "") }
  }

  private func normalizeApiCollectionHeaders(_ value: Any?) throws -> [[String: Any]] {
    guard let values = value as? [[String: Any]], values.count <= 64 else {
      throw LocalHTTPError(status: 400, message: "API Collection request headers are invalid")
    }
    let forbidden = Set([
      "authorization", "connection", "content-length", "cookie", "host",
      "proxy-authorization", "set-cookie", "transfer-encoding",
    ])
    var names = Set<String>()
    var totalBytes = 0
    var normalized: [[String: Any]] = []
    normalized.reserveCapacity(values.count)
    for header in values {
      guard apiCollectionExactKeys(header, ["name", "value"]) else {
        throw LocalHTTPError(status: 400, message: "API Collection request header shape is invalid")
      }
      let name = try apiCollectionText(
        header["name"],
        label: "API Collection request header name",
        maximumBytes: 128
      )
      let headerValue = try apiCollectionText(
        header["value"],
        label: "API Collection request header value",
        maximumBytes: 2 * 1_024,
        allowEmpty: true
      )
      let lowerName = name.lowercased()
      guard name.range(of: #"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"#, options: .regularExpression) != nil,
        !forbidden.contains(lowerName), names.insert(lowerName).inserted
      else {
        throw LocalHTTPError(status: 400, message: "API Collection request header is forbidden or invalid")
      }
      totalBytes += name.utf8.count + headerValue.utf8.count
      guard totalBytes <= 16 * 1_024 else {
        throw LocalHTTPError(status: 400, message: "API Collection request headers exceed 16 KiB")
      }
      normalized.append(["name": name, "value": headerValue])
    }
    return normalized
  }

  private func normalizeApiCollectionFolder(_ value: Any?) throws -> [String: Any] {
    guard let folder = value as? [String: Any],
      apiCollectionExactKeys(folder, ["id", "name", "parent_id", "variables"])
    else {
      throw LocalHTTPError(status: 400, message: "API Collection folder shape is invalid")
    }
    let identifier = try apiCollectionInteger(folder["id"], label: "API Collection folder ID", minimum: 1)
    let parent: Any
    if folder["parent_id"] is NSNull {
      parent = NSNull()
    } else {
      parent = try apiCollectionInteger(
        folder["parent_id"],
        label: "API Collection parent folder ID",
        minimum: 1
      )
    }
    let name = try apiCollectionText(
      folder["name"],
      label: "API Collection folder name",
      maximumBytes: 128,
      trim: true
    )
    guard !name.contains("/") else {
      throw LocalHTTPError(status: 400, message: "API Collection folder names cannot contain slashes")
    }
    return [
      "id": identifier,
      "name": name,
      "parent_id": parent,
      "variables": try normalizeApiCollectionVariables(folder["variables"]),
    ]
  }

  private func normalizeApiCollectionRequest(
    _ value: Any?,
    requireMetadata: Bool
  ) throws -> [String: Any] {
    guard let request = value as? [String: Any] else {
      throw LocalHTTPError(status: 400, message: "API Collection request shape is invalid")
    }
    var expected = Set([
      "id", "folder_id", "name", "url", "method", "headers", "body", "timeout_ms", "variables",
    ])
    if requireMetadata {
      expected.formUnion(["created_at_ms", "updated_at_ms"])
    }
    guard apiCollectionExactKeys(request, expected) else {
      throw LocalHTTPError(status: 400, message: "API Collection request shape is invalid")
    }
    let name = try apiCollectionText(
      request["name"],
      label: "API Collection request name",
      maximumBytes: 128,
      trim: true
    )
    guard !name.contains("/") else {
      throw LocalHTTPError(status: 400, message: "API Collection request names cannot contain slashes")
    }
    guard let body = request["body"] as? String, body.utf8.count <= 64 * 1_024 else {
      throw LocalHTTPError(status: 400, message: "API Collection request body exceeds 64 KiB")
    }
    let timeout = try apiCollectionInteger(
      request["timeout_ms"],
      label: "API Collection request timeout",
      minimum: 100
    )
    guard timeout <= 30_000 else {
      throw LocalHTTPError(status: 400, message: "API Collection request timeout exceeds 30 seconds")
    }
    var normalized: [String: Any] = [
      "id": try apiCollectionInteger(request["id"], label: "API Collection request ID", minimum: 1),
      "folder_id": try apiCollectionInteger(
        request["folder_id"],
        label: "API Collection request folder ID",
        minimum: 1
      ),
      "name": name,
      "url": try apiCollectionText(
        request["url"],
        label: "API Collection request URL template",
        maximumBytes: 8 * 1_024,
        trim: true
      ),
      "method": try apiCollectionText(
        request["method"],
        label: "API Collection request method template",
        maximumBytes: 256,
        trim: true
      ),
      "headers": try normalizeApiCollectionHeaders(request["headers"]),
      "body": body,
      "timeout_ms": timeout,
      "variables": try normalizeApiCollectionVariables(request["variables"]),
    ]
    if requireMetadata {
      let created = try apiCollectionInteger(
        request["created_at_ms"],
        label: "API Collection request creation time"
      )
      let updated = try apiCollectionInteger(
        request["updated_at_ms"],
        label: "API Collection request update time"
      )
      guard updated >= created else {
        throw LocalHTTPError(status: 400, message: "API Collection request timestamps are invalid")
      }
      normalized["created_at_ms"] = created
      normalized["updated_at_ms"] = updated
    }
    return normalized
  }

  private func normalizeApiCollection(_ value: Any?) throws -> [String: Any] {
    guard let collection = value as? [String: Any],
      apiCollectionExactKeys(
        collection,
        ["contract_version", "document_kind", "generation", "updated_at_ms", "folders", "requests", "limits"]
      ),
      try apiCollectionInteger(collection["contract_version"], label: "API Collection contract") == 1,
      collection["document_kind"] as? String == "api-collection",
      let limits = collection["limits"] as? [String: Any],
      NSDictionary(dictionary: limits).isEqual(to: apiCollectionLimits())
    else {
      throw LocalHTTPError(status: 400, message: "API Collection document contract is unsupported")
    }
    let generation = try apiCollectionInteger(collection["generation"], label: "API Collection generation")
    let updatedAt = try apiCollectionInteger(collection["updated_at_ms"], label: "API Collection update time")
    guard let rawFolders = collection["folders"] as? [Any], 1...32 ~= rawFolders.count,
      let rawRequests = collection["requests"] as? [Any], rawRequests.count <= 128
    else {
      throw LocalHTTPError(status: 400, message: "API Collection counts are invalid")
    }
    let folders = try rawFolders.map(normalizeApiCollectionFolder)
    let requests = try rawRequests.map { try normalizeApiCollectionRequest($0, requireMetadata: true) }
    var foldersByID: [Int: [String: Any]] = [:]
    for folder in folders {
      let identifier = folder["id"] as! Int
      guard foldersByID.updateValue(folder, forKey: identifier) == nil else {
        throw LocalHTTPError(status: 400, message: "API Collection folder IDs are duplicated")
      }
    }
    guard let root = foldersByID[1], root["name"] as? String == "API Collection",
      root["parent_id"] is NSNull,
      !folders.contains(where: { ($0["id"] as! Int) != 1 && $0["parent_id"] is NSNull })
    else {
      throw LocalHTTPError(status: 400, message: "API Collection root folder is invalid")
    }
    var siblingNames = Set<String>()
    for folder in folders {
      let identifier = folder["id"] as! Int
      let parent = folder["parent_id"] as? Int
      let siblingKey = "\(parent.map(String.init) ?? "root")\u{0}\((folder["name"] as! String).lowercased())"
      guard siblingNames.insert(siblingKey).inserted else {
        throw LocalHTTPError(status: 400, message: "API Collection folder name is duplicated")
      }
      var seen = Set([identifier])
      var current = folder
      var depth = 0
      while let parentID = current["parent_id"] as? Int {
        guard let parentFolder = foldersByID[parentID], seen.insert(parentID).inserted else {
          throw LocalHTTPError(status: 400, message: "API Collection folder hierarchy is invalid")
        }
        current = parentFolder
        depth += 1
        guard depth <= 4 else {
          throw LocalHTTPError(status: 400, message: "API Collection folder depth exceeds four levels")
        }
      }
    }
    var requestIDs = Set<Int>()
    var requestNames = Set<String>()
    for request in requests {
      let identifier = request["id"] as! Int
      let folderID = request["folder_id"] as! Int
      let nameKey = "\(folderID)\u{0}\((request["name"] as! String).lowercased())"
      guard requestIDs.insert(identifier).inserted, foldersByID[folderID] != nil,
        requestNames.insert(nameKey).inserted
      else {
        throw LocalHTTPError(status: 400, message: "API Collection request ID, folder, or name is invalid")
      }
    }
    let normalized: [String: Any] = [
      "contract_version": 1,
      "document_kind": "api-collection",
      "generation": generation,
      "updated_at_ms": updatedAt,
      "folders": folders.sorted { ($0["id"] as! Int) < ($1["id"] as! Int) },
      "requests": requests.sorted { ($0["id"] as! Int) < ($1["id"] as! Int) },
      "limits": apiCollectionLimits(),
    ]
    let encoded = try JSONSerialization.data(withJSONObject: normalized, options: [])
    guard encoded.count <= 2 * 1_024 * 1_024 else {
      throw LocalHTTPError(status: 400, message: "API Collection document exceeds 2 MiB")
    }
    if generation == 0 {
      guard updatedAt == 0, folders.count == 1,
        (root["variables"] as? [Any])?.isEmpty == true, requests.isEmpty
      else {
        throw LocalHTTPError(status: 400, message: "API Collection generation zero must be empty")
      }
    }
    return normalized
  }

  private func loadApiCollectionLocked() throws -> [String: Any] {
    let descriptor = Darwin.open(apiCollectionStoreURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    if descriptor < 0 {
      if errno == ENOENT { return emptyApiCollection() }
      throw LocalHTTPError(status: 500, message: "API Collection store could not be opened safely")
    }
    defer { Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_size <= 2 * 1_024 * 1_024
    else {
      throw LocalHTTPError(status: 500, message: "API Collection store must be a bounded regular file")
    }
    do {
      let maximumBytes = 2 * 1_024 * 1_024
      var data = Data()
      data.reserveCapacity(min(Int(metadata.st_size), maximumBytes))
      var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
      while data.count <= maximumBytes {
        let requested = min(buffer.count, maximumBytes + 1 - data.count)
        let count = Darwin.read(descriptor, &buffer, requested)
        if count < 0 {
          throw LocalHTTPError(status: 500, message: "API Collection store could not be read")
        }
        if count == 0 { break }
        data.append(buffer, count: count)
      }
      guard data.count <= maximumBytes else {
        throw LocalHTTPError(status: 500, message: "API Collection store exceeds 2 MiB")
      }
      return try normalizeApiCollection(JSONSerialization.jsonObject(with: data, options: []))
    } catch let error as LocalHTTPError where error.status == 500 {
      throw error
    } catch {
      throw LocalHTTPError(status: 500, message: "API Collection store is malformed")
    }
  }

  private func apiCollectionData(_ collection: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: collection, options: [])
  }

  private func apiCollectionResponse(ifNoneMatch: String?) throws -> (Data, Int, [String: String]) {
    apiCollectionLock.lock()
    defer { apiCollectionLock.unlock() }
    let collection = try loadApiCollectionLocked()
    let generation = collection["generation"] as! Int
    let etag = "\"api-collection-\(generation)\""
    if ifNoneMatch == etag {
      return (Data(), 304, ["ETag": etag])
    }
    return (try apiCollectionData(collection), 200, ["ETag": etag])
  }

  private func apiCollectionRequestBody(_ request: URLRequest) throws -> Data {
    if let body = request.httpBody {
      guard body.count <= 2 * 1_024 * 1_024 + 64 * 1_024 else {
        throw LocalHTTPError(status: 413, message: "API Collection action is oversized")
      }
      return body
    }
    guard let stream = request.httpBodyStream else {
      throw LocalHTTPError(status: 400, message: "API Collection action body is missing")
    }
    stream.open()
    defer { stream.close() }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
    while stream.hasBytesAvailable {
      let count = stream.read(&buffer, maxLength: buffer.count)
      if count < 0 {
        throw LocalHTTPError(status: 400, message: "API Collection action body could not be read")
      }
      if count == 0 { break }
      data.append(buffer, count: count)
      guard data.count <= 2 * 1_024 * 1_024 + 64 * 1_024 else {
        throw LocalHTTPError(status: 413, message: "API Collection action is oversized")
      }
    }
    return data
  }

  private func apiCollectionContent(_ collection: [String: Any]) -> [String: Any] {
    let requests = (collection["requests"] as? [[String: Any]] ?? []).map { request in
      request.filter { !["created_at_ms", "updated_at_ms"].contains($0.key) }
    }
    return ["folders": collection["folders"] ?? [], "requests": requests]
  }

  private func writeApiCollectionLocked(_ collection: [String: Any]) throws {
    let directory = apiCollectionStoreURL.deletingLastPathComponent()
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700]
    )
    var data = try apiCollectionData(collection)
    data.append(0x0a)
    guard data.count <= 2 * 1_024 * 1_024 else {
      throw LocalHTTPError(status: 400, message: "API Collection store exceeds 2 MiB")
    }
    try data.write(to: apiCollectionStoreURL, options: [.atomic])
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: apiCollectionStoreURL.path
    )
    let storedDescriptor = Darwin.open(
      apiCollectionStoreURL.path,
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    )
    guard storedDescriptor >= 0 else {
      throw LocalHTTPError(status: 500, message: "API Collection store could not be synchronized")
    }
    defer { Darwin.close(storedDescriptor) }
    guard Darwin.fsync(storedDescriptor) == 0 else {
      throw LocalHTTPError(status: 500, message: "API Collection store could not be synchronized")
    }
    let directoryDescriptor = Darwin.open(directory.path, O_RDONLY | O_CLOEXEC)
    if directoryDescriptor >= 0 {
      _ = Darwin.fsync(directoryDescriptor)
      Darwin.close(directoryDescriptor)
    }
  }

  private func replaceApiCollection(request: URLRequest) throws -> (Data, Int, [String: String]) {
    let body: Any
    do {
      body = try JSONSerialization.jsonObject(with: apiCollectionRequestBody(request), options: [])
    } catch let error as LocalHTTPError {
      throw error
    } catch {
      throw LocalHTTPError(status: 400, message: "API Collection action body is malformed")
    }
    guard let action = body as? [String: Any],
      apiCollectionExactKeys(action, ["action", "expected_generation", "folders", "requests"]),
      action["action"] as? String == "replace_api_collection",
      let rawFolders = action["folders"] as? [Any],
      let rawRequests = action["requests"] as? [Any]
    else {
      throw LocalHTTPError(status: 400, message: "API Collection action is invalid")
    }
    let expectedGeneration = try apiCollectionInteger(
      action["expected_generation"],
      label: "Expected API Collection generation"
    )
    apiCollectionLock.lock()
    defer { apiCollectionLock.unlock() }
    let current = try loadApiCollectionLocked()
    guard current["generation"] as? Int == expectedGeneration else {
      throw LocalHTTPError(
        status: 409,
        message: "API Collection changed in another window; refresh before saving"
      )
    }
    let folders = try rawFolders.map(normalizeApiCollectionFolder)
    let requestContents = try rawRequests.map {
      try normalizeApiCollectionRequest($0, requireMetadata: false)
    }
    let currentRequests = Dictionary(uniqueKeysWithValues:
      (current["requests"] as? [[String: Any]] ?? []).map { ($0["id"] as! Int, $0) }
    )
    let now = Int(Date().timeIntervalSince1970 * 1_000)
    let requests = requestContents.map { content -> [String: Any] in
      var result = content
      if let previous = currentRequests[content["id"] as! Int] {
        result["created_at_ms"] = previous["created_at_ms"]
        let previousContent = previous.filter { !["created_at_ms", "updated_at_ms"].contains($0.key) }
        result["updated_at_ms"] = NSDictionary(dictionary: previousContent).isEqual(to: content)
          ? previous["updated_at_ms"] : now
      } else {
        result["created_at_ms"] = now
        result["updated_at_ms"] = now
      }
      return result
    }
    let candidate = try normalizeApiCollection([
      "contract_version": 1,
      "document_kind": "api-collection",
      "generation": expectedGeneration + 1,
      "updated_at_ms": now,
      "folders": folders,
      "requests": requests,
      "limits": apiCollectionLimits(),
    ])
    let result: [String: Any]
    if NSDictionary(dictionary: apiCollectionContent(candidate)).isEqual(to: apiCollectionContent(current)) {
      result = current
    } else {
      try writeApiCollectionLocked(candidate)
      result = candidate
    }
    let generation = result["generation"] as! Int
    return (
      try apiCollectionData(result),
      200,
      ["ETag": "\"api-collection-\(generation)\""]
    )
  }

  private func debuggerUnavailableResponse(
    ifNoneMatch: String?
  ) throws -> (Data, Int, [String: String]) {
    let etag = "\"debugger-unavailable-v2\""
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
        "heap_diff_baseline": NSNull(),
        "memory_origin_trace": [
          "protocol_version": 1,
          "trace_id": 0,
          "state": "idle",
          "target_id": NSNull(),
          "query": "",
          "scope": "all",
          "case_sensitive": false,
          "before_steps": 0,
          "after_steps": 0,
          "step_limit": 32,
          "step_count": 0,
          "first_match_step": NSNull(),
          "started_at_ms": 0,
          "elapsed_ms": 0,
          "partial": false,
          "limit_reason": NSNull(),
          "message": "Enter a value and arm a trace.",
          "steps": [],
        ],
        "request_interception": [
          "protocol_version": 1,
          "experiment_id": 0,
          "state": "idle",
          "isolated": false,
          "target_id": NSNull(),
          "created_at_ms": 0,
          "disposed_at_ms": 0,
          "rule": [
            "mode": "continue",
            "url_pattern": "*",
            "method_filter": "",
            "rewrite_url": "",
            "rewrite_method": "",
            "rewrite_header_count": 0,
            "rewrite_body_bytes": 0,
            "response_code": 200,
            "response_header_count": 0,
            "response_body_bytes": 0,
          ],
          "last_request": NSNull(),
          "result": NSNull(),
          "audit": [],
          "audit_evictions": 0,
          "pending_requests": 0,
          "message": "Create an isolated experiment to intercept a request.",
          "limits": [
            "audit_entries": 128,
            "pending_requests": 16,
            "headers": 64,
            "body_bytes": 64 * 1_024,
            "response_bytes": 64 * 1_024,
          ],
        ],
        "repeater": [
          "protocol_version": 1,
          "session_id": 0,
          "state": "idle",
          "variables": [],
          "history": [],
          "history_bytes": 0,
          "history_evictions": 0,
          "active_execution": NSNull(),
          "comparison": NSNull(),
          "message": "Create an isolated request-lab context to use Repeater.",
          "limits": [
            "history_entries": 24,
            "history_bytes": 512 * 1_024,
            "variables": 32,
            "variable_bytes": 32 * 1_024,
            "request_bytes": 64 * 1_024,
            "response_bytes": 64 * 1_024,
            "timeout_ms": 30_000,
          ],
        ],
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
    let apiCollectionStoreURL = configuredApiCollectionStore()
    let handler = LocalContentHandler(
      indexURL: indexURL,
      eventStoreURL: eventStoreURL,
      traceStoreURL: traceStoreURL,
      signalStoreURL: signalStoreURL,
      artifactStoreURL: artifactStoreURL,
      apiCollectionStoreURL: apiCollectionStoreURL,
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

  private func configuredApiCollectionStore() -> URL {
    let arguments = CommandLine.arguments
    if let storeFlag = arguments.firstIndex(of: "--api-collection"),
      storeFlag + 1 < arguments.count
    {
      return URL(fileURLWithPath: arguments[storeFlag + 1]).standardizedFileURL
    }
    if let configuredPath = ProcessInfo.processInfo.environment["REB_API_COLLECTION_STORE"],
      !configuredPath.isEmpty
    {
      return URL(fileURLWithPath: configuredPath).standardizedFileURL
    }
    let base = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    ).first ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
      "Library/Application Support"
    )
    return base.appendingPathComponent("Origin Trace/api-collection-v1.json")
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
      let exerciseCollectionWrite =
        ProcessInfo.processInfo.environment["REB_APP_SMOKE_API_COLLECTION_WRITE"] == "1"
      let exercise = """
        window.__rebSmokeExerciseError = null;
        void (async () => {
          if (\(exerciseCollectionWrite ? "true" : "false")) {
            const current = await fetch('/api/api-collection', {cache: 'no-store'}).then(response => {
              if (!response.ok) throw new Error(`Collection GET returned ${response.status}`);
              return response.json();
            });
            const folders = current.folders.map(folder => folder.id !== 1 ? folder : ({
              ...folder,
              variables: [...folder.variables.filter(variable => variable.name !== 'native_smoke'),
                {name: 'native_smoke', value: 'verified'}]
            }));
            const requests = current.requests.map(({created_at_ms, updated_at_ms, ...request}) => request);
            const response = await fetch('/api/api-collection/actions', {
              method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({action: 'replace_api_collection',
                expected_generation: current.generation, folders, requests})
            });
            if (!response.ok) throw new Error(`Collection POST returned ${response.status}`);
            const updated = await response.json();
            if (!isApiCollection(updated)) throw new Error('Collection POST returned a malformed document');
            state.apiCollection = updated;
            state.apiCollectionLoaded = true;
            state.apiCollectionEtag = `"api-collection-${updated.generation}"`;
            setCollectionNotice('ready', 'Native API Collection write verified.');
            renderApiCollection();
          }
        [...document.querySelectorAll('.request-row')]
          .find(row => row.textContent.includes('live'))?.click();
        document.querySelector('#trace-origin')?.click();
        })().catch(error => { window.__rebSmokeExerciseError = String(error); });
        true
        """
      webView.evaluateJavaScript(exercise) { _, exerciseError in
        if let exerciseError {
          print("SMOKE_ERROR \(exerciseError.localizedDescription)")
          NSApp.terminate(nil)
          return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
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
              debuggerContractValid: isDebuggerResponse(state.debuggerSession),
              repeaterAvailable: state.debuggerSession?.repeater?.protocol_version === 1,
              apiCollectionContractValid: isApiCollection(state.apiCollection),
              apiCollectionGeneration: state.apiCollection?.generation,
              apiCollectionStoreVisible: document.querySelector('#collection-generation')?.textContent,
              apiCollectionWriteExercised: \(exerciseCollectionWrite ? "true" : "false"),
              smokeExerciseError: window.__rebSmokeExerciseError,
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
