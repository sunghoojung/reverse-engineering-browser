import Foundation

enum ClientProjectExportError: LocalizedError {
  case invalidPayload, invalidArchive

  var errorDescription: String? {
    switch self {
    case .invalidPayload: return "Invalid or oversized client-project export request."
    case .invalidArchive: return "The client-project ZIP failed its fixed-format validation."
    }
  }
}

// This is deliberately not a general ZIP reader. Accept only the bounded,
// deterministic stored records authored by captured_client.js. Never extract
// entries or interpret a captured value as a destination or executable input.
struct ClientProjectArchive {
  enum Mode: String {
    case raw, redactedCopy = "redacted_copy"

    var filename: String {
      self == .raw ? "reb-client-project.raw.zip" : "reb-client-project.redacted.zip"
    }
  }

  static let maximumBytes = 2 * 1_024 * 1_024
  static let maximumFileBytes = 1_024 * 1_024
  static let maximumBase64Bytes = ((maximumBytes + 2) / 3) * 4
  static let requiredPaths: Set<String> = Set([
    "provenance.json", "requests/request-001.json", "config.example.json",
    ".gitignore", "package.json", "src/client.mjs", "src/services/service-001.mjs",
    "examples/request-001.mjs", "README.md", "go/go.mod", "go/client/client.go",
    "go/services/service001.go", "go/cmd/request-001/main.go", "go/client/mimic.go"
  ].map { "reb-client-project/" + $0 })
  static let pythonRequiredPaths: Set<String> = Set([
    "provenance.json", "requests/request-001.json", "config.example.json",
    ".gitignore", "client.py", "requirements.txt", "README.md"
  ].map { "reb-client-project/" + $0 })
  static let evidencePaths: Set<String> = [
    "reb-client-project/evidence/capture.json", "reb-client-project/evidence/repeater-run.json"
  ]

  let bytes: Data
  let mode: Mode
  let fileCount: Int

  static func decode(_ body: Any) throws -> ClientProjectArchive {
    guard let payload = body as? [String: Any],
      Set(payload.keys) == Set(["format", "mode", "base64"]),
      payload["format"] as? String == "reb-client-project-save-v1",
      let rawMode = payload["mode"] as? String, let mode = Mode(rawValue: rawMode),
      let base64 = payload["base64"] as? String,
      !base64.isEmpty, base64.utf8.count <= maximumBase64Bytes,
      let bytes = Data(base64Encoded: base64), bytes.count <= maximumBytes,
      bytes.base64EncodedString() == base64
    else { throw ClientProjectExportError.invalidPayload }
    return try validate(bytes, expectedMode: mode)
  }

  static func validate(_ data: Data, expectedMode: Mode? = nil) throws -> ClientProjectArchive {
    guard data.count >= 22, data.count <= maximumBytes else {
      throw ClientProjectExportError.invalidArchive
    }
    let reader = ZIPBytes(bytes: Array(data))
    let end = data.count - 22
    // No split disks, ZIP64, comments, descriptors, compression or extra fields.
    guard reader.u32(end) == 0x06054b50,
      reader.u16(end + 4) == 0, reader.u16(end + 6) == 0,
      reader.u16(end + 20) == 0
    else { throw ClientProjectExportError.invalidArchive }
    let count = reader.u16(end + 8)
    let centralSize = reader.u32(end + 12)
    let centralStart = reader.u32(end + 16)
    guard (1...16).contains(count), reader.u16(end + 10) == count,
      centralStart <= end, centralSize == end - centralStart
    else { throw ClientProjectExportError.invalidArchive }

    var local = 0
    var central = centralStart
    var paths = Set<String>()
    var provenance: Data?
    let allowedPaths = requiredPaths.union(pythonRequiredPaths).union(evidencePaths)
    for _ in 0..<count {
      try reader.require(local, 30, before: centralStart)
      try reader.require(central, 46, before: end)
      guard reader.u32(local) == 0x04034b50,
        reader.u16(local + 4) == 20, reader.u16(local + 6) == 0x0800,
        reader.u16(local + 8) == 0, reader.u16(local + 10) == 0,
        reader.u16(local + 12) == 33, reader.u16(local + 28) == 0,
        reader.u32(central) == 0x02014b50,
        reader.u16(central + 4) == 20, reader.u16(central + 6) == 20,
        reader.u16(central + 8) == 0x0800, reader.u16(central + 10) == 0,
        reader.u16(central + 12) == 0, reader.u16(central + 14) == 33,
        reader.u16(central + 30) == 0, reader.u16(central + 32) == 0,
        reader.u16(central + 34) == 0, reader.u16(central + 36) == 0,
        reader.u32(central + 38) == 0, reader.u32(central + 42) == local
      else { throw ClientProjectExportError.invalidArchive }
      let length = reader.u32(local + 18)
      let nameLength = reader.u16(local + 26)
      let checksum = reader.u32(local + 14)
      guard length <= maximumFileBytes, nameLength > 0, nameLength <= 128,
        reader.u32(local + 22) == length, reader.u16(central + 28) == nameLength,
        reader.u32(central + 16) == checksum, reader.u32(central + 20) == length,
        reader.u32(central + 24) == length
      else { throw ClientProjectExportError.invalidArchive }
      let contentStart = local + 30 + nameLength
      try reader.require(local + 30, nameLength + length, before: centralStart)
      try reader.require(central + 46, nameLength, before: end)
      let nameBytes = Array(reader.bytes[(local + 30)..<contentStart])
      guard let path = String(bytes: nameBytes, encoding: .utf8),
        allowedPaths.contains(path), paths.insert(path).inserted,
        nameBytes.elementsEqual(reader.bytes[(central + 46)..<(central + 46 + nameLength)])
      else { throw ClientProjectExportError.invalidArchive }
      let content = reader.bytes[contentStart..<(contentStart + length)]
      guard Int(crc32(content)) == checksum, String(bytes: content, encoding: .utf8) != nil else {
        throw ClientProjectExportError.invalidArchive
      }
      if path == "reb-client-project/provenance.json" { provenance = Data(content) }
      local = contentStart + length
      central += 46 + nameLength
    }
    guard local == centralStart, central == end,
      (paths.subtracting(evidencePaths) == requiredPaths || paths.subtracting(evidencePaths) == pythonRequiredPaths),
      !paths.isDisjoint(with: evidencePaths),
      let provenance,
      let object = (try? JSONSerialization.jsonObject(with: provenance)) as? [String: Any],
      object["format"] as? String == "reb-client-project-v1",
      let rawMode = object["mode"] as? String, let mode = Mode(rawValue: rawMode),
      expectedMode == nil || mode == expectedMode
    else { throw ClientProjectExportError.invalidArchive }
    return ClientProjectArchive(bytes: data, mode: mode, fileCount: count)
  }

  private static func crc32(_ bytes: ArraySlice<UInt8>) -> UInt32 {
    var checksum: UInt32 = 0xffffffff
    for byte in bytes {
      checksum ^= UInt32(byte)
      for _ in 0..<8 {
        checksum = (checksum >> 1) ^ ((checksum & 1) == 1 ? 0xedb88320 : 0)
      }
    }
    return checksum ^ 0xffffffff
  }

  private struct ZIPBytes {
    let bytes: [UInt8]

    func require(_ offset: Int, _ length: Int, before limit: Int) throws {
      guard limit <= bytes.count, offset >= 0, length >= 0,
        offset <= limit, length <= limit - offset
      else { throw ClientProjectExportError.invalidArchive }
    }

    // Callers first bound each complete fixed header with require().
    func u16(_ offset: Int) -> Int {
      return Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
    }

    func u32(_ offset: Int) -> Int {
      return Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
        | (Int(bytes[offset + 2]) << 16) | (Int(bytes[offset + 3]) << 24)
    }
  }
}

enum RequestHarSaveError: LocalizedError {
  case invalidPayload

  var errorDescription: String? { "Invalid HAR save request." }
}

// The page's request to save the backend's HAR of Traffic rows. The page names
// only which rows: the path is fixed, and every query key is one that
// export_requests_har reads (protocol/openapi.json).
struct RequestHarSave {
  static let format = "reb-request-har-save-v1"
  static let path = "/api/requests/har"
  static let keys: Set<String> = [
    "rows", "credential_values", "through", "sort", "order", "q", "tab_id", "domain", "type", "named",
    "failed", "invert", "hide_internal", "third_party", "from_ns", "to_ns",
  ]

  let query: String
  let filename: String
  let credentialValues: Bool

  static func decode(_ body: Any) throws -> RequestHarSave {
    guard let payload = body as? [String: Any],
      Set(payload.keys) == Set(["format", "query", "filename"]),
      payload["format"] as? String == format,
      let query = payload["query"] as? String, let filename = payload["filename"] as? String,
      // A query the parser had to re-encode is not one the page built with URLSearchParams.
      let components = URLComponents(string: "http://127.0.0.1/?" + query), components.percentEncodedQuery == query,
      let items = components.queryItems, !items.isEmpty,
      items.allSatisfy({ keys.contains($0.name) }), Set(items.map(\.name)).count == items.count
    else { throw RequestHarSaveError.invalidPayload }
    // A suggested name only; the panel's choice is the destination.
    let suggested = filename.range(of: #"^[a-z][a-z.-]{0,63}\.har$"#, options: .regularExpression) != nil
    return RequestHarSave(query: query, filename: suggested ? filename : "requests.har",
      credentialValues: items.contains { $0.name == "credential_values" && $0.value == "1" })
  }
}

// The archive's closing _reb object, its last member: whether every selected
// row was written, how many entries were, and why an export stopped early.
struct RequestHarSummary {
  let complete: Bool
  let entries: Int
  let error: String?

  static func read(_ file: URL) -> RequestHarSummary? {
    guard let handle = try? FileHandle(forReadingFrom: file) else { return nil }
    defer { try? handle.close() }
    guard let size = try? handle.seekToEnd() else { return nil }
    // The object holds counts, the index position and one message.
    let tail = min(size, 1 << 20)
    guard (try? handle.seek(toOffset: size - tail)) != nil, let data = try? handle.readToEnd(),
      let marker = data.range(of: Data(#"],"_reb":"#.utf8), options: .backwards),
      data.suffix(2).elementsEqual("}}".utf8), marker.upperBound <= data.endIndex - 2,
      let object = (try? JSONSerialization.jsonObject(with: Data(data[marker.upperBound..<(data.endIndex - 2)]))) as? [String: Any],
      object["format"] as? String == "reb-request-har-v1",
      let complete = object["complete"] as? Bool, let entries = object["entries"] as? Int
    else { return nil }
    return RequestHarSummary(complete: complete, entries: entries, error: object["error"] as? String)
  }
}

#if canImport(Cocoa) && canImport(WebKit)
import Cocoa
import UniformTypeIdentifiers
import WebKit

// A page cannot select a path. Only the owned, fully loaded main document may
// request a panel, and only a current panel approval may write its bounded ZIP
// or the Traffic HAR the backend streams to it.
final class NativeClientProjectExport: NSObject, WKScriptMessageHandlerWithReply {
  static let handlerName = "rebClientProjectExport"
  static let requestHandlerName = "rebRequestExport"
  private enum Payload {
    case project(ClientProjectArchive)
    case har(RequestHarSave)
  }
  private struct Request {
    let id: UUID
    let generation: UInt64
    let payload: Payload
    let panel: NSSavePanel
    let reply: (Any?, String?) -> Void
  }

  // Streams the backend's answer for the trusted document's path and query to
  // a file; nil on success, else a message without paths. Set by the app.
  var download: ((_ document: URL, _ path: String, _ query: String, _ destination: URL,
    _ done: @escaping (String?) -> Void) -> Void)?

  private weak var webView: WKWebView?
  private weak var window: NSWindow?
  private var trustedURL: URL?
  private var documentReady = false
  private var generation: UInt64 = 0
  private var pending: Request?
  private var downloading = false
  private var closeObserver: NSObjectProtocol?
  private var smokePanelObserver: ((NSSavePanel) -> Void)?
  private var smokeWriteObserver: ((URL) -> Void)?
  private var smokeReplyObserver: ((String) -> Void)?

  init(webView: WKWebView, window: NSWindow) {
    self.webView = webView
    self.window = window
    super.init()
    closeObserver = NotificationCenter.default.addObserver(
      forName: NSWindow.willCloseNotification, object: window, queue: .main
    ) { [weak self] _ in self?.navigationWillStart() }
  }

  deinit {
    if let closeObserver { NotificationCenter.default.removeObserver(closeObserver) }
  }

  // Native-only test observers. They are never populated outside the explicit
  // packaged smoke mode, and do not add any JavaScript operation or destination.
  func installSmokeObservers(panel: @escaping (NSSavePanel) -> Void,
                             willWrite: @escaping (URL) -> Void,
                             reply: @escaping (String) -> Void) {
    guard ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1",
      ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT"] == "1"
    else { return }
    smokePanelObserver = panel
    smokeWriteObserver = willWrite
    smokeReplyObserver = reply
  }

  // Called only by explicit native load sites. Navigations and redirects never
  // add trusted URLs, even if their destinations use loopback or the reb scheme.
  func prepareForLoad(_ url: URL) {
    navigationWillStart()
    trustedURL = url
  }

  func navigationWillStart() {
    generation &+= 1
    documentReady = false
    guard let request = pending else { return }
    pending = nil
    request.panel.cancel(nil)
    request.reply(["status": "canceled"], nil)
  }

  func navigationDidFinish(_ view: WKWebView) {
    documentReady = view === webView && trustedURL != nil && view.url == trustedURL
  }

  func userContentController(
    _ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
    replyHandler: @escaping (Any?, String?) -> Void
  ) {
    let har = message.name == Self.requestHandlerName
    guard message.name == Self.handlerName || har,
      message.webView === webView, message.frameInfo.isMainFrame,
      documentReady, let trustedURL, webView?.url == trustedURL,
      message.frameInfo.request.url == trustedURL
    else {
      replyHandler(nil, har ? "HAR saving is unavailable outside the owned application document."
        : "Client-project export is unavailable outside the owned application document.")
      return
    }
    // HTTP additionally has a non-opaque security origin to check. The custom
    // app scheme is scoped by the exact native URL, WebView and main frame above.
    if trustedURL.scheme == "http" {
      let origin = message.frameInfo.securityOrigin
      let brackets = CharacterSet(charactersIn: "[]")
      guard origin.protocol == "http",
        origin.host.trimmingCharacters(in: brackets) == trustedURL.host?.trimmingCharacters(in: brackets),
        origin.port == trustedURL.port
      else {
        replyHandler(nil, har ? "HAR saving refused an unexpected document origin."
          : "Client-project export refused an unexpected document origin.")
        return
      }
    }
    guard pending == nil, !downloading, let window, window.isVisible, window.attachedSheet == nil else {
      replyHandler(nil, har ? "Finish the current native dialog or save before saving a HAR."
        : "Finish the current native dialog before exporting a client project.")
      return
    }
    let payload: Payload
    do { payload = har ? .har(try RequestHarSave.decode(message.body)) : .project(try ClientProjectArchive.decode(message.body)) }
    catch { replyHandler(nil, error.localizedDescription); return }

    let panel = NSSavePanel()
    switch payload {
    case .project(let archive):
      panel.title = "Save client project"
      panel.message = archive.mode == .raw
        ? "Raw evidence can contain credentials and personal data. Save locally and review before sharing."
        : "This redacted copy can still contain sensitive names, paths and identifiers. Review before sharing."
      panel.nameFieldStringValue = archive.mode.filename
      panel.allowedContentTypes = [.zip]
    case .har(let save):
      panel.title = "Save HAR"
      panel.message = save.credentialValues
        ? "Raw requests include credential values, cookies, URLs and bodies. Save locally and review before sharing."
        : "Credential values are withheld; URLs, other headers and bodies can still be private. Review before sharing."
      panel.nameFieldStringValue = save.filename
      panel.allowedContentTypes = [UTType(filenameExtension: "har", conformingTo: .json) ?? .json]
    }
    panel.allowsOtherFileTypes = false
    panel.canCreateDirectories = true
    panel.isExtensionHidden = false
    let request = Request(id: UUID(), generation: generation, payload: payload,
                          panel: panel, reply: { [weak self] value, error in
      self?.smokeReplyObserver?(error == nil
        ? ((value as? [String: Any])?["status"] as? String ?? "unexpected") : "failed")
      replyHandler(value, error)
    })
    pending = request
    let requestID = request.id
    smokePanelObserver?(panel)
    panel.beginSheetModal(for: window) { [weak self] response in
      guard let self, let current = self.pending, current.id == requestID else { return }
      self.pending = nil
      guard response == .OK, current.generation == self.generation,
        self.documentReady, self.webView?.url == self.trustedURL,
        let destination = current.panel.url, destination.isFileURL
      else { current.reply(["status": "canceled"], nil); return }
      switch current.payload {
      case .project(let archive):
        do {
          self.smokeWriteObserver?(destination)
          try archive.bytes.write(to: destination, options: .atomic)
          current.reply(["status": "saved"], nil)
        } catch {
          // Do not expose selected filesystem paths or raw capture data to JS/logs.
          current.reply(nil, "The client project could not be saved. Choose a writable destination and try again.")
        }
      case .har(let save):
        guard let download = self.download, let document = self.trustedURL else {
          current.reply(nil, "HAR saving is unavailable in this application.")
          return
        }
        // The reply waits for the whole archive; until then no other save starts.
        self.smokeWriteObserver?(destination)
        self.downloading = true
        download(document, RequestHarSave.path, save.query, destination) { failure in
          DispatchQueue.main.async {
            self.downloading = false
            if let failure { current.reply(nil, failure); return }
            guard let summary = RequestHarSummary.read(destination) else {
              current.reply(nil, "The saved file does not end with a HAR summary.")
              return
            }
            var result: [String: Any] = ["status": "saved", "complete": summary.complete, "entries": summary.entries]
            if let error = summary.error { result["error"] = error }
            current.reply(result, nil)
          }
        }
      }
    }
  }
}
#endif
