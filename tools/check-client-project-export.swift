import Foundation

// Compiled alongside the production validator by app-build. Fixtures are
// authored data only; this tool never creates NSApp, opens a panel or saves ZIPs.
@main
enum ClientProjectExportChecks {
  private struct Entry {
    var path: String
    var body: Data
  }

  private static func reject(_ label: String, _ action: () throws -> Void) {
    do { try action(); preconditionFailure("Accepted invalid client-project fixture: \(label)") }
    catch is ClientProjectExportError { }
    catch { preconditionFailure("Unexpected error for \(label): \(error)") }
  }

  private static func number(_ bytes: Data, _ offset: Int, _ width: Int) -> Int {
    (0..<width).reduce(0) { $0 | (Int(bytes[offset + $1]) << ($1 * 8)) }
  }

  private static func put(_ value: Int, into bytes: inout Data, at offset: Int, width: Int) {
    for byte in 0..<width { bytes[offset + byte] = UInt8((value >> (byte * 8)) & 255) }
  }

  private static func entries(_ data: Data) -> [Entry] {
    let end = data.count - 22, count = number(data, end + 8, 2)
    var result: [Entry] = [], cursor = 0
    for _ in 0..<count {
      let size = number(data, cursor + 18, 4), length = number(data, cursor + 26, 2)
      let start = cursor + 30 + length
      result.append(Entry(path: String(data: data[(cursor + 30)..<start], encoding: .utf8)!,
                          body: Data(data[start..<(start + size)])))
      cursor = start + size
    }
    return result
  }

  // Independent tiny stored-ZIP writer lets invalid UTF-8, paths and sizes carry
  // correct CRC/central records, proving those failures are caught in their own right.
  private static func zip(_ entries: [Entry]) -> Data {
    var locals = Data(), directory = Data()
    for entry in entries {
      let name = Data(entry.path.utf8)
      var checksum: UInt32 = 0xffffffff
      for byte in entry.body {
        checksum ^= UInt32(byte)
        for _ in 0..<8 { checksum = (checksum >> 1) ^ ((checksum & 1) == 1 ? 0xedb88320 : 0) }
      }
      checksum ^= 0xffffffff
      var local = Data(repeating: 0, count: 30)
      for (offset, value, width) in [(0, 0x04034b50, 4), (4, 20, 2), (6, 0x800, 2),
        (12, 33, 2), (14, Int(checksum), 4), (18, entry.body.count, 4),
        (22, entry.body.count, 4), (26, name.count, 2)] {
        put(value, into: &local, at: offset, width: width)
      }
      local.append(name); local.append(entry.body)
      var central = Data(repeating: 0, count: 46)
      for (offset, value, width) in [(0, 0x02014b50, 4), (4, 20, 2), (6, 20, 2),
        (8, 0x800, 2), (14, 33, 2), (16, Int(checksum), 4),
        (20, entry.body.count, 4), (24, entry.body.count, 4), (28, name.count, 2),
        (42, locals.count, 4)] {
        put(value, into: &central, at: offset, width: width)
      }
      central.append(name); locals.append(local); directory.append(central)
    }
    var end = Data(repeating: 0, count: 22)
    for (offset, value, width) in [(0, 0x06054b50, 4), (8, entries.count, 2),
      (10, entries.count, 2), (12, directory.count, 4), (16, locals.count, 4)] {
      put(value, into: &end, at: offset, width: width)
    }
    locals.append(directory); locals.append(end)
    return locals
  }

  static func main() throws {
    precondition(CommandLine.arguments.count == 2, "Provide the authored-example.zip fixture")
    let authored = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
    let checked = try ClientProjectArchive.validate(authored, expectedMode: .raw)
    let files = entries(authored)
    precondition(checked.fileCount == files.count && checked.bytes == authored)
    precondition(zip(files) == authored, "Independent writer must match the JavaScript producer byte-for-byte")
    let message: [String: Any] = ["format": "reb-client-project-save-v1", "mode": "raw",
                                  "base64": authored.base64EncodedString()]
    let decoded = try ClientProjectArchive.decode(message)
    precondition(decoded.bytes == authored)
    precondition(ClientProjectArchive.Mode.raw.filename == "reb-client-project.raw.zip")
    precondition(ClientProjectArchive.Mode.redactedCopy.filename == "reb-client-project.redacted.zip")
    reject("wrong mode") { _ = try ClientProjectArchive.validate(authored, expectedMode: .redactedCopy) }
    for (key, value) in [("format", "other"), ("mode", "other"), ("base64", "!!!"),
      ("base64", ""), ("base64", authored.base64EncodedString() + "\n"),
      ("base64", String(repeating: "A", count: ClientProjectArchive.maximumBase64Bytes + 4))] {
      var invalid = message; invalid[key] = value
      reject("payload \(key)") { _ = try ClientProjectArchive.decode(invalid) }
    }
    var extra = message; extra["path"] = "/tmp/unapproved.zip"
    reject("destination in message") { _ = try ClientProjectArchive.decode(extra) }
    reject("non-object message") { _ = try ClientProjectArchive.decode([1, 2, 3]) }

    let end = authored.count - 22, central = number(authored, end + 16, 4)
    let firstBody = 30 + number(authored, 26, 2)
    for (label, offset, width, value) in [
      ("signature", 0, 4, 0), ("ZIP64 version", 4, 2, 45), ("encrypted flag", 6, 2, 0x801),
      ("descriptor flag", 6, 2, 0x808), ("compression", 8, 2, 8), ("extra field", 28, 2, 1),
      ("file bound", 18, 4, ClientProjectArchive.maximumFileBytes + 1),
      ("CRC", 14, 4, 0), ("content CRC", firstBody, 1, 0),
      ("central signature", central, 4, 0), ("central CRC", central + 16, 4, 0),
      ("central size", central + 20, 4, 0), ("central offset", central + 42, 4, 1),
      ("symlink attributes", central + 38, 4, 0xa1ff0000),
      ("central comment", central + 32, 2, 1), ("central name", central + 46, 1, 0),
      ("disk", end + 4, 2, 1), ("count", end + 8, 2, 17),
      ("unequal counts", end + 10, 2, 1), ("directory size", end + 12, 4, 0),
      ("directory beyond end", end + 16, 4, 0xffffffff), ("end comment", end + 20, 2, 1)
    ] {
      var invalid = authored; put(value, into: &invalid, at: offset, width: width)
      reject(label) { _ = try ClientProjectArchive.validate(invalid) }
    }
    for length in [0, 1, 21, 22, 29, firstBody, central, authored.count - 1] {
      reject("truncation \(length)") { _ = try ClientProjectArchive.validate(Data(authored.prefix(length))) }
    }
    reject("trailing bytes") { _ = try ClientProjectArchive.validate(authored + Data([0])) }
    reject("leading bytes") { _ = try ClientProjectArchive.validate(Data([0]) + authored) }
    reject("empty ZIP") { _ = try ClientProjectArchive.validate(zip([])) }
    for path in ["../escape", "reb-client-project/../escape", "reb-client-project/a\\b",
      "reb-client-project/unknown.json", "reb-client-project/README.md/", "reb-client-project/./README.md"] {
      var invalid = files; invalid[0].path = path
      reject("fixed path \(path)") { _ = try ClientProjectArchive.validate(zip(invalid)) }
    }
    reject("duplicate entry") { _ = try ClientProjectArchive.validate(zip(files + [files[0]])) }
    reject("missing required file") { _ = try ClientProjectArchive.validate(zip(Array(files.dropFirst()))) }
    reject("no evidence") {
      _ = try ClientProjectArchive.validate(zip(files.filter { !ClientProjectArchive.evidencePaths.contains($0.path) }))
    }
    var invalidUTF8 = files; invalidUTF8[files.count - 1].body = Data([0xff])
    reject("UTF-8 with matching CRC") { _ = try ClientProjectArchive.validate(zip(invalidUTF8)) }

    var redacted = files
    let provenance = files.firstIndex { $0.path == "reb-client-project/provenance.json" }!
    var metadata = try JSONSerialization.jsonObject(with: files[provenance].body) as! [String: Any]
    metadata["mode"] = "redacted_copy"
    redacted[provenance].body = try JSONSerialization.data(withJSONObject: metadata)
    let redactedArchive = try ClientProjectArchive.validate(zip(redacted), expectedMode: .redactedCopy)
    precondition(redactedArchive.mode == .redactedCopy)
    let run = Entry(path: "reb-client-project/evidence/repeater-run.json", body: Data("{}".utf8))
    _ = try ClientProjectArchive.validate(zip(files + [run]))
    _ = try ClientProjectArchive.validate(zip(files.filter { !ClientProjectArchive.evidencePaths.contains($0.path) } + [run]))

    var boundary = files
    let readme = files.firstIndex { $0.path == "reb-client-project/README.md" }!
    let client = files.firstIndex { $0.path == "reb-client-project/src/client.mjs" }!
    boundary[readme].body = Data(repeating: 120, count: ClientProjectArchive.maximumFileBytes)
    _ = try ClientProjectArchive.validate(zip(boundary))
    boundary[client].body = Data()
    let remaining = ClientProjectArchive.maximumBytes - zip(boundary).count
    precondition(remaining > 0 && remaining <= ClientProjectArchive.maximumFileBytes)
    boundary[client].body = Data(repeating: 120, count: remaining)
    let maximumArchive = try ClientProjectArchive.validate(zip(boundary))
    precondition(maximumArchive.bytes.count == ClientProjectArchive.maximumBytes)
    boundary[client].body.append(120)
    reject("archive byte bound") { _ = try ClientProjectArchive.validate(zip(boundary)) }
    boundary = files
    boundary[readme].body = Data(repeating: 120, count: ClientProjectArchive.maximumFileBytes + 1)
    reject("entry byte bound") { _ = try ClientProjectArchive.validate(zip(boundary)) }
    print("PASS native client-project ZIP parity, modes, fixed paths, bounds, CRC, UTF-8, central records and malformed payload refusal (no save panel or writes)")
  }
}
