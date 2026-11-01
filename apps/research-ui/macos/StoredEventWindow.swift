import Darwin
import Foundation

// Newest-general and newest-network windows over the stored evidence tail.
// The scan stops at 64 MiB plus the predecessor byte so a canvas flood cannot
// force the native reader to parse the whole capture. The cache reuses a
// byte-verified overlap; it is not an authority for a rewritten or rotated file.
struct StoredEventWindow {
  var events: [[String: Any]]
  var networkEvents: [[String: Any]]
  var sequenceGaps: UInt64
  var sequenceGapsSaturated: Bool
  var queueDrops: UInt64
  var queueDropsSaturated: Bool
  var namedGaps: [NamedGap]
  var coverage: [String: Any]
}

// Gap markers in one category whose payload names a producer reason, such as
// native_wasm_dispatch_budget_incomplete, in first-seen order.
struct NamedGap: Equatable {
  var category: String
  var reason: String
  var count: UInt64
}

struct StoredEventWindowError: LocalizedError {
  let message: String
  var errorDescription: String? { message }
  init(_ message: String) { self.message = message }
}

final class StoredEventWindowCache {
  static let scanBytes = 64 * 1024 * 1024
  static let maxRecordBytes = 4096
  static let maxEvents = 5000
  // Browser reasons are fixed producer identifiers, so 64 distinct pairs covers
  // every documented one. A further pair stays an unexplained queue-drop marker.
  static let maxNamedGaps = 64

  private struct Record {
    var start: UInt64
    var end: UInt64
    var terminated: Bool
    var session: UInt64
    var process: UInt64
    var sequence: UInt64
    var drops: UInt64
    var namedGap: (category: String, reason: String)?
    var network: Bool
    var event: [String: Any]?
  }

  private struct Snapshot {
    var device: UInt64
    var inode: UInt64
    var start: UInt64
    var end: UInt64
    var predecessor: UInt8?
    var bytes: [UInt8]
    var records: [Record]

    func overlaps(_ newer: Snapshot) -> Bool {
      guard device == newer.device, inode == newer.inode,
        newer.start >= start, newer.end >= end, newer.start <= end
      else { return false }
      let offset = Int(newer.start - start)
      let shared = Int(end - newer.start)
      guard offset >= 0, shared >= 0, offset + shared <= bytes.count, shared <= newer.bytes.count else {
        return false
      }
      let predecessorByte: UInt8? = offset == 0 ? predecessor : bytes[offset - 1]
      guard predecessorByte == newer.predecessor else { return false }
      return bytes[offset..<(offset + shared)].elementsEqual(newer.bytes[..<shared])
    }
  }

  private let maximumBytes: Int
  private let lock = NSLock()
  private var snapshot: Snapshot?
  var parsedRecords = 0

  init(maximumBytes: Int = StoredEventWindowCache.scanBytes) {
    self.maximumBytes = maximumBytes
  }

  func read(path: String, limit: Int) throws -> StoredEventWindow {
    lock.lock()
    defer { lock.unlock() }
    let previous = snapshot
    snapshot = nil
    parsedRecords = 0
    do {
      guard var tail = try readTail(path) else {
        var records: [Record] = []
        return try summarize(records: &records, start: 0, end: 0, bytes: [], limit: limit).window
      }
      let skip: Int
      if tail.start == 0 || tail.predecessor == 0x0a {
        skip = 0
      } else if let newline = tail.bytes.firstIndex(of: 0x0a) {
        skip = newline + 1
      } else {
        skip = tail.bytes.count
      }
      if skip > Self.maxRecordBytes + 1 {
        throw StoredEventWindowError("The evidence store contains an oversized event")
      }
      let first = tail.start + UInt64(skip)
      var parseFrom = first
      if var old = previous, old.overlaps(tail) {
        old.records.removeAll { $0.start < first || !$0.terminated }
        if let last = old.records.last { parseFrom = last.end }
        tail.records = old.records
      }
      var position = Int(parseFrom - tail.start)
      while position < tail.bytes.count {
        let newline = tail.bytes[position...].firstIndex(of: 0x0a)
        let length = newline.map { $0 - position } ?? (tail.bytes.count - position)
        let terminated = newline != nil
        let endIndex = position + length + (terminated ? 1 : 0)
        let line = tail.bytes[position..<(position + length)]
        if !line.allSatisfy(isAsciiWhitespace) {
          if length > Self.maxRecordBytes {
            throw StoredEventWindowError("The evidence store contains an oversized event")
          }
          let object = try parseEvent(Data(line))
          let gap = (object["type"] as? String) == "gap"
          tail.records.append(Record(
            start: tail.start + UInt64(position),
            end: tail.start + UInt64(endIndex),
            terminated: terminated,
            session: try requiredUnsigned(object["session_id"]),
            process: try requiredUnsigned(object["process_id"]),
            sequence: try requiredUnsigned(object["sequence_number"]),
            drops: gap ? dropWeight(object) : 0,
            namedGap: gap ? namedGap(object) : nil,
            network: isNetwork(object),
            event: nil
          ))
          parsedRecords += 1
        }
        position = endIndex
      }
      let summarized = try summarize(
        records: &tail.records,
        start: first,
        end: tail.end,
        bytes: Array(tail.bytes[skip...]),
        limit: limit
      )
      for index in tail.records.indices where !summarized.retained[index] {
        tail.records[index].event = nil
      }
      snapshot = tail
      return summarized.window
    } catch {
      snapshot = nil
      throw error
    }
  }

  private func readTail(_ path: String) throws -> Snapshot? {
    var info = Darwin.stat()
    let statResult = path.withCString { stat($0, &info) }
    if statResult != 0 {
      if errno == ENOENT { return nil }
      throw StoredEventWindowError("The evidence store could not be read")
    }
    guard info.st_mode & S_IFMT == S_IFREG else {
      throw StoredEventWindowError("Evidence store must be a regular file")
    }
    let end = UInt64(info.st_size)
    let budget = UInt64(max(maximumBytes, 0))
    let start = end >= budget ? end - budget : 0
    let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { try? handle.close() }
    let predecessor: UInt8?
    if start == 0 {
      predecessor = nil
    } else {
      try handle.seek(toOffset: start - 1)
      let byte = try readExact(handle, count: 1)
      predecessor = byte[0]
    }
    try handle.seek(toOffset: start)
    let bytes = try readExact(handle, count: Int(end - start))
    return Snapshot(
      device: UInt64(info.st_dev),
      inode: info.st_ino,
      start: start,
      end: end,
      predecessor: predecessor,
      bytes: bytes,
      records: []
    )
  }

  private func summarize(
    records: inout [Record],
    start: UInt64,
    end: UInt64,
    bytes: [UInt8],
    limit: Int
  ) throws -> (window: StoredEventWindow, retained: [Bool]) {
    let capped = min(max(limit, 0), Self.maxEvents)
    var sequenceGaps: UInt64 = 0
    var sequenceGapsSaturated = false
    var queueDrops: UInt64 = 0
    var queueDropsSaturated = false
    var namedGaps: [NamedGap] = []
    var marks: [UInt64: [UInt64: Set<UInt64>]] = [:]
    var retained = Array(repeating: false, count: records.count)
    var events: [[String: Any]] = []
    var networkEvents: [[String: Any]] = []
    let generalStart = records.count >= capped ? records.count - capped : 0
    let networkCount = records.reduce(0) { $0 + ($1.network ? 1 : 0) }
    var networkSkip = networkCount >= capped ? networkCount - capped : 0
    for index in records.indices {
      var record = records[index]
      marks[record.session, default: [:]][record.process, default: []].insert(record.sequence)
      add(&queueDrops, &queueDropsSaturated, record.drops)
      if let named = record.namedGap {
        // At most 64 entries, and only gap markers reach this lookup.
        if let existing = namedGaps.firstIndex(where: { $0.category == named.category && $0.reason == named.reason }) {
          namedGaps[existing].count += 1
        } else if namedGaps.count < Self.maxNamedGaps {
          namedGaps.append(NamedGap(category: named.category, reason: named.reason, count: 1))
        }
      }
      let keepGeneral = index >= generalStart
      let keepNetwork: Bool
      if record.network && networkSkip > 0 {
        networkSkip -= 1
        keepNetwork = false
      } else {
        keepNetwork = record.network
      }
      if keepGeneral || keepNetwork {
        if record.event == nil {
          let from = Int(record.start - start)
          let to = Int(record.end - start) - (record.terminated ? 1 : 0)
          guard from >= 0, to >= from, to <= bytes.count else {
            throw StoredEventWindowError("The evidence store contains a malformed event")
          }
          record.event = try parseEvent(Data(bytes[from..<to]))
          records[index] = record
        }
        if keepGeneral { events.append(record.event!) }
        if keepNetwork { networkEvents.append(record.event!) }
        retained[index] = true
      }
    }
    // ACK-delayed identities close holes; duplicates cannot create gaps.
    for processes in marks.values {
      for seen in processes.values {
        if let low = seen.min(), let high = seen.max() {
          add(&sequenceGaps, &sequenceGapsSaturated, high - low - UInt64(seen.count - 1))
        }
      }
    }
    let coverage: [String: Any] = [
      "scope": start == 0 ? "store" : "bounded_tail",
      "scan_start": String(start),
      "scan_end": String(end),
      "scan_limit": maximumBytes,
      "events_limited": records.count > capped,
      "network_events_limited": networkCount > capped,
    ]
    return (
      StoredEventWindow(
        events: events,
        networkEvents: networkEvents,
        sequenceGaps: sequenceGaps,
        sequenceGapsSaturated: sequenceGapsSaturated,
        queueDrops: queueDrops,
        queueDropsSaturated: queueDropsSaturated,
        namedGaps: namedGaps,
        coverage: coverage
      ),
      retained
    )
  }
}

private func parseEvent(_ data: Data) throws -> [String: Any] {
  let value = try JSONSerialization.jsonObject(with: data)
  guard let object = value as? [String: Any] else {
    throw StoredEventWindowError("The evidence store contains a malformed event")
  }
  return object
}

private func requiredUnsigned(_ value: Any?) throws -> UInt64 {
  guard let parsed = unsignedValue(value) else {
    throw StoredEventWindowError("The evidence store contains a malformed event")
  }
  return parsed
}

private func unsignedValue(_ value: Any?) -> UInt64? {
  if let text = value as? String { return unsignedText(text) }
  if let number = value as? NSNumber {
    if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
    return unsignedText(number.stringValue)
  }
  return nil
}

private func unsignedText(_ text: String) -> UInt64? {
  guard !text.isEmpty, text.count <= 20, text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
  guard text.count == 1 || !text.hasPrefix("0") else { return nil }
  return UInt64(text)
}

// The HTTP contract weighs every non-count marker as one queue drop, so a named
// marker stays in queue_drops; named_gaps lets a reader take that weight back out.
private func dropWeight(_ event: [String: Any]) -> UInt64 {
  guard let hex = event["payload"] as? String,
    let data = hexBytes(hex),
    let text = String(data: data, encoding: .utf8),
    let count = unsignedText(text),
    count > 0
  else { return 1 }
  return count
}

// A lowercase letter, then lowercase letters, digits or underscores. A decimal
// drop count never matches, nor does page-shaped or truncated text.
private func isIdentifier<Bytes: Collection>(_ bytes: Bytes, maximum: Int) -> Bool where Bytes.Element == UInt8 {
  guard let first = bytes.first, bytes.count <= maximum, first >= 0x61, first <= 0x7a else { return false }
  return bytes.allSatisfy { ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5f }
}

// A browser stage that refuses or stops sampling an observation writes its
// reason as the payload. That loss belongs to the marker's category.
private func namedGap(_ event: [String: Any]) -> (category: String, reason: String)? {
  guard (event["payload_truncated"] as? Bool) != true,
    let category = event["category"] as? String,
    isIdentifier(Array(category.utf8), maximum: 32),
    let hex = event["payload"] as? String,
    let data = hexBytes(hex),
    isIdentifier(data, maximum: 128),
    let reason = String(data: data, encoding: .utf8)
  else { return nil }
  return (category, reason)
}

private func hexBytes(_ text: String) -> Data? {
  guard text.count % 2 == 0 else { return nil }
  var data = Data()
  data.reserveCapacity(text.count / 2)
  var index = text.startIndex
  while index < text.endIndex {
    let next = text.index(index, offsetBy: 2)
    guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
    data.append(byte)
    index = next
  }
  return data
}

private func isNetwork(_ event: [String: Any]) -> Bool {
  guard event["category"] as? String == "network", let type = event["type"] as? String else { return false }
  return [
    "request_initiated", "request_started", "request_redirected", "response_started",
    "response_completed", "request_completed", "request_failed",
  ].contains(type)
}

private func add(_ total: inout UInt64, _ saturated: inout Bool, _ count: UInt64) {
  let (sum, overflow) = total.addingReportingOverflow(count)
  if overflow {
    total = UInt64.max
    saturated = true
  } else {
    total = sum
  }
}

private func isAsciiWhitespace(_ byte: UInt8) -> Bool {
  byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0c || byte == 0x0d
}

private func readExact(_ handle: FileHandle, count: Int) throws -> [UInt8] {
  var bytes: [UInt8] = []
  bytes.reserveCapacity(count)
  var remaining = count
  while remaining > 0 {
    guard let chunk = try handle.read(upToCount: remaining), !chunk.isEmpty else {
      throw StoredEventWindowError("The evidence store changed while it was read")
    }
    bytes.append(contentsOf: chunk)
    remaining -= chunk.count
  }
  return bytes
}
