import Darwin
import Foundation

// A live session folder the launcher wrote (scripts/run-live-session.sh), for
// Open Session and Open Recent Session. The app opens its stores in the
// offline workspace in place; it never moves or copies them.
struct RecordedSession: Equatable {
  let folder: URL
  let started: Date
  let lastWritten: Date

  // Where the app's sessions are kept, one folder each. An explicit
  // REB_LIVE_SESSION_ROOT wins, as it does for the launcher.
  static func root(environment: [String: String], originTrace: URL) -> URL {
    if let path = environment["REB_LIVE_SESSION_ROOT"], !path.isEmpty {
      return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
    }
    return originTrace.appendingPathComponent("sessions/live", isDirectory: true)
  }

  // A folder is a recorded session when it holds an event store.
  static func at(_ folder: URL) -> RecordedSession? {
    let folder = folder.standardizedFileURL
    let events = folder.appendingPathComponent("events.jsonl")
    guard let folderValues = try? folder.resourceValues(forKeys: [.isDirectoryKey, .creationDateKey]),
      folderValues.isDirectory == true,
      let eventValues = try? events.resourceValues(forKeys: [.isRegularFileKey, .contentModificationDateKey]),
      eventValues.isRegularFile == true
    else { return nil }
    let lastWritten = eventValues.contentModificationDate ?? .distantPast
    return RecordedSession(folder: folder, started: folderValues.creationDate ?? lastWritten, lastWritten: lastWritten)
  }

  // The newest sessions under `root` that no broker is still writing, newest
  // first.
  static func recent(in root: URL, limit: Int) -> [RecordedSession] {
    let folders = (try? FileManager.default.contentsOfDirectory(
      at: root, includingPropertiesForKeys: [.isDirectoryKey, .creationDateKey], options: [.skipsHiddenFiles])) ?? []
    return folders.compactMap(at)
      .sorted { $0.started > $1.started }
      .filter { !recording($0.folder) }
      .prefix(limit)
      .map { $0 }
  }

  // The broker holds an exclusive lease on the event store's guard for as long
  // as it writes (services/event-broker/README.md, Store ownership), so a
  // shared nonblocking lock it refuses means the session is still recording.
  // The backend checks a running broker the same way (capture.rs).
  static func recording(_ folder: URL) -> Bool {
    let guardPath = folder.appendingPathComponent("events.jsonl.reb-lock-v1").path
    let descriptor = Darwin.open(guardPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    guard descriptor >= 0 else { return false }
    defer { close(descriptor) }
    if flock(descriptor, LOCK_SH | LOCK_NB) == 0 {
      _ = flock(descriptor, LOCK_UN)
      return false
    }
    return errno == EWOULDBLOCK
  }

  // A menu title: when it started and for how long it wrote evidence.
  var title: String {
    let date = DateFormatter()
    date.dateStyle = .medium
    date.timeStyle = .short
    date.doesRelativeDateFormatting = true
    let span = lastWritten.timeIntervalSince(started)
    let length: String
    if span < 60 {
      length = "under a minute"
    } else {
      let duration = DateComponentsFormatter()
      duration.allowedUnits = span < 3600 ? [.minute] : [.hour, .minute]
      duration.unitsStyle = .short
      length = duration.string(from: span) ?? "under a minute"
    }
    return "\(date.string(from: started)) (\(length))"
  }
}
