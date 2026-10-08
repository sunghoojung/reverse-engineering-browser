import Darwin
import Foundation

struct LocalHTTPError: Error {
  let status: Int
  let message: String
}

// Shared with workspace_lease.rs: every writer opens this permanent sibling independently
// and holds flock from the generation reread through the durable atomic replace.
// The directory descriptor pins parent symlink aliases for the entire transaction.
final class NativeWorkspaceLease {
  static let lockSuffix = ".reb-workspace-lock-v1"

  private var directoryDescriptor: Int32 = -1
  private var lockDescriptor: Int32 = -1
  private var ownsLock = false
  private let filename: String
  private let label: String
  private let maximumBytes: Int

  init(at url: URL, label: String, maximumBytes: Int) throws {
    self.filename = url.lastPathComponent
    self.label = label
    self.maximumBytes = maximumBytes
    let foldedFilename = filename.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
    guard url.isFileURL, !url.hasDirectoryPath, !filename.isEmpty,
      filename != ".", filename != "..", !filename.contains("/"),
      !filename.utf8.contains(0), !foldedFilename.hasSuffix(Self.lockSuffix),
      !foldedFilename.hasPrefix(".reb-workspace-"), maximumBytes > 0, maximumBytes < Int.max
    else {
      throw LocalHTTPError(status: 500, message: "\(label) store has an invalid or reserved filename")
    }
    let directory = url.deletingLastPathComponent()
    do {
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
    } catch {
      throw LocalHTTPError(status: 500, message: "\(label) store directory could not be created")
    }
    do {
      // Follow parent aliases once, then never resolve the parent path again.
      directoryDescriptor = Darwin.open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
      guard directoryDescriptor >= 0 else {
        throw failure("store directory could not be opened")
      }
      var directoryMetadata = stat()
      guard fstat(directoryDescriptor, &directoryMetadata) == 0,
        (directoryMetadata.st_mode & S_IFMT) == S_IFDIR,
        directoryMetadata.st_uid == geteuid(), (directoryMetadata.st_mode & 0o022) == 0
      else {
        throw failure("store directory must be owned by this user and not writable by other users")
      }
      // Normal saves open once. Only an absent sidecar is created exclusively;
      // EEXIST from a competing creator permits one existing-only open.
      let lockName = filename + Self.lockSuffix
      let lockFlags = O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
      lockDescriptor = Darwin.openat(directoryDescriptor, lockName, lockFlags)
      if lockDescriptor < 0 && errno == ENOENT {
        lockDescriptor = Darwin.openat(
          directoryDescriptor, lockName, lockFlags | O_CREAT | O_EXCL, mode_t(0o600)
        )
        if lockDescriptor < 0 && errno == EEXIST {
          lockDescriptor = Darwin.openat(directoryDescriptor, lockName, lockFlags)
        }
      }
      guard lockDescriptor >= 0 else {
        throw failure("save lock could not be opened safely")
      }
      var lockMetadata = stat()
      guard fstat(lockDescriptor, &lockMetadata) == 0,
        (lockMetadata.st_mode & S_IFMT) == S_IFREG, lockMetadata.st_uid == geteuid(),
        lockMetadata.st_nlink == 1, lockMetadata.st_size == 0,
        (lockMetadata.st_mode & 0o7777) == 0o600
      else {
        throw failure("save lock must be an empty, private, user-owned regular file with one link")
      }
      // Never wait for another writer, including another handler in this process.
      // A fresh open, rather than dup, gives flock a distinct owner.
      guard flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0 else {
        if errno == EWOULDBLOCK || errno == EAGAIN {
          throw LocalHTTPError(
            status: 409, message: "\(label) is being saved elsewhere; reload before saving again"
          )
        }
        throw failure("save lock could not be acquired")
      }
      ownsLock = true
      var namedLockMetadata = stat()
      guard fstatat(
        directoryDescriptor, filename + Self.lockSuffix, &namedLockMetadata, AT_SYMLINK_NOFOLLOW
      ) == 0,
        namedLockMetadata.st_dev == lockMetadata.st_dev,
        namedLockMetadata.st_ino == lockMetadata.st_ino,
        namedLockMetadata.st_nlink == 1, namedLockMetadata.st_size == 0,
        namedLockMetadata.st_uid == geteuid(),
        (namedLockMetadata.st_mode & S_IFMT) == S_IFREG,
        (namedLockMetadata.st_mode & 0o7777) == 0o600
      else {
        throw failure("save lock changed while it was being acquired")
      }
    } catch {
      close()
      throw error
    }
  }

  deinit { close() }

  // Explicit defer at the call site also preserves the lease through no-op
  // response serialization, independent of Swift's last-use ARC optimization.
  func close() {
    if lockDescriptor >= 0 {
      if ownsLock { _ = flock(lockDescriptor, LOCK_UN) }
      ownsLock = false
      Darwin.close(lockDescriptor)
      lockDescriptor = -1
    }
    if directoryDescriptor >= 0 {
      Darwin.close(directoryDescriptor)
      directoryDescriptor = -1
    }
    // Never unlink the sidecar: waiters must keep referring to the same inode.
  }

  func read() throws -> Data? {
    let descriptor = Darwin.openat(
      directoryDescriptor, filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
    )
    if descriptor < 0 {
      if errno == ENOENT { return nil }
      throw failure("store could not be opened safely")
    }
    defer { Darwin.close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG, metadata.st_uid == geteuid(),
      metadata.st_nlink == 1, metadata.st_size >= 0, metadata.st_size <= Int64(maximumBytes)
    else {
      throw failure("store must be a bounded, user-owned regular file with one link")
    }
    var data = Data()
    data.reserveCapacity(Int(metadata.st_size))
    var buffer = [UInt8](repeating: 0, count: 16 * 1_024)
    while data.count <= maximumBytes {
      let requested = min(buffer.count, maximumBytes + 1 - data.count)
      let count = Darwin.read(descriptor, &buffer, requested)
      if count < 0 {
        if errno == EINTR { continue }
        throw failure("store could not be read")
      }
      if count == 0 { break }
      data.append(buffer, count: count)
    }
    guard data.count <= maximumBytes else { throw failure("store exceeds its byte limit") }
    return data
  }

  func write(_ data: Data) throws {
    guard data.count <= maximumBytes else {
      throw LocalHTTPError(status: 400, message: "\(label) store exceeds its byte limit")
    }
    var temporaryName = ""
    var temporaryDescriptor: Int32 = -1
    for _ in 0..<16 {
      temporaryName = ".reb-workspace-\(UUID().uuidString).tmp"
      temporaryDescriptor = Darwin.openat(
        directoryDescriptor, temporaryName,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600)
      )
      if temporaryDescriptor >= 0 { break }
      if errno != EEXIST { throw failure("temporary store could not be created") }
    }
    guard temporaryDescriptor >= 0 else { throw failure("temporary store name could not be allocated") }
    var renamed = false
    defer {
      Darwin.close(temporaryDescriptor)
      if !renamed { _ = Darwin.unlinkat(directoryDescriptor, temporaryName, 0) }
    }
    // Set private permissions before writing any bytes, never after publication.
    guard fchmod(temporaryDescriptor, mode_t(0o600)) == 0 else {
      throw failure("temporary store permissions could not be set")
    }
    // Case/normalization aliases must never expose the target as a temporary.
    var temporaryMetadata = stat()
    var targetMetadata = stat()
    guard fstat(temporaryDescriptor, &temporaryMetadata) == 0 else {
      throw failure("temporary store could not be inspected")
    }
    if fstatat(directoryDescriptor, filename, &targetMetadata, AT_SYMLINK_NOFOLLOW) == 0 {
      guard temporaryMetadata.st_dev != targetMetadata.st_dev || temporaryMetadata.st_ino != targetMetadata.st_ino else {
        throw failure("store filename aliases the reserved temporary namespace")
      }
    } else if errno != ENOENT {
      throw failure("store destination could not be inspected")
    }
    try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
      var offset = 0
      while offset < bytes.count {
        let count = Darwin.write(temporaryDescriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw failure("temporary store could not be written") }
        offset += count
      }
    }
    guard Darwin.fsync(temporaryDescriptor) == 0 else {
      throw failure("temporary store could not be synchronized")
    }
    guard Darwin.renameat(directoryDescriptor, temporaryName, directoryDescriptor, filename) == 0 else {
      throw failure("store could not be replaced")
    }
    renamed = true
    guard Darwin.fsync(directoryDescriptor) == 0 else {
      throw failure("save may have occurred, but durability could not be confirmed; reload before saving again")
    }
  }

  private func failure(_ message: String) -> LocalHTTPError {
    LocalHTTPError(status: 500, message: "\(label) \(message)")
  }
}
