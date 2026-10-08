import Darwin
import Foundation

// Standalone production-helper checks, built by app-build without launching NSApp.
@main
enum NativeWorkspaceLeaseChecks {
  private static let manager = FileManager.default

  private static func lease(_ url: URL, maximumBytes: Int = 1_024) throws -> NativeWorkspaceLease {
    try NativeWorkspaceLease(at: url, label: "Test workspace", maximumBytes: maximumBytes)
  }

  private static func check(_ condition: Bool, _ message: String) {
    precondition(condition, message)
  }

  private static func expectError(_ status: Int, _ operation: () throws -> Void) throws {
    do {
      try operation()
      preconditionFailure("Expected HTTP \(status)")
    } catch let error as LocalHTTPError {
      check(error.status == status, "Expected HTTP \(status), received \(error.status): \(error.message)")
    }
  }

  private static func metadata(_ url: URL) throws -> stat {
    var result = stat()
    check(lstat(url.path, &result) == 0, "Cannot inspect fixture")
    return result
  }

  private static func writeFixture(_ data: Data, to url: URL, mode: mode_t = 0o600) throws {
    try data.write(to: url)
    check(chmod(url.path, mode) == 0, "Cannot set fixture permissions")
  }

  private static func child(_ arguments: [String], input: Pipe? = nil, output: Pipe? = nil) throws -> Process {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    process.arguments = arguments
    process.standardInput = input ?? Pipe()
    if let output { process.standardOutput = output }
    try process.run()
    return process
  }

  private static func waitForExit(_ process: Process) {
    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline {
      // Match Foundation's task wait model while retaining an outer deadline.
      RunLoop.current.run(until: min(deadline, Date().addingTimeInterval(0.01)))
    }
    if process.isRunning {
      _ = kill(process.processIdentifier, SIGKILL)
      preconditionFailure("Workspace helper did not exit before its deadline")
    }
    process.waitUntilExit()
  }

  static func main() throws {
    if CommandLine.arguments.count == 3 {
      let url = URL(fileURLWithPath: CommandLine.arguments[2])
      if CommandLine.arguments[1] == "--hold" {
        let held = try lease(url)
        defer { held.close() }
        FileHandle.standardOutput.write(Data("LOCKED\n".utf8))
        _ = try FileHandle.standardInput.read(upToCount: 1)
        return
      }
      if CommandLine.arguments[1] == "--expect-busy" {
        try expectError(409) { let unexpected = try lease(url); unexpected.close() }
        return
      }
      preconditionFailure("Unknown workspace lease check option")
    }
    check(CommandLine.arguments.count == 1, "Unexpected workspace lease check arguments")
    let root = manager.temporaryDirectory.appendingPathComponent("reb-native-workspace-\(UUID().uuidString)")
    try manager.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? manager.removeItem(at: root) }
    func store(_ name: String) -> URL {
      root.appendingPathComponent(name).appendingPathComponent("workspace.json")
    }
    func lockURL(_ url: URL) -> URL {
      url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + NativeWorkspaceLease.lockSuffix)
    }

    let url = store("roundtrip")
    let data = Data("{\"generation\":1}\n".utf8)
    let held = try lease(url)
    check(try held.read() == nil, "Absent workspace must remain absent")
    let lockBefore = try metadata(lockURL(url))
    check((try metadata(url.deletingLastPathComponent())).st_mode & 0o777 == 0o700, "New directory must be private")
    try expectError(409) { let other = try lease(url); other.close() }
    let contender = try child(["--expect-busy", url.path])
    waitForExit(contender)
    check(contender.terminationStatus == 0, "Second process did not observe the lease")
    try held.write(data)
    check(try held.read() == data, "Atomic replacement did not round-trip")
    check((try metadata(url)).st_mode & 0o777 == 0o600, "Published file must be private")
    held.close()
    let saved = try metadata(url)
    let noOp = try lease(url)
    check(try noOp.read() == data, "A no-op transaction must see the saved bytes")
    noOp.close()
    let unchanged = try metadata(url)
    check(saved.st_ino == unchanged.st_ino && saved.st_mtimespec.tv_sec == unchanged.st_mtimespec.tv_sec
      && saved.st_mtimespec.tv_nsec == unchanged.st_mtimespec.tv_nsec, "A no-op lease rewrote the target")
    check((try metadata(lockURL(url))).st_ino == lockBefore.st_ino, "Sidecar inode changed")

    // Legacy readable files remain valid, but every replacement is private.
    check(chmod(url.path, 0o644) == 0, "Cannot prepare readable legacy store")
    let legacy = try lease(url)
    check(try legacy.read() == data, "Readable legacy store was rejected")
    try legacy.write(data)
    legacy.close()
    check((try metadata(url)).st_mode & 0o777 == 0o600, "Legacy replacement must be private")

    let alias = root.appendingPathComponent("alias")
    try manager.createSymbolicLink(at: alias, withDestinationURL: url.deletingLastPathComponent())
    let real = try lease(url)
    try expectError(409) {
      let other = try lease(alias.appendingPathComponent(url.lastPathComponent)); other.close()
    }
    real.close()

    // Retargeting the lexical parent after acquire cannot redirect its read,
    // temporary write, rename, cleanup, or lock release into another directory.
    let pinnedURL = store("pinned")
    let pinned = try lease(pinnedURL)
    try pinned.write(data)
    let relocated = root.appendingPathComponent("relocated")
    try manager.moveItem(at: pinnedURL.deletingLastPathComponent(), to: relocated)
    try manager.createDirectory(at: pinnedURL.deletingLastPathComponent(), withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    let sentinel = Data("unrelated".utf8)
    try writeFixture(sentinel, to: pinnedURL)
    check(try pinned.read() == data, "Lease followed a changed parent path")
    let replacement = Data("{\"generation\":2}\n".utf8)
    try pinned.write(replacement)
    pinned.close()
    check(try Data(contentsOf: pinnedURL) == sentinel, "Replacement touched the new lexical parent")
    check(try Data(contentsOf: relocated.appendingPathComponent("workspace.json")) == replacement,
      "Replacement missed the pinned directory")

    for kind in ["symlink", "hardlink", "fifo", "directory", "readable", "nonempty"] {
      let target = store("bad-lock-\(kind)")
      try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700])
      let sidecar = lockURL(target)
      let external = target.deletingLastPathComponent().appendingPathComponent("untouched")
      try writeFixture(sentinel, to: external)
      switch kind {
      case "symlink": try manager.createSymbolicLink(at: sidecar, withDestinationURL: external)
      case "hardlink": check(link(external.path, sidecar.path) == 0, "Cannot link lock fixture")
      case "fifo": check(mkfifo(sidecar.path, 0o600) == 0, "Cannot create lock FIFO")
      case "directory": try manager.createDirectory(at: sidecar, withIntermediateDirectories: false)
      case "readable": try writeFixture(Data(), to: sidecar, mode: 0o644)
      default: try writeFixture(data, to: sidecar)
      }
      try expectError(500) { let rejected = try lease(target); rejected.close() }
      check(try Data(contentsOf: external) == sentinel, "Refused lock changed unrelated data")
      check(!manager.fileExists(atPath: target.path), "Refused lock created a target")
    }

    for kind in ["symlink", "hardlink", "fifo", "directory", "oversized"] {
      let target = store("bad-target-\(kind)")
      let transaction = try lease(target)
      let external = target.deletingLastPathComponent().appendingPathComponent("untouched")
      try writeFixture(sentinel, to: external)
      switch kind {
      case "symlink": try manager.createSymbolicLink(at: target, withDestinationURL: external)
      case "hardlink": check(link(external.path, target.path) == 0, "Cannot link target fixture")
      case "fifo": check(mkfifo(target.path, 0o600) == 0, "Cannot create target FIFO")
      case "directory": try manager.createDirectory(at: target, withIntermediateDirectories: false)
      default: try writeFixture(Data(repeating: 0, count: 1_025), to: target)
      }
      try expectError(500) { _ = try transaction.read() }
      transaction.close()
      check(try Data(contentsOf: external) == sentinel, "Refused target changed unrelated data")
    }

    let bounded = try lease(url, maximumBytes: data.count)
    check(try bounded.read() == data, "Exact byte limit must be accepted")
    try expectError(400) { try bounded.write(Data(repeating: 0, count: data.count + 1)) }
    bounded.close()
    check(try Data(contentsOf: url) == data, "Oversized write changed saved data")

    for mode in [mode_t(0o770), mode_t(0o707)] {
      let target = store("unsafe-parent-\(mode)")
      try manager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: false)
      check(chmod(target.deletingLastPathComponent().path, mode) == 0, "Cannot prepare unsafe parent")
      try expectError(500) { let rejected = try lease(target); rejected.close() }
      check(!manager.fileExists(atPath: lockURL(target).path), "Unsafe directory gained a lock")
    }
    try expectError(500) {
      let rejected = try lease(root.appendingPathComponent("reserved" + NativeWorkspaceLease.lockSuffix))
      rejected.close()
    }
    try expectError(500) {
      let rejected = try lease(root.appendingPathComponent(".reb-workspace-configured-target.tmp"))
      rejected.close()
    }

    for reserved in [".REB-WORKSPACE-123-0.tmp", ".reb-worKspace-123-0.tmp", "store.json.REB-WORKSPACE-LOCK-V1"] {
      try expectError(500) { let rejected = try lease(root.appendingPathComponent(reserved)); rejected.close() }
    }

    let failURL = store("failed-rename")
    let failed = try lease(failURL)
    try manager.createDirectory(at: failURL, withIntermediateDirectories: false)
    try expectError(500) { try failed.write(data) }
    failed.close()
    let names = try manager.contentsOfDirectory(atPath: failURL.deletingLastPathComponent().path)
    check(Set(names) == Set([failURL.lastPathComponent, lockURL(failURL).lastPathComponent]),
      "Failed replacement leaked a temporary file or removed the sidecar")

    // Process death must release the kernel lease; no stale PID/timeout files.
    let crashURL = store("crash")
    let input = Pipe()
    let output = Pipe()
    let holder = try child(["--hold", crashURL.path], input: input, output: output)
    defer { if holder.isRunning { _ = kill(holder.processIdentifier, SIGKILL) } }
    var readiness = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
    check(poll(&readiness, 1, 5_000) > 0, "Child lease readiness timed out")
    let ready = try output.fileHandleForReading.read(upToCount: 7)
    check(ready == Data("LOCKED\n".utf8), "Child failed to acquire its lease")
    try expectError(409) { let other = try lease(crashURL); other.close() }
    check(kill(holder.processIdentifier, SIGKILL) == 0, "Cannot stop fixture holder")
    waitForExit(holder)
    let recovered = try lease(crashURL)
    recovered.close()
    check(manager.fileExists(atPath: lockURL(crashURL).path), "Crash removed the permanent sidecar")

    print("PASS native workspace lease: contention, aliases, pinned directory, private atomic replace, bounds, refusal and crash recovery")
  }
}
