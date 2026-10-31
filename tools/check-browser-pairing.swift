import Foundation

// Compile with the production pairing gate. Owned fixtures only: the signed
// bundle copies this checker's own executable and is never launched.
@main
enum BrowserPairingChecks {
  static func main() throws {
    let manager = FileManager.default
    let directory = manager.temporaryDirectory
      .appendingPathComponent("reb-browser-pairing-\(UUID().uuidString)", isDirectory: true)
    defer { try? manager.removeItem(at: directory) }

    let signed = try bundle(in: directory, named: "Signed") { executable in
      guard let own = Bundle.main.executableURL else { preconditionFailure("no executable") }
      try manager.copyItem(at: own, to: executable)
    }
    precondition(run("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", signed.path]).status == 0)
    let printed = run("/usr/bin/codesign", ["-dvvv", signed.path]).output
      .split(separator: "\n").compactMap { line -> String? in
        line.hasPrefix("CDHash=") ? String(line.dropFirst("CDHash=".count)) : nil
      }
    precondition(printed.count == 1, "codesign must print one CDHash")
    let hash = BrowserPairing.codeDirectoryHash(applicationURL: signed)
    precondition(hash == printed[0], "Security and codesign must agree on the CDHash")

    let script = try bundle(in: directory, named: "Script") { executable in
      try Data("#!/bin/sh\nexit 0\n".utf8).write(to: executable)
    }
    precondition(BrowserPairing.codeDirectoryHash(applicationURL: script) == nil, "unsigned script bundle")
    precondition(BrowserPairing.codeDirectoryHash(
      applicationURL: directory.appendingPathComponent("Missing.app")) == nil, "missing bundle")

    let pinned = printed[0]
    let other = String(repeating: "0", count: 40)
    let paired: [String: Any] = [
      "CFBundleShortVersionString": "9.8.7",
      BrowserPairing.releaseTypeKey: "paired",
      BrowserPairing.pairedBrowserKey: pinned,
    ]
    precondition(BrowserPairing.unverifiedReason(appInfo: paired, browserCDHash: pinned) == nil,
                 "the exact paired browser starts without a decision")
    var cases: [(String, [String: Any], String?)] = [
      ("different browser build", paired, other),
      ("unreadable browser signature", paired, nil),
      ("placeholder pin", paired.merging([BrowserPairing.pairedBrowserKey: "PLACEHOLDER"]) { $1 }, "PLACEHOLDER"),
      ("uppercase pin", paired.merging([BrowserPairing.pairedBrowserKey: pinned.uppercased()]) { $1 },
       pinned.uppercased()),
      ("missing pin", paired.filter { $0.key != BrowserPairing.pairedBrowserKey }, pinned),
      ("missing release type", paired.filter { $0.key != BrowserPairing.releaseTypeKey }, pinned),
      ("unknown release type", paired.merging([BrowserPairing.releaseTypeKey: "preview"]) { $1 }, pinned),
    ]
    for (name, info, browser) in cases {
      let reason = BrowserPairing.unverifiedReason(appInfo: info, browserCDHash: browser)
      precondition(reason?.hasPrefix("Origin Trace 9.8.7 is verified only with the exact Brave") == true, name)
      precondition(reason?.contains("Native capture completeness is not established") == true, name)
    }
    cases = [("companion with matching pin",
              paired.merging([BrowserPairing.releaseTypeKey: "companion"]) { $1 }, pinned)]
    for (name, info, browser) in cases {
      let reason = BrowserPairing.unverifiedReason(appInfo: info, browserCDHash: browser)
      precondition(reason?.hasPrefix("Origin Trace 9.8.7 is a companion-only release") == true, name)
    }
    let unversioned = BrowserPairing.unverifiedReason(appInfo: [:], browserCDHash: nil)
    precondition(unversioned?.hasPrefix("This Origin Trace build is verified only") == true, "no version")
    print("PASS browser pairing: exact CDHash only; mismatched, unsigned, placeholder and companion warn")
  }

  private static func bundle(
    in directory: URL, named name: String, executable write: (URL) throws -> Void
  ) throws -> URL {
    let app = directory.appendingPathComponent(name + ".app", isDirectory: true)
    let macOS = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
    try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
    let executable = macOS.appendingPathComponent(name)
    try write(executable)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    let info: [String: Any] = [
      "CFBundleIdentifier": "com.reverseengineeringbrowser.pairing-fixture." + name.lowercased(),
      "CFBundleExecutable": name,
      "CFBundlePackageType": "APPL",
    ]
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
      .write(to: app.appendingPathComponent("Contents/Info.plist"))
    return app
  }

  private static func run(_ path: String, _ arguments: [String]) -> (status: Int32, output: String) {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe
    do { try process.run() } catch { preconditionFailure("\(path): \(error)") }
    let output = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: output, as: UTF8.self))
  }
}
