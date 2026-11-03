import Foundation

// Compile with the production coordinator, so these exercise its actual parser.
@main
enum LiveSessionFailureChecks {
  static func main() {
    let fallback = "The live capture coordinator stopped before startup completed."
    let prefix = "REB_LIVE_SESSION_FAILURE: "
    let browser = "Brave stopped before its debugger endpoint became ready. See: /owned/brave.log"
    let helper = "Event broker stopped during startup. See: /owned/broker.log"
    let noise = "Live session cleanup complete.\nrun-live-session.sh: line 165: 40660 Terminated: 15 sleep 1\n"
    let cases: [(String, String?, String)] = [
      ("missing log", nil, fallback),
      ("empty log", "", fallback),
      ("cleanup and Bash noise only", noise, fallback),
      ("unmarked error", browser + "\n" + noise, fallback),
      ("empty marker", prefix + "\n", fallback),
      ("blank marker", prefix + "   \n", fallback),
      ("marker inside unrelated output", "unrelated " + prefix + browser, fallback),
      ("browser failure then Bash termination", prefix + browser + "\n" + noise, browser),
      ("helper failure then Bash termination", prefix + helper + "\n" + noise, helper),
      ("last explicit failure", prefix + helper + "\n" + prefix + browser + "\n" + noise, browser),
      ("empty trailing marker", prefix + browser + "\n" + prefix + "\n" + noise, browser),
      ("long trailing diagnostics", prefix + browser + "\n" + String(repeating: noise, count: 100), browser),
      ("bounded visible cause", prefix + String(repeating: "x", count: 5000), String(repeating: "x", count: 4096)),
    ]
    for (name, log, expected) in cases {
      let data = log.map { Data($0.utf8) }
      precondition(LiveSessionCoordinator.failureCause(in: data) == expected, name)
    }
    print("PASS native live failure causes: marked browser/helper errors, Bash noise, fallback, and bounds")

    // The launcher's mask grammar. tools/check-native-only-launch.mjs runs the
    // same vectors through scripts/run-live-session.sh.
    let masks: [(String?, UInt32?)] = [
      (nil, 4095), ("", 4095), ("1", 1), ("1280", 1280), ("4095", 4095), ("0400", 400),
      ("0x500", 1280), ("0X500", 1280), ("0x300", 768), ("0x0fff", 4095), ("0000001280", 1280),
      ("0", nil), ("4096", nil), ("0x", nil), ("0x0", nil), ("0x1000", nil), ("+1280", nil),
      ("-1", nil), (" 1280", nil), ("1280 ", nil), ("1+1", nil), ("abc", nil), ("1e3", nil),
      ("0b11", nil), ("12345678901", nil), ("0x123456789", nil), ("\u{FF11}\u{FF12}", nil),
      ("a[$(touch /tmp/x)]", nil),
    ]
    for (value, expected) in masks {
      precondition(LiveSessionCoordinator.categoryMask(value) == expected, "mask \(String(describing: value))")
    }
    // Content mode turns on only what the mask allows, and an unreadable mask
    // never reads as every category.
    let defaults = { (mask: String?, content: Bool) -> [String: String] in
      LiveSessionCoordinator.captureDefaults(
        environment: mask.map { ["REB_CAPTURE_CATEGORY_MASK": $0] } ?? [:], captureNetworkContent: content)
    }
    let names = ["REB_CAPTURE_CANVAS_IMAGES", "REB_CAPTURE_REQUEST_CONTENT", "REB_NATIVE_WASM_DISPATCH", "REB_NATIVE_WASM_CALL_INDIRECT"]
    let defaultCases: [(String?, Bool, [String])] = [
      (nil, true, ["1", "1", "1", "1"]), (nil, false, ["0", "0", "1", "1"]),
      ("0x500", true, ["0", "1", "0", "0"]), ("0x300", true, ["0", "0", "0", "0"]),
      ("768", true, ["0", "0", "0", "0"]), ("1025", true, ["1", "0", "0", "0"]),
      ("0x7ff", true, ["1", "1", "1", "1"]), ("0xzz", true, ["0", "0", "0", "0"]),
      (" 4095", true, ["0", "0", "0", "0"]),
    ]
    for (mask, content, expected) in defaultCases {
      let environment = defaults(mask, content)
      precondition(names.map { environment[$0] } == expected, "defaults \(String(describing: mask)) content=\(content)")
      precondition(environment["REB_NATIVE_QUIET_MODE"] == "1", "quiet mode default")
    }
    // An explicit setting always wins, even where the mask would not allow it.
    let explicit = LiveSessionCoordinator.captureDefaults(
      environment: ["REB_CAPTURE_CATEGORY_MASK": "256", "REB_CAPTURE_REQUEST_CONTENT": "1", "REB_NATIVE_WASM_DISPATCH": "0"],
      captureNetworkContent: false)
    precondition(explicit["REB_CAPTURE_REQUEST_CONTENT"] == "1" && explicit["REB_NATIVE_WASM_DISPATCH"] == "0", "explicit values")
    print("PASS native live category mask: the launcher's decimal and 0x grammar, content defaults only where the mask allows, no 4095 fallback for unreadable text")

    // Content is the default for app-started captures. Metadata is the opt-out,
    // and any value that is not exactly "content" opts out rather than in.
    let modes: [(String?, LiveCaptureMode)] = [
      (nil, .content), ("", .content), ("content", .content), ("metadata", .metadata),
      ("Metadata", .metadata), ("metadta", .metadata), ("Content", .metadata), (" content", .metadata),
    ]
    for (value, expected) in modes {
      let environment = value.map { ["REB_AUTOMATIC_CAPTURE_MODE": $0] } ?? [:]
      precondition(LiveCaptureMode.configured(environment) == expected, "mode \(String(describing: value))")
    }
    precondition(LiveCaptureMode.content.capturesNetworkContent && !LiveCaptureMode.metadata.capturesNetworkContent, "mode content")
    precondition(LiveCaptureMode.content.title.contains("default") && !LiveCaptureMode.metadata.title.contains("recommended"), "mode labels")
    // The default mode retains content; an explicit Metadata choice keeps hosts only.
    let byMode = { (mode: LiveCaptureMode) in
      LiveSessionCoordinator.captureDefaults(environment: [:], captureNetworkContent: mode.capturesNetworkContent)
    }
    let defaultMode = byMode(LiveCaptureMode.configured([:]))
    precondition(defaultMode["REB_CAPTURE_REQUEST_CONTENT"] == "1" && defaultMode["REB_CAPTURE_CANVAS_IMAGES"] == "1", "default mode content")
    let metadataMode = byMode(LiveCaptureMode.configured(["REB_AUTOMATIC_CAPTURE_MODE": "metadata"]))
    precondition(metadataMode["REB_CAPTURE_REQUEST_CONTENT"] == "0" && metadataMode["REB_CAPTURE_CANVAS_IMAGES"] == "0", "metadata mode")
    print("PASS native live capture mode: Content by default, an explicit or misspelled Metadata choice keeps hosts only")

    // Every app-started capture permits document-start Console scripts, in
    // either mode and whatever the mask, unless the environment says otherwise.
    for (mask, content) in [(nil, true), (nil, false), ("1", true), ("0xzz", false)] {
      precondition(defaults(mask, content)["REB_CONSOLE_DOCUMENT_START"] == "1", "document-start default \(String(describing: mask))")
    }
    for value in ["0", "1"] {
      let explicitStart = LiveSessionCoordinator.captureDefaults(
        environment: ["REB_CONSOLE_DOCUMENT_START": value], captureNetworkContent: true)
      precondition(explicitStart["REB_CONSOLE_DOCUMENT_START"] == value, "explicit document-start \(value)")
    }
    print("PASS native live document-start permission: on by default for app captures, an explicit 0 survives")
  }
}
