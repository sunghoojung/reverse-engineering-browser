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

    // The coordinator's phase rule: one transition per report, startup and
    // ended sessions named apart, and nothing after a launch ends.
    typealias Coordinator = LiveSessionCoordinator
    let workspace = URL(string: "http://127.0.0.1:7319/")!
    let marked = Data((prefix + browser + "\n" + noise).utf8)
    let log = "\n\nSession log: /owned/live.log"
    let next = { (phase: Coordinator.Phase, report: Coordinator.Report) in
      Coordinator.next(phase, after: report, logPath: "/owned/live.log")
    }
    let transitions: [(String, Coordinator.Phase, Coordinator.Report, Coordinator.Phase?)] = [
      ("handshake", .starting, .published(workspace), .ready(workspace)),
      ("exit during startup", .starting, .exited(log: marked), .failed(.init(message: browser + log, afterStartup: false))),
      ("unmarked exit during startup", .starting, .exited(log: nil), .failed(.init(message: fallback + log, afterStartup: false))),
      ("startup deadline", .starting, .timedOut(log: nil), .failed(.init(
        message: "Live capture did not become ready within 60 seconds. " + fallback + log, afterStartup: false))),
      ("exit after the handshake", .ready(workspace), .exited(log: marked), .failed(.init(message: browser + log, afterStartup: true))),
      ("unmarked exit after the handshake", .ready(workspace), .exited(log: nil),
        .failed(.init(message: Coordinator.sessionFallback + log, afterStartup: true))),
      ("stop while starting", .starting, .stopped, .ended),
      ("stop while ready", .ready(workspace), .stopped, .ended),
      ("second handshake", .ready(workspace), .published(workspace), nil),
      ("deadline after the handshake", .ready(workspace), .timedOut(log: nil), nil),
      ("exit after stop", .ended, .exited(log: marked), nil),
      ("exit after a reported failure", .failed(.init(message: browser, afterStartup: false)), .exited(log: nil), nil),
      ("handshake after stop", .ended, .published(workspace), nil),
      ("stop after a failure", .failed(.init(message: browser, afterStartup: true)), .stopped, nil),
      ("report before start", .idle, .published(workspace), nil),
    ]
    for (name, phase, report, expected) in transitions {
      precondition(next(phase, report) == expected, name)
    }
    print("PASS native live session phases: handshake, startup failure, ended session, stop, and no report after the end")

    // The launcher's mask grammar. tools/check-native-only-launch.mjs runs the
    // same vectors through scripts/run-live-session.sh.
    let masks: [(String?, UInt32?)] = [
      (nil, 4095), ("", 4095), ("1", 1), ("1280", 1280), ("4095", 4095), ("0400", 400),
      ("0x500", 1280), ("0X500", 1280), ("0x300", 768), ("0x0fff", 4095), ("0000001280", 1280),
      ("0", nil), ("4096", nil), ("0x", nil), ("0x0", nil), ("0x1000", nil), ("+1280", nil),
      ("-1", nil), (" 1280", nil), ("1280 ", nil), ("1+1", nil), ("abc", nil), ("1e3", nil),
      ("0b11", nil), ("12345678901", nil), ("0x123456789", nil), ("\u{FF11}\u{FF12}", nil),
      ("0x\u{FF11}\u{FF12}", nil), ("0x\u{FF41}", nil),
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
    let names = [
      "REB_CAPTURE_CANVAS_IMAGES", "REB_CAPTURE_REQUEST_CONTENT", "REB_NATIVE_WASM_DISPATCH",
      "REB_NATIVE_WASM_CALL_INDIRECT", "REB_NATIVE_REQUEST_STACKS",
    ]
    let defaultCases: [(String?, Bool, [String])] = [
      (nil, true, ["1", "1", "1", "1", "1"]), (nil, false, ["0", "0", "1", "1", "1"]),
      ("0x500", true, ["0", "1", "0", "0", "1"]), ("0x300", true, ["0", "0", "0", "0", "0"]),
      ("768", true, ["0", "0", "0", "0", "0"]), ("1025", true, ["1", "0", "0", "0", "0"]),
      ("0x7ff", true, ["1", "1", "1", "1", "1"]), ("0xzz", true, ["0", "0", "0", "0", "0"]),
      (" 4095", true, ["0", "0", "0", "0", "0"]),
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

    // The start panel's content limits: the launcher's bounds and grammar,
    // the agent path's rules for a start message, and the environment they
    // reach the launcher through only in a session that retains content.
    let defaultLimits = ContentLimits.defaults
    precondition(defaultLimits == ContentLimits(requestContentBudgetMiB: 256, responseBodyBudgetMiB: 512, responseMedia: false), "default limits")
    let configuredCases: [([String: String], ContentLimits)] = [
      ([:], defaultLimits),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "1024", "REB_RESPONSE_BODY_BUDGET_MIB": "16384", "REB_CAPTURE_RESPONSE_MEDIA": "1"],
        ContentLimits(requestContentBudgetMiB: 1024, responseBodyBudgetMiB: 16384, responseMedia: true)),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "1", "REB_RESPONSE_BODY_BUDGET_MIB": "1"],
        ContentLimits(requestContentBudgetMiB: 1, responseBodyBudgetMiB: 1, responseMedia: false)),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "4097", "REB_RESPONSE_BODY_BUDGET_MIB": "16385"], defaultLimits),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "0", "REB_RESPONSE_BODY_BUDGET_MIB": "0512"], defaultLimits),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "+64", "REB_RESPONSE_BODY_BUDGET_MIB": " 64"], defaultLimits),
      (["REB_REQUEST_CONTENT_BUDGET_MIB": "\u{FF16}\u{FF14}", "REB_RESPONSE_BODY_BUDGET_MIB": "64k"], defaultLimits),
      (["REB_CAPTURE_RESPONSE_MEDIA": "yes"], defaultLimits),
    ]
    for (environment, expected) in configuredCases {
      precondition(ContentLimits.configured(environment) == expected, "configured limits \(environment)")
    }
    let start = { (request: Any?, response: Any?, media: Any?) -> Result<ContentLimits, ContentLimits.Refusal> in
      var body: [String: Any] = ["op": "start", "mode": "content"]
      if let request { body["request_content_budget_mib"] = request }
      if let response { body["response_body_budget_mib"] = response }
      if let media { body["response_media"] = media }
      return ContentLimits.validated(body)
    }
    let yes = NSNumber(value: true), no = NSNumber(value: false)
    precondition(start(NSNumber(value: 256), NSNumber(value: 512), no) == .success(defaultLimits), "default start")
    precondition(start(NSNumber(value: 4096), NSNumber(value: 16384), yes)
      == .success(ContentLimits(requestContentBudgetMiB: 4096, responseBodyBudgetMiB: 16384, responseMedia: true)), "raised start")
    precondition(start(NSNumber(value: 1), NSNumber(value: 1.0), no)
      == .success(ContentLimits(requestContentBudgetMiB: 1, responseBodyBudgetMiB: 1, responseMedia: false)), "smallest start")
    let requestRule = ContentLimits.Refusal(message: ContentLimits.requestContentBudgetRule)
    let responseRule = ContentLimits.Refusal(message: ContentLimits.responseBodyBudgetRule)
    let mediaRule = ContentLimits.Refusal(message: "Capture media and fonts must be on or off.")
    let refusals: [(String, Any?, Any?, Any?, ContentLimits.Refusal)] = [
      ("request over", NSNumber(value: 4097), NSNumber(value: 512), no, requestRule),
      ("request zero", NSNumber(value: 0), NSNumber(value: 512), no, requestRule),
      ("request negative", NSNumber(value: -1), NSNumber(value: 512), no, requestRule),
      ("request fraction", NSNumber(value: 12.5), NSNumber(value: 512), no, requestRule),
      ("request text", "256", NSNumber(value: 512), no, requestRule),
      ("request boolean", yes, NSNumber(value: 512), no, requestRule),
      ("request infinite", NSNumber(value: Double.infinity), NSNumber(value: 512), no, requestRule),
      ("response over", NSNumber(value: 256), NSNumber(value: 16385), no, responseRule),
      ("response huge", NSNumber(value: 256), NSNumber(value: 1e300), no, responseRule),
      ("response boolean", NSNumber(value: 256), no, no, responseRule),
      ("media number", NSNumber(value: 256), NSNumber(value: 512), NSNumber(value: 1), mediaRule),
      ("media text", NSNumber(value: 256), NSNumber(value: 512), "true", mediaRule),
    ]
    for (name, request, response, media, expected) in refusals {
      precondition(start(request, response, media) == .failure(expected), "refused limits: \(name)")
    }
    for missing in 0..<3 {
      let values: [Any?] = [NSNumber(value: 256), NSNumber(value: 512), no].enumerated().map { $0.offset == missing ? nil : $0.element }
      guard case .failure(let refusal) = start(values[0], values[1], values[2]) else { preconditionFailure("missing limit \(missing)") }
      precondition(refusal.message.contains("needs a request content budget"), "missing limit \(missing): \(refusal.message)")
    }
    let raised = ContentLimits(requestContentBudgetMiB: 1024, responseBodyBudgetMiB: 2048, responseMedia: true)
    let limitNames = ["REB_REQUEST_CONTENT_BUDGET_MIB", "REB_RESPONSE_BODY_BUDGET_MIB", "REB_CAPTURE_RESPONSE_MEDIA"]
    let inherited = ["REB_REQUEST_CONTENT_BUDGET_MIB": "999", "REB_RESPONSE_BODY_BUDGET_MIB": "99", "REB_CAPTURE_RESPONSE_MEDIA": "0"]
    let limitCases: [(String, [String: String], Bool, ContentLimits?, [String?])] = [
      ("content default", [:], true, defaultLimits, ["256", "512", "0"]),
      ("content raised", [:], true, raised, ["1024", "2048", "1"]),
      ("chosen limits replace inherited ones", inherited, true, raised, ["1024", "2048", "1"]),
      ("no panel choice passes the environment", inherited, true, nil, ["999", "99", "0"]),
      ("no panel choice, no environment", [:], true, nil, [nil, nil, nil]),
      ("metadata passes nothing", [:], false, raised, [nil, nil, nil]),
      ("a mask without content passes nothing", ["REB_CAPTURE_CATEGORY_MASK": "0x300"], true, raised, [nil, nil, nil]),
      ("content off by the environment passes nothing", ["REB_CAPTURE_REQUEST_CONTENT": "0"], true, raised, [nil, nil, nil]),
    ]
    for (name, given, content, limits, expected) in limitCases {
      let environment = LiveSessionCoordinator.captureDefaults(environment: given, captureNetworkContent: content, contentLimits: limits)
      precondition(limitNames.map { environment[$0] } == expected, "content limits: \(name) \(limitNames.map { environment[$0] })")
    }
    // The start panel message SessionPanel.swift accepts only through LivePanelStart.parse.
    let parse = { (body: [String: Any]) in LivePanelStart.parse(["op": "start"].merging(body) { _, given in given }) }
    precondition(parse(["mode": "metadata"]) == .success(LivePanelStart(mode: .metadata, limits: nil)), "metadata start")
    precondition(parse(["mode": "content", "request_content_budget_mib": NSNumber(value: 1024), "response_body_budget_mib": NSNumber(value: 512),
      "response_media": yes]) == .success(LivePanelStart(mode: .content, limits: ContentLimits(requestContentBudgetMiB: 1024,
        responseBodyBudgetMiB: 512, responseMedia: true))), "content start")
    let startRefusals: [(String, [String: Any], String)] = [
      ("limits on metadata", ["mode": "metadata", "response_media": yes], "Budgets and media capture apply only to a Content session."),
      ("a budget on metadata", ["mode": "metadata", "request_content_budget_mib": NSNumber(value: 64)],
        "Budgets and media capture apply only to a Content session."),
      ("content without limits", ["mode": "content"], "A Content session needs a request content budget, a response body budget and the media choice."),
      ("content out of bounds", ["mode": "content", "request_content_budget_mib": NSNumber(value: 5000), "response_body_budget_mib": NSNumber(value: 512),
        "response_media": no], ContentLimits.requestContentBudgetRule),
      ("a Keychain switch", ["mode": "metadata", "keychain": yes], "The start panel offers only the capture mode and a Content session's limits."),
      ("an unknown mode", ["mode": "everything"], "Choose Content or Metadata only."),
    ]
    for (name, body, message) in startRefusals {
      precondition(parse(body) == .failure(ContentLimits.Refusal(message: message)), "refused start: \(name)")
    }
    // A session that keeps no request content is given none of the content-only
    // switches, inherited or chosen; the panel's mode decides request content.
    let media = ["REB_CAPTURE_RESPONSE_MEDIA": "1", "REB_REQUEST_CONTENT_BUDGET_MIB": "999", "REB_RESPONSE_BODY_BUDGET_MIB": "99"]
    let modeCases: [(String, [String: String], Bool, Bool, ContentLimits?, String, [String?])] = [
      ("a metadata start drops inherited content switches", media, false, true, nil, "0", [nil, nil, nil]),
      ("an automatic metadata launch drops them too", media, false, false, nil, "0", [nil, nil, nil]),
      ("a chosen Content mode wins over an inherited 0", ["REB_CAPTURE_REQUEST_CONTENT": "0"], true, true, raised, "1", ["1024", "2048", "1"]),
      ("a chosen Metadata mode wins over an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"].merging(media) { a, _ in a }, false, true, nil, "0",
        [nil, nil, nil]),
      ("an automatic launch keeps an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"].merging(media) { a, _ in a }, false, false, nil, "1",
        ["999", "99", "1"]),
      ("an automatic launch keeps an inherited 0 and drops the rest", ["REB_CAPTURE_REQUEST_CONTENT": "0"].merging(media) { a, _ in a }, true, false,
        raised, "0", [nil, nil, nil]),
    ]
    for (name, given, content, chosen, limits, expectedContent, expected) in modeCases {
      let environment = LiveSessionCoordinator.captureDefaults(
        environment: given, captureNetworkContent: content, contentLimits: limits, modeChosen: chosen)
      precondition(environment["REB_CAPTURE_REQUEST_CONTENT"] == expectedContent, "request content: \(name)")
      precondition(limitNames.map { environment[$0] } == expected, "content switches: \(name) \(limitNames.map { environment[$0] })")
    }
    precondition(LiveSessionCoordinator.retainsRequestContent(environment: [:], captureNetworkContent: true, modeChosen: true), "content retains")
    precondition(!LiveSessionCoordinator.retainsRequestContent(environment: ["REB_CAPTURE_CATEGORY_MASK": "0x300"], captureNetworkContent: true,
      modeChosen: true), "a mask without Network and Artifact retains nothing, so the panel names no limits")
    precondition(LiveSessionCoordinator.retainsRequestContent(environment: ["REB_CAPTURE_REQUEST_CONTENT": "0"], captureNetworkContent: true,
      modeChosen: true), "a chosen Content mode retains content over an inherited 0")
    print("PASS native content limits: the launcher's bounds and grammar for the panel's first values, start messages checked as the agent path checks them, launcher switches only for a session that retains content, inherited content-only switches dropped otherwise, and the panel's mode deciding request content")

    // Saved invocation sites arm app-started captures. Digests follow the
    // mode, the launcher drops sites a Brave cannot arm, and explicit values win.
    let saved = URL(fileURLWithPath: "/private/tmp/origin-trace-live-x-js-invocation-sites.json")
    let invocationNames = ["REB_NATIVE_JS_INVOCATION_SITES", "REB_NATIVE_JS_INVOCATION_DIGESTS", "REB_NATIVE_JS_INVOCATION_IF_SUPPORTED"]
    let invocationCases: [(String, [String: String], Bool, URL?, [String?])] = [
      ("content", [:], true, saved, [saved.path, "1", "1"]),
      ("metadata", [:], false, saved, [saved.path, "0", "1"]),
      ("nothing saved", [:], true, nil, [nil, nil, nil]),
      ("explicit digests off", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "0"], true, saved, [saved.path, "0", "1"]),
      ("explicit digests on", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"], false, saved, [saved.path, "1", "1"]),
      ("explicit sites", ["REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json"], true, saved, ["/explicit.json", nil, nil]),
      ("explicit sites off", ["REB_NATIVE_JS_INVOCATION_SITES": ""], true, saved, ["", nil, nil]),
      ("strict check kept", ["REB_NATIVE_JS_INVOCATION_IF_SUPPORTED": "0"], true, saved, [saved.path, "1", "0"]),
      ("no VM category", ["REB_CAPTURE_CATEGORY_MASK": "1280"], true, saved, [nil, nil, nil]),
      ("unreadable mask", ["REB_CAPTURE_CATEGORY_MASK": "0xzz"], true, saved, [nil, nil, nil]),
    ]
    for (name, given, content, url, expected) in invocationCases {
      let environment = LiveSessionCoordinator.captureDefaults(
        environment: given, captureNetworkContent: content, savedInvocationSites: url)
      precondition(invocationNames.map { environment[$0] } == expected, "invocation defaults: \(name) \(invocationNames.map { environment[$0] })")
    }
    print("PASS native live invocation sites: saved sites armed with digests in Content and without in Metadata, explicit sites and digests win, no VM category arms nothing")

    // The Swift store reads and writes exactly what the backend and browser do.
    let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    let fixture = try! JSONSerialization.jsonObject(with: Data(contentsOf: repository.appendingPathComponent(
      "tools/fixtures/native-js-invocation/site-cases.json"))) as! [String: Any]
    let files = (fixture["files"] as! [[String: Any]]).compactMap { $0["file"] as? String }
    precondition(files.count >= 2, "fixture files")
    for text in files {
      let sites = InvocationSiteSet.parse(text)
      precondition(sites != nil && InvocationSiteSet.file(sites!) == text, "fixture file round trip")
    }
    let file = files[0]
    for bad in ["", "{}", file.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.0"),
                file.replacingOccurrences(of: "function-entry", with: "dispatch"), " " + file,
                file.replacingOccurrences(of: "\"anchor_offset\":", with: "\"anchor_offset\":true,\"x\":")] {
      precondition(InvocationSiteSet.parse(bad) == nil, "refused site file \(bad.prefix(40))")
    }
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("reb-site-store-\(UUID().uuidString)/app")
    defer { try? FileManager.default.removeItem(at: folder.deletingLastPathComponent()) }
    let store = folder.appendingPathComponent(InvocationSiteSet.fileName)
    precondition(InvocationSiteSet.load(store) == .empty, "missing store is empty")
    var sites = InvocationSiteSet.parse(file)!
    sites[0].label = "window.hsw"
    sites[0].sourceURL = "https://example.test/glue.js"
    sites[0].sessionID = "11"
    try! InvocationSiteSet.write(sites, to: store)
    precondition((try? String(contentsOf: store, encoding: .utf8)) == file, "the site file is the browser's exact text")
    let mode = { (url: URL) in ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? NSNumber)?.intValue }
    precondition(mode(store) == 0o600 && mode(InvocationSiteSet.labelsURL(store)) == 0o600 && mode(folder) == 0o700, "user-only store")
    precondition(InvocationSiteSet.load(store) == .saved(sites), "labels round trip")
    try! InvocationSiteSet.write(Array(sites.dropFirst()), to: store)
    guard case .saved(let remaining) = InvocationSiteSet.load(store) else { preconditionFailure("removed one site") }
    precondition(remaining == Array(sites.dropFirst()) && remaining[0].label == "Unlabeled function", "remove keeps the rest")
    precondition(InvocationSiteSet.file(Array(repeating: sites[0], count: 2)) == nil, "duplicates refused")
    try! "{\"sites\":[],\"version\":1}".write(to: store, atomically: true, encoding: .utf8)
    precondition(InvocationSiteSet.load(store) == .unreadable, "an invalid file is unreadable, never armed")
    try! InvocationSiteSet.write([], to: store)
    precondition(!FileManager.default.fileExists(atPath: store.path) && InvocationSiteSet.load(store) == .empty, "clear removes the set")
    precondition(InvocationSiteSet.storeURL(environment: ["REB_JS_INVOCATION_SITE_STORE": "/a/b.json"], applicationSupport: folder).path == "/a/b.json"
      && InvocationSiteSet.storeURL(environment: [:], applicationSupport: folder) == store, "store location")
    print("PASS native saved invocation sites: the shared fixture's exact files, refused spellings, atomic user-only writes, labels, remove, unreadable and clear")
  }
}
