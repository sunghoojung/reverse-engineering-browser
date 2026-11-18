import Foundation

// Compile with the production coordinator, so these exercise its actual parser.
@main
enum LiveSessionFailureChecks {
  // Starts as the app does: resolve the content switches once from the mode,
  // the panel's limits and the environment, then build the launcher's
  // environment from them.
  static func launch(
    _ environment: [String: String], content: Bool, sites: URL? = nil, limits: ContentLimits? = nil, chosen: Bool = false
  ) -> [String: String] {
    LiveSessionCoordinator.captureDefaults(
      environment: environment,
      content: LiveCaptureContent.resolve(
        environment: environment, mode: content ? .content : .metadata, limits: limits, modeChosen: chosen),
      savedInvocationSites: sites)
  }

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
      launch(mask.map { ["REB_CAPTURE_CATEGORY_MASK": $0] } ?? [:], content: content)
    }
    let names = [
      "REB_CAPTURE_CANVAS_IMAGES", "REB_CAPTURE_REQUEST_CONTENT", "REB_NATIVE_WASM_DISPATCH",
      "REB_NATIVE_WASM_CALL_INDIRECT", "REB_NATIVE_REQUEST_STACKS", "REB_NATIVE_PROMISE_STACKS",
    ]
    let defaultCases: [(String?, Bool, [String])] = [
      (nil, true, ["1", "1", "1", "1", "1", "1"]), (nil, false, ["0", "0", "1", "1", "1", "1"]),
      ("0x500", true, ["0", "1", "0", "0", "1", "1"]), ("0x300", true, ["0", "0", "0", "0", "0", "0"]),
      ("768", true, ["0", "0", "0", "0", "0", "0"]), ("1025", true, ["1", "0", "0", "0", "0", "0"]),
      ("0x7ff", true, ["1", "1", "1", "1", "1", "1"]), ("0xzz", true, ["0", "0", "0", "0", "0", "0"]),
      (" 4095", true, ["0", "0", "0", "0", "0", "0"]),
    ]
    for (mask, content, expected) in defaultCases {
      let environment = defaults(mask, content)
      precondition(names.map { environment[$0] } == expected, "defaults \(String(describing: mask)) content=\(content)")
      precondition(environment["REB_NATIVE_QUIET_MODE"] == "1", "quiet mode default")
    }
    // An explicit setting wins in Content mode, even where the mask would not allow it.
    let explicit = launch(
      ["REB_CAPTURE_CATEGORY_MASK": "256", "REB_CAPTURE_REQUEST_CONTENT": "1", "REB_NATIVE_WASM_DISPATCH": "0"], content: true)
    precondition(explicit["REB_CAPTURE_REQUEST_CONTENT"] == "1" && explicit["REB_NATIVE_WASM_DISPATCH"] == "0", "explicit values")
    // An explicit promise stacks choice wins; explicit request stacks leave it to the launcher's default.
    precondition(launch(["REB_NATIVE_PROMISE_STACKS": "0"], content: true)["REB_NATIVE_PROMISE_STACKS"] == "0", "explicit promise stacks")
    precondition(launch(["REB_NATIVE_REQUEST_STACKS": "0"], content: true)["REB_NATIVE_PROMISE_STACKS"] == nil, "promise stacks follow request stacks")
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
      launch([:], content: mode.capturesNetworkContent)
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
      let explicitStart = launch(["REB_CONSOLE_DOCUMENT_START": value], content: true)
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
      let environment = launch(given, content: content, limits: limits)
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
      ("an automatic Metadata launch drops an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"].merging(media) { a, _ in a }, false, false,
        nil, "0", [nil, nil, nil]),
      ("an automatic Content launch keeps an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"].merging(media) { a, _ in a }, true, false,
        nil, "1", ["999", "99", "1"]),
      ("an automatic launch keeps an inherited 0 and drops the rest", ["REB_CAPTURE_REQUEST_CONTENT": "0"].merging(media) { a, _ in a }, true, false,
        raised, "0", [nil, nil, nil]),
    ]
    for (name, given, content, chosen, limits, expectedContent, expected) in modeCases {
      let environment = launch(given, content: content, limits: limits, chosen: chosen)
      precondition(environment["REB_CAPTURE_REQUEST_CONTENT"] == expectedContent, "request content: \(name)")
      precondition(limitNames.map { environment[$0] } == expected, "content switches: \(name) \(limitNames.map { environment[$0] })")
    }
    let panelContent = { (given: [String: String]) in
      LiveCaptureContent.resolve(environment: given, mode: .content, limits: raised, modeChosen: true)
    }
    precondition(panelContent([:]).retainsRequestContent && panelContent([:]).limits == raised, "content retains")
    let hostsOnly = panelContent(["REB_CAPTURE_CATEGORY_MASK": "0x300"])
    precondition(!hostsOnly.retainsRequestContent && hostsOnly.limits == nil,
      "a mask without Network and Artifact retains nothing, so the panel names no limits")
    precondition(panelContent(["REB_CAPTURE_REQUEST_CONTENT": "0"]).retainsRequestContent,
      "a chosen Content mode retains content over an inherited 0")
    // An inherited REB_CAPTURE_REQUEST_CONTENT=0 still protects someone who
    // just presses Start: the panel preselects Metadata and says why, and only
    // choosing Content there captures content.
    let optedOut = ["REB_CAPTURE_REQUEST_CONTENT": "0"]
    precondition(LiveCaptureMode.configured(optedOut) == .metadata, "an inherited 0 preselects Metadata")
    precondition(LiveCaptureMode.configured(optedOut.merging(["REB_AUTOMATIC_CAPTURE_MODE": "content"]) { a, _ in a }) == .metadata,
      "an inherited 0 wins over REB_AUTOMATIC_CAPTURE_MODE=content")
    precondition(LiveCaptureMode.configured(["REB_CAPTURE_REQUEST_CONTENT": "1"]) == .content, "an inherited 1 keeps the default")
    precondition(LiveCaptureMode.requestContentOptedOut(optedOut) && !LiveCaptureMode.requestContentOptedOut([:]), "opt-out")
    precondition(LiveCaptureMode.optOutNote.contains("Metadata is preselected"), "the panel says why")
    let preselected = LiveCaptureMode.configured(optedOut)
    guard case .success(let untouched) = parse(["mode": preselected.rawValue]) else { preconditionFailure("preselected start") }
    let pressed = launch(optedOut.merging(media) { a, _ in a }, content: untouched.mode.capturesNetworkContent,
      limits: untouched.limits, chosen: true)
    precondition(untouched.mode == .metadata && pressed["REB_CAPTURE_REQUEST_CONTENT"] == "0"
      && limitNames.allSatisfy({ pressed[$0] == nil }), "Start pressed without touching the mode is a Metadata start")
    guard case .success(let chosen) = parse(["mode": "content", "request_content_budget_mib": NSNumber(value: 256),
      "response_body_budget_mib": NSNumber(value: 512), "response_media": no]) else { preconditionFailure("chosen content") }
    let content = launch(optedOut, content: chosen.mode.capturesNetworkContent, limits: chosen.limits, chosen: true)
    precondition(content["REB_CAPTURE_REQUEST_CONTENT"] == "1" && content["REB_REQUEST_CONTENT_BUDGET_MIB"] == "256",
      "choosing Content there is a Content start")
    print("PASS native content limits: the launcher's bounds and grammar for the panel's first values, start messages checked as the agent path checks them, launcher switches only for a session that retains content, inherited content-only switches dropped otherwise, the panel's mode deciding request content, and an inherited opt-out preselecting Metadata")

    // Saved invocation sites arm app-started captures, which follow the saved
    // set. Digests follow the mode, the launcher drops sites a Brave cannot
    // arm, and explicit values win.
    let saved = URL(fileURLWithPath: "/private/tmp/origin-trace-live-x-js-invocation-sites.json")
    let invocationNames = ["REB_NATIVE_JS_INVOCATION_SITES", "REB_NATIVE_JS_INVOCATION_DIGESTS",
      "REB_NATIVE_JS_INVOCATION_IF_SUPPORTED", "REB_NATIVE_JS_INVOCATION_LIVE"]
    let invocationCases: [(String, [String: String], Bool, URL?, [String?])] = [
      ("content", [:], true, saved, [saved.path, "1", "1", "1"]),
      ("metadata", [:], false, saved, [saved.path, "0", "1", "1"]),
      ("no copy", [:], true, nil, [nil, nil, nil, nil]),
      ("explicit digests off", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "0"], true, saved, [saved.path, "0", "1", "1"]),
      ("explicit digests on", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"], true, saved, [saved.path, "1", "1", "1"]),
      ("explicit digests never reach Metadata", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"], false, saved, [saved.path, "0", "1", "1"]),
      ("nor with explicit sites", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1", "REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json"], false, saved,
        ["/explicit.json", "0", nil, nil]),
      ("explicit sites", ["REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json"], true, saved, ["/explicit.json", nil, nil, nil]),
      ("explicit sites off", ["REB_NATIVE_JS_INVOCATION_SITES": ""], true, saved, ["", nil, nil, nil]),
      ("strict check kept", ["REB_NATIVE_JS_INVOCATION_IF_SUPPORTED": "0"], true, saved, [saved.path, "1", "0", "1"]),
      ("following opted out", ["REB_NATIVE_JS_INVOCATION_LIVE": "0"], true, saved, [saved.path, "1", "1", "0"]),
      ("no VM category", ["REB_CAPTURE_CATEGORY_MASK": "1280"], true, saved, [nil, nil, nil, nil]),
      ("unreadable mask", ["REB_CAPTURE_CATEGORY_MASK": "0xzz"], true, saved, [nil, nil, nil, nil]),
    ]
    for (name, given, content, url, expected) in invocationCases {
      let environment = launch(given, content: content, sites: url)
      precondition(invocationNames.map { environment[$0] } == expected, "invocation defaults: \(name) \(invocationNames.map { environment[$0] })")
    }
    print("PASS native live invocation sites: saved sites armed and followed, with digests in Content and without in Metadata, explicit sites and Content digests win, no VM category arms nothing")

    // A Metadata start decides every content-derived switch, whatever the
    // environment holds: chosen in the panel or by REB_AUTOMATIC_CAPTURE_MODE,
    // with saved, explicit or no invocation sites. Each leak is listed.
    let metadataOff = ["REB_CAPTURE_REQUEST_CONTENT": "0", "REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]
    let everyContentSwitch = ["REB_CAPTURE_REQUEST_CONTENT": "1", "REB_CAPTURE_CANVAS_IMAGES": "1",
      "REB_NATIVE_JS_INVOCATION_DIGESTS": "1"].merging(media) { a, _ in a }
    let inheritedCases: [(String, [String: String])] = [
      ("nothing", [:]),
      ("request content", ["REB_CAPTURE_REQUEST_CONTENT": "1"]),
      ("Canvas images", ["REB_CAPTURE_CANVAS_IMAGES": "1"]),
      ("invocation digests", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"]),
      ("explicit sites and digests", ["REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json", "REB_NATIVE_JS_INVOCATION_DIGESTS": "1"]),
      ("every content switch", everyContentSwitch),
    ]
    var leaks: [String] = []
    for (name, given) in inheritedCases {
      for (start, chosen) in [("panel", true), ("automatic", false)] {
        // The automatic launch's Metadata comes from the app environment.
        let environment = chosen ? given : given.merging(["REB_AUTOMATIC_CAPTURE_MODE": "metadata"]) { a, _ in a }
        let mode = chosen ? LiveCaptureMode.metadata : LiveCaptureMode.configured(environment)
        for sites in [saved, nil] as [URL?] {
          let launched = launch(environment, content: mode.capturesNetworkContent, sites: sites, chosen: chosen)
          for key in LiveCaptureContent.names where launched[key] != metadataOff[key] {
            leaks.append("\(start) Metadata start, inherited \(name), \(sites == nil ? "no" : "saved") sites: \(key)=\(launched[key] ?? "unset")")
          }
        }
      }
    }
    precondition(leaks.isEmpty, "Metadata starts were given content-derived switches:\n" + leaks.joined(separator: "\n"))
    print("PASS native Metadata start: no request content, Canvas images, invocation digests, budgets or media, from the panel or the automatic launch, whatever the environment holds")

    // Retry gives the launcher the failed start's content switches, never a
    // new reading of the environment, so the mode and limits the panel names
    // are always what the launcher got. The failed starts include the case
    // that leaked: an automatic Metadata launch with an inherited
    // REB_CAPTURE_REQUEST_CONTENT=1.
    let automaticMetadata = ["REB_AUTOMATIC_CAPTURE_MODE": "metadata", "REB_CAPTURE_REQUEST_CONTENT": "1"]
    let automaticContent = ["REB_REQUEST_CONTENT_BUDGET_MIB": "64", "REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]
    let failedStarts: [(String, [String: String], LiveCaptureContent)] = [
      ("automatic Metadata with an inherited 1", automaticMetadata, LiveCaptureContent.resolve(
        environment: automaticMetadata, mode: LiveCaptureMode.configured(automaticMetadata), limits: nil, modeChosen: false)),
      ("panel Metadata over every content switch", everyContentSwitch, LiveCaptureContent.resolve(
        environment: everyContentSwitch, mode: .metadata, limits: nil, modeChosen: true)),
      ("panel Content with raised limits", media, LiveCaptureContent.resolve(environment: media, mode: .content, limits: raised, modeChosen: true)),
      ("automatic Content with the environment's limits", automaticContent, LiveCaptureContent.resolve(
        environment: automaticContent, mode: LiveCaptureMode.configured(automaticContent), limits: nil, modeChosen: false)),
      ("panel Content with a mask without Network", ["REB_CAPTURE_CATEGORY_MASK": "0x600"], LiveCaptureContent.resolve(
        environment: ["REB_CAPTURE_CATEGORY_MASK": "0x600"], mode: .content, limits: raised, modeChosen: true)),
    ]
    let retryEnvironments: [(String, [String: String])] = [
      ("nothing", [:]), ("every content switch on", everyContentSwitch),
      ("every content switch off", ["REB_CAPTURE_REQUEST_CONTENT": "0", "REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]),
    ]
    var mismatches: [String] = []
    for (name, given, failed) in failedStarts {
      let mask = given["REB_CAPTURE_CATEGORY_MASK"].map { ["REB_CAPTURE_CATEGORY_MASK": $0] } ?? [:]
      let first = LiveSessionCoordinator.captureDefaults(environment: given, content: failed, savedInvocationSites: saved)
      let firstSwitches = LiveCaptureContent.names.map { first[$0] }
      // The panel's label: Metadata keeps nothing, and named limits are the ones given.
      if failed.mode == .metadata, LiveCaptureContent.names.contains(where: { first[$0] != metadataOff[$0] }) {
        mismatches.append("\(name): labeled \(failed.mode.title) but given \(firstSwitches)")
      }
      if failed.retainsRequestContent != (first["REB_CAPTURE_REQUEST_CONTENT"] == "1") {
        mismatches.append("\(name): request content \(failed.retainsRequestContent) but given \(first["REB_CAPTURE_REQUEST_CONTENT"] ?? "unset")")
      }
      if let limits = failed.limits, limits.launcherEnvironment.contains(where: { first[$0.key] != $0.value }) {
        mismatches.append("\(name): names limits \(limits) but given \(firstSwitches)")
      }
      for (retryName, environment) in retryEnvironments {
        let retried = LiveSessionCoordinator.captureDefaults(
          environment: environment.merging(mask) { a, _ in a }, content: failed, savedInvocationSites: saved)
        if LiveCaptureContent.names.map({ retried[$0] }) != firstSwitches {
          mismatches.append("\(name), Retry with \(retryName) inherited: \(LiveCaptureContent.names.map { retried[$0] }) after \(firstSwitches)")
        }
      }
    }
    precondition(mismatches.isEmpty, "Retry or its label differed from the failed start:\n" + mismatches.joined(separator: "\n"))
    print("PASS native live Retry: the failed start's content switches whatever the environment holds, Metadata labels that keep nothing and named limits that were given")

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
