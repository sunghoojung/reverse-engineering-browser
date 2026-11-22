import Foundation

// Compile with the production coordinator, so these exercise its actual parser.
@main
enum LiveSessionFailureChecks {
  // Starts as the app does: resolve the content switches once from the mode
  // and the environment, take the session options from the environment (as a
  // launch with nothing saved does), then build the launcher's environment
  // from them.
  static func launch(
    _ environment: [String: String], content: Bool, sites: URL? = nil, chosen: Bool = false
  ) -> [String: String] {
    LiveSessionCoordinator.captureDefaults(
      environment: environment,
      content: LiveCaptureContent.resolve(
        environment: environment, mode: content ? .content : .metadata, modeChosen: chosen),
      options: LiveSessionOptions.configured(environment),
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
    // The launcher prints the session's store before it can end, and names a
    // clean Brave close as the cause with status 0.
    let endedFolder = URL(fileURLWithPath: "/owned/sessions/live/42", isDirectory: true)
    let started = "Evidence store: /owned/sessions/live/42/events.jsonl\n"
    let closedCause = "Brave was closed, so the live session ended. Its evidence stays in /owned/sessions/live/42."
    let closed = Data((started + prefix + closedCause + "\nLive session cleanup complete.\n").utf8)
    let next = { (phase: Coordinator.Phase, report: Coordinator.Report) in
      Coordinator.next(phase, after: report, logPath: "/owned/live.log")
    }
    let transitions: [(String, Coordinator.Phase, Coordinator.Report, Coordinator.Phase?)] = [
      ("handshake", .starting, .published(workspace), .ready(workspace)),
      ("exit during startup", .starting, .exited(log: marked, status: 1), .failed(.init(message: browser + log, afterStartup: false))),
      ("unmarked exit during startup", .starting, .exited(log: nil, status: 1), .failed(.init(message: fallback + log, afterStartup: false))),
      ("startup deadline", .starting, .timedOut(log: nil), .failed(.init(
        message: "Live capture did not become ready within 60 seconds. " + fallback + log, afterStartup: false))),
      ("exit after the handshake", .ready(workspace), .exited(log: marked, status: 1), .failed(.init(message: browser + log, afterStartup: true))),
      ("unmarked exit after the handshake", .ready(workspace), .exited(log: nil, status: 1),
        .failed(.init(message: Coordinator.sessionFallback + log, afterStartup: true))),
      ("a named end the researcher chose", .ready(workspace), .exited(log: closed, status: 0), .failed(.init(
        message: closedCause + log, afterStartup: true, sessionDirectory: endedFolder, endedNormally: true))),
      ("an unnamed clean exit is not a chosen end", .ready(workspace), .exited(log: nil, status: 0),
        .failed(.init(message: Coordinator.sessionFallback + log, afterStartup: true))),
      ("a fault names its folder too", .ready(workspace), .exited(log: Data((started + prefix + helper + "\n").utf8), status: 1),
        .failed(.init(message: helper + log, afterStartup: true, sessionDirectory: endedFolder))),
      ("stop while starting", .starting, .stopped, .ended),
      ("stop while ready", .ready(workspace), .stopped, .ended),
      ("second handshake", .ready(workspace), .published(workspace), nil),
      ("deadline after the handshake", .ready(workspace), .timedOut(log: nil), nil),
      ("exit after stop", .ended, .exited(log: marked, status: 1), nil),
      ("exit after a reported failure", .failed(.init(message: browser, afterStartup: false)), .exited(log: nil, status: 1), nil),
      ("handshake after stop", .ended, .published(workspace), nil),
      ("stop after a failure", .failed(.init(message: browser, afterStartup: true)), .stopped, nil),
      ("report before start", .idle, .published(workspace), nil),
    ]
    for (name, phase, report, expected) in transitions {
      precondition(next(phase, report) == expected, name)
    }
    for (text, expected) in [
      (started, endedFolder), ("Evidence store: /owned/a b/events.jsonl\n", URL(fileURLWithPath: "/owned/a b", isDirectory: true)),
      ("Evidence store: relative/events.jsonl\n", nil), ("Evidence store: /owned/events.json\n", nil),
      ("Evidence store: /events.jsonl\n", nil), ("nothing\n", nil),
    ] as [(String, URL?)] {
      precondition(Coordinator.sessionDirectory(in: Data(text.utf8)) == expected, "session folder \(text)")
    }
    precondition(Coordinator.sessionDirectory(in: nil) == nil, "no log names no folder")
    print("PASS native live session phases: handshake, startup failure, ended session with its folder, a chosen end apart from a fault, stop, and no report after the end")

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
    // An explicit setting wins in Content mode, even where the mask would not allow it.
    let explicit = launch(
      ["REB_CAPTURE_CATEGORY_MASK": "256", "REB_CAPTURE_REQUEST_CONTENT": "1", "REB_NATIVE_WASM_DISPATCH": "0"], content: true)
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

    // The start panel message SessionPanel.swift accepts only through
    // LivePanelStart.parse: the mode and nothing else. A Content session keeps
    // every body whole, so the removed budget and media keys are refused as
    // any other key is.
    let parse = { (body: [String: Any]) in LivePanelStart.parse(["op": "start"].merging(body) { _, given in given }) }
    let yes = NSNumber(value: true), no = NSNumber(value: false)
    precondition(parse(["mode": "metadata"]) == .success(LivePanelStart(mode: .metadata)), "metadata start")
    precondition(parse(["mode": "content"]) == .success(LivePanelStart(mode: .content)), "content start")
    let onlyMode = "The start panel offers only the capture mode."
    let startRefusals: [(String, [String: Any], String)] = [
      ("a removed request content budget", ["mode": "content", "request_content_budget_mib": NSNumber(value: 256)], onlyMode),
      ("a removed response body budget", ["mode": "content", "response_body_budget_mib": NSNumber(value: 512)], onlyMode),
      ("the removed media switch", ["mode": "content", "response_media": yes], onlyMode),
      ("a Keychain switch", ["mode": "metadata", "keychain": yes], onlyMode),
      ("an unknown mode", ["mode": "everything"], "Choose Content or Metadata only."),
      ("no mode", [:], "Choose Content or Metadata only."),
    ]
    for (name, body, message) in startRefusals {
      precondition(parse(body) == .failure(LivePanelStart.Refusal(message: message)), "refused start: \(name)")
    }
    // The panel's mode decides request content; an automatic launch keeps an
    // inherited value in Content mode and never in Metadata.
    let modeCases: [(String, [String: String], Bool, Bool, String)] = [
      ("a metadata start", [:], false, true, "0"),
      ("a chosen Content mode wins over an inherited 0", ["REB_CAPTURE_REQUEST_CONTENT": "0"], true, true, "1"),
      ("a chosen Metadata mode wins over an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"], false, true, "0"),
      ("an automatic Metadata launch drops an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"], false, false, "0"),
      ("an automatic Content launch keeps an inherited 1", ["REB_CAPTURE_REQUEST_CONTENT": "1"], true, false, "1"),
      ("an automatic launch keeps an inherited 0", ["REB_CAPTURE_REQUEST_CONTENT": "0"], true, false, "0"),
      ("a mask without Network and Artifact keeps hosts only", ["REB_CAPTURE_CATEGORY_MASK": "0x300"], true, true, "0"),
    ]
    for (name, given, content, chosen, expected) in modeCases {
      precondition(launch(given, content: content, chosen: chosen)["REB_CAPTURE_REQUEST_CONTENT"] == expected, "request content: \(name)")
    }
    precondition(LiveCaptureContent.resolve(environment: [:], mode: .content, modeChosen: true).retainsRequestContent, "content retains")
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
    let pressed = launch(optedOut, content: untouched.mode.capturesNetworkContent, chosen: true)
    precondition(untouched.mode == .metadata && pressed["REB_CAPTURE_REQUEST_CONTENT"] == "0",
      "Start pressed without touching the mode is a Metadata start")
    guard case .success(let chosen) = parse(["mode": "content"]) else { preconditionFailure("chosen content") }
    let content = launch(optedOut, content: chosen.mode.capturesNetworkContent, chosen: true)
    precondition(content["REB_CAPTURE_REQUEST_CONTENT"] == "1", "choosing Content there is a Content start")
    print("PASS native start panel: a start names only its mode, removed budget and media keys refused, the panel's mode deciding request content, and an inherited opt-out preselecting Metadata")

    // Saved invocation sites arm app-started captures. Digests follow the
    // mode and the session option, the launcher drops sites a Brave cannot
    // arm, and explicit sites win.
    let saved = URL(fileURLWithPath: "/private/tmp/origin-trace-live-x-js-invocation-sites.json")
    let invocationNames = ["REB_NATIVE_JS_INVOCATION_SITES", "REB_NATIVE_JS_INVOCATION_DIGESTS", "REB_NATIVE_JS_INVOCATION_IF_SUPPORTED"]
    let invocationCases: [(String, [String: String], Bool, URL?, [String?])] = [
      ("content", [:], true, saved, [saved.path, "1", "1"]),
      ("metadata", [:], false, saved, [saved.path, "0", "1"]),
      ("nothing saved", [:], true, nil, [nil, "0", nil]),
      ("explicit digests off", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "0"], true, saved, [saved.path, "0", "1"]),
      ("explicit digests on", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"], true, saved, [saved.path, "1", "1"]),
      ("explicit digests never reach Metadata", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1"], false, saved, [saved.path, "0", "1"]),
      ("nor with explicit sites", ["REB_NATIVE_JS_INVOCATION_DIGESTS": "1", "REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json"], false, saved,
        ["/explicit.json", "0", nil]),
      ("explicit sites", ["REB_NATIVE_JS_INVOCATION_SITES": "/explicit.json"], true, saved, ["/explicit.json", "1", nil]),
      ("explicit sites off", ["REB_NATIVE_JS_INVOCATION_SITES": ""], true, saved, ["", "0", nil]),
      ("strict check kept", ["REB_NATIVE_JS_INVOCATION_IF_SUPPORTED": "0"], true, saved, [saved.path, "1", "0"]),
      ("no VM category", ["REB_CAPTURE_CATEGORY_MASK": "1280"], true, saved, [nil, "0", nil]),
      ("unreadable mask", ["REB_CAPTURE_CATEGORY_MASK": "0xzz"], true, saved, [nil, "0", nil]),
    ]
    for (name, given, content, url, expected) in invocationCases {
      let environment = launch(given, content: content, sites: url)
      precondition(invocationNames.map { environment[$0] } == expected, "invocation defaults: \(name) \(invocationNames.map { environment[$0] })")
    }
    print("PASS native live invocation sites: saved sites armed with digests in Content and without in Metadata, explicit sites win, digests only with armed sites, no VM category arms nothing")

    // A Metadata start decides every content-derived switch, whatever the
    // environment holds: chosen in the panel or by REB_AUTOMATIC_CAPTURE_MODE,
    // with saved, explicit or no invocation sites. Each leak is listed.
    let metadataOff = ["REB_CAPTURE_REQUEST_CONTENT": "0", "REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]
    let everyContentSwitch = ["REB_CAPTURE_REQUEST_CONTENT": "1", "REB_CAPTURE_CANVAS_IMAGES": "1",
      "REB_NATIVE_JS_INVOCATION_DIGESTS": "1"]
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
    print("PASS native Metadata start: no request content, Canvas images or invocation digests, from the panel or the automatic launch, whatever the environment holds")

    // Retry gives the launcher the failed start's content switches, never a
    // new reading of the environment, so the mode the panel names is always
    // what the launcher got. The failed starts include the case
    // that leaked: an automatic Metadata launch with an inherited
    // REB_CAPTURE_REQUEST_CONTENT=1.
    let automaticMetadata = ["REB_AUTOMATIC_CAPTURE_MODE": "metadata", "REB_CAPTURE_REQUEST_CONTENT": "1"]
    let automaticContent = ["REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]
    let failedStarts: [(String, [String: String], LiveCaptureContent)] = [
      ("automatic Metadata with an inherited 1", automaticMetadata, LiveCaptureContent.resolve(
        environment: automaticMetadata, mode: LiveCaptureMode.configured(automaticMetadata), modeChosen: false)),
      ("panel Metadata over every content switch", everyContentSwitch, LiveCaptureContent.resolve(
        environment: everyContentSwitch, mode: .metadata, modeChosen: true)),
      ("panel Content", [:], LiveCaptureContent.resolve(environment: [:], mode: .content, modeChosen: true)),
      ("automatic Content with the environment's switches", automaticContent, LiveCaptureContent.resolve(
        environment: automaticContent, mode: LiveCaptureMode.configured(automaticContent), modeChosen: false)),
      ("panel Content with a mask without Network", ["REB_CAPTURE_CATEGORY_MASK": "0x600"], LiveCaptureContent.resolve(
        environment: ["REB_CAPTURE_CATEGORY_MASK": "0x600"], mode: .content, modeChosen: true)),
    ]
    let retryEnvironments: [(String, [String: String])] = [
      ("nothing", [:]), ("every content switch on", everyContentSwitch),
      ("every content switch off", ["REB_CAPTURE_REQUEST_CONTENT": "0", "REB_CAPTURE_CANVAS_IMAGES": "0", "REB_NATIVE_JS_INVOCATION_DIGESTS": "0"]),
    ]
    var mismatches: [String] = []
    for (name, given, failed) in failedStarts {
      let mask = given["REB_CAPTURE_CATEGORY_MASK"].map { ["REB_CAPTURE_CATEGORY_MASK": $0] } ?? [:]
      // Retry repeats the failed start's options as well (sessionPanel.options).
      let options = LiveSessionOptions.configured(given)
      let first = LiveSessionCoordinator.captureDefaults(environment: given, content: failed, options: options, savedInvocationSites: saved)
      let firstSwitches = LiveCaptureContent.names.map { first[$0] }
      // The panel's label: Metadata keeps nothing.
      if failed.mode == .metadata, LiveCaptureContent.names.contains(where: { first[$0] != metadataOff[$0] }) {
        mismatches.append("\(name): labeled \(failed.mode.title) but given \(firstSwitches)")
      }
      if failed.retainsRequestContent != (first["REB_CAPTURE_REQUEST_CONTENT"] == "1") {
        mismatches.append("\(name): request content \(failed.retainsRequestContent) but given \(first["REB_CAPTURE_REQUEST_CONTENT"] ?? "unset")")
      }
      for (retryName, environment) in retryEnvironments {
        let retried = LiveSessionCoordinator.captureDefaults(
          environment: environment.merging(mask) { a, _ in a }, content: failed, options: options, savedInvocationSites: saved)
        if LiveCaptureContent.names.map({ retried[$0] }) != firstSwitches {
          mismatches.append("\(name), Retry with \(retryName) inherited: \(LiveCaptureContent.names.map { retried[$0] }) after \(firstSwitches)")
        }
      }
    }
    precondition(mismatches.isEmpty, "Retry or its label differed from the failed start:\n" + mismatches.joined(separator: "\n"))
    print("PASS native live Retry: the failed start's content switches whatever the environment holds, and Metadata labels that keep nothing")

    // The start panel's session options: the defaults app sessions run with,
    // a start message checked for exactly the known names as booleans, and
    // launcher switches that are exactly the choice wherever the mask allows.
    let optionDefaults = LiveSessionOptions.defaults
    precondition(!optionDefaults.freshProfile && optionDefaults.requestStacks && !optionDefaults.promiseStacks
      && optionDefaults.wasmDispatch && optionDefaults.ignoreDebuggerStatements && optionDefaults.canvasImages
      && optionDefaults.invocationDigests && optionDefaults.documentStart && !optionDefaults.browserInternal
      && !optionDefaults.extensionTraffic, "session option defaults")
    let every = Dictionary(uniqueKeysWithValues: LiveSessionOptions.keys.map { ($0, yes as Any) })
    guard case .success(let allOn) = LiveSessionOptions.parse(every) else { preconditionFailure("every option on") }
    precondition(allOn.freshProfile && allOn.promiseStacks && allOn.browserInternal && allOn.extensionTraffic, "options parse")
    let optionRefusals: [(String, Any?)] = [
      ("missing", nil), ("not an object", "fresh"), ("one name missing", every.filter { $0.key != "fresh_profile" }),
      ("an unknown name", every.merging(["duration_seconds": yes]) { a, _ in a }),
      ("a number", every.merging(["fresh_profile": NSNumber(value: 1)]) { _, b in b }),
      ("text", every.merging(["wasm_dispatch": "true"]) { _, b in b }),
    ]
    for (name, value) in optionRefusals {
      guard case .failure = LiveSessionOptions.parse(value) else { preconditionFailure("options refused: \(name)") }
    }
    // Fresh profile is never saved, so a later app run starts in the research
    // profile; every other choice round trips.
    var allOnSaved = allOn
    allOnSaved.freshProfile = false
    precondition(allOn.stored["fresh_profile"] == nil && LiveSessionOptions(stored: allOn.stored) == allOnSaved
      && LiveSessionOptions(stored: ["fresh_profile": yes]) == optionDefaults
      && LiveSessionOptions(stored: ["wasm_dispatch": NSNumber(value: 0), "later": yes]) == optionDefaults,
      "a saved record keeps known booleans other than Fresh profile and defaults the rest")
    let state = optionDefaults.panelState["request_stacks"] as? [String: Any]
    precondition(state?["value"] as? Bool == true && state?["default"] as? Bool == true
      && optionDefaults.panelState.count == LiveSessionOptions.keys.count, "panel state")
    // Each environment switch seeds its option, and outranks a saved choice.
    var seeded = optionDefaults
    seeded.freshProfile = true
    seeded.wasmDispatch = false
    precondition(LiveSessionOptions.configured(["REB_FRESH_PROFILE": "1", "REB_NATIVE_WASM_DISPATCH": "0", "REB_CAPTURE_BROWSER_INTERNAL": "x"])
      == seeded, "environment seeds")
    precondition(LiveSessionOptions.configured([:], saved: allOn) == allOn
      && !LiveSessionOptions.configured(["REB_CAPTURE_EXTENSION_TRAFFIC": "0"], saved: allOn).extensionTraffic, "saved choices")
    let switchCases: [(UInt32, LiveSessionOptions, [String: String])] = [
      (4095, optionDefaults, ["REB_FRESH_PROFILE": "0", "REB_NATIVE_REQUEST_STACKS": "1", "REB_NATIVE_PROMISE_STACKS": "0",
        "REB_NATIVE_WASM_DISPATCH": "1", "REB_NATIVE_WASM_CALL_INDIRECT": "1", "REB_NATIVE_QUIET_MODE": "1",
        "REB_CONSOLE_DOCUMENT_START": "1", "REB_CAPTURE_BROWSER_INTERNAL": "0", "REB_CAPTURE_EXTENSION_TRAFFIC": "0"]),
      (4095, allOn, ["REB_FRESH_PROFILE": "1", "REB_NATIVE_REQUEST_STACKS": "1", "REB_NATIVE_PROMISE_STACKS": "1",
        "REB_CAPTURE_BROWSER_INTERNAL": "1", "REB_CAPTURE_EXTENSION_TRAFFIC": "1"]),
      // Promise stacks need request stacks, and both need Network and Artifact.
      (4095, LiveSessionOptions(stored: ["promise_stacks": yes, "request_stacks": no]),
        ["REB_NATIVE_REQUEST_STACKS": "0", "REB_NATIVE_PROMISE_STACKS": "0"]),
      (512 | 256, allOn, ["REB_NATIVE_REQUEST_STACKS": "0", "REB_NATIVE_PROMISE_STACKS": "0", "REB_NATIVE_WASM_DISPATCH": "0"]),
      (0, allOn, ["REB_NATIVE_WASM_DISPATCH": "0", "REB_NATIVE_WASM_CALL_INDIRECT": "0", "REB_NATIVE_QUIET_MODE": "1"]),
    ]
    for (mask, options, expected) in switchCases {
      let switches = options.launcherEnvironment(mask: mask)
      precondition(expected.allSatisfy { switches[$0.key] == $0.value }, "switches \(mask) \(switches)")
    }
    // Every option replaces an inherited switch, and the profile and duration
    // never come from the environment.
    let panelEnvironment = ["REB_NATIVE_REQUEST_STACKS": "0", "REB_FRESH_PROFILE": "1", "REB_CAPTURE_BROWSER_INTERNAL": "1"]
    let chosenDefaults = LiveSessionCoordinator.captureDefaults(
      environment: panelEnvironment, content: LiveCaptureContent.resolve(environment: panelEnvironment, mode: .content, modeChosen: true),
      options: optionDefaults)
    precondition(chosenDefaults["REB_NATIVE_REQUEST_STACKS"] == "1" && chosenDefaults["REB_FRESH_PROFILE"] == "0"
      && chosenDefaults["REB_CAPTURE_BROWSER_INTERNAL"] == "0", "the panel's options replace inherited switches")
    // call_indirect sites have no option of their own: an explicit 0 turns
    // off just them, and an inherited 1 never outlasts Wasm dispatch off.
    let callIndirect = { (inherited: String, options: LiveSessionOptions) -> [String: String] in
      let environment = ["REB_NATIVE_WASM_CALL_INDIRECT": inherited]
      return LiveSessionCoordinator.captureDefaults(
        environment: environment, content: LiveCaptureContent.resolve(environment: environment, mode: .content, modeChosen: true),
        options: options)
    }
    var wasmOff = optionDefaults
    wasmOff.wasmDispatch = false
    precondition(callIndirect("0", optionDefaults)["REB_NATIVE_WASM_CALL_INDIRECT"] == "0"
      && callIndirect("0", optionDefaults)["REB_NATIVE_WASM_DISPATCH"] == "1"
      && callIndirect("1", wasmOff)["REB_NATIVE_WASM_CALL_INDIRECT"] == "0", "call_indirect opt-out")
    // The saved mode applies unless the environment decides it.
    precondition(LiveCaptureMode.configured([:], saved: .metadata) == .metadata
      && LiveCaptureMode.configured(["REB_AUTOMATIC_CAPTURE_MODE": "content"], saved: .metadata) == .content
      && LiveCaptureMode.configured(["REB_CAPTURE_REQUEST_CONTENT": "0"], saved: .content) == .metadata, "saved mode")
    let profiles = URL(fileURLWithPath: "/owned/Origin Trace", isDirectory: true)
    precondition(LiveSessionOptions.researchProfile(environment: [:], originTrace: profiles, systemKeychain: false).path
      == "/owned/Origin Trace/research-profiles/default"
      && LiveSessionOptions.researchProfile(environment: [:], originTrace: profiles, systemKeychain: true).path
      == "/owned/Origin Trace/research-profiles/system-keychain"
      && LiveSessionOptions.researchProfile(environment: ["REB_RESEARCH_PROFILE_ROOT": "/owned/p"], originTrace: profiles, systemKeychain: false).path
      == "/owned/p/default", "one research profile per Keychain mode, under an explicit root when one is set")
    precondition(RecordedSession.root(environment: [:], originTrace: profiles).path == "/owned/Origin Trace/sessions/live"
      && RecordedSession.root(environment: ["REB_LIVE_SESSION_ROOT": "/owned/s"], originTrace: profiles).path == "/owned/s", "session root")
    print("PASS native session options: defaults, exact start messages, environment seeds over saved choices, switches only where the mask allows, inherited switches replaced, the saved mode, and one research profile per Keychain mode")

    // The panel's choices survive an app run in a user-only file; anything
    // unreadable starts from the defaults.
    let preferenceFolder = FileManager.default.temporaryDirectory.appendingPathComponent("reb-session-preferences-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: preferenceFolder) }
    let preferenceStore = preferenceFolder.appendingPathComponent("app/" + LiveSessionPreferences.fileName)
    precondition(LiveSessionPreferences.load(preferenceStore) == LiveSessionPreferences(), "missing preferences")
    let remembered = LiveSessionPreferences(mode: .metadata, options: allOn)
    try! remembered.write(to: preferenceStore)
    precondition(LiveSessionPreferences.load(preferenceStore) == LiveSessionPreferences(mode: .metadata, options: allOnSaved),
      "preferences round trip, without Fresh profile")
    let fileMode = ((try? FileManager.default.attributesOfItem(atPath: preferenceStore.path))?[.posixPermissions] as? NSNumber)?.intValue
    precondition(fileMode == 0o600, "user-only preferences")
    for bad in ["", "[]", "{\"version\":2,\"mode\":\"metadata\"}", "{\"mode\":\"metadata\"}"] {
      try! bad.write(to: preferenceStore, atomically: true, encoding: .utf8)
      precondition(LiveSessionPreferences.load(preferenceStore) == LiveSessionPreferences(), "unreadable preferences \(bad)")
    }
    try! "{\"version\":1,\"mode\":\"everything\",\"options\":{\"fresh_profile\":true,\"wasm_dispatch\":false}}".write(to: preferenceStore, atomically: true, encoding: .utf8)
    precondition(LiveSessionPreferences.load(preferenceStore)
      == LiveSessionPreferences(mode: nil, options: LiveSessionOptions(stored: ["wasm_dispatch": no])), "partly readable preferences")
    precondition(LiveSessionPreferences.load(preferenceStore).options?.freshProfile == false, "a saved Fresh profile is ignored")
    precondition(LiveSessionPreferences.storeURL(environment: ["REB_LIVE_SESSION_PREFERENCES": "/a/p.json"], applicationSupport: preferenceFolder).path == "/a/p.json"
      && LiveSessionPreferences.storeURL(environment: [:], applicationSupport: preferenceFolder).lastPathComponent == LiveSessionPreferences.fileName,
      "preferences location")
    print("PASS native saved start choices: round trip without Fresh profile, user-only file, unreadable or other-version files ignored, unknown values defaulted, explicit location")

    // Open Recent Session lists recorded sessions newest first and leaves out
    // one a broker still writes.
    let sessionRoot = preferenceFolder.appendingPathComponent("sessions/live", isDirectory: true)
    for (name, events) in [("1", true), ("2", true), ("3", false), ("4", true)] {
      let session = sessionRoot.appendingPathComponent(name, isDirectory: true)
      try! FileManager.default.createDirectory(at: session, withIntermediateDirectories: true)
      if events { FileManager.default.createFile(atPath: session.appendingPathComponent("events.jsonl").path, contents: Data()) }
      Thread.sleep(forTimeInterval: 0.02)
    }
    precondition(RecordedSession.recent(in: sessionRoot, limit: 10).map(\.folder.lastPathComponent) == ["4", "2", "1"], "newest first")
    precondition(RecordedSession.recent(in: sessionRoot, limit: 2).count == 2 && RecordedSession.at(sessionRoot.appendingPathComponent("3")) == nil,
      "a limit, and a folder without an event store is no session")
    let guardURL = sessionRoot.appendingPathComponent("4/events.jsonl.reb-lock-v1")
    FileManager.default.createFile(atPath: guardURL.path, contents: Data())
    let holder = open(guardURL.path, O_RDONLY | O_CLOEXEC)
    precondition(holder >= 0 && flock(holder, LOCK_EX | LOCK_NB) == 0, "hold the broker guard")
    // flock leases belong to the open file description, so this process's own
    // second open is refused just as the app's would be.
    precondition(RecordedSession.recording(sessionRoot.appendingPathComponent("4")), "a held guard is recording")
    precondition(RecordedSession.recent(in: sessionRoot, limit: 10).map(\.folder.lastPathComponent) == ["2", "1"], "a recording session is left out")
    close(holder)
    precondition(!RecordedSession.recording(sessionRoot.appendingPathComponent("4"))
      && !RecordedSession.recording(sessionRoot.appendingPathComponent("1")), "a released or missing guard is not recording")
    let titled = RecordedSession(folder: sessionRoot, started: Date(timeIntervalSince1970: 0), lastWritten: Date(timeIntervalSince1970: 4_560))
    // The duration words follow the locale; its numbers do not.
    precondition(titled.title.hasSuffix(")") && titled.title.contains("16"), "menu title \(titled.title)")
    print("PASS native recorded sessions: newest first, folders without an event store skipped, a session still recording left out, menu titles")

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
