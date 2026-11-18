import Foundation

// The start panel's session options beyond the capture mode and content
// limits: the browser profile and the native switches the launcher otherwise
// reads only from the environment (scripts/run-live-session.sh). The page sends
// them as one `options` object of booleans, checked here; native turns them
// into launcher switches. A switch whose categories the mask lacks stays off,
// as the defaults always have, instead of failing the launch.
struct LiveSessionOptions: Equatable {
  // A new, empty browser profile for one session instead of the persistent
  // research profile.
  var freshProfile = false
  var requestStacks = true
  // Promise registration stacks, off by default for their cost; they need
  // request stacks (protocol/native-network-v3.md, Promise registrations).
  var promiseStacks = false
  // Wasm br_table and call_indirect sampling. It forces Liftoff-only
  // compilation, so a researcher timing a Wasm-heavy page can turn it off.
  var wasmDispatch = true
  var ignoreDebuggerStatements = true
  // Content-mode capture: a Metadata session records neither.
  var canvasImages = true
  var invocationDigests = true
  // Permission only: arming a document-start Console script stays a separate
  // confirmed action in a live Console connection.
  var documentStart = true
  // Browser-internal pages and extension workers are counted, not recorded,
  // unless these are on (protocol/native-network-v3.md).
  var browserInternal = false
  var extensionTraffic = false

  static let defaults = LiveSessionOptions()

  struct Refusal: Error, Equatable {
    let message: String
  }

  // The page's names, in the order the panel lists them, with the field each
  // one sets and the environment switch it seeds from.
  private static let fields: [(key: String, path: WritableKeyPath<LiveSessionOptions, Bool>, seed: String)] = [
    ("fresh_profile", \.freshProfile, "REB_FRESH_PROFILE"),
    ("request_stacks", \.requestStacks, "REB_NATIVE_REQUEST_STACKS"),
    ("promise_stacks", \.promiseStacks, "REB_NATIVE_PROMISE_STACKS"),
    ("wasm_dispatch", \.wasmDispatch, "REB_NATIVE_WASM_DISPATCH"),
    ("ignore_debugger_statements", \.ignoreDebuggerStatements, "REB_NATIVE_QUIET_MODE"),
    ("canvas_images", \.canvasImages, "REB_CAPTURE_CANVAS_IMAGES"),
    ("invocation_digests", \.invocationDigests, "REB_NATIVE_JS_INVOCATION_DIGESTS"),
    ("document_start", \.documentStart, "REB_CONSOLE_DOCUMENT_START"),
    ("browser_internal", \.browserInternal, "REB_CAPTURE_BROWSER_INTERNAL"),
    ("extension_traffic", \.extensionTraffic, "REB_CAPTURE_EXTENSION_TRAFFIC"),
  ]
  static let keys = fields.map(\.key)

  // What a launch starts from: the choices the start panel last saved, else
  // the defaults, with each switch the app environment sets to 0 or 1 in
  // their place, as an explicit launch setting.
  static func configured(_ environment: [String: String], saved: LiveSessionOptions? = nil) -> LiveSessionOptions {
    var options = saved ?? defaults
    for field in fields {
      switch environment[field.seed] {
      case "1": options[keyPath: field.path] = true
      case "0": options[keyPath: field.path] = false
      default: break
      }
    }
    return options
  }

  // A start message's options: exactly the known names, each true or false.
  // JSON numbers and booleans both arrive as NSNumber, so a number is never
  // read as a choice.
  static func parse(_ value: Any?) -> Result<LiveSessionOptions, Refusal> {
    guard let object = value as? [String: Any], Set(object.keys) == Set(keys) else {
      return .failure(Refusal(message: "The start panel must name every session option."))
    }
    var options = defaults
    for field in fields {
      guard let number = object[field.key] as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
        return .failure(Refusal(message: "Each session option must be on or off."))
      }
      options[keyPath: field.path] = number.boolValue
    }
    return .success(options)
  }

  // What the page draws: each value with its default.
  var panelState: [String: Any] {
    Dictionary(uniqueKeysWithValues: Self.fields.map {
      ($0.key, ["value": self[keyPath: $0.path], "default": Self.defaults[keyPath: $0.path]] as [String: Any])
    })
  }

  // Fresh profile is a choice for this app run only. Saved, it would start
  // every later run's automatic session signed out, with no panel on screen
  // to show why.
  private static let savedFields = fields.filter { $0.key != "fresh_profile" }

  var stored: [String: Bool] {
    Dictionary(uniqueKeysWithValues: Self.savedFields.map { ($0.key, self[keyPath: $0.path]) })
  }

  // A saved record: a known name with a boolean value is taken, anything else
  // keeps its default, so a file from another version still loads.
  init(stored: [String: Any]) {
    for field in Self.savedFields {
      if let number = stored[field.key] as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() {
        self[keyPath: field.path] = number.boolValue
      }
    }
  }

  init() {}

  // The launcher switches for these choices, other than the two content
  // switches (canvas images and invocation digests), which need the mode and
  // the armed sites and are set by LiveSessionCoordinator.captureDefaults.
  // `mask` is the session's category mask. Each value replaces any inherited
  // one, so the session is what the panel names.
  func launcherEnvironment(mask: UInt32) -> [String: String] {
    let allows = { (required: UInt32) in mask & required == required }
    let on = { (value: Bool) in value ? "1" : "0" }
    // Request stacks need Network (256) and Artifact (1024). A Brave that
    // predates the flag drops it with a launch log line, since the panel
    // cannot change the browser.
    let stacks = requestStacks && allows(1280)
    // Wasm dispatch needs VM (512) and Artifact (1024).
    let wasm = wasmDispatch && allows(1536)
    return [
      "REB_FRESH_PROFILE": on(freshProfile),
      "REB_NATIVE_REQUEST_STACKS": on(stacks),
      "REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED": "1",
      "REB_NATIVE_PROMISE_STACKS": on(stacks && promiseStacks),
      "REB_NATIVE_WASM_DISPATCH": on(wasm),
      "REB_NATIVE_WASM_CALL_INDIRECT": on(wasm),
      "REB_NATIVE_QUIET_MODE": on(ignoreDebuggerStatements),
      "REB_CONSOLE_DOCUMENT_START": on(documentStart),
      "REB_CAPTURE_BROWSER_INTERNAL": on(browserInternal),
      "REB_CAPTURE_EXTENSION_TRAFFIC": on(extensionTraffic),
    ]
  }

  // Where the launcher keeps the persistent research profiles for app
  // sessions: one per Keychain mode, because cookies encrypted under one
  // cannot be read under the other. An explicit REB_RESEARCH_PROFILE_ROOT
  // wins, as it does for the launcher.
  static func researchProfileRoot(environment: [String: String], originTrace: URL) -> URL {
    if let path = environment["REB_RESEARCH_PROFILE_ROOT"], !path.isEmpty {
      return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
    }
    return originTrace.appendingPathComponent("research-profiles", isDirectory: true)
  }

  static func researchProfile(environment: [String: String], originTrace: URL, systemKeychain: Bool) -> URL {
    researchProfileRoot(environment: environment, originTrace: originTrace)
      .appendingPathComponent(systemKeychain ? "system-keychain" : "default", isDirectory: true)
  }
}

// The start panel's last choices, saved for the next app run: the capture
// mode and the session options other than Fresh profile. The content limits
// are not saved. A file the app cannot read is ignored, and the panel starts
// from the environment and the defaults instead.
struct LiveSessionPreferences: Equatable {
  var mode: LiveCaptureMode?
  var options: LiveSessionOptions?

  static let fileName = "live-session-preferences-v1.json"

  // An explicit REB_LIVE_SESSION_PREFERENCES wins, as for the other app stores.
  static func storeURL(environment: [String: String], applicationSupport: URL) -> URL {
    if let path = environment["REB_LIVE_SESSION_PREFERENCES"], !path.isEmpty {
      return URL(fileURLWithPath: path).standardizedFileURL
    }
    return applicationSupport.appendingPathComponent(fileName)
  }

  static func load(_ url: URL) -> LiveSessionPreferences {
    guard let data = try? Data(contentsOf: url),
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      (object["version"] as? NSNumber)?.intValue == 1
    else { return LiveSessionPreferences() }
    return LiveSessionPreferences(
      mode: (object["mode"] as? String).flatMap(LiveCaptureMode.init(rawValue:)),
      options: (object["options"] as? [String: Any]).map(LiveSessionOptions.init(stored:)))
  }

  func write(to url: URL) throws {
    var object: [String: Any] = ["version": 1]
    if let mode { object["mode"] = mode.rawValue }
    if let options { object["options"] = options.stored }
    try InvocationSiteSet.writePrivate(
      try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), to: url)
  }
}
