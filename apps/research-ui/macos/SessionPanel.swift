import Cocoa
import WebKit

// The native half of the in-window live session panel. The page draws the
// choices; this side decides what the panel shows, accepts a choice only while
// that decision is open, validates the capture mode, and keeps the saved
// invocation sites the next capture arms. As with the agent bridge, only the
// exact main document the app loaded can ask. The page has no Keychain
// choice: a session it starts or retries always uses the isolated profile.
// A Content start also names its content limits (ContentLimits), checked here
// as the agent path checks them; a Metadata start names none.
//
// Site labels and source URLs reach the page only to be drawn as text, as the
// backend's saved-site route already serves them to the live workspace. The
// page sends back an index, never a URL, and nothing here logs or stores them.
@MainActor
final class NativeSessionPanel: NSObject, WKScriptMessageHandlerWithReply {
  static let handlerName = "rebSession"

  // What the panel shows. Choose and Failed are open decisions: until one is
  // answered nothing starts a session behind it. Choose offers `limits` for a
  // Content session; Starting and Failed carry the limits the panel chose, or
  // nil for a session it did not start, whose limits are the environment's.
  enum Content: Equatable {
    case hidden
    case choose(mode: LiveCaptureMode, limits: ContentLimits)
    case starting(mode: LiveCaptureMode, limits: ContentLimits?)
    case failed(LiveSessionCoordinator.Failure, mode: LiveCaptureMode, limits: ContentLimits?)
  }

  enum Choice {
    // The limits are present exactly for a Content start.
    case start(LiveCaptureMode, ContentLimits?)
    case retry
    case offline
  }

  var content = Content.hidden {
    didSet {
      guard content != oldValue else { return }
      answered = false
      if case .choose = content, !isChoosing(oldValue) { reloadSites() }
      publish()
    }
  }

  var decisionOpen: Bool {
    switch content {
    case .choose, .failed: return true
    case .hidden, .starting: return false
    }
  }

  // Called after the reply, so a choice that replaces the document never
  // answers a page that is already leaving.
  var decide: ((Choice) -> Void)?

  private weak var webView: WKWebView?
  private let siteStoreURL: URL
  private var trustedURL: URL?
  private var documentReady = false
  private var sites = InvocationSiteSet.State.empty
  // Counts reads of the site file, so a Remove names the list the page saw.
  private var siteGeneration = 0
  private var siteNotice: String?
  // A choice was accepted for the decision on screen; a second click or a
  // second page cannot answer it again before the app acts on the first.
  private var answered = false

  init(webView: WKWebView, siteStoreURL: URL) {
    self.webView = webView
    self.siteStoreURL = siteStoreURL
    super.init()
  }

  func prepareForLoad(_ url: URL) {
    navigationWillStart()
    trustedURL = url
  }

  func navigationWillStart() {
    documentReady = false
  }

  func navigationDidFinish(_ view: WKWebView) {
    documentReady = view === webView && trustedURL != nil && view.url == trustedURL
    publish()
  }

  func userContentController(
    _ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
    replyHandler: @escaping (Any?, String?) -> Void
  ) {
    guard message.name == Self.handlerName,
      message.webView === webView, message.frameInfo.isMainFrame,
      documentReady, let trustedURL, webView?.url == trustedURL,
      message.frameInfo.request.url == trustedURL, originMatches(message, trustedURL),
      let body = message.body as? [String: Any], let op = body["op"] as? String
    else {
      replyHandler(nil, "The live session panel is unavailable outside the application document.")
      return
    }
    do {
      let (reply, choice) = try handle(op, body)
      replyHandler(reply, nil)
      if let choice { Task { @MainActor [weak self] in self?.decide?(choice) } }
    } catch let failure as SessionPanelRefusal {
      replyHandler(nil, failure.message)
      publish()
    } catch {
      replyHandler(nil, error.localizedDescription)
    }
  }

  // The custom app scheme is already scoped by the exact URL above.
  private func originMatches(_ message: WKScriptMessage, _ trusted: URL) -> Bool {
    guard trusted.scheme == "http" else { return true }
    let origin = message.frameInfo.securityOrigin
    let brackets = CharacterSet(charactersIn: "[]")
    return origin.protocol == "http"
      && origin.host.trimmingCharacters(in: brackets) == trusted.host?.trimmingCharacters(in: brackets)
      && origin.port == trusted.port
  }

  private func handle(_ op: String, _ body: [String: Any]) throws -> (Any?, Choice?) {
    if ["start", "retry", "offline"].contains(op) {
      guard !answered else { throw SessionPanelRefusal("This choice is already being handled.") }
    }
    let accept = { (choice: Choice) -> (Any?, Choice?) in
      self.answered = true
      return (["ok": true], choice)
    }
    switch op {
    case "state":
      return (state(), nil)
    case "start":
      guard case .choose = content else { throw SessionPanelRefusal("This start choice is no longer open.") }
      // The mode and a Content session's limits are the only choices; a page
      // cannot add a Keychain or any other switch.
      guard Set(body.keys).isSubset(of: ["op", "mode"] + ContentLimits.keys) else {
        throw SessionPanelRefusal("The start panel offers only the capture mode and a Content session's limits.")
      }
      guard let raw = body["mode"] as? String, let mode = LiveCaptureMode(rawValue: raw) else {
        throw SessionPanelRefusal("Choose Content or Metadata only.")
      }
      guard mode.capturesNetworkContent else {
        guard ContentLimits.keys.allSatisfy({ body[$0] == nil }) else {
          throw SessionPanelRefusal("Budgets and media capture apply only to a Content session.")
        }
        return accept(.start(mode, nil))
      }
      switch ContentLimits.validated(body) {
      case .success(let limits): return accept(.start(mode, limits))
      case .failure(let refusal): throw SessionPanelRefusal(refusal.message)
      }
    case "retry":
      guard case .failed = content else { throw SessionPanelRefusal("There is no failed session to retry.") }
      return accept(.retry)
    case "offline":
      guard decisionOpen else { throw SessionPanelRefusal("There is no session choice open.") }
      return accept(.offline)
    case "removeSite", "clearSites":
      guard isChoosing(content) else { throw SessionPanelRefusal("Saved functions change only before a session starts.") }
      guard (body["generation"] as? NSNumber)?.intValue == siteGeneration else {
        throw SessionPanelRefusal("The saved functions changed; review the list again.")
      }
      // Sources or another app run may have rewritten the file since it was
      // read; never write over a list the page did not see.
      guard InvocationSiteSet.load(siteStoreURL) == sites else {
        reloadSites()
        throw SessionPanelRefusal("The saved functions changed; review the list again.")
      }
      guard case .saved(var saved) = sites else {
        if op == "clearSites", case .unreadable = sites {
          save([])
          return (state(), nil)
        }
        throw SessionPanelRefusal("There are no saved functions to change.")
      }
      if op == "removeSite" {
        guard let number = body["index"] as? NSNumber, number.doubleValue == Double(number.intValue),
          case let index = number.intValue, saved.indices.contains(index)
        else {
          throw SessionPanelRefusal("That saved function is no longer listed.")
        }
        saved.remove(at: index)
      } else {
        saved = []
      }
      save(saved)
      return (state(), nil)
    default:
      throw SessionPanelRefusal("Unknown live session request.")
    }
  }

  private func isChoosing(_ value: Content) -> Bool {
    if case .choose = value { return true }
    return false
  }

  private func reloadSites() {
    sites = InvocationSiteSet.load(siteStoreURL)
    siteGeneration += 1
  }

  private func save(_ saved: [InvocationSiteSet.Site]) {
    do {
      try InvocationSiteSet.write(saved, to: siteStoreURL)
      siteNotice = nil
    } catch {
      siteNotice = "The saved functions could not be changed: \(error.localizedDescription)"
    }
    reloadSites()
    publish()
  }

  private func state() -> [String: Any] {
    let modes = [LiveCaptureMode.content, .metadata].map { ["id": $0.rawValue, "title": $0.title] }
    switch content {
    case .hidden:
      return ["panel": "hidden"]
    case .starting(let mode, let limits):
      var value: [String: Any] = ["panel": "starting", "mode": mode.rawValue, "modes": modes]
      if let limits { value["limits"] = limits.panelState }
      return value
    case .choose(let mode, let limits):
      return ["panel": "choose", "mode": mode.rawValue, "modes": modes, "sites": siteState(), "limits": limits.panelState]
    case .failed(let failure, let mode, let limits):
      var value: [String: Any] = [
        "panel": "failed", "mode": mode.rawValue, "modes": modes,
        "failure": [
          "title": failure.afterStartup ? "Live session ended" : "Live session unavailable",
          "message": failure.message, "afterStartup": failure.afterStartup,
        ],
      ]
      if let limits { value["limits"] = limits.panelState }
      return value
    }
  }

  private func siteState() -> [String: Any] {
    var result: [String: Any] = ["generation": siteGeneration, "limit": InvocationSiteSet.limit]
    if let siteNotice { result["notice"] = siteNotice }
    switch sites {
    case .empty:
      result["state"] = "empty"
      result["items"] = []
    case .unreadable:
      result["state"] = "unreadable"
      result["items"] = []
    case .saved(let saved):
      result["state"] = "saved"
      result["items"] = saved.map { site -> [String: Any] in
        ["label": site.label, "sourceURL": site.sourceURL ?? NSNull()]
      }
    }
    return result
  }

  // State moves as a JSON argument, never as script text.
  private func publish() {
    let value = state()
    guard documentReady, let webView, JSONSerialization.isValidJSONObject(value),
      let data = try? JSONSerialization.data(withJSONObject: value)
    else { return }
    let payload = String(decoding: data, as: UTF8.self)
    webView.callAsyncJavaScript(
      "window.__rebSessionPanel && window.__rebSessionPanel(JSON.parse(payload));",
      arguments: ["payload": payload], in: nil, in: .page, completionHandler: nil)
  }
}

struct SessionPanelRefusal: Error {
  let message: String
  init(_ message: String) { self.message = message }
}
