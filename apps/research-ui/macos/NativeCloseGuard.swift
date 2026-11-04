import Cocoa
import WebKit

// One guarded decision about the window's document at a time: before the
// window closes, before the app quits, and before the app replaces the
// document with another workspace. Active requests coalesce close/Quit
// callbacks, and close or Quit takes over a pending replacement. AppKit can
// abort a close sheet before delivering Quit, which then requires a fresh
// guarded decision. The native sheet prevents new editor input between the JS
// snapshot and the outcome. Only this app's explicitly loaded document can
// approve without asking.
final class NativeCloseGuard: NSObject, NSWindowDelegate {
  typealias Query = (WKWebView, @escaping (Any?, Error?) -> Void) -> Void
  // Optional smoke diagnostics; no observer is installed in normal app use.
  var requestObserver: ((String, UUID) -> Void)?

  // An app-initiated load that discards the current document. It runs only
  // after a clean answer or an explicit choice; otherwise nothing changes.
  struct Replacement {
    let question: String
    let actionTitle: String
    let approved: () -> Void
  }

  private enum Purpose {
    case close, quit
    case replace(Replacement)
  }

  private enum Phase {
    case checking, dirty, unavailable
  }

  private struct Request {
    let id: UUID
    let generation: UInt64
    let url: URL?
    let alert: NSAlert
    var purpose: Purpose
    var phase = Phase.checking
  }

  private weak var window: NSWindow?
  private weak var webView: WKWebView?
  private var trustedURL: URL?
  private var generation: UInt64 = 0
  private var request: Request?
  private var timeout: Timer?
  private var keyMonitor: Any?
  private var closed = false
  private let query: Query

  init(window: NSWindow, webView: WKWebView, query: Query? = nil) {
    self.window = window
    self.webView = webView
    self.query = query ?? { view, completion in
      view.evaluateJavaScript("""
        (() => {
          if (document.readyState !== 'complete' ||
              typeof hasUnsavedWork !== 'function') return 'unavailable';
          const dirty = hasUnsavedWork();
          return dirty === false ? 'clean' : dirty === true ? 'dirty' : 'unavailable';
        })()
        """, completionHandler: completion)
    }
    super.init()
  }

  // Called before native code loads a new local/owned-loopback UI. Navigation
  // itself never expands this trust boundary, including same-origin redirects.
  func prepareForLoad(_ url: URL) {
    navigationWillStart()
    trustedURL = url
  }

  func navigationWillStart() {
    generation &+= 1
    finish(allow: false)
  }

  func replaceDocument(_ replacement: Replacement) {
    begin(.replace(replacement))
  }

  func windowShouldClose(_ sender: NSWindow) -> Bool {
    guard sender === window else { return false }
    begin(.close)
    return false
  }

  func windowWillClose(_ notification: Notification) {
    guard (notification.object as? NSWindow) === window else { return }
    closed = true
    finish(allow: false)
  }

  func applicationShouldTerminate() -> NSApplication.TerminateReply {
    // Preserve the normal last-window-close path after this guard approved it.
    guard !closed, window != nil else { return .terminateNow }
    if request == nil, window?.attachedSheet != nil { return .terminateCancel }
    begin(.quit)
    return .terminateLater
  }

  private func begin(_ purpose: Purpose) {
    if let current = request {
      switch (current.purpose, purpose) {
      case (_, .replace):
        // Another decision is open; the document stays, and the app can ask again.
        requestObserver?("refuse-replace", current.id)
      case (.replace, _):
        // Closing or quitting decides about the same document instead.
        requestObserver?("supersede-replace", current.id)
        request?.purpose = purpose
        present()
      case (_, .quit):
        requestObserver?("coalesce-quit", current.id)
        request?.purpose = .quit
      case (_, .close):
        requestObserver?("coalesce-close", current.id)
      }
      return
    }
    guard let window, !closed else { return }
    // Do not replace another native decision, such as live-session setup.
    guard window.attachedSheet == nil else { return }
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Stay")
    alert.addButton(withTitle: "Close Anyway")
    // Let Quit reach our delegate instead of being vetoed before the delegate.
    // AppKit may abort this sheet first; that cancellation must not carry an
    // old approval into the fresh Quit request.
    // Sudden termination is disabled in Info.plist; finish still owns approval.
    alert.window.preventsApplicationTerminationWhenModal = false
    let id = UUID()
    let currentURL = webView?.url
    request = Request(id: id, generation: generation, url: currentURL, alert: alert, purpose: purpose)
    present()
    switch purpose {
    case .close: requestObserver?("begin-close", id)
    case .quit: requestObserver?("begin-quit", id)
    case .replace: requestObserver?("begin-replace", id)
    }
    keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self, let current = self.request,
        event.window === current.alert.window,
        event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
        [36, 53, 76].contains(event.keyCode)
      else { return event }
      current.alert.buttons[0].performClick(nil)
      return nil
    }
    alert.beginSheetModal(for: window) { [weak self] response in
      guard let self, self.request?.id == id else { return }
      self.requestObserver?("sheet-response \(response.rawValue)", id)
      self.finish(allow: response == .alertSecondButtonReturn && self.request?.phase != .checking)
    }
    configureSafeButtons(alert)
    let timer = Timer(timeInterval: 5, repeats: false) { [weak self] _ in
      self?.received(nil, error: nil, id: id)
    }
    timeout = timer
    RunLoop.main.add(timer, forMode: .common)
    RunLoop.main.add(timer, forMode: .modalPanel)
    guard let webView, trustedURL != nil, currentURL == trustedURL, !webView.isLoading else {
      received(nil, error: nil, id: id)
      return
    }
    requestObserver?("query", id)
    query(webView) { [weak self] result, error in
      self?.received(result, error: error, id: id)
    }
  }

  // The sheet's words for the current purpose and phase. Stay remains the only
  // keyboard default; the destructive choice waits for an answer.
  private func present() {
    guard let current = request else { return }
    let alert = current.alert
    var replacement: Replacement?
    if case .replace(let value) = current.purpose { replacement = value }
    let verb = replacement == nil ? "Closing" : "Continuing"
    switch current.phase {
    case .checking:
      alert.messageText = "Checking for unsaved work…"
      alert.informativeText = "Keep this window open while Origin Trace checks your edits."
    case .dirty:
      alert.messageText = replacement?.question ?? "Close with unsaved or unconfirmed changes?"
      alert.informativeText =
        "\(verb) may lose unsaved Analyst, API Collection or notebook edits, or interrupt a pending "
        + "save. A save may already have completed; \(verb.lowercased()) cannot undo it. Stay to "
        + "finish saving and verify the result."
    case .unavailable:
      alert.messageText = "Couldn’t check for unsaved work"
      alert.informativeText =
        "The interface is unavailable or did not report its save state. \(verb) anyway may lose "
        + "edits or interrupt a pending save, and cannot undo an already completed save. "
        + "Stay to retry safely."
    }
    alert.buttons[1].title = replacement?.actionTitle ?? "Close Anyway"
    alert.buttons[1].isEnabled = current.phase != .checking
    alert.layout()
    configureSafeButtons(alert)
  }

  private func isCurrent(_ current: Request) -> Bool {
    !closed && webView != nil && current.generation == generation && webView?.url == current.url
  }

  private func received(_ result: Any?, error: Error?, id: UUID) {
    guard let current = request, current.id == id, current.phase == .checking else { return }
    timeout?.invalidate()
    timeout = nil
    guard isCurrent(current) else {
      finish(allow: false)
      return
    }
    if error == nil, result as? String == "clean",
      current.url == trustedURL, webView?.isLoading == false
    {
      finish(allow: true)
      return
    }
    request?.phase = error == nil && result as? String == "dirty" ? .dirty : .unavailable
    present()
  }

  private func configureSafeButtons(_ alert: NSAlert) {
    // AppKit recomputes shortcuts during layout. Set the safe default on the
    // presented sheet as well as after changing its warning text.
    alert.window.defaultButtonCell = alert.buttons[0].cell as? NSButtonCell
    alert.buttons[0].keyEquivalent = "\r"
    alert.buttons[0].keyEquivalentModifierMask = []
    alert.buttons[1].keyEquivalent = ""
  }

  private func finish(allow: Bool) {
    guard let current = request else { return }
    let approved = allow && isCurrent(current)
    requestObserver?(approved ? "finish-allow" : "finish-cancel", current.id)
    request = nil // Reentrant sheet callbacks cannot reuse this approval.
    timeout?.invalidate()
    timeout = nil
    if let keyMonitor { NSEvent.removeMonitor(keyMonitor) }
    keyMonitor = nil
    if current.alert.window.sheetParent != nil {
      window?.endSheet(current.alert.window, returnCode: .abort)
    }
    switch current.purpose {
    case .quit:
      NSApp.reply(toApplicationShouldTerminate: approved)
    case .close:
      if approved { window?.close() }
    case .replace(let replacement):
      if approved { replacement.approved() }
    }
  }
}
