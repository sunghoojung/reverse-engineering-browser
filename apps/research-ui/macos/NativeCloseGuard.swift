import Cocoa
import WebKit

// One request covers both the window close button and application Quit. The
// native sheet prevents new editor input between the JS snapshot and close.
// Only this app's explicitly loaded document can approve a clean shutdown.
final class NativeCloseGuard: NSObject, NSWindowDelegate {
  typealias Query = (WKWebView, @escaping (Any?, Error?) -> Void) -> Void

  private enum Phase {
    case checking, dirty, unavailable
  }

  private struct Request {
    let id: UUID
    let generation: UInt64
    let url: URL?
    let alert: NSAlert
    var phase = Phase.checking
    var quitWaiting = false
  }

  private weak var window: NSWindow?
  private weak var webView: WKWebView?
  private var trustedURL: URL?
  private var generation: UInt64 = 0
  private var request: Request?
  private var timeout: Timer?
  private var escapeMonitor: Any?
  private var closed = false
  private let query: Query

  init(window: NSWindow, webView: WKWebView, query: Query? = nil) {
    self.window = window
    self.webView = webView
    self.query = query ?? { view, completion in
      view.evaluateJavaScript("""
        (() => {
          if (document.readyState !== 'complete' ||
              typeof analystHasUnsavedWork !== 'function') return 'unavailable';
          const dirty = analystHasUnsavedWork();
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

  func windowShouldClose(_ sender: NSWindow) -> Bool {
    guard sender === window else { return false }
    begin(quit: false)
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
    begin(quit: true)
    return .terminateLater
  }

  private func begin(quit: Bool) {
    if request != nil {
      if quit { request?.quitWaiting = true }
      return
    }
    guard let window else { return }
    // Do not replace another native decision, such as live-session setup.
    guard window.attachedSheet == nil else { return }
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "Checking unsaved Analyst work…"
    alert.informativeText = "Keep this window open while Origin Trace checks your edits."
    alert.addButton(withTitle: "Stay")
    alert.addButton(withTitle: "Close Anyway").isEnabled = false
    alert.buttons[0].keyEquivalent = "\r"
    alert.buttons[1].keyEquivalent = ""
    let id = UUID()
    let currentURL = webView?.url
    request = Request(id: id, generation: generation, url: currentURL, alert: alert,
                      quitWaiting: quit)
    escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self, let current = self.request,
        event.window === current.alert.window, event.keyCode == 53
      else { return event }
      current.alert.buttons[0].performClick(nil)
      return nil
    }
    alert.beginSheetModal(for: window) { [weak self] response in
      guard let self, self.request?.id == id else { return }
      self.finish(allow: response == .alertSecondButtonReturn && self.request?.phase != .checking)
    }
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
    query(webView) { [weak self] result, error in
      self?.received(result, error: error, id: id)
    }
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
    } else if error == nil, result as? String == "dirty" {
      request?.phase = .dirty
      current.alert.messageText = "Close with unsaved or unconfirmed Analyst changes?"
      current.alert.informativeText =
        "Closing may lose unsaved edits or interrupt a pending save. A save may already "
        + "have completed; closing cannot undo it. Stay to finish saving and verify the result."
      current.alert.buttons[1].isEnabled = true
      current.alert.layout()
    } else {
      request?.phase = .unavailable
      current.alert.messageText = "Couldn’t check unsaved Analyst work"
      current.alert.informativeText =
        "The interface is unavailable or did not report its save state. Closing anyway may "
        + "lose edits or interrupt a pending save, and cannot undo an already completed save. "
        + "Stay to retry safely."
      current.alert.buttons[1].isEnabled = true
      current.alert.layout()
    }
  }

  private func finish(allow: Bool) {
    guard let current = request else { return }
    let approved = allow && isCurrent(current)
    request = nil // Reentrant sheet callbacks cannot reuse this approval.
    timeout?.invalidate()
    timeout = nil
    if let escapeMonitor { NSEvent.removeMonitor(escapeMonitor) }
    escapeMonitor = nil
    if current.alert.window.sheetParent != nil {
      window?.endSheet(current.alert.window, returnCode: .abort)
    }
    if current.quitWaiting {
      NSApp.reply(toApplicationShouldTerminate: approved)
    } else if approved {
      window?.close()
    }
  }
}
