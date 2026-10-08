import Cocoa
import Darwin
import WebKit

// Runs only inside the existing explicitly requested packaged-app smoke mode.
// It uses the real bundled UI, AppKit close/Quit lifecycle and native sheet
// buttons. The host script supplies only disposable synthetic workspaces.
final class NativeCloseGuardSmoke {
  private let scenario: String
  private let window: NSWindow
  private let webView: WKWebView
  private let closeGuard: NativeCloseGuard
  private var timer: Timer?
  private var expectedExit = false
  private var injectedGuard: NativeCloseGuard?
  private var callbacks: [(Any?, Error?) -> Void] = []

  init(scenario: String, window: NSWindow, webView: WKWebView, closeGuard: NativeCloseGuard) {
    self.scenario = scenario
    self.window = window
    self.webView = webView
    self.closeGuard = closeGuard
  }

  func start() {
    evaluate("showScreen('analyst'); true") { _ in
      self.waitForWorkspace(deadline: Date().addingTimeInterval(10))
    }
  }

  private func waitForWorkspace(deadline: Date) {
    evaluate("state.localAnalystLoaded && !state.localAnalystRefreshing && state.localAnalyst.generation === 1") { value in
      if value as? Bool == true {
        self.configure()
      } else {
        self.require(Date() < deadline, "bundled synthetic Analyst workspace did not load")
        self.after(0.05) { self.waitForWorkspace(deadline: deadline) }
      }
    }
  }

  func willTerminate() {
    require(expectedExit, "AppKit terminated before an approved close")
    print("NATIVE_CLOSE_OK \(scenario)")
  }

  private func configure() {
    if scenario == "untrusted-close" {
      webView.loadHTMLString("<script>function analystHasUnsavedWork() { return false; }</script>",
                            baseURL: nil)
      wait(until: { !self.webView.isLoading }, label: "untrusted replacement document") {
        self.waitForDecision { self.chooseStay() }
        self.window.performClose(nil)
      }
      return
    }
    if scenario == "late-callback" || scenario == "timeout-close" {
      exerciseInjectedQuery()
      return
    }
    let setups = [
      "clean-close": "", "clean-quit": "",
      "file-return-close": """
        analystElements.content.value = 'Synthetic unsaved native draft';
        analystElements.content.dispatchEvent(new Event('input', {bubbles: true}));
        """,
      "folder-escape-quit": """
        analystElements.folderName.value = 'Synthetic unsaved native folder';
        analystElements.folderName.dispatchEvent(new Event('input', {bubbles: true}));
        """,
      "saving-quit": "state.localAnalystSaving = true;",
      "pending-close": "state.localAnalystPendingSave = {generation: 1};",
      "missing-close": "analystHasUnsavedWork = undefined;",
      "throwing-quit": "analystHasUnsavedWork = () => { throw new Error('synthetic'); };",
      "malformed-close": "analystHasUnsavedWork = () => 0;",
      "repeated-close-quit": "state.analystDraftDirty = true;",
      "navigation-close": "state.analystDraftDirty = true;",
    ]
    guard let setup = setups[scenario] else { fail("unknown scenario"); return }
    evaluate("""
      state.analystDraftDirty = false; state.analystFolderDirty = false;
      state.localAnalystSaving = false; state.localAnalystPendingSave = null;
      if (!selectAnalystFile(1)) throw new Error('Synthetic file selection failed');
      \(setup)
      window.__closeSnapshotNow = () => JSON.stringify({
        file: analystFileDraft(), folder: analystFolderDraft(),
        fileID: state.analystSelectedFileId, folderID: state.analystSelectedFolderId,
        fileDirty: state.analystDraftDirty, folderDirty: state.analystFolderDirty,
        saving: state.localAnalystSaving, pending: state.localAnalystPendingSave
      });
      window.__closeSnapshot = window.__closeSnapshotNow();
      window.__closeQueries = 0;
      if (typeof analystHasUnsavedWork === 'function') {
        const query = analystHasUnsavedWork;
        analystHasUnsavedWork = () => { window.__closeQueries++; return query(); };
      }
      true
      """) { _ in
      if self.scenario.hasPrefix("clean-") {
        self.expectedExit = true
        self.requestClose()
      } else {
        self.waitForDecision {
          if self.scenario == "navigation-close" {
            self.exerciseNavigation()
          } else {
            self.chooseStay()
          }
        }
        self.requestClose()
      }
    }
  }

  private func requestClose() {
    if scenario == "repeated-close-quit" {
      window.performClose(nil)
      window.performClose(nil)
      NSApp.terminate(nil)
    } else if scenario.hasSuffix("-quit") {
      // A user Quit arrives through AppKit's event queue. Calling terminate
      // reentrantly from a WK callback after Stay can precede cancellation of
      // the previous terminateLater request and bypass the next delegate query.
      for type in [NSEvent.EventType.keyDown, .keyUp] {
        guard let event = NSEvent.keyEvent(
          with: type, location: .zero, modifierFlags: [.command],
          timestamp: ProcessInfo.processInfo.systemUptime,
          windowNumber: window.windowNumber, context: nil,
          characters: "q", charactersIgnoringModifiers: "q",
          isARepeat: false, keyCode: 12
        ) else { fail("could not create Quit keyboard event"); return }
        NSApp.postEvent(event, atStart: false)
      }
    } else {
      window.performClose(nil)
    }
  }

  private func chooseStay() {
    guard let sheet = window.attachedSheet, let stay = button("Stay") else {
      fail("missing Stay button"); return
    }
    require(sheet.defaultButtonCell === (stay.cell as? NSButtonCell), "Stay must be the native default button")
    require(button("Close Anyway")?.keyEquivalent == "", "destructive keyboard default")
    wait(until: { self.window.attachedSheet == nil }, label: "Stay dismissal") {
      self.require(self.window.isVisible, "Stay closed the window")
      if self.scenario != "untrusted-close" {
        self.evaluate("window.__closeSnapshotNow() === window.__closeSnapshot") { unchanged in
          self.require(unchanged as? Bool == true, "Stay changed the draft or its owner/save state")
          self.evaluate("window.__closeQueries") { value in
            let expected = self.scenario == "missing-close" ? 0 : 1
            self.require((value as? NSNumber)?.intValue == expected, "query missing or not coalesced")
            self.approveNextClose()
          }
        }
      } else {
        self.approveNextClose()
      }
    }
    if scenario.contains("return") || scenario.contains("escape") {
      let escape = scenario.contains("escape")
      guard let event = NSEvent.keyEvent(
        with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
        windowNumber: sheet.windowNumber, context: nil,
        characters: escape ? "\u{1b}" : "\r",
        charactersIgnoringModifiers: escape ? "\u{1b}" : "\r",
        isARepeat: false, keyCode: escape ? 53 : 36
      ) else { fail("could not create keyboard event"); return }
      NSApp.sendEvent(event)
    } else {
      stay.performClick(nil)
    }
  }

  private func approveNextClose() {
    waitForDecision {
      self.expectedExit = true
      self.button("Close Anyway")!.performClick(nil)
    }
    requestClose()
  }

  private func exerciseNavigation() {
    // Invalidate an open decision with a real same-URL WKWebView reload. Its
    // old sheet must not authorize closing the replacement document.
    evaluate("window.__nativeCloseOldDocument = true; true") { _ in
      self.webView.reload()
      self.waitForReplacement(deadline: Date().addingTimeInterval(10))
    }
  }

  private func waitForReplacement(deadline: Date) {
    evaluate("typeof window.__nativeCloseOldDocument === 'undefined' && document.readyState === 'complete'") { value in
      if value as? Bool == true, !self.webView.isLoading, self.window.attachedSheet == nil {
        self.require(self.window.isVisible, "navigation reused an old close approval")
        self.evaluate("state.analystDraftDirty = true; true") { _ in
          self.waitForDecision {
            self.require(self.window.isVisible, "replacement closed without a new choice")
            self.expectedExit = true
            self.button("Close Anyway")!.performClick(nil)
          }
          self.window.performClose(nil)
        }
      } else {
        self.require(Date() < deadline, "reload did not commit a replacement document")
        self.after(0.05) { self.waitForReplacement(deadline: deadline) }
      }
    }
  }

  private func exerciseInjectedQuery() {
    let guardUnderTest = NativeCloseGuard(window: window, webView: webView) { _, completion in
      self.callbacks.append(completion)
    }
    injectedGuard = guardUnderTest
    guardUnderTest.prepareForLoad(webView.url!)
    window.delegate = guardUnderTest
    if scenario == "timeout-close" {
      waitForDecision {
        self.require(self.window.isVisible, "a missing query reply closed the window")
        self.callbacks[0]("clean", nil) // The timed-out reply cannot override the warning.
        self.require(self.window.isVisible, "late clean reply reused a timed-out request")
        self.window.delegate = self.closeGuard
        self.expectedExit = true
        self.button("Close Anyway")!.performClick(nil)
      }
      window.performClose(nil)
      return
    }
    window.performClose(nil)
    require(callbacks.count == 1, "query injection was not reached")
    guardUnderTest.navigationWillStart()
    wait(until: { self.window.attachedSheet == nil }, label: "invalidated request") {
      self.window.performClose(nil)
      self.require(self.callbacks.count == 2, "new request did not get a new query")
      self.callbacks[0]("clean", nil)
      self.require(self.window.isVisible, "stale callback closed the current window")
      self.waitForDecision {
        self.wait(until: { self.window.attachedSheet == nil }, label: "injected Stay") {
          self.require(self.window.isVisible, "injected Stay closed the window")
          self.window.delegate = self.closeGuard
          self.injectedGuard = nil
          self.expectedExit = true
          self.window.performClose(nil)
        }
        self.button("Stay")!.performClick(nil)
      }
      self.callbacks[1]("dirty", nil)
    }
  }

  private func waitForDecision(_ completion: @escaping () -> Void) {
    wait(until: { self.button("Close Anyway")?.isEnabled == true },
         label: "native close decision") {
      let unavailable = ["missing-close", "throwing-quit", "malformed-close", "untrusted-close", "timeout-close"]
        .contains(self.scenario)
      let expected = unavailable ? "Couldn’t check unsaved Analyst work"
        : "Close with unsaved or unconfirmed Analyst changes?"
      self.captureDecision()
      self.require(self.sheetText().contains(expected), "wrong warning category; a timeout is not a dirty-state pass")
      completion()
    }
  }

  private func captureDecision() {
    guard let path = ProcessInfo.processInfo.environment["REB_APP_SMOKE_NATIVE_CLOSE_OUTPUT"],
      let view = window.attachedSheet?.contentView
    else { fail("native decision screenshot is unavailable"); return }
    view.layoutSubtreeIfNeeded()
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
      fail("native decision bitmap is unavailable"); return
    }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    guard let data = bitmap.representation(using: .png, properties: [:]) else {
      fail("native decision PNG is unavailable"); return
    }
    do {
      try data.write(to: URL(fileURLWithPath: path).appendingPathComponent("\(scenario)-prompt.png"))
    } catch { fail("native decision screenshot could not be written") }
  }

  private func sheetText() -> String {
    func text(_ view: NSView) -> String {
      let own = (view as? NSTextField)?.stringValue ?? ""
      return ([own] + view.subviews.map(text)).joined(separator: "\n")
    }
    guard let content = window.attachedSheet?.contentView else { return "" }
    return text(content)
  }

  private func button(_ title: String) -> NSButton? {
    func find(_ view: NSView) -> NSButton? {
      if let button = view as? NSButton, button.title == title { return button }
      for child in view.subviews { if let match = find(child) { return match } }
      return nil
    }
    guard let content = window.attachedSheet?.contentView else { return nil }
    return find(content)
  }

  private func evaluate(_ script: String, completion: @escaping (Any?) -> Void) {
    webView.evaluateJavaScript(script) { value, error in
      if let error { self.fail(error.localizedDescription); return }
      completion(value)
    }
  }

  private func after(_ seconds: TimeInterval, completion: @escaping () -> Void) {
    let deadline = Date().addingTimeInterval(seconds)
    wait(until: { Date() >= deadline }, label: "startup", completion: completion)
  }

  private func wait(until condition: @escaping () -> Bool, label: String,
                    completion: @escaping () -> Void) {
    timer?.invalidate()
    let deadline = Date().addingTimeInterval(12)
    let next = Timer(timeInterval: 0.025, repeats: true) { timer in
      if condition() {
        timer.invalidate()
        self.timer = nil
        completion()
      } else if Date() > deadline {
        self.fail("timed out waiting for \(label)")
      }
    }
    timer = next
    RunLoop.main.add(next, forMode: .common)
    RunLoop.main.add(next, forMode: .modalPanel)
  }

  private func require(_ condition: Bool, _ message: String) {
    if !condition { fail(message) }
  }

  private func fail(_ message: String) {
    print("SMOKE_ERROR native close \(scenario): \(message)")
    exit(1)
  }
}
