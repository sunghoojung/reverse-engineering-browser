import Cocoa
import Darwin
import UniformTypeIdentifiers
import WebKit

// Explicit packaged smoke only: generate a synthetic project in the real WebKit
// UI and drive real NSSavePanel actions. Every destination is created here under
// a new temporary directory; no JS message can supply a path or test control.
final class ClientProjectExportSmoke: NSObject {
  private enum Phase: String { case cancel, save, writeFailure, navigation, replacementSave }
  private let webView: WKWebView
  private let window: NSWindow
  private let exporter: NativeClientProjectExport
  private let manager = FileManager.default
  private var directory: URL!
  private var phaseDirectory: URL!
  private var expected = Data()
  private var phase = Phase.cancel
  private var panelCount = 0
  private var reply: String?
  private var busyRefused = false
  private var replacementFinished = false
  private var timer: Timer?
  private var watchdog: DispatchSourceTimer?
  private var deferredAction: (() -> Void)?

  init(webView: WKWebView, window: NSWindow, exporter: NativeClientProjectExport) {
    self.webView = webView
    self.window = window
    self.exporter = exporter
    super.init()
  }

  func start() {
    require(ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1"
      && ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT"] == "1", "smoke mode required")
    NSApp.activate(ignoringOtherApps: true)
    directory = manager.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("reb-client-project-smoke-" + UUID().uuidString,
                                                                 isDirectory: true)
    do { try manager.createDirectory(at: directory, withIntermediateDirectories: false) }
    catch { fail("cannot create owned temporary directory") }
    exporter.installSmokeObservers(panel: { [weak self] panel in self?.presented(panel) },
      willWrite: { [weak self] destination in self?.willWrite(destination) },
      reply: { [weak self] status in
        self?.reply = status
        self?.trace("native-reply \(status)")
      })
    prepareFixture { self.schedule("start-cancel") { self.run(.cancel) } }
  }

  func didFinishNavigation() {
    trace("navigation-finished")
    if phase == .navigation { replacementFinished = true }
  }

  private func prepareFixture(_ completion: @escaping () -> Void) {
    stage("prepare-fixture")
    webView.callAsyncJavaScript("""
      const request = {method:'POST',url:'https://example.invalid/authored?x=1&x=2',
        headers:[{name:'Content-Type',value:'text/plain'}],body:'Authored native smoke 雪',timeout_ms:15000};
      const source = capturedClientRun({id:1,started_at_ms:123,request,resolved_request:request,
        response:{status:200,url:request.url,headers:[],body:'Authored response'}},'native-smoke');
      const bytes = capturedClientProject(source,'raw').bytes;
      let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
      window.__nativeProjectSmokePayload = {format:'reb-client-project-save-v1',mode:'raw',base64:btoa(binary)};
      return window.__nativeProjectSmokePayload.base64;
      """, arguments: [:], in: nil, in: .page) { result in
      guard case .success(let value) = result, let base64 = value as? String,
        let bytes = Data(base64Encoded: base64)
      else { self.fail("could not generate the authored project in packaged WebKit"); return }
      do { _ = try ClientProjectArchive.validate(bytes, expectedMode: .raw) }
      catch { self.fail("authored project failed native validation"); return }
      if !self.expected.isEmpty { self.require(bytes == self.expected, "replacement fixture changed") }
      self.expected = bytes
      self.trace("fixture-ready")
      completion()
    }
  }

  private func run(_ next: Phase) {
    phase = next
    reply = nil
    stage("request-bridge")
    phaseDirectory = directory.appendingPathComponent(next.rawValue, isDirectory: true)
    do { try manager.createDirectory(at: phaseDirectory, withIntermediateDirectories: false) }
    catch { fail("cannot create phase directory") }
    webView.callAsyncJavaScript("""
      return await window.webkit.messageHandlers.rebClientProjectExport.postMessage(window.__nativeProjectSmokePayload);
      """, arguments: [:], in: nil, in: .page) { result in
      self.trace("script-reply \(next.rawValue)")
      // Reload destroys the old JavaScript promise. The native cancellation
      // receipt and replacement navigation are verified independently below.
      if next == .navigation { return }
      switch result {
      case .success(let value):
        let status = (value as? [String: Any])?["status"] as? String
        self.require(status == (next == .cancel ? "canceled" : "saved"), "wrong save result")
        self.require(next != .writeFailure, "filesystem failure incorrectly reported saved")
      case .failure(let error):
        self.require(next == .writeFailure && error.localizedDescription.contains("could not be saved"),
                     "unexpected bridge failure: \(error.localizedDescription)")
      }
      self.stage("wait-panel-dismissal")
      self.wait(until: { self.window.attachedSheet == nil }, label: "panel dismissal") {
        self.verify(next)
      }
    }
  }

  private var destination: URL {
    phaseDirectory.appendingPathComponent(ClientProjectArchive.Mode.raw.filename)
  }

  private func presented(_ panel: NSSavePanel) {
    panelCount += 1
    stage("configure-panel")
    require(panel.nameFieldStringValue == ClientProjectArchive.Mode.raw.filename, "suggested filename changed")
    require(!panel.allowsOtherFileTypes && panel.allowedContentTypes == [.zip], "save type changed")
    panel.directoryURL = phaseDirectory
    stage("wait-panel-ready")
    wait(until: { panel.sheetParent === self.window && panel.isVisible && panel.isKeyWindow }, label: "real key Save panel") {
      self.trace("panel-ready defaultEnabled=\(String(describing: panel.defaultButtonCell?.isEnabled))")
      self.require(panel.directoryURL?.resolvingSymlinksInPath() == self.phaseDirectory.resolvingSymlinksInPath(),
                   "panel did not open the owned temporary directory")
      self.capturePanel(panel)
      if self.phase == .cancel {
        self.stage("request-while-pending")
        self.webView.callAsyncJavaScript("""
          try { await window.webkit.messageHandlers.rebClientProjectExport.postMessage(window.__nativeProjectSmokePayload); return false; }
          catch (error) { return String(error).includes('Finish the current native dialog'); }
          """, arguments: [:], in: nil, in: .page) { result in
          guard case .success(let value) = result, value as? Bool == true else {
            self.fail("a pending panel did not reject the second request"); return
          }
          self.busyRefused = true
          self.schedule("cancel-action") {
            self.trace("cancel-dispatched")
            panel.cancel(nil)
            self.trace("cancel-returned")
          }
        }
      } else if self.phase == .navigation {
        self.replacementFinished = false
        self.schedule("reload-action") {
          self.trace("reload-dispatched")
          self.webView.reload()
          self.wait(until: { self.reply == "canceled" && self.window.attachedSheet == nil
            && self.replacementFinished }, label: "navigation cancellation and replacement") {
            self.verify(.navigation)
          }
        }
      } else {
        // Since macOS 10.15 NSSavePanel.ok(_:) cannot be invoked directly:
        // https://developer.apple.com/documentation/appkit/nssavepanel/ok(_:)
        // Deliver Return through the owned key window's normal event path.
        // This exercises the real remote panel, including its validation; no
        // modal response, selected URL or bridge completion is manufactured.
        self.schedule("save-action") {
          self.stage("save-key-dispatched")
          for type in [NSEvent.EventType.keyDown, .keyUp] {
            guard let event = NSEvent.keyEvent(with: type, location: .zero,
              modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
              windowNumber: panel.windowNumber, context: nil, characters: "\r",
              charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36)
            else { self.fail("cannot construct the owned panel Return event"); return }
            panel.sendEvent(event)
          }
          self.trace("save-key-returned")
        }
      }
    }
  }

  private func willWrite(_ url: URL) {
    stage("atomic-write")
    require(url.resolvingSymlinksInPath() == destination.resolvingSymlinksInPath(), "unexpected write destination")
    if phase == .writeFailure {
      // Force a genuine atomic-write error after ordinary panel approval: a
      // directory cannot be replaced by file bytes. Only our new temp path is touched.
      do { try manager.createDirectory(at: url, withIntermediateDirectories: false) }
      catch { fail("cannot create authored write-failure obstacle") }
    }
  }

  private func verify(_ completed: Phase) {
    stage("verify-outcome")
    do {
      let children = try manager.contentsOfDirectory(atPath: phaseDirectory.path)
      switch completed {
      case .cancel, .navigation:
        require(reply == "canceled" && children.isEmpty, "cancellation wrote an artifact or returned wrong status")
      case .save, .replacementSave:
        let actual = try Data(contentsOf: destination)
        require(reply == "saved" && actual == expected, "saved ZIP differs from authored bytes")
        require(children == [ClientProjectArchive.Mode.raw.filename], "atomic save left an unexpected file")
      case .writeFailure:
        require(reply == "failed", "write failure did not reject the request")
        require(try manager.contentsOfDirectory(atPath: destination.path).isEmpty,
                "failed write modified the obstacle")
        require(children == [ClientProjectArchive.Mode.raw.filename], "failed atomic write left a partial artifact")
      }
    } catch { fail("cannot verify authored save outcome") }
    print("NATIVE_CLIENT_PROJECT_PHASE \(completed.rawValue)")
    fflush(stdout)
    switch completed {
    case .cancel: schedule("start-save") { self.run(.save) }
    case .save: schedule("start-write-failure") { self.run(.writeFailure) }
    case .writeFailure: schedule("start-navigation") { self.run(.navigation) }
    case .navigation:
      schedule("prepare-replacement") {
        self.prepareFixture { self.schedule("start-replacement-save") { self.run(.replacementSave) } }
      }
    case .replacementSave:
      require(panelCount == 5 && busyRefused, "unexpected panel count or missing busy refusal")
      do { try manager.removeItem(at: directory) }
      catch { fail("cannot clean up owned temporary directory") }
      print("NATIVE_CLIENT_PROJECT_OK {\"savedExactBytes\":true,\"cancelNoWrite\":true,\"busyRefused\":true,\"navigationNoWrite\":true,\"writeFailureRefused\":true,\"replacementSaved\":true,\"panelCount\":5}")
      fflush(stdout)
      schedule("quit") { NSApp.terminate(nil) }
    }
  }

  // AppKit panel callbacks and modal timers can run before the previous sheet's
  // transition unwinds. Dispatch the next UI action from the normal event loop,
  // following NativeCloseGuardSmoke's deferred Quit pattern, rather than nesting it.
  private func schedule(_ label: String, _ action: @escaping () -> Void) {
    require(deferredAction == nil, "overlapping deferred actions")
    stage("scheduled-" + label)
    deferredAction = action
    perform(#selector(dispatchDeferredAction(_:)), with: nil, afterDelay: 0, inModes: [.default])
  }

  @objc private func dispatchDeferredAction(_ sender: Any?) {
    guard let action = deferredAction else { fail("missing deferred action"); return }
    deferredAction = nil
    trace("default-dispatch")
    action()
  }

  private func capturePanel(_ panel: NSSavePanel) {
    guard let output = ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT_OUTPUT"],
      let view = panel.contentView
    else { trace("panel-render-unavailable"); return }
    // Render only this authored test's owned NSView, without screen recording,
    // desktop capture, Accessibility permissions or any additional user access.
    stage("render-panel")
    view.layoutSubtreeIfNeeded()
    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
      trace("panel-bitmap-unavailable"); return
    }
    view.cacheDisplay(in: view.bounds, to: bitmap)
    guard let bytes = bitmap.representation(using: .png, properties: [:]) else {
      trace("panel-png-unavailable"); return
    }
    do {
      try bytes.write(to: URL(fileURLWithPath: output).appendingPathComponent(phase.rawValue + "-panel.png"))
      trace("panel-rendered")
    } catch { trace("panel-render-write-failed") }
  }

  private func trace(_ event: String) {
    let mode = RunLoop.current.currentMode?.rawValue ?? "none"
    print("NATIVE_CLIENT_PROJECT_TRACE \(phase.rawValue) \(event) mode=\(mode) "
      + "sheet=\(window.attachedSheet != nil) modal=\(NSApp.modalWindow != nil)")
    fflush(stdout)
  }

  private func stage(_ label: String) {
    trace(label)
    watchdog?.cancel()
    // This is independent of the AppKit run loop: a blocked native call must
    // identify its stage, not silently hang until the outer process timeout.
    let marker = phase.rawValue + "/" + label
    let next = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
    next.schedule(deadline: .now() + 10)
    next.setEventHandler {
      let message = "SMOKE_ERROR native client-project stage timed out: " + marker + "\n"
      FileHandle.standardError.write(Data(message.utf8))
      exit(1)
    }
    watchdog = next
    next.resume()
  }

  private func wait(until condition: @escaping () -> Bool, label: String,
                    completion: @escaping () -> Void) {
    timer?.invalidate()
    let deadline = Date().addingTimeInterval(10)
    let next = Timer(timeInterval: 0.025, repeats: true) { timer in
      if condition() {
        timer.invalidate()
        self.timer = nil
        completion()
      } else if Date() > deadline { self.fail("timed out waiting for \(label)") }
    }
    timer = next
    RunLoop.main.add(next, forMode: .common)
    RunLoop.main.add(next, forMode: .modalPanel)
  }

  private func require(_ condition: Bool, _ message: String) {
    if !condition { fail(message) }
  }

  private func fail(_ message: String) {
    timer?.invalidate()
    watchdog?.cancel()
    if let directory { try? manager.removeItem(at: directory) }
    print("SMOKE_ERROR native client-project: \(message)")
    fflush(stdout)
    exit(1)
  }
}
