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
    // XCUIApplication does not forward the launched app's standard streams to
    // xcodebuild. Retain authored smoke diagnostics beside its native receipt.
    if let output = ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT_OUTPUT"] {
      let path = URL(fileURLWithPath: output).appendingPathComponent("native-smoke.log").path
      require(freopen(path, "w", stdout) != nil && dup2(fileno(stdout), fileno(stderr)) >= 0,
              "cannot retain native smoke diagnostics")
    }
    NSApp.activate(ignoringOtherApps: true)
    guard let output = ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT_OUTPUT"]
    else { fail("native UI-test receipt destination is missing"); return }
    // The driver owns a fresh output directory. Share this deterministic child
    // with XCTest so it can select the exact fixture through the real panel UI.
    directory = URL(fileURLWithPath: output).resolvingSymlinksInPath()
      .appendingPathComponent("destinations", isDirectory: true)
    do { try manager.createDirectory(at: directory, withIntermediateDirectories: false) }
    catch { fail("cannot create owned temporary directory") }
    // The UI test cannot choose which form of this folder the panel returns.
    // Check on every run that the destination guard accepts its resolved alias.
    if let resolved = realpath(directory.path, nil) {
      let alias = URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
      free(resolved)
      let name = ClientProjectArchive.Mode.raw.filename
      require(canonicalFile(alias.appendingPathComponent(name)) == canonicalFile(directory.appendingPathComponent(name)),
              "destination guard rejects the resolved alias of the owned folder")
    } else { fail("cannot resolve owned temporary directory") }
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
    window.title = "Client project smoke: \(next.rawValue)"
    reply = nil
    stage("request-bridge")
    phaseDirectory = directory.appendingPathComponent(next.rawValue, isDirectory: true)
    do { try manager.createDirectory(at: phaseDirectory, withIntermediateDirectories: false) }
    catch { fail("cannot create phase directory") }
    webView.callAsyncJavaScript("""
      try {
        return {fulfilled:true,value:await window.webkit.messageHandlers.rebClientProjectExport.postMessage(window.__nativeProjectSmokePayload)};
      } catch (error) {
        // Preserve the actual rejected bridge message. WebKit wraps a rejected
        // async result in an NSError whose localizedDescription is generic.
        return {fulfilled:false,message:String(error)};
      }
      """, arguments: [:], in: nil, in: .page) { result in
      self.trace("script-reply \(next.rawValue)")
      // Reload destroys the old JavaScript promise. The native cancellation
      // receipt and replacement navigation are verified independently below.
      if next == .navigation { return }
      switch result {
      case .success(let value):
        guard let outcome = value as? [String: Any], let fulfilled = outcome["fulfilled"] as? Bool
        else { self.fail("missing bridge outcome"); return }
        if next == .writeFailure {
          self.require(!fulfilled && (outcome["message"] as? String)?.contains("could not be saved") == true,
                       "filesystem failure did not return the expected rejection")
        } else {
          let status = (outcome["value"] as? [String: Any])?["status"] as? String
          self.require(fulfilled && status == (next == .cancel ? "canceled" : "saved"), "wrong save result")
        }
      case .failure(let error):
        self.fail("unexpected JavaScript evaluation failure: \(error.localizedDescription)")
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
        // Apple hosts Save panels in a separate process. The Xcode UI test
        // clicks the real Save control; direct ok(_:) and synthetic in-process
        // keyboard events cannot approve it. No native completion is fabricated.
        self.stage("await-xcode-save-click", timeout: 30)
      }
    }
  }

  // Apple's panel can return /private/var or /var for the same temporary folder;
  // identical Go to Folder input has produced both. resolvingSymlinksInPath()
  // strips /private only from a path that exists, and the file is not written
  // yet, so canonicalize its existing parent instead.
  private func canonicalFile(_ url: URL) -> URL {
    url.deletingLastPathComponent().resolvingSymlinksInPath()
      .appendingPathComponent(url.lastPathComponent, isDirectory: false)
  }

  private func willWrite(_ url: URL) {
    stage("atomic-write")
    trace("write-destination privateAlias=\(url.path.hasPrefix("/private/"))")
    let actual = canonicalFile(url)
    let expected = canonicalFile(destination)
    // Keep the exact destination guard. Diagnose URL representation versus
    // navigation/filename mismatches without recording arbitrary selected paths.
    let mismatch = "unexpected write destination"
      + " pathMatch=\(actual.path == expected.path)"
      + " standardizedMatch=\(actual.standardizedFileURL == expected.standardizedFileURL)"
      + " parentMatch=\(actual.deletingLastPathComponent().path == expected.deletingLastPathComponent().path)"
      + " filenameMatch=\(actual.lastPathComponent == expected.lastPathComponent)"
      + " ownedRoot=\(actual.pathComponents.starts(with: directory.resolvingSymlinksInPath().pathComponents))"
    require(actual == expected, mismatch)
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
      if let output = ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT_OUTPUT"] {
        let result: [String: Any] = ["savedExactBytes": true, "cancelNoWrite": true,
          "busyRefused": true, "navigationNoWrite": true, "writeFailureRefused": true,
          "replacementSaved": true, "panelCount": 5]
        do {
          let bytes = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
          try bytes.write(to: URL(fileURLWithPath: output).appendingPathComponent("result.json"))
        } catch { fail("cannot write the native test receipt") }
      } else { fail("native UI-test receipt destination is missing") }
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

  private func trace(_ event: String) {
    let mode = RunLoop.current.currentMode?.rawValue ?? "none"
    print("NATIVE_CLIENT_PROJECT_TRACE \(phase.rawValue) \(event) mode=\(mode) "
      + "sheet=\(window.attachedSheet != nil) modal=\(NSApp.modalWindow != nil)")
    fflush(stdout)
  }

  private func stage(_ label: String, timeout: TimeInterval = 10) {
    trace(label)
    watchdog?.cancel()
    // This is independent of the AppKit run loop: a blocked native call must
    // identify its stage, not silently hang until the outer process timeout.
    let marker = phase.rawValue + "/" + label
    let next = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
    next.schedule(deadline: .now() + timeout)
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
