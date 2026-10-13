import Cocoa
import Darwin
import UniformTypeIdentifiers
import WebKit

// Explicit packaged smoke only: generate a synthetic project in the real WebKit
// UI and drive real NSSavePanel actions. Every destination is created here under
// a new temporary directory; no JS message can supply a path or test control.
final class ClientProjectExportSmoke {
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

  init(webView: WKWebView, window: NSWindow, exporter: NativeClientProjectExport) {
    self.webView = webView
    self.window = window
    self.exporter = exporter
  }

  func start() {
    require(ProcessInfo.processInfo.environment["REB_APP_SMOKE_TEST"] == "1"
      && ProcessInfo.processInfo.environment["REB_APP_SMOKE_CLIENT_PROJECT"] == "1", "smoke mode required")
    directory = manager.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("reb-client-project-smoke-" + UUID().uuidString,
                                                                 isDirectory: true)
    do { try manager.createDirectory(at: directory, withIntermediateDirectories: false) }
    catch { fail("cannot create owned temporary directory") }
    exporter.installSmokeObservers(panel: { [weak self] panel in self?.presented(panel) },
      willWrite: { [weak self] destination in self?.willWrite(destination) },
      reply: { [weak self] status in self?.reply = status })
    prepareFixture { self.run(.cancel) }
  }

  func didFinishNavigation() {
    if phase == .navigation { replacementFinished = true }
  }

  private func prepareFixture(_ completion: @escaping () -> Void) {
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
      completion()
    }
  }

  private func run(_ next: Phase) {
    phase = next
    reply = nil
    phaseDirectory = directory.appendingPathComponent(next.rawValue, isDirectory: true)
    do { try manager.createDirectory(at: phaseDirectory, withIntermediateDirectories: false) }
    catch { fail("cannot create phase directory") }
    webView.callAsyncJavaScript("""
      return await window.webkit.messageHandlers.rebClientProjectExport.postMessage(window.__nativeProjectSmokePayload);
      """, arguments: [:], in: nil, in: .page) { result in
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
    require(panel.nameFieldStringValue == ClientProjectArchive.Mode.raw.filename, "suggested filename changed")
    require(!panel.allowsOtherFileTypes && panel.allowedContentTypes == [.zip], "save type changed")
    panel.directoryURL = phaseDirectory
    wait(until: { panel.sheetParent === self.window && panel.isVisible }, label: "real Save panel") {
      self.require(panel.directoryURL?.resolvingSymlinksInPath() == self.phaseDirectory.resolvingSymlinksInPath(),
                   "panel did not open the owned temporary directory")
      if self.phase == .cancel {
        self.webView.callAsyncJavaScript("""
          try { await window.webkit.messageHandlers.rebClientProjectExport.postMessage(window.__nativeProjectSmokePayload); return false; }
          catch (error) { return String(error).includes('Finish the current native dialog'); }
          """, arguments: [:], in: nil, in: .page) { result in
          guard case .success(let value) = result, value as? Bool == true else {
            self.fail("a pending panel did not reject the second request"); return
          }
          self.busyRefused = true
          panel.cancel(nil)
        }
      } else if self.phase == .navigation {
        self.replacementFinished = false
        self.webView.reload()
        self.wait(until: { self.reply == "canceled" && self.window.attachedSheet == nil
          && self.replacementFinished }, label: "navigation cancellation and replacement") {
          self.verify(.navigation)
        }
      } else {
        // Use AppKit's ordinary Save action, retaining its normal destination
        // and validation behavior. No modal return code is manufactured.
        panel.ok(nil)
      }
    }
  }

  private func willWrite(_ url: URL) {
    require(url.resolvingSymlinksInPath() == destination.resolvingSymlinksInPath(), "unexpected write destination")
    if phase == .writeFailure {
      // Force a genuine atomic-write error after ordinary panel approval: a
      // directory cannot be replaced by file bytes. Only our new temp path is touched.
      do { try manager.createDirectory(at: url, withIntermediateDirectories: false) }
      catch { fail("cannot create authored write-failure obstacle") }
    }
  }

  private func verify(_ completed: Phase) {
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
    case .cancel: run(.save)
    case .save: run(.writeFailure)
    case .writeFailure: run(.navigation)
    case .navigation: prepareFixture { self.run(.replacementSave) }
    case .replacementSave:
      require(panelCount == 5 && busyRefused, "unexpected panel count or missing busy refusal")
      do { try manager.removeItem(at: directory) }
      catch { fail("cannot clean up owned temporary directory") }
      print("NATIVE_CLIENT_PROJECT_OK {\"savedExactBytes\":true,\"cancelNoWrite\":true,\"busyRefused\":true,\"navigationNoWrite\":true,\"writeFailureRefused\":true,\"replacementSaved\":true,\"panelCount\":5}")
      fflush(stdout)
      NSApp.terminate(nil)
    }
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
    if let directory { try? manager.removeItem(at: directory) }
    print("SMOKE_ERROR native client-project: \(message)")
    fflush(stdout)
    exit(1)
  }
}
