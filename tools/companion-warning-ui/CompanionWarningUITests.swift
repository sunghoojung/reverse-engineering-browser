import AppKit
import XCTest

// Exercise the packaged application's production live-session startup with no
// browser pairing prompt. The outer cloud-CI driver owns the synthetic stores,
// inert Brave app and launch receipts. This sandboxed runner persists
// screenshots only through XCTest attachments.
final class CompanionWarningUITests: XCTestCase {
  // The retired pairing prompt must never return before a live session.
  private let retiredPairingTitle = "This browser pairing has not been verified"
  private let setupTitle = "Start a live research session"
  private let failureTitle = "Live session unavailable"
  private let stoppedBrowser = "Brave stopped during native startup"

  @MainActor
  func testAutomaticSessionStartsWithoutPairingPrompt() throws {
    let app = try launchApplication(scenario: "automatic")
    defer { if app.state != .notRunning { app.terminate() } }

    // Reaching the inert browser's startup failure proves the launch was not
    // held behind any decision.
    let failure = assertStartupFailure(app)
    attachScreenshot(app, name: "automatic-startup-failure")
    failure.buttons["Continue Offline"].click()
    assertOffline(app, observationTimeout: 65)
    attachScreenshot(app, name: "automatic-after-offline")
  }

  @MainActor
  func testReturnRetriesAndNewSessionUsesSetup() throws {
    let app = try launchApplication(scenario: "retry")
    defer { if app.state != .notRunning { app.terminate() } }

    let first = failureDetail(assertStartupFailure(app))
    attachScreenshot(app, name: "retry-initial-failure")
    // No focus change or button click: Return is the failure alert's Retry.
    app.typeKey(.return, modifierFlags: [])
    let retried = assertFreshStartupFailure(app, after: first)
    attachScreenshot(app, name: "retry-fresh-failure")
    retried.buttons["Continue Offline"].click()
    assertOffline(app)
    attachScreenshot(app, name: "retry-after-offline")

    openNewLiveSession(app)
    let later = assertStartupFailure(app)
    attachScreenshot(app, name: "retry-new-session-failure")
    later.buttons["Continue Offline"].click()
    assertOffline(app, observationTimeout: 65)
    attachScreenshot(app, name: "retry-new-session-offline")
    // The outer driver verifies exactly three browser launches.
  }

  @MainActor
  func testReopenDuringFailureDoesNotStartAnotherSession() throws {
    let app = try launchApplication(scenario: "modal-reopen")
    defer { if app.state != .notRunning { app.terminate() } }

    let first = failureDetail(assertStartupFailure(app))
    attachScreenshot(app, name: "modal-reopen-initial-failure")
    let firstPID = try reopenApplication()
    let secondPID = try reopenApplication()
    XCTAssertEqual(firstPID, secondPID, "Reopen must address the existing app instance")
    XCTAssertEqual(app.staticTexts.matching(identifier: failureTitle).count, 1,
                   "Reopen must not nest a second live-session alert")
    XCTAssertEqual(failureDetail(app.dialogs.containing(.staticText, identifier: failureTitle).element),
                   first, "Reopen must not replace the open failure with another session")
    attachScreenshot(app, name: "modal-reopen-single-failure")

    // Reopen must preserve modal keyboard focus: Return still reaches Retry.
    app.typeKey(.return, modifierFlags: [])
    let retried = assertFreshStartupFailure(app, after: first)
    retried.buttons["Continue Offline"].click()
    assertOffline(app)
    // An explicit offline decision also suppresses automatic live startup on
    // a later OS reopen. Activating the app alone would not test that callback.
    let offlinePID = try reopenApplication()
    XCTAssertEqual(firstPID, offlinePID)
    assertOffline(app, observationTimeout: 65)
    attachScreenshot(app, name: "modal-reopen-still-offline")
  }

  @MainActor
  private func launchApplication(scenario: String) throws -> XCUIApplication {
    continueAfterFailure = false
    let environment = ProcessInfo.processInfo.environment
    let appPath = try XCTUnwrap(environment["REB_COMPANION_WARNING_APP"])
    let root = try XCTUnwrap(environment["REB_COMPANION_WARNING_ROOT"])
    let brave = try XCTUnwrap(environment["REB_COMPANION_WARNING_BRAVE"])
    let directory = URL(fileURLWithPath: root).appendingPathComponent(scenario, isDirectory: true)
    let stores = directory.appendingPathComponent("stores", isDirectory: true)
    let home = directory.appendingPathComponent("home", isDirectory: true)
    let app = XCUIApplication(url: URL(fileURLWithPath: appPath))
    // Explicit --store arguments disable automatic live startup. These are the
    // normal production environment overrides; no smoke flag or test backdoor.
    app.launchArguments = []
    app.launchEnvironment = [
      "HOME": home.path,
      "CFFIXED_USER_HOME": home.path,
      "REB_BRAVE_BINARY": brave,
      "REB_EVENT_STORE": stores.appendingPathComponent("events.jsonl").path,
      "REB_ORIGIN_TRACE_STORE": stores.appendingPathComponent("traces.jsonl").path,
      "REB_REQUEST_SIGNAL_STORE": stores.appendingPathComponent("signals.jsonl").path,
      "REB_ARTIFACT_STORE": stores.appendingPathComponent("artifacts", isDirectory: true).path,
      "REB_API_COLLECTION_STORE": stores.appendingPathComponent("collection.json").path,
      "REB_LOCAL_ANALYST_STORE": stores.appendingPathComponent("analyst.json").path,
      "REB_LIVE_SESSION_ROOT": directory.appendingPathComponent("live", isDirectory: true).path,
      "REB_BRAVE_CACHE_ROOT": directory.appendingPathComponent("cache", isDirectory: true).path,
      "REB_BRAVE_PROFILE": directory.appendingPathComponent("profile", isDirectory: true).path,
      "REB_AUTOMATIC_CAPTURE_MODE": "metadata",
      "REB_AUTOMATIC_USE_SYSTEM_KEYCHAIN": "0",
      "REB_DISABLE_AUTOMATIC_LIVE_SESSION": "0",
      "REB_CAPTURE_CANVAS_IMAGES": "0",
      // The inert browser has no V8, so the launcher would refuse any native V8
      // switch before reaching it. These are the documented opt-outs.
      "REB_NATIVE_QUIET_MODE": "0",
      "REB_NATIVE_WASM_DISPATCH": "0",
      "REB_NATIVE_WASM_CALL_INDIRECT": "0",
      "REB_LOCALHOST_ONLY": "1",
      "REB_COMPANION_WARNING_RECEIPT": directory.appendingPathComponent("launches.txt").path,
    ]
    app.launch()
    return app
  }

  @MainActor
  @discardableResult
  private func assertStartupFailure(_ app: XCUIApplication) -> XCUIElement {
    let failure = app.staticTexts[failureTitle]
    XCTAssertTrue(failure.waitForExistence(timeout: 90),
                  "The inert browser must reach the real startup failure alert: " + app.debugDescription)
    XCTAssertFalse(app.staticTexts[retiredPairingTitle].exists,
                   "A live session must start without a browser pairing prompt")
    let dialog = app.dialogs.containing(.staticText, identifier: failureTitle).element
    XCTAssertTrue(dialog.exists)
    XCTAssertTrue(failureDetail(dialog).contains(stoppedBrowser),
                  "Failure must come from the owned browser exiting, not a missing helper: " + app.debugDescription)
    // NSAlert also exposes a Touch Bar Retry button; target only the real dialog.
    XCTAssertEqual(dialog.buttons.matching(identifier: "Retry").count, 1)
    XCTAssertTrue(dialog.buttons["Retry"].isEnabled)
    XCTAssertTrue(dialog.buttons["Continue Offline"].isEnabled)
    XCTAssertTrue(dialog.buttons["Continue Offline"].isHittable)
    return dialog
  }

  /// Each attempt writes a new session log, and the alert names its path.
  @MainActor
  private func assertFreshStartupFailure(_ app: XCUIApplication, after previous: String) -> XCUIElement {
    let fresh = app.staticTexts.matching(NSPredicate(
      format: "(label CONTAINS %@ OR value CONTAINS %@) AND NOT (label == %@ OR value == %@)",
      stoppedBrowser, stoppedBrowser, previous, previous)).firstMatch
    XCTAssertTrue(fresh.waitForExistence(timeout: 90),
                  "Retry must relaunch and report a new session failure: " + app.debugDescription)
    return assertStartupFailure(app)
  }

  @MainActor
  private func failureDetail(_ dialog: XCUIElement) -> String {
    let detail = dialog.staticTexts.matching(NSPredicate(
      format: "label CONTAINS %@ OR value CONTAINS %@", "Session log:", "Session log:")).firstMatch
    XCTAssertTrue(detail.exists, "The failure alert must name its session log")
    return (detail.value as? String).flatMap { $0.isEmpty ? nil : $0 } ?? detail.label
  }

  @MainActor
  private func assertOffline(_ app: XCUIApplication, observationTimeout: TimeInterval = 2) {
    let failure = app.staticTexts[failureTitle]
    let dismissed = XCTNSPredicateExpectation(
      predicate: NSPredicate(format: "exists == false"), object: failure)
    XCTAssertEqual(XCTWaiter.wait(for: [dismissed], timeout: 10), .completed,
                   "Continue Offline must dismiss the failure alert")
    XCTAssertTrue(app.windows["Origin Trace"].waitForExistence(timeout: 10),
                  "The stored-evidence window must remain open")
    // The initial offline decisions and final reopen observe longer than the
    // coordinator's 60-second startup deadline. A short wait then termination
    // could hide an accidental launch while its helpers are still starting.
    let liveDialog = app.staticTexts.matching(NSPredicate(
      format: "label IN %@ OR value IN %@",
      [retiredPairingTitle, failureTitle, setupTitle] as NSArray,
      [retiredPairingTitle, failureTitle, setupTitle] as NSArray)).firstMatch
    let unexpected = XCTNSPredicateExpectation(
      predicate: NSPredicate(format: "exists == true"), object: liveDialog)
    unexpected.isInverted = true
    XCTAssertEqual(XCTWaiter.wait(for: [unexpected], timeout: observationTimeout), .completed,
                   "Offline must not leave a duplicate or delayed live-session dialog")
    XCTAssertEqual(app.state, .runningForeground)
  }

  @MainActor
  private func openNewLiveSession(_ app: XCUIApplication) {
    let menu = app.menuBars.menuBarItems["Origin Trace"]
    XCTAssertTrue(menu.exists, "The normal application menu must be present")
    menu.click()
    let newSession = app.menuItems["New Live Session…"]
    XCTAssertTrue(newSession.waitForExistence(timeout: 5))
    newSession.click()
    XCTAssertTrue(app.staticTexts[setupTitle].waitForExistence(timeout: 10))
    XCTAssertFalse(app.staticTexts[retiredPairingTitle].exists)
    let start = app.dialogs.containing(.staticText, identifier: setupTitle).element.buttons["Start Session"]
    XCTAssertTrue(start.isEnabled && start.isHittable)
    attachScreenshot(app, name: "retry-new-session-setup")
    start.click()
  }

  @MainActor
  private func reopenApplication() throws -> pid_t {
    let appPath = try XCTUnwrap(ProcessInfo.processInfo.environment["REB_COMPANION_WARNING_APP"])
    let applicationURL = URL(fileURLWithPath: appPath).resolvingSymlinksInPath().standardizedFileURL
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = true
    configuration.addsToRecentItems = false
    configuration.createsNewApplicationInstance = false
    configuration.allowsRunningApplicationSubstitution = false
    let reopened = expectation(description: "Launch Services reopens the existing packaged app")
    var openedApplication: NSRunningApplication?
    var openError: Error?
    NSWorkspace.shared.openApplication(at: applicationURL, configuration: configuration) { running, error in
      openedApplication = running
      openError = error
      reopened.fulfill()
    }
    XCTAssertEqual(XCTWaiter.wait(for: [reopened], timeout: 15), .completed)
    XCTAssertNil(openError, "Launch Services reopen failed: " + String(describing: openError))
    let running = try XCTUnwrap(openedApplication)
    XCTAssertEqual(running.bundleURL?.resolvingSymlinksInPath().standardizedFileURL, applicationURL)
    XCTAssertFalse(running.isTerminated)
    return running.processIdentifier
  }

  @MainActor
  private func attachScreenshot(_ app: XCUIApplication, name: String) {
    let attachment = XCTAttachment(screenshot: app.screenshot())
    attachment.name = name
    attachment.lifetime = .keepAlways
    add(attachment)
  }
}
