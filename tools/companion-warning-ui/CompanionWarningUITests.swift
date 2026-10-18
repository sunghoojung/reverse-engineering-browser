import AppKit
import XCTest

// Exercise the packaged application's production NSAlerts. The outer cloud-CI
// driver owns the synthetic stores, inert Brave app and launch receipts. This
// sandboxed runner persists screenshots only through XCTest attachments.
final class CompanionWarningUITests: XCTestCase {
  private let warningTitle = "This browser pairing has not been verified"
  private let setupTitle = "Start a live research session"
  private let failureTitle = "Live session unavailable"

  @MainActor
  func testReturnDefaultsToOfflineAndLaterSessionWarnsAgain() throws {
    let app = try launchApplication(scenario: "keyboard-offline")
    defer { if app.state != .notRunning { app.terminate() } }

    assertCompatibilityWarning(app)
    attachScreenshot(app, name: "keyboard-offline-initial-warning")
    // No focus change or button click: Return must use NSAlert's safe default.
    app.typeKey(.return, modifierFlags: [])
    assertOffline(app, observationTimeout: 65)
    attachScreenshot(app, name: "keyboard-offline-after-return")

    openNewLiveSession(app)
    assertCompatibilityWarning(app)
    attachScreenshot(app, name: "keyboard-offline-later-session-warning")
    app.dialogs.containing(.staticText, identifier: warningTitle).element.buttons["Continue Offline"].click()
    assertOffline(app)
    attachScreenshot(app, name: "keyboard-offline-later-session-offline")
  }

  @MainActor
  func testExplicitContinueOfflineDoesNotLaunchBrowser() throws {
    let app = try launchApplication(scenario: "button-offline")
    defer { if app.state != .notRunning { app.terminate() } }

    assertCompatibilityWarning(app)
    attachScreenshot(app, name: "button-offline-initial-warning")
    app.dialogs.containing(.staticText, identifier: warningTitle).element.buttons["Continue Offline"].click()
    assertOffline(app, observationTimeout: 65)
    attachScreenshot(app, name: "button-offline-after-click")
  }

  @MainActor
  func testExplicitOptInFailureAndRetryRequireAnotherDecision() throws {
    let app = try launchApplication(scenario: "retry")
    defer { if app.state != .notRunning { app.terminate() } }

    assertCompatibilityWarning(app)
    attachScreenshot(app, name: "retry-initial-warning")
    app.dialogs.containing(.staticText, identifier: warningTitle).element.buttons["Start Unverified Session"].click()
    let failure = app.staticTexts[failureTitle]
    XCTAssertTrue(failure.waitForExistence(timeout: 90),
                  "The inert browser must reach the real startup failure alert: " + app.debugDescription)
    let stoppedBrowser = app.staticTexts.matching(NSPredicate(
      format: "label CONTAINS %@ OR value CONTAINS %@",
      "Brave stopped before its debugger endpoint became ready",
      "Brave stopped before its debugger endpoint became ready")).firstMatch
    XCTAssertTrue(stoppedBrowser.exists,
                  "Failure must come from the owned browser exiting, not a missing helper: " + app.debugDescription)
    // NSAlert also exposes a Touch Bar Retry button; target only the real dialog.
    let failureDialog = app.dialogs.containing(.staticText, identifier: failureTitle).element
    XCTAssertTrue(failureDialog.exists)
    XCTAssertEqual(failureDialog.buttons.matching(identifier: "Retry").count, 1)
    XCTAssertTrue(failureDialog.buttons["Retry"].isEnabled)
    XCTAssertTrue(failureDialog.buttons["Continue Offline"].isEnabled)
    attachScreenshot(app, name: "retry-real-startup-failure")

    failureDialog.buttons["Retry"].click()
    assertCompatibilityWarning(app)
    XCTAssertFalse(failure.exists, "The failure alert must end before its fresh compatibility decision")
    attachScreenshot(app, name: "retry-fresh-warning")
    app.dialogs.containing(.staticText, identifier: warningTitle).element.buttons["Continue Offline"].click()
    assertOffline(app)
    attachScreenshot(app, name: "retry-after-offline")
    // Only the first explicit opt-in may reach the fake executable. The outer
    // driver verifies exactly one receipt after the UI runner has finished.
  }

  @MainActor
  func testReopenWhileModalDoesNotDuplicateDecision() throws {
    let app = try launchApplication(scenario: "modal-reopen")
    defer { if app.state != .notRunning { app.terminate() } }

    assertCompatibilityWarning(app)
    attachScreenshot(app, name: "modal-reopen-initial-warning")
    let firstPID = try reopenApplication()
    assertCompatibilityWarning(app)
    let secondPID = try reopenApplication()
    XCTAssertEqual(firstPID, secondPID, "Reopen must address the existing app instance")
    assertCompatibilityWarning(app)
    XCTAssertEqual(app.staticTexts.matching(identifier: warningTitle).count, 1,
                   "Reopen must not nest a second compatibility alert")
    attachScreenshot(app, name: "modal-reopen-single-warning")

    app.dialogs.containing(.staticText, identifier: warningTitle).element.buttons["Continue Offline"].click()
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
      "REB_NATIVE_QUIET_MODE": "0",
      "REB_LOCALHOST_ONLY": "1",
      "REB_COMPANION_WARNING_RECEIPT": directory.appendingPathComponent("launches.txt").path,
    ]
    app.launch()
    return app
  }

  @MainActor
  private func assertCompatibilityWarning(_ app: XCUIApplication) {
    let warning = app.staticTexts[warningTitle]
    XCTAssertTrue(warning.waitForExistence(timeout: 30),
                  "Missing production companion warning: " + app.debugDescription)
    let explanation = app.staticTexts.matching(NSPredicate(
      format: "label CONTAINS %@ OR value CONTAINS %@",
      "companion-only release", "companion-only release")).firstMatch
    XCTAssertTrue(explanation.exists, "The companion release limitation must be visible")
    let detail = explanation.label + " " + (explanation.value as? String ?? "")
    for phrase in ["0.3.0", "0.3.1", "runtime-buffer", "VM capture", "CDP Traffic",
                   "native capture completeness is not established"] {
      XCTAssertTrue(detail.contains(phrase), "Missing warning detail: " + phrase)
    }
    let dialog = app.dialogs.containing(.staticText, identifier: warningTitle).element
    XCTAssertTrue(dialog.exists)
    XCTAssertEqual(dialog.buttons.matching(identifier: "Continue Offline").count, 1)
    XCTAssertEqual(dialog.buttons.matching(identifier: "Start Unverified Session").count, 1)
    XCTAssertTrue(dialog.buttons["Continue Offline"].isEnabled)
    XCTAssertTrue(dialog.buttons["Start Unverified Session"].isEnabled)
    XCTAssertTrue(dialog.buttons["Continue Offline"].isHittable)
    XCTAssertTrue(dialog.buttons["Start Unverified Session"].isHittable)
  }

  @MainActor
  private func assertOffline(_ app: XCUIApplication, observationTimeout: TimeInterval = 2) {
    let warning = app.staticTexts[warningTitle]
    let dismissed = XCTNSPredicateExpectation(
      predicate: NSPredicate(format: "exists == false"), object: warning)
    XCTAssertEqual(XCTWaiter.wait(for: [dismissed], timeout: 10), .completed,
                   "One offline decision must dismiss the compatibility alert")
    XCTAssertTrue(app.windows["Origin Trace"].waitForExistence(timeout: 10),
                  "The stored-evidence window must remain open")
    // The initial offline decisions and final reopen observe longer than the
    // coordinator's 60-second startup deadline. A short wait then termination
    // could hide an accidental launch while its helpers are still starting.
    let liveDialog = app.staticTexts.matching(NSPredicate(
      format: "label IN %@ OR value IN %@",
      [warningTitle, failureTitle, setupTitle] as NSArray,
      [warningTitle, failureTitle, setupTitle] as NSArray)).firstMatch
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
    let start = app.dialogs.containing(.staticText, identifier: setupTitle).element.buttons["Start Session"]
    XCTAssertTrue(start.isEnabled && start.isHittable)
    attachScreenshot(app, name: "keyboard-offline-new-session-setup")
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
