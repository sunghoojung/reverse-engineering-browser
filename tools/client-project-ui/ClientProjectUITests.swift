import XCTest

// A real Xcode UI-test process operates Apple's out-of-process Save panel.
// The app's existing smoke owns every fixture/destination and verifies bytes.
final class ClientProjectUITests: XCTestCase {
  @MainActor
  func testNativeSavePanels() throws {
    continueAfterFailure = false
    let environment = ProcessInfo.processInfo.environment
    let appPath = try XCTUnwrap(environment["REB_CLIENT_PROJECT_APP"])
    let output = try XCTUnwrap(environment["REB_CLIENT_PROJECT_OUTPUT"])
    let stores = try XCTUnwrap(environment["REB_CLIENT_PROJECT_STORES"])
    let app = XCUIApplication(url: URL(fileURLWithPath: appPath))
    app.launchArguments = ["--store", stores + "/events.jsonl",
      "--trace-store", stores + "/traces.jsonl", "--signal-store", stores + "/signals.jsonl",
      "--artifacts", stores + "/artifacts", "--api-collection", stores + "/collection.json",
      "--local-analyst", stores + "/analyst.json"]
    app.launchEnvironment = ["REB_APP_SMOKE_TEST": "1", "REB_APP_SMOKE_CLIENT_PROJECT": "1",
      "REB_APP_SMOKE_CLIENT_PROJECT_OUTPUT": output, "REB_DISABLE_AUTOMATIC_LIVE_SESSION": "1",
      "REB_APP_SMOKE_NATIVE_CLOSE": "", "REB_APP_SMOKE_LIVE_FAILURE": "0"]
    app.launch()
    defer { if app.state != .notRunning { app.terminate() } }
    for phase in ["save", "writeFailure", "replacementSave"] {
      let window = app.windows["Client project smoke: " + phase]
      XCTAssertTrue(window.waitForExistence(timeout: 30), "Missing native phase " + phase)
      let save = window.sheets.buttons["Save"].firstMatch
      XCTAssertTrue(save.waitForExistence(timeout: 15), "Missing real Save button: " + app.debugDescription)
      XCTAssertTrue(save.isEnabled, "Real Save button is disabled")
      let screenshot = app.screenshot()
      // The UI-test runner is sandboxed. XCTest owns screenshot persistence;
      // the outer driver exports attachments and checks the native byte receipt.
      let attachment = XCTAttachment(screenshot: screenshot)
      attachment.name = phase + "-native-save-panel"
      attachment.lifetime = .keepAlways
      add(attachment)
      save.click()
      // Wait for the old phase to end before resolving the next Save control.
      let advanced = XCTNSPredicateExpectation(predicate: NSPredicate(format: "exists == false"), object: window)
      XCTAssertEqual(XCTWaiter.wait(for: [advanced], timeout: 20), .completed)
    }
    XCTAssertTrue(app.wait(for: .notRunning, timeout: 20), "Native exact-byte verification did not finish")
  }
}
