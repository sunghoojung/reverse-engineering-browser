import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from server import ResearchHandler


class ResearchUiTests(unittest.TestCase):
    def test_event_store_preserves_normalized_records(self) -> None:
        event = {
            "protocol_version": 1,
            "session_id": 7,
            "sequence_number": 12,
            "category": "network",
            "type": "request_started",
            "payload_encoding": "hex",
            "payload": "504f5354202f63617274",
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text(json.dumps(event) + "\n", encoding="utf-8")
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            self.assertEqual(handler.load_events(), [event])

    def test_missing_event_store_is_an_empty_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            handler = object.__new__(ResearchHandler)
            handler.event_store = Path(directory) / "missing.jsonl"

            self.assertEqual(handler.load_events(), [])

    def test_event_store_rejects_non_object_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text("[]\n", encoding="utf-8")
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            with self.assertRaisesRegex(ValueError, "malformed event"):
                handler.load_events()

    def test_ui_keeps_captured_values_out_of_html_injection_paths(self) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        self.assertIn("Request Field Backtrace", html)
        self.assertIn("Trace origin", html)
        self.assertIn("Evidence gap", html)
        self.assertIn("Unknown", html)
        self.assertIn("width: 100%", html)
        self.assertIn("height: 100vh", html)
        self.assertIn("standalone preview", html)
        self.assertIn("textContent", html)
        for unsafe_sink in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"):
            self.assertNotIn(unsafe_sink, html)

    def test_network_workspace_exposes_baseline_inspection_and_health_states(self) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        for label in ("Headers", "Payload", "Preview", "Response", "Initiator", "Timing"):
            self.assertIn(f">{label}</button>", html)
        self.assertIn('data-kind="loading"', html)
        for state in ("empty", "disconnected", "malformed", "gap"):
            self.assertIn(f"'{state}'", html)
        self.assertIn("Fetch/XHR", html)
        self.assertIn("No live requests yet", html)
        self.assertIn("Response body capture is disabled", html)
        self.assertIn("`${integerText(event, 'session_id')}:${event.process_id}`", html)
        self.assertIn("body.events.every(isBrokerEvent)", html)
        self.assertIn("body.count === body.events.length", html)
        self.assertIn("isCanonicalInteger(event[field], 0n, uint64Max)", html)
        self.assertIn("function correlatedRendererIdentity(event)", html)
        self.assertIn("`S${session}:P${event.process_id}:C${context}:B${requestId}`", html)
        self.assertIn("browser context ${context}", html)
        self.assertIn("[13, 'xhr']", html)
        self.assertIn("No requests match the current filters", html)

    def test_tab_controls_have_keyboard_and_panel_relationships(self) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        self.assertIn('role="tabpanel" aria-labelledby="inspector-tab-payload"', html)
        self.assertIn('aria-controls="request-inspector"', html)
        self.assertIn('aria-controls="field-tree"', html)
        self.assertIn("enableTabKeyboardNavigation('.inspector-tab')", html)
        self.assertIn("['ArrowLeft', 'ArrowRight', 'Home', 'End']", html)
        self.assertIn("row.addEventListener('keydown', moveRequestSelection)", html)
        self.assertIn('role="listbox" aria-label="Captured requests"', html)
        self.assertIn("row.setAttribute('role', 'option')", html)
        self.assertIn("row.setAttribute('aria-pressed'", html)
        self.assertIn('aria-label="Filter requests"', html)
        self.assertIn("button.disabled = traceUnavailable", html)
        self.assertIn("&& !state.selectedField) return", html)
        self.assertIn("requestAnimationFrame", html)
        self.assertIn("selectedRow ?? elements.requestFilter", html)

    def test_network_model_validates_and_aggregates_without_losing_integer_precision(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")

        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
        start = html.index("      const eventCategories")
        end = html.index("      function setNetworkNotice")
        model = html[start:end]
        exercise = r"""
const v2 = (overrides = {}) => ({
  protocol_version: 2,
  session_id: "1",
  sequence_number: "1",
  monotonic_time_ns: "9007199254740993000",
  process_id: 10,
  thread_id: 20,
  navigation_id: "100",
  frame_id: "200",
  artifact_id: "300",
  parent_event_id: "0",
  request_id: "81",
  browser_context_id_high: "0",
  browser_context_id_low: "0",
  encoded_data_length: "0",
  decoded_body_length: "0",
  status_code: 0,
  error_code: 0,
  resource_type: 13,
  flags: 0,
  initiator_request_id: 0,
  initiator_process_id: 0,
  payload_truncated: false,
  category: "network",
  type: "request_initiated",
  payload_size: 5,
  payload_encoding: "hex",
  payload: "4745542078",
  ...overrides
});
const legacyV2 = (overrides = {}) => {
  const event = v2(overrides);
  delete event.browser_context_id_high;
  delete event.browser_context_id_low;
  return event;
};
const oneSidedContext = legacyV2();
oneSidedContext.browser_context_id_high = "1";
const v1 = (overrides = {}) => ({
  protocol_version: 1,
  session_id: 1,
  sequence_number: 1,
  monotonic_time_ns: 1000,
  process_id: 10,
  thread_id: 20,
  navigation_id: 100,
  frame_id: 200,
  artifact_id: 300,
  parent_event_id: 0,
  category: "network",
  type: "request_started",
  payload_size: 5,
  payload_encoding: "hex",
  payload: "4745542078",
  ...overrides
});
const requests = requestsFromEvents([
  v2(),
  v2({sequence_number: "2", monotonic_time_ns: "9007199254741993000", type: "request_started"}),
  v2({sequence_number: "3", monotonic_time_ns: "9007199254742993000", type: "response_started", status_code: 200, payload_size: 0, payload: ""}),
  v2({sequence_number: "4", monotonic_time_ns: "9007199254743993000", type: "request_completed", payload_size: 0, payload: ""}),
  v2({sequence_number: "5", type: "gap", request_id: "0", payload_size: 0, payload: ""}),
  v2({session_id: "2"})
]);
const outOfOrder = requestsFromEvents([
  v2({
    sequence_number: "4",
    monotonic_time_ns: "9007199254743993000",
    process_id: 99,
    request_id: "700",
    initiator_process_id: 10,
    initiator_request_id: 81,
    browser_context_id_high: "9007199254740993",
    browser_context_id_low: "18446744073709551615",
    type: "request_completed",
    status_code: 204,
    payload_size: 0,
    payload: ""
  }),
  v2({
    sequence_number: "3",
    monotonic_time_ns: "9007199254742993000",
    process_id: 99,
    request_id: "700",
    initiator_process_id: 10,
    initiator_request_id: 81,
    browser_context_id_high: "9007199254740993",
    browser_context_id_low: "18446744073709551615",
    type: "request_redirected",
    status_code: 302,
    payload_size: 14,
    payload: "4745542072656469726563746564"
  }),
  v2({
    sequence_number: "2",
    monotonic_time_ns: "9007199254741993000",
    process_id: 99,
    request_id: "700",
    initiator_process_id: 10,
    initiator_request_id: 81,
    browser_context_id_high: "9007199254740993",
    browser_context_id_low: "18446744073709551615",
    type: "request_started"
  }),
  v2()
]);
const browserContextRequests = requestsFromEvents([
  v2({type: "request_started", process_id: 99, request_id: "700", browser_context_id_high: "9007199254740993", browser_context_id_low: "1"}),
  v2({type: "request_started", process_id: 99, request_id: "700", browser_context_id_high: "9007199254740993", browser_context_id_low: "2"}),
  v2({type: "request_started", process_id: 100, request_id: "700", browser_context_id_high: "9007199254740993", browser_context_id_low: "1"})
]);
process.stdout.write(JSON.stringify({
  v2Accepted: isBrokerEvent(v2()),
  legacyV2Accepted: isBrokerEvent(legacyV2()),
  oneSidedContextRejected: !isBrokerEvent(oneSidedContext),
  nonCanonicalContextRejected: !isBrokerEvent(v2({browser_context_id_low: "01"})),
  numericV2Rejected: !isBrokerEvent(v2({session_id: 1})),
  nonCanonicalV2Rejected: !isBrokerEvent(v2({session_id: "01"})),
  negativeUnsignedV2Rejected: !isBrokerEvent(v2({request_id: "-1"})),
  oversizedV2Rejected: !isBrokerEvent(v2({session_id: "18446744073709551616"})),
  mismatchedPayloadRejected: !isBrokerEvent(v2({payload_size: 4})),
  truncationMismatchRejected: !isBrokerEvent(v2({payload_truncated: true})),
  unknownV2Rejected: !isBrokerEvent(v2({category: "unknown"})),
  unsupportedFlagsRejected: !isBrokerEvent(v2({flags: 8})),
  v1Accepted: isBrokerEvent(v1()),
  unsafeV1Rejected: !isBrokerEvent(v1({session_id: 9007199254740992})),
  requestIds: requests.map(request => request.id),
  status: requests[0].status,
  resourceType: requests[0].type,
  duration: requests[0].time,
  outOfOrder: {
    count: outOfOrder.length,
    id: outOfOrder[0].id,
    status: outOfOrder[0].status,
    operation: outOfOrder[0].operation,
    path: outOfOrder[0].path,
    duration: outOfOrder[0].time,
    events: outOfOrder[0].events.length
  },
  browserContextIds: browserContextRequests.map(request => request.id),
  browserContextToken: browserContextToken(v2({
    browser_context_id_high: "9007199254740993",
    browser_context_id_low: "18446744073709551615"
  })),
  gap: String(countSequenceGaps([
    v2({sequence_number: "9007199254740993000"}),
    v2({sequence_number: "9007199254740993002"})
  ])),
  explicitGap: String(countSequenceGaps([
    v2(),
    v2({sequence_number: "2", type: "gap", request_id: "0", payload_size: 0, payload: ""})
  ]))
}));
"""
        completed = subprocess.run(
            [node, "-e", model + exercise],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            json.loads(completed.stdout),
            {
                "v2Accepted": True,
                "legacyV2Accepted": True,
                "oneSidedContextRejected": True,
                "nonCanonicalContextRejected": True,
                "numericV2Rejected": True,
                "nonCanonicalV2Rejected": True,
                "negativeUnsignedV2Rejected": True,
                "oversizedV2Rejected": True,
                "mismatchedPayloadRejected": True,
                "truncationMismatchRejected": True,
                "unknownV2Rejected": True,
                "unsupportedFlagsRejected": True,
                "v1Accepted": True,
                "unsafeV1Rejected": True,
                "requestIds": ["S1:R10:81", "S2:R10:81"],
                "status": 200,
                "resourceType": "xhr",
                "duration": "3.000 ms",
                "outOfOrder": {
                    "count": 1,
                    "id": "S1:R10:81",
                    "status": 204,
                    "operation": "request_completed",
                    "path": "redirected",
                    "duration": "3.000 ms",
                    "events": 4,
                },
                "browserContextIds": [
                    "S1:P99:C9007199254740993:1:B700",
                    "S1:P99:C9007199254740993:2:B700",
                    "S1:P100:C9007199254740993:1:B700",
                ],
                "browserContextToken": "9007199254740993:18446744073709551615",
                "gap": "1",
                "explicitGap": "1",
            },
        )

    def test_native_application_uses_the_packaged_icon(self) -> None:
        macos_directory = Path(__file__).parent / "macos"
        application = (macos_directory / "OriginTraceApp.swift").read_text(encoding="utf-8")
        plist = (macos_directory / "Info.plist").read_text(encoding="utf-8")
        build_script = (Path(__file__).parents[2] / "scripts" / "build-research-app.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("configureApplicationIcon(resourcesURL: resourcesURL)", application)
        self.assertIn('appendingPathComponent("OriginTrace.icns")', application)
        self.assertIn("NSApp.applicationIconImage = icon", application)
        self.assertNotIn("makeApplicationIcon", application)
        self.assertIn("<key>CFBundleIconFile</key>", plist)
        self.assertIn("<string>OriginTrace</string>", plist)
        self.assertIn("origin-trace-icon.png", build_script)
        self.assertIn("iconutil -c icns", build_script)


if __name__ == "__main__":
    unittest.main()
