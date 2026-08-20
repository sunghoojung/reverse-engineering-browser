import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

from server import JSONL_TAIL_CHUNK_BYTES, MAX_EVENT_JSON_BYTES, ResearchHandler


class ResearchUiTests(unittest.TestCase):
    def test_evidence_contract_rejects_unexpected_and_sensitive_fields(self) -> None:
        validator = Path(__file__).parents[2] / "tools" / "validate-evidence-store.py"
        valid_event = {
            "artifact_id": "300",
            "browser_context_id_high": "0",
            "browser_context_id_low": "0",
            "category": "network",
            "decoded_body_length": "0",
            "encoded_data_length": "0",
            "error_code": 0,
            "flags": 0,
            "frame_id": "200",
            "initiator_process_id": 0,
            "initiator_request_id": 0,
            "monotonic_time_ns": "1000",
            "navigation_id": "100",
            "parent_event_id": "0",
            "payload": "474554202f",
            "payload_encoding": "hex",
            "payload_size": 5,
            "payload_truncated": False,
            "process_id": 10,
            "protocol_version": 2,
            "request_id": "81",
            "resource_type": 13,
            "sequence_number": "1",
            "session_id": "1",
            "status_code": 0,
            "thread_id": 20,
            "type": "request_started",
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text(json.dumps(valid_event) + "\n", encoding="utf-8")
            subprocess.run(
                ["python3", str(validator), str(store)],
                check=True,
                capture_output=True,
                text=True,
            )

            valid_event["authorization"] = "secret"
            store.write_text(json.dumps(valid_event) + "\n", encoding="utf-8")
            result = subprocess.run(
                ["python3", str(validator), str(store)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected=['authorization']", result.stderr)

            valid_event.pop("authorization")
            payload = b"Authorization: Bearer example"
            valid_event["payload"] = payload.hex()
            valid_event["payload_size"] = len(payload)
            store.write_text(json.dumps(valid_event) + "\n", encoding="utf-8")
            result = subprocess.run(
                ["python3", str(validator), str(store)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sensitive HTTP metadata", result.stderr)

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

    def test_event_store_reads_only_the_requested_tail_window(self) -> None:
        events = [
            {"sequence_number": str(index), "payload": "x" * 2048}
            for index in range(1, 41)
        ]
        events[-1]["payload"] = "newest ☃"
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text(
                "\n\n".join(json.dumps(event, ensure_ascii=False) for event in events),
                encoding="utf-8",
            )
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            self.assertGreater(store.stat().st_size, JSONL_TAIL_CHUNK_BYTES)
            self.assertEqual(handler.load_events(2), events[-2:])
            self.assertEqual(handler.load_events(40), events)
            self.assertEqual(handler.load_events(0), [])

    def test_event_store_rejects_oversized_records(self) -> None:
        oversized = b"{" + (b"x" * MAX_EVENT_JSON_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_bytes(b'{"sequence_number":"1"}\n' + oversized)
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            with self.assertRaisesRegex(ValueError, "oversized event"):
                handler.load_events(1)
            with self.assertRaisesRegex(ValueError, "oversized event"):
                handler.load_events()

    def test_event_store_tail_rejects_a_malformed_selected_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text('{"sequence_number":"1"}\n[]\n', encoding="utf-8")
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            with self.assertRaisesRegex(ValueError, "malformed event"):
                handler.load_events(1)

    def test_event_store_tail_does_not_parse_records_outside_the_window(self) -> None:
        newest = {"sequence_number": "2", "payload": "visible"}
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "events.jsonl"
            store.write_text(
                "malformed historical record\n" + json.dumps(newest) + "\n",
                encoding="utf-8",
            )
            handler = object.__new__(ResearchHandler)
            handler.event_store = store

            self.assertEqual(handler.load_events(1), [newest])

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

    def test_event_api_uses_conditional_responses_for_unchanged_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "events.jsonl"
            store.write_text('{"sequence_number":"1"}\n', encoding="utf-8")
            artifact_store = root / "artifacts"
            artifact_store.mkdir()
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.event_store = store
            ResearchHandler.artifact_store = artifact_store
            ResearchHandler.broker_socket = None
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/api/events?limit=10"
                with urllib.request.urlopen(url) as response:
                    self.assertEqual(json.load(response)["count"], 1)
                    etag = response.headers["ETag"]

                request = urllib.request.Request(url, headers={"If-None-Match": etag})
                with self.assertRaises(urllib.error.HTTPError) as unchanged:
                    urllib.request.urlopen(request)
                self.assertEqual(unchanged.exception.code, HTTPStatus.NOT_MODIFIED)
                self.assertEqual(unchanged.exception.headers["ETag"], etag)

                different_window = urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/api/events?limit=1",
                    headers={"If-None-Match": etag},
                )
                with urllib.request.urlopen(different_window) as response:
                    self.assertEqual(json.load(response)["count"], 1)
                    self.assertNotEqual(response.headers["ETag"], etag)

                with store.open("a", encoding="utf-8") as stream:
                    stream.write('{"sequence_number":"2"}\n')
                with urllib.request.urlopen(request) as response:
                    self.assertEqual(json.load(response)["count"], 2)
                    self.assertNotEqual(response.headers["ETag"], etag)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_artifact_manifest_and_content_are_validated(self) -> None:
        content = b"export function checkout() { return true; }\n"
        digest = hashlib.sha256(content).hexdigest()
        artifact = {
            "protocol_version": 1,
            "artifact_id": "300",
            "session_id": "7",
            "navigation_id": "100",
            "frame_id": "200",
            "parent_artifact_id": "0",
            "creator_event_id": "79",
            "kind": "javascript",
            "url": "https://checkout.acme.test/assets/cart.js",
            "mime_type": "text/javascript",
            "byte_size": len(content),
            "sha256": digest,
            "sensitive": False,
            "content_path": f"blobs/{digest}.bin",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "blobs").mkdir()
            (root / artifact["content_path"]).write_bytes(content)
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            handler = object.__new__(ResearchHandler)
            handler.artifact_store = root

            self.assertEqual(handler.load_artifacts(), [artifact])
            loaded, path = handler.find_artifact("300")
            self.assertEqual(loaded, artifact)
            self.assertEqual(path.read_bytes(), content)

    def test_artifact_api_lists_metadata_and_bounds_content_windows(self) -> None:
        content = b"export const artifact = true;\n"
        digest = hashlib.sha256(content).hexdigest()
        artifact = {
            "protocol_version": 1,
            "artifact_id": "300",
            "session_id": "7",
            "navigation_id": "100",
            "frame_id": "200",
            "parent_artifact_id": "0",
            "creator_event_id": "79",
            "kind": "javascript",
            "url": "https://checkout.acme.test/assets/cart.js",
            "mime_type": "text/javascript",
            "byte_size": len(content),
            "sha256": digest,
            "sensitive": False,
            "content_path": f"blobs/{digest}.bin",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "blobs").mkdir()
            (root / artifact["content_path"]).write_bytes(content)
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.event_store = root / "events.jsonl"
            ResearchHandler.artifact_store = root
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with urllib.request.urlopen(
                    f"{base_url}/api/artifacts?limit=10"
                ) as response:
                    catalog = json.load(response)
                    catalog_etag = response.headers["ETag"]
                self.assertEqual(catalog["count"], 1)
                self.assertEqual(catalog["artifacts"][0]["artifact_id"], "300")
                self.assertNotIn("content_path", catalog["artifacts"][0])

                conditional_catalog = urllib.request.Request(
                    f"{base_url}/api/artifacts?limit=10",
                    headers={"If-None-Match": catalog_etag},
                )
                with self.assertRaises(urllib.error.HTTPError) as unchanged:
                    urllib.request.urlopen(conditional_catalog)
                self.assertEqual(unchanged.exception.code, HTTPStatus.NOT_MODIFIED)

                with urllib.request.urlopen(
                    f"{base_url}/api/artifacts/300/content?offset=2&limit=4"
                ) as response:
                    self.assertEqual(response.read(), content[2:6])
                    self.assertEqual(
                        response.headers["Content-Type"], "application/octet-stream"
                    )
                    self.assertEqual(
                        response.headers["Content-Security-Policy"], "sandbox"
                    )
                    self.assertEqual(
                        response.headers["X-Content-Type-Options"], "nosniff"
                    )
                    self.assertEqual(response.headers["X-Artifact-Truncated"], "1")
                    self.assertEqual(
                        response.headers["X-Artifact-Total-Bytes"], str(len(content))
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_vm_analysis_api_runs_automatically_and_filters_from_a_request(
        self,
    ) -> None:
        content = (
            Path(__file__).parents[2]
            / "tests"
            / "fixtures"
            / "vm-analysis"
            / "pure-js-vm.js"
        ).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        artifact = {
            "protocol_version": 1,
            "artifact_id": "300",
            "session_id": "7",
            "navigation_id": "100",
            "frame_id": "200",
            "parent_artifact_id": "0",
            "creator_event_id": "79",
            "kind": "javascript",
            "url": "https://authorized.test/pure-js-vm.js",
            "mime_type": "text/javascript",
            "byte_size": len(content),
            "sha256": digest,
            "sensitive": False,
            "content_path": f"blobs/{digest}.bin",
        }
        events = [
            {
                "session_id": "7",
                "sequence_number": "1",
                "frame_id": "200",
                "artifact_id": "300",
                "request_id": "81",
                "category": "network",
                "type": "request_started",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_store = root / "artifacts"
            (artifact_store / "blobs").mkdir(parents=True)
            (artifact_store / artifact["content_path"]).write_bytes(content)
            (artifact_store / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            event_store = root / "events.jsonl"
            event_store.write_text(
                "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
            )
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.event_store = event_store
            ResearchHandler.artifact_store = artifact_store
            ResearchHandler.broker_socket = None
            ResearchHandler.analysis_signature = None
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}/api/analysis/vm"
                with urllib.request.urlopen(base_url) as response:
                    automatic = json.load(response)
                    etag = response.headers["ETag"]
                self.assertEqual(automatic["summary"]["likely_vm_count"], 1)
                analysis_path = artifact_store / "analysis" / "vm-analysis-v1.json"
                self.assertTrue(analysis_path.is_file())

                tampered = json.loads(analysis_path.read_text(encoding="utf-8"))
                tampered["profile"]["candidate_threshold"] = 999
                analysis_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
                with urllib.request.urlopen(base_url) as response:
                    repaired = json.load(response)
                self.assertEqual(repaired["profile"]["candidate_threshold"], 20)
                self.assertEqual(
                    json.loads(analysis_path.read_text(encoding="utf-8"))["profile"][
                        "candidate_threshold"
                    ],
                    20,
                )

                unchanged = urllib.request.Request(
                    base_url, headers={"If-None-Match": etag}
                )
                with self.assertRaises(urllib.error.HTTPError) as not_modified:
                    urllib.request.urlopen(unchanged)
                self.assertEqual(not_modified.exception.code, HTTPStatus.NOT_MODIFIED)

                with urllib.request.urlopen(f"{base_url}?request_id=81") as response:
                    request_first = json.load(response)
                self.assertEqual(
                    request_first["selection"]["edge_semantics"],
                    "correlated-not-causal",
                )
                self.assertEqual(
                    [result["artifact_id"] for result in request_first["results"]],
                    ["300"],
                )

                with urllib.request.urlopen(f"{base_url}?request_id=82") as response:
                    unrelated = json.load(response)
                self.assertEqual(unrelated["results"], [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_artifact_manifest_rejects_sensitive_code_and_path_escape(self) -> None:
        artifact = {
            "protocol_version": 1,
            "artifact_id": "300",
            "session_id": "7",
            "navigation_id": "100",
            "frame_id": "200",
            "parent_artifact_id": "0",
            "creator_event_id": "79",
            "kind": "javascript",
            "url": "https://checkout.acme.test/assets/cart.js",
            "mime_type": "text/javascript",
            "byte_size": 1,
            "sha256": "0" * 64,
            "sensitive": True,
            "content_path": "../outside.bin",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "store"
            root.mkdir()
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            handler = object.__new__(ResearchHandler)
            handler.artifact_store = root

            with self.assertRaisesRegex(ValueError, "malformed record"):
                handler.load_artifacts()

            artifact["sensitive"] = False
            artifact["content_path"] = f"blobs/{artifact['sha256']}.bin"
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            (root / "blobs").mkdir()
            (Path(directory) / "outside.bin").write_bytes(b"x")
            (root / artifact["content_path"]).symlink_to(
                Path(directory) / "outside.bin"
            )
            with self.assertRaisesRegex(ValueError, "escapes"):
                handler.find_artifact("300")

    def test_artifact_manifest_rejects_noncanonical_blob_path_and_boolean_size(
        self,
    ) -> None:
        artifact = {
            "protocol_version": 1,
            "artifact_id": "300",
            "session_id": "7",
            "navigation_id": "100",
            "frame_id": "200",
            "parent_artifact_id": "0",
            "creator_event_id": "79",
            "kind": "javascript",
            "url": "https://checkout.acme.test/assets/cart.js",
            "mime_type": "text/javascript",
            "byte_size": 1,
            "sha256": "0" * 64,
            "sensitive": False,
            "content_path": "blobs/other.bin",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            handler = object.__new__(ResearchHandler)
            handler.artifact_store = root

            with self.assertRaisesRegex(ValueError, "malformed record"):
                handler.load_artifacts()

            artifact["content_path"] = f"blobs/{artifact['sha256']}.bin"
            artifact["byte_size"] = True
            (root / "manifest.jsonl").write_text(
                json.dumps(artifact) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "malformed record"):
                handler.load_artifacts()

    def test_broker_connection_tracks_unix_socket_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "broker.sock"
            handler = object.__new__(ResearchHandler)
            handler.broker_socket = socket_path
            self.assertFalse(handler.broker_connected())

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
                self.assertTrue(handler.broker_connected())
            finally:
                listener.close()

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
        for unsafe_sink in (
            ".innerHTML",
            ".outerHTML",
            "insertAdjacentHTML",
            "document.write",
        ):
            self.assertNotIn(unsafe_sink, html)

    def test_network_workspace_exposes_baseline_inspection_and_health_states(
        self,
    ) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        for label in (
            "Headers",
            "Payload",
            "Preview",
            "Response",
            "Initiator",
            "Timing",
        ):
            self.assertIn(f">{label}</button>", html)
        self.assertIn('data-kind="loading"', html)
        for state in ("empty", "disconnected", "malformed", "gap"):
            self.assertIn(f"'{state}'", html)
        self.assertIn("Fetch/XHR", html)
        self.assertIn("No live requests yet", html)
        self.assertIn("Response body capture is disabled", html)
        self.assertGreaterEqual(html.count("'If-None-Match'"), 2)
        self.assertGreaterEqual(html.count("response.status === 304"), 2)
        self.assertIn("`${integerText(event, 'session_id')}:${event.process_id}`", html)
        self.assertIn("body.events.every(isBrokerEvent)", html)
        self.assertIn("body.count === body.events.length", html)
        self.assertIn("isCanonicalInteger(event[field], 0n, uint64Max)", html)
        self.assertIn("function correlatedRendererIdentity(event)", html)
        self.assertIn(
            "`S${session}:P${event.process_id}:C${context}:B${requestId}`", html
        )
        self.assertIn("browser context ${context}", html)
        self.assertIn("[13, 'xhr']", html)
        self.assertIn("No requests match the current filters", html)

    def test_sources_workspace_matches_the_devtools_navigation_model(self) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        self.assertIn('data-screen="sources">Sources</button>', html)
        self.assertIn('aria-label="Sources navigator"', html)
        self.assertIn(">Page</button>", html)
        self.assertIn(">Filesystem</button>", html)
        self.assertIn(">Overrides</button>", html)
        self.assertIn('aria-label="Source editor"', html)
        self.assertIn('aria-label="Debugger sidebar"', html)
        for pane in (
            "Artifact details",
            "Watch",
            "Breakpoints",
            "Scope",
            "Call Stack",
            "XHR/fetch Breakpoints",
            "Event Listener Breakpoints",
        ):
            self.assertIn(f">{pane}</summary>", html)
        self.assertIn("function renderSourceTree()", html)
        self.assertIn("function formatWasmHex(buffer)", html)
        self.assertIn("function openQuickOpen()", html)
        self.assertIn("Viewer preview limited to the first 2 MB", html)
        self.assertIn("Readable derived view", html)
        self.assertIn("Original evidence", html)
        self.assertIn("elements.sourceCode.replaceChildren", html)

    def test_sources_model_rejects_malformed_artifact_catalogs(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")

        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
        start = html.index("      function isPlainObject")
        end = html.index("      function legacyBrowserRequestKey")
        model = """
const uint64Max = 18446744073709551615n;
const artifactKinds = new Set(['javascript', 'wasm', 'source_map', 'response_body']);
const artifactIdentifierFields = [
  'artifact_id', 'session_id', 'navigation_id', 'frame_id', 'parent_artifact_id', 'creator_event_id'
];
""" + html[start:end]
        exercise = r"""
const artifact = {
  protocol_version: 1,
  artifact_id: '300',
  session_id: '7',
  navigation_id: '100',
  frame_id: '200',
  parent_artifact_id: '0',
  creator_event_id: '79',
  kind: 'javascript',
  url: 'https://checkout.acme.test/assets/cart.js',
  mime_type: 'text/javascript',
  byte_size: 123,
  sha256: 'a'.repeat(64),
  sensitive: false
};
process.stdout.write(JSON.stringify({
  accepted: isArtifact(artifact),
  canonicalIdRequired: !isArtifact({...artifact, artifact_id: '0300'}),
  kindRequired: !isArtifact({...artifact, kind: 'archive'}),
  digestRequired: !isArtifact({...artifact, sha256: 'a'}),
  sensitiveCodeRejected: !isArtifact({...artifact, sensitive: true}),
  approvedBodyAccepted: isArtifact({...artifact, kind: 'response_body', sensitive: true}),
  envelopeCountRequired: !isArtifactResponse({count: 2, artifacts: [artifact]}),
  validEnvelope: isArtifactResponse({count: 1, artifacts: [artifact]})
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
                "accepted": True,
                "canonicalIdRequired": True,
                "kindRequired": True,
                "digestRequired": True,
                "sensitiveCodeRejected": True,
                "approvedBodyAccepted": True,
                "envelopeCountRequired": True,
                "validEnvelope": True,
            },
        )

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

    def test_vm_lab_exposes_typed_evidence_and_failure_states(self) -> None:
        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

        self.assertIn('data-screen="vm">VM Lab</button>', html)
        self.assertIn('id="screen-vm"', html)
        self.assertIn('role="listbox" aria-label="Captured VM findings"', html)
        for evidence_kind in (
            "interpreter",
            "guest program",
            "invocation",
            "host binding",
            "hypothesis",
            "coverage",
        ):
            self.assertIn(evidence_kind, html)
        self.assertIn("function decodeVmFinding(event)", html)
        self.assertIn("function vmFindingsFromEvents(events)", html)
        self.assertIn("malformed VM", html)
        self.assertIn("No VM findings yet", html)
        self.assertIn("gaps may", html)
        self.assertIn("Last valid VM findings remain visible", html)
        self.assertIn("['ArrowUp', 'ArrowDown', 'Home', 'End']", html)
        self.assertIn("state.broker === 'connecting'", html)
        self.assertIn("source p${finding.processId}:t${finding.threadId}", html)
        self.assertIn("operation ${finding.kind}", html)
        self.assertIn("focusedFindingId", html)
        self.assertIn("focus({ preventScroll: true })", html)
        self.assertIn("Open in Sources", html)
        self.assertIn("selectArtifact(sourceArtifact.artifact_id)", html)
        self.assertIn("function isVmAnalysisDocument(document)", html)
        self.assertIn("function vmFindingsFromAnalysis(document)", html)
        self.assertIn("/api/analysis/vm", html)
        self.assertIn("Malformed VM analysis was rejected", html)
        self.assertIn("anti-bot relevance", html)
        self.assertIn("Related VM candidates", html)
        self.assertIn("correlated · unknown", html)

    def test_vm_analysis_refresh_failure_retains_last_valid_findings(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")

        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
        start = html.index("      function retainVmAnalysisOnFailure")
        end = html.index("      async function refreshVmAnalysis", start)
        helper = html[start:end]
        exercise = r"""
const derived = { findingId: "analysis:derived" };
const event = { findingId: "event:captured" };
const targetState = {
  lastValidAnalysisFindings: [derived],
  eventVmFindings: [event],
  vmFindings: []
};
retainVmAnalysisOnFailure(targetState, "unavailable", "connection failed");
console.log(JSON.stringify({
  status: targetState.vmAnalysisStatus,
  error: targetState.vmAnalysisError,
  findings: targetState.vmFindings.map(finding => finding.findingId),
  derivedIdentityRetained: targetState.vmFindings[0] === derived,
  eventIdentityRetained: targetState.vmFindings[1] === event
}));
"""
        completed = subprocess.run(
            [node, "-e", helper + exercise],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            json.loads(completed.stdout),
            {
                "status": "unavailable",
                "error": "connection failed",
                "findings": ["analysis:derived", "event:captured"],
                "derivedIdentityRetained": True,
                "eventIdentityRetained": True,
            },
        )

    def test_network_model_validates_and_aggregates_without_losing_integer_precision(
        self,
    ) -> None:
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
  artifactCapturedAccepted: isBrokerEvent(v2({category: "artifact", type: "artifact_captured"})),
  artifactFailureAccepted: isBrokerEvent(v2({category: "artifact", type: "artifact_capture_failed"})),
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
                "artifactCapturedAccepted": True,
                "artifactFailureAccepted": True,
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

    def test_vm_model_decodes_versioned_findings_and_rejects_bad_contracts(
        self,
    ) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")

        html = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
        start = html.index("      const eventCategories")
        end = html.index("      function setNetworkNotice")
        model = html[start:end]
        exercise = r"""
const findingEvent = (mutate = () => {}) => {
  const bytes = new Uint8Array(128);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 1, true);
  view.setUint16(2, 128, true);
  bytes[4] = 6;
  bytes[5] = 3;
  bytes[6] = 1;
  bytes[7] = 2;
  view.setUint16(8, 22, true);
  view.setUint32(12, 42, true);
  view.setUint32(16, 60, true);
  view.setBigUint64(24, 106n, true);
  view.setBigUint64(32, 7001n, true);
  view.setBigUint64(40, 1001n, true);
  const label = 'handlers characterized';
  [...label].forEach((character, index) => { bytes[72 + index] = character.charCodeAt(0); });
  mutate(bytes, view);
  const payload = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return {
    protocol_version: 2,
    session_id: '1',
    sequence_number: '13',
    monotonic_time_ns: '1000',
    process_id: 10,
    thread_id: 20,
    navigation_id: '100',
    frame_id: '200',
    artifact_id: '300',
    parent_event_id: '12',
    request_id: '0',
    browser_context_id_high: '0',
    browser_context_id_low: '0',
    encoded_data_length: '0',
    decoded_body_length: '0',
    status_code: 0,
    error_code: 0,
    resource_type: 0,
    flags: 0,
    initiator_request_id: 0,
    initiator_process_id: 0,
    payload_truncated: false,
    category: 'vm',
    type: 'vm_finding',
    payload_size: 128,
    payload_encoding: 'hex',
    payload
  };
};
const valid = findingEvent();
const decoded = decodeVmFinding(valid);
const badCounts = findingEvent((bytes, view) => { view.setUint32(12, 61, true); });
const badTail = findingEvent(bytes => { bytes[100] = 1; });
const truncated = {...valid, flags: 1, payload_truncated: true};
const overflowRange = findingEvent((bytes, view) => {
  bytes[4] = 2;
  bytes[7] = 1;
  view.setUint32(12, 0, true);
  view.setUint32(16, 0, true);
  view.setBigUint64(56, 18446744073709551615n, true);
  view.setBigUint64(64, 2n, true);
});
const modelResult = vmFindingsFromEvents([valid, badCounts, badTail, truncated, overflowRange]);
process.stdout.write(JSON.stringify({
  brokerAccepted: isBrokerEvent(valid),
  findingId: decoded.findingId,
  investigationId: decoded.investigationId,
  kind: decoded.kind,
  runtime: decoded.hostRuntime,
  confidence: decoded.confidence,
  label: decoded.label,
  observedCount: decoded.observedCount,
  totalCount: decoded.totalCount,
  flags: decoded.flags,
  monotonicTimeNs: decoded.monotonicTimeNs,
  processId: decoded.processId,
  threadId: decoded.threadId,
  badCountsRejected: decodeVmFinding(badCounts) === null,
  badTailRejected: decodeVmFinding(badTail) === null,
  truncatedRejected: decodeVmFinding(truncated) === null,
  overflowRangeRejected: decodeVmFinding(overflowRange) === null,
  validCount: modelResult.findings.length,
  malformedCount: modelResult.malformedCount
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
                "brokerAccepted": True,
                "findingId": "106",
                "investigationId": "7001",
                "kind": "coverage",
                "runtime": "mixed",
                "confidence": "observed",
                "label": "handlers characterized",
                "observedCount": 42,
                "totalCount": 60,
                "flags": ["partial"],
                "monotonicTimeNs": "1000",
                "processId": 10,
                "threadId": 20,
                "badCountsRejected": True,
                "badTailRejected": True,
                "truncatedRejected": True,
                "overflowRangeRejected": True,
                "validCount": 1,
                "malformedCount": 4,
            },
        )

    def test_native_application_uses_the_packaged_icon(self) -> None:
        macos_directory = Path(__file__).parent / "macos"
        application = (macos_directory / "OriginTraceApp.swift").read_text(
            encoding="utf-8"
        )
        plist = (macos_directory / "Info.plist").read_text(encoding="utf-8")
        build_script = (
            Path(__file__).parents[2] / "scripts" / "build-research-app.sh"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "configureApplicationIcon(resourcesURL: resourcesURL)", application
        )
        self.assertIn('appendingPathComponent("OriginTrace.icns")', application)
        self.assertIn("NSApp.applicationIconImage = icon", application)
        self.assertNotIn("makeApplicationIcon", application)
        self.assertIn('case "/api/artifacts":', application)
        self.assertIn('case "/api/analysis/vm":', application)
        self.assertIn("vmAnalysisResponse(for: requestURL)", application)
        self.assertIn("artifactContentResponse(for: requestURL)", application)
        self.assertIn('"Content-Security-Policy": "sandbox"', application)
        self.assertIn('"X-Artifact-Truncated"', application)
        self.assertIn('firstIndex(of: "--artifacts")', application)
        self.assertIn("source-tree-row[data-artifact-id]", application)
        self.assertIn("sourceLines", application)
        self.assertIn("<key>CFBundleIconFile</key>", plist)
        self.assertIn("<string>OriginTrace</string>", plist)
        self.assertIn("origin-trace-icon.png", build_script)
        self.assertIn("build/sessions/artifacts", build_script)
        self.assertIn('"${resources_path}/artifacts"', build_script)
        self.assertIn("iconutil -c icns", build_script)


if __name__ == "__main__":
    unittest.main()
