"""Exercise the OpenAPI client and CLI against a temporary real HTTP server."""

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from api_client import ApiClient, ApiClientError, ApiContract, endpoint_file_url
from api_collection import ApiCollectionStore
from local_analyst import LocalAnalystStore
from server import LoopbackThreadingHTTPServer, ResearchHandler


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "apps/research-ui/api_cli.py"


class ApiCliTest(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, str(CLI), *arguments],
                              capture_output=True, text=True, timeout=10, check=False)

    def test_discovery_and_local_endpoint_rejection(self):
        contract = ApiContract()
        self.assertEqual(len(contract.operations), 19)
        listed = self.run_cli("list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("get_events\tGET\t/api/events", listed.stdout)
        described = self.run_cli("describe", "debugger_action")
        self.assertEqual(described.returncode, 0, described.stderr)
        self.assertEqual(len(json.loads(described.stdout)["actions"]), 59)
        for url in ("https://127.0.0.1:7319", "http://example.invalid:7319",
                    "http://127.0.0.1:7319/other", "http://user@localhost:7319"):
            with self.assertRaises(ApiClientError):
                ApiClient(url)
        with tempfile.TemporaryDirectory() as temporary:
            endpoint = Path(temporary) / "endpoint"
            endpoint.write_text("http://example.invalid:7319\n")
            with self.assertRaises(ApiClientError):
                endpoint_file_url(endpoint)

    def test_real_server_json_errors_conditional_and_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)

            class Handler(ResearchHandler):
                ui_directory = ROOT / "apps/research-ui"
                event_store = directory / "events.jsonl"
                trace_store = directory / "trace.jsonl"
                signal_store = directory / "signals.jsonl"
                artifact_store = directory / "artifacts"
                api_collection_store = ApiCollectionStore(directory / "collection.json")
                local_analyst_store = LocalAnalystStore(directory / "analyst.json")
                debugger = None
                broker_socket = None
                broker_pid = None
                capture_stopped = False

            content = b"ab\x00def"
            digest = hashlib.sha256(content).hexdigest()
            (Handler.artifact_store / "blobs").mkdir(parents=True)
            (Handler.artifact_store / "blobs" / f"{digest}.bin").write_bytes(content)
            artifact = {
                "protocol_version": 1, "artifact_id": "1", "session_id": "1",
                "navigation_id": "0", "frame_id": "0", "parent_artifact_id": "0",
                "creator_event_id": "0", "execution_context_id": "0",
                "capture_origin": "unknown", "kind": "javascript",
                "url": "https://example.invalid/code.js", "mime_type": "text/javascript",
                "byte_size": len(content), "sha256": digest, "sensitive": False,
                "content_path": f"blobs/{digest}.bin",
            }
            (Handler.artifact_store / "manifest.jsonl").write_text(json.dumps(artifact) + "\n")
            server = LoopbackThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"
            endpoint = directory / "endpoint"
            endpoint.write_text(base_url + "\n")
            try:
                client = ApiClient(endpoint_file_url(endpoint))
                health = client.call("get_health")
                self.assertEqual(health.status, 200)
                self.assertEqual(health.json()["status"], "ok")
                events = client.call("get_events", {"limit": 1})
                self.assertEqual(events.json()["events"], [])
                unchanged = client.call("get_events", {"limit": 1,
                                                       "If-None-Match": events.headers["etag"]})
                self.assertEqual((unchanged.status, unchanged.body), (304, b""))
                unavailable = client.call("debugger_action", body={"action": "pause"})
                self.assertEqual(unavailable.status, 409)
                self.assertIn("error", unavailable.json())

                output = self.run_cli("call", "get_events", "--endpoint-file", str(endpoint),
                                      "--param", "limit=1", "--show-headers")
                self.assertEqual(output.returncode, 0, output.stderr)
                self.assertEqual(json.loads(output.stdout)["events"], [])
                self.assertIn('"etag"', output.stderr)
                cached = self.run_cli("call", "get_events", "--endpoint-file", str(endpoint),
                                      "--param", "limit=1", "--param",
                                      f"If-None-Match={events.headers['etag']}")
                self.assertEqual(cached.returncode, 0, cached.stderr)
                self.assertEqual(cached.stdout, "")
                denied = self.run_cli("call", "debugger_action", "--base-url", base_url)
                self.assertEqual(denied.returncode, 2)
                self.assertIn("requires a JSON body", denied.stderr)
                action_body = directory / "action.json"
                action_body.write_text('{"action":"pause"}')
                rejected = self.run_cli("call", "debugger_action", "--base-url", base_url,
                                        "--body-file", str(action_body))
                self.assertEqual(rejected.returncode, 1)
                self.assertIn("HTTP 409", rejected.stderr)

                chunk = client.call("get_artifact_content",
                                    {"artifact_id": "1", "offset": 2, "limit": 2})
                self.assertEqual((chunk.status, chunk.body), (200, b"\x00d"))
                self.assertEqual(chunk.headers["x-artifact-total-bytes"], "6")
                saved = directory / "chunk.bin"
                binary = self.run_cli("call", "get_artifact_content", "--base-url", base_url,
                                      "--param", "artifact_id=1", "--param", "offset=2",
                                      "--param", "limit=2", "--output", str(saved))
                self.assertEqual(binary.returncode, 0, binary.stderr)
                self.assertEqual(saved.read_bytes(), b"\x00d")
                again = self.run_cli("call", "get_artifact_content", "--base-url", base_url,
                                     "--param", "artifact_id=1", "--output", str(saved))
                self.assertEqual(again.returncode, 2)
                self.assertEqual(saved.read_bytes(), b"\x00d")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_preflight_body_and_parameter_limits(self):
        client = ApiClient("http://127.0.0.1:7319")
        with self.assertRaisesRegex(ApiClientError, "unknown parameter"):
            client.call("get_events", {"not_a_parameter": 1})
        with self.assertRaisesRegex(ApiClientError, "missing parameter"):
            client.call("get_artifact_content")
        with self.assertRaisesRegex(ApiClientError, "does not accept a body"):
            client.call("get_events", body={})
        with self.assertRaisesRegex(ApiClientError, "requires a JSON body"):
            client.call("debugger_action")
        maximum = client.contract.operation("debugger_action").definition["x-max-body-bytes"]
        with self.assertRaisesRegex(ApiClientError, "exceeds"):
            client.call("debugger_action", body={"action": "pause", "padding": "x" * maximum})


if __name__ == "__main__":
    unittest.main()
