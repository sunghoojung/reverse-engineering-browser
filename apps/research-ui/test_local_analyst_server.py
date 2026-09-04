#!/usr/bin/env python3

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from local_analyst import LocalAnalystRunner, LocalAnalystStore
from server import ResearchHandler


class LocalAnalystServerTest(unittest.TestCase):
    def test_local_analyst_http_library_run_and_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_store = ResearchHandler.local_analyst_store
            previous_runner = ResearchHandler.local_analyst_runner
            runner = LocalAnalystRunner(Path(__file__).parent)
            if not runner.available():
                self.skipTest("Node.js 22 or newer is not installed")
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.local_analyst_store = LocalAnalystStore(
                root / "workspace.json"
            )
            ResearchHandler.local_analyst_runner = runner
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"

            def post(value: dict) -> dict:
                request = urllib.request.Request(
                    f"{base}/api/local-analyst/actions",
                    data=json.dumps(value).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.load(response)

            try:
                with urllib.request.urlopen(
                    f"{base}/api/local-analyst"
                ) as response:
                    empty = json.load(response)
                    self.assertEqual(response.headers["ETag"], '"local-analyst-0"')
                source = (
                    'console.info("events", WB.Node.Evidence.events().length); '
                    'return {seed: Utils.getVar("seed")};'
                )
                saved = post(
                    {
                        "action": "replace_local_analyst_workspace",
                        "expected_generation": empty["generation"],
                        "folders": empty["folders"],
                        "files": [
                            {
                                "id": 1,
                                "folder_id": 1,
                                "name": "inspect.js",
                                "kind": "analyst-script",
                                "language": "javascript",
                                "content": source,
                            }
                        ],
                    }
                )
                self.assertEqual(saved["generation"], 1)
                run = {
                    "action": "run_local_analyst_script",
                    "protocol_version": 1,
                    "run_id": 1,
                    "script_id": 1,
                    "library_generation": 1,
                    "source": source,
                    "variables": {"seed": "verified"},
                    "evidence": {
                        "events": [{"sequence_number": "1"}],
                        "artifacts": [],
                        "trace_edges": [],
                        "signal_profiles": [],
                        "vm_analysis": None,
                        "selected_artifact": None,
                        "summary": {"events": 1},
                    },
                    "confirmed": True,
                    "confirmed_sensitive": False,
                }
                completed = post(run)
                self.assertTrue(completed["ok"])
                self.assertIn('"seed":"verified"', completed["result_text"])

                wait_source = "await new Promise(() => {});"
                saved = post(
                    {
                        "action": "replace_local_analyst_workspace",
                        "expected_generation": 1,
                        "folders": empty["folders"],
                        "files": [
                            {
                                "id": 1,
                                "folder_id": 1,
                                "name": "inspect.js",
                                "kind": "analyst-script",
                                "language": "javascript",
                                "content": wait_source,
                            }
                        ],
                    }
                )
                run.update(
                    {
                        "run_id": 2,
                        "library_generation": saved["generation"],
                        "source": wait_source,
                    }
                )
                results = []
                run_thread = threading.Thread(target=lambda: results.append(post(run)))
                run_thread.start()
                deadline = time.monotonic() + 2
                while (
                    ResearchHandler.local_analyst_runner.active_run_id() != 2
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                cancelled = post(
                    {"action": "cancel_local_analyst_script", "run_id": 2}
                )
                self.assertTrue(cancelled["cancel_requested"])
                run_thread.join(timeout=2)
                self.assertFalse(run_thread.is_alive())
                self.assertEqual(results[0]["outcome"], "cancelled")

                wrong_origin = urllib.request.Request(
                    f"{base}/api/local-analyst",
                    headers={"Origin": "https://outside.test"},
                )
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(wrong_origin)
                self.assertEqual(rejected.exception.code, 403)
            finally:
                ResearchHandler.local_analyst_runner.stop()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                ResearchHandler.local_analyst_store = previous_store
                ResearchHandler.local_analyst_runner = previous_runner


if __name__ == "__main__":
    unittest.main()
