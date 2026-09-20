#!/usr/bin/env python3

import json
import threading
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from server import ResearchHandler
from ui_test_support import UI_DIRECTORY


class DeobfuscationServerTest(unittest.TestCase):
    def test_endpoint_requires_a_script_and_live_debugging(self) -> None:
        class Handler(ResearchHandler):
            ui_directory = UI_DIRECTORY
            debugger = None

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        def get(query: str) -> tuple[int, dict]:
            try:
                with urllib.request.urlopen(
                    f"{base}/api/deobfuscation{query}", timeout=5
                ) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)

        try:
            status, body = get("")
            self.assertEqual(status, 400)
            self.assertEqual(body, {"error": "Script ID or artifact ID is required"})

            script = urllib.parse.urlencode({"script_id": "7", "mode": "bogus"})
            status, body = get(f"?{script}")
            self.assertEqual(status, 400)
            self.assertEqual(body, {"error": "Deobfuscation mode is invalid"})

            status, body = get("?script_id=7")
            self.assertEqual(status, 409)
            self.assertEqual(body, {"error": "Live debugging is not enabled"})

            status, body = get("?script_id=7&mode=derived")
            self.assertEqual(status, 409)
            self.assertEqual(body, {"error": "Live debugging is not enabled"})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_endpoint_analyzes_a_javascript_artifact_without_live_debugging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            content_path = Path(directory) / "source.js"
            content_path.write_text("const value = 1 + 2;", encoding="utf-8")

            class Handler(ResearchHandler):
                ui_directory = UI_DIRECTORY
                debugger = None

                def find_artifact(self, artifact_id):
                    if artifact_id != "9":
                        raise FileNotFoundError(artifact_id)
                    return {"artifact_id": "9", "kind": "javascript"}, content_path

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{server.server_port}/api/deobfuscation?artifact_id=9",
                    timeout=5,
                ) as response:
                    body = json.load(response)
                self.assertEqual(body["artifact_id"], "9")
                self.assertEqual(body["analysis"]["schema"], "deobfuscation-analysis-v1")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
