#!/usr/bin/env python3

import base64
import gzip
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from decoder_service import DecoderService
from server import ResearchHandler


class DecoderServerTest(unittest.TestCase):
    def test_decoder_http_contract_limits_errors_and_origin(self) -> None:
        previous_service = ResearchHandler.decoder_service
        root = Path(__file__).resolve().parents[2]
        ResearchHandler.decoder_service = DecoderService(root / "build/reb-decoder")
        ResearchHandler.ui_directory = Path(__file__).parent
        server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        def post(value: dict) -> tuple[int, dict]:
            request = urllib.request.Request(
                f"{base}/api/decoder/actions",
                data=json.dumps(value).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)

        try:
            with urllib.request.urlopen(f"{base}/api/decoder") as response:
                state = json.load(response)
            self.assertTrue(state["available"])
            self.assertEqual(state["limits"]["output_bytes"], 1 << 20)

            status, transformed = post(
                {
                    "protocol_version": 1,
                    "action": "transform",
                    "operation_id": 9,
                    "operation": "base64-decode",
                    "input_base64": base64.b64encode(b"T3JpZ2luIFRyYWNl").decode(),
                }
            )
            self.assertEqual(status, 200)
            self.assertEqual(transformed["operation_id"], 9)
            self.assertEqual(transformed["utf8_text"], "Origin Trace")

            status, inspection = post(
                {
                    "protocol_version": 1,
                    "action": "jwt_inspect",
                    "token": "eyJhbGciOiJub25lIn0.e30.",
                }
            )
            self.assertEqual(status, 200)
            self.assertEqual(inspection["signature_status"], "unsigned")

            status, error = post(
                {
                    "protocol_version": 1,
                    "action": "transform",
                    "operation_id": 10,
                    "operation": "gzip-decompress",
                    "input_base64": base64.b64encode(
                        gzip.compress(b"A" * ((1 << 20) + 1))
                    ).decode(),
                }
            )
            self.assertEqual(status, 422)
            self.assertIn("byte limit", error["error"])

            status, error = post(
                {
                    "protocol_version": 1,
                    "action": "transform",
                    "operation_id": 11,
                    "operation": "execute",
                    "input_base64": "",
                }
            )
            self.assertEqual(status, 400)
            self.assertIn("allowlisted", error["error"])

            wrong_origin = urllib.request.Request(
                f"{base}/api/decoder", headers={"Origin": "https://outside.test"}
            )
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(wrong_origin)
            self.assertEqual(rejected.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            ResearchHandler.decoder_service = previous_service


if __name__ == "__main__":
    unittest.main()
