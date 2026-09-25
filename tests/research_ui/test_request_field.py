import hashlib
import json
import subprocess
import unittest
from unittest import mock

from debugger.request_field import extract_field, extract_request_value, query_context_digest


class RequestFieldTests(unittest.TestCase):
    @mock.patch("debugger.request_field.worker_path", return_value="/fixture/worker")
    @mock.patch("debugger.request_field.subprocess.run")
    def test_only_selected_value_is_retained(self, run, _path):
        run.return_value = subprocess.CompletedProcess([], 0, json.dumps({
            "schema": "reb-request-field-v1", "status": "available", "value": '"ws1.sample"'
        }).encode())
        result = extract_field('{"payload":"ws1.sample","secret":"do-not-retain"}', "/payload")
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["preview"], '"ws1.sample"')
        self.assertEqual(result["sha256"], hashlib.sha256(b'"ws1.sample"').hexdigest())
        self.assertNotIn("secret", str(result))
        self.assertNotIn("do-not-retain", str(result))
        self.assertIn(b'"pointer": "/payload"', run.call_args.kwargs["input"])
        self.assertEqual(run.call_args.kwargs["timeout"], 1)

    @mock.patch("debugger.request_field.worker_path", return_value=None)
    def test_unavailable_worker_and_oversized_body_are_explicit(self, _path):
        self.assertEqual(extract_field("{}", "/a")["status"], "unavailable")
        self.assertEqual(extract_field("x" * (128 * 1024 + 1), "/a")["status"], "truncated")

    @mock.patch("debugger.request_field.worker_path", return_value="/fixture/worker")
    @mock.patch("debugger.request_field.subprocess.run")
    def test_invalid_worker_response_does_not_become_evidence(self, run, _path):
        run.return_value = subprocess.CompletedProcess([], 0, b'{"schema":"wrong","status":"available","value":"secret"}')
        result = extract_field('{"a":"secret"}', "/a")
        self.assertEqual(result, {"status": "unavailable", "sha256": None, "preview": "", "bytes": 0})

    def test_request_selectors_are_bounded_and_select_only_one_value(self):
        query = extract_request_value("query", "nonce", url="https://example.test/send?nonce=alpha&private=hidden")
        self.assertEqual(query["status"], "available")
        self.assertEqual(query["preview"], '"alpha"')
        self.assertNotIn("hidden", str(query))
        self.assertEqual(extract_request_value("query", "nonce",
            url="https://example.test/send?nonce=a&nonce=b")["status"], "ambiguous")
        self.assertEqual(extract_request_value("query", "nonce",
            url="https://example.test/send?other=a")["status"], "missing")
        form = extract_request_value("form", "payload", body="payload=one+two&secret=hidden")
        self.assertEqual(form["preview"], '"one two"')
        self.assertNotIn("hidden", str(form))
        self.assertEqual(extract_request_value("form", "payload", body="payload=a&payload=b")["status"], "ambiguous")
        header = extract_request_value("header", "x-run", headers={"X-Run": "alpha", "Authorization": "secret"})
        self.assertEqual(header["preview"], '"alpha"')
        self.assertNotIn("secret", str(header))
        self.assertEqual(extract_request_value("header", "x-run", headers={})["status"], "missing")
        empty_body = extract_request_value("body", "", body="")
        self.assertEqual(empty_body["status"], "available")
        self.assertEqual(empty_body["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(empty_body["bytes"], 0)
        self.assertEqual(extract_request_value("body", "", body="x" * 4097)["status"], "value_too_large")
        self.assertEqual(extract_request_value("body", "", body="x" * (128 * 1024 + 1))["status"], "truncated")
        key = b"test-key"
        self.assertEqual(query_context_digest("https://example.test/?payload=a&other=one", "query", "payload", key),
                         query_context_digest("https://example.test/?payload=b&other=one", "query", "payload", key))
        self.assertNotEqual(query_context_digest("https://example.test/?payload=a&other=one", "query", "payload", key),
                            query_context_digest("https://example.test/?payload=b&other=two", "query", "payload", key))


if __name__ == "__main__":
    unittest.main()
