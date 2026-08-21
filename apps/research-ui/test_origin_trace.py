import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

from origin_trace import OriginTraceError, build_origin_trace
from server import ResearchHandler


def event(
    sequence: int,
    category: str,
    operation: str,
    *,
    request_id: int = 0,
    parent_event_id: int = 0,
    artifact_id: int = 300,
    process_id: int = 10,
) -> dict:
    value = f"{category}.{operation}"
    return {
        "protocol_version": 2,
        "session_id": "1",
        "sequence_number": str(sequence),
        "monotonic_time_ns": str(sequence * 100),
        "process_id": process_id,
        "thread_id": 20,
        "navigation_id": "100",
        "frame_id": "200",
        "artifact_id": str(artifact_id),
        "parent_event_id": str(parent_event_id),
        "request_id": str(request_id),
        "browser_context_id_high": "0",
        "browser_context_id_low": "0",
        "encoded_data_length": "0",
        "decoded_body_length": "0",
        "status_code": 0,
        "error_code": 0,
        "resource_type": 0,
        "flags": 0,
        "initiator_request_id": 0,
        "initiator_process_id": 0,
        "payload_truncated": False,
        "category": category,
        "type": operation,
        "payload_size": len(value),
        "payload_encoding": "hex",
        "payload": value.encode().hex(),
    }


def edge(source: int, target: int, relation: str = "parent_event") -> dict:
    return {
        "protocol_version": 1,
        "session_id": "1",
        "from_process_id": 10,
        "from_sequence_number": str(source),
        "to_process_id": 10,
        "to_sequence_number": str(target),
        "relation": relation,
        "confidence": "observed",
        "request_id": "81",
        "artifact_id": "300",
    }


class OriginTraceTests(unittest.TestCase):
    def test_versioned_schemas_are_valid_json(self) -> None:
        protocol = Path(__file__).parents[2] / "protocol"
        for name in (
            "origin-trace-edge-v1.schema.json",
            "origin-trace-document-v1.schema.json",
        ):
            schema = json.loads((protocol / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(schema["additionalProperties"])

    def test_trace_reaches_an_observed_browser_source(self) -> None:
        events = [
            event(1, "canvas", "api_call"),
            event(2, "wasm", "module_instantiated", parent_event_id=1),
            event(3, "network", "request_initiated", request_id=81, parent_event_id=2),
            event(4, "network", "request_started", request_id=81, parent_event_id=3),
        ]
        document = build_origin_trace(events, [edge(2, 1), edge(3, 2), edge(4, 3)], [], "81")

        self.assertEqual(document["status"], "complete")
        self.assertEqual(
            [step["category"] for step in document["steps"]],
            ["network", "network", "wasm", "canvas"],
        )
        self.assertEqual(document["coverage"]["percent"], 100)
        self.assertEqual(document["gaps"], [])

    def test_missing_retained_predecessor_is_an_explicit_gap(self) -> None:
        request = event(4, "network", "request_started", request_id=81)
        document = build_origin_trace([request], [edge(4, 3)], [], "81")

        self.assertEqual(document["status"], "partial")
        self.assertEqual(document["gaps"][0]["reason"], "missing_event")
        self.assertEqual(document["coverage"]["percent"], 0)

    def test_exact_root_disambiguates_reused_request_ids(self) -> None:
        first = event(4, "network", "request_started", request_id=81)
        second = event(
            9,
            "network",
            "request_started",
            request_id=81,
            process_id=20,
        )
        ambiguous = build_origin_trace([first, second], [], [], "81")
        selected = build_origin_trace(
            [first, second],
            [],
            [],
            "81",
            root_process_id=20,
            root_sequence_number="9",
        )

        self.assertEqual(ambiguous["status"], "ambiguous")
        self.assertEqual(selected["steps"][0]["event"]["process_id"], 20)

    def test_trace_rejects_malformed_edges_and_duplicate_event_references(self) -> None:
        request = event(4, "network", "request_started", request_id=81)
        malformed = edge(4, 3)
        malformed["secret"] = "not allowed"
        with self.assertRaisesRegex(OriginTraceError, "malformed edge"):
            build_origin_trace([request], [malformed], [], "81")
        with self.assertRaisesRegex(OriginTraceError, "duplicate event"):
            build_origin_trace([request, request], [], [], "81")

    def test_trace_api_is_bounded_conditional_and_root_specific(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_store = root / "events.jsonl"
            trace_store = root / "origin-trace.jsonl"
            artifact_store = root / "artifacts"
            artifact_store.mkdir()
            events = [
                event(1, "canvas", "api_call"),
                event(2, "network", "request_initiated", request_id=81),
                event(3, "network", "request_started", request_id=81),
            ]
            event_store.write_text(
                "".join(json.dumps(item) + "\n" for item in events), encoding="utf-8"
            )
            trace_store.write_text(
                json.dumps(edge(3, 2)) + "\n" + json.dumps(edge(2, 1)) + "\n",
                encoding="utf-8",
            )
            ResearchHandler.ui_directory = Path(__file__).parent
            ResearchHandler.event_store = event_store
            ResearchHandler.trace_store = trace_store
            ResearchHandler.artifact_store = artifact_store
            ResearchHandler.broker_socket = None
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = (
                    f"http://127.0.0.1:{server.server_port}/api/origin-trace"
                    "?request_id=81&root_process_id=10&root_sequence_number=3"
                )
                with urllib.request.urlopen(url) as response:
                    document = json.load(response)
                    etag = response.headers["ETag"]
                self.assertEqual(document["status"], "complete")
                self.assertEqual(len(document["steps"]), 3)

                unchanged = urllib.request.Request(
                    url, headers={"If-None-Match": etag}
                )
                with self.assertRaises(urllib.error.HTTPError) as response:
                    urllib.request.urlopen(unchanged)
                self.assertEqual(response.exception.code, HTTPStatus.NOT_MODIFIED)

                with self.assertRaises(urllib.error.HTTPError) as response:
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{server.server_port}/api/origin-trace"
                    )
                self.assertEqual(response.exception.code, HTTPStatus.BAD_REQUEST)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
