import json
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
        self.assertNotIn(".innerHTML", html)


if __name__ == "__main__":
    unittest.main()
