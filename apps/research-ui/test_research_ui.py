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
