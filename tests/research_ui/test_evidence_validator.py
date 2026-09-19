"""Exercise the offline validator through its user-facing JSONL command."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


VALIDATOR = Path(__file__).resolve().parents[2] / "tools" / "validate-evidence-store.py"


def event(category: str, event_type: str, payload: bytes, version: int = 3) -> dict:
    value = {
        "protocol_version": version,
        "session_id": "10383268391294403687",
        "sequence_number": "3",
        "monotonic_time_ns": "142677246851000",
        "process_id": 100,
        "thread_id": 101,
        "navigation_id": "0",
        "frame_id": "10518304036118273256",
        "artifact_id": "0",
        "parent_event_id": "0",
        "request_id": "0",
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
        "type": event_type,
        "payload_size": len(payload),
        "payload_encoding": "hex",
        "payload": payload.hex(),
    }
    if version == 3:
        value["tab_id"] = 1
    return value


class EvidenceValidatorTests(unittest.TestCase):
    def validate(self, records: list[dict]) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text("".join(json.dumps(record) + "\n" for record in records))
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )

    def test_runtime_and_artifact_records_from_live_capture_are_supported(self) -> None:
        for version in (2, 3):
            with self.subTest(version=version):
                records = [
                    event("runtime", "api_call", b"Performance.now", version),
                    event("runtime", "property_read", b"Performance.timeOrigin", version),
                    event("artifact", "artifact_captured", b"", version),
                    event("artifact", "artifact_capture_failed", b"active_memory_limit", version),
                    event("runtime", "gap", b"2", version),
                ]
                result = self.validate(records)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("5 events", result.stdout)

    def test_unknown_names_remain_invalid(self) -> None:
        for category, event_type in (
            ("unknown", "api_call"),
            ("runtime", "invented_event"),
            ("artifact", "artifact_capture_succeeded"),
        ):
            with self.subTest(category=category, event_type=event_type):
                result = self.validate([event(category, event_type, b"")])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unknown category or event type", result.stderr)

    def test_new_categories_keep_payload_limits_and_privacy_checks(self) -> None:
        for category, event_type in (
            ("runtime", "api_call"),
            ("artifact", "artifact_capture_failed"),
        ):
            with self.subTest(category=category):
                self.assertEqual(
                    self.validate([event(category, event_type, b"x" * 128)]).returncode, 0
                )
                for payload, error in (
                    (b"x" * 129, "payload size exceeds"),
                    (b"Authorization: secret", "sensitive HTTP metadata"),
                    (b"Cookie: secret", "sensitive HTTP metadata"),
                ):
                    result = self.validate([event(category, event_type, payload)])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                malformed = event(category, event_type, b"x")
                malformed["payload"] = "zz"
                result = self.validate([malformed])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not valid hex", result.stderr)
