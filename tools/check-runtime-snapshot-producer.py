#!/usr/bin/env python3
"""Exercise native fixture transfer, receiver manifest, and exact snapshot joins."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", required=True)
    parser.add_argument("--receiver", required=True)
    parser.add_argument("--analyzer", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="reb-runtime-snapshot-") as temporary:
        root = Path(temporary)
        artifacts = root / "artifacts"
        stream = subprocess.run(
            [args.producer, "--vm-snapshot-fixture"], check=True, capture_output=True
        ).stdout
        subprocess.run(
            [args.receiver, "--store", str(artifacts)], input=stream, check=True,
            capture_output=True,
        )
        events = root / "events.jsonl"
        events.write_text("", encoding="utf-8")
        manifest = artifacts / "manifest.jsonl"
        original = manifest.read_text(encoding="utf-8")
        records = [json.loads(line) for line in original.splitlines()]
        parent, snapshot = records
        assert parent["capture_origin"] == "runtime_allocating_script"
        assert snapshot["parent_artifact_id"] == parent["artifact_id"]
        assert snapshot["creator_event_id"] == "1"
        assert snapshot["execution_context_id"] != "0"
        expected = bytes([1, 7, 2, 3, 0]) + bytes(27)
        assert (artifacts / snapshot["content_path"]).read_bytes() == expected

        def analyze() -> dict:
            subprocess.run(
                [args.analyzer, "--artifacts", str(artifacts), "--events", str(events)],
                check=True, capture_output=True,
            )
            return json.loads(
                (artifacts / "analysis/vm-opcode-workspace-v1.json").read_text(encoding="utf-8")
            )["workspaces"][0]

        joined = analyze()
        assert joined["snapshots"][0]["preview_hex"] == expected.hex()
        # Only synthetic fixture copies are changed here, never retained captures.
        for field in ("parent_artifact_id", "session_id", "navigation_id", "frame_id"):
            changed = dict(snapshot)
            changed[field] = "0" if field == "parent_artifact_id" else "999"
            manifest.write_text(
                json.dumps(parent) + "\n" + json.dumps(changed) + "\n", encoding="utf-8"
            )
            rejected = analyze()
            assert not rejected["snapshots"], field
            reasons = {item["reason"] for item in rejected["coverage"]["omissions"]}
            assert "static-initializer-only" in reasons, field
            assert "runtime-snapshot-unavailable" not in reasons, field
        manifest.write_text(original, encoding="utf-8")
    print("PASS native-produced snapshot provenance, manifest round-trip and exact scope joins")


if __name__ == "__main__":
    main()
