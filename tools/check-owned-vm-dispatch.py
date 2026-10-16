#!/usr/bin/env python3
"""Verify opt-in owned dispatch export through the actual native event broker."""

import argparse
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--analyzer")
    args = parser.parse_args()
    ids = {
        "session": 101,
        "navigation": 102,
        "frame": 103,
        "invocation": 104,
        "finding": 105,
        "investigation": 106,
        "interpreter-artifact": 107,
        "bytecode-artifact": 108,
    }
    common = [item for key, value in ids.items() for item in (f"--{key}-id", str(value))]
    repository = Path(__file__).resolve().parents[1]
    references_root = repository / "tools/fixtures/native-vm-dispatch"
    references = json.loads((references_root / "references.json").read_text())
    assert references["program_manifest_sha256"] == hashlib.sha256(
        (repository / "protocol/owned-vm-programs-v1.json").read_bytes()
    ).hexdigest()
    for fixture in ("register", "stack"):
        reference = next(row for row in references["sources"] if row["fixture"] == fixture)
        source = (references_root / reference["path"]).read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        assert reference["sha256"] == digest
        command = [args.binary, "--emit-dispatch-events-v1", "--fixture", fixture, *common]
        produced = subprocess.run(command, capture_output=True, check=True, timeout=10)
        assert not produced.stderr
        with tempfile.TemporaryDirectory(prefix="reb-owned-dispatch-") as root:
            store = Path(root) / "events.jsonl"
            broker = subprocess.run(
                [args.broker, "--store", str(store)],
                input=produced.stdout,
                capture_output=True,
                check=True,
                timeout=10,
            )
            assert b"accepted=10" in broker.stderr, broker.stderr
            events = [json.loads(line) for line in store.read_text().splitlines()]
            if args.analyzer:
                artifacts = Path(root) / "artifacts"
                (artifacts / "blobs").mkdir(parents=True)
                (artifacts / "blobs" / f"{digest}.bin").write_bytes(source)
                artifact = {"protocol_version": 1, "artifact_id": "107", "session_id": "101",
                            "navigation_id": "102", "frame_id": "103", "parent_artifact_id": "0",
                            "creator_event_id": "0", "execution_context_id": "1",
                            "capture_origin": "dynamic_javascript", "kind": "javascript",
                            "url": f"fixture://declared-native-reference/{fixture}.js", "mime_type": "text/javascript",
                            "byte_size": len(source), "sha256": digest, "sensitive": False,
                            "content_path": f"blobs/{digest}.bin"}
                (artifacts / "manifest.jsonl").write_text(json.dumps(artifact) + "\n")
                subprocess.run([args.analyzer, "--artifacts", str(artifacts), "--events", str(store)],
                               capture_output=True, check=True, timeout=30)
                document = json.loads((artifacts / "analysis/vm-opcode-workspace-v2.json").read_text())
                assert document["contract_version"] == 2
                workspace = document["workspaces"][0]
                assert workspace["source_artifact_sha256"] == digest
                assert workspace["sample_count"] == 9 and len(workspace["samples"]) == 9
                assert {row["opcode"]: row["sample_count"] for row in workspace["handlers"]} == {
                    1: 2, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1}
                assert all(row["state"] == "observed" for row in workspace["handlers"])
                assert all(row["instruction_pointer_units"] == "instruction-index" for row in workspace["samples"])
                assert all(row["invocation_id"] == "104" for row in workspace["samples"])
                assert workspace["coverage"]["characterized_bytes"] == 0
                assert not workspace["coverage"]["complete"]
        assert len(events) == 10
        marker, *samples = events
        assert marker["type"] == "vm_finding" and marker["sequence_number"] == "1"
        marker_bytes = bytes.fromhex(marker["payload"])
        assert marker_bytes[4:8] == bytes([3, 0, 1, 4])
        assert struct.unpack_from("<QQQQ", marker_bytes, 24) == (105, 106, 104, 108)
        assert marker_bytes[72:72 + len(f"owned-{fixture}-v1")] == f"owned-{fixture}-v1".encode()
        for index, event in enumerate(samples):
            assert event["type"] == "vm_dispatch_sample"
            assert event["category"] == "vm"
            assert event["sequence_number"] == str(index + 2)
            assert event["parent_event_id"] == "1"
            assert event["artifact_id"] == "107"
            assert event["session_id"] == "101"
            assert event["navigation_id"] == "102"
            assert event["frame_id"] == "103"
            assert event["process_id"] == marker["process_id"] > 0
            data = bytes.fromhex(event["payload"])
            assert len(data) == 128 and event["payload_size"] == 128
            assert struct.unpack_from("<HH", data) == (1, 128)
            assert struct.unpack_from("<IIII", data, 4) == (
                [0, 1, 2, 3, 4, 5, 6, 8, 10][index],
                [1, 1, 2, 3, 4, 5, 6, 7, 8][index],
                [1, 1, 2, 3, 4, 5, 6, 7, 8][index],
                index,
            )
            assert struct.unpack_from("<QQQQ", data, 24) == (105, 106, 107, 108)
            assert data[20:24] == bytes(4) and data[56] == 0 and data[58:] == bytes(70)
            assert data[57] == [1, 1, 2, 1, 1, 2, 1, 2, 0][index]
        for invalid in (
            command[:-1], command + ["--session-id", "101"],
            command[:3] + ["unknown"] + command[4:],
            command[:-1] + ["0"], command[:-1] + ["01"],
            command[:-1] + ["18446744073709551616"],
            command[:6] + ["--session-id", "102"] + command[8:],
        ):
            rejected = subprocess.run(invalid, capture_output=True, check=False, timeout=10)
            assert rejected.returncode == 2 and not rejected.stdout, invalid
    print("Owned register/stack dispatch export: all 18 instructions stored by the broker")


if __name__ == "__main__":
    main()
