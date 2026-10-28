#!/usr/bin/env python3
"""Snapshot one origin-trace-vm build's tier, score, finding ID and dispatch
inventory for every differential input.

usage: dispatch-base-expectations.py --binary BIN --inputs DIR --commit SHA --output FILE

DIR holds the files and inputs.json that the ignored Rust test
`write_differential_inputs` writes. The snapshot is the expectation that the
current analyzer must reproduce; see tools/fixtures/dispatch-review/README.md.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    inputs = pathlib.Path(args.inputs)
    index = json.loads((inputs / "inputs.json").read_text())
    with tempfile.TemporaryDirectory(prefix="dispatch-base-") as temporary:
        root = pathlib.Path(temporary)
        (root / "blobs").mkdir()
        with (root / "manifest.jsonl").open("w") as manifest:
            for position, entry in enumerate(index, 1):
                data = (inputs / entry["file"]).read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                (root / "blobs" / f"{digest}.bin").write_bytes(data)
                wasm = entry["kind"] == "wasm"
                record = {
                    "protocol_version": 1, "artifact_id": str(position), "session_id": "1",
                    "navigation_id": "1", "frame_id": "1", "parent_artifact_id": "0",
                    "creator_event_id": "0", "execution_context_id": "1",
                    "capture_origin": "webassembly_compile" if wasm else "dynamic_javascript",
                    "kind": "wasm" if wasm else "javascript",
                    "url": "fixture://differential/" + entry["file"],
                    "mime_type": "application/wasm" if wasm else "text/javascript",
                    "byte_size": len(data), "sha256": digest, "sensitive": False,
                    "content_path": f"blobs/{digest}.bin",
                }
                manifest.write(json.dumps(record) + "\n")
        (root / "events.jsonl").write_text("")
        output = root / "out.json"
        subprocess.run(
            [args.binary, "--artifacts", str(root), "--events", str(root / "events.jsonl"),
             "--output", str(output)],
            check=True,
        )
        results = {result["artifact_id"]: result for result in json.loads(output.read_text())["results"]}
    expectations = {}
    for position, entry in enumerate(index, 1):
        result = results[str(position)]
        expectations[entry["name"]] = {
            "tier": result.get("tier"),
            "vm_score": result.get("vm_score"),
            "finding_id": result.get("finding_id"),
            "dispatch_inventory": result.get("frontend", {}).get("dispatch_inventory"),
        }
    document = {"base_commit": args.commit, "inputs": dict(sorted(expectations.items()))}
    pathlib.Path(args.output).write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(expectations)} base expectations to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
