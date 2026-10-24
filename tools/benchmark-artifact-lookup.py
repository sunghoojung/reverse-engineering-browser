#!/usr/bin/env python3
"""Measure exact artifact HTTP lookups using authored synthetic data only.

Build each revision with the same release toolchain, preserve both binaries, then
run this script for each binary while other builds are idle. No captured data,
external requests, or running app stores are read. Timings are observational,
not hardware-dependent test thresholds.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import resource
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--records", type=int, default=50_000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warm-reads", type=int, default=5)
    parser.add_argument("--parallel", type=int, choices=range(1, 5), default=1)
    args = parser.parse_args()
    if not 1 <= args.records <= 200_000 or not 1 <= args.rounds <= 20 or not 1 <= args.warm_reads <= 20:
        parser.error("Use 1–200000 records, 1–20 rounds and 1–20 warm reads")
    binary = args.binary.resolve(strict=True)
    samples = {"cold_ms": [], "warm_ms": [], "append_ms": []}
    process_cpu_ms = []
    with tempfile.TemporaryDirectory(prefix="reb-artifact-benchmark-") as temporary, ThreadPoolExecutor(max_workers=args.parallel) as pool:
        root = Path(temporary)
        artifacts = root / "artifacts"
        (artifacts / "blobs").mkdir(parents=True)
        content = b"synthetic benchmark only\n"
        digest = hashlib.sha256(content).hexdigest()
        (artifacts / "blobs" / f"{digest}.bin").write_bytes(content)
        row = {
            "protocol_version": 1, "artifact_id": "1", "session_id": "1", "navigation_id": "1",
            "frame_id": "1", "parent_artifact_id": "0", "creator_event_id": "1", "kind": "javascript",
            "url": "https://fixture.invalid/benchmark.js", "mime_type": "text/javascript",
            "byte_size": len(content), "sha256": digest, "sensitive": False,
            "content_path": f"blobs/{digest}.bin",
        }
        manifest = artifacts / "manifest.jsonl"
        with manifest.open("w", encoding="utf-8") as output:
            for identifier in range(1, args.records + 1):
                row["artifact_id"] = str(identifier)
                output.write(json.dumps(row, separators=(",", ":")) + "\n")
        initial_bytes = manifest.stat().st_size
        for round_number in range(args.rounds):
            endpoint = root / f"endpoint-{round_number}"
            command = [str(binary), "--port", "0", "--endpoint-file", str(endpoint)]
            for flag, name in [
                ("--store", "events"), ("--trace-store", "trace"), ("--signal-store", "signals"),
                ("--artifacts", "artifacts"), ("--api-collection", "collection"),
                ("--local-analyst", "analyst"),
            ]:
                command.extend([flag, str(root / name)])
            cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 20
                while not endpoint.exists():
                    if process.poll() is not None:
                        raise RuntimeError("Synthetic backend exited before publishing its endpoint")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Synthetic backend startup exceeded 20 seconds")
                    time.sleep(0.02)
                url = endpoint.read_text(encoding="utf-8").strip()

                def request(_):
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(f"{url}/api/artifacts/1/content?limit=16", timeout=30) as response:
                        assert response.read() == content[:16]

                def measure():
                    start = time.perf_counter()
                    list(pool.map(request, range(args.parallel)))
                    return (time.perf_counter() - start) * 1000

                samples["cold_ms"].append(measure())
                samples["warm_ms"].extend(measure() for _ in range(args.warm_reads))
                row["artifact_id"] = str(args.records + round_number + 1)
                with manifest.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(row, separators=(",", ":")) + "\n")
                samples["append_ms"].append(measure())
            finally:
                process.kill()
                process.communicate(timeout=10)
                cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
                process_cpu_ms.append(1000 * (
                    cpu_after.ru_utime + cpu_after.ru_stime - cpu_before.ru_utime - cpu_before.ru_stime
                ))
    print(json.dumps({
        "binary": str(binary), "initial_records": args.records, "initial_manifest_bytes": initial_bytes,
        "rounds": args.rounds, "warm_reads_per_round": args.warm_reads,
        "concurrent_requests_per_sample": args.parallel,
        "median_ms": {key: statistics.median(values) for key, values in samples.items()},
        "samples": samples,
        "backend_cpu_ms_per_round": process_cpu_ms,
        "median_backend_cpu_ms_per_round": statistics.median(process_cpu_ms),
    }, indent=2))


if __name__ == "__main__":
    main()
