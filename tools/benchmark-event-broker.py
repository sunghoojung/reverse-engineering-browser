#!/usr/bin/env python3
"""Compare two real broker executables using generated, non-private native records."""

import argparse
import hashlib
import json
import resource
import socket
import statistics
import struct
import subprocess
import tempfile
import time
from pathlib import Path


def write_fixture(path, records):
    """Four Canvas observations and one exact renderer/browser request lifecycle."""
    sequences = {42: 0, 84: 0}
    with path.open("wb") as output:
        for index in range(records):
            phase = index % 8
            network = phase >= 4
            operation = (8, 5, 10, 11)[phase - 4] if network else 1
            process = 84 if phase >= 5 else 42
            sequences[process] += 1
            request = index // 8 + 1
            payload = b"GET fixture.invalid" if network else b"canvas.getImageData"
            record = bytearray(320)
            struct.pack_into("<HHHHIIQQQII", record, 0, 3, 144, 9 if network else 1,
                             operation, len(payload), 1, sequences[process], index * 100,
                             7, process, 1)
            struct.pack_into("<QQQQQQQ", record, 48, 100, 200, 0,
                             sequences[process] - 1 if phase == 4 else 0,
                             request if network else 0, 99 if process == 84 else 0, 0)
            if process == 84:
                struct.pack_into("<II", record, 132, request, 42)
            record[144:144 + len(payload)] = payload
            output.write(record)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run_broker(binary, root, fixture, transport, sidecars):
    names = ["events"] + (["edges", "signals"] if sidecars else [])
    args = [str(binary), "--store", str(root / "events"), "--capacity", "10000"]
    if sidecars:
        args += ["--trace-store", str(root / "edges"), "--signal-store", str(root / "signals")]
    if transport == "socket":
        args += ["--socket", str(root / "broker.sock"), "--token-file", str(root / "token"),
                 "--session-id", "7", "--category-mask", "4095", "--duration-seconds", "60"]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    with fixture.open("rb") as source:
        with subprocess.Popen(args, stdin=source if transport == "stdin" else subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
            try:
                if transport == "socket":
                    deadline = time.monotonic() + 10
                    while not (root / "broker.sock").exists():
                        if child.poll() is not None:
                            raise RuntimeError(child.communicate()[1].decode())
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Broker readiness timed out for the owned fixture")
                        time.sleep(0.001)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(60)
                        connection.connect(str(root / "broker.sock"))
                        token = bytes.fromhex((root / "token").read_text().strip())
                        connection.sendall(struct.pack("<IHHQ32s16x", 0x52454249, 1, 64, 7, token))
                        while block := source.read(320 * 256):
                            connection.sendall(block)
                _, errors = child.communicate(timeout=60)
                if child.returncode:
                    raise RuntimeError(errors.decode())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
    wall = time.perf_counter() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
    # Hashing is outside both measured regions. No fixture or evidence is retained.
    return {"wall_seconds": wall, "broker_cpu_seconds": cpu,
            "sha256": [digest(root / name) for name in names],
            "stats": errors.decode().split("Broker stopped:", 1)[-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--records", type=int, default=200000)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--transport", choices=("stdin", "socket"), default="stdin")
    parser.add_argument("--without-sidecars", action="store_true")
    args = parser.parse_args()
    if not 8 <= args.records <= 1000000 or args.records % 8 or not 1 <= args.rounds <= 25:
        parser.error("records must be a multiple of 8 in [8, 1000000]; rounds must be in [1, 25]")
    binaries = {"baseline": args.baseline.resolve(strict=True),
                "candidate": args.candidate.resolve(strict=True)}
    results = {name: [] for name in binaries}
    expected = None
    with tempfile.TemporaryDirectory(prefix="reb-broker-benchmark-") as folder:
        root = Path(folder)
        fixture = root / "fixture.bin"
        write_fixture(fixture, args.records)
        # One warmup per binary, then alternating order to reduce order bias.
        for round_index in range(args.rounds + 1):
            order = list(binaries) if round_index % 2 == 0 else list(reversed(binaries))
            for name in order:
                result = run_broker(binaries[name], root, fixture, args.transport,
                                    not args.without_sidecars)
                signature = (result["sha256"], result["stats"])
                if expected is None:
                    expected = signature
                if signature != expected:
                    raise AssertionError("Broker output bytes or accounting changed")
                if f"accepted={args.records} invalid=0" not in result["stats"]:
                    raise AssertionError("Generated workload was not fully accepted")
                if "sequence_gaps=0 " not in result["stats"] or "queue_drops=0 " not in result["stats"]:
                    raise AssertionError("Generated workload lost evidence")
                if round_index:
                    results[name].append(result)
                print(json.dumps({"round": round_index, "binary": name, **result}), flush=True)
    print(json.dumps({"records": args.records, "transport": args.transport,
                      "sidecars": not args.without_sidecars, "identical_bytes_and_stats": True,
                      "median": {name: {metric: statistics.median(row[metric] for row in rows)
                                        for metric in ("wall_seconds", "broker_cpu_seconds")}
                                 for name, rows in results.items()}}))


if __name__ == "__main__":
    main()
