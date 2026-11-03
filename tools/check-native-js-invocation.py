#!/usr/bin/env python3
"""Drive authored native JavaScript invocation records through the real broker.

The broker's origin-trace index must draw issued_during_invocation and
invocation_settlement edges only from exact (session, process, invocation)
identities, never from time, and the backend must walk them in a request
trace. See protocol/native-js-invocation-v1.md. Records are authored here; a
rebuilt Brave is not involved.
"""

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

VM, NETWORK = 10, 9
REQUEST_STARTED, REQUEST_INITIATED = 5, 8
START, SETTLE, REQUEST = 22, 23, 24
ROLLING_BASE = 0x100000001B3


def record(category, operation, sequence, process, request=0, *, frame=6, payload=b"",
           session=7, initiator=(0, 0)):
    data = bytearray(320)
    struct.pack_into("<HHHHIIQQQII", data, 0, 3, 144, category, operation, len(payload), 0,
                     sequence, 1000 + sequence, session, process, 1)
    struct.pack_into("<QQQQQ", data, 48, 0, frame, 0, 0, request)
    struct.pack_into("<II", data, 132, initiator[1], initiator[0])
    data[144:144 + len(payload)] = payload
    return bytes(data)


def start(invocation, parent=0):
    p = bytearray(128)
    struct.pack_into("<HHBBH", p, 0, 1, 128, 0, 0, 2)
    struct.pack_into("<IIIII", p, 8, 17, 41, 900, invocation, parent)
    p[32], p[33], p[72] = 3, 9, 0x5A
    struct.pack_into("<Q", p, 104, 7)
    return bytes(p)


def rolling(value):
    result = 0
    for byte in value:
        result = (result * ROLLING_BASE + byte) % (1 << 64)
    return result


def settle(invocation, value=None):
    p = bytearray(128)
    struct.pack_into("<HHBBBBI", p, 0, 1, 128, 0, 1, 3, 3, invocation)
    if value is not None:
        struct.pack_into("<IBBBBIQ", p, 12, len(value), 1, 1, 0, 0, len(value), rolling(value))
        p[32:64] = hashlib.sha256(value).digest()
    struct.pack_into("<Q", p, 64, 7)
    return bytes(p)


def request(state, invocation):
    p = bytearray(128)
    struct.pack_into("<HHB", p, 0, 1, 128, state)
    struct.pack_into("<I", p, 8, invocation)
    return bytes(p)


def run(broker, records, capacity=64, keep=None):
    with tempfile.TemporaryDirectory(prefix="reb-js-invocation-") as folder:
        root = Path(keep or folder)
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run([broker, "--store", str(root / "events"), "--trace-store", str(root / "edges"),
                        "--capacity", str(capacity)], input=b"".join(records),
                       check=True, capture_output=True, timeout=10)
        events = [json.loads(line) for line in (root / "events").read_text().splitlines()]
        edges = [json.loads(line) for line in (root / "edges").read_text().splitlines()]
        return events, edges


def invocation_edges(edges):
    return sorted((edge["relation"], edge["from_process_id"], edge["from_sequence_number"],
                   edge["to_process_id"], edge["to_sequence_number"]) for edge in edges
                  if edge["relation"] in ("issued_during_invocation", "invocation_settlement"))


def verify_http(backend, root):
    endpoint = root / "endpoint"
    with subprocess.Popen([backend, "--port", "0", "--endpoint-file", str(endpoint),
                           "--store", str(root / "events"), "--trace-store", str(root / "edges"),
                           "--signal-store", str(root / "signals"), "--artifacts", str(root / "artifacts"),
                           "--api-collection", str(root / "collection"), "--local-analyst", str(root / "analyst")],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as child:
        try:
            deadline = time.monotonic() + 10
            while not endpoint.exists():
                assert child.poll() is None, "Backend exited before endpoint publication"
                assert time.monotonic() < deadline, "Backend startup timeout"
                time.sleep(0.02)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            url = (endpoint.read_text().strip() + "/api/origin-trace?request_id=900&session_id=7"
                   "&root_process_id=84&root_sequence_number=1")
            with opener.open(url, timeout=10) as response:
                trace = json.load(response)
            relations = [step["relation"] for step in trace["steps"]]
            assert relations == ["trace_target", "request_initiator", "issued_during_invocation"], trace
            assert trace["steps"][2]["value"] == "invocation 5 started at site 0 with 2 argument(s)", trace
            assert trace["coverage"]["observed_links"] == 2, trace
            assert trace["coverage"]["correlated_links"] == 0, trace
        finally:
            child.terminate()
            child.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--backend")
    args = parser.parse_args()
    # Renderer 42 runs invocations 5 and 6 interleaved; request 9 starts inside
    # 5 and request 10 inside 6. Browser 84 records request 9 as 900.
    session = [
        record(VM, START, 1, 42, payload=start(5)),
        record(VM, START, 2, 42, payload=start(6)),
        record(NETWORK, REQUEST_INITIATED, 3, 42, 9, payload=b"POST"),
        record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(2, 5)),
        record(NETWORK, REQUEST_INITIATED, 5, 42, 10, payload=b"POST"),
        record(VM, REQUEST, 6, 42, 10, frame=0, payload=request(2, 6)),
        record(VM, SETTLE, 7, 42, payload=settle(6, b"token-b")),
        record(VM, SETTLE, 8, 42, payload=settle(5, b"token-a")),
        record(NETWORK, REQUEST_STARTED, 1, 84, 900, payload=b"POST", initiator=(42, 9)),
    ]
    with tempfile.TemporaryDirectory(prefix="reb-js-invocation-http-") as folder:
        root = Path(folder)
        events, edges = run(args.broker, session, keep=root)
        assert invocation_edges(edges) == sorted([
            ("issued_during_invocation", 42, "3", 42, "1"),
            ("issued_during_invocation", 42, "5", 42, "2"),
            ("invocation_settlement", 42, "7", 42, "2"),
            ("invocation_settlement", 42, "8", 42, "1"),
        ]), edges
        assert all(edge["confidence"] == "observed" for edge in edges
                   if edge["relation"].startswith(("issued_", "invocation_")))
        assert len(events) == len(session)
        validator = Path(__file__).with_name("validate-evidence-store.py")
        subprocess.run([sys.executable, str(validator), str(root / "events")], check=True,
                       capture_output=True, timeout=30)
        if args.backend:
            verify_http(args.backend, root)

    # An unknown request, another process, another session or a dropped
    # record never borrows an invocation.
    base = [record(VM, START, 1, 42, payload=start(5)),
            record(NETWORK, REQUEST_INITIATED, 3, 42, 9, payload=b"POST")]
    for wrong in [record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(3, 0)),
                  record(VM, REQUEST, 4, 43, 9, frame=0, payload=request(2, 5)),
                  record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(2, 5), session=8),
                  record(VM, REQUEST, 4, 42, 11, frame=0, payload=request(2, 5)),
                  record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(2, 6))]:
        assert not invocation_edges(run(args.broker, [*base, wrong])[1]), wrong.hex()
    # The request record must already be retained; a later one is not linked.
    late = [record(VM, START, 1, 42, payload=start(5)),
            record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(2, 5)),
            record(NETWORK, REQUEST_INITIATED, 5, 42, 9, payload=b"POST")]
    assert not invocation_edges(run(args.broker, late)[1])
    # A reused (session, process, invocation) key is ambiguous: no edge at all.
    reused = [record(VM, START, 1, 42, payload=start(5)), record(VM, START, 2, 42, payload=start(5)),
              record(NETWORK, REQUEST_INITIATED, 3, 42, 9, payload=b"POST"),
              record(VM, REQUEST, 4, 42, 9, frame=0, payload=request(2, 5)),
              record(VM, SETTLE, 5, 42, payload=settle(5))]
    assert not invocation_edges(run(args.broker, reused)[1])
    # An evicted start is never revived.
    filler = [record(NETWORK, REQUEST_INITIATED, 10 + index, 99, 100 + index, payload=b"POST")
              for index in range(8)]
    evicted = [record(VM, START, 1, 42, payload=start(5)), *filler,
               record(VM, SETTLE, 30, 42, payload=settle(5))]
    assert not invocation_edges(run(args.broker, evicted, capacity=3)[1])
    # A malformed invocation record is refused by the broker, never indexed.
    rejected_with_digest = bytearray(settle(5, b"x"))
    rejected_with_digest[5] = 2
    for operation, malformed in [(START, start(5, parent=5)), (SETTLE, bytes(rejected_with_digest))]:
        with tempfile.TemporaryDirectory(prefix="reb-js-invocation-bad-") as folder:
            root = Path(folder)
            result = subprocess.run(
                [args.broker, "--store", str(root / "events"), "--trace-store", str(root / "edges")],
                input=record(VM, operation, 1, 42, payload=malformed), capture_output=True, timeout=10)
            assert result.returncode != 0, malformed.hex()
            edges = root / "edges"
            assert not edges.exists() or not edges.read_text().strip()
    print("PASS native JavaScript invocation: exact identity edges through the real broker, "
          "interleaved invocations kept apart, unknown/cross-process/cross-session/reused/evicted "
          "records refused, and the backend trace walks issued_during_invocation")


if __name__ == "__main__":
    main()
