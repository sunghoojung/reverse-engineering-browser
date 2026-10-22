#!/usr/bin/env python3
"""Exercise native request identities and arrival order through the real broker."""

import argparse
import json
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


def event(operation, sequence, process, request, *, session=7, initiator=(0, 0), context=0):
    record = bytearray(320)
    struct.pack_into("<HHHHIIQQQII", record, 0, 3, 144, 9, operation, 0, 0,
                     sequence, sequence * 100, session, process, 1)
    struct.pack_into("<QQQ", record, 80, request, context, 0)
    struct.pack_into("<II", record, 132, initiator[1], initiator[0])
    return record


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
            for sequence in [1, 2]:
                url = (endpoint.read_text().strip() + "/api/origin-trace?request_id=900&session_id=7"
                       f"&root_process_id=84&root_sequence_number={sequence}")
                with opener.open(url, timeout=10) as response:
                    trace = json.load(response)
                assert trace["status"] == "partial", trace
                assert [step["request_id"] for step in trace["steps"]] == ["900", "9"], trace
                assert trace["steps"][1]["event"] == {"session_id": "7", "process_id": 42,
                                                       "sequence_number": "1"}, trace
                assert trace["steps"][1]["relation"] == "request_initiator", trace
        finally:
            child.terminate()
            child.wait(timeout=10)


def run(broker, records, capacity=64, backend=None):
    with tempfile.TemporaryDirectory(prefix="reb-request-identity-") as folder:
        root = Path(folder)
        subprocess.run([broker, "--store", str(root / "events"), "--trace-store", str(root / "edges"),
                        "--capacity", str(capacity)], input=b"".join(records),
                       check=True, capture_output=True, timeout=10)
        if backend:
            verify_http(backend, root)
        return [json.loads(line) for line in (root / "edges").read_text().splitlines()]


def initiators(edges):
    return [edge for edge in edges if edge["relation"] == "request_initiator"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--backend")
    args = parser.parse_args()
    initiate = event(8, 1, 42, 9)
    start = event(5, 1, 84, 900, initiator=(42, 9), context=99)
    complete = event(11, 2, 84, 900, initiator=(42, 9), context=99)
    expected = {(84, "1", 42, "1"), (84, "2", 42, "1")}
    for records in ([initiate, start, complete], [start, initiate, complete],
                    [start, complete, initiate]):
        edges = run(args.broker, records, backend=args.backend)
        linked = initiators(edges)
        assert {(edge["from_process_id"], edge["from_sequence_number"], edge["to_process_id"],
                 edge["to_sequence_number"]) for edge in linked} == expected, linked
        assert all(edge["request_id"] == "900" and edge["confidence"] == "observed" for edge in linked)
        assert len([edge for edge in edges if edge["relation"] == "request_lifecycle"]) == 1

    # Same numeric ID, host, or timestamp in another stream/session is not evidence.
    for wrong in [event(8, 1, 43, 9), event(8, 1, 42, 10), event(8, 1, 42, 9, session=8),
                  event(5, 1, 42, 9), event(11, 1, 42, 9)]:
        assert not initiators(run(args.broker, [wrong, start]))
        assert not initiators(run(args.broker, [start, wrong]))
    assert not initiators(run(args.broker, [initiate, event(8, 2, 42, 9), start]))
    for invalid in [event(5, 1, 84, 900, initiator=(0, 9)),
                    event(5, 1, 84, 900, initiator=(42, 0)),
                    event(1, 1, 84, 900, initiator=(42, 9)),
                    event(5, 1, 84, 0, initiator=(42, 9))]:
        assert not initiators(run(args.broker, [initiate, invalid]))
        assert not initiators(run(args.broker, [invalid, initiate]))

    large_init = event(8, 2**53 + 1, 42, 2**32 - 1)
    large_start = event(5, 2**53 + 3, 84, 2**64 - 1, initiator=(42, 2**32 - 1), context=99)
    for records in [[large_init, large_start], [large_start, large_init]]:
        linked = initiators(run(args.broker, records))
        assert len(linked) == 1 and linked[0]["request_id"] == str(2**64 - 1)
        assert linked[0]["to_sequence_number"] == str(2**53 + 1)

    # Unrelated browser contexts may reuse a browser-local ID without cross-linking.
    other = event(5, 3, 84, 900, initiator=(43, 9), context=100)
    edges = run(args.broker, [start, other, initiate, complete])
    assert len(initiators(edges)) == 2
    lifecycle = [edge for edge in edges if edge["relation"] == "request_lifecycle"]
    assert len(lifecycle) == 1 and lifecycle[0]["to_sequence_number"] == "1"

    # Evicted endpoints must not be revived; pending bookkeeping stays bounded.
    filler = [event(5, index + 1, 99, index + 100) for index in range(10)]
    assert not initiators(run(args.broker, [start, *filler, initiate], capacity=3))
    assert not initiators(run(args.broker, [initiate, *filler, start], capacity=3))
    assert not initiators(run(args.broker, [start, initiate], capacity=1))
    many = [event(5, index + 1, 84, 900 + index, initiator=(42, 9), context=99)
            for index in range(10)]
    linked = initiators(run(args.broker, [*many, initiate], capacity=4))
    assert {edge["from_sequence_number"] for edge in linked} == {"8", "9", "10"}
    assert len(initiators(run(args.broker, [start, initiate, initiate]))) == 1
    print("PASS native request identity: exact disjoint IDs, both arrival orders, typed initiators, "
          "session/process/context isolation, reuse ambiguity, duplicate and retention limits")


if __name__ == "__main__":
    main()
