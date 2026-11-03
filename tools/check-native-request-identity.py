#!/usr/bin/env python3
"""Exercise native request identities and arrival order through the real broker."""

import argparse
import hashlib
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


# A native-network-v2 child record: the parent's identity, an explicit parent
# sequence and a 128-byte payload (protocol/native-network-v2.md).
def child_record(operation, sequence, parent, payload, *, artifact=0):
    record = event(operation, sequence, 84, 900, context=99)
    struct.pack_into("<I", record, 8, len(payload))
    struct.pack_into("<QQ", record, 64, artifact, parent)
    record[144:144 + len(payload)] = payload
    return record


def target_payload(target):
    payload = bytearray(128)
    struct.pack_into("<HHIBBH", payload, 0, 1, 128, len(target), 2, 0, 0)
    payload[12:12 + len(target)] = target
    return bytes(payload)


def body_payload(body, content_type=b"application/json"):
    payload = bytearray(128)
    struct.pack_into("<HHBBBBQQII", payload, 0, 1, 128, 1, 4, 1 | 2 | 16, len(content_type),
                     len(body), len(body), 1, 0)
    payload[32:64] = hashlib.sha256(body).digest()
    payload[64:64 + len(content_type)] = content_type
    return bytes(payload)


def traces(backend, root, sequences):
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
            documents = []
            for sequence in sequences:
                url = (endpoint.read_text().strip() + "/api/origin-trace?request_id=900&session_id=7"
                       f"&root_process_id=84&root_sequence_number={sequence}")
                with opener.open(url, timeout=10) as response:
                    documents.append(json.load(response))
            return documents
        finally:
            child.terminate()
            child.wait(timeout=10)


def verify_http(backend, root):
    for trace in traces(backend, root, [1, 2]):
        assert trace["status"] == "partial", trace
        assert [step["request_id"] for step in trace["steps"]] == ["900", "9"], trace
        assert trace["steps"][1]["event"] == {"session_id": "7", "process_id": 42,
                                               "sequence_number": "1"}, trace
        assert trace["steps"][1]["relation"] == "request_initiator", trace


def verify_children_http(backend, root):
    response, body = traces(backend, root, [6, 3])
    assert [(step["event"]["sequence_number"], step["relation"]) for step in response["steps"]] == [
        ("6", "trace_target"), ("4", "request_lifecycle"), ("1", "request_lifecycle")], response
    assert [(step["event"]["sequence_number"], step["relation"]) for step in body["steps"]] == [
        ("3", "trace_target"), ("1", "parent_event")], body
    assert body["steps"][0]["value"] == (
        "Binary request_body record, 128 bytes, not shown as text; Traffic shows its fields"), body


def run(broker, records, capacity=64, backend=None, verify=verify_http):
    with tempfile.TemporaryDirectory(prefix="reb-request-identity-") as folder:
        root = Path(folder)
        subprocess.run([broker, "--store", str(root / "events"), "--trace-store", str(root / "edges"),
                        "--capacity", str(capacity)], input=b"".join(records),
                       check=True, capture_output=True, timeout=10)
        if backend:
            verify(backend, root)
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

    # Target and body records hang off their lifecycle parent only. The next
    # lifecycle record links to the previous lifecycle record, never to a child,
    # including the target a redirect emits.
    lifecycle_records = [
        event(5, 1, 84, 900, context=99),
        child_record(23, 2, 1, target_payload(b"/getcaptcha?s=1")),
        child_record(22, 3, 1, body_payload(b'{"a":1}'), artifact=320),
        event(9, 4, 84, 900, context=99),
        child_record(23, 5, 4, target_payload(b"/checkcaptcha?s=1")),
        event(10, 6, 84, 900, context=99),
        event(11, 7, 84, 900, context=99),
    ]
    edges = run(args.broker, lifecycle_records, backend=args.backend, verify=verify_children_http)
    links = {(edge["from_sequence_number"], edge["to_sequence_number"], edge["relation"]) for edge in edges}
    assert links == {("2", "1", "parent_event"), ("3", "1", "parent_event"), ("5", "4", "parent_event"),
                     ("4", "1", "request_lifecycle"), ("6", "4", "request_lifecycle"),
                     ("7", "6", "request_lifecycle")}, edges
    print("PASS native request identity: exact disjoint IDs, both arrival orders, typed initiators, "
          "session/process/context isolation, reuse ambiguity, duplicate and retention limits, "
          "request target and body records outside the lifecycle chain")


if __name__ == "__main__":
    main()
