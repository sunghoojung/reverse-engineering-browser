#!/usr/bin/env python3
"""Drive refused records through the real broker and backend.

Every record the broker refuses at validation must leave a broker_refusal
record in the store (protocol/broker-refusal-v1.md) that the evidence
validator accepts, that the backend counts in /api/events and the session
summary, and that closes the refused record's sequence hole when it can name
its place. A session's category mask and expiry still store nothing. Records
are authored here; a rebuilt Brave is not involved.
"""

import argparse
import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

CANVAS, WEBGL, VM = 1, 2, 10
API_CALL, WASM_GUEST_DISPATCH, BROKER_REFUSAL = 1, 18, 53
BROKER_PROCESS = 0xFFFFFFFF
SESSION, PROCESS = 7, 9
VALIDATOR = Path(__file__).with_name("validate-evidence-store.py")


def record(sequence, category=CANVAS, operation=API_CALL, *, process=PROCESS, payload=b"",
           version=3, header=144, payload_size=None, reserved=False, flags=0, scheme=0, parent=0):
    data = bytearray(320)
    struct.pack_into("<HHHHIIQQQII", data, 0, version, header, category, operation,
                     len(payload) if payload_size is None else payload_size, 1, sequence,
                     1000 + sequence, SESSION, process, 3)
    struct.pack_into("<QQQQQ", data, 48, 5, 6, 0, parent, 0)
    struct.pack_into("<H", data, 130, flags)
    data[140] = scheme
    data[144:144 + len(payload)] = payload
    if reserved:
        data[300] = 1
    return bytes(data)


# (refused record, reason, stored category). The first three refused headers
# cannot name their place, so their refusals take the broker's own stream.
CASES = [
    (record(2, payload_size=129), "payload_size", "canvas"),
    (record(3, reserved=True), "reserved", "canvas"),
    (record(4, category=999), "category", "unknown"),
    (record(5, operation=999), "type", "canvas"),
    (record(6, operation=BROKER_REFUSAL), "type", "canvas"),
    (record(7, flags=0x8000), "flags", "canvas"),
    (record(8, scheme=99), "network_class", "canvas"),
    (record(9, category=VM, operation=WASM_GUEST_DISPATCH), "typed_payload", "vm"),
    (record(10, version=2), "protocol_version", "canvas"),
    (record(11, header=100), "header_size", "canvas"),
    (record(12, process=BROKER_PROCESS), "process_id", "canvas"),
]
ENVELOPE = 3


def stop_line(stderr):
    lines = [line for line in stderr.splitlines() if line.startswith("Broker stopped:")]
    assert len(lines) == 1, stderr
    return dict(field.split("=", 1) for field in lines[0].split()[2:])


def validate(store):
    result = subprocess.run([sys.executable, str(VALIDATOR), str(store)], capture_output=True,
                            text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr


def payload_fields(event):
    payload = bytes.fromhex(event["payload"])
    return struct.unpack_from("<HHHHHHHHIHBBQQQII", payload, 0)


def backend_reads(backend, root):
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
            base = endpoint.read_text().strip()

            def get(path):
                with opener.open(base + path, timeout=30) as response:
                    return json.load(response)

            return get("/api/events?limit=100"), get("/api/session/summary"), get("/api/events?type=broker_refusal")
        finally:
            child.terminate()
            child.wait(timeout=10)


def verify_standard_input(broker, backend):
    """Every reason, from one stream of process 9: records 1 and 13 are valid
    and each other sequence was refused."""
    with tempfile.TemporaryDirectory(prefix="reb-broker-refusals-") as folder:
        root = Path(folder)
        records = [record(1)] + [case[0] for case in CASES] + [record(13, parent=12)]
        run = subprocess.run([broker, "--store", str(root / "events"), "--trace-store", str(root / "edges")],
                             input=b"".join(records), capture_output=True, timeout=10, check=False)
        stats = stop_line(run.stderr.decode())
        assert run.returncode == 1, "a refusal still fails the broker's exit status"
        assert (stats["accepted"], stats["invalid"], stats["refusals_recorded"]) == ("2", "11", "11"), stats
        # The broker counts the three holes its own-stream refusals leave.
        assert stats["sequence_gaps"] == str(ENVELOPE), stats
        events = [json.loads(line) for line in (root / "events").read_text().splitlines()]
        assert len(events) == len(records), events
        validate(root / "events")
        refusals = events[1:-1]
        broker_sequence = 0
        for event, (refused, reason, category) in zip(refusals, CASES):
            fields = payload_fields(event)
            assert event["type"] == "broker_refusal" and event["category"] == category, event
            assert event["session_id"] == str(SESSION) and event["payload_size"] == 128, event
            assert fields[0:2] == (1, 128), fields
            sequence = struct.unpack_from("<Q", refused, 16)[0]
            assert fields[13] == sequence, "the refused sequence is kept as read"
            if fields[2] <= ENVELOPE:
                broker_sequence += 1
                assert fields[3] == 2, fields
                assert event["process_id"] == BROKER_PROCESS and event["thread_id"] == 0, event
                assert event["sequence_number"] == str(broker_sequence), event
                assert event["frame_id"] == "0" and event["navigation_id"] == "0", event
            else:
                assert fields[3] == 1, fields
                assert event["process_id"] == PROCESS and event["thread_id"] == 3, event
                assert event["sequence_number"] == str(sequence), event
                assert (event["navigation_id"], event["frame_id"]) == ("5", "6"), event
            # Never a byte of the refused payload.
            assert not any(bytes.fromhex(event["payload"])[56:]), event
        assert broker_sequence == ENVELOPE

        window, summary, filtered = backend_reads(backend, root)
        expected = []
        for _, reason, category in CASES:
            known = next((entry for entry in expected
                          if entry["category"] == category and entry["reason"] == reason), None)
            if known:
                known["count"] = str(int(known["count"]) + 1)
            else:
                expected.append({"category": category, "reason": reason, "count": "1"})
        assert window["broker_refusals"] == expected, window["broker_refusals"]
        assert summary["events"]["broker_refusals"] == expected, summary["events"]
        assert window["sequence_gaps"] == str(ENVELOPE) and window["queue_drops"] == "0", window
        assert window["named_gaps"] == [], window
        assert filtered["count"] == len(CASES), filtered["count"]
        decoded = [event["broker_refusal"] for event in window["events"] if event["type"] == "broker_refusal"]
        assert [entry["reason"] for entry in decoded] == [case[1] for case in CASES], decoded
        assert all(entry["status"] == "decoded" for entry in decoded), decoded
        assert decoded[3]["refused"]["type"] == 999 and decoded[4]["refused"]["type"] == BROKER_REFUSAL
        checks = [check for check in summary["checks"] if check["code"] == "broker_refusal"]
        assert [(check["category"], check["reason"], check["count"]) for check in checks] == \
            [(entry["category"], entry["reason"], entry["count"]) for entry in expected], checks
        assert all(check["severity"] == "error" for check in checks), checks
        gaps = [check for check in summary["checks"] if check["code"] == "sequence_gaps"]
        assert gaps and gaps[0]["message"].startswith(f"{ENVELOPE} sequence numbers"), summary["checks"]


def socket_session(broker, root, records, *, mask, seconds, wait=0.0):
    token = root / "token"
    command = [broker, "--store", str(root / "events"), "--socket", str(root / "broker.sock"),
               "--token-file", str(token), "--session-id", str(SESSION),
               "--category-mask", str(mask), "--duration-seconds", str(seconds)]
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE) as child:
        try:
            assert child.stderr is not None
            stderr = b""
            deadline = time.monotonic() + 10
            while b"Broker listening on" not in stderr:
                assert time.monotonic() < deadline, stderr
                if select.select([child.stderr], [], [], 0.1)[0]:
                    chunk = os.read(child.stderr.fileno(), 4096)
                    assert chunk, stderr
                    stderr += chunk
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(root / "broker.sock"))
                connection.sendall(struct.pack("<IHHQ32s16x", 0x52454249, 1, 64, SESSION,
                                               bytes.fromhex(token.read_text().strip())))
                time.sleep(wait)
                try:
                    connection.sendall(b"".join(records))
                except OSError:
                    pass  # An expired broker may already have closed the connection.
            stderr += child.stderr.read()
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
    return child.returncode, stop_line(stderr.decode())


def verify_session_policy(broker):
    """Disabled categories and an expired session store no refusal; an
    unknown category cannot be matched against the mask, so its refusal is
    kept."""
    with tempfile.TemporaryDirectory(prefix="reb-broker-refusal-policy-") as folder:
        root = Path(folder)
        records = [
            record(1),
            record(2, reserved=True),
            record(3, category=999),
            record(4, category=WEBGL),
            record(5, category=WEBGL, reserved=True),
        ]
        code, stats = socket_session(broker, root, records, mask=1 << (WEBGL - 1), seconds=60)
        assert code == 1, stats
        assert (stats["accepted"], stats["invalid"], stats["refusals_recorded"],
                stats["category_rejected"]) == ("1", "3", "2", "1"), stats
        events = [json.loads(line) for line in (root / "events").read_text().splitlines()]
        assert [(event["category"], event["type"], event["sequence_number"]) for event in events] == [
            ("unknown", "broker_refusal", "3"), ("webgl", "api_call", "4"),
            ("webgl", "broker_refusal", "5")], events
        validate(root / "events")
    with tempfile.TemporaryDirectory(prefix="reb-broker-refusal-expiry-") as folder:
        root = Path(folder)
        code, stats = socket_session(broker, root, [record(1, reserved=True), record(2, category=999)],
                                     mask=(1 << 12) - 1, seconds=1, wait=1.3)
        assert code == 0, stats
        assert (stats["accepted"], stats["invalid"], stats["refusals_recorded"]) == ("0", "0", "0"), stats
        assert (root / "events").read_bytes() == b""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--backend", required=True)
    args = parser.parse_args()
    verify_standard_input(args.broker, args.backend)
    verify_session_policy(args.broker)
    print("PASS every refused record leaves a validated, counted broker_refusal; "
          "masked and expired sessions store none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
