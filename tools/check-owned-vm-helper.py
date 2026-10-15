#!/usr/bin/env python3
"""Verify the real owned native helper against independent transition goldens."""

import argparse
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import time
from unittest import mock

MAGIC = 0x314D5652
MAX_U64 = (1 << 64) - 1
REQUEST = struct.Struct("<IHHQQQQ")
RESPONSE = struct.Struct("<IHHQII")
STATS = {
    "attempted", "recorded", "full", "malformed", "wrong_document",
    "stale_generation", "exhausted", "expired", "partial",
}
FIELDS = {
    "schema", "fixture", "program_id", "fixture_revision", "session_id",
    "document_id", "invocation_id", "run_generation", "state", "executed_count",
    "retained_count", "snapshot", "transition", "recorder_result", "stats", "tick_units",
}


def read_exact(pipe, count):
    deadline = time.monotonic() + 3
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "helper reply timed out"
        assert select.select([pipe], [], [], remaining)[0], "helper reply timed out"
        part = os.read(pipe.fileno(), count - len(data))
        assert part, ("short helper reply", len(data), count)
        data.extend(part)
    return bytes(data)


def canonical_u64(value):
    assert isinstance(value, str) and value.isascii() and value.isdecimal(), value
    assert value == str(int(value)) and int(value) <= MAX_U64, value


class Helper:
    def __init__(self, binary, fixture="register", lifetime=60000, identity=17):
        self.command = [
            binary, "--control-owned-fixture-v1", "--fixture", fixture,
            "--session-id", str(identity), "--document-id", str(identity),
            "--invocation-id", str(identity), "--run-generation", str(identity),
            "--lifetime-ms", str(lifetime),
        ]
        self.process = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        self.identity = identity
        self.fixture = fixture
        self.max_payload = 0
        try:
            self.initial = self.reply(0, 0)
        except BaseException:
            # A failed constructor never enters the context manager. Retire its
            # exact child and close every pipe before reporting the failure.
            try:
                self.process.kill()
                self.process.wait(timeout=3)
            finally:
                for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                    pipe.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
            raise
        self.process.stdout.close()
        self.process.stderr.close()

    def frame(self, operation, request_id, count, generation=None, **changes):
        fields = {
            "magic": MAGIC, "version": 1, "operation": operation,
            "request_id": request_id,
            "generation": self.identity if generation is None else generation,
            "count": count, "reserved": 0,
        }
        fields.update(changes)
        return REQUEST.pack(*fields.values())

    def write(self, frame):
        self.process.stdin.write(frame)
        self.process.stdin.flush()

    def request(self, operation, request_id, count, status=0, **changes):
        self.write(self.frame(operation, request_id, count, **changes))
        return self.reply(request_id, status)

    def reply(self, request_id, status):
        magic, version, actual, received, size, reserved = RESPONSE.unpack(
            read_exact(self.process.stdout, RESPONSE.size)
        )
        assert (magic, version, actual, received, reserved) == (
            MAGIC, 1, status, request_id, 0,
        ), (magic, version, actual, received, reserved)
        assert 0 < size <= 32768
        self.max_payload = max(self.max_payload, size)
        payload = json.loads(read_exact(self.process.stdout, size).decode("utf-8"))
        assert set(payload) == FIELDS, payload
        assert payload["schema"] == "reb-owned-vm-helper-v1"
        assert payload["fixture"] == self.fixture
        assert payload["program_id"] == f"owned-{self.fixture}-v1"
        assert payload["fixture_revision"] == 1
        assert payload["tick_units"] == "monotonic-nanoseconds"
        assert set(payload["stats"]) == STATS
        for field in ("session_id", "document_id", "invocation_id", "run_generation"):
            assert payload[field] == str(self.identity)
        for field in ("executed_count", "retained_count"):
            canonical_u64(payload[field])
        for value in payload["stats"].values():
            canonical_u64(value)
        return payload

    def finish(self, code=0, diagnostic=b""):
        self.process.stdin.close()
        assert self.process.wait(timeout=3) == code
        assert self.process.stdout.read() == b""
        stderr = self.process.stderr.read()
        assert stderr == diagnostic and len(stderr) <= 8192, stderr


def failed_initialization_cleanup(binary):
    original_popen = subprocess.Popen
    children = []

    def malformed_initial(_command, **kwargs):
        # The child sends a complete but invalid header, then stays alive until
        # killed. This deterministically exercises failure before __enter__.
        script = (
            "import sys; sys.stdout.buffer.write(bytes(24)); "
            "sys.stdout.buffer.flush(); sys.stdin.buffer.read()"
        )
        child = original_popen([sys.executable, "-c", script], **kwargs)
        children.append(child)
        return child

    with mock.patch.object(subprocess, "Popen", side_effect=malformed_initial):
        try:
            Helper(binary)
        except AssertionError:
            pass
        else:
            raise AssertionError("malformed initial response was accepted")
    assert len(children) == 1
    child = children[0]
    assert child.returncode is not None, "failed initialization left its child alive"
    assert all(pipe.closed for pipe in (child.stdin, child.stdout, child.stderr))
    try:
        os.waitpid(child.pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError("failed initialization did not reap its child")


def assert_inert(payload, count, snapshot):
    assert payload["executed_count"] == str(count)
    assert payload["snapshot"] == snapshot
    assert payload["transition"] is None and payload["recorder_result"] is None
    assert payload["stats"]["attempted"] == str(count)


def golden_runs(binary, goldens):
    peak = 0
    for architecture in ("register", "stack"):
        golden = goldens[architecture]
        with Helper(binary, architecture, identity=MAX_U64) as helper:
            initial = helper.initial
            assert initial["state"] == "paused"
            assert initial["snapshot"] == golden["initial"]
            assert initial["executed_count"] == initial["retained_count"] == "0"
            assert initial["transition"] is None and initial["recorder_result"] is None
            assert all(value == "0" for value in initial["stats"].values())
            # Waiting past two run intervals cannot execute a first instruction.
            time.sleep(0.55)
            assert_inert(helper.request(1, 1, 0), 0, golden["initial"])
            previous_tick = 0
            for count, expected in enumerate(golden["transitions"]):
                payload = helper.request(2, 2 + count * 2, count)
                assert payload["executed_count"] == str(count + 1)
                assert payload["retained_count"] == str(count + 1)
                assert payload["snapshot"] == expected["after"]
                assert payload["recorder_result"] == "recorded"
                transition = payload["transition"].copy()
                tick = transition.pop("tick")
                canonical_u64(tick)
                assert int(tick) >= previous_tick
                previous_tick = int(tick)
                assert transition == expected, (architecture, count, transition, expected)
                assert payload["state"] == ("halted" if count == 8 else "paused")
                assert_inert(helper.request(1, 3 + count * 2, count + 1), count + 1,
                             expected["after"])
            final = helper.request(2, 20, 9, status=6)
            assert final["state"] == "halted"
            assert_inert(final, 9, golden["transitions"][-1]["after"])
            closed = helper.request(3, 21, 9, status=9)
            assert closed["state"] == "stopped"
            assert_inert(closed, 9, final["snapshot"])
            helper.finish()
            peak = max(peak, helper.max_payload)
    return peak


def guard_and_transport(binary):
    with Helper(binary) as helper:
        snapshot = helper.initial["snapshot"]
        assert_inert(helper.request(2, 0, 0, status=4), 0, snapshot)
        assert_inert(helper.request(2, 1, 0, generation=18, status=2), 0, snapshot)
        assert_inert(helper.request(2, 1, 0, status=4), 0, snapshot)
        assert_inert(helper.request(2, 2, MAX_U64, status=3), 0, snapshot)
        assert_inert(helper.request(2, 2, 0, status=4), 0, snapshot)
        first = helper.request(2, 3, 0)
        assert first["executed_count"] == "1"
        assert_inert(helper.request(2, 3, 1, status=4), 1, first["snapshot"])
        assert_inert(helper.request(2, 4, 0, status=3), 1, first["snapshot"])
        assert_inert(helper.request(1, 5, 1), 1, first["snapshot"])
        # Close has exact guards too, so stale control cannot dispose this run.
        assert_inert(helper.request(3, 6, 1, generation=18, status=2), 1, first["snapshot"])
        helper.request(3, 7, 1, status=9)
        helper.finish()
    with Helper(binary) as helper:
        frame = helper.frame(2, 1, 0)
        for offset in range(len(frame) - 1):
            helper.write(frame[offset:offset + 1])
            assert not select.select([helper.process.stdout], [], [], 0)[0]
        helper.write(frame[-1:])
        assert helper.reply(1, 0)["executed_count"] == "1"
        helper.finish()  # EOF at a frame boundary is a clean immediate exit.
    for field, value in (("magic", 0), ("version", 2), ("operation", 0),
                         ("operation", 4), ("reserved", MAX_U64)):
        with Helper(binary) as helper:
            malformed = helper.frame(2, 1, 0, **{field: value}) if field != "operation" else (
                helper.frame(value, 1, 0)
            )
            helper.write(malformed + helper.frame(2, 2, 0))
            rejected = helper.reply(1, 1)
            assert rejected["state"] == "failed"
            assert_inert(rejected, 0, helper.initial["snapshot"])
            helper.finish(code=2)
    for size in (0, 1, 7, 15, 16, 31, 39):
        with Helper(binary) as helper:
            helper.write(helper.frame(2, 1, 0)[:size])
            helper.finish(
                code=2 if size else 0,
                diagnostic=b"Incomplete owned fixture request frame\n" if size else b"",
            )
    with Helper(binary) as helper:
        limited = helper.request(2, MAX_U64, 0, status=7)
        assert limited["state"] == "failed"
        assert_inert(limited, 0, helper.initial["snapshot"])
        helper.finish()
    with Helper(binary, lifetime=40) as helper:
        time.sleep(0.08)
        snapshot = helper.initial["snapshot"]
        # Stale guards are checked before looking at the current run's deadline.
        assert_inert(helper.request(2, 1, 0, generation=18, status=2), 0, snapshot)
        assert_inert(helper.request(2, 2, 1, status=3), 0, snapshot)
        expired = helper.request(2, 3, 0, status=5)
        assert expired["state"] == "expired" and expired["stats"]["expired"] == "0"
        assert_inert(expired, 0, snapshot)
        helper.finish()


    with Helper(binary) as helper:
        first = helper.request(2, MAX_U64 - 1, 0)
        assert first["executed_count"] == "1"
        limited = helper.request(2, MAX_U64, 1, status=7)
        assert_inert(limited, 1, first["snapshot"])
        helper.finish()
    with Helper(binary, lifetime=40) as helper:
        frame = helper.frame(2, 1, 0)
        helper.write(frame[:-1])
        time.sleep(0.08)
        helper.write(frame[-1:])
        expired = helper.reply(1, 5)
        assert_inert(expired, 0, helper.initial["snapshot"])
        helper.finish()
    with Helper(binary, lifetime=40) as helper:
        first = helper.request(2, 1, 0)
        time.sleep(0.08)
        expired = helper.request(2, 2, 1, status=5)
        assert expired["state"] == "expired" and expired["stats"]["expired"] == "0"
        assert_inert(expired, 1, first["snapshot"])
        helper.finish()


def invalid_arguments(binary):
    with Helper(binary) as helper:
        command = helper.command
        helper.finish()
    for flag, value in (
        ("--fixture", "external"), ("--session-id", "0"), ("--document-id", "01"),
        ("--invocation-id", "-1"), ("--run-generation", "18446744073709551616"),
        ("--lifetime-ms", "60001"), ("--lifetime-ms", "0"),
    ):
        invalid = command.copy()
        invalid[invalid.index(flag) + 1] = value
        result = subprocess.run(invalid, capture_output=True, timeout=3, check=False)
        assert result.returncode == 2 and not result.stdout
        assert result.stderr == b"Invalid owned fixture control arguments\n"
    for invalid in (command[:-2], command + ["--fixture", "register"],
                    command[:-2] + ["--session-id", "1"]):
        result = subprocess.run(invalid, capture_output=True, timeout=3, check=False)
        assert result.returncode == 2 and not result.stdout
        assert result.stderr == b"Invalid owned fixture control arguments\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    golden_path = Path(__file__).parent / "fixtures" / "owned-vm-golden-transitions-v1.json"
    goldens = json.loads(golden_path.read_text(encoding="utf-8"))
    assert goldens["schema"] == "reb-owned-fixture-independent-goldens-v1"
    failed_initialization_cleanup(args.binary)
    peak = golden_runs(args.binary, goldens)
    guard_and_transport(args.binary)
    invalid_arguments(args.binary)
    print(f"Owned VM helper: 18 independent goldens and lifecycle checks passed (peak {peak} bytes)")


if __name__ == "__main__":
    main()
