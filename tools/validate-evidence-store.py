#!/usr/bin/env python3

import argparse
import fcntl
import hashlib
import json
import select
import subprocess
import tempfile
from pathlib import Path


EXPECTED_FIELDS = {
    "artifact_id",
    "browser_context_id_high",
    "browser_context_id_low",
    "category",
    "decoded_body_length",
    "encoded_data_length",
    "error_code",
    "flags",
    "frame_id",
    "initiator_process_id",
    "initiator_request_id",
    "monotonic_time_ns",
    "navigation_id",
    "parent_event_id",
    "payload",
    "payload_encoding",
    "payload_size",
    "payload_truncated",
    "process_id",
    "protocol_version",
    "request_id",
    "resource_type",
    "sequence_number",
    "session_id",
    "status_code",
    "thread_id",
    "type",
}
UNSIGNED_STRING_INTEGER_FIELDS = {
    "artifact_id",
    "browser_context_id_high",
    "browser_context_id_low",
    "frame_id",
    "monotonic_time_ns",
    "navigation_id",
    "parent_event_id",
    "request_id",
    "sequence_number",
    "session_id",
}
SIGNED_STRING_INTEGER_FIELDS = {
    "decoded_body_length",
    "encoded_data_length",
}
INTEGER_FIELDS = {
    "error_code",
    "flags",
    "initiator_process_id",
    "initiator_request_id",
    "payload_size",
    "process_id",
    "protocol_version",
    "resource_type",
    "status_code",
    "thread_id",
}
SENSITIVE_PAYLOAD_MARKERS = (
    b"authorization:",
    b"cookie:",
    b"proxy-authorization:",
    b"set-cookie:",
)
EVENT_CATEGORIES = {
    "artifact",
    "canvas",
    "navigator",
    "network",
    "permissions",
    "runtime",
    "storage",
    "vm",
    "wasm",
    "web_audio",
    "webgl",
    "webrtc",
}
EVENT_TYPES = {
    "api_call",
    "artifact_capture_failed",
    "artifact_captured",
    "gap",
    "module_compiled",
    "module_instantiated",
    "property_read",
    "request_completed",
    "request_failed",
    "request_initiated",
    "request_redirected",
    "request_started",
    "response_completed",
    "response_started",
    "vm_finding",
}
UINT64_MAX = (1 << 64) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def parse_canonical_integer(value: object, field: str, line_number: int) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError(f"line {line_number}: {field} is not a canonical integer string")
    if value[0] == "-":
        digits = value[1:]
        if not digits or not digits.isdigit() or value.startswith("-0"):
            raise ValueError(f"line {line_number}: {field} is not canonical")
    elif not value.isdigit() or (value.startswith("0") and value != "0"):
        raise ValueError(f"line {line_number}: {field} is not canonical")
    return int(value)


def validate_event(event: object, line_number: int) -> None:
    if not isinstance(event, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")

    protocol_version = event.get("protocol_version")
    expected_fields = EXPECTED_FIELDS | ({"tab_id"} if protocol_version == 3 else set())
    fields = set(event)
    if fields != expected_fields:
        missing = sorted(expected_fields - fields)
        unexpected = sorted(fields - expected_fields)
        raise ValueError(
            f"line {line_number}: evidence schema mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )

    for field in UNSIGNED_STRING_INTEGER_FIELDS:
        value = parse_canonical_integer(event[field], field, line_number)
        if not 0 <= value <= UINT64_MAX:
            raise ValueError(f"line {line_number}: {field} is outside uint64 range")

    for field in SIGNED_STRING_INTEGER_FIELDS:
        value = parse_canonical_integer(event[field], field, line_number)
        if not INT64_MIN <= value <= INT64_MAX:
            raise ValueError(f"line {line_number}: {field} is outside int64 range")

    for field in INTEGER_FIELDS:
        if not isinstance(event[field], int) or isinstance(event[field], bool):
            raise ValueError(f"line {line_number}: {field} is not an integer")

    if protocol_version == 3 and (
        not isinstance(event["tab_id"], int)
        or isinstance(event["tab_id"], bool)
        or not 0 <= event["tab_id"] < 2**32
    ):
        raise ValueError(f"line {line_number}: tab_id is outside uint32 range")

    if not isinstance(event["payload_truncated"], bool):
        raise ValueError(f"line {line_number}: payload_truncated is not a boolean")
    if protocol_version not in {2, 3}:
        raise ValueError(f"line {line_number}: unsupported protocol version")
    if event["category"] not in EVENT_CATEGORIES or event["type"] not in EVENT_TYPES:
        raise ValueError(f"line {line_number}: unknown category or event type")
    if not 0 <= event["flags"] <= 7:
        raise ValueError(f"line {line_number}: unsupported event flags")
    if not 0 <= event["payload_size"] <= 128:
        raise ValueError(f"line {line_number}: payload size exceeds the inline limit")
    if event["payload_encoding"] != "hex":
        raise ValueError(f"line {line_number}: unsupported payload encoding")
    try:
        payload = bytes.fromhex(event["payload"])
    except (TypeError, ValueError) as exception:
        raise ValueError(f"line {line_number}: payload is not valid hex") from exception
    if len(payload) != event["payload_size"]:
        raise ValueError(f"line {line_number}: payload size does not match encoded data")
    lowered_payload = payload.lower()
    if any(marker in lowered_payload for marker in SENSITIVE_PAYLOAD_MARKERS):
        raise ValueError(f"line {line_number}: payload contains sensitive HTTP metadata")


def validate_store(path: Path) -> int:
    event_count = 0
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            validate_event(json.loads(line), line_number)
            event_count += 1
    if event_count == 0:
        raise ValueError("evidence store is empty")
    return event_count



def validate_writer_guards(broker: Path, receiver: Path, producer: Path) -> None:
    """Real writer lifetime barriers; no sleeps, browser, sockets or network."""
    marker = b"REB_EVIDENCE_GUARD_V1\n"
    with tempfile.TemporaryDirectory(prefix="reb-guard-check-") as temporary:
        root = Path(temporary)
        for binary, store, guard, ready in [
            (broker, root / "events.jsonl", root / "events.jsonl.reb-lock-v1", b"Event store ready\n"),
            (receiver, root / "artifacts", root / "artifacts/evidence.reb-lock-v1", b"Artifact store ready\n"),
        ]:
            command = [str(binary.resolve()), "--store", str(store)]
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                assert child.stderr is not None and child.stdin is not None
                assert select.select([child.stderr], [], [], 10)[0], "Writer readiness deadline"
                assert child.stderr.readline() == ready, "Writer failed before acquiring its guard"
                assert guard.read_bytes() == marker
                assert guard.stat().st_mode & 0o777 == 0o600
                inode = guard.stat().st_ino
                with guard.open("rb") as held:
                    try:
                        fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass
                    else:
                        raise AssertionError("A live writer did not retain its exclusive guard")
                before = hashlib.sha256(store.read_bytes()).digest() if store.is_file() else None
                competing = subprocess.run(command, input=b"", capture_output=True, timeout=10, check=False)
                assert competing.returncode != 0, "A second writer acquired the same store"
                if before is not None:
                    assert hashlib.sha256(store.read_bytes()).digest() == before, "Competing writer truncated evidence"
                # Broker output is deliberately buffered until EOF. Its lifetime
                # guard covers the final delayed stream flush and stream close.
                if binary == broker:
                    events = subprocess.run([str(producer.resolve())], capture_output=True, timeout=10, check=True).stdout
                    child.stdin.write(events)
                    child.stdin.flush()
                    with guard.open("rb") as held:
                        try:
                            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        except BlockingIOError:
                            pass
                        else:
                            raise AssertionError("Buffered broker released its writer guard early")
                child.stdin.close()
                assert child.wait(timeout=10) == 0
                assert guard.stat().st_ino == inode and guard.read_bytes() == marker
                with guard.open("rb") as held:
                    fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    before = hashlib.sha256(store.read_bytes()).digest() if store.is_file() else None
                    blocked = subprocess.run(command, input=b"", capture_output=True, timeout=10, check=False)
                    assert blocked.returncode != 0, "Writer bypassed an export lease"
                    if before is not None:
                        assert hashlib.sha256(store.read_bytes()).digest() == before
                if binary == broker:
                    assert validate_store(store) == 14
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
            # Process death releases the lease without deleting/replacing the
            # immutable inode. It does not certify complete captured evidence.
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                assert child.stderr is not None
                assert select.select([child.stderr], [], [], 10)[0]
                assert child.stderr.readline() == ready
                child.kill()
                child.wait(timeout=10)
                with guard.open("rb") as held:
                    fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
                assert guard.stat().st_ino == inode
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        # Every alias and output role must participate before first mutation.
        event = root / "held.jsonl"
        command = [str(broker.resolve()), "--store", str(event)]
        subprocess.run(command, input=b"", capture_output=True, timeout=10, check=True)
        event.write_bytes(b"original retained bytes\n")
        event_guard = root / "held.jsonl.reb-lock-v1"
        with event_guard.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for alias_kind in ("symlink", "hardlink"):
                alias = root / f"{alias_kind}.jsonl"
                if alias_kind == "symlink":
                    alias.symlink_to(event)
                else:
                    alias.hardlink_to(event)
                failed = subprocess.run([str(broker.resolve()), "--store", str(alias)], input=b"", capture_output=True, timeout=10, check=False)
                assert failed.returncode != 0
                assert event.read_bytes() == b"original retained bytes\n"
                alias.unlink()
            fresh = root / "new-main.jsonl"
            failed = subprocess.run([str(broker.resolve()), "--store", str(fresh), "--trace-store", str(event)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and not fresh.exists()
            failed = subprocess.run([str(broker.resolve()), "--store", str(event_guard)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and event_guard.read_bytes() == marker
        artifacts = root / "aliased-artifacts"
        artifacts.mkdir()
        manifest = artifacts / "manifest.jsonl"
        for alias_kind in ("symlink", "hardlink"):
            if alias_kind == "symlink":
                manifest.symlink_to(event)
            else:
                manifest.hardlink_to(event)
            failed = subprocess.run([str(receiver.resolve()), "--store", str(artifacts)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0
            assert event.read_bytes() == b"original retained bytes\n"
            manifest.unlink()
        external_blobs = root / "external-blobs"
        external_blobs.mkdir()
        (artifacts / "blobs").rmdir()
        (artifacts / "blobs").symlink_to(external_blobs, target_is_directory=True)
        failed = subprocess.run([str(receiver.resolve()), "--store", str(artifacts)], input=b"", capture_output=True, timeout=10, check=False)
        assert failed.returncode != 0 and not list(external_blobs.iterdir())
        (artifacts / "blobs").unlink()
        (artifacts / "blobs").mkdir()
        for forbidden in (artifacts / "manifest.jsonl", artifacts / "artifact-1.part", artifacts / "blobs" / ("0" * 64 + ".bin")):
            failed = subprocess.run([str(broker.resolve()), "--store", str(forbidden)], input=b"", capture_output=True, timeout=10, check=False)
            assert failed.returncode != 0 and not forbidden.exists()

    print("Evidence writer guard check passed (lifetime, buffered flush, competing owners, shared export and process death)")

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate normalized broker evidence")
    parser.add_argument("store", type=Path)
    parser.add_argument("--broker", type=Path)
    parser.add_argument("--receiver", type=Path)
    parser.add_argument("--producer", type=Path)
    args = parser.parse_args()
    if any((args.broker, args.receiver, args.producer)) and not all((args.broker, args.receiver, args.producer)):
        parser.error("--broker, --receiver and --producer must be supplied together")
    try:
        event_count = validate_store(args.store)
    except (OSError, ValueError, json.JSONDecodeError) as exception:
        parser.error(str(exception))
    print(f"Evidence contract check passed ({event_count} events)")
    if args.broker:
        validate_writer_guards(args.broker, args.receiver, args.producer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
