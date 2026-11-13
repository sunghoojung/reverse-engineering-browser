#!/usr/bin/env python3
"""Actual native sink -> production receiver ACK -> broker/analyzer/controller checks.

Only Chromium platform, Mojo completion delivery and socket scheduling are adapters.
All corpus bytes come from the compiled production sinks; no evidence is repaired.
With --receiver, the production browser socket writers also run over real
AF_UNIX sockets against that receiver executable, and its socket framing and
manifest recovery are exercised directly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "browser/integration/brave/overlay"
HEADERS = (
    "base/containers/span.h",
    "base/no_destructor.h",
    "base/location.h",
    "base/task/sequenced_task_runner.h",
    "base/files/file_path.h",
    "base/functional/bind.h",
    "base/process/process_handle.h",
    "base/threading/platform_thread.h",
    "base/time/time.h",
    "base/numerics/safe_conversions.h",
    "content/public/browser/browser_context.h",
    "net/http/http_response_headers.h",
    "net/url_request/redirect_info.h",
    "services/network/public/cpp/resource_request.h",
    "services/network/public/cpp/url_loader_completion_status.h",
    "services/network/public/mojom/url_response_head.mojom.h",
    "mojo/public/cpp/base/big_buffer.h",
    "mojo/public/cpp/system/data_pipe.h",
    "url/gurl.h",
    "net/http/http_request_headers.h",
    "services/network/public/cpp/data_element.h",
    "services/network/public/cpp/resource_request_body.h",
    "base/component_export.h",
    "base/synchronization/lock.h",
    "services/network/public/mojom/http_raw_headers.mojom.h",
    "net/cookies/canonical_cookie.h",
    "net/cookies/cookie_access_result.h",
    "net/cookies/cookie_constants.h",
    "net/cookies/cookie_inclusion_status.h",
    "net/cookies/cookie_partition_key.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h",
    "brave/components/reverse_engineering_browser/browser/native_request_body_reader.h",
    "brave/components/reverse_engineering_browser/browser/native_probe_session.h",
    "brave/components/reverse_engineering_browser/common/native_probe_transport.mojom.h",
    "base/functional/callback.h",
    "brave/components/reverse_engineering_browser/common/native_wasm_guest_adapter.h",
    "base/memory/raw_ptr.h",
    "base/memory/raw_ref.h",
    "base/memory/scoped_refptr.h",
    "base/task/thread_pool.h",
    "base/memory/weak_ptr.h",
    "base/memory/shared_memory_mapping.h",
    "base/memory/unsafe_shared_memory_region.h",
    "content/public/browser/child_process_security_policy.h",
    "content/public/browser/render_frame_host.h",
    "content/public/browser/render_process_host.h",
    "content/public/browser/web_contents.h",
    "content/public/browser/weak_document_ptr.h",
    "mojo/public/cpp/bindings/remote.h",
)


TRANSPORT_HEADERS = (
    "build/build_config.h",
    "base/command_line.h",
    "base/containers/span.h",
    "base/files/file_path.h",
    "base/files/file_util.h",
    "base/functional/bind.h",
    "base/logging.h",
    "base/memory/scoped_refptr.h",
    "base/no_destructor.h",
    "base/process/process_handle.h",
    "base/strings/string_number_conversions.h",
    "base/synchronization/condition_variable.h",
    "base/synchronization/lock.h",
    "base/synchronization/waitable_event.h",
    "base/task/sequenced_task_runner.h",
    "base/task/thread_pool.h",
    "base/thread_annotations.h",
    "base/threading/platform_thread.h",
    "base/threading/thread.h",
    "base/time/time.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_capture_sink.h",
    "brave/components/reverse_engineering_browser/browser/native_network_capture_sink.h",
    "brave/components/reverse_engineering_browser/browser/native_probe_session.h",
)


def run(*command: str, **kwargs) -> None:
    subprocess.run(command, check=True, **kwargs)


def check_schedule_table(replays: list[dict]) -> None:
    """The contract's partial body sizing table must be what the capture does."""
    text = (ROOT / "protocol/native-network-v3.md").read_text()
    mib, second = 1024 * 1024, 1_000_000_000
    for replay in replays:
        row = re.search(
            r"^\| " + re.escape(replay["name"]) + r" \| (\d+) \| (\d+) MiB \| (\d+) s old([^|]*)\|$",
            text,
            re.MULTILINE,
        )
        if not row:
            raise SystemExit(f"native-network-v3.md has no sizing row for {replay['name']}")
        expected = (int(row[1]), int(row[2]), int(row[3]))
        actual = (replay["snapshots"], replay["copied_bytes"] // mib, replay["stale_ns"] // second)
        if expected != actual:
            raise SystemExit(f"native-network-v3.md sizing row {replay['name']} says {expected}, the replay {actual}")
        sealed = re.search(r"sealed after (\d+) s", row[4])
        if (replay["sealed_ns"] is None) != (sealed is None) or (
            sealed and int(sealed[1]) != replay["sealed_ns"] // second
        ):
            raise SystemExit(f"native-network-v3.md sizing row {replay['name']} names the seal wrongly")
    print(f"PASS partial body sizing table matches the replay of {len(replays)} streams")


def compiler_flags() -> list[str]:
    flags = [
        "-std=c++20",
        "-O2",
        "-g",
        "-pthread",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wshadow",
        "-Werror",
    ]
    if sanitizer := os.environ.get("REB_PROBE_TEST_SANITIZERS"):
        flags.extend(["-O1", f"-fsanitize={sanitizer}", "-fno-omit-frame-pointer"])
    return flags


def compile_driver(build: Path) -> Path:
    include = build / "include"
    include.mkdir()
    (include / "brave").symlink_to(OVERLAY, target_is_directory=True)
    stubs = build / "stubs"
    for header in HEADERS:
        path = stubs / header
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "chromium_stubs.h"\n', encoding="utf-8")
    fixture = ROOT / "tools/native-artifact-capture"
    sources = OVERLAY / "components/reverse_engineering_browser"
    binary = build / "native-artifact-capture"
    run(
        os.environ.get("CXX", "c++"),
        *compiler_flags(),
        f"-I{fixture}",
        f"-I{stubs}",
        f"-I{ROOT / 'tools/native-test-support'}",
        f"-I{include}",
        f"-I{ROOT / 'include'}",
        str(fixture / "main.cc"),
        str(sources / "browser/native_network_capture_sink.cc"),
        str(sources / "common/native_network_headers_hook.cc"),
        str(sources / "common/native_navigation_initiator_hook.cc"),
        str(sources / "browser/native_artifact_capture_sink.cc"),
        str(sources / "browser/native_artifact_stream.cc"),
        str(sources / "browser/native_response_body_capture.cc"),
        str(sources / "browser/native_probe_host.cc"),
        str(sources / "browser/native_tab_resolver.cc"),
        str(sources / "common/native_probe_queue.cc"),
        str(ROOT / "src/evidence/artifact.cpp"),
        str(ROOT / "src/capture/event.cpp"),
        "-o",
        str(binary),
    )
    return binary


def check_transport(receiver: str) -> None:
    """Production browser socket writers against the production receiver."""
    # A short root keeps every socket path inside sockaddr_un.
    with tempfile.TemporaryDirectory(prefix="reb-at-", dir="/tmp") as temporary:
        build = Path(temporary)
        include = build / "include"
        include.mkdir()
        (include / "brave").symlink_to(OVERLAY, target_is_directory=True)
        stubs = build / "stubs"
        for header in TRANSPORT_HEADERS:
            path = stubs / header
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "chromium_stubs.h"\n', encoding="utf-8")
        fixture = ROOT / "tools/native-artifact-transport"
        sources = OVERLAY / "components/reverse_engineering_browser"
        binary = build / "native-artifact-transport"
        run(
            os.environ.get("CXX", "c++"),
            *compiler_flags(),
            f"-I{fixture}",
            f"-I{stubs}",
            f"-I{include}",
            str(fixture / "main.cc"),
            str(sources / "browser/native_artifact_socket_client.cc"),
            str(sources / "browser/native_probe_socket_client.cc"),
            str(sources / "browser/native_local_ipc_client.cc"),
            str(sources / "common/native_probe_queue.cc"),
            "-o",
            str(binary),
        )
        root = build / "run"
        root.mkdir()
        run(str(binary), receiver, str(root), timeout=120)


ARTIFACT_MAGIC = 0x41424552
ACK_MAGIC = 0x4B414252
HELLO_MAGIC = 0x52454249
KIND_JAVASCRIPT = 1
STATUS_ACCEPTED = 0
STATUS_INVALID = 2
STATUS_TOO_LARGE = 3
TEST_TOKEN = bytes([0xAA]) * 32


def artifact_frame(
    artifact_id: int, content: bytes, *, session_id: int = 7, declared: int | None = None
) -> bytes:
    url = f"https://fixture.test/{artifact_id}.js".encode()
    mime = b"text/javascript"
    size = len(content) if declared is None else declared
    # magic, version, header size, kind, flags, reserved; six identifiers and
    # the content size; metadata sizes, digest, context, origin, reserved.
    header = struct.pack(
        "<IHHHHI7QII32sQHHI",
        *(ARTIFACT_MAGIC, 1, 128, KIND_JAVASCRIPT, 0, 0),
        *(session_id, 0, 0, artifact_id, 0, 0, size),
        *(len(url), len(mime), bytes(32), 0, 0, 0, 0),
    )
    assert len(header) == 128
    return header + url + mime + content


STREAM_MAGIC = 0x53424552
OP_DATA, OP_CHECKPOINT, OP_END = 1, 2, 3


def open_frame(artifact_id: int) -> bytes:
    """A version 2 open header: no size or digest; stream frames carry the content."""
    url = f"https://fixture.test/{artifact_id}.js".encode()
    mime = b"text/javascript"
    header = struct.pack(
        "<IHHHHI7QII32sQHHI",
        *(ARTIFACT_MAGIC, 2, 128, KIND_JAVASCRIPT, 0, 0),
        *(7, 0, 0, artifact_id, 0, 0, 0),
        *(len(url), len(mime), bytes(32), 0, 0, 0, 0),
    )
    return header + url + mime


def stream_frame(
    op: int, artifact_id: int, data: bytes = b"", *, value: int = 0, size: int = 0,
    digest: bytes = bytes(32),
) -> bytes:
    # magic, version, frame size, op, reserved, data size; session, artifact,
    # value and content size; expected digest.
    return struct.pack(
        "<IHHHHI4Q32s", STREAM_MAGIC, 2, 80, op, 0, len(data), 7, artifact_id, value, size, digest
    ) + data


def read_ack(connection: socket.socket, version: int = 1) -> tuple[int, int] | None:
    data = b""
    while len(data) < 32:
        chunk = connection.recv(32 - len(data))
        if not chunk:
            return None
        data += chunk
    magic, acked, size, status, reserved0, artifact_id, reserved1 = struct.unpack(
        "<IHHIIQ8s", data
    )
    assert (magic, acked, size, reserved0, reserved1) == (ACK_MAGIC, version, 32, 0, bytes(8))
    return status, artifact_id


def check_receiver_socket(receiver: str) -> None:
    """Receiver socket framing: what keeps a connection and what closes it."""
    with tempfile.TemporaryDirectory(prefix="reb-rs-", dir="/tmp") as temporary:
        root = Path(temporary)
        token = root / "token"
        token.write_text("a" * 64)
        token.chmod(0o600)
        socket_path = root / "artifact.sock"
        child = subprocess.Popen(
            [
                receiver,
                "--store",
                str(root / "artifacts"),
                "--socket",
                str(socket_path),
                "--token-file",
                str(token),
                "--session-id",
                "7",
                "--max-artifact-bytes",
                "65536",
            ],
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10
            while not socket_path.is_socket():
                assert child.poll() is None and time.monotonic() < deadline, "receiver socket"
                time.sleep(0.01)

            def connect() -> socket.socket:
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(10)
                connection.connect(str(socket_path))
                connection.sendall(
                    struct.pack("<IHHQ32s16s", HELLO_MAGIC, 1, 64, 7, TEST_TOKEN, bytes(16))
                )
                return connection

            with connect() as connection:
                connection.sendall(artifact_frame(1, b"one();"))
                assert read_ack(connection) == (STATUS_ACCEPTED, 1)
                # Over the 64 KiB limit but within the discard bound: the
                # receiver reads the body, answers, and keeps the connection.
                connection.sendall(artifact_frame(2, b"x" * (256 * 1024)))
                assert read_ack(connection) == (STATUS_TOO_LARGE, 2)
                connection.sendall(artifact_frame(3, b"three();"))
                assert read_ack(connection) == (STATUS_ACCEPTED, 3)
                # A declared body past the discard bound cannot come from a
                # supported sender; the receiver answers and closes.
                connection.sendall(artifact_frame(4, b"", declared=32 * 1024 * 1024)[:128])
                assert read_ack(connection) == (STATUS_TOO_LARGE, 4)
                assert read_ack(connection) is None, "an undiscardable frame closes"
            with connect() as connection:
                connection.sendall(bytes(128))
                assert read_ack(connection) == (STATUS_INVALID, 0)
                assert read_ack(connection) is None, "an invalid header closes"
            with connect() as connection:
                connection.sendall(artifact_frame(5, b"five();", session_id=8))
                assert read_ack(connection) == (STATUS_INVALID, 5)
                assert read_ack(connection) is None, "a session mismatch closes"
            with connect() as connection:
                connection.sendall(artifact_frame(6, b"six();"))
                assert read_ack(connection) == (STATUS_ACCEPTED, 6)
                # Two interleaved streams and a checkpoint, a refused end and an
                # oversize stream on the same connection, and one left open.
                head = b"head();" * 9000
                digest = hashlib.sha256(head).digest()
                for frame, expected in (
                    (open_frame(10), (STATUS_ACCEPTED, 10)),
                    (open_frame(11), (STATUS_ACCEPTED, 11)),
                    (stream_frame(OP_DATA, 10, head[:40000]), (STATUS_ACCEPTED, 10)),
                    (stream_frame(OP_DATA, 11, b"eleven();"), (STATUS_ACCEPTED, 11)),
                    (stream_frame(OP_CHECKPOINT, 10, value=12, size=40000), (STATUS_ACCEPTED, 12)),
                    (stream_frame(OP_DATA, 10, head[40000:]), (STATUS_ACCEPTED, 10)),
                    (stream_frame(OP_END, 10, size=len(head), digest=digest), (STATUS_ACCEPTED, 10)),
                    (stream_frame(OP_END, 11, size=9, digest=bytes([1]) * 32), (STATUS_INVALID, 11)),
                    (open_frame(13), (STATUS_ACCEPTED, 13)),
                    (stream_frame(OP_DATA, 13, b"x" * 60000), (STATUS_ACCEPTED, 13)),
                    (stream_frame(OP_DATA, 13, b"x" * 10000), (STATUS_TOO_LARGE, 13)),
                    (stream_frame(OP_DATA, 13, b"y"), (STATUS_INVALID, 13)),
                    (open_frame(14), (STATUS_ACCEPTED, 14)),
                    (stream_frame(OP_DATA, 14, b"open();"), (STATUS_ACCEPTED, 14)),
                ):
                    connection.sendall(frame)
                    assert read_ack(connection, 2) == expected, frame[:16]
        finally:
            child.send_signal(signal.SIGTERM)
            _, errors = child.communicate(timeout=10)
        assert child.returncode == 0, errors.decode()
        log = errors.decode()
        assert log.count("rejected; connection kept") == 4, log
        assert log.count("closed after an unsynchronized frame") == 3, log
        assert "accepted=5 " in log and "too_large=3 " in log and "invalid=4 " in log, log
        assert "streams_abandoned=1 " in log, log
        manifest = [
            json.loads(line)
            for line in (root / "artifacts/manifest.jsonl").read_text().splitlines()
        ]
        assert [item["artifact_id"] for item in manifest] == ["1", "3", "6", "12", "10"]
        assert manifest[3]["byte_size"] == 40000 and manifest[4]["byte_size"] == len(head)
        assert manifest[3]["sha256"] == hashlib.sha256(head[:40000]).hexdigest()
        assert manifest[4]["sha256"] == digest.hex()
        assert not list((root / "artifacts").glob("*.part")), "no stream outlives its connection"
    print(
        "PASS artifact receiver socket: a valid rejected frame is discarded and answered on the "
        "same connection; invalid, mismatched and undiscardable frames close it; interleaved "
        "version 2 streams publish a checkpoint and an end with exact digests, stream refusals "
        "keep the connection, and a stream open at disconnect is abandoned"
    )


def check_receiver_recovery(receiver: str) -> None:
    """Interrupted-append recovery in the production executable.

    Commit rollback is driven by injected fsync failures in tests/artifact_test.cpp;
    macOS does not apply RLIMIT_FSIZE to O_APPEND writes, so it cannot be used here.
    """
    with tempfile.TemporaryDirectory(prefix="reb-recover-") as temporary:
        store = Path(temporary) / "artifacts"
        manifest = store / "manifest.jsonl"
        subprocess.run(
            [receiver, "--store", str(store)],
            input=artifact_frame(1, b"one();"),
            capture_output=True,
            check=True,
            timeout=10,
        )
        before = manifest.read_bytes()
        # An interrupted append leaves a final record without its newline.
        torn = b'{"protocol_version":1,"artifact_id":"9'
        with manifest.open("ab") as stream:
            stream.write(torn)
        recovered = subprocess.run(
            [receiver, "--store", str(store)],
            input=b"",
            capture_output=True,
            check=True,
            timeout=10,
        )
        note = f"removed an unacknowledged final record of {len(torn)} bytes".encode()
        assert note in recovered.stderr, recovered.stderr.decode()
        assert manifest.read_bytes() == before, "only the torn record is removed"
        resumed = subprocess.run(
            [receiver, "--store", str(store)],
            input=artifact_frame(2, b"two();"),
            capture_output=True,
            check=True,
            timeout=10,
        )
        assert b"removed an unacknowledged" not in resumed.stderr
        assert len(manifest.read_bytes().splitlines()) == 2
        # A receiver killed with streams open leaves their partial files, and
        # no later clean exit would reach them.
        killed = subprocess.Popen(
            [receiver, "--store", str(store)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        partial = [store / "artifact-500.part", store / "artifact-501.part"]
        try:
            assert killed.stdin is not None
            killed.stdin.write(
                open_frame(500)
                + open_frame(501)
                + stream_frame(OP_DATA, 500, b"partial();")
            )
            killed.stdin.flush()
            deadline = time.monotonic() + 10
            while not all(path.exists() for path in partial):
                assert killed.poll() is None and time.monotonic() < deadline, "partial stream files"
                time.sleep(0.01)
        finally:
            killed.kill()
            killed.communicate(timeout=10)
        assert killed.returncode == -signal.SIGKILL
        assert all(path.exists() for path in partial), "SIGKILL leaves the partial files"
        restarted = subprocess.Popen(
            [receiver, "--store", str(store)], stdin=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, errors = restarted.communicate(artifact_frame(3, b"three();"), timeout=10)
        assert restarted.returncode == 0, errors.decode()
        assert b"removed 2 partial stream files" in errors, errors.decode()
        assert not list(store.glob("*.part")), "no partial stream file survives a restart"
        assert len(manifest.read_bytes().splitlines()) == 3, "capture resumes on the same store"
    print(
        "PASS artifact receiver recovery: an interrupted final record is cut back with a note, "
        "partial stream files from a killed receiver are removed and counted, and capture "
        "resumes on the same store"
    )


def records(path: Path) -> list[dict]:
    return (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


def check_stores(output: Path, cases: list[dict]) -> None:
    artifacts = records(output / "artifacts/manifest.jsonl")
    component = {
        item["artifact_id"]: item
        for item in records(output / "in-process-artifacts/manifest.jsonl")
    }
    events = records(output / "events.jsonl")
    assert artifacts and events, "Real production stores must be nonempty"
    for item in artifacts:
        assert item == component[item["artifact_id"]], (
            "Production receiver must retain the same metadata"
        )
        data = (output / "artifacts" / item["content_path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
        assert (
            data
            == (output / "in-process-artifacts" / item["content_path"]).read_bytes()
        )
    roots = {
        item["sequence_number"]: item
        for item in events
        if item["type"] == "request_started"
    }
    for case in cases:
        selection = case["selection"]
        root = roots[selection["root_event"]["sequence_number"]]
        assert root["request_id"] == selection["request_id"]
        assert int(root["sequence_number"]) > 2**53
        for artifact_id in case["expected_artifact_ids"]:
            item = next(
                item for item in artifacts if item["artifact_id"] == artifact_id
            )
            capture = next(
                item
                for item in events
                if item["type"] == "artifact_captured"
                and item["artifact_id"] == artifact_id
            )
            assert capture["parent_event_id"] == item["creator_event_id"] != "0"
    check_request_bodies(output, artifacts, events)
    check_response_bodies(output, artifacts, events)
    check_request_headers(output, artifacts, events)
    print(
        "PASS production receiver/broker consumed exact native bytes, preserved metadata/hash/uint64 identity"
    )


def check_response_bodies(output: Path, artifacts: list[dict], events: list[dict]) -> None:
    """Response bodies (native-network-v3.md) survive the production receiver and broker."""
    expected = json.loads((output / "response-bodies.json").read_text())
    by_sequence = {item["sequence_number"]: item for item in events}
    retained = 0
    for body in expected:
        record = by_sequence[body["record_sequence"]]
        assert record["type"] == "response_body" and record["category"] == "network"
        assert record["parent_event_id"] == body["response_sequence"]
        assert record["request_id"] == body["request_id"]
        assert record["artifact_id"] == body["artifact_id"]
        payload = bytes.fromhex(record["payload"])
        assert payload[4] == body["state"]
        assert int.from_bytes(payload[8:16], "little") == body["body_length"]
        assert int.from_bytes(payload[16:24], "little") == body["captured_length"]
        assert payload[32:64].hex() == body["sha256"]
        if body["artifact_id"] == "0":
            assert body["captured_length"] == 0 and body["sha256"] == "00" * 32
            continue
        retained += 1
        item = next(a for a in artifacts if a["artifact_id"] == body["artifact_id"])
        assert item["kind"] == "response_body" and item["capture_origin"] == "network_response"
        assert item["sensitive"] is True and item["execution_context_id"] == "0"
        assert item["creator_event_id"] == body["response_sequence"]
        assert item["url"] == body["url"] and item["mime_type"] == body["mime_type"]
        data = (output / "artifacts" / item["content_path"]).read_bytes()
        assert len(data) == body["captured_length"] == item["byte_size"]
        assert hashlib.sha256(data).hexdigest() == body["sha256"] == item["sha256"]
        captured = next(
            e
            for e in events
            if e["type"] == "artifact_captured" and e["artifact_id"] == body["artifact_id"]
        )
        assert captured["parent_event_id"] == body["response_sequence"]
    assert retained >= 7 and len(expected) > retained
    print(
        "PASS production receiver/broker retained response bodies, partial and refused records, exact creator joins"
    )


def check_request_headers(output: Path, artifacts: list[dict], events: list[dict]) -> None:
    """Content-mode header blocks (native-network-v3.md) survive the receiver and broker."""
    expected = json.loads((output / "request-headers.json").read_text())
    assert expected, "The corpus must contain header blocks"
    by_sequence = {item["sequence_number"]: item for item in events}
    for block in expected:
        item = next(a for a in artifacts if a["artifact_id"] == block["artifact_id"])
        assert item["kind"] == "request_headers" and item["capture_origin"] == "network_request"
        assert item["sensitive"] is True and item["execution_context_id"] == "0"
        assert item["url"] == block["url"] and item["mime_type"] == "text/plain"
        assert item["creator_event_id"] == block["header_sequence"]
        data = (output / "artifacts" / item["content_path"]).read_bytes()
        assert data == b"Content-Type: application/json;charset=UTF-8\r\n", data
        record = by_sequence[block["header_sequence"]]
        assert record["type"] == "request_headers" and record["category"] == "network"
        assert record["artifact_id"] == block["artifact_id"]
        assert record["parent_event_id"] == block["start_sequence"]
        payload = bytes.fromhex(record["payload"])
        assert payload[48:80].hex() == hashlib.sha256(data).hexdigest()
        assert int.from_bytes(payload[12:16], "little") == len(data)


def check_request_bodies(output: Path, artifacts: list[dict], events: list[dict]) -> None:
    """Content-mode request bodies survive the production receiver and broker."""
    expected = json.loads((output / "request-bodies.json").read_text())
    assert expected, "The corpus must contain request bodies"
    by_sequence = {item["sequence_number"]: item for item in events}
    for body in expected:
        item = next(a for a in artifacts if a["artifact_id"] == body["artifact_id"])
        assert item["kind"] == "request_body" and item["capture_origin"] == "network_request"
        assert item["sensitive"] is True and item["execution_context_id"] == "0"
        assert item["url"] == body["url"] and item["mime_type"] == body["mime_type"]
        assert item["creator_event_id"] == body["body_sequence"]
        data = (output / "artifacts" / item["content_path"]).read_bytes()
        assert len(data) == body["captured_length"] == item["byte_size"]
        truncated = body["captured_length"] < body["body_length"]
        assert body["state"] == (5 if truncated else 4)
        if not truncated:
            assert hashlib.sha256(data).hexdigest() == body["sha256"]
        record = by_sequence[body["body_sequence"]]
        assert record["type"] == "request_body" and record["category"] == "network"
        assert record["artifact_id"] == body["artifact_id"]
        assert record["parent_event_id"] == body["start_sequence"]
        payload = bytes.fromhex(record["payload"])
        # Past 4 MiB the record carries no digest; the artifact's is checked above.
        hashed = body["body_length"] <= 4 * 1024 * 1024
        assert payload[32:64].hex() == (body["sha256"] if hashed else "00" * 32)
        assert int.from_bytes(payload[8:16], "little") == body["body_length"]
        target = next(
            e
            for e in events
            if e["type"] == "request_target"
            and e["parent_event_id"] == body["start_sequence"]
        )
        prefix = bytes.fromhex(target["payload"])[12:].rstrip(b"\0").decode()
        assert body["url"].removeprefix("https://api.hcaptcha.test").startswith(prefix)
        captured = next(
            e
            for e in events
            if e["type"] == "artifact_captured" and e["artifact_id"] == body["artifact_id"]
        )
        assert captured["parent_event_id"] == body["body_sequence"]
    for target in json.loads((output / "request-targets.json").read_text()):
        item = next(a for a in artifacts if a["artifact_id"] == target["artifact_id"])
        assert item["kind"] == "request_target" and item["capture_origin"] == "network_request"
        assert item["sensitive"] is True and item["execution_context_id"] == "0"
        assert item["url"] == target["origin"] and item["mime_type"] == "text/plain"
        assert item["creator_event_id"] == target["target_sequence"]
        data = (output / "artifacts" / item["content_path"]).read_bytes()
        assert len(data) == target["target_length"] == item["byte_size"]
        assert hashlib.sha256(data).hexdigest() == target["sha256"] == item["sha256"]
        record = by_sequence[target["target_sequence"]]
        assert record["type"] == "request_target" and record["artifact_id"] == item["artifact_id"]
        assert record["parent_event_id"] == target["start_sequence"]
        payload = bytes.fromhex(record["payload"])
        assert payload[0:2] == b"\x02\x00" and payload[9] == 1
        assert int.from_bytes(payload[4:8], "little") == target["target_length"]
        assert data.startswith(payload[12:].rstrip(b"\0"))
        captured = next(
            e
            for e in events
            if e["type"] == "artifact_captured" and e["artifact_id"] == item["artifact_id"]
        )
        assert captured["parent_event_id"] == target["target_sequence"]
    # The independent Python mirror of the record rules accepts the broker output.
    run(
        "python3",
        str(ROOT / "tools/validate-evidence-store.py"),
        str(output / "events.jsonl"),
    )
    print(
        "PASS production receiver/broker retained sensitive request bodies, full targets and exact creator-record joins"
    )


def check_analysis(output: Path, cases: list[dict]) -> None:
    document = json.loads((output / "analysis.json").read_text())
    results = document["results"]
    assert results, "Authored source must produce actual VM candidates"
    for case in cases:
        selection = case["selection"]
        matches = {
            result["artifact_id"]
            for result in results
            for link in result.get("exact_request_links", [])
            if link["request_id"] == selection["request_id"]
            and link["root_event"] == selection["root_event"]
        }
        assert matches == set(case["expected_artifact_ids"]), (case["name"], matches)
    for result in results:
        assert result["tier"] != "proven", (
            "Source-only fixture must not invent executed guest VM proof"
        )
    print(
        "PASS real VM analyzer: exact selections, missing ACK/creator, generated/runtime and ambiguous identities"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver")
    parser.add_argument("--broker")
    parser.add_argument("--analyzer")
    parser.add_argument("--backend")
    parser.add_argument(
        "--output", type=Path, help="New corpus directory; refuses an existing path"
    )
    args = parser.parse_args()
    if bool(args.receiver) != bool(args.broker):
        parser.error("--receiver and --broker must be supplied together")
    if args.analyzer and not args.receiver:
        parser.error("--analyzer requires --receiver and --broker")
    if args.backend and not args.analyzer:
        parser.error("--backend requires --analyzer")
    for name in ("receiver", "broker", "analyzer", "backend"):
        if value := getattr(args, name):
            setattr(args, name, str(Path(value).resolve(strict=True)))
    with tempfile.TemporaryDirectory(prefix="reb-native-artifact-") as temporary:
        build = Path(temporary)
        driver = compile_driver(build)
        output = args.output.resolve() if args.output else build / "corpus"
        output.mkdir(parents=True, exist_ok=False)
        run(
            str(driver),
            str(output),
            str(ROOT / "tools/fixtures/vm-workspace-effects/stack.js"),
        )
        check_schedule_table(json.loads((output / "schedule-replay.json").read_text()))
        cases = json.loads((output / "cases.json").read_text())
        wire_hashes = {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("events.bin", "artifacts.bin", "acks.bin")
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
                unix_status = (
                    "available; the socket writers run in the separate transport stage"
                )
        except OSError as error:
            unix_status = f"unavailable: {error}"
        manifest = {
            "schema": "reb-native-artifact-linkage-test-v1",
            "session_dir": str(output),
            "cases": cases,
            "wire_sha256": wire_hashes,
            "native_socket_boundary": unix_status,
            "limits": [
                "Not a Brave/V8/Blink runtime",
                "Mojo body delivery and socket scheduling are adapters",
                "ACK status and artifact ID are from production ArtifactReceiver.ReceiveOne",
                "Authored source and initialized test bytes only; no guest execution proof",
            ],
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        if args.receiver:
            # The corpus carries content-mode request bodies, which the
            # receiver retains only when started for sensitive capture.
            with (output / "artifacts.bin").open("rb") as stream:
                run(
                    args.receiver,
                    "--store",
                    str(output / "artifacts"),
                    "--allow-sensitive",
                    stdin=stream,
                )
            with (output / "events.bin").open("rb") as stream:
                run(
                    args.broker,
                    "--store",
                    str(output / "events.jsonl"),
                    "--trace-store",
                    str(output / "origin-trace.jsonl"),
                    "--signal-store",
                    str(output / "request-signals.jsonl"),
                    stdin=stream,
                )
            check_stores(output, cases)
            check_receiver_socket(args.receiver)
            check_receiver_recovery(args.receiver)
            check_transport(args.receiver)
        else:
            print(
                "SKIPPED production service stdio replay, receiver socket/recovery and socket "
                "writer transport: --receiver/--broker not supplied"
            )
        if args.analyzer:
            run(
                args.analyzer,
                "--artifacts",
                str(output / "artifacts"),
                "--events",
                str(output / "events.jsonl"),
                "--output",
                str(output / "analysis.json"),
            )
            check_analysis(output, cases)
        else:
            print("SKIPPED analyzer: --analyzer not supplied")
        if args.backend:
            environment = dict(
                os.environ,
                REB_VM_LINKAGE_PIPELINE=str(output / "manifest.json"),
                REB_VM_LINKAGE_BACKEND=args.backend,
            )
            run(
                "node",
                str(ROOT / "tools/check-vm-request-linkage-ui.mjs"),
                "--pipeline",
                env=environment,
            )
        else:
            print("SKIPPED HTTP/controller pipeline: --backend not supplied")
        assert all(
            hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
            for name, digest in wire_hashes.items()
        ), "No pipeline stage may rewrite native evidence"
        print(f"Native AF_UNIX boundary: {unix_status}")
        if args.output:
            print(f"Corpus retained at {output}")


if __name__ == "__main__":
    main()
