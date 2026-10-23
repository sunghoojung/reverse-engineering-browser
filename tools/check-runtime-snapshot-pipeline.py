#!/usr/bin/env python3
"""Real capture sinks -> native wire -> receiver/broker -> VM analysis.

Chromium types, Mojo delivery and the artifact socket enqueue boundary are narrow
adapters, not a patched browser. Inputs are authored source and initialized bytes.
The real sinks assign artifact metadata and parent IDs; the real receiver and
analyzer produce the manifest and reports. No persisted output is repaired.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "browser/integration/brave/overlay"
SNAPSHOT_COUNTS = {
    "accepted": 2,
    "full-ring": 1,
    "reconfigured": 16,
    "after-emitter": 17,
    "scope": 4,
}
CASES = (
    *SNAPSHOT_COUNTS,
    "disabled",
    "expired",
    "stale",
    "browser-stale",
    "parent-rejected",
    "missing-source",
)
HEADERS = (
    "base/component_export.h",
    "base/compiler_specific.h",
    "base/no_destructor.h",
    "base/process/process_handle.h",
    "base/threading/platform_thread.h",
    "base/time/time.h",
    "base/functional/bind.h",
    "url/gurl.h",
    "mojo/public/cpp/base/big_buffer.h",
    "mojo/public/cpp/system/data_pipe.h",
    "services/network/public/cpp/resource_request.h",
    "services/network/public/mojom/url_response_head.mojom.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h",
    "brave/components/reverse_engineering_browser/browser/native_probe_session.h",
)


def run(*command: str, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, check=False, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} failed ({result.returncode}): "
            + result.stderr.decode(errors="replace")
        )
    return result


def compile_driver(build: Path) -> Path:
    include = build / "include"
    include.mkdir()
    (include / "brave").symlink_to(OVERLAY, target_is_directory=True)
    stubs = build / "stubs"
    for header in HEADERS:
        path = stubs / header
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "chromium_stubs.h"\n', encoding="utf-8")
    fixture = ROOT / "tools/runtime-snapshot-pipeline"
    sources = OVERLAY / "components/reverse_engineering_browser"
    binary = build / "runtime-snapshot-pipeline"
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
    result = subprocess.run(
        [
            os.environ.get("CXX", "c++"),
            *flags,
            f"-I{fixture}",
            f"-I{stubs}",
            f"-I{include}",
            str(fixture / "main.cc"),
            str(sources / "renderer/native_probe_sink.cc"),
            str(sources / "browser/native_artifact_capture_sink.cc"),
            str(sources / "common/native_probe_queue.cc"),
            "-o",
            str(binary),
        ],
        check=False,
    )
    result.check_returncode()
    return binary


def check_backend(
    backend: str, output: Path, records: list[dict], report: dict
) -> None:
    endpoint = output / "endpoint.txt"
    command = [
        backend,
        "--port",
        "0",
        "--endpoint-file",
        str(endpoint),
        "--store",
        str(output / "events.jsonl"),
        "--artifacts",
        str(output / "artifacts"),
        "--trace-store",
        str(output / "trace.jsonl"),
        "--signal-store",
        str(output / "signals.jsonl"),
        "--api-collection",
        str(output / "collection.json"),
        "--local-analyst",
        str(output / "analyst.json"),
        "--ui-directory",
        str(ROOT / "apps/research-ui"),
    ]
    with (output / "backend.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while not endpoint.exists():
                if process.poll() is not None:
                    raise RuntimeError(
                        "Backend exited: " + (output / "backend.log").read_text()
                    )
                if time.monotonic() >= deadline:
                    raise TimeoutError("Backend did not publish its loopback endpoint")
                time.sleep(0.05)
            url = endpoint.read_text().strip()
            assert url.startswith("http://127.0.0.1:")

            def get(path: str) -> bytes:
                with urllib.request.urlopen(url + path, timeout=10) as response:
                    return response.read()

            retained = json.loads(get("/api/artifacts"))["artifacts"]
            assert {item["artifact_id"] for item in retained} == {
                item["artifact_id"] for item in records
            }
            for item in records:
                content = get(f"/api/artifacts/{item['artifact_id']}/content")
                assert hashlib.sha256(content).hexdigest() == item["sha256"]
            opcodes = json.loads(get("/api/analysis/vm/opcodes"))
            assert opcodes == report
            analysis = json.loads(get("/api/analysis/vm"))
            assert analysis["results"] and opcodes["summary"]["snapshot_count"] > 0
            assert opcodes["summary"]["sample_count"] == 0
            assert b"Origin Trace" in get("/")
            print(
                "PASS real backend HTTP exposes exact persisted source, snapshot bytes and VM workspace"
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", required=True)
    parser.add_argument("--broker", required=True)
    parser.add_argument("--analyzer")
    parser.add_argument("--backend")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.backend and not args.analyzer:
        parser.error("--backend requires --analyzer")
    source = ROOT / "tests/fixtures/runtime-buffer-vm.js"
    with tempfile.TemporaryDirectory(prefix="reb-snapshot-pipeline-") as temporary:
        build = Path(temporary)
        driver = compile_driver(build)
        root = args.output.resolve() if args.output else build / "evidence"
        root.mkdir(parents=True, exist_ok=False)
        for case in CASES:
            output = root / case
            run(str(driver), str(output), str(source), case)
            artifacts = output / "artifacts"
            run(
                args.receiver,
                "--store",
                str(artifacts),
                input=(output / "artifacts.bin").read_bytes(),
            )
            events_path = output / "events.jsonl"
            run(
                args.broker,
                "--store",
                str(events_path),
                input=(output / "events.bin").read_bytes(),
            )
            manifest = artifacts / "manifest.jsonl"
            records = (
                [json.loads(line) for line in manifest.read_text().splitlines()]
                if manifest.exists()
                else []
            )
            events = [json.loads(line) for line in events_path.read_text().splitlines()]
            parents = [
                item
                for item in records
                if item["capture_origin"] == "runtime_allocating_script"
            ]
            snapshots = [
                item
                for item in records
                if item["capture_origin"] == "runtime_typed_array"
            ]
            if case in SNAPSHOT_COUNTS:
                assert len(snapshots) == SNAPSHOT_COUNTS[case]
                assert len(parents) == {"scope": 4, "after-emitter": 2}.get(case, 1)
                for parent in parents:
                    content = (artifacts / parent["content_path"]).read_bytes()
                    assert content == source.read_bytes()
                    assert parent["sha256"] == hashlib.sha256(content).hexdigest()
                for snapshot in snapshots:
                    parent = next(
                        item
                        for item in parents
                        if item["artifact_id"] == snapshot["parent_artifact_id"]
                    )
                    assert snapshot["creator_event_id"] != "0"
                    for key in ("session_id", "frame_id", "execution_context_id"):
                        assert parent[key] == snapshot[key]
                    assert snapshot["url"] == "script://9"
                    content = (artifacts / snapshot["content_path"]).read_bytes()
                    assert (
                        len(content) == 32
                        and content[0] == 1
                        and content[2:5] == bytes([2, 3, 0])
                    )
                if case != "scope":
                    for snapshot in snapshots:
                        assert any(
                            event["sequence_number"] == snapshot["creator_event_id"]
                            and event["session_id"] == snapshot["session_id"]
                            and event["frame_id"] == snapshot["frame_id"]
                            for event in events
                        )
                if args.analyzer:
                    run(
                        args.analyzer,
                        "--artifacts",
                        str(artifacts),
                        "--events",
                        str(events_path),
                    )
                    report = json.loads(
                        (artifacts / "analysis/vm-opcode-workspace-v2.json").read_text()
                    )
                    workspaces = report["workspaces"]
                    assert workspaces, (
                        "Real retained allocator source must yield a VM workspace"
                    )
                    # Snapshots are bytes only, not invented guest dispatch/PC evidence.
                    assert all(not item["samples"] for item in workspaces)
                    assert any(item["snapshots"] for item in workspaces)
                    run(
                        "node",
                        str(ROOT / "tools/check-runtime-snapshot-model.mjs"),
                        str(artifacts / "analysis"),
                    )
                    if args.backend and case == "accepted":
                        check_backend(args.backend, output, records, report)
                    if case not in ("scope", "after-emitter"):
                        assert len(workspaces[0]["snapshots"]) == len(snapshots)
                        assert (
                            workspaces[0]["snapshots"][0]["preview_hex"]
                            == bytes([1, 7, 2, 3, 0] + [0] * 27).hex()
                        )
            else:
                assert not records, case
            print(f"PASS real sink/wire/receiver/broker pipeline: {case}")
        print(
            "V8/Blink allocation hooks, Mojo IPC and browser artifact socket runtime are not exercised."
        )
        if not args.analyzer:
            print("VM analyzer stage unavailable: no --analyzer was supplied.")


if __name__ == "__main__":
    main()
