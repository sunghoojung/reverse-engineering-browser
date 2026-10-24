#!/usr/bin/env python3
"""Actual native sink -> production receiver ACK -> broker/analyzer/controller checks.

Only Chromium platform, Mojo completion delivery and socket scheduling are adapters.
All corpus bytes come from the compiled production sinks; no evidence is repaired.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "browser/integration/brave/overlay"
HEADERS = (
    "base/containers/span.h",
    "base/no_destructor.h",
    "base/files/file_path.h",
    "base/functional/bind.h",
    "base/process/process_handle.h",
    "base/threading/platform_thread.h",
    "base/time/time.h",
    "content/public/browser/browser_context.h",
    "net/http/http_response_headers.h",
    "net/url_request/redirect_info.h",
    "services/network/public/cpp/resource_request.h",
    "services/network/public/cpp/url_loader_completion_status.h",
    "services/network/public/mojom/url_response_head.mojom.h",
    "mojo/public/cpp/base/big_buffer.h",
    "mojo/public/cpp/system/data_pipe.h",
    "url/gurl.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_socket_client.h",
    "brave/components/reverse_engineering_browser/browser/native_artifact_body_tee.h",
    "brave/components/reverse_engineering_browser/browser/native_probe_session.h",
)


def run(*command: str, **kwargs) -> None:
    subprocess.run(command, check=True, **kwargs)


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
    run(
        os.environ.get("CXX", "c++"),
        *flags,
        f"-I{fixture}",
        f"-I{stubs}",
        f"-I{include}",
        f"-I{ROOT / 'include'}",
        str(fixture / "main.cc"),
        str(sources / "browser/native_network_capture_sink.cc"),
        str(sources / "browser/native_artifact_capture_sink.cc"),
        str(ROOT / "src/evidence/artifact.cpp"),
        "-o",
        str(binary),
    )
    return binary


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
    print(
        "PASS production receiver/broker consumed exact native bytes, preserved metadata/hash/uint64 identity"
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
        cases = json.loads((output / "cases.json").read_text())
        wire_hashes = {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("events.bin", "artifacts.bin", "acks.bin")
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
                unix_status = (
                    "available, but native socket writer is outside this component test"
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
            with (output / "artifacts.bin").open("rb") as stream:
                run(args.receiver, "--store", str(output / "artifacts"), stdin=stream)
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
        else:
            print(
                "SKIPPED production service stdio replay: --receiver/--broker not supplied"
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
