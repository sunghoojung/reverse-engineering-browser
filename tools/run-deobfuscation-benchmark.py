#!/usr/bin/env python3
"""Run the bounded deobfuscator against a semantic regression corpus."""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests/fixtures/deobfuscation-benchmark/corpus-v1.json"
DEFAULT_WORKER = ROOT / "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker"
WORKER_TIMEOUT_SECONDS = 5
NODE_TIMEOUT_SECONDS = 3


class BenchmarkFailure(RuntimeError):
    """A corpus case failed a required benchmark invariant."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--worker", type=Path, default=DEFAULT_WORKER)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser.parse_args()


def read_manifest(path: Path) -> list[dict[str, object]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or not isinstance(document.get("cases"), list):
        raise BenchmarkFailure("benchmark manifest must use schema_version 1 and contain cases")
    cases = document["cases"]
    identifiers = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(identifiers) != len(cases) or len(set(identifiers)) != len(cases):
        raise BenchmarkFailure("benchmark case identifiers must be unique strings")
    return cases


def run_worker(worker: Path, case: dict[str, object]) -> tuple[dict[str, object], float]:
    request = {
        "source": case["source"],
        "assume_intrinsics": bool(case.get("assume_intrinsics", False)),
    }
    started = time.monotonic()
    completed = subprocess.run(
        [str(worker)],
        input=json.dumps(request, separators=(",", ":")) + "\n",
        text=True,
        capture_output=True,
        timeout=WORKER_TIMEOUT_SECONDS,
        check=True,
    )
    elapsed_ms = (time.monotonic() - started) * 1000
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise BenchmarkFailure(f"worker emitted {len(lines)} response lines")
    response = json.loads(lines[0])
    if not response.get("ok"):
        raise BenchmarkFailure(f"worker rejected source: {response.get('syntax_errors')}")
    if response.get("transformations_truncated"):
        raise BenchmarkFailure("worker exhausted its transformation budget")
    return response, elapsed_ms


def node_result(node: str, source: str) -> object:
    probe = source + "\nprocess.stdout.write(JSON.stringify(result));\n"
    completed = subprocess.run(
        [node, "-e", probe],
        text=True,
        capture_output=True,
        timeout=NODE_TIMEOUT_SECONDS,
        check=True,
    )
    return json.loads(completed.stdout)


def covered_source_bytes(transformations: list[dict[str, object]]) -> int:
    ranges = sorted(
        (int(item["original_start"]), int(item["original_end"]))
        for item in transformations
    )
    covered = 0
    cursor = 0
    for start, end in ranges:
        if end <= cursor:
            continue
        covered += end - max(start, cursor)
        cursor = end
    return covered


def run_case(worker: Path, node: str, case: dict[str, object]) -> dict[str, object]:
    identifier = case["id"]
    source = case["source"]
    if not isinstance(identifier, str) or not isinstance(source, str):
        raise BenchmarkFailure("case id and source must be strings")
    response, elapsed_ms = run_worker(worker, case)
    transformations = response.get("transformations")
    derived = response.get("derived_source")
    if not isinstance(transformations, list) or not isinstance(derived, str):
        raise BenchmarkFailure(f"{identifier}: worker response is missing derived output")
    observed_kinds = {item.get("kind") for item in transformations}
    required_kinds = set(case.get("required_transformations", []))
    missing = sorted(required_kinds - observed_kinds)
    if missing:
        raise BenchmarkFailure(f"{identifier}: missing transformations {missing}")

    original_result = node_result(node, source)
    derived_result = node_result(node, derived)
    expected_result = case.get("expected_result")
    if original_result != expected_result:
        raise BenchmarkFailure(
            f"{identifier}: original result {original_result!r} != {expected_result!r}"
        )
    if derived_result != original_result:
        raise BenchmarkFailure(
            f"{identifier}: derived result {derived_result!r} != {original_result!r}"
        )

    source_bytes = len(source.encode("utf-8"))
    changed_bytes = covered_source_bytes(transformations)
    return {
        "id": identifier,
        "passed": True,
        "elapsed_ms": round(elapsed_ms, 2),
        "source_bytes": source_bytes,
        "changed_bytes": changed_bytes,
        "mapping_coverage_percent": round((changed_bytes / source_bytes) * 100, 2),
        "transformations": len(transformations),
        "semantic_result": original_result,
    }


def main() -> int:
    args = parse_args()
    node = shutil.which("node")
    if node is None:
        raise BenchmarkFailure("Node.js is required for semantic comparison")
    worker = args.worker.resolve()
    if not worker.is_file() or not os.access(worker, os.X_OK):
        raise BenchmarkFailure(f"deobfuscation worker is not executable: {worker}")

    cases = read_manifest(args.manifest.resolve())
    results = [run_case(worker, node, case) for case in cases]
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    max_rss_kib = (
        int(child_usage.ru_maxrss / 1024)
        if sys.platform == "darwin"
        else int(child_usage.ru_maxrss)
    )
    report = {
        "schema_version": 1,
        "passed": len(results),
        "total": len(cases),
        "observed_child_max_rss_kib": max_rss_kib,
        "cases": results,
    }
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in results:
            print(
                f"PASS {result['id']}: {result['elapsed_ms']:.2f} ms, "
                f"{result['transformations']} rewrites, "
                f"{result['mapping_coverage_percent']:.2f}% source coverage"
            )
        print(
            f"Deobfuscation benchmark: {len(results)}/{len(cases)} passed; "
            f"child max RSS {max_rss_kib} KiB"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BenchmarkFailure, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"deobfuscation benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
