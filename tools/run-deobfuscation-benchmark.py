#!/usr/bin/env python3
"""Compare bounded typed observations of repository-owned regression fixtures only."""

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
FIXTURE_ROOT = ROOT / "tools/fixtures/deobfuscation-benchmark"
DEFAULT_MANIFEST = FIXTURE_ROOT / "corpus-v2.json"
DEFAULT_WORKER = ROOT / "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker"
WORKER_TIMEOUT_SECONDS = 5
NODE_TIMEOUT_SECONDS = 3

# Appended at script scope, rather than wrapping the fixture in a function or
# try block which would change directives, lexical scope and top-level `this`.
# This is a trusted-test observation format, not an untrusted-code sandbox or
# a generic serializer. Accessors, symbols, cycles and exotic objects fail closed.
OBSERVE = r"""
;(() => {
  const {isProxy} = require('node:util').types;
  const seen = new Set();
  let nodes = 0;
  const encode = (value, depth = 0) => {
    if (++nodes > 10000 || depth > 64) throw Error('observation budget exceeded');
    if (value === null) return ['null'];
    switch (typeof value) {
      case 'undefined': return ['undefined'];
      case 'boolean': return ['boolean', value];
      case 'string':
        if (value.length > 65536) throw Error('observation string budget exceeded');
        return ['string', value];
      case 'number': {
        if (Number.isNaN(value)) return ['number', 'NaN'];
        if (value === Infinity) return ['number', '+Infinity'];
        if (value === -Infinity) return ['number', '-Infinity'];
        const bytes = Buffer.alloc(8);
        bytes.writeDoubleBE(value);
        return ['number', bytes.toString('hex')];
      }
      case 'object': break;
      default: throw Error('unsupported observation type');
    }
    if (isProxy(value)) throw Error('proxy observation');
    if (seen.has(value)) throw Error('cyclic or shared observation object');
    seen.add(value);
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== (array ? Array.prototype : Object.prototype) && prototype !== null) {
      throw Error('unsupported observation prototype');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length > 10000) throw Error('observation property budget exceeded');
    const entries = [];
    for (const key of keys) {
      if (typeof key !== 'string') throw Error('symbol observation key');
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value')) throw Error('accessor observation');
      if (array && key === 'length') continue;
      entries.push([key, encode(descriptor.value, depth + 1)]);
    }
    // Array length plus present own keys preserves holes and extra properties.
    return array ? ['array', value.length, entries]
      : ['object', prototype === null ? 'null' : 'plain', entries];
  };
  const kind = typeof completion === 'undefined' ? 'normal' : completion;
  if (kind !== 'normal' && kind !== 'throw') throw Error('unsupported completion kind');
  const observation = ['observation', kind, encode(result),
    encode(typeof effects === 'undefined' ? [] : effects)];
  const text = JSON.stringify(observation);
  if (text.length > 1048576) throw Error('observation output budget exceeded');
  process.stdout.write(text);
})();
"""


class BenchmarkFailure(RuntimeError):
    """A corpus case failed a required benchmark invariant."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--worker", type=Path, default=DEFAULT_WORKER)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--oracle-self-test", action="store_true")
    return parser.parse_args()


def read_manifest(path: Path) -> list[dict[str, object]]:
    if not path.resolve().is_relative_to(FIXTURE_ROOT.resolve()):
        raise BenchmarkFailure("only reviewed repository fixture manifests may be executed")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 2 or not isinstance(document.get("cases"), list):
        raise BenchmarkFailure("benchmark manifest must use schema_version 2 and contain cases")
    cases = document["cases"]
    identifiers = [case.get("id") for case in cases if isinstance(case, dict)]
    if (
        len(identifiers) != len(cases)
        or not all(isinstance(identifier, str) and identifier for identifier in identifiers)
        or len(set(identifiers)) != len(cases)
    ):
        raise BenchmarkFailure("benchmark case identifiers must be unique strings")
    for case in cases:
        if case.get("mode") != "trusted-differential" or "expected_observation" not in case:
            raise BenchmarkFailure("each case must be a trusted differential fixture with typed expectations")
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
    probe = source + "\n" + OBSERVE
    completed = subprocess.run(
        [node, "--max-old-space-size=64", "-e", probe],
        text=True,
        capture_output=True,
        timeout=NODE_TIMEOUT_SECONDS,
        check=True,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )
    return json.loads(completed.stdout)


def canonical_observation(value: object) -> str:
    # ASCII JSON compares JavaScript UTF-16 strings, including lone surrogates,
    # without Python's True == 1 or signed-zero equality coercions.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def oracle_self_test(node: str) -> int:
    controls = [
        ("undefined/null", "const result=[void 0];", "const result=[null];"),
        ("negative zero", "const result=-0;", "const result=0;"),
        ("NaN/null", "const result=NaN;", "const result=null;"),
        ("infinities", "const result=Infinity;", "const result=-Infinity;"),
        ("hole/undefined", "const result=[,];", "const result=[void 0];"),
        ("boolean/number", "const result=true;", "const result=1;"),
        ("missing property", "const result={};", "const result={x:void 0};"),
        ("effect order", "const result=0; const effects=['a','b'];", "const result=0; const effects=['b','a'];"),
        ("missing effect", "const result=0; const effects=['a'];", "const result=0; const effects=[];"),
        ("completion", "const result='TypeError';", "const result='TypeError'; const completion='throw';"),
    ]
    for label, original, wrong in controls:
        if canonical_observation(node_result(node, original)) == canonical_observation(node_result(node, wrong)):
            raise BenchmarkFailure(f"oracle accepted wrong-output control: {label}")
    for source in [
        "const result={get x(){process.stdout.write('getter-called');return 1;}};",
        "const result=()=>0;",
        "const result=new Proxy({}, {});",
        "const result=new Proxy({}, {getPrototypeOf(){process.stdout.write('proxy-trap');return Object.prototype;},ownKeys(){process.stdout.write('proxy-trap');return [];}});",
    ]:
        try:
            node_result(node, source)
        except subprocess.CalledProcessError as error:
            if "getter-called" in error.stdout or "proxy-trap" in error.stdout:
                raise BenchmarkFailure("oracle invoked an accessor or proxy trap") from error
        else:
            raise BenchmarkFailure("oracle accepted an unsupported observation")
    return len(controls)


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
    expected_result = case["expected_observation"]
    if canonical_observation(original_result) != canonical_observation(expected_result):
        raise BenchmarkFailure(
            f"{identifier}: original result {original_result!r} != {expected_result!r}"
        )
    if canonical_observation(derived_result) != canonical_observation(original_result):
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
        "changed_source_percent": round((changed_bytes / source_bytes) * 100, 2),
        "transformations": len(transformations),
        "typed_observation": original_result,
    }


def main() -> int:
    args = parse_args()
    node = shutil.which("node")
    if node is None:
        raise BenchmarkFailure("Node.js is required for semantic comparison")
    controls = oracle_self_test(node)
    if args.oracle_self_test:
        print(f"Typed observation oracle: {controls} wrong-output controls rejected")
        return 0
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
        "schema_version": 2,
        "oracle_wrong_output_controls": controls,
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
                f"{result['changed_source_percent']:.2f}% changed source bytes"
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
