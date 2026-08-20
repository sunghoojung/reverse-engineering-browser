import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from vm_analyzer import (
    AnalysisError,
    Limits,
    _find_js_rule,
    analyze_store,
    canonical_json,
    verify_analysis_document,
    write_analysis,
)

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures" / "vm-analysis"


def wasm_vm_fixture() -> bytes:
    type_payload = bytes([1, 0x60, 0, 0])
    function_payload = bytes([1, 0])
    table_payload = bytes([1, 0x70, 0, 4])
    memory_payload = bytes([1, 0, 1])
    body = bytes(
        [
            1,
            1,
            0x7F,
            0x03,
            0x40,
            0x20,
            0,
            0x41,
            1,
            0x6A,
            0x21,
            0,
            0x20,
            0,
            0x28,
            2,
            0,
            0x11,
            0,
            0,
            0x20,
            0,
            0x0E,
            1,
            0,
            0,
            0x0B,
            0x0F,
            0x0B,
        ]
    )
    code_payload = bytes([1, len(body)]) + body
    data_payload = bytes([1, 0, 0x41, 0, 0x0B, 5, 1, 7, 2, 3, 0])
    return (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1, len(type_payload)])
        + type_payload
        + bytes([3, len(function_payload)])
        + function_payload
        + bytes([4, len(table_payload)])
        + table_payload
        + bytes([5, len(memory_payload)])
        + memory_payload
        + bytes([10, len(code_payload)])
        + code_payload
        + bytes([11, len(data_payload)])
        + data_payload
    )


def ordinary_wasm_fixture() -> bytes:
    type_payload = bytes([1, 0x60, 2, 0x7F, 0x7F, 1, 0x7F])
    function_payload = bytes([1, 0])
    body = bytes([0, 0x20, 0, 0x20, 1, 0x6A, 0x0B])
    code_payload = bytes([1, len(body)]) + body
    return (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1, len(type_payload)])
        + type_payload
        + bytes([3, len(function_payload)])
        + function_payload
        + bytes([10, len(code_payload)])
        + code_payload
    )


def immediate_bytes_wasm_fixture() -> bytes:
    type_payload = bytes([1, 0x60, 0, 0])
    function_payload = bytes([1, 0])
    body = bytes(
        [
            0,
            0x41,
            0x03,
            0x1A,
            0x41,
            0x0E,
            0x1A,
            0x41,
            0x11,
            0x1A,
            0x41,
            0x28,
            0x1A,
            0x0B,
        ]
    )
    code_payload = bytes([1, len(body)]) + body
    return (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1, len(type_payload)])
        + type_payload
        + bytes([3, len(function_payload)])
        + function_payload
        + bytes([12, 1, 0])
        + bytes([10, len(code_payload)])
        + code_payload
    )


class VmAnalyzerTests(unittest.TestCase):
    def make_store(
        self, root: Path, entries: list[tuple[str, str, bytes, str]]
    ) -> Path:
        store = root / "artifacts"
        (store / "blobs").mkdir(parents=True)
        manifest = []
        for index, (kind, name, content, parent_id) in enumerate(entries, start=1):
            digest = hashlib.sha256(content).hexdigest()
            artifact_id = str(index)
            (store / "blobs" / f"{digest}.bin").write_bytes(content)
            manifest.append(
                {
                    "protocol_version": 1,
                    "artifact_id": artifact_id,
                    "session_id": "7",
                    "navigation_id": "100",
                    "frame_id": "200",
                    "parent_artifact_id": parent_id,
                    "creator_event_id": str(70 + index),
                    "kind": kind,
                    "url": f"https://authorized.test/{name}",
                    "mime_type": "application/wasm"
                    if kind == "wasm"
                    else "text/javascript",
                    "byte_size": len(content),
                    "sha256": digest,
                    "sensitive": False,
                    "content_path": f"blobs/{digest}.bin",
                }
            )
        (store / "manifest.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in manifest), encoding="utf-8"
        )
        return store

    def test_positive_and_negative_corpus_has_stable_two_tier_scores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    (
                        "javascript",
                        "pure-js-vm.js",
                        (FIXTURES / "pure-js-vm.js").read_bytes(),
                        "0",
                    ),
                    ("wasm", "ordinary-wasm.wasm", ordinary_wasm_fixture(), "0"),
                    (
                        "javascript",
                        "deeply-nested-non-vm.js",
                        (FIXTURES / "deeply-nested-non-vm.js").read_bytes(),
                        "0",
                    ),
                    ("wasm", "pure-wasm-vm.wasm", wasm_vm_fixture(), "0"),
                    (
                        "javascript",
                        "obfuscated-non-vm.js",
                        (FIXTURES / "obfuscated-non-vm.js").read_bytes(),
                        "0",
                    ),
                    (
                        "javascript",
                        "fingerprinting-non-vm.js",
                        (FIXTURES / "fingerprinting-non-vm.js").read_bytes(),
                        "0",
                    ),
                    (
                        "javascript",
                        "disjoint-js-signals.js",
                        (FIXTURES / "disjoint-js-signals.js").read_bytes(),
                        "0",
                    ),
                    (
                        "wasm",
                        "immediate-bytes.wasm",
                        immediate_bytes_wasm_fixture(),
                        "0",
                    ),
                ],
            )
            first = analyze_store(store)
            second = analyze_store(store)

            self.assertEqual(canonical_json(first), canonical_json(second))
            results = {result["artifact_id"]: result for result in first["results"]}
            self.assertEqual(results["1"]["tier"], "likely-vm")
            self.assertNotEqual(results["2"]["tier"], "likely-vm")
            self.assertEqual(results["3"]["tier"], "none")
            self.assertEqual(results["4"]["tier"], "likely-vm")
            self.assertNotEqual(results["5"]["tier"], "likely-vm")
            self.assertEqual(results["6"]["tier"], "none")
            self.assertGreater(results["6"]["anti_bot_score"], 0)
            self.assertNotEqual(results["7"]["tier"], "likely-vm")
            self.assertLess(len(results["7"]["evidence_families"]), 3)
            self.assertEqual(results["8"]["tier"], "none")
            self.assertFalse(
                {"wasm-dispatch-loop", "wasm-memory-traffic", "wasm-byte-data"}
                & {item["rule_id"] for item in results["8"]["observations"]}
            )
            self.assertEqual(
                results["1"]["bytecode_snapshot"]["snapshot_hex"], "0107020300"
            )
            self.assertEqual(first["summary"]["likely_vm_count"], 2)

    def test_top_level_vm_is_not_hidden_by_an_unrelated_function(self) -> None:
        source = b"""function helper() { return 1; }
const program = new Uint8Array([1, 2, 3]);
let ip = 0;
const stack = [];
while (ip < program.length) {
  const opcode = program[ip++];
  switch (opcode) {
    case 1: stack.push(1); break;
    default: throw new Error('unknown opcode');
  }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                Path(directory), [("javascript", "top-level-vm.js", source, "0")]
            )

            result = analyze_store(store)["results"][0]

            self.assertEqual(result["tier"], "likely-vm")
            self.assertEqual(
                result["observations"][0]["function_region"]["byte_offset"], 0
            )

    def test_javascript_match_and_region_work_are_strictly_bounded(self) -> None:
        class CountingPattern:
            def __init__(self) -> None:
                self.match_count = 0

            def finditer(self, source: str):
                for match in re.finditer(r"pc\+\+", source):
                    self.match_count += 1
                    yield match

        pattern = CountingPattern()
        observation = _find_js_rule(
            "pc++;" * 1000,
            "js.instruction-pointer",
            (pattern,),
            "bounded test",
            Limits(max_js_matches_per_rule=3),
        )
        self.assertIsNotNone(observation)
        self.assertEqual(pattern.match_count, 4)
        self.assertEqual(observation["match_count"], 3)
        self.assertTrue(observation["matches_truncated"])

        nested_source = (
            "".join(f"function f{index}(){{" for index in range(128))
            + "return 1;"
            + "}" * 128
        ).encode()
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                Path(directory),
                [("javascript", "nested-functions.js", nested_source, "0")],
            )
            result = analyze_store(
                store,
                limits=Limits(
                    max_js_function_regions=32,
                    max_js_region_work_bytes=512,
                ),
            )["results"][0]

        self.assertEqual(result["status"], "partial")
        reasons = {item["reason"] for item in result["coverage"]["omissions"]}
        self.assertIn("javascript-function-region-limit", reasons)
        self.assertIn("javascript-region-work-limit", reasons)

    def test_javascript_coordinates_are_utf8_byte_offsets(self) -> None:
        source = "const marker = 'π';\n" + (FIXTURES / "pure-js-vm.js").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                Path(directory),
                [("javascript", "unicode-prefix-vm.js", source.encode(), "0")],
            )

            result = analyze_store(store)["results"][0]
            dispatch = next(
                item
                for item in result["observations"]
                if item["rule_id"] == "js.dispatch-loop"
            )

            character_offset = source.index("while")
            self.assertEqual(
                dispatch["coordinate"]["byte_offset"],
                len(source[:character_offset].encode("utf-8")),
            )

    def test_wasm_function_coordinates_include_imported_functions(self) -> None:
        wasm = wasm_vm_fixture()
        import_payload = bytes([1, 1, ord("m"), 1, ord("f"), 0, 0])
        type_end = 8 + 2 + wasm[9]
        wasm = (
            wasm[:type_end]
            + bytes([2, len(import_payload)])
            + import_payload
            + wasm[type_end:]
        )
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                Path(directory), [("wasm", "imported-function-vm.wasm", wasm, "0")]
            )

            result = analyze_store(store)["results"][0]
            dispatch = next(
                item
                for item in result["observations"]
                if item["rule_id"] == "wasm.dispatch-loop"
            )

            self.assertEqual(dispatch["coordinate"]["function_index"], 1)
            self.assertEqual(result["frontend"]["imported_function_count"], 1)

    def test_mixed_runtime_requires_creator_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    (
                        "javascript",
                        "mixed-host.js",
                        (FIXTURES / "mixed-host.js").read_bytes(),
                        "0",
                    ),
                    ("wasm", "mixed-guest.wasm", wasm_vm_fixture(), "1"),
                ],
            )
            document = analyze_store(store)

            self.assertEqual(document["summary"]["mixed_count"], 1)
            self.assertEqual(document["mixed_findings"][0]["runtime"], "mixed")
            self.assertEqual(
                document["mixed_findings"][0]["boundary"]["state"], "observed"
            )

    def test_request_first_graph_labels_correlation_without_claiming_causality(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    (
                        "javascript",
                        "pure-js-vm.js",
                        (FIXTURES / "pure-js-vm.js").read_bytes(),
                        "0",
                    )
                ],
            )
            events = root / "events.jsonl"
            records = [
                {
                    "session_id": "7",
                    "sequence_number": "1",
                    "navigation_id": "100",
                    "frame_id": "200",
                    "artifact_id": "1",
                    "category": "canvas",
                    "type": "api_call",
                },
                {
                    "session_id": "7",
                    "sequence_number": "2",
                    "navigation_id": "100",
                    "frame_id": "200",
                    "artifact_id": "1",
                    "request_id": "81",
                    "category": "network",
                    "type": "request_started",
                },
                {
                    "session_id": "7",
                    "sequence_number": "3",
                    "navigation_id": "101",
                    "frame_id": "200",
                    "artifact_id": "1",
                    "request_id": "82",
                    "category": "network",
                    "type": "request_started",
                },
            ]
            events.write_text(
                "".join(json.dumps(item) + "\n" for item in records), encoding="utf-8"
            )
            result = analyze_store(store, events)["results"][0]

            self.assertEqual(result["related_request_ids"], ["81"])
            states = {edge["state"] for edge in result["graph"]["edges"]}
            self.assertIn("observed", states)
            self.assertIn("inferred", states)
            self.assertIn("correlated", states)
            request_edge = next(
                edge for edge in result["graph"]["edges"] if edge["to"] == "request:81"
            )
            self.assertIn(
                "Exact value provenance is not claimed", request_edge["reason"]
            )

    def test_failed_child_does_not_abort_mixed_runtime_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                Path(directory),
                [
                    (
                        "javascript",
                        "pure-js-vm.js",
                        (FIXTURES / "pure-js-vm.js").read_bytes(),
                        "0",
                    ),
                    ("wasm", "malformed.wasm", b"not-wasm", "1"),
                ],
            )

            document = analyze_store(store)

        self.assertEqual(len(document["results"]), 2)
        self.assertEqual(document["results"][1]["status"], "failed")
        self.assertEqual(document["mixed_findings"], [])
        self.assertEqual(document["summary"]["failed_count"], 1)

    def test_named_limits_and_malformed_wasm_remain_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = (FIXTURES / "pure-js-vm.js").read_bytes()
            store = self.make_store(
                root,
                [
                    ("javascript", "large.js", source, "0"),
                    ("wasm", "broken.wasm", b"not-wasm", "0"),
                ],
            )
            document = analyze_store(store, limits=Limits(max_artifact_bytes=96))
            java_script, wasm = document["results"]

            self.assertEqual(java_script["status"], "failed")
            self.assertFalse(java_script["coverage"]["complete"])
            self.assertEqual(
                java_script["coverage"]["omissions"][0]["reason"], "artifact-byte-limit"
            )
            self.assertEqual(java_script["error"]["code"], "artifact-byte-limit")
            self.assertEqual(wasm["status"], "failed")
            self.assertEqual(wasm["error"]["code"], "malformed-artifact")

    def test_truncated_unsupported_and_section_limited_wasm_fail_closed(self) -> None:
        unsupported_body = bytes([0, 0xFD, 0, 0x0B])
        unsupported_code = bytes([1, len(unsupported_body)]) + unsupported_body
        type_payload = bytes([1, 0x60, 0, 0])
        function_payload = bytes([1, 0])
        unsupported_module = (
            b"\x00asm\x01\x00\x00\x00"
            + bytes([1, len(type_payload)])
            + type_payload
            + bytes([3, len(function_payload)])
            + function_payload
            + bytes([10, len(unsupported_code)])
            + unsupported_code
        )
        cases = (
            b"\x00asm\x01\x00\x00\x00\x0a\x0a\x01",
            b"\x00asm\x02\x00\x00\x00",
            b"\x00asm\x01\x00\x00\x00\x00\x00\x00\x00",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    ("wasm", "truncated.wasm", cases[0], "0"),
                    ("wasm", "unsupported.wasm", cases[1], "0"),
                    ("wasm", "too-many-sections.wasm", cases[2], "0"),
                ],
            )
            document = analyze_store(store, limits=Limits(max_wasm_sections=1))

            self.assertTrue(
                all(result["status"] == "failed" for result in document["results"])
            )
            self.assertIn("truncated", document["results"][0]["error"]["message"])
            self.assertIn("unsupported", document["results"][1]["error"]["message"])
            self.assertIn(
                "section count limit", document["results"][2]["error"]["message"]
            )

            opcode_store = self.make_store(
                root / "opcode",
                [("wasm", "unsupported-opcode.wasm", unsupported_module, "0")],
            )
            unsupported = analyze_store(opcode_store)["results"][0]
            self.assertIn(
                "unsupported WebAssembly prefixed opcode",
                unsupported["error"]["message"],
            )

    def test_analysis_store_is_content_addressed_derived_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    (
                        "javascript",
                        "pure-js-vm.js",
                        (FIXTURES / "pure-js-vm.js").read_bytes(),
                        "0",
                    )
                ],
            )
            document = analyze_store(store)
            path = write_analysis(document, store)

            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["document_digest"], document["document_digest"])
            self.assertEqual(len(stored["profile_digest"]), 64)
            self.assertEqual(stored["producer"]["version"], "1.0.0")

            stored["profile"]["candidate_threshold"] = 999
            with self.assertRaisesRegex(AnalysisError, "profile digest mismatch"):
                verify_analysis_document(stored)

            stored = json.loads(path.read_text(encoding="utf-8"))
            stored["summary"]["candidate_count"] += 1
            with self.assertRaisesRegex(AnalysisError, "document digest mismatch"):
                verify_analysis_document(stored)

    def test_manifest_and_event_inputs_are_bounded_and_named(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(
                root,
                [
                    (
                        "javascript",
                        "pure-js-vm.js",
                        (FIXTURES / "pure-js-vm.js").read_bytes(),
                        "0",
                    ),
                    ("wasm", "ordinary.wasm", ordinary_wasm_fixture(), "0"),
                ],
            )
            events = root / "events.jsonl"
            event = {
                "session_id": "7",
                "sequence_number": "1",
                "navigation_id": "100",
                "frame_id": "200",
                "category": "network",
                "type": "request_started",
            }
            events.write_text(
                json.dumps(event) + " " * 200 + "\n" + json.dumps(event) + "\n",
                encoding="utf-8",
            )

            document = analyze_store(
                store,
                events,
                Limits(max_event_line_bytes=96, max_event_records=1),
            )

            self.assertFalse(document["input_coverage"]["complete"])
            reasons = {
                omission["reason"]
                for omission in document["input_coverage"]["omissions"]
            }
            self.assertIn("event-line-byte-limit", reasons)
            self.assertEqual(document["results"][0]["status"], "partial")

            events.write_text(
                json.dumps(event) + "\n" + json.dumps(event) + "\n", encoding="utf-8"
            )
            event_limited = analyze_store(store, events, Limits(max_event_records=1))
            self.assertIn(
                "event-record-limit",
                {
                    omission["reason"]
                    for omission in event_limited["input_coverage"]["omissions"]
                },
            )

            manifest_limited = analyze_store(
                store, limits=Limits(max_artifact_records=1)
            )
            self.assertEqual(len(manifest_limited["results"]), 1)
            self.assertIn(
                "artifact-manifest-record-limit",
                {
                    omission["reason"]
                    for omission in manifest_limited["input_coverage"]["omissions"]
                },
            )

            line_limited = analyze_store(
                store, limits=Limits(max_manifest_line_bytes=64)
            )
            self.assertEqual(line_limited["results"], [])
            self.assertEqual(
                line_limited["input_coverage"]["omissions"][0]["reason"],
                "artifact-manifest-line-byte-limit",
            )

    def test_invalid_manifest_contract_and_path_fail_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = self.make_store(root, [])
            outside = root / "outside.js"
            outside.write_text("throw new Error('must not be read')", encoding="utf-8")
            invalid = {
                "protocol_version": 1,
                "artifact_id": "01",
                "session_id": "7",
                "navigation_id": "100",
                "frame_id": "200",
                "parent_artifact_id": "0",
                "creator_event_id": "71",
                "kind": "javascript",
                "url": "https://authorized.test/outside.js",
                "mime_type": "text/javascript",
                "byte_size": outside.stat().st_size,
                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
                "sensitive": False,
                "content_path": "../outside.js",
            }
            (store / "manifest.jsonl").write_text(
                json.dumps(invalid) + "\n", encoding="utf-8"
            )

            document = analyze_store(store)

            self.assertEqual(document["results"][0]["status"], "failed")
            self.assertEqual(
                document["results"][0]["error"]["code"],
                "invalid-artifact-manifest",
            )
            self.assertFalse(document["input_coverage"]["complete"])


if __name__ == "__main__":
    unittest.main()
