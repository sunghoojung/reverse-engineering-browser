#!/usr/bin/env python3

import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path

from local_analyst import (
    LocalAnalystConflict,
    LocalAnalystError,
    LocalAnalystRunner,
    LocalAnalystStore,
    empty_local_analyst_workspace,
    local_analyst_limits,
    normalize_analyst_result,
    normalize_analyst_run_request,
)


class LocalAnalystTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(__file__).parent

    @staticmethod
    def replacement(generation: int, folders: list, files: list) -> dict:
        return {
            "action": "replace_local_analyst_workspace",
            "expected_generation": generation,
            "folders": folders,
            "files": files,
        }

    @staticmethod
    def run_request(source: str, run_id: int = 1) -> dict:
        return {
            "action": "run_local_analyst_script",
            "protocol_version": 1,
            "run_id": run_id,
            "script_id": 7,
            "library_generation": 3,
            "source": source,
            "variables": {"seed": "verified", "private": "not-public"},
            "evidence": {
                "events": [{"sequence_number": "1", "category": "network"}],
                "artifacts": [{"artifact_id": "9", "kind": "javascript"}],
                "trace_edges": [],
                "signal_profiles": [],
                "vm_analysis": {"protocol_version": 1, "results": []},
                "selected_artifact": None,
                "summary": {"events": 1, "artifacts": 1},
            },
            "confirmed": True,
            "confirmed_sensitive": False,
        }

    @staticmethod
    def workspace(source: str) -> dict:
        return {
            "contract_version": 1,
            "document_kind": "local-analyst-workspace",
            "generation": 3,
            "updated_at_ms": 1,
            "folders": [
                {"id": 1, "name": "Analyst Workspace", "parent_id": None}
            ],
            "files": [
                {
                    "id": 7,
                    "folder_id": 1,
                    "name": "test.js",
                    "kind": "analyst-script",
                    "language": "javascript",
                    "content": source,
                    "content_bytes": len(source.encode("utf-8")),
                    "created_at_ms": 1,
                    "updated_at_ms": 1,
                }
            ],
            "limits": local_analyst_limits(),
        }

    def test_store_replaces_atomically_and_preserves_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workspace.json"
            store = LocalAnalystStore(path)
            empty = store.load()
            self.assertEqual(empty, empty_local_analyst_workspace())
            folders = [
                {"id": 1, "name": "Analyst Workspace", "parent_id": None},
                {"id": 2, "name": "Checkout", "parent_id": 1},
            ]
            files = [
                {
                    "id": 1,
                    "folder_id": 2,
                    "name": "inspect.js",
                    "kind": "analyst-script",
                    "language": "javascript",
                    "content": "return WB.Node.Evidence.events().length;",
                },
                {
                    "id": 2,
                    "folder_id": 2,
                    "name": "notes.md",
                    "kind": "scratchpad",
                    "language": "markdown",
                    "content": "# Findings\n",
                },
            ]
            saved = store.replace(self.replacement(0, folders, files))
            self.assertEqual(saved["generation"], 1)
            self.assertEqual(saved["files"][0]["content_bytes"], 40)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            unchanged = store.replace(self.replacement(1, folders, files))
            self.assertEqual(unchanged["generation"], 1)
            created = saved["files"][0]["created_at_ms"]
            files[0]["content"] = "return 2;"
            updated = store.replace(self.replacement(1, folders, files))
            self.assertEqual(updated["generation"], 2)
            self.assertEqual(updated["files"][0]["created_at_ms"], created)
            self.assertGreaterEqual(updated["files"][0]["updated_at_ms"], created)
            with self.assertRaises(LocalAnalystConflict):
                store.replace(self.replacement(1, folders, files))

    def test_store_rejects_hierarchy_duplicates_limits_and_symlinks(self) -> None:
        root = {"id": 1, "name": "Analyst Workspace", "parent_id": None}
        folders = [root]
        parent = 1
        for identifier in range(2, 7):
            folders.append(
                {"id": identifier, "name": f"Level {identifier}", "parent_id": parent}
            )
            parent = identifier
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalAnalystStore(Path(temporary) / "workspace.json")
            with self.assertRaisesRegex(LocalAnalystError, "depth"):
                store.replace(self.replacement(0, folders, []))
            duplicate = [root, {"id": 2, "name": "Same", "parent_id": 1}]
            file = {
                "id": 1,
                "folder_id": 1,
                "name": "Same",
                "kind": "scratchpad",
                "language": "text",
                "content": "",
            }
            with self.assertRaisesRegex(LocalAnalystError, "duplicated"):
                store.replace(self.replacement(0, duplicate, [file]))
            oversized = [
                {
                    **file,
                    "id": identifier,
                    "name": f"file-{identifier}",
                    "content": "x" * (32 * 1024),
                }
                for identifier in range(1, 18)
            ]
            with self.assertRaisesRegex(LocalAnalystError, "512 KiB"):
                store.replace(self.replacement(0, [root], oversized))
            target = Path(temporary) / "target.json"
            target.write_text("{}", encoding="utf-8")
            symlink = Path(temporary) / "linked.json"
            os.symlink(target, symlink)
            with self.assertRaisesRegex(LocalAnalystError, "regular file"):
                LocalAnalystStore(symlink).load()

    def test_runner_exposes_frozen_evidence_and_skips_accessors(self) -> None:
        runner = LocalAnalystRunner(self.directory)
        if not runner.available():
            self.skipTest("Node.js 22 or newer is not installed")
        source = """
let getterCalls = 0;
const value = {visible: "ok"};
Object.defineProperty(value, "secret", {enumerable: true, get() { getterCalls += 1; return "bad"; }});
value.circular = value;
let mutation = "allowed";
try { WB.Node.Evidence.events().push({}); } catch { mutation = "blocked"; }
console.info("events", WB.Node.Evidence.events().length);
return {seed: Utils.getVar("seed"), mutation, frozen: Object.isFrozen(WB.Node.Evidence.events()), value, getterCalls};
"""
        result = runner.run(self.run_request(source), self.workspace(source))
        self.assertTrue(result["ok"])
        self.assertEqual(result["outcome"], "completed")
        self.assertIn('"seed":"verified"', result["result_text"])
        self.assertIn('"mutation":"blocked"', result["result_text"])
        self.assertIn("[Accessor not invoked]", result["result_text"])
        self.assertIn("[Circular]", result["result_text"])
        self.assertIn('"getterCalls":0', result["result_text"])
        self.assertEqual(result["logs"][0]["level"], "info")
        self.assertNotIn("not-public", json.dumps(result))

    def test_runner_blocks_host_capabilities_and_string_code_generation(self) -> None:
        runner = LocalAnalystRunner(self.directory)
        if not runner.available():
            self.skipTest("Node.js 22 or newer is not installed")
        source = """
let escaped;
try { escaped = globalThis.constructor.constructor("return process")(); }
catch (error) { escaped = error.name; }
return {process: typeof process, require: typeof require, fetch: typeof fetch,
  WebSocket: typeof WebSocket, escaped};
"""
        result = runner.run(self.run_request(source), self.workspace(source))
        self.assertTrue(result["ok"])
        self.assertEqual(
            json.loads(result["result_text"]),
            {
                "process": "undefined",
                "require": "undefined",
                "fetch": "undefined",
                "WebSocket": "undefined",
                "escaped": "EvalError",
            },
        )

    def test_runner_reports_syntax_failure_timeout_and_cancellation(self) -> None:
        runner = LocalAnalystRunner(self.directory)
        if not runner.available():
            self.skipTest("Node.js 22 or newer is not installed")
        syntax_source = "return (;"
        syntax = runner.run(
            self.run_request(syntax_source), self.workspace(syntax_source)
        )
        self.assertFalse(syntax["ok"])
        self.assertEqual(syntax["outcome"], "failed")

        wait_source = "await new Promise(() => {});"
        timed = runner.run(
            self.run_request(wait_source, run_id=2), self.workspace(wait_source)
        )
        self.assertEqual(timed["outcome"], "timed_out")
        self.assertIn("2 second", timed["error"])

        completed = []

        def execute() -> None:
            completed.append(
                runner.run(
                    self.run_request(wait_source, run_id=3),
                    self.workspace(wait_source),
                )
            )

        thread = threading.Thread(target=execute)
        thread.start()
        deadline = time.monotonic() + 2
        while runner.active_run_id() != 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(runner.active_run_id(), 3)
        self.assertTrue(runner.cancel(3))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(completed[0]["outcome"], "cancelled")

    def test_run_validation_rejects_sensitive_and_malformed_results(self) -> None:
        request = self.run_request("return true;")
        request["evidence"]["selected_artifact"] = {
            "artifact_id": "9",
            "sensitive": True,
            "content": "private",
        }
        with self.assertRaisesRegex(LocalAnalystError, "sensitive"):
            normalize_analyst_run_request(request)
        request["confirmed_sensitive"] = True
        normalized = normalize_analyst_run_request(request)
        malformed = {
            "protocol_version": 1,
            "run_id": 999,
            "script_id": 7,
            "library_generation": 3,
            "ok": True,
            "outcome": "completed",
            "result_type": "boolean",
            "result_text": "true",
            "result_truncated": False,
            "logs": [],
            "logs_truncated": False,
            "duration_ms": 1,
            "error": "",
        }
        with self.assertRaisesRegex(LocalAnalystError, "correlation"):
            normalize_analyst_result(malformed, normalized)
        self.assertEqual(local_analyst_limits()["evidence_bytes"], 768 * 1024)


if __name__ == "__main__":
    unittest.main()
