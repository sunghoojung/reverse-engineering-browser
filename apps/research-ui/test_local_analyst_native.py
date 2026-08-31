#!/usr/bin/env python3

import json
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path


class LocalAnalystNativeRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.system() != "Darwin":
            raise unittest.SkipTest("The native analyst runner requires macOS")
        cls.directory = Path(__file__).resolve().parent
        cls.temporary = tempfile.TemporaryDirectory()
        cls.runner = Path(cls.temporary.name) / "OriginTraceAnalystRunner"
        subprocess.run(
            [
                "xcrun",
                "swiftc",
                "-parse-as-library",
                "-framework",
                "JavaScriptCore",
                str(cls.directory / "macos" / "AnalystRunner.swift"),
                "-o",
                str(cls.runner),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def run_script(self, source: str, *, timeout: float = 4.0) -> dict:
        request = {
            "protocol_version": 1,
            "run_id": 7,
            "script_id": 9,
            "library_generation": 3,
            "source": source,
            "variables": {"seed": "native"},
            "evidence": {
                "events": [{"sequence_number": "1"}],
                "artifacts": [{"artifact_id": "2"}],
                "trace_edges": [],
                "signal_profiles": [],
                "vm_analysis": None,
                "selected_artifact": None,
                "summary": {"events": 1},
            },
        }
        completed = subprocess.run(
            [str(self.runner), str(self.directory / "analyst_runner_core.js")],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        return json.loads(completed.stdout)

    def test_native_runner_executes_async_helpers_and_logs(self) -> None:
        result = self.run_script(
            """
            await Promise.resolve();
            console.info("events", WB.Node.Evidence.events().length);
            return {seed: Utils.getVar("seed"), artifacts: WB.Node.Evidence.artifacts().length};
            """
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["outcome"], "completed")
        self.assertEqual(json.loads(result["result_text"]), {"seed": "native", "artifacts": 1})
        self.assertEqual(result["logs"], [{"level": "info", "text": '"events" 1'}])
        self.assertEqual(
            (result["run_id"], result["script_id"], result["library_generation"]),
            (7, 9, 3),
        )

    def test_native_runner_exposes_no_host_capabilities_or_dynamic_code(self) -> None:
        result = self.run_script(
            """
            const capabilities = [typeof process, typeof require, typeof fetch, typeof document];
            let constructorBlocked = false;
            let evalBlocked = false;
            try { globalThis.constructor.constructor("return 1")(); }
            catch (error) { constructorBlocked = error instanceof TypeError; }
            try { eval("1"); }
            catch (error) { evalBlocked = error instanceof TypeError; }
            return {capabilities, constructorBlocked, evalBlocked};
            """
        )
        self.assertTrue(result["ok"])
        self.assertEqual(
            json.loads(result["result_text"]),
            {
                "capabilities": ["undefined", "undefined", "undefined", "undefined"],
                "constructorBlocked": True,
                "evalBlocked": True,
            },
        )

    def test_native_runner_times_out_unresolved_async_work(self) -> None:
        result = self.run_script("await new Promise(() => {});")
        self.assertFalse(result["ok"])
        self.assertEqual(result["outcome"], "timed_out")
        self.assertIn("2 second execution limit", result["error"])


if __name__ == "__main__":
    unittest.main()
