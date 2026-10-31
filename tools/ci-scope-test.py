#!/usr/bin/env python3
"""Lock the CI path allowlists. A product path must not classify as docs or rust."""

import importlib.util
from pathlib import Path
import unittest


HELPER = Path(__file__).with_name("ci-scope.py")


def load_scope():
    spec = importlib.util.spec_from_file_location("ci_scope", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CiScope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = load_scope()

    def mode(self, *paths: str) -> str:
        return self.scope.classify(list(paths))

    def test_empty_and_unknown_stay_on_the_full_gate(self):
        self.assertEqual(self.mode(), "full")
        self.assertEqual(self.mode(""), "full")
        self.assertEqual(self.mode("src/capture/event.cpp"), "full")
        self.assertEqual(self.mode("protocol/http-api.md"), "full")
        self.assertEqual(self.mode("apps/research-ui/app.js"), "full")
        self.assertEqual(self.mode("tools/check-graphql-sdl.mjs"), "full")
        self.assertEqual(self.mode("../etc/passwd"), "full")

    def test_documentation_only(self):
        self.assertEqual(self.mode("README.md"), "docs")
        self.assertEqual(self.mode("AGENTS.md", "docs/architecture/technical-architecture.md"), "docs")
        self.assertEqual(self.mode(".agents/skills/reb-validation/SKILL.md"), "docs")
        self.assertEqual(self.mode("apps/research-ui/README.md"), "docs")
        self.assertEqual(self.mode("apps/origin-trace-backend/README.md"), "docs")

    def test_rust_backends_skip_only_the_macos_app_gate(self):
        self.assertEqual(self.mode("apps/origin-trace-backend/src/lib.rs"), "rust")
        self.assertEqual(
            self.mode(
                "apps/origin-trace-backend/Cargo.lock",
                "apps/deobfuscator-worker/src/main.rs",
                "README.md",
            ),
            "rust",
        )

    def test_mixed_product_changes_run_the_full_gate(self):
        self.assertEqual(
            self.mode(
                "apps/origin-trace-backend/src/lib.rs",
                "src/capture/event.cpp",
            ),
            "full",
        )
        self.assertEqual(
            self.mode("docs/README.md", "apps/research-ui/macos/OriginTraceApp.swift"),
            "full",
        )

    def test_skip_logic_and_build_files_force_the_full_gate(self):
        for path in (
            "tools/ci-scope.py",
            "tools/ci-scope-decision.sh",
            ".github/workflows/ci.yml",
            ".github/actions/ci-prepare/action.yml",
            "mk/quality.mk",
            "Makefile",
            ".githooks/pre-push",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.mode(path), "full")
                self.assertEqual(self.mode("README.md", path), "full")


if __name__ == "__main__":
    unittest.main()
