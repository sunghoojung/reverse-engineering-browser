#!/usr/bin/env python3
"""Synthetic Brave provenance records; no browser build, download or execution."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).with_name("write-brave-provenance.py")
PINS = {
    "brave-core": "v1.95.52",
    "chromium": "151.0.7922.108",
    "v8": "20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921",
    "depot_tools": "a20039648c0de69d8156906b18052bd47e9bf230",
}
GENERATED = """# Do not edit, any changes will be lost on next build.
import("//brave/build/args/brave_defaults.gni")
is_component_build=false
target_cpu="arm64"
is_official_build=false
is_debug=false
brave_channel="development"
skip_signing=true
enable_updater=false
enable_sparkle=false
brave_services_key=""
"""
ARGS = """# This file is user-editable.
import("//out/Static_arm64/args_generated.gni")
cc_wrapper = "sccache"  # compiler cache
symbol_level = 0
"""
CDHASH = "c" * 40
VERSION = "Brave Browser 151.1.95.0"


def git(root, *arguments):
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
         *arguments], cwd=root, env=environment, check=True, capture_output=True, text=True,
    ).stdout.strip()


class BraveProvenance(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("brave_provenance", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repository"
        config = self.root / "browser/config"
        config.mkdir(parents=True)
        for name, value in PINS.items():
            (config / f"{name}.rev").write_text(value + "\n")
        git(self.root, "init", "--quiet")
        git(self.root, "add", ".")
        git(self.root, "commit", "--quiet", "--no-verify", "-m", "Pins")
        self.commit = git(self.root, "rev-parse", "HEAD")
        self.helper.__file__ = str(self.root / "tools/write-brave-provenance.py")
        self.build = Path(temporary.name) / "src/out/Static_arm64"
        self.build.mkdir(parents=True)
        (self.build / "args_generated.gni").write_text(GENERATED)
        self.args = self.build / "args.gn"
        self.args.write_text(ARGS)
        self.output = Path(temporary.name) / "release"
        self.output.mkdir()
        self.zip = self.output / "Brave-Browser-Development-v0.5.0-macos-arm64.zip"
        self.zip.write_bytes(b"synthetic browser archive")
        self.record = self.output / "Brave-Browser-Development-v0.5.0-macos-arm64.provenance.json"

    def argv(self, **overrides):
        values = {
            "zip": str(self.zip), "sha256": self.helper.digest(self.zip),
            "source-commit": self.commit, "build-args": str(self.args),
            "executable-version": VERSION, "cdhash": CDHASH, **overrides,
        }
        return [item for name, value in values.items() for item in (f"--{name}", value)]

    def write(self, **overrides):
        with contextlib.redirect_stdout(io.StringIO()):
            self.helper.main(self.argv(**overrides))

    def test_record_is_deterministic_and_complete(self):
        self.write()
        first = self.record.read_bytes()
        self.write(output=str(self.output / "again.json"))
        self.assertEqual(first, (self.output / "again.json").read_bytes())
        record = json.loads(first)
        self.assertEqual(record["schema"], "reb-brave-distribution-provenance-v1")
        self.assertEqual(record["release"], "v0.5.0")
        self.assertEqual(record["artifact"], self.zip.name)
        self.assertEqual(record["sha256"], self.helper.digest(self.zip))
        self.assertEqual(record["size_bytes"], self.zip.stat().st_size)
        self.assertEqual(record["browser_version"], "151.1.95.0")
        self.assertEqual(record["app_cdhash"], CDHASH)
        self.assertEqual(record["build_source_commit"], self.commit)
        self.assertEqual(record["pins"], {
            "brave_core": PINS["brave-core"], "chromium": PINS["chromium"],
            "v8": PINS["v8"], "depot_tools": PINS["depot_tools"],
        })
        self.assertEqual(record["build_args"]["target_cpu"], "arm64")
        self.assertIs(record["build_args"]["is_component_build"], False)
        self.assertEqual(record["build_args"]["symbol_level"], 0)
        self.assertEqual(record["build_args"]["cc_wrapper"], "sccache")
        self.assertEqual(record["build_args"]["brave_services_key"], "")
        self.assertEqual(record["build_args_imports"], ["//brave/build/args/brave_defaults.gni"])
        self.assertEqual(list(record["build_args"]), sorted(record["build_args"]))

    def test_pins_come_from_the_build_commit_not_the_worktree(self):
        (self.root / "browser/config/brave-core.rev").write_text("v1.96.1\n")
        self.write()
        self.assertEqual(json.loads(self.record.read_text())["pins"]["brave_core"], "v1.95.52")

    def test_later_assignment_wins_and_credentials_and_paths_are_redacted(self):
        self.args.write_text(ARGS + 'symbol_level = 1\ngoogle_api_key = "synthetic"\n'
                             'mac_sdk_path = "/Users/someone/sdk"\n')
        self.write()
        args = json.loads(self.record.read_text())["build_args"]
        self.assertEqual(args["symbol_level"], 1)
        self.assertEqual(args["google_api_key"], "<redacted: credential>")
        self.assertEqual(args["mac_sdk_path"], "<redacted: local path>")
        self.assertNotIn("synthetic", self.record.read_text())

    def test_existing_record_is_not_replaced(self):
        self.record.write_text("existing")
        with self.assertRaises(FileExistsError):
            self.write()
        self.assertEqual(self.record.read_text(), "existing")

    def test_inconsistent_inputs_are_rejected_without_output(self):
        cases = {
            "changed archive hash": {"sha256": "0" * 64},
            "short commit": {"source-commit": self.commit[:12]},
            "unknown commit": {"source-commit": "d" * 40},
            "uppercase CDHash": {"cdhash": CDHASH.upper()},
            "other Chromium major": {"executable-version": "Brave Browser 150.1.95.0"},
            "other Brave minor": {"executable-version": "Brave Browser 151.1.96.0"},
            "no version": {"executable-version": "Brave Browser"},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.write(**overrides)
        renamed = self.output / "Brave-Browser-Development-0.5.0-macos-arm64.zip"
        renamed.write_bytes(self.zip.read_bytes())
        with self.assertRaises(ValueError):
            self.write(zip=str(renamed))
        self.assertEqual(sorted(path.name for path in self.output.iterdir()),
                         sorted([self.zip.name, renamed.name]))

    def test_build_arguments_must_describe_a_research_distribution(self):
        cases = {
            "component build": GENERATED.replace("is_component_build=false", "is_component_build=true"),
            "missing updater flag": GENERATED.replace("enable_updater=false\n", ""),
            "bundled service": GENERATED + "enable_brave_wallet=true\n",
            "service opt-in": GENERATED + "reb_enable_bundled_brave_services=true\n",
            "conditional": GENERATED + "if (is_mac) {\n  symbol_level = 1\n}\n",
            "escaping import": GENERATED + 'import("//out/../secrets.gni")\n',
        }
        for name, generated in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                (self.build / "args_generated.gni").write_text(generated)
                self.write()
        self.assertFalse(self.record.exists())


if __name__ == "__main__":
    unittest.main()
