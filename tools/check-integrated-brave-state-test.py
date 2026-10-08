#!/usr/bin/env python3
"""Bounded Git fixtures for integrated-build preservation guards; no browser download."""

import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).with_name("check-integrated-brave-state.py")


def git(path, *arguments):
    return subprocess.check_output(["git", "-C", str(path), *arguments],
                                   stderr=subprocess.DEVNULL).decode().strip()


class StateGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.brave = self.root / "upstream/src/brave"
        self.chromium = self.brave.parent
        self.v8 = self.chromium / "v8"
        self.receipt = self.root / "receipt.json"
        for path in (self.repo, self.chromium, self.brave, self.v8):
            path.mkdir(parents=True, exist_ok=True)
            git(path, "init", "-q")
            git(path, "config", "user.name", "Fixture")
            git(path, "config", "user.email", "fixture@example.invalid")
            (path / ".gitignore").write_text("brave/\nv8/\nignored/\nbuild/\n")
            (path / "tracked.txt").write_text("original\n")
            git(path, "add", ".gitignore", "tracked.txt")
            git(path, "commit", "-qm", "fixture")
        pins = self.repo / "browser/config"
        pins.mkdir(parents=True)
        for name, path in (("brave-core", self.brave), ("chromium", self.chromium), ("v8", self.v8)):
            (pins / f"{name}.rev").write_text(git(path, "rev-parse", "HEAD"))
        overlay = self.repo / "browser/integration/brave/overlay/ignored"
        overlay.mkdir(parents=True)
        (overlay / "overlay.cc").write_text("owned overlay\n")
        git(self.repo, "add", "browser")
        git(self.repo, "commit", "-qm", "pins and overlay")

    def call(self, mode="check", *extra):
        return subprocess.run([sys.executable, str(HELPER), mode, "--repository", str(self.repo),
                               "--brave", str(self.brave), "--receipt", str(self.receipt), *extra],
                              capture_output=True, text=True, check=False)

    def test_clean_and_recorded_repeat(self):
        self.assertEqual(self.call().returncode, 0)
        (self.brave / "tracked.txt").write_text("known integration\n")
        self.assertEqual(self.call("record").returncode, 0)
        before = self.receipt.read_bytes()
        self.assertEqual(self.call().returncode, 0)
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)

    def test_dirty_tracked_upstream_preserved(self):
        self.assertEqual(self.call("record").returncode, 0)
        for path in (self.brave, self.chromium, self.v8):
            with self.subTest(path=path):
                target = path / "tracked.txt"
                target.write_text("user edit\n")
                self.assertNotEqual(self.call().returncode, 0)
                self.assertEqual(target.read_text(), "user edit\n")
                target.write_text("original\n")

    def test_untracked_collision_and_ignored_overlay(self):
        (self.brave / "new.cc").write_text("private edit\n")
        self.assertNotEqual(self.call().returncode, 0)
        (self.brave / "new.cc").unlink()
        target = self.brave / "ignored/overlay.cc"
        target.parent.mkdir()
        target.write_text("known integration\n")
        self.assertNotEqual(self.call().returncode, 0)
        self.assertEqual(self.call("record").returncode, 0)
        self.assertEqual(self.call().returncode, 0)
        target.write_text("private edit\n")
        self.assertNotEqual(self.call().returncode, 0)
        self.assertEqual(target.read_text(), "private edit\n")

    def test_ignored_siso_collision_content_and_mode(self):
        target = self.chromium / "build/config/siso/brave_siso_config.star"
        target.parent.mkdir(parents=True)
        target.write_text("known generated integration")
        self.assertNotEqual(self.call().returncode, 0)
        self.assertEqual(self.call("record").returncode, 0)
        self.assertEqual(self.call().returncode, 0)
        target.chmod(0o755)
        self.assertNotEqual(self.call().returncode, 0)
        target.chmod(0o644)
        target.write_text("private generated-file edit")
        self.assertNotEqual(self.call().returncode, 0)
        self.assertEqual(target.read_text(), "private generated-file edit")

    def test_mismatch_and_symlink_are_rejected(self):
        git(self.brave, "commit", "--allow-empty", "-qm", "wrong pin")
        self.assertNotEqual(self.call().returncode, 0)
        git(self.brave, "checkout", "-q", "HEAD~1")
        (self.brave / "ignored").symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(self.call().returncode, 0)

    def wrapper(self, overrides=None):
        scripts = self.repo / "scripts"
        scripts.mkdir(exist_ok=True)
        wrapper = scripts / "build-integrated-brave.sh"
        shutil.copyfile(HELPER.parent.parent / "scripts/build-integrated-brave.sh", wrapper)
        helper_dir = self.repo / "tools"
        helper_dir.mkdir(exist_ok=True)
        shutil.copyfile(HELPER, helper_dir / HELPER.name)
        git(self.repo, "add", "scripts", "tools")
        git(self.repo, "commit", "-qm", "wrapper fixture")
        mocks = self.root / "bin"
        mocks.mkdir(exist_ok=True)
        values = {
            "uname": 'if [ "$1" = -s ]; then echo Darwin; else echo arm64; fi',
            "xcodebuild": "exit 0",
            "df": "printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nfixture 999999999 0 999999999 0%% /\\n'",
            "make": f"touch '{self.root}/mutated'; exit 90",
            "cargo": "exit 0",
            "c++": "exit 0",
        }
        for name, content in values.items():
            path = mocks / name
            path.write_text("#!/bin/sh\n" + content + "\n")
            path.chmod(0o755)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("REB_")}
        environment.update(PATH=str(mocks) + os.pathsep + os.environ["PATH"],
                           REB_BRAVE_DIRECTORY=str(self.brave))
        environment.update(overrides or {})
        result = subprocess.run(["bash", str(wrapper)], env=environment, capture_output=True,
                                text=True, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "mutated").exists(), result.stdout + result.stderr)
        return result

    def test_wrapper_stops_dirty_overlay_before_mutating_helpers(self):
        target = self.brave / "ignored/overlay.cc"
        target.parent.mkdir()
        target.write_text("private overlay edit")
        result = self.wrapper()
        self.assertIn("Upstream edits", result.stderr)
        self.assertEqual(target.read_text(), "private overlay edit")

    def test_wrapper_stops_wrong_pin_before_mutating_helpers(self):
        git(self.v8, "commit", "--allow-empty", "-qm", "wrong pin")
        self.assertIn("Pinned revision mismatch", self.wrapper().stderr)

    def test_wrapper_refuses_override(self):
        self.assertIn("Unset REB_BRAVE_OUTPUT_DIRECTORY",
                      self.wrapper({"REB_BRAVE_OUTPUT_DIRECTORY": "out/Other"}).stderr)

    def test_receipt_does_not_follow_temporary_collision(self):
        private_file = self.root / "private.txt"
        private_file.write_text("preserve me")
        self.receipt.with_suffix(".tmp").symlink_to(private_file)
        self.assertEqual(self.call("record").returncode, 0)
        self.assertEqual(private_file.read_text(), "preserve me")
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)

    def test_stale_receipt_identity(self):
        (self.brave / "tracked.txt").write_text("known integration\n")
        self.assertEqual(self.call("record").returncode, 0)
        receipt = json.loads(self.receipt.read_text())
        receipt["integration"] = "stale"
        self.receipt.write_text(json.dumps(receipt))
        self.assertNotEqual(self.call().returncode, 0)


if __name__ == "__main__":
    unittest.main()
