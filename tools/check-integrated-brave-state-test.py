#!/usr/bin/env python3
"""Bounded Git fixtures for integrated-build preservation guards; no browser download."""

import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


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
            (path / ".gitignore").write_text("brave/\nv8/\nignored/\nbuild/\nout/\n")
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

    def wrapper(self, overrides=None, initialize=False, expect_bootstrap=False):
        scripts = self.repo / "scripts"
        scripts.mkdir(exist_ok=True)
        wrapper = scripts / "build-integrated-brave.sh"
        shutil.copyfile(HELPER.parent.parent / "scripts/build-integrated-brave.sh", wrapper)
        bootstrap = scripts / "bootstrap-brave.sh"
        bootstrap.write_text(f"#!/bin/sh\ntouch '{self.root}/bootstrap-admitted'\nexit 91\n")
        bootstrap.chmod(0o755)
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
        arguments = ["bash", str(wrapper)] + (["--init"] if initialize else [])
        result = subprocess.run(arguments, env=environment, capture_output=True,
                                text=True, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "mutated").exists(), result.stdout + result.stderr)
        self.assertEqual((self.root / "bootstrap-admitted").exists(), expect_bootstrap,
                         result.stdout + result.stderr)
        return result

    def fresh_nested_brave(self):
        self.brave = self.repo / "browser/worktree/src/brave"
        self.chromium = self.brave.parent
        self.v8 = self.chromium / "v8"
        ignore = self.repo / ".gitignore"
        ignore.write_text(ignore.read_text() + "browser/worktree/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore generated browser workspace")

    def make_pristine_unborn_brave(self):
        self.fresh_nested_brave()
        self.brave.mkdir(parents=True)
        git(self.brave, "init", "-q")
        git(self.brave, "remote", "add", "origin", "https://github.com/brave/brave-core.git")

    def test_absent_nested_upstream_reaches_bootstrap(self):
        self.fresh_nested_brave()
        self.assertFalse(self.brave.exists())
        self.assertEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertEqual(self.call("reserve", "--require-clean").stdout.strip(),
                         str(150 * 1024 * 1024))
        self.assertEqual(self.wrapper(initialize=True, expect_bootstrap=True).returncode, 91)
        self.assertFalse(self.brave.exists())  # Stub never downloads or creates a checkout.

    def test_pristine_unborn_brave_is_admitted_only_for_init(self):
        self.make_pristine_unborn_brave()
        self.assertNotEqual(self.call().returncode, 0)
        self.assertNotEqual(self.call("record").returncode, 0)
        self.assertEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertEqual(self.wrapper(initialize=True, expect_bootstrap=True).returncode, 91)
        self.assertEqual(list(self.brave.iterdir()), [self.brave / ".git"])

    def test_unborn_brave_preserves_any_worktree_or_index_data(self):
        self.make_pristine_unborn_brave()
        target = self.brave / "private.txt"
        target.write_text("preserve existing partial work")
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertEqual(target.read_text(), "preserve existing partial work")
        git(self.brave, "add", "private.txt")
        target.unlink()  # An index-only user file must still block initialization.
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertEqual(git(self.brave, "show", ":private.txt"), "preserve existing partial work")

    def test_unborn_brave_wrong_remote_refs_and_operation_state_refused(self):
        self.make_pristine_unborn_brave()
        git(self.brave, "remote", "set-url", "origin", "https://example.invalid/other.git")
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        git(self.brave, "remote", "set-url", "origin", "https://github.com/brave/brave-core.git")
        git(self.brave, "config", "--add", "remote.origin.url", "https://example.invalid/extra.git")
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        git(self.brave, "config", "--unset-all", "remote.origin.url")
        git(self.brave, "config", "remote.origin.url", "https://github.com/brave/brave-core.git")
        pending = self.brave / ".git/MERGE_HEAD"
        pending.write_text("unfinished")
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        pending.unlink()
        git(self.brave, "fetch", str(self.repo), "HEAD")
        git(self.brave, "update-ref", "refs/tags/preserve", git(self.brave, "rev-parse", "FETCH_HEAD"))
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)

    def test_unborn_custom_hooks_and_executable_configuration_refused(self):
        self.make_pristine_unborn_brave()
        marker = self.root / "unexpected-hook-ran"
        hook = self.brave / ".git/hooks/post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertTrue(hook.exists())
        self.assertFalse(marker.exists())
        hook.unlink()
        for key, value in (("core.hooksPath", "/unexpected/hooks"),
                           ("core.fsmonitor", "/unexpected/monitor"),
                           ("include.path", "/unexpected/config")):
            with self.subTest(key=key):
                git(self.brave, "config", key, value)
                self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
                self.assertEqual(git(self.brave, "config", "--get", key), value)
                git(self.brave, "config", "--unset", key)
        self.assertFalse(marker.exists())

    def test_broken_upstream_symlink_refused_during_init(self):
        self.fresh_nested_brave()
        self.brave.parent.mkdir(parents=True)
        self.brave.symlink_to(self.root / "absent-target", target_is_directory=True)
        self.assertNotEqual(self.call("check", "--require-clean").returncode, 0)
        self.assertTrue(self.brave.is_symlink())

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

    def completed_browser_fixture(self):
        output = self.chromium / "out/Component_arm64"
        executable = output / "Brave Browser.app/Contents/MacOS/Brave Browser"
        executable.parent.mkdir(parents=True)
        executable.write_text("completed browser fixture")
        executable.chmod(0o755)
        (output / "args.gn").write_text("is_component_build = true\n")
        self.assertEqual(self.call("record").returncode, 0)
        self.assertEqual(self.call("complete").returncode, 0)
        return executable

    def test_first_incomplete_and_unproven_build_disk_reserve(self):
        first = str(150 * 1024 * 1024)
        self.assertEqual(self.call("reserve").stdout.strip(), first)
        output = self.chromium / "out/Component_arm64"
        output.mkdir(parents=True)
        (output / "args.gn").write_text("partial build")
        self.assertEqual(self.call("record").returncode, 0)
        self.assertEqual(self.call("reserve").stdout.strip(), first)
        self.assertNotEqual(self.call("complete").returncode, 0)

    def test_valid_repeat_init_and_changed_output_reserves(self):
        executable = self.completed_browser_fixture()
        self.assertEqual(self.call("reserve").stdout.strip(), str(50 * 1024 * 1024))
        self.assertEqual(self.call("reserve", "--require-clean").stdout.strip(),
                         str(150 * 1024 * 1024))
        args = self.chromium / "out/Component_arm64/args.gn"
        original_args = args.read_text()
        args.write_text("changed output configuration")
        self.assertEqual(self.call("reserve").stdout.strip(), str(150 * 1024 * 1024))
        args.write_text(original_args)
        self.assertEqual(self.call("reserve").stdout.strip(), str(50 * 1024 * 1024))
        executable.write_text("changed browser")
        self.assertEqual(self.call("reserve").stdout.strip(), str(150 * 1024 * 1024))

    def test_stale_source_completion_uses_first_build_reserve(self):
        self.completed_browser_fixture()
        git(self.repo, "commit", "--allow-empty", "-qm", "new integration")
        self.assertEqual(self.call("reserve").stdout.strip(), str(150 * 1024 * 1024))

    def test_repeat_reserve_size_and_invalid_measurement(self):
        spec = importlib.util.spec_from_file_location("brave_state", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.subprocess, "check_output", return_value="104857600 output"):
            self.assertEqual(module.repeat_reserve_kib("output"), 100 * 1024 * 1024)
        for value in ("", "invalid output", "-1 output", "0 output"):
            with self.subTest(value=value), patch.object(module.subprocess, "check_output",
                                                         return_value=value):
                with self.assertRaises(ValueError):
                    module.repeat_reserve_kib("output")

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
