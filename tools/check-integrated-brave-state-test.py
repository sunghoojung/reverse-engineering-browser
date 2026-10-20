#!/usr/bin/env python3
"""Bounded Git fixtures for integrated-build preservation guards; no browser download."""

import importlib.util
import json
import os
import shlex
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
            ignored = "/build/\n/out/\n__pycache__/\n" if path == self.repo else "brave/\nv8/\nignored/\nbuild/\nout/\n"
            (path / ".gitignore").write_text(ignored)
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

    def patch_advance_fixture(self, two_files=False):
        import difflib
        def patch_text(before, after):
            return "diff --git a/tracked.txt b/tracked.txt\n" + "".join(difflib.unified_diff(
                before.splitlines(keepends=True), after.splitlines(keepends=True),
                fromfile="a/tracked.txt", tofile="b/tracked.txt"))
        directory = self.repo / "browser/integration/brave/patches/chromium"
        directory.mkdir(parents=True)
        (directory / "0001-first.patch").write_text(patch_text("original\n", "first\n"))
        second = patch_text("first\n", "second\n")
        extra = ("diff --git a/extra.txt b/extra.txt\nnew file mode 100644\n"
                 "--- /dev/null\n+++ b/extra.txt\n@@ -0,0 +1 @@\n+old extra\n")
        (directory / "0002-second.patch").write_text(second + (extra if two_files else ""))
        (self.chromium / "tracked.txt").write_text("second\n")
        if two_files:
            (self.chromium / "extra.txt").write_text("old extra\n")
        git(self.repo, "add", "browser")
        git(self.repo, "commit", "-qm", "known overlapping patch stack")
        self.assertEqual(self.call("record").returncode, 0)
        current = self.root / "advanced-source"
        subprocess.check_call(["git", "clone", "-q", str(self.repo), str(current)])
        git(current, "config", "user.name", "Fixture")
        git(current, "config", "user.email", "fixture@example.invalid")
        patch = current / "browser/integration/brave/patches/chromium/0002-second.patch"
        patch.write_text(patch_text("first\n", "fixed\n") +
                         (extra.replace("+old extra", "+new extra") if two_files else ""))
        git(current, "add", "browser")
        git(current, "commit", "-qm", "one-file compatibility fix")
        return current, current / "build/integrated-brave-state.json"

    def advance(self, current, receipt):
        return subprocess.run([sys.executable, str(HELPER), "advance-patch",
                               "--repository", str(current), "--brave", str(self.brave),
                               "--receipt", str(receipt), "--previous-repository", str(self.repo),
                               "--previous-receipt", str(self.receipt)], capture_output=True, text=True)

    def test_patch_advance_reuses_one_file_and_preserves_receipt_and_indexes(self):
        current, receipt = self.patch_advance_fixture()
        before = self.receipt.read_bytes()
        indexes = [git(root, "ls-files", "--stage") for root in (self.brave, self.chromium, self.v8)]
        result = self.advance(current, receipt)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("status: advanced", result.stdout)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "fixed\n")
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertEqual(indexes, [git(root, "ls-files", "--stage") for root in (self.brave, self.chromium, self.v8)])
        recorded = receipt.read_bytes(), receipt.stat().st_mtime_ns
        self.assertIn("status: already_advanced", self.advance(current, receipt).stdout)
        self.assertEqual((receipt.read_bytes(), receipt.stat().st_mtime_ns), recorded)
        checked = subprocess.run([sys.executable, str(HELPER), "check", "--repository", str(current),
                                  "--brave", str(self.brave), "--receipt", str(receipt)], capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_patch_advance_rejects_unknown_edits_before_mutation(self):
        current, receipt = self.patch_advance_fixture()
        before = self.receipt.read_bytes()
        (self.brave / "tracked.txt").write_text("private edit\n")
        result = self.advance(current, receipt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SOURCE_PATCH_ADVANCE_REFUSED", result.stdout)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertEqual((self.brave / "tracked.txt").read_text(), "private edit\n")
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertFalse(receipt.exists())

    def test_patch_advance_preflights_all_hunks_before_mutation(self):
        current, receipt = self.patch_advance_fixture()
        patch = current / "browser/integration/brave/patches/chromium/0002-second.patch"
        patch.write_text(patch.read_text().replace("-first", "-wrong"))
        git(current, "add", "browser")
        git(current, "commit", "-qm", "unapplicable fixture")
        before = git(self.chromium, "ls-files", "--stage")
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertEqual(git(self.chromium, "ls-files", "--stage"), before)
        self.assertFalse(receipt.exists())

    def test_patch_advance_rejects_multiple_changed_files(self):
        current, receipt = self.patch_advance_fixture(two_files=True)
        result = self.advance(current, receipt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one existing source-file", result.stdout)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertEqual((self.chromium / "extra.txt").read_text(), "old extra\n")

    def test_patch_advance_preserves_conflicting_receipt_and_symlink(self):
        current, receipt = self.patch_advance_fixture()
        receipt.parent.mkdir()
        receipt.write_text("private receipt")
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        self.assertEqual(receipt.read_text(), "private receipt")
        receipt.unlink()
        target = self.root / "private"
        target.write_text("private value")
        receipt.symlink_to(target)
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        self.assertTrue(receipt.is_symlink())
        self.assertEqual(target.read_text(), "private value")
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")

    def test_patch_advance_rolls_back_on_receipt_failure_and_can_retry(self):
        current, receipt = self.patch_advance_fixture()
        spec = importlib.util.spec_from_file_location("advance_state_fixture", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from types import SimpleNamespace
        args = SimpleNamespace(repository=current, brave=self.brave, receipt=receipt,
                               previous_repository=self.repo, previous_receipt=self.receipt,
                               require_clean=False)
        identity = {"integration": git(current, "rev-parse", "HEAD"), "brave": str(self.brave.resolve()),
                    "upstream": module.source_states(current, self.brave)}
        original_write = module.write_receipt
        def fail_receipt(path, value):
            if path == receipt:
                raise OSError("owned fixture write failure")
            original_write(path, value)
        with patch.object(module, "write_receipt", side_effect=fail_receipt):
            with self.assertRaises(OSError):
                module.advance_known_patch(args, identity)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertFalse(receipt.exists())
        self.assertEqual(self.advance(current, receipt).returncode, 0)

    def test_patch_advance_recovers_prepared_applied_file_without_rewriting(self):
        current, receipt = self.patch_advance_fixture()
        self.assertEqual(self.advance(current, receipt).returncode, 0)
        audit_path = receipt.with_name("integrated-brave-patch-advance.json")
        audit = json.loads(audit_path.read_text())
        audit["status"] = "prepared"
        audit.pop("source_after", None)
        audit_path.write_text(json.dumps(audit))
        receipt.unlink()
        timestamp = (self.chromium / "tracked.txt").stat().st_mtime_ns
        result = self.advance(current, receipt)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.chromium / "tracked.txt").stat().st_mtime_ns, timestamp)
        self.assertTrue(receipt.exists())

    def test_patch_advance_recovery_preserves_new_unknown_edit(self):
        current, receipt = self.patch_advance_fixture()
        self.assertEqual(self.advance(current, receipt).returncode, 0)
        audit_path = receipt.with_name("integrated-brave-patch-advance.json")
        audit = json.loads(audit_path.read_text())
        audit["status"] = "prepared"
        audit_path.write_text(json.dumps(audit))
        receipt.unlink()
        (self.chromium / "tracked.txt").write_text("private later edit\n")
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "private later edit\n")
        self.assertFalse(receipt.exists())

    def test_patch_advance_rejects_pin_or_overlay_changes(self):
        current, receipt = self.patch_advance_fixture()
        pin = current / "browser/config/v8.rev"
        before = pin.read_text()
        pin.write_text("wrong pin")
        git(current, "add", "browser")
        git(current, "commit", "-qm", "wrong pin fixture")
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        pin.write_text(before)
        overlay = current / "browser/integration/brave/overlay/ignored/overlay.cc"
        overlay.write_text("changed overlay")
        git(current, "add", "browser")
        git(current, "commit", "-qm", "overlay change fixture")
        self.assertNotEqual(self.advance(current, receipt).returncode, 0)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertFalse(receipt.exists())

    def test_patch_advance_preserves_concurrent_destination_edit(self):
        current, receipt = self.patch_advance_fixture()
        spec = importlib.util.spec_from_file_location("advance_concurrent_fixture", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from types import SimpleNamespace
        args = SimpleNamespace(repository=current, brave=self.brave, receipt=receipt,
                               previous_repository=self.repo, previous_receipt=self.receipt,
                               require_clean=False)
        identity = {"integration": git(current, "rev-parse", "HEAD"), "brave": str(self.brave.resolve()),
                    "upstream": module.source_states(current, self.brave)}
        original_atomic = module.atomic_source
        def concurrent_edit(path, content, mode):
            original_atomic(path, content, mode)
            path.write_text("private concurrent edit\n")
        with patch.object(module, "atomic_source", side_effect=concurrent_edit):
            with self.assertRaises(ValueError):
                module.advance_known_patch(args, identity)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "private concurrent edit\n")
        audit = json.loads(receipt.with_name("integrated-brave-patch-advance.json").read_text())
        self.assertEqual(audit["status"], "needs_review")
        self.assertFalse(receipt.exists())

    def test_patch_advance_serializes_checkout_updates(self):
        from brave_patch_advance import exclusive_source_update
        current, receipt = self.patch_advance_fixture()
        with exclusive_source_update(self.brave):
            result = self.advance(current, receipt)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Another patch advancement", result.stdout)
            self.assertEqual((self.chromium / "tracked.txt").read_text(), "second\n")
        self.assertEqual(self.advance(current, receipt).returncode, 0)

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
        shutil.copyfile(HELPER.with_name("brave_patch_contract.py"), helper_dir / "brave_patch_contract.py")
        shutil.copyfile(HELPER.with_name("brave_patch_advance.py"), helper_dir / "brave_patch_advance.py")
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

    def test_bootstrap_retains_pinned_release_tag(self):
        revision = "v1.2.3"
        git(self.brave, "tag", "-a", revision, "-m", "owned release fixture")
        worktree = self.root / "fresh-bootstrap"
        environment = {key: value for key, value in os.environ.items() if not key.startswith("REB_")}
        environment["REB_BRAVE_WORKTREE"] = str(worktree)
        result = subprocess.run(
            ["bash", str(HELPER.parent.parent / "scripts/bootstrap-brave.sh"),
             "--remote", str(self.brave), "--revision", revision],
            env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checkout = worktree / "src/brave"
        self.assertEqual(git(checkout, "rev-parse", f"{revision}^{{commit}}"),
                         git(checkout, "rev-parse", "HEAD"))

    def test_wrapper_records_prepared_sources_and_still_rejects_user_edits(self):
        scripts = self.repo / "scripts"
        scripts.mkdir()
        wrapper = scripts / "build-integrated-brave.sh"
        shutil.copyfile(HELPER.parent.parent / "scripts/build-integrated-brave.sh", wrapper)
        helper_dir = self.repo / "tools"
        helper_dir.mkdir()
        shutil.copyfile(HELPER, helper_dir / HELPER.name)
        shutil.copyfile(HELPER.with_name("brave_patch_contract.py"), helper_dir / "brave_patch_contract.py")
        shutil.copyfile(HELPER.with_name("brave_patch_advance.py"), helper_dir / "brave_patch_advance.py")
        output = self.chromium / "out/Component_arm64"
        executable = output / "Brave Browser.app/Contents/MacOS/Brave Browser"
        phases = self.root / "phases"
        toolchain = scripts / "brave-toolchain.sh"
        toolchain.write_text(
            "#!/bin/sh\nset -eu\n"
            f"printf '%s\\n' \"$*\" >> {shlex.quote(str(phases))}\n"
            # Actual Brave build preparation rewrites tracked branding inputs.
            f"printf 'prepared branding\\n' > {shlex.quote(str(self.chromium / 'tracked.txt'))}\n"
            # A Ninja policy action also copies source inputs after prepare-only.
            f"if [ \"$*\" != 'build --prepare_only' ]; then printf 'derived policy\\n' > {shlex.quote(str(self.chromium / 'policy.yaml'))}; fi\n"
            f"mkdir -p {shlex.quote(str(executable.parent))}\n"
            f"printf 'is_component_build = true\\n' > {shlex.quote(str(output / 'args.gn'))}\n"
            f"printf 'built browser\\n' > {shlex.quote(str(executable))}\n"
            f"chmod 755 {shlex.quote(str(executable))}\n"
        )
        toolchain.chmod(0o755)
        sync = scripts / "sync-browser-integration.sh"
        sync.write_text("#!/bin/sh\nexit 0\n")
        sync.chmod(0o755)
        demo = self.repo / "build/reb-event-demo"
        demo.parent.mkdir()
        demo.write_text("#!/bin/sh\nexit 0\n")
        demo.chmod(0o755)
        git(self.repo, "add", "scripts", "tools")
        git(self.repo, "commit", "-qm", "build preparation fixture")
        mocks = self.root / "bin"
        mocks.mkdir()
        for name, content in {
            "uname": 'if [ "$1" = -s ]; then echo Darwin; else echo arm64; fi',
            "xcodebuild": "exit 0",
            "df": "printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\nfixture 999999999 0 999999999 0%% /\\n'",
            "make": "exit 0", "cargo": "exit 0", "c++": "exit 0", "codesign": "exit 0",
        }.items():
            target = mocks / name
            target.write_text("#!/bin/sh\n" + content + "\n")
            target.chmod(0o755)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("REB_")}
        environment.update(PATH=str(mocks) + os.pathsep + os.environ["PATH"],
                           REB_BRAVE_DIRECTORY=str(self.brave), REB_BRAVE_JOBS="6",
                           SISO_LIMITS="remote=2,local=3")
        with toolchain.open("a") as stream:
            stream.write(f"printf '%s\\n' \"$SISO_LIMITS\" >> {shlex.quote(str(self.root / 'limits'))}\n")
        git(self.repo, "add", "scripts")
        git(self.repo, "commit", "-qm", "local executor fixture")
        command = ["bash", str(wrapper)]
        result = subprocess.run(command, env=environment, capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(phases.read_text().splitlines(), [
            "build --prepare_only", "build --target components/policy:generate_policy_templates",
            "build --ninja j:6"])
        self.assertEqual((self.root / "limits").read_text().splitlines(), ["remote=2,local=3"] * 3)
        self.assertTrue((demo.parent / "integrated-brave-complete.json").is_file())
        # A failing native target must prevent the aggregate browser compile.
        (mocks / "make").write_text('#!/bin/sh\nif [ "$1" = brave-foundation-check ]; then exit 1; fi\nexit 0\n')
        count = len(phases.read_text().splitlines())
        failed = subprocess.run(command, env=environment, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(phases.read_text().splitlines()[count:], [
            "build --prepare_only", "build --target components/policy:generate_policy_templates"])
        before = phases.read_bytes()
        (self.chromium / "tracked.txt").write_text("private user edit\n")
        result = subprocess.run(command, env=environment, capture_output=True,
                                text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Upstream edits", result.stderr)
        self.assertEqual(phases.read_bytes(), before)
        self.assertEqual((self.chromium / "tracked.txt").read_text(), "private user edit\n")

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

    def next_source(self, changes):
        number = getattr(self, "handoff_number", 0) + 1
        self.handoff_number = number
        repository = self.root / f"next-source-{number}"
        git(self.repo, "worktree", "add", "--detach", str(repository), "HEAD")
        for name, content in changes.items():
            path = repository / name
            if content is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
        git(repository, "add", "-A")
        git(repository, "commit", "-qm", "compatible tooling fixture")
        return repository

    def adopt(self, repository):
        receipt = repository / "build/integrated-brave-state.json"
        result = subprocess.run([
            sys.executable, str(HELPER), "adopt", "--repository", str(repository),
            "--brave", str(self.brave), "--receipt", str(receipt),
            "--previous-repository", str(self.repo), "--previous-receipt", str(self.receipt),
        ], capture_output=True, text=True, check=False)
        return result, receipt

    def test_handoff_preserves_proof_and_reuses_only_identical_inputs(self):
        self.assertEqual(self.call("record").returncode, 0)
        before = self.receipt.read_bytes()
        repository = self.next_source({"tools/build-note.py": "# tooling only\n"})
        result, receipt = self.adopt(repository)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertEqual(json.loads(receipt.read_text())["integration"], git(repository, "rev-parse", "HEAD"))
        self.assertEqual(self.adopt(repository)[0].returncode, 0)

    def test_handoff_refuses_upstream_edits_and_preserves_destination(self):
        self.assertEqual(self.call("record").returncode, 0)
        repository = self.next_source({"docs/build.md": "Tooling update\n"})
        target = self.v8 / "tracked.txt"
        target.write_text("private upstream edit\n")
        result, receipt = self.adopt(repository)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(receipt.exists())
        self.assertEqual(target.read_text(), "private upstream edit\n")

    def test_handoff_does_not_replace_an_existing_or_symlinked_receipt(self):
        self.assertEqual(self.call("record").returncode, 0)
        before = self.receipt.read_bytes()
        repository = self.next_source({"docs/build.md": "Tooling update\n"})
        receipt = repository / "build/integrated-brave-state.json"
        receipt.parent.mkdir()
        receipt.symlink_to(self.receipt)
        self.assertNotEqual(self.adopt(repository)[0].returncode, 0)
        self.assertTrue(receipt.is_symlink())
        self.assertEqual(self.receipt.read_bytes(), before)
        receipt.unlink()
        receipt.write_text('{"preserve":"existing proof"}\n')
        self.assertNotEqual(self.adopt(repository)[0].returncode, 0)
        self.assertEqual(receipt.read_text(), '{"preserve":"existing proof"}\n')

    def test_handoff_refuses_production_and_overlay_changes(self):
        self.assertEqual(self.call("record").returncode, 0)
        for relative in ("apps/new.cpp", "browser/integration/brave/overlay/ignored/overlay.cc"):
            with self.subTest(relative=relative):
                repository = self.next_source({relative: "changed production input\n"})
                result, receipt = self.adopt(repository)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(receipt.exists())

    def test_handoff_allows_exact_patch_owner_relocation_but_not_hunk_changes(self):
        old = "browser/integration/brave/patches/chromium/0003.patch"
        new = "browser/integration/brave/patches/v8/0000.patch"
        text = ("diff --git a/v8/tracked.txt b/v8/tracked.txt\n"
                "--- a/v8/tracked.txt\n+++ b/v8/tracked.txt\n"
                "@@ -1 +1 @@\n-original\n+patched\n")
        path = self.repo / old
        path.parent.mkdir(parents=True)
        path.write_text(text)
        git(self.repo, "add", "browser")
        git(self.repo, "commit", "-qm", "historical nested patch fixture")
        (self.v8 / "tracked.txt").write_text("patched\n")
        self.assertEqual(self.call("record").returncode, 0)
        before = self.receipt.read_bytes()
        relocated = text.replace("a/v8/", "a/").replace("b/v8/", "b/")
        repository = self.next_source({old: None, new: relocated})
        result, receipt = self.adopt(repository)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.receipt.read_bytes(), before)
        check = subprocess.run([sys.executable, str(HELPER), "check", "--repository", str(repository),
                                "--brave", str(self.brave), "--receipt", str(receipt)],
                               capture_output=True, text=True, check=False)
        self.assertEqual(check.returncode, 0, check.stderr)
        changed = self.next_source({old: None, new: relocated.replace("+patched", "+different")})
        result, receipt = self.adopt(changed)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(receipt.exists())

    def sync_fixture(self, nested=False):
        scripts = self.repo / "scripts"
        scripts.mkdir()
        shutil.copyfile(HELPER.parent.parent / "scripts/sync-browser-integration.sh", scripts / "sync.sh")
        tools = self.repo / "tools"
        tools.mkdir()
        shutil.copyfile(HELPER.with_name("brave_patch_contract.py"), tools / "brave_patch_contract.py")
        patches = self.repo / "browser/integration/brave/patches"
        for folder, value in (("", "Brave"), ("chromium", "Chromium")):
            directory = patches / folder
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "0001.patch").write_text(
                "diff --git a/tracked.txt b/tracked.txt\n--- a/tracked.txt\n+++ b/tracked.txt\n"
                f"@@ -1 +1 @@\n-original\n+{value}\n")
        if nested:
            (patches / "chromium/0002.patch").write_text(
                "diff --git a/v8/tracked.txt b/v8/tracked.txt\n--- a/v8/tracked.txt\n+++ b/v8/tracked.txt\n"
                "@@ -1 +1 @@\n-original\n+nested\n")
        else:
            directory = patches / "v8"
            directory.mkdir()
            (directory / "0001.patch").write_text(
                "diff --git a/tracked.txt b/tracked.txt\n--- a/tracked.txt\n+++ b/tracked.txt\n"
                "@@ -1 +1,2 @@\n-original\n+first\n+context\n"
                "diff --git a/added.txt b/added.txt\nnew file mode 100644\n--- /dev/null\n+++ b/added.txt\n"
                "@@ -0,0 +1 @@\n+owned regression\n")
            (directory / "0002.patch").write_text(
                "diff --git a/tracked.txt b/tracked.txt\n--- a/tracked.txt\n+++ b/tracked.txt\n"
                "@@ -1,2 +1,2 @@\n-first\n+second\n context\n")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("REB_")}
        environment["REB_BRAVE_DIRECTORY"] = str(self.brave)
        return lambda: subprocess.run(["bash", str(scripts / "sync.sh")], env=environment,
                                      capture_output=True, text=True, check=False)

    def test_sync_keeps_applied_added_files_and_real_indexes_untouched(self):
        sync = self.sync_fixture()
        first = sync()
        self.assertEqual(first.returncode, 0, first.stderr)
        target = self.v8 / "added.txt"
        stamp = 900_000_000_000_000_000
        os.utime(target, ns=(stamp, stamp))
        second = sync()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("Already applied: V8 patch stack", second.stdout)
        self.assertEqual(target.stat().st_mtime_ns, stamp)
        self.assertEqual(git(self.v8, "diff", "--cached"), "")
        self.assertEqual((self.v8 / "tracked.txt").read_text(), "second\ncontext\n")

    def test_sync_refuses_nested_owner_before_any_source_mutation(self):
        result = self.sync_fixture(nested=True)()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("belongs to nested checkout", result.stderr)
        for root in (self.brave, self.chromium, self.v8):
            self.assertEqual((root / "tracked.txt").read_text(), "original\n")

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
