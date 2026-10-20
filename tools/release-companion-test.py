#!/usr/bin/env python3
"""Companion-only release contracts using synthetic archives and mocked GitHub."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "release_companion", Path(__file__).with_name("release-companion.py")
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
SHA = "a" * 40


class CompanionRelease(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "build/release-companion"
        self.output.mkdir(parents=True)
        self.plist = self.root / "apps/research-ui/macos/Info.plist"
        self.plist.parent.mkdir(parents=True)
        self.info = {
            "CFBundleShortVersionString": "0.3.2",
            "CFBundleVersion": "32",
            "OriginTraceReleaseType": "companion",
        }
        self.plist.write_bytes(plistlib.dumps(self.info))
        self.write_archive()
        self.environment = {
            "RELEASE_TAG": "v0.3.2", "RELEASE_SOURCE_SHA": SHA,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "sunghoojung/reverse-engineering-browser",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
        }
        patches = [
            patch.dict(os.environ, self.environment, clear=True),
            patch.object(HELPER.subprocess, "check_output", return_value=SHA + "\n"),
            patch.object(HELPER.platform, "system", return_value="Darwin"),
            patch.object(HELPER.platform, "machine", return_value="arm64"),
            patch.object(HELPER.platform, "mac_ver", return_value=("15.7.1", ("", "", ""), "arm64")),
            patch.object(HELPER.PUBLISHER, "urlopen", side_effect=AssertionError("No network")),
        ]
        for mocked in patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def write_archive(self, info=None, extra=None, content=b"synthetic companion"):
        with zipfile.ZipFile(self.output / HELPER.ARCHIVE, "w") as archive:
            archive.writestr(HELPER.PLIST_PATH, plistlib.dumps(self.info if info is None else info))
            archive.writestr("Origin Trace.app/Contents/MacOS/OriginTrace", content)
            if extra is not None:
                archive.writestr(extra, b"unexpected")

    def reject_publish(self):
        with patch.object(HELPER.PUBLISHER, "establish_tag") as establish, patch.object(
            HELPER.subprocess, "run"
        ) as command:
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                HELPER.publish(self.root)
        establish.assert_not_called()
        command.assert_not_called()

    def remote_release(self):
        return {"draft": False, "assets": [
            {"name": name, "state": "uploaded", "size": (self.output / name).stat().st_size,
             "digest": f"sha256:{HELPER.PUBLISHER.digest(self.output / name)}"}
            for name in (HELPER.ARCHIVE, HELPER.PROVENANCE, HELPER.CHECKSUMS)
        ]}

    def test_prepare_binds_exact_source_run_archive_and_companion_limits(self):
        HELPER.prepare(self.root)
        manifest = json.loads((self.output / HELPER.PROVENANCE).read_text())
        self.assertEqual(manifest["release"], "v0.3.2")
        self.assertEqual(manifest["source_commit"], SHA)
        self.assertEqual(manifest["workflow_run"], {
            "id": "123", "attempt": "2", "event": "workflow_dispatch",
        })
        self.assertTrue(manifest["validation_run"].endswith("/123/attempts/2"))
        self.assertEqual(manifest["origin_trace"]["platform"], "macOS 15 arm64")
        self.assertFalse(manifest["origin_trace"]["apple_notarized"])
        self.assertEqual(manifest["origin_trace"]["signing"], "ad-hoc")
        self.assertEqual(manifest["browser"], {
            "included": False, "rebuilt": False, "matched_pair": False,
        })
        self.assertEqual({path.name for path in self.output.iterdir()}, {
            HELPER.ARCHIVE, HELPER.PROVENANCE, HELPER.CHECKSUMS, HELPER.NOTES,
        })
        sums = (self.output / HELPER.CHECKSUMS).read_text().splitlines()
        self.assertEqual(len(sums), 2)
        for line in sums:
            checksum, name = line.split("  ")
            self.assertEqual(checksum, HELPER.PUBLISHER.digest(self.output / name))
        notes = (self.output / HELPER.NOTES).read_text()
        for limit in HELPER.LIMITS:
            self.assertIn(limit, notes)
        self.assertIn("lack the new native VM and runtime-buffer features", notes)
        self.assertIn("Stock Chrome CDP testing is not proof", notes)
        self.assertIn("offline escape", notes)
        self.assertIn("macOS 13/14 compatibility is not established", notes)
        self.assertEqual(manifest["checks"], HELPER.CHECKS)

    def test_warning_acceptance_claims_cover_choices_and_keep_fake_browser_boundary(self):
        HELPER.prepare(self.root)
        manifest = json.loads((self.output / HELPER.PROVENANCE).read_text())
        checks = "\n".join(manifest["checks"])
        notes = (self.output / HELPER.NOTES).read_text()
        for claim in ("Production AppKit warning via XCUITest", "default and clicked Offline",
                      "explicit fake-browser launch", "failure Retry", "later-session warning",
                      "modal-reopen acceptance", "independent fake-browser launch receipts"):
            self.assertIn(claim, checks)
            self.assertIn(claim, notes)
        boundary = (
            "Warning interaction QA uses an owned fake-browser executable only; "
            "it does not establish native browser/companion compatibility or capture coverage."
        )
        self.assertIn(boundary, manifest["limits"])
        self.assertIn(boundary, notes)
        self.assertNotIn("not claimed as native interaction QA", notes)

    def test_pull_request_can_prepare_only_and_workflow_sha_is_not_source_sha(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_SHA": "b" * 40}):
            HELPER.prepare(self.root)
            self.reject_publish()

    def test_invalid_inputs_fail_before_creating_metadata(self):
        for key, value in [
            ("RELEASE_TAG", "v0.3.1"), ("RELEASE_TAG", "v0.3.3"),
            ("RELEASE_SOURCE_SHA", "short"), ("RELEASE_SOURCE_SHA", "b" * 40),
            ("GITHUB_REPOSITORY", "another/repository"),
            ("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request_target"),
            ("GITHUB_RUN_ID", ""), ("GITHUB_RUN_ID", "../123"),
            ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_RUN_ATTEMPT", "01"),
        ]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError):
                    HELPER.prepare(self.root)
        self.assertEqual([path.name for path in self.output.iterdir()], [HELPER.ARCHIVE])

    def test_prepare_requires_native_mac_arm64(self):
        for method, value in [("system", "Linux"), ("machine", "x86_64"),
                              ("mac_ver", ("14.7", ("", "", ""), "arm64"))]:
            with self.subTest(method=method), patch.object(HELPER.platform, method, return_value=value):
                with self.assertRaises(ValueError):
                    HELPER.prepare(self.root)

    def test_source_and_packaged_versions_and_release_type_must_match(self):
        for location in ("source", "archive"):
            for key, value in [("CFBundleShortVersionString", "0.3.1"),
                               ("CFBundleVersion", "31"), ("OriginTraceReleaseType", "paired")]:
                with self.subTest(location=location, key=key):
                    bad = {**self.info, key: value}
                    self.plist.write_bytes(plistlib.dumps(bad if location == "source" else self.info))
                    self.write_archive(info=bad if location == "archive" else self.info)
                    with self.assertRaises(ValueError):
                        HELPER.prepare(self.root)

    def test_archive_rejects_another_app_unsafe_paths_or_duplicate_entries(self):
        for extra in ("Brave Browser Development.app/Contents/Info.plist", "../outside",
                      "Origin Trace.app/../outside", "Origin Trace.app/Contents/Brave.app/file",
                      "Origin Trace.app/Contents\\file", HELPER.PLIST_PATH):
            with self.subTest(extra=extra):
                with self.assertWarns(UserWarning) if extra == HELPER.PLIST_PATH else self.subTest():
                    self.write_archive(extra=extra)
                with self.assertRaises(ValueError):
                    HELPER.prepare(self.root)

    def test_ditto_resource_forks_are_allowed(self):
        self.write_archive(extra="__MACOSX/Origin Trace.app/Contents/._Info.plist")
        with zipfile.ZipFile(self.output / HELPER.ARCHIVE, "a") as archive:
            archive.writestr("__MACOSX/._Origin Trace.app", b"synthetic resource fork")
        HELPER.prepare(self.root)

    def test_preparation_refuses_stale_metadata_or_extra_browser(self):
        for name in (HELPER.NOTES, "Brave.zip"):
            with self.subTest(name=name):
                extra = self.output / name
                extra.write_text("stale")
                with self.assertRaises(ValueError):
                    HELPER.prepare(self.root)
                extra.unlink()

    def test_publish_verifies_fresh_tag_and_exact_remote_assets_on_linux(self):
        HELPER.prepare(self.root)
        with patch.object(HELPER.PUBLISHER, "establish_tag") as establish, patch.object(
            HELPER.PUBLISHER, "tag_commit", return_value=SHA
        ) as tag, patch.object(HELPER.PUBLISHER, "api", return_value=self.remote_release()) as api, \
                patch.object(HELPER.subprocess, "run") as command, \
                patch.object(HELPER.platform, "system", return_value="Linux"):
            HELPER.publish(self.root)
        establish.assert_called_once_with("v0.3.2", SHA, "workflow_dispatch")
        tag.assert_called_once_with("v0.3.2")
        api.assert_called_once_with("releases/tags/v0.3.2")
        command.assert_called_once_with([
            "gh", "release", "create", "v0.3.2", "--repo", HELPER.REPOSITORY,
            *[str(self.output / name) for name in (HELPER.ARCHIVE, HELPER.PROVENANCE, HELPER.CHECKSUMS)],
            "--verify-tag", "--target", SHA, "--title", "Origin Trace v0.3.2 (companion only)",
            "--notes-file", str(self.output / HELPER.NOTES),
        ], check=True)

    def test_publish_requires_dispatch_and_same_run_attempt(self):
        HELPER.prepare(self.root)
        for key, value in [("GITHUB_EVENT_NAME", "push"), ("GITHUB_EVENT_NAME", "pull_request"),
                           ("GITHUB_RUN_ID", "124"), ("GITHUB_RUN_ATTEMPT", "3")]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                self.reject_publish()

    def test_modified_provenance_rejected_even_with_updated_checksums(self):
        HELPER.prepare(self.root)
        path = self.output / HELPER.PROVENANCE
        original = path.read_text()
        for key, value in [("source_commit", "b" * 40), ("release", "v0.3.1"),
                           ("release_type", "paired"), ("browser", {"included": True}),
                           ("limits", []), ("unexpected", True)]:
            with self.subTest(key=key):
                manifest = {**json.loads(original), key: value}
                path.write_text(json.dumps(manifest, indent=2) + "\n")
                (self.output / HELPER.CHECKSUMS).write_text(HELPER.checksums_text(self.output))
                self.reject_publish()
        path.write_text(original)

    def test_modified_notes_checksums_and_archive_rejected(self):
        HELPER.prepare(self.root)
        for name in (HELPER.NOTES, HELPER.CHECKSUMS):
            path = self.output / name
            original = path.read_text()
            for content in ("", original + "unexpected\n", original + original):
                with self.subTest(name=name, content=content):
                    path.write_text(content)
                    self.reject_publish()
            path.write_text(original)
        self.write_archive(content=b"different companion")
        self.reject_publish()

    def test_publish_rejects_missing_extra_symlink_and_directory_assets(self):
        HELPER.prepare(self.root)
        extra = self.output / "Brave.zip"
        extra.write_bytes(b"unexpected browser")
        self.reject_publish()
        extra.unlink()
        notes = self.output / HELPER.NOTES
        content = notes.read_bytes()
        notes.unlink()
        self.reject_publish()
        notes.mkdir()
        self.reject_publish()
        notes.rmdir()
        outside = self.root / "notes"
        outside.write_bytes(content)
        notes.symlink_to(outside)
        self.reject_publish()

    def test_existing_tag_or_release_never_creates_or_updates_release(self):
        HELPER.prepare(self.root)
        for release, tag in [({"id": 1}, None), (None, SHA)]:
            with self.subTest(release=release, tag=tag), patch.object(
                HELPER.PUBLISHER, "api", return_value=release
            ) as api, patch.object(HELPER.PUBLISHER, "tag_commit", return_value=tag), \
                    patch.object(HELPER.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    HELPER.publish(self.root)
                self.assertEqual(api.call_count, 1)
                command.assert_not_called()

    def test_remote_missing_or_mismatched_assets_fail_after_single_create(self):
        HELPER.prepare(self.root)
        for failure in ("missing", "digest", "size", "draft"):
            remote = self.remote_release()
            if failure == "missing":
                remote["assets"].pop()
            elif failure == "draft":
                remote["draft"] = True
            else:
                remote["assets"][0][failure] = "wrong" if failure == "digest" else 0
            with self.subTest(failure=failure), patch.object(HELPER.PUBLISHER, "establish_tag"), \
                    patch.object(HELPER.PUBLISHER, "tag_commit", return_value=SHA), \
                    patch.object(HELPER.PUBLISHER, "api", return_value=remote), \
                    patch.object(HELPER.subprocess, "run") as command:
                with self.assertRaises(ValueError):
                    HELPER.publish(self.root)
                command.assert_called_once()

    def test_changed_remote_tag_and_create_failure_are_not_retried(self):
        HELPER.prepare(self.root)
        with patch.object(HELPER.PUBLISHER, "establish_tag"), patch.object(
            HELPER.PUBLISHER, "tag_commit", return_value="b" * 40
        ), patch.object(HELPER.subprocess, "run") as command:
            with self.assertRaises(ValueError):
                HELPER.publish(self.root)
            command.assert_called_once()
        with patch.object(HELPER.PUBLISHER, "establish_tag"), patch.object(
            HELPER.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "gh")
        ) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                HELPER.publish(self.root)
            command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
