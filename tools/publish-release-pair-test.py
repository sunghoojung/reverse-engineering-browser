#!/usr/bin/env python3
"""Fail-closed publication contracts with mocked GitHub responses; no writes."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError


SPEC = importlib.util.spec_from_file_location(
    "publish_release_pair", Path(__file__).with_name("publish-release-pair.py")
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
SHA = "a" * 40
TAG = HELPER.REVIEWED_TAG
ROOT = Path(__file__).resolve().parents[1]


class Publication(unittest.TestCase):
    def test_remote_assets_require_complete_sizes_and_digests(self):
        valid = {"draft": False, "assets": [
            {"name": "pair.zip", "size": 12, "digest": "sha256:abc", "state": "uploaded"},
        ]}
        HELPER.verify_assets(valid, {"pair.zip": (12, "abc")})
        for key, value in [("size", 11), ("digest", None), ("digest", "sha256:wrong"),
                           ("state", "starter"), ("name", "other.zip")]:
            with self.subTest(key=key, value=value):
                invalid = {"draft": False, "assets": [{**valid["assets"][0], key: value}]}
                with self.assertRaises(ValueError):
                    HELPER.verify_assets(invalid, {"pair.zip": (12, "abc")})
        with self.assertRaises(ValueError):
            HELPER.verify_assets({"draft": False, "assets": []}, {"pair.zip": (12, "abc")})
        with self.assertRaises(ValueError):
            HELPER.verify_assets({**valid, "draft": True}, {"pair.zip": (12, "abc")})
        HELPER.verify_assets({**valid, "draft": True}, {"pair.zip": (12, "abc")}, draft=True)
        with self.assertRaises(ValueError):
            HELPER.verify_assets(valid, {"pair.zip": (12, "abc")}, draft=True)

    def test_only_get_404_means_absence(self):
        for method, status in [("GET", 404), ("GET", 401), ("GET", 403),
                               ("GET", 500), ("POST", 404), ("POST", 422)]:
            with self.subTest(method=method, status=status), patch.dict(
                os.environ, {"GH_TOKEN": "synthetic-test-value"}
            ), patch.object(HELPER, "urlopen", side_effect=HTTPError(
                "https://api.github.com", status, "synthetic", None, None
            )):
                if method == "GET" and status == 404:
                    self.assertIsNone(HELPER.api("test", method))
                else:
                    with self.assertRaises(HTTPError):
                        HELPER.api("test", method)

    def test_fresh_tag_uses_create_not_update(self):
        with patch.object(HELPER, "api", return_value=None) as api, patch.object(
            HELPER, "tag_commit", side_effect=[None, SHA]
        ):
            HELPER.establish_tag(TAG, SHA, "workflow_dispatch")
        self.assertEqual(api.call_args_list, [
            call(f"releases/tags/{TAG}"),
            call("git/refs", "POST", {"ref": f"refs/tags/{TAG}", "sha": SHA}),
        ])

    def test_existing_release_stops_before_tag_creation(self):
        with patch.object(HELPER, "api", return_value={"id": 1}) as api:
            with self.assertRaises(ValueError):
                HELPER.establish_tag(TAG, SHA, "workflow_dispatch")
        self.assertEqual(api.call_count, 1)

    def test_dispatch_adopts_only_a_tag_naming_the_tested_source(self):
        with patch.object(HELPER, "api", return_value=None) as api, patch.object(
            HELPER, "tag_commit", return_value=SHA
        ):
            HELPER.establish_tag(TAG, SHA, "workflow_dispatch")
        self.assertEqual(api.call_args_list, [call(f"releases/tags/{TAG}")])
        with patch.object(HELPER, "api", return_value=None) as api, patch.object(
            HELPER, "tag_commit", return_value="b" * 40
        ):
            with self.assertRaises(ValueError):
                HELPER.establish_tag(TAG, SHA, "workflow_dispatch")
        self.assertEqual(api.call_count, 1)

    def test_concurrent_tag_creation_error_is_not_retried(self):
        conflict = HTTPError("https://api.github.com", 422, "exists", None, None)
        with patch.object(HELPER, "api", side_effect=[None, conflict]) as api, patch.object(
            HELPER, "tag_commit", return_value=None
        ):
            with self.assertRaises(HTTPError):
                HELPER.establish_tag(TAG, SHA, "workflow_dispatch")
        self.assertEqual(api.call_count, 2)

    def test_mismatched_created_tag_is_rejected(self):
        with patch.object(HELPER, "api", return_value=None), patch.object(
            HELPER, "tag_commit", side_effect=[None, "b" * 40]
        ):
            with self.assertRaises(ValueError):
                HELPER.establish_tag(TAG, SHA, "workflow_dispatch")

    def test_tag_push_must_match_without_mutation(self):
        for current in [SHA, "b" * 40, None]:
            with self.subTest(current=current), patch.object(
                HELPER, "api", return_value=None
            ) as api, patch.object(HELPER, "tag_commit", return_value=current):
                if current == SHA:
                    HELPER.establish_tag(TAG, SHA, "push")
                else:
                    with self.assertRaises(ValueError):
                        HELPER.establish_tag(TAG, SHA, "push")
                self.assertEqual(api.call_args_list, [call(f"releases/tags/{TAG}")])


class FakeGitHub:
    """Release endpoints with drafts, as the publication helper uses them."""

    def __init__(self, expected, damage=None):
        self.expected, self.damage = expected, damage
        self.releases, self.calls, self.next_id = [], [], 1

    def release(self, title, draft=True, target=SHA):
        release = {"id": self.next_id, "tag_name": TAG, "name": title, "draft": draft,
                   "target_commitish": target, "assets": [
                       {"name": name, "state": "uploaded", "size": size, "digest": f"sha256:{checksum}"}
                       for name, (size, checksum) in self.expected.items()]}
        self.next_id += 1
        self.releases.append(release)
        return release

    def api(self, path, method="GET", data=None):
        self.calls.append((method, path))
        if path.startswith("releases?"):
            return [dict(release) for release in self.releases]
        if path == f"releases/tags/{TAG}":
            return next((release for release in self.releases if not release["draft"]), None)
        identifier = int(path.split("/")[1])
        release = next(release for release in self.releases if release["id"] == identifier)
        if method == "DELETE":
            self.releases.remove(release)
            return None
        release.update(data)
        return release

    def run(self, command, check):
        title = command[command.index("--title") + 1]
        release = self.release(title)
        if self.damage:
            release["assets"][0]["digest"] = "sha256:damaged"


class DraftPublication(unittest.TestCase):
    expected = {"pair.zip": (12, "abc"), f"SHA256SUMS-{TAG}.txt": (64, "def")}
    title = f"Origin Trace + Brave {TAG}"

    def publish(self, github, tag_commit=SHA):
        with patch.object(HELPER, "api", side_effect=github.api), patch.object(
            HELPER.subprocess, "run", side_effect=github.run
        ) as command, patch.object(HELPER, "tag_commit", return_value=tag_commit):
            try:
                HELPER.publish_verified(TAG, SHA, [Path("pair.zip")], self.expected, self.title,
                                        Path("release-notes.md"))
            finally:
                self.command = command

    def test_verified_draft_is_published(self):
        github = FakeGitHub(self.expected)
        self.publish(github)
        self.assertIn("--draft", self.command.call_args.args[0])
        self.assertEqual([release["draft"] for release in github.releases], [False])

    def test_damaged_upload_is_deleted_before_publication(self):
        github = FakeGitHub(self.expected, damage=True)
        with self.assertRaises(ValueError):
            self.publish(github)
        self.assertEqual(github.releases, [])
        self.assertNotIn(("PATCH", "releases/1"), github.calls)

    def test_moved_tag_withdraws_nothing_it_did_not_publish(self):
        github = FakeGitHub(self.expected)
        with self.assertRaises(ValueError):
            self.publish(github, tag_commit="b" * 40)
        self.assertEqual(github.releases, [])

    def test_failed_published_check_withdraws_to_a_draft(self):
        github = FakeGitHub(self.expected)
        original = github.api

        def lose_asset(path, method="GET", data=None):
            result = original(path, method, data)
            if path == f"releases/tags/{TAG}" and result:
                result = {**result, "assets": result["assets"][:1]}
            return result

        github.api = lose_asset
        with self.assertRaises(ValueError):
            self.publish(github)
        self.assertEqual([release["draft"] for release in github.releases], [True])

    def test_create_failure_is_not_retried_or_published(self):
        github = FakeGitHub(self.expected)
        github.run = Mock(side_effect=subprocess.CalledProcessError(1, "gh"))
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish(github)
        self.command.assert_called_once()
        self.assertFalse([entry for entry in github.calls if entry[0] != "GET"])

    def test_rerun_replaces_only_its_own_interrupted_draft(self):
        github = FakeGitHub(self.expected)
        github.release(self.title)
        self.publish(github)
        self.assertEqual([release["draft"] for release in github.releases], [False])
        for other in ({"title": "Someone else's draft"}, {"title": self.title, "target": "b" * 40}):
            with self.subTest(other=other):
                github = FakeGitHub(self.expected)
                github.release(**other)
                with self.assertRaises(ValueError):
                    self.publish(github)
                self.command.assert_not_called()
                self.assertEqual(len(github.releases), 1)


class Admission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        previous = os.getcwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, previous)
        self.directory = Path("build/release-pair")
        self.directory.mkdir(parents=True)
        self.names = [
            f"Origin-Trace-{TAG}-macos.zip",
            f"Brave-Browser-Development-{HELPER.REVIEWED_BRAVE_TAG}-macos-arm64.zip",
            f"Brave-Browser-Development-{HELPER.REVIEWED_BRAVE_TAG}-macos-arm64.provenance.json",
            f"Origin-Trace-Brave-{TAG}.provenance.json",
        ]
        for name in self.names[:3]:
            (self.directory / name).write_text(f"synthetic {name}")
        (self.directory / self.names[3]).write_text(
            json.dumps({"release": TAG, "source_commit": SHA}))
        (self.directory / "release-notes.md").write_text("synthetic notes")
        self.write_sums(self.names)
        self.environment = {
            "RELEASE_TAG": TAG, "RELEASE_SOURCE_SHA": SHA,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GH_TOKEN": "synthetic-test-value",
        }

    def write_sums(self, names):
        (self.directory / f"SHA256SUMS-{TAG}.txt").write_text("".join(
            f"{HELPER.digest(self.directory / name)}  {name}\n" for name in names))

    def run_main(self):
        with patch.dict(os.environ, self.environment, clear=True), patch.object(
            HELPER, "establish_tag"
        ) as establish, patch.object(HELPER, "publish_verified") as publish:
            try:
                HELPER.main()
            finally:
                self.calls = establish, publish

    def test_reviewed_pair_publishes_exact_assets(self):
        self.run_main()
        establish, publish = self.calls
        establish.assert_called_once_with(TAG, SHA, "workflow_dispatch")
        tag, source, assets, expected, title, notes = publish.call_args.args
        self.assertEqual((tag, source, title), (TAG, SHA, f"Origin Trace + Brave {TAG}"))
        self.assertEqual([path.name for path in assets], sorted(self.names) + [f"SHA256SUMS-{TAG}.txt"])
        self.assertEqual(set(expected), {path.name for path in assets})
        self.assertEqual(notes, self.directory / "release-notes.md")

    def test_other_tags_and_assets_stop_before_any_publication(self):
        cases = [("tag", "v0.3.1"), ("tag", "v0.5.1"), ("event", "pull_request"),
                 ("sums", self.names[:3]), ("sums", self.names + ["release-notes.md"])]
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                self.write_sums(self.names)
                if kind == "tag":
                    self.environment["RELEASE_TAG"] = value
                elif kind == "event":
                    self.environment["GITHUB_EVENT_NAME"] = value
                else:
                    self.write_sums(value)
                with self.assertRaises(ValueError):
                    self.run_main()
                for mocked in self.calls:
                    mocked.assert_not_called()
                self.environment.update(RELEASE_TAG=TAG, GITHUB_EVENT_NAME="workflow_dispatch")

    def test_workflow_and_application_name_the_reviewed_release(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(re.findall(r'\[\[ "\$REQUESTED_TAG" == (v[0-9.]+) \]\]', workflow), [TAG])
        with (ROOT / "apps/research-ui/macos/Info.plist").open("rb") as source:
            self.assertEqual("v" + plistlib.load(source)["CFBundleShortVersionString"], TAG)


if __name__ == "__main__":
    unittest.main()
