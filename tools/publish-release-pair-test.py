#!/usr/bin/env python3
"""Fail-closed publication contracts with mocked GitHub responses; no writes."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import tempfile
import unittest
from unittest.mock import call, patch
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

    def test_existing_dispatch_tag_is_never_adopted(self):
        with patch.object(HELPER, "api", return_value=None) as api, patch.object(
            HELPER, "tag_commit", return_value=SHA
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
            f"Brave-Browser-Development-{TAG}-macos-arm64.zip",
            f"Brave-Browser-Development-{TAG}-macos-arm64.provenance.json",
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
        ) as establish, patch.object(HELPER.subprocess, "run") as command, patch.object(
            HELPER, "tag_commit", return_value=SHA
        ), patch.object(HELPER, "api") as api, patch.object(HELPER, "verify_assets") as verify:
            try:
                HELPER.main()
            finally:
                self.calls = establish, command, api, verify

    def test_reviewed_pair_publishes_exact_assets(self):
        self.run_main()
        establish, command, api, verify = self.calls
        establish.assert_called_once_with(TAG, SHA, "workflow_dispatch")
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[:6], ["gh", "release", "create", TAG, "--repo", HELPER.REPOSITORY])
        published = [Path(argument).name for argument in arguments[6:arguments.index("--verify-tag")]]
        self.assertEqual(published, sorted(self.names) + [f"SHA256SUMS-{TAG}.txt"])
        self.assertEqual(arguments[-1], str(self.directory / "release-notes.md"))
        api.assert_called_once_with(f"releases/tags/{TAG}")
        verify.assert_called_once()

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
