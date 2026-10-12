#!/usr/bin/env python3
"""Fail-closed publication contracts with mocked GitHub responses; no writes."""

import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError


SPEC = importlib.util.spec_from_file_location(
    "publish_release_pair", Path(__file__).with_name("publish-release-pair.py")
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
SHA = "a" * 40
TAG = "v0.3.1"


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


if __name__ == "__main__":
    unittest.main()
