#!/usr/bin/env python3
"""Synthetic release receipts; no browser download or execution."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch


HELPER = Path(__file__).with_name("write-release-pair.py")


class ReleasePair(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("release_pair", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.helper.__file__ = str(root / "tools/write-release-pair.py")
        self.output = root / "build/release-pair"
        self.output.mkdir(parents=True)
        app = root / "apps/research-ui/macos"
        app.mkdir(parents=True)
        (app / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleShortVersionString": "0.3.1",
        }))
        (self.output / "Origin-Trace-v0.3.1-macos.zip").write_bytes(b"synthetic app")
        (self.output / "source").mkdir()
        self.old = self.output / "source" / f"{self.helper.BRAVE_NAME}.zip"
        self.old.write_bytes(b"synthetic unchanged browser")
        self.helper.BRAVE_SHA256 = self.helper.digest(self.old)
        self.provenance = self.output / "source" / f"{self.helper.BRAVE_NAME}.provenance.json"
        self.original = {"sha256": self.helper.BRAVE_SHA256, "build_origin": "local"}
        self.provenance.write_text(json.dumps(self.original))
        self.helper.PROVENANCE_SHA256 = self.helper.digest(self.provenance)
        self.environment = {
            "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.3.1",
            "GITHUB_RUN_ID": "123",
        }

    def run_helper(self):
        with patch.dict(os.environ, self.environment, clear=True), patch.object(
            self.helper.subprocess, "check_output", return_value="a" * 40 + "\n"
        ):
            self.helper.main()

    def test_pair_preserves_browser_history_and_checksums_all_assets(self):
        self.run_helper()
        pair = json.loads((self.output / "Origin-Trace-Brave-v0.3.1.provenance.json").read_text())
        self.assertEqual(pair["brave"]["original_provenance"], self.original)
        self.assertEqual(pair["source_commit"], "a" * 40)
        self.assertEqual(pair["brave"]["sha256"], self.helper.digest(self.old))
        sums = (self.output / "SHA256SUMS-v0.3.1.txt").read_text().splitlines()
        self.assertEqual(len(sums), 4)
        for line in sums:
            checksum, name = line.split("  ")
            self.assertEqual(checksum, self.helper.digest(self.output / name))

    def test_changed_browser_is_rejected(self):
        self.old.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.run_helper()

    def test_changed_provenance_is_rejected(self):
        self.provenance.write_text("{}")
        with self.assertRaises(ValueError):
            self.run_helper()

    def test_tag_version_mismatch_is_rejected(self):
        self.environment["GITHUB_REF_NAME"] = "v0.3.0"
        with self.assertRaises(ValueError):
            self.run_helper()

    def test_existing_archive_is_not_replaced(self):
        existing = self.output / "Brave-Browser-Development-v0.3.1-macos-arm64.zip"
        existing.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            self.run_helper()
        self.assertEqual(existing.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
