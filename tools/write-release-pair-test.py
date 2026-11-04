#!/usr/bin/env python3
"""Synthetic release receipts; no browser download or execution."""

import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HELPER = Path(__file__).with_name("write-release-pair.py")
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TAG = "v0.5.2"
# The paired browser is the unchanged v0.5.1 build, so it keeps that release's name.
BRAVE_TAG = "v0.5.1"
NAME = f"Brave-Browser-Development-{BRAVE_TAG}-macos-arm64"
CDHASH = "c" * 40
BUILD = "b" * 40
SOURCE_URL = "https://github.com/sunghoojung/reverse-engineering-browser/releases/download/preview-0.5.1"


def pin_script(**values):
    lines = "".join(f"readonly {name}={value}\n" for name, value in values.items())
    return (
        "#!/usr/bin/env bash\n# BEGIN reviewed paired browser pin\n# Reviewed values.\n"
        f"{lines}# END reviewed paired browser pin\n"
    )


class ReleasePair(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("release_pair", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.helper.__file__ = str(self.root / "tools/write-release-pair.py")
        self.output = self.root / "build/release-pair"
        self.output.mkdir(parents=True)
        self.info = {
            "CFBundleShortVersionString": "0.5.2",
            "OriginTraceReleaseType": "paired",
        }
        self.plist = self.root / "apps/research-ui/macos/Info.plist"
        self.plist.parent.mkdir(parents=True)
        self.plist.write_bytes(plistlib.dumps(self.info))
        (self.output / f"Origin-Trace-{TAG}-macos.zip").write_bytes(b"synthetic app")
        (self.output / "source").mkdir()
        self.brave = self.output / "source" / f"{NAME}.zip"
        self.brave.write_bytes(b"synthetic paired browser")
        self.provenance = self.output / "source" / f"{NAME}.provenance.json"
        self.browser = {
            "schema": "reb-brave-distribution-provenance-v1", "release": BRAVE_TAG,
            "artifact": f"{NAME}.zip", "sha256": self.helper.digest(self.brave),
            "build_source_commit": BUILD, "app_cdhash": CDHASH,
            "pins": {"brave_core": "v1.95.52", "chromium": "151.0.7922.108"},
        }
        self.pin = {}
        self.write_provenance(self.browser)
        self.environment = {
            "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": TAG, "GITHUB_RUN_ID": "123",
            "RELEASE_TAG": TAG,
        }

    def write_pin(self, **overrides):
        self.pin = {
            "brave_name": NAME, "source_url": SOURCE_URL,
            "brave_sha256": self.helper.digest(self.brave),
            "provenance_sha256": self.helper.digest(self.provenance),
            "build_source": BUILD, **overrides,
        }
        script = self.root / self.helper.PIN_SCRIPT
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(pin_script(**self.pin))

    def write_provenance(self, browser):
        self.provenance.write_text(json.dumps(browser))
        self.write_pin()

    def run_helper(self):
        with patch.dict(os.environ, self.environment, clear=True), patch.object(
            self.helper.subprocess, "check_output", return_value="a" * 40 + "\n"
        ):
            self.helper.main()

    def test_pair_records_browser_provenance_notes_and_checksums(self):
        self.run_helper()
        pair = json.loads((self.output / f"Origin-Trace-Brave-{TAG}.provenance.json").read_text())
        self.assertEqual(pair["schema"], "origin-trace-release-pair-v2")
        self.assertEqual(pair["source_commit"], "a" * 40)
        self.assertEqual(pair["brave"]["provenance"], self.browser)
        self.assertEqual(pair["brave"]["sha256"], self.helper.digest(self.brave))
        self.assertEqual(pair["brave"]["cdhash"], CDHASH)
        self.assertEqual(pair["brave"]["build_source_commit"], BUILD)
        self.assertEqual(pair["brave"]["hosted_source"], f"{SOURCE_URL}/{NAME}.zip")
        self.assertEqual((self.output / f"{NAME}.zip").read_bytes(), self.brave.read_bytes())
        sums = (self.output / f"SHA256SUMS-{TAG}.txt").read_text().splitlines()
        self.assertEqual([line.split("  ")[1] for line in sums], [
            f"Origin-Trace-{TAG}-macos.zip", f"{NAME}.zip", f"{NAME}.provenance.json",
            f"Origin-Trace-Brave-{TAG}.provenance.json",
        ])
        for line in sums:
            checksum, name = line.split("  ")
            self.assertEqual(checksum, self.helper.digest(self.output / name))
        notes = (self.output / "release-notes.md").read_text()
        downloads = f"{self.helper.REPOSITORY}/releases/download/{TAG}"
        for phrase in [f"{downloads}/{NAME}.zip", f"{downloads}/{NAME}.provenance.json",
                       f"{downloads}/SHA256SUMS-{TAG}.txt", CDHASH, "a" * 40,
                       "Brave v1.95.52 and Chromium 151.0.7922.108", "not an official Brave release",
                       "not Apple-notarized", "consumer services", "dormant", "since v0.5.1",
                       "first published with v0.5.1", "exits with status 3", "byte for byte",
                       "Before v0.5.1 was published", "REB_NATIVE_WASM_CALL_INDIRECT",
                       "defines every native V8 flag", "`REB_NATIVE_QUIET_MODE=0`"]:
            self.assertIn(phrase, notes)
        self.assertNotIn("\u2014", notes)
        self.assertNotIn("a new Brave Browser Development build", notes)

    def test_browser_built_for_this_release_is_described_as_new(self):
        name = f"Brave-Browser-Development-{TAG}-macos-arm64"
        self.brave = self.brave.rename(self.brave.with_name(f"{name}.zip"))
        self.provenance.unlink()
        self.provenance = self.provenance.with_name(f"{name}.provenance.json")
        self.write_provenance({**self.browser, "release": TAG, "artifact": f"{name}.zip"})
        self.write_pin(brave_name=name)
        self.run_helper()
        notes = (self.output / "release-notes.md").read_text()
        self.assertIn("a new Brave Browser Development build", notes)
        self.assertIn("Before publishing", notes)
        self.assertNotIn("byte for byte", notes)
        self.assertTrue((self.output / f"{name}.zip").exists())

    def test_browser_built_for_a_later_release_is_rejected(self):
        name = "Brave-Browser-Development-v0.5.3-macos-arm64"
        self.brave = self.brave.rename(self.brave.with_name(f"{name}.zip"))
        self.provenance.unlink()
        self.provenance = self.provenance.with_name(f"{name}.provenance.json")
        self.write_provenance({**self.browser, "release": "v0.5.3", "artifact": f"{name}.zip"})
        self.write_pin(brave_name=name)
        with self.assertRaises(ValueError):
            self.run_helper()
        self.assertFalse((self.output / f"{name}.zip").exists())

    def test_changed_browser_or_provenance_bytes_are_rejected(self):
        for path in (self.brave, self.provenance):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaises(ValueError):
                    self.run_helper()
                path.write_bytes(original)

    def test_provenance_for_another_archive_or_build_is_rejected(self):
        # prepare-release-brave.sh compares the recorded CDHash with the extracted app.
        for key, value in [("schema", "other"), ("release", "v0.3.0"), ("release", TAG),
                           ("sha256", "0" * 64),
                           ("artifact", "other.zip"), ("build_source_commit", "d" * 40)]:
            with self.subTest(key=key):
                self.write_provenance({**self.browser, key: value})
                with self.assertRaises(ValueError):
                    self.run_helper()

    def test_unfinished_or_mismatched_pin_is_rejected(self):
        for key, value in [("source_url", "PLACEHOLDER"), ("brave_sha256", "PLACEHOLDER"),
                           ("provenance_sha256", "PLACEHOLDER"), ("build_source", "PLACEHOLDER"),
                           ("source_url", "https://example.invalid/releases/download/x"),
                           ("brave_name", "Brave-Browser-Development-v0.5.3-macos-arm64")]:
            with self.subTest(key=key, value=value):
                self.write_pin(**{key: value})
                with self.assertRaises(ValueError):
                    self.run_helper()
        self.assertFalse((self.output / f"{NAME}.zip").exists())

    def test_application_must_be_a_paired_release(self):
        self.plist.write_bytes(plistlib.dumps({**self.info, "OriginTraceReleaseType": "companion"}))
        with self.assertRaises(ValueError):
            self.run_helper()

    def test_provenance_must_record_the_app_cdhash(self):
        for value in [None, "PLACEHOLDER", CDHASH.upper()]:
            with self.subTest(value=value):
                browser = {key: item for key, item in self.browser.items() if key != "app_cdhash"}
                if value is not None:
                    browser["app_cdhash"] = value
                self.write_provenance(browser)
                with self.assertRaises(ValueError):
                    self.run_helper()
        self.assertFalse((self.output / f"{NAME}.zip").exists())

    def test_tag_version_mismatch_is_rejected(self):
        self.environment["GITHUB_REF_NAME"] = "v0.3.2"
        with self.assertRaises(ValueError):
            self.run_helper()

    def test_missing_requested_release_is_rejected(self):
        del self.environment["RELEASE_TAG"]
        with self.assertRaises(ValueError):
            self.run_helper()
        self.assertFalse((self.output / f"{NAME}.zip").exists())

    def test_rerun_reuses_identical_pinned_copies(self):
        self.run_helper()
        recorded = {path.name: path.read_bytes() for path in self.output.iterdir() if path.is_file()}
        self.run_helper()
        self.assertEqual({path.name: path.read_bytes() for path in self.output.iterdir() if path.is_file()},
                         recorded)

    def test_existing_archive_or_provenance_is_not_replaced(self):
        for name in (f"{NAME}.zip", f"{NAME}.provenance.json"):
            with self.subTest(name=name):
                existing = self.output / name
                existing.write_bytes(b"existing")
                with self.assertRaises(FileExistsError):
                    self.run_helper()
                self.assertEqual(existing.read_bytes(), b"existing")
                existing.unlink()

    def test_pin_block_rejects_unexpected_lines(self):
        for block in ["readonly brave_name=$(curl x)\n", "brave_name=x\n", "readonly extra=x\n",
                      "readonly brave_name=a\nreadonly brave_name=b\n"]:
            with self.subTest(block=block), self.assertRaises(ValueError):
                self.helper.pin_block("# BEGIN reviewed paired browser pin\n" + block
                                      + "# END reviewed paired browser pin\n")


class RepositoryPin(unittest.TestCase):
    """The checked-in pin and application agree, and an unfinished pin never passes."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location("release_pair", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.script = (REPOSITORY_ROOT / self.helper.PIN_SCRIPT).read_text()
        with (REPOSITORY_ROOT / "apps/research-ui/macos/Info.plist").open("rb") as source:
            self.info = plistlib.load(source)

    def test_checked_in_pin_names_this_or_an_earlier_release(self):
        pin = self.helper.pin_block(self.script)
        version = "v" + self.info["CFBundleShortVersionString"]
        brave = re.fullmatch(self.helper.PIN_SHAPES["brave_name"], pin["brave_name"]).group(1)
        self.assertLessEqual(self.helper.version_key(brave), self.helper.version_key(version))
        publish = importlib.util.spec_from_file_location(
            "publish_pair", HELPER.with_name("publish-release-pair.py"))
        reviewed = importlib.util.module_from_spec(publish)
        publish.loader.exec_module(reviewed)
        self.assertEqual((reviewed.REVIEWED_TAG, reviewed.REVIEWED_BRAVE_TAG), (version, brave))
        self.assertEqual(self.info["OriginTraceReleaseType"], "paired")

    def test_shell_refuses_placeholders_before_any_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "apps/research-ui/macos").mkdir(parents=True)
            (root / "apps/research-ui/macos/Info.plist").write_bytes(plistlib.dumps(self.info))
            block = re.compile(r"# BEGIN reviewed paired browser pin\n.*# END reviewed paired browser pin\n",
                               re.DOTALL)
            placeholders = pin_script(
                brave_name=self.helper.pin_block(self.script)["brave_name"], source_url="PLACEHOLDER",
                brave_sha256="PLACEHOLDER", provenance_sha256="PLACEHOLDER", build_source="PLACEHOLDER",
            ).split("\n", 1)[1]
            script = root / "scripts/prepare-release-brave.sh"
            script.write_text(block.sub(lambda _: placeholders, self.script, count=1))
            result = subprocess.run(["bash", str(script)], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            for name in ["source_url", "brave_sha256", "provenance_sha256", "build_source"]:
                self.assertIn(name, result.stderr)
            self.assertNotIn("brave_name", result.stderr)
            self.assertFalse((root / "build").exists())
            later = pin_script(
                brave_name="Brave-Browser-Development-v99.0.0-macos-arm64", source_url="PLACEHOLDER",
                brave_sha256="PLACEHOLDER", provenance_sha256="PLACEHOLDER", build_source="PLACEHOLDER",
            ).split("\n", 1)[1]
            script.write_text(block.sub(lambda _: later, self.script, count=1))
            result = subprocess.run(["bash", str(script)], cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("brave_name", result.stderr)
            self.assertFalse((root / "build").exists())


if __name__ == "__main__":
    unittest.main()
