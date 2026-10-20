#!/usr/bin/env python3
"""Prepare and publish only the reviewed v0.3.2 companion release."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "publish_release_pair", Path(__file__).with_name("publish-release-pair.py")
)
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)
TAG = "v0.3.2"
VERSION = "0.3.2"
BUILD = "32"
REPOSITORY = PUBLISHER.REPOSITORY
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
ARCHIVE = f"Origin-Trace-{TAG}-macos.zip"
PROVENANCE = f"Origin-Trace-{TAG}.provenance.json"
CHECKSUMS = f"SHA256SUMS-{TAG}.txt"
NOTES = "release-notes.md"
PLIST_PATH = "Origin Trace.app/Contents/Info.plist"
CHECKS = [
    "make check on macOS 15 arm64",
    "Packaged application build and strict code-signature verification",
    "Packaged launcher, backend/CDP readiness, relocated UI and cleanup with stock Chrome",
    "Native close/Quit lifecycle suite",
    "Production AppKit warning via XCUITest: default and clicked Offline, explicit fake-browser "
    "launch, failure Retry, later-session warning and modal-reopen acceptance",
    "Warning screenshots and independent fake-browser launch receipts",
]
LIMITS = [
    "Companion-only release: no Brave browser is included or rebuilt.",
    "No tested or source-equivalent matched browser/companion pair is claimed.",
    "Historical v0.3.0/v0.3.1 Brave archives lack the new native VM and runtime-buffer features.",
    "Stock Chrome CDP testing is not proof of native Brave probe or VM/runtime-buffer capture.",
    "The companion is ad-hoc signed, not Apple-notarized.",
    "Release validation uses macOS 15 arm64; macOS 13/14 compatibility is not established.",
    "Warning interaction QA uses an owned fake-browser executable only; "
    "it does not establish native browser/companion compatibility or capture coverage.",
]


def root_directory():
    return Path(__file__).resolve().parents[1]


def require_version(info):
    expected = {
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": BUILD,
        "OriginTraceReleaseType": "companion",
    }
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError("Only the reviewed v0.3.2 companion application is admitted")


def context(root, publishing=False):
    if os.environ.get("RELEASE_TAG") != TAG:
        raise ValueError("Only the reviewed v0.3.2 companion release is admitted")
    event = os.environ.get("GITHUB_EVENT_NAME")
    admitted = {"workflow_dispatch"} if publishing else {"workflow_dispatch", "pull_request"}
    if event not in admitted:
        raise ValueError("Companion release is forbidden for this event")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("Unexpected release repository")
    source_sha = os.environ.get("RELEASE_SOURCE_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("A full immutable source commit is required")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if head != source_sha:
        raise ValueError("Release source differs from checked-out HEAD")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not all(re.fullmatch(r"[1-9][0-9]*", value) for value in (run_id, attempt)):
        raise ValueError("An exact workflow run and attempt are required")
    with (root / "apps/research-ui/macos/Info.plist").open("rb") as source:
        require_version(plistlib.load(source))
    return {
        "source_commit": source_sha,
        "validation_run": f"{REPOSITORY_URL}/actions/runs/{run_id}/attempts/{attempt}",
        "workflow_run": {"id": run_id, "attempt": attempt, "event": event},
    }


def require_files(directory, expected):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Release candidate directory must be a real directory")
    entries = list(directory.iterdir())
    if {path.name for path in entries} != set(expected):
        raise ValueError("Companion release files are incomplete or unexpected")
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ValueError("Release candidates must be regular files, not links or directories")


def require_archive(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or names.count(PLIST_PATH) != 1:
            raise ValueError("Companion archive has duplicate entries or no unique app plist")
        for name in names:
            if "\\" in name or any(part in {".", ".."} for part in name.split("/")):
                raise ValueError("Companion archive contains an unsafe path")
            if not (name.startswith("Origin Trace.app/") or name == "__MACOSX/"
                    or name.startswith("__MACOSX/Origin Trace.app/")
                    or name == "__MACOSX/._Origin Trace.app"):
                raise ValueError("Companion archive contains an unexpected top-level entry")
            if any(part.endswith(".app") and part not in {"Origin Trace.app", "._Origin Trace.app"}
                   for part in name.split("/")):
                raise ValueError("Companion archive must not include another application")
        info = archive.getinfo(PLIST_PATH)
        if info.file_size > 1024 * 1024:
            raise ValueError("Companion app plist is unexpectedly large")
        require_version(plistlib.loads(archive.read(info)))


def manifest_text(directory, source):
    archive = directory / ARCHIVE
    manifest = {
        "schema": "origin-trace-companion-release-v1",
        "release": TAG,
        "release_type": "companion",
        **source,
        "origin_trace": {
            "artifact": ARCHIVE,
            "sha256": PUBLISHER.digest(archive),
            "size_bytes": archive.stat().st_size,
            "version": VERSION,
            "build": BUILD,
            "platform": "macOS 15 arm64",
            "build_origin": "GitHub Actions macOS 15 arm64 build",
            "signing": "ad-hoc",
            "apple_notarized": False,
        },
        "browser": {"included": False, "rebuilt": False, "matched_pair": False},
        "checks": CHECKS,
        "limits": LIMITS,
    }
    return json.dumps(manifest, indent=2) + "\n"


def notes_text(source):
    downloads = f"{REPOSITORY_URL}/releases/download/{TAG}"
    return (
        f"Origin Trace {TAG} is a companion-only macOS Apple silicon release.\n\n"
        f"[Download Origin Trace]({downloads}/{ARCHIVE}). "
        "This download contains only the Origin Trace app and its companion tools. "
        "Live browser sessions require a separately supplied compatible browser.\n\n"
        "Default launch shows a browser compatibility warning with an offline escape "
        "before starting a live session.\n\n"
        f"Source: `{source['source_commit']}`. "
        f"[Build and validation run]({source['validation_run']}). "
        f"[Companion provenance]({downloads}/{PROVENANCE}). "
        f"[Checksums]({downloads}/{CHECKSUMS}).\n\n"
        "Checks performed by this workflow:\n"
        + "\n".join(f"- {check}" for check in CHECKS) + "\n\n"
        "Release boundaries:\n"
        + "\n".join(f"- {limit}" for limit in LIMITS) + "\n"
    )


def checksums_text(directory):
    return "".join(
        f"{PUBLISHER.digest(directory / name)}  {name}\n"
        for name in (ARCHIVE, PROVENANCE)
    )


def prepare(root):
    source = context(root)
    if (platform.system() != "Darwin" or platform.machine() != "arm64"
            or not re.fullmatch(r"15\.[0-9]+(?:\.[0-9]+)?", platform.mac_ver()[0])):
        raise ValueError("Companion preparation requires a native macOS 15 arm64 build runner")
    directory = root / "build/release-companion"
    require_files(directory, {ARCHIVE})
    require_archive(directory / ARCHIVE)
    (directory / PROVENANCE).write_text(manifest_text(directory, source))
    (directory / NOTES).write_text(notes_text(source))
    (directory / CHECKSUMS).write_text(checksums_text(directory))


def publish(root):
    source = context(root, publishing=True)
    directory = root / "build/release-companion"
    require_files(directory, {ARCHIVE, PROVENANCE, CHECKSUMS, NOTES})
    require_archive(directory / ARCHIVE)
    if (directory / PROVENANCE).read_text() != manifest_text(directory, source):
        raise ValueError("Companion provenance differs from the exact source, run or archive")
    if (directory / NOTES).read_text() != notes_text(source):
        raise ValueError("Companion release notes differ from the reviewed release contract")
    if (directory / CHECKSUMS).read_text() != checksums_text(directory):
        raise ValueError("Companion release asset checksums are incomplete or changed")
    assets = [directory / name for name in (ARCHIVE, PROVENANCE, CHECKSUMS)]
    expected_assets = {
        path.name: (path.stat().st_size, PUBLISHER.digest(path)) for path in assets
    }
    # The shared helper creates a new ref only and refuses existing tags/releases.
    # The companion's stricter event admission above never enables its push path.
    PUBLISHER.establish_tag(TAG, source["source_commit"], "workflow_dispatch")
    subprocess.run([
        "gh", "release", "create", TAG, "--repo", REPOSITORY,
        *[str(path) for path in assets], "--verify-tag", "--target", source["source_commit"],
        "--title", f"Origin Trace {TAG} (companion only)",
        "--notes-file", str(directory / NOTES),
    ], check=True)
    if PUBLISHER.tag_commit(TAG) != source["source_commit"]:
        raise ValueError("Published tag no longer matches the tested companion source")
    release = PUBLISHER.api(f"releases/tags/{TAG}")
    PUBLISHER.verify_assets(release, expected_assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "publish"))
    args = parser.parse_args()
    {"prepare": prepare, "publish": publish}[args.command](root_directory())


if __name__ == "__main__":
    main()
