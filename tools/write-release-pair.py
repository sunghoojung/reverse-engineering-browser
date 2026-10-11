#!/usr/bin/env python3
"""Record the tested companion/browser pair without rewriting browser history."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess


BRAVE_NAME = "Brave-Browser-Development-v0.3.0-macos-arm64"
BRAVE_SHA256 = "07209f53456ab30fc4ad6c6d6028daf56f0251c0910e15b5b1dc441f2c8469af"
PROVENANCE_SHA256 = "8101ff5fe36a2f97e0363913ac6ef9469cd3acf19fecefd73d616f1f0b4ef01c"
REPOSITORY = "https://github.com/sunghoojung/reverse-engineering-browser"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "build/release-pair"
    with (root / "apps/research-ui/macos/Info.plist").open("rb") as source:
        version = plistlib.load(source)["CFBundleShortVersionString"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid application version")
    tag = f"v{version}"
    if os.environ.get("RELEASE_TAG", tag) != tag:
        raise ValueError("Requested release does not match the application version")
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        if os.environ["GITHUB_REF_NAME"] != tag:
            raise ValueError("Tag does not match the packaged application version")
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    origin = output / f"Origin-Trace-{tag}-macos.zip"
    previous = output / "source" / f"{BRAVE_NAME}.zip"
    source_provenance = output / "source" / f"{BRAVE_NAME}.provenance.json"
    provenance = output / source_provenance.name
    if digest(previous) != BRAVE_SHA256 or digest(source_provenance) != PROVENANCE_SHA256:
        raise ValueError("Published Brave bytes or provenance changed")
    original = json.loads(source_provenance.read_text())
    if original["sha256"] != BRAVE_SHA256:
        raise ValueError("Brave provenance does not describe this archive")
    brave = output / f"Brave-Browser-Development-{tag}-macos-arm64.zip"
    if brave.exists():
        raise FileExistsError(brave)
    shutil.copyfile(previous, brave)
    shutil.copyfile(source_provenance, provenance)
    if digest(brave) != BRAVE_SHA256:
        raise ValueError("Copied Brave bytes differ")
    run_url = f"{REPOSITORY}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    manifest = {
        "schema": "origin-trace-release-pair-v1",
        "release": tag,
        "source_commit": source_sha,
        "validation_run": run_url,
        "origin_trace": {
            "artifact": origin.name,
            "sha256": digest(origin),
            "size_bytes": origin.stat().st_size,
            "build_origin": "Pull-request macOS CI preview" if os.environ.get(
                "GITHUB_EVENT_NAME"
            ) == "pull_request" else "macOS release CI build",
        },
        "brave": {
            "artifact": brave.name,
            "sha256": BRAVE_SHA256,
            "size_bytes": brave.stat().st_size,
            "reuse": "Exact v0.3.0 ZIP bytes; not a new browser compilation",
            "original_provenance": original,
            "original_provenance_artifact": provenance.name,
        },
        "pairing": {
            "platform": "macOS arm64",
            "installation": "Extract both app bundles into the same directory",
            "source_equivalence": (
                "Browser inputs and protocol bytes match the original build source"
            ),
            "checks": [
                "Published Brave ZIP and provenance SHA256",
                "Strict signatures and extracted Brave executable version",
                "Real packaged launcher with disposable Brave profile",
                "Live backend/debugger readiness and relocated WebKit UI",
                "Launcher shutdown and browser-exit cleanup",
                "Full native close/Quit suite including five repeated attempts",
            ],
            "limits": [
                "Ad-hoc signing, not Apple notarization",
                "Brave retains its original local-build provenance",
                "No claim of Finder automatic-launch or full native capture/Canvas QA",
                "Worker/proxy foundations remain dormant",
            ],
        },
    }
    pair = output / f"Origin-Trace-Brave-{tag}.provenance.json"
    pair.write_text(json.dumps(manifest, indent=2) + "\n")
    assets = [origin, brave, provenance, pair]
    sums = output / f"SHA256SUMS-{tag}.txt"
    sums.write_text("".join(f"{digest(path)}  {path.name}\n" for path in assets))
    downloads = f"{REPOSITORY}/releases/download/{tag}"
    (output / "release-notes.md").write_text(
        f"Origin Trace {tag} fixes the native repeated Close/Quit lifecycle gate.\n\n"
        f"Download both [Origin Trace]({downloads}/{origin.name}) and "
        f"[Brave Browser Development for Apple silicon]({downloads}/{brave.name}). "
        "Extract the app bundles beside each other.\n\n"
        "Quit can reach the guarded delegate while a Close sheet is open. AppKit "
        "aborts that sheet first, and the fresh Quit decision checks the current "
        "document again. Stay retains drafts; Close Anyway remains explicit. "
        "The native test verifies request UUIDs, one query per decision, both "
        "decisions and five fresh-process repeated attempts.\n\n"
        f"Source: `{source_sha}`. [Validation pipeline]({run_url}). "
        f"[Pair provenance and exact browser pins]({downloads}/{pair.name}). "
        f"[Checksums]({downloads}/{sums.name}).\n\n"
        "Brave is byte-for-byte the v0.3.0 browser archive, with unchanged browser "
        "inputs/protocols and its original local-build provenance. It was not "
        "rebuilt in clean CI. The new companion and that browser passed the "
        "packaged live-session, readiness, relocated UI and cleanup checks. "
        "These checks do not claim Finder automatic launch or complete native "
        "capture/Canvas QA. Both bundles are ad-hoc signed, not notarized. "
        "Worker/proxy foundations remain dormant. Existing v0.3.0 assets are "
        "unchanged.\n"
    )


if __name__ == "__main__":
    main()
