#!/usr/bin/env python3
"""Publish a tested pair: a non-overwriting tag, then a draft verified before it is published."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.error import HTTPError
from urllib.request import Request, urlopen


REPOSITORY = "sunghoojung/reverse-engineering-browser"
# The one paired release this source admits. Publishing another version needs
# a new review of this constant, the browser pin and the release notes.
REVIEWED_TAG = "v0.5.0"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def verify_assets(release, expected, draft=False):
    if release is None or release.get("draft") is not draft:
        raise ValueError("Release draft is missing" if draft else "Release was not published")
    assets = release["assets"]
    if len(assets) != len(expected) or {asset["name"] for asset in assets} != set(expected):
        raise ValueError("Published release asset set differs from the tested pair")
    for asset in assets:
        size, checksum = expected[asset["name"]]
        if asset["state"] != "uploaded" or asset["size"] != size:
            raise ValueError(f"Release asset is incomplete: {asset['name']}")
        if asset.get("digest") != f"sha256:{checksum}":
            raise ValueError(f"Remote release asset digest differs: {asset['name']}")


def api(path, method="GET", data=None):
    request = Request(
        f"https://api.github.com/repos/{REPOSITORY}/{path}",
        method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None  # DELETE answers 204.
    except HTTPError as error:
        # Authentication, rate-limit, transport and server failures are not
        # evidence that a tag or release is absent.
        if method == "GET" and error.code == 404:
            return None
        raise


def tag_commit(tag):
    reference = api(f"git/ref/tags/{tag}")
    if reference is None:
        return None
    target = reference["object"]
    for _ in range(8):
        if target["type"] == "commit":
            return target["sha"]
        if target["type"] != "tag":
            raise ValueError("Release tag does not resolve to a commit")
        target = api(f"git/tags/{target['sha']}")["object"]
    raise ValueError("Release tag chain is too deep")


def establish_tag(tag, source_sha, event):
    if api(f"releases/tags/{tag}") is not None:
        raise ValueError("Refusing to replace an existing release")
    current = tag_commit(tag)
    if event == "workflow_dispatch":
        if current is None:
            # POST creates only a new ref. A concurrent creator causes an error;
            # unlike an update or force-push it cannot overwrite their ref.
            api("git/refs", "POST", {"ref": f"refs/tags/{tag}", "sha": source_sha})
        elif current != source_sha:
            raise ValueError("Refusing to replace an existing tag")
        else:
            # An earlier attempt created this tag for the same tested source,
            # and no release exists. A rerun adopts it rather than stalling.
            print(f"Adopting existing tag {tag}: it names the tested source and has no release")
    elif event != "push" or current != source_sha:
        raise ValueError("Tag event does not match the tested source")
    if tag_commit(tag) != source_sha:
        raise ValueError("Release tag differs from the tested source")


def drafts(tag):
    """Unpublished releases for a tag; only the release list reports drafts."""
    return [release for release in api("releases?per_page=100") or []
            if release.get("draft") is True and release.get("tag_name") == tag]


def publish_verified(tag, source_sha, assets, expected, title, notes):
    """Upload a draft, verify it, then publish; a failed attempt leaves no release."""
    for stale in drafts(tag):
        # Only an interrupted attempt at this exact publication is replaced.
        if stale.get("target_commitish") != source_sha or stale.get("name") != title:
            raise ValueError(f"A different draft release for {tag} exists; review it first")
        api(f"releases/{stale['id']}", "DELETE")
    subprocess.run([
        "gh", "release", "create", tag, "--repo", REPOSITORY, *[str(path) for path in assets],
        "--draft", "--verify-tag", "--target", source_sha, "--title", title,
        "--notes-file", str(notes),
    ], check=True)
    created = drafts(tag)
    if len(created) != 1:
        raise ValueError(f"Expected one new draft release for {tag}, found {len(created)}")
    draft = created[0]
    try:
        verify_assets(draft, expected, draft=True)
        if tag_commit(tag) != source_sha:
            raise ValueError("Release tag no longer matches the tested source")
        api(f"releases/{draft['id']}", "PATCH", {"draft": False})
    except BaseException:
        api(f"releases/{draft['id']}", "DELETE")
        raise
    try:
        if tag_commit(tag) != source_sha:
            raise ValueError("Published tag no longer matches the tested source")
        verify_assets(api(f"releases/tags/{tag}"), expected)
    except BaseException:
        # Withdraw to a draft rather than delete: reversible, and it keeps the
        # uploaded bytes for inspection. A rerun replaces this exact draft.
        api(f"releases/{draft['id']}", "PATCH", {"draft": True})
        raise


def main():
    tag = os.environ["RELEASE_TAG"]
    source_sha = os.environ["RELEASE_SOURCE_SHA"]
    event = os.environ["GITHUB_EVENT_NAME"]
    if tag != REVIEWED_TAG or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError(f"Only the reviewed {REVIEWED_TAG} release is admitted")
    if event not in {"push", "workflow_dispatch"}:
        raise ValueError("Publication is forbidden for this event")
    directory = Path("build/release-pair")
    sums = directory / f"SHA256SUMS-{tag}.txt"
    names = set()
    for line in sums.read_text().splitlines():
        checksum, name = line.split("  ")
        if Path(name).name != name or name in names:
            raise ValueError("Invalid or repeated release asset path")
        names.add(name)
        actual = digest(directory / name)
        if actual != checksum:
            raise ValueError(f"Release asset checksum mismatch: {name}")
    expected = {
        f"Origin-Trace-{tag}-macos.zip",
        f"Brave-Browser-Development-{tag}-macos-arm64.zip",
        f"Brave-Browser-Development-{tag}-macos-arm64.provenance.json",
        f"Origin-Trace-Brave-{tag}.provenance.json",
    }
    if names != expected:
        raise ValueError("Release assets are incomplete or unexpected")
    manifest = json.loads((directory / f"Origin-Trace-Brave-{tag}.provenance.json").read_text())
    if manifest["source_commit"] != source_sha or manifest["release"] != tag:
        raise ValueError("Pair provenance does not match the release inputs")
    assets = [directory / name for name in sorted(names)] + [sums]
    expected_assets = {path.name: (path.stat().st_size, digest(path)) for path in assets}
    establish_tag(tag, source_sha, event)
    publish_verified(tag, source_sha, assets, expected_assets, f"Origin Trace + Brave {tag}",
                     directory / "release-notes.md")


if __name__ == "__main__":
    main()
