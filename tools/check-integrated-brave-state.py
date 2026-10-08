#!/usr/bin/env python3
"""Refuse destructive reuse of an unrelated or edited upstream checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def git(directory, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(directory), *arguments], stderr=subprocess.DEVNULL
    )


def snapshot(directory, pin, overlays=()):
    if not directory.exists():
        return None
    if directory.resolve() != Path(
        os.fsdecode(git(directory, "rev-parse", "--show-toplevel")).strip()
    ).resolve():
        raise ValueError(f"Not an independent Git checkout: {directory}")
    actual = git(directory, "rev-parse", "HEAD").strip()
    expected = git(directory, "rev-parse", f"{pin}^{{commit}}").strip()
    if actual != expected:
        raise ValueError(f"Pinned revision mismatch: {directory} (expected {pin})")
    status = git(directory, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    digest = hashlib.sha256()
    digest.update(status)
    digest.update(git(directory, "diff", "--binary", "HEAD", "--"))
    for name in git(directory, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if not name:
            continue
        path = directory / os.fsdecode(name)
        digest.update(name + b"\0")
        if path.is_symlink():
            digest.update(b"symlink\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(str(path.stat().st_mode).encode() + b"\0")
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        else:
            raise ValueError(f"Unsupported untracked path: {path}")
    dirty = bool(status)
    # Brave ignores some overlay destinations, so Git status alone is insufficient.
    for relative in overlays:
        path = directory / relative
        for ancestor in (path, *path.parents):
            if ancestor == directory.parent:
                break
            if ancestor.is_symlink():
                raise ValueError(f"Symlink at an overlay destination: {ancestor}")
        digest.update(os.fsencode(relative) + b"\0")
        if path.exists():
            if not path.is_file():
                raise ValueError(f"Non-file overlay destination: {path}")
            digest.update(str(path.stat().st_mode).encode() + b"\0")
            digest.update(path.read_bytes())
            if not git(directory, "ls-files", "--", str(relative)).strip():
                dirty = True
        else:
            digest.update(b"missing\0")
    return {"head": actual.decode(), "dirty": dirty, "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "record"))
    parser.add_argument("--brave", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    roots = (args.brave, args.brave.parent, args.brave.parent / "v8")
    pins = ("brave-core", "chromium", "v8")
    integration = args.repository / "browser/integration/brave"
    overlay_root = integration / "overlay"
    monitored = {name: set() for name in pins}
    monitored["brave-core"].update(path.relative_to(overlay_root)
                                  for path in overlay_root.rglob("*") if path.is_file())
    for name, folder in zip(pins, ("", "chromium", "v8")):
        for patch in (integration / "patches" / folder).glob("*.patch"):
            for line in patch.read_text().splitlines():
                if line.startswith(("+++ b/", "--- a/")):
                    relative = Path(line[6:].split("\t", 1)[0])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError(f"Unsafe patch path in {patch}")
                    monitored[name].add(relative)
    monitored["chromium"].add(Path("build/config/siso/brave_siso_config.star"))
    states = {}
    for name, directory in zip(pins, roots):
        pin = (args.repository / "browser/config" / f"{name}.rev").read_text().strip()
        # src/ can exist before Chromium initialization, but is not yet a repo.
        if name == "chromium" and not (directory / ".git").exists():
            if directory.exists() and any(path.name != "brave" for path in directory.iterdir()):
                raise ValueError(f"Nonempty Chromium path is not a checkout: {directory}")
            states[name] = None
        else:
            states[name] = snapshot(directory, pin, sorted(monitored[name]))
    identity = {
        "integration": git(args.repository, "rev-parse", "HEAD").decode().strip(),
        "brave": str(args.brave.resolve()),
        "upstream": states,
    }
    if args.mode == "record":
        if any(value is None for value in states.values()):
            raise ValueError("Cannot record incomplete upstream checkouts")
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=args.receipt.parent,
                                         prefix="integrated-brave-state-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(identity, indent=2) + "\n")
        try:
            temporary.replace(args.receipt)
        finally:
            temporary.unlink(missing_ok=True)
    elif any(value and value["dirty"] for value in states.values()):
        if args.require_clean:
            raise ValueError("--init requires clean upstream checkouts; omit --init for a recorded build")
        previous = json.loads(args.receipt.read_text()) if args.receipt.exists() else None
        if previous != identity:
            raise ValueError("Upstream edits differ from this integration's recorded sync state")
    print(f"Upstream state {args.mode} passed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Build stopped: {error}. Preserve your edits and use a fresh pinned "
              "checkout; no stash/reset/clean was performed.", file=sys.stderr)
        sys.exit(1)
