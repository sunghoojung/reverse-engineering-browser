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


def pristine_unborn_brave(directory):
    git_directory = directory / ".git"
    if not git_directory.is_dir() or git_directory.is_symlink():
        return False
    if any(path.name != ".git" for path in directory.iterdir()):
        return False
    hooks = git_directory / "hooks"
    if hooks.is_symlink() or (hooks.exists() and (
        not hooks.is_dir() or any(not path.name.endswith(".sample") for path in hooks.iterdir())
    )):
        raise ValueError("Unexpected Git hooks in unborn checkout; inspect them before initialization")
    # Check effective local/global/system configuration before commands that can
    # consult hooks or filesystem monitors. Includes can hide executable settings.
    configuration = subprocess.run(
        ["git", "-C", str(directory), "config", "--name-only", "--get-regexp",
         r"^(core\.(hookspath|fsmonitor)|include\.path|includeif\..*\.path)$"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if configuration.returncode == 0:
        raise ValueError("Unexpected Git hook/monitor/include configuration; inspect it before initialization")
    if configuration.returncode != 1:
        raise ValueError("Cannot verify Git configuration before initialization")
    if git(directory, "ls-files", "-z") or git(directory, "for-each-ref", "--format=%(refname)"):
        return False
    if not git(directory, "symbolic-ref", "-q", "HEAD").startswith(b"refs/heads/"):
        return False
    pending = ("MERGE_HEAD", "REBASE_HEAD", "CHERRY_PICK_HEAD", "rebase-apply", "rebase-merge")
    if any((git_directory / name).exists() for name in pending):
        return False
    remotes = git(directory, "remote").decode().splitlines()
    if not remotes:
        return False
    for name in remotes:
        urls = git(directory, "config", "--get-all", f"remote.{name}.url").decode().splitlines()
        if not urls or any(url != "https://github.com/brave/brave-core.git" for url in urls):
            return False
    return True


def snapshot(directory, pin, overlays=(), allow_unborn=False):
    if directory.is_symlink():
        raise ValueError(f"Symlinked upstream checkout: {directory}")
    if not directory.exists():
        return None
    if directory.resolve() != Path(
        os.fsdecode(git(directory, "rev-parse", "--show-toplevel")).strip()
    ).resolve():
        raise ValueError(f"Not an independent Git checkout: {directory}")
    try:
        actual = git(directory, "rev-parse", "--verify", "HEAD^{commit}").strip()
    except subprocess.CalledProcessError:
        if allow_unborn and pristine_unborn_brave(directory):
            return None  # Bootstrap may safely finish its empty, official-remote checkout.
        raise ValueError(f"Uninitialized or partial upstream checkout is not safely reusable: {directory}") from None
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


def write_receipt(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent,
                                     prefix="integrated-brave-state-", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(json.dumps(value, indent=2) + "\n")
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def completed_output(brave):
    output = brave.parent / "out/Component_arm64"
    args = output / "args.gn"
    if output.is_symlink() or args.is_symlink() or not args.is_file():
        raise ValueError("Completed component output/args are missing or symlinked")
    names = ("Brave Browser", "Brave Browser Development", "Brave Browser Dev", "Brave Browser Beta")
    for name in names:
        executable = output / f"{name}.app/Contents/MacOS" / name
        if executable.is_file() and os.access(executable, os.X_OK):
            for ancestor in (executable, *executable.parents):
                if ancestor == output.parent:
                    break
                if ancestor.is_symlink():
                    raise ValueError("Completed browser output is symlinked")
            return {"directory": str(output.resolve()), "args_sha256": file_digest(args),
                    "executable": str(executable.relative_to(output)),
                    "executable_sha256": file_digest(executable)}
    raise ValueError("Completed component browser executable is missing")


def repeat_reserve_kib(output):
    result = subprocess.check_output(["du", "-sk", output], text=True).split()
    if not result or not result[0].isdigit() or int(result[0]) <= 0:
        raise ValueError("Cannot measure completed component output")
    # Reserve at least one whole output's allocation for rebuild/link replacement.
    return max(50 * 1024 * 1024, int(result[0]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "record", "reserve", "complete"))
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
        if directory.is_symlink():
            raise ValueError(f"Symlinked upstream checkout: {directory}")
        # src/ can exist before Chromium initialization, but is not yet a repo.
        if name == "chromium" and not (directory / ".git").exists():
            if directory.exists() and any(path.name != "brave" for path in directory.iterdir()):
                raise ValueError(f"Nonempty Chromium path is not a checkout: {directory}")
            states[name] = None
        else:
            states[name] = snapshot(directory, pin, sorted(monitored[name]),
                                    allow_unborn=name == "brave-core" and args.require_clean)
    identity = {
        "integration": git(args.repository, "rev-parse", "HEAD").decode().strip(),
        "brave": str(args.brave.resolve()),
        "upstream": states,
    }
    completion_receipt = args.receipt.with_name("integrated-brave-complete.json")
    if args.mode == "reserve":
        required = 150 * 1024 * 1024
        if not args.require_clean and all(value is not None for value in states.values()):
            try:
                previous = json.loads(completion_receipt.read_text())
                output = completed_output(args.brave)
                if previous == {"source": identity, "output": output}:
                    required = repeat_reserve_kib(output["directory"])
            except (OSError, ValueError, subprocess.CalledProcessError):
                pass  # Missing/stale/unmeasurable proof keeps the first-build reserve.
        print(required)
        return
    if args.mode in ("record", "complete"):
        if any(value is None for value in states.values()):
            raise ValueError("Cannot record incomplete upstream checkouts")
        if args.mode == "complete":
            if not args.receipt.exists() or json.loads(args.receipt.read_text()) != identity:
                raise ValueError("Source state changed during the build")
            write_receipt(completion_receipt,
                          {"source": identity, "output": completed_output(args.brave)})
        else:
            write_receipt(args.receipt, identity)
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
