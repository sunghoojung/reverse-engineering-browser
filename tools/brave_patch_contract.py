"""Patch paths, independent checkout ownership, and byte-equivalent routing."""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


def patch_paths(patches):
    paths = set()
    for patch in patches:
        records = iter(subprocess.check_output(
            ["git", "apply", "--numstat", "-z", "--", str(patch)]
        ).split(b"\0"))
        for record in records:
            if not record:
                continue
            fields = record.split(b"\t", 2)
            if len(fields) != 3:
                raise ValueError(f"Malformed patch path record: {patch}")
            names = [fields[2]] if fields[2] else [next(records), next(records)]
            for name in names:
                path = Path(os.fsdecode(name))
                if not name or path.is_absolute() or any(part in ("..", ".git") for part in path.parts):
                    raise ValueError(f"Unsafe patch path: {path}")
                paths.add(path)
    return sorted(paths)


def verify_ownership(checkout, patches):
    expected = checkout.resolve()
    for relative in patch_paths(patches):
        target = checkout / relative
        for ancestor in (target, *target.parents):
            if ancestor == checkout.parent:
                break
            if ancestor.is_symlink():
                raise ValueError(f"Symlink at a patch destination: {ancestor}")
        directory = target if target.is_dir() else target.parent
        while not directory.exists():
            directory = directory.parent
        actual = Path(os.fsdecode(subprocess.check_output(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"]
        )).strip()).resolve()
        if actual != expected:
            raise ValueError(f"Patch destination {relative} belongs to nested checkout {actual}; "
                             "move the patch to that checkout's stack")


def monitored_paths(repository):
    integration = repository / "browser/integration/brave"
    overlay = integration / "overlay"
    result = {name: set() for name in ("brave-core", "chromium", "v8")}
    result["brave-core"].update(path.relative_to(overlay)
                               for path in overlay.rglob("*") if path.is_file())
    for name, folder in (("brave-core", ""), ("chromium", "chromium"), ("v8", "v8")):
        for patch in (integration / "patches" / folder).glob("*.patch"):
            for line in patch.read_text().splitlines():
                if line.startswith(("+++ b/", "--- a/")):
                    relative = Path(line[6:].split("\t", 1)[0])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError(f"Unsafe patch path in {patch}")
                    result[name].add(relative)
    result["chromium"].add(Path("build/config/siso/brave_siso_config.star"))
    return result


def patch_projection(repository):
    """Keep ordered diff bytes per actual Git owner, ignoring only routing prefixes."""
    root = repository / "browser/integration/brave/patches"
    result = {name: [] for name in ("brave-core", "chromium", "v8")}
    for owner, folder in (("brave-core", ""), ("chromium", "chromium"), ("v8", "v8")):
        for patch in sorted((root / folder).glob("*.patch")):
            if not patch_paths([patch]):
                raise ValueError(f"Empty patch: {patch}")
            blocks = re.split(r"(?=^diff --git )", patch.read_bytes().decode("utf-8"), flags=re.MULTILINE)
            for block in blocks:
                if not block.startswith("diff --git "):
                    continue
                header = shlex.split(block.splitlines()[0])
                if len(header) != 4 or not header[2].startswith("a/") or not header[3].startswith("b/"):
                    raise ValueError(f"Unsupported patch header in {patch}")
                before, after = header[2][2:], header[3][2:]
                if before != after:
                    raise ValueError("Patch-routing handoff does not support file renames")
                actual, prefix = owner, ""
                if owner == "chromium":
                    for nested, name in (("v8/", "v8"), ("brave/", "brave-core")):
                        if before.startswith(nested):
                            actual, prefix = name, nested
                            break
                normalized = []
                for line in block.splitlines(keepends=True):
                    if prefix and line.startswith("diff --git "):
                        line = line.replace(" a/" + prefix, " a/", 1).replace(" b/" + prefix, " b/", 1)
                    elif prefix and line.startswith(("--- a/" + prefix, "+++ b/" + prefix)):
                        line = line[:6] + line[6 + len(prefix):]
                    normalized.append(line)
                result[actual].append("".join(normalized))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("paths", "verify"))
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("patches", type=Path, nargs="*")
    args = parser.parse_intermixed_args()
    if args.mode == "verify":
        if args.checkout is None:
            parser.error("verify requires --checkout")
        verify_ownership(args.checkout, args.patches)
    else:
        for path in patch_paths(args.patches):
            sys.stdout.buffer.write(os.fsencode(path) + b"\0")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, StopIteration, subprocess.CalledProcessError) as error:
        print(f"Patch contract failed: {error}", file=sys.stderr)
        sys.exit(1)
