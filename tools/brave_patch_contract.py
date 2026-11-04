"""Patch paths, independent checkout ownership, ordered stack state, and source locking."""

import argparse
import errno
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile


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


class PrivateIndex:
    """A throwaway Git index for one checkout; the real index is never read or written."""

    def __init__(self, checkout, directory):
        self.checkout = Path(checkout)
        self.path = Path(directory) / "index"
        self.environment = dict(os.environ, GIT_INDEX_FILE=str(self.path))

    def git(self, *arguments, check=True, input=None):
        result = subprocess.run(["git", "--literal-pathspecs", "-C", str(self.checkout), *arguments],
                                env=self.environment, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        if check and result.returncode:
            detail = result.stderr.decode(errors="replace").strip()[:500]
            raise ValueError(f"git {arguments[0]} failed in {self.checkout}: {detail}")
        return result

    def load_worktree(self, paths):
        """Stage the working-tree content of exactly these paths over their HEAD entries.

        The index holds only these paths: Chromium's full tree would make every
        patch check rewrite an index of hundreds of thousands of entries.
        """
        self.git("read-tree", "--empty")
        if paths:
            entries = self.git("ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", *map(str, paths)).stdout
            self.git("update-index", "-z", "--index-info", input=entries)
        known = set(self.git("ls-files", "-z", "--", *map(str, paths)).stdout.split(b"\0")) if paths else set()
        # A path absent from both HEAD and the working tree matches no pathspec.
        present = [str(path) for path in paths
                   if os.fsencode(str(path)) in known or os.path.lexists(self.checkout / path)]
        if present:
            self.git("add", "-A", "-f", "--", *present)

    def entries(self, paths):
        """Map each path to "<mode> <blob>" or None when the index lacks it."""
        result = {str(path): None for path in paths}
        if paths:
            for record in self.git("ls-files", "-s", "-z", "--", *map(str, paths)).stdout.split(b"\0"):
                if record:
                    meta, name = record.split(b"\t", 1)
                    mode, blob, _ = meta.split(b" ")
                    result[os.fsdecode(name)] = f"{mode.decode()} {blob.decode()}"
        return result

    def applies(self, patch, reverse=False):
        return self.git("apply", "--cached", *(["--reverse"] if reverse else []),
                        "--", str(patch), check=False).returncode == 0


def worktree_entries(checkout, paths):
    """Current working-tree content of the given paths, hashed as Git would stage it."""
    with tempfile.TemporaryDirectory(prefix="reb-worktree-entries-") as directory:
        index = PrivateIndex(checkout, directory)
        index.load_worktree(paths)
        return index.entries(paths)


def stack_plan(checkout, patches):
    """Return (applied, expected) for an ordered stack, or raise ValueError.

    A synchronized checkout holds an applied prefix of its stack: the first
    ``applied`` patches and none of the rest. An interrupted sync leaves such a
    prefix, and the next sync resumes from it. A later patch may edit lines an
    earlier one introduced, so every candidate prefix is removed newest-first in
    a private index before the remaining patches are checked forward from the
    current content. ``expected`` is each patched path's content once the whole
    stack is applied. Any other state, such as a later patch applied without an
    earlier one, has no explanation and is refused before anything changes.
    """
    patches = [Path(patch) for patch in patches]
    paths = patch_paths(patches)
    with tempfile.TemporaryDirectory(prefix="reb-patch-plan-") as directory:
        index = PrivateIndex(checkout, directory)
        index.load_worktree(paths)
        current = index.path.read_bytes()
        for applied in range(len(patches), -1, -1):
            index.path.write_bytes(current)
            if not all(index.applies(patch, reverse=True) for patch in reversed(patches[:applied])):
                continue
            index.path.write_bytes(current)
            if all(index.applies(patch) for patch in patches[applied:]):
                return applied, index.entries(paths)
    names = ", ".join(patch.name for patch in patches)
    raise ValueError(f"{checkout} does not hold an ordered prefix of its patch stack ({names}). "
                     "A later patch is applied without an earlier one, or a patched file was edited; "
                     "inspect `git -C <checkout> diff` before synchronizing")


def source_lock_path(brave):
    """One lock per upstream workspace: Brave, Chromium and V8 change together."""
    return Path(os.path.abspath(brave)).parent.parent / ".reb-source.lock"


def open_source_lock(brave):
    path = source_lock_path(brave)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"Brave source lock is not a regular file: {path}")
    return descriptor


def lock_source(brave, descriptor):
    """Take the workspace lock on an open descriptor without waiting for it."""
    import fcntl
    path = source_lock_path(brave)
    try:
        held, named = os.fstat(descriptor), os.lstat(path)
    except OSError as error:
        raise ValueError(f"Brave source lock descriptor {descriptor} is not open on {path}") from error
    if stat.S_ISLNK(named.st_mode) or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError(f"Descriptor {descriptor} does not hold the Brave source lock {path}")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        raise ValueError(f"Another integrated build, sync, bootstrap or patch advancement holds {path}; "
                         "let it finish before changing this Brave checkout") from None


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
    parser.add_argument("mode", choices=("paths", "verify", "plan", "lock-path", "lock"))
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--brave", type=Path)
    parser.add_argument("--fd", type=int)
    parser.add_argument("patches", type=Path, nargs="*")
    args = parser.parse_intermixed_args()
    if args.mode in ("verify", "plan") and args.checkout is None:
        parser.error(f"{args.mode} requires --checkout")
    if args.mode in ("lock-path", "lock") and args.brave is None:
        parser.error(f"{args.mode} requires --brave")
    if args.mode == "verify":
        verify_ownership(args.checkout, args.patches)
    elif args.mode == "plan":
        print(stack_plan(args.checkout, args.patches)[0])
    elif args.mode == "lock-path":
        os.close(open_source_lock(args.brave))
        print(source_lock_path(args.brave))
    elif args.mode == "lock":
        if args.fd is None:
            parser.error("lock requires --fd")
        lock_source(args.brave, args.fd)
    else:
        for path in patch_paths(args.patches):
            sys.stdout.buffer.write(os.fsencode(path) + b"\0")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, StopIteration, subprocess.CalledProcessError) as error:
        print(f"Patch contract failed: {error}", file=sys.stderr)
        sys.exit(1)
