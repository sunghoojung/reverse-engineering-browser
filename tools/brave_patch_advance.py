"""Preflight a single existing source-file change from two ordered patch stacks."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from brave_patch_contract import patch_paths, verify_ownership


OWNERS = (("brave-core", ""), ("chromium", "chromium"), ("v8", "v8"))
MAX_SOURCE_BYTES = 16 * 1024 * 1024


def digest(content):
    return hashlib.sha256(content).hexdigest()


def stacks(repository):
    root = repository / "browser/integration/brave/patches"
    return {owner: sorted((root / folder).glob("*.patch")) for owner, folder in OWNERS}


def prepare_single_file(previous, current, brave):
    old, new = stacks(previous), stacks(current)
    roots = dict(zip((name for name, _ in OWNERS), (brave, brave.parent, brave.parent / "v8")))
    changed = []
    for owner, _ in OWNERS:
        before, after = old[owner], new[owner]
        if [p.name for p in before] != [p.name for p in after] or patch_paths(before) != patch_paths(after):
            raise ValueError("Patch advancement requires the same ordered patches and destination inventory")
        verify_ownership(roots[owner], before)
        verify_ownership(roots[owner], after)
        if [p.read_bytes() for p in before] != [p.read_bytes() for p in after]:
            changed.append(owner)
    if len(changed) != 1:
        raise ValueError("Patch advancement requires changes in exactly one independent checkout")
    owner = changed[0]
    checkout = roots[owner]
    paths = patch_paths(old[owner])
    with tempfile.TemporaryDirectory(prefix="reb-patch-preflight-") as directory:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(Path(directory) / "index")

        def git(*arguments, input=None):
            try:
                return subprocess.check_output(
                    ["git", "--literal-pathspecs", "-C", str(checkout), *arguments],
                    env=env, input=input, stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as error:
                detail = error.stderr.decode(errors="replace").strip()[:500]
                raise ValueError(f"Ordered {owner} patch preflight refused: {detail}") from None

        git("read-tree", "HEAD")
        git("add", "-A", "-f", "--", *(str(path) for path in paths))
        original = git("write-tree").strip().decode()
        for patch in reversed(old[owner]):
            git("apply", "--cached", "--reverse", "--", str(patch))
        for patch in new[owner]:
            git("apply", "--cached", "--", str(patch))
        desired = git("write-tree").strip().decode()
        names = [name for name in git("diff-tree", "--no-commit-id", "--name-only", "-r", "-z",
                                       original, desired).split(b"\0") if name]
        if len(names) != 1:
            raise ValueError("Patch advancement permits exactly one existing source-file change")
        relative = os.fsdecode(names[0])
        modes = [git("ls-tree", tree, "--", relative).split(b" ", 1)[0]
                 for tree in (original, desired)]
        if modes[0] not in (b"100644", b"100755") or modes[0] != modes[1]:
            raise ValueError("Added, deleted, symlinked or mode-changing files require a fresh checkout")
        before = git("show", f"{original}:{relative}")
        after = git("show", f"{desired}:{relative}")
    if max(len(before), len(after)) > MAX_SOURCE_BYTES:
        raise ValueError("Patch advancement source files are limited to 16 MiB")
    target = checkout / relative
    if not target.is_file() or target.is_symlink() or target.read_bytes() != before:
        raise ValueError("Patch destination changed during preflight")
    plan = {"owner": owner, "relative": relative, "mode": stat.S_IMODE(target.stat().st_mode),
            "before_sha256": digest(before), "after_sha256": digest(after)}
    return plan, before, after


def atomic_source(path, content, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".reb-patch-advance-", delete=False) as file:
        temporary = Path(file.name)
        file.write(content)
        file.flush()
        os.fchmod(file.fileno(), mode)
        os.fsync(file.fileno())
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def preserve_blob(path, content):
    if path.is_symlink():
        raise ValueError("Symlinked patch-advance backup")
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError("Existing patch-advance backup differs; preserve it separately")
        return
    with path.open("xb") as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


@contextmanager
def exclusive_source_update(brave):
    try:
        import fcntl
    except ImportError:
        raise ValueError("Patch advancement requires POSIX file locking") from None
    directory = Path(os.fsdecode(subprocess.check_output(
        ["git", "-C", str(brave), "rev-parse", "--absolute-git-dir"]
    )).strip())
    descriptor = os.open(directory / "reb-source-advance.lock",
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another patch advancement owns this checkout; wait for it to finish") from None
        yield
    finally:
        os.close(descriptor)
