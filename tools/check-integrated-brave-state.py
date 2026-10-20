#!/usr/bin/env python3
"""Refuse destructive reuse of an unrelated or edited upstream checkout."""

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile

from brave_patch_contract import monitored_paths, patch_paths, patch_projection
from brave_patch_advance import OWNERS, atomic_source, digest, exclusive_source_update, prepare_single_file, preserve_blob, stacks


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


def snapshot(directory, pin, overlays=(), allow_unborn=False, excluded=()):
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
    pathspec = ("--", ".", *(f":(exclude,literal){path}" for path in excluded)) if excluded else ()
    status = git(directory, "status", "--porcelain=v1", "-z", "--untracked-files=all", *pathspec)
    digest = hashlib.sha256()
    digest.update(status)
    digest.update(git(directory, "diff", "--binary", "HEAD", *(pathspec or ("--",))))
    for name in git(directory, "ls-files", "--others", "--exclude-standard", "-z", *pathspec).split(b"\0"):
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
        if relative in excluded:
            continue
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


def source_states(repository, brave, require_clean=False, excluded=()):
    roots = (brave, brave.parent, brave.parent / "v8")
    pins = ("brave-core", "chromium", "v8")
    monitored = monitored_paths(repository)
    states = {}
    for name, directory in zip(pins, roots):
        pin = (repository / "browser/config" / f"{name}.rev").read_text().strip()
        if directory.is_symlink():
            raise ValueError(f"Symlinked upstream checkout: {directory}")
        if name == "chromium" and not (directory / ".git").exists():
            if directory.exists() and any(path.name != "brave" for path in directory.iterdir()):
                raise ValueError(f"Nonempty Chromium path is not a checkout: {directory}")
            states[name] = None
        else:
            states[name] = snapshot(directory, pin, sorted(monitored[name]),
                                    allow_unborn=name == "brave-core" and require_clean,
                                    excluded=tuple(path for owner, path in excluded if owner == name))
    return states


def adopt_known_inputs(args, identity):
    previous_repository = args.previous_repository
    if previous_repository is None or args.previous_receipt is None or args.require_clean:
        raise ValueError("adopt requires --previous-repository and --previous-receipt, without --require-clean")
    for repository in (previous_repository, args.repository):
        if Path(os.fsdecode(git(repository, "rev-parse", "--show-toplevel")).strip()).resolve() != repository.resolve():
            raise ValueError("Handoff requires independent source checkout roots")
        if git(repository, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError("Handoff requires clean previous and current source checkouts")
    if args.previous_receipt.is_symlink() or not args.previous_receipt.is_file():
        raise ValueError("Previous source receipt is missing or symlinked")
    previous_commit = git(previous_repository, "rev-parse", "HEAD").decode().strip()
    previous = json.loads(args.previous_receipt.read_text())
    expected = {"integration": previous_commit, "brave": identity["brave"],
                "upstream": source_states(previous_repository, args.brave)}
    if previous != expected or any(value is None for value in expected["upstream"].values()):
        raise ValueError("Previous receipt does not match the unchanged upstream inputs")
    git(args.repository, "merge-base", "--is-ancestor", previous_commit, identity["integration"])
    changed = git(args.repository, "diff", "--name-only", "-z", "--no-renames",
                  previous_commit, identity["integration"], "--").split(b"\0")
    for raw in changed:
        path = os.fsdecode(raw)
        if path and not (path.endswith(".md") or path.startswith((
            "scripts/", "tools/", "docs/", ".agents/", "browser/integration/brave/patches/"
        ))):
            raise ValueError(f"Production inputs changed; use a fresh checkout: {path}")
    for name in ("brave-core", "chromium", "v8"):
        relative = Path("browser/config") / f"{name}.rev"
        if (previous_repository / relative).read_bytes() != (args.repository / relative).read_bytes():
            raise ValueError("Pinned revisions changed during handoff")
    overlay = "browser/integration/brave/overlay"
    if git(args.repository, "rev-parse", f"{previous_commit}:{overlay}") != git(
        args.repository, "rev-parse", f"{identity['integration']}:{overlay}"
    ) or patch_projection(previous_repository) != patch_projection(args.repository):
        raise ValueError("Effective overlays or ordered patch contents changed; use a fresh checkout")
    audit = {
        "previous_integration": previous_commit, "integration": identity["integration"],
        "previous_receipt_sha256": file_digest(args.previous_receipt),
        "unchanged_production_inputs": True,
    }
    audit_path = args.receipt.with_name("integrated-brave-handoff.json")
    for path, value in ((args.receipt, identity), (audit_path, audit)):
        if path.is_symlink() or (path.exists() and json.loads(path.read_text()) != value):
            raise ValueError("Destination receipt already exists or is symlinked; preserve it before an explicit handoff")
    changed = False
    for path, value in ((audit_path, audit), (args.receipt, identity)):
        if not path.exists():
            write_receipt(path, value)
            changed = True
    return changed



def advance_known_patch(args, identity):
    previous_repository = args.previous_repository
    if previous_repository is None or args.previous_receipt is None or args.require_clean:
        raise ValueError("advance-patch requires both previous-source options, without --require-clean")
    for repository in (previous_repository, args.repository):
        if Path(os.fsdecode(git(repository, "rev-parse", "--show-toplevel")).strip()).resolve() != repository.resolve():
            raise ValueError("Patch advancement requires independent source checkout roots")
        if git(repository, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError("Patch advancement requires clean previous and current source checkouts")
    if args.previous_receipt.is_symlink() or not args.previous_receipt.is_file():
        raise ValueError("Previous source receipt is missing or symlinked")
    try:
        args.receipt.resolve().relative_to(args.repository.resolve())
    except ValueError:
        raise ValueError("The new receipt must belong to the updated source checkout") from None
    for path in (args.receipt, *args.receipt.parents):
        if path == args.repository.parent:
            break
        if path.is_symlink():
            raise ValueError("Symlink at a patch-advance receipt destination")
    previous_commit = git(previous_repository, "rev-parse", "HEAD").decode().strip()
    previous = json.loads(args.previous_receipt.read_text())
    if previous.get("integration") != previous_commit or previous.get("brave") != identity["brave"]:
        raise ValueError("Previous receipt/source identity differs from the requested checkout")
    if not previous.get("upstream") or any(value is None for value in previous["upstream"].values()):
        raise ValueError("Patch advancement requires initialized, previously recorded upstream inputs")
    git(args.repository, "merge-base", "--is-ancestor", previous_commit, identity["integration"])
    changed = git(args.repository, "diff", "--name-only", "-z", "--no-renames",
                  previous_commit, identity["integration"], "--").split(b"\0")
    for raw in changed:
        path = os.fsdecode(raw)
        if path and not (path.endswith(".md") or path.startswith((
            "scripts/", "tools/", "docs/", ".agents/", "browser/integration/brave/patches/"
        ))):
            raise ValueError(f"Patch advancement does not admit other production changes: {path}")
    for name, _ in OWNERS:
        relative = Path("browser/config") / f"{name}.rev"
        if (previous_repository / relative).read_bytes() != (args.repository / relative).read_bytes():
            raise ValueError("Pinned revisions changed during patch advancement")
    overlay = "browser/integration/brave/overlay"
    if git(args.repository, "rev-parse", f"{previous_commit}:{overlay}") != git(
        args.repository, "rev-parse", f"{identity['integration']}:{overlay}"
    ):
        raise ValueError("Overlay changes require a fresh pinned checkout")
    audit_path = args.receipt.with_name("integrated-brave-patch-advance.json")
    request = {"version": 1, "integration": identity["integration"],
               "previous_integration": previous_commit, "brave": identity["brave"],
               "previous_receipt_sha256": file_digest(args.previous_receipt)}
    if audit_path.is_symlink():
        raise ValueError("Symlinked patch-advance audit")
    audit = json.loads(audit_path.read_text()) if audit_path.exists() else None
    if audit is not None and (not isinstance(audit, dict) or audit.get("request") != request):
        raise ValueError("An audit from another operation exists; preserve it separately")
    if audit is not None:
        plan = audit.get("file")
        if (audit.get("status") not in ("prepared", "complete", "rolled_back", "needs_review") or
                not isinstance(plan, dict) or not isinstance(plan.get("relative"), str) or
                not isinstance(plan.get("mode"), int) or not 0 <= plan["mode"] <= 0o777 or
                not isinstance(audit.get("unaffected_upstream"), dict) or
                not isinstance(audit.get("index_entries"), dict)):
            raise ValueError("Malformed patch-advance audit; preserve it separately")
    if args.receipt.exists():
        if audit and audit.get("status") == "complete" and json.loads(args.receipt.read_text()) == identity:
            return False
        raise ValueError("An existing destination receipt differs; preserve it separately")
    roots = dict(zip((name for name, _ in OWNERS), (args.brave, args.brave.parent, args.brave.parent / "v8")))

    def indexes():
        return {name: digest(git(root, "ls-files", "--stage", "-z")) for name, root in roots.items()}

    if audit is None:
        if previous["upstream"] != source_states(previous_repository, args.brave):
            raise ValueError("Previous receipt does not match the unchanged upstream inputs")
        plan, before, after = prepare_single_file(previous_repository, args.repository, args.brave)
        if previous["upstream"] != source_states(previous_repository, args.brave):
            raise ValueError("Upstream inputs changed during ordered patch preflight")
        excluded = ((plan["owner"], Path(plan["relative"])),)
        audit = {"request": request, "status": "prepared", "file": plan,
                 "unaffected_upstream": source_states(previous_repository, args.brave, excluded=excluded),
                 "index_entries": indexes()}
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        preserve_blob(args.receipt.with_name("integrated-brave-patch-before.bin"), before)
        preserve_blob(args.receipt.with_name("integrated-brave-patch-after.bin"), after)
        write_receipt(audit_path, audit)
    else:
        plan = audit["file"]
        relative = Path(plan["relative"])
        if plan["owner"] not in roots or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Unsafe destination in patch-advance audit")
        if relative not in patch_paths(stacks(args.repository)[plan["owner"]]):
            raise ValueError("Audit destination is outside the current patch inventory")
        before_path = args.receipt.with_name("integrated-brave-patch-before.bin")
        after_path = args.receipt.with_name("integrated-brave-patch-after.bin")
        if before_path.is_symlink() or after_path.is_symlink():
            raise ValueError("Symlinked patch-advance backup")
        if max(before_path.stat().st_size, after_path.stat().st_size) > 16 * 1024 * 1024:
            raise ValueError("Patch-advance backup exceeds 16 MiB")
        before, after = before_path.read_bytes(), after_path.read_bytes()
        if digest(before) != plan["before_sha256"] or digest(after) != plan["after_sha256"]:
            raise ValueError("Patch-advance backup differs from the verified plan")
        excluded = ((plan["owner"], relative),)
    target = roots[plan["owner"]] / plan["relative"]

    def verify_unaffected():
        if file_digest(args.previous_receipt) != request["previous_receipt_sha256"]:
            raise ValueError("Previous receipt changed during patch advancement")
        if source_states(previous_repository, args.brave, excluded=excluded) != audit["unaffected_upstream"]:
            raise ValueError("Unrelated upstream edits appeared during patch advancement")
        if indexes() != audit["index_entries"]:
            raise ValueError("Real Git index entries changed during patch advancement")
        if target.is_symlink() or not target.is_file() or stat.S_IMODE(target.stat().st_mode) != plan["mode"]:
            raise ValueError("Patch destination type or permissions changed")
        if target.read_bytes() not in (before, after):
            raise ValueError("Patch destination contains an unknown edit")

    verify_unaffected()
    if target.read_bytes() == before and previous["upstream"] != source_states(previous_repository, args.brave):
        raise ValueError("Previous receipt no longer matches the source before advancement")
    try:
        if target.read_bytes() == before:
            atomic_source(target, after, plan["mode"])
        verify_unaffected()
        if target.read_bytes() != after:
            raise ValueError("Patch destination differs from the preflighted result")
        identity["upstream"] = source_states(args.repository, args.brave)
        audit["status"] = "complete"
        audit["source_after"] = identity
        write_receipt(audit_path, audit)
        write_receipt(args.receipt, identity)
    except BaseException:
        # Restore only our exact bytes. A concurrent unknown edit is preserved.
        restored = False
        if (target.is_file() and not target.is_symlink() and
                stat.S_IMODE(target.stat().st_mode) == plan["mode"]):
            if target.read_bytes() == after:
                atomic_source(target, before, plan["mode"])
            restored = target.read_bytes() == before
        audit["status"] = "rolled_back" if restored else "needs_review"
        write_receipt(audit_path, audit)
        raise
    if file_digest(args.previous_receipt) != request["previous_receipt_sha256"]:
        raise ValueError("Previous receipt changed concurrently; preserve both receipts for inspection")
    return True


def main():
    parser = argparse.ArgumentParser(description=(__doc__ + " advance-patch explicitly updates one recorded source file after ordered patch preflight."))
    parser.add_argument("mode", choices=("check", "record", "reserve", "complete", "adopt", "advance-patch"))
    parser.add_argument("--brave", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--previous-repository", type=Path)
    parser.add_argument("--previous-receipt", type=Path)
    args = parser.parse_args()
    if args.mode not in ("adopt", "advance-patch") and (args.previous_repository is not None or args.previous_receipt is not None):
        parser.error("Previous-source options apply only to adopt or advance-patch")
    states = source_states(args.repository, args.brave, args.require_clean)
    identity = {
        "integration": git(args.repository, "rev-parse", "HEAD").decode().strip(),
        "brave": str(args.brave.resolve()),
        "upstream": states,
    }
    completion_receipt = args.receipt.with_name("integrated-brave-complete.json")
    if args.mode == "advance-patch":
        with exclusive_source_update(args.brave):
            identity["upstream"] = source_states(args.repository, args.brave)
            changed = advance_known_patch(args, identity)
        print("status: " + ("advanced" if changed else "already_advanced"))
        print("integration: " + json.dumps(identity["integration"]))
        print("receipt: " + json.dumps(str(args.receipt)))
        print("previous_receipt: preserved")
        return
    if args.mode == "adopt":
        changed = adopt_known_inputs(args, identity)
        print("status: " + ("adopted" if changed else "already_adopted"))
        print("integration: " + json.dumps(identity["integration"]))
        print("receipt: " + json.dumps(str(args.receipt)))
        print("previous_receipt: preserved")
        return
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
        if len(sys.argv) > 1 and sys.argv[1] in ("adopt", "advance-patch"):
            message = ("Cannot verify the requested source or pinned checkout" if isinstance(
                error, subprocess.CalledProcessError) else str(error))
            print("error: " + ("SOURCE_PATCH_ADVANCE_REFUSED" if sys.argv[1] == "advance-patch" else "SOURCE_HANDOFF_REFUSED"))
            print("message: " + json.dumps(message[:500]))
            print('help: "Preserve existing inputs and receipts; inspect the stated mismatch or use a fresh pinned checkout"')
            sys.exit(1)
        print(f"Build stopped: {error}. Preserve your edits and use a fresh pinned "
              "checkout; no stash/reset/clean was performed.", file=sys.stderr)
        sys.exit(1)
