#!/usr/bin/env python3
"""Extract a digest-pinned official LLVM release privately; never install system-wide.

The archive is an immutable llvm/llvm-project GitHub release asset, so the pin
stays downloadable (unlike rotating apt.llvm.org snapshot pools). Only the
compiler, linker, archive tools and Clang resource directory are extracted.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ["-fdiagnostics-show-inlining-chain", "-fno-lifetime-dse",
         "-fsanitize-ignore-for-ubsan-feature=array-bounds",
         "-fsanitize-ignore-for-ubsan-feature=return"]
RELEASE_PREFIX = "https://github.com/llvm/llvm-project/releases/download/"
MAX_ARCHIVE_BYTES = 2 * 1024**3


def validate_manifest(manifest):
    if manifest.get("version") != 2 or manifest.get("compiler_major") != 23:
        raise ValueError("Unsupported LLVM manifest")
    release, url, root = manifest.get("release"), manifest.get("url"), manifest.get("root")
    if not isinstance(release, str) or not re.fullmatch(r"llvmorg-23\.\d+\.\d+", release):
        raise ValueError("Release must be an official llvmorg-23.x.y tag")
    if not isinstance(url, str) or not url.startswith(RELEASE_PREFIX + release + "/") \
            or not re.fullmatch(r"[A-Za-z0-9:/._-]+\.tar\.zst", url):
        raise ValueError("Archive must be a .tar.zst asset of the pinned official release")
    if not isinstance(root, str) or not re.fullmatch(r"LLVM-23\.\d+\.\d+-Linux-X64", root):
        raise ValueError("Invalid archive root")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("sha256", ""))):
        raise ValueError("Invalid archive digest")
    size = manifest.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_ARCHIVE_BYTES:
        raise ValueError("Invalid archive size")
    members = manifest.get("members")
    if not isinstance(members, list) or not 1 <= len(members) <= 32 or len(set(members)) != len(members):
        raise ValueError("Unbounded or duplicate member list")
    for member in members:
        path = PurePosixPath(member) if isinstance(member, str) else None
        if path is None or path.is_absolute() or ".." in path.parts or \
                not re.fullmatch(r"(bin|lib)/[A-Za-z0-9+._/-]+", member):
            raise ValueError("Invalid archive member")
    for required in ("bin/clang-23", "bin/clang++", "bin/ld.lld", "lib/clang/23"):
        if required not in members:
            raise ValueError("Missing required member: " + required)
    return manifest


def self_test():
    good = {"version": 2, "compiler_major": 23, "release": "llvmorg-23.1.4",
            "url": RELEASE_PREFIX + "llvmorg-23.1.4/LLVM-23.1.4-Linux-X64.tar.zst",
            "sha256": "a" * 64, "size": 8, "root": "LLVM-23.1.4-Linux-X64",
            "members": ["bin/clang-23", "bin/clang++", "bin/ld.lld", "lib/clang/23"]}
    validate_manifest(good)
    validate_manifest(json.loads((ROOT / "tools/native-llvm23-release.json").read_text()))
    for field, value in (("url", "https://apt.llvm.org/x.tar.zst"), ("sha256", "bad"),
                         ("size", -1), ("members", ["../outside"]), ("release", "main"),
                         ("url", RELEASE_PREFIX + "llvmorg-23.1.3/LLVM-23.1.4-Linux-X64.tar.zst")):
        bad = json.loads(json.dumps(good))
        bad[field] = value
        try:
            validate_manifest(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid manifest accepted: " + field)
    print("PASS official LLVM release manifest validation; no download performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--manifest", type=Path, default=ROOT / "tools/native-llvm23-release.json")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.prefix is None or args.receipt is None:
        parser.error("--prefix and --receipt are required")
    manifest_bytes = args.manifest.read_bytes()
    manifest = validate_manifest(json.loads(manifest_bytes))
    prefix = args.prefix.resolve()
    if prefix.exists():
        raise ValueError("Use a fresh private prefix; never overwrite an existing toolchain")
    prefix.mkdir(parents=True)
    if shutil.disk_usage(prefix).free < 4 * 1024**3:
        raise RuntimeError("Need 4GiB free for the download and private LLVM extraction")
    if shutil.which("zstd") is None:
        raise RuntimeError("Missing required tool: zstd")
    receipt = {"status": "installing", "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
               "release": manifest["release"], "archive_sha256": manifest["sha256"],
               "prefix": str(prefix), "system_installation": False}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="llvm-release-", dir=prefix.parent) as downloads:
            archive = Path(downloads) / "llvm.tar.zst"
            digest = hashlib.sha256()
            received = 0
            with urllib.request.urlopen(manifest["url"], timeout=120) as source, archive.open("wb") as output:
                while data := source.read(4 * 1024 * 1024):
                    received += len(data)
                    if received > manifest["size"]:
                        raise ValueError("Archive exceeded pinned size")
                    digest.update(data)
                    output.write(data)
            if received != manifest["size"] or digest.hexdigest() != manifest["sha256"]:
                raise ValueError("Archive identity mismatch")
            members = [manifest["root"] + "/" + member for member in manifest["members"]]
            # Release archives use a 1 GiB zstd window; the default decoder limit is lower.
            decompress = subprocess.Popen(["zstd", "-dc", "--long=31", str(archive)],
                                          stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "--no-same-owner", "-C", str(prefix), "-f", "-", *members],
                           stdin=decompress.stdout, check=True, timeout=1800)
            decompress.stdout.close()
            if decompress.wait(timeout=60):
                raise RuntimeError("Archive decompression failed")
        bin_dir = prefix / manifest["root"] / "bin"
        for path in (prefix / manifest["root"]).rglob("*"):
            resolved = path.resolve()
            if prefix not in resolved.parents:
                raise ValueError("Extracted path escapes the private prefix: " + str(path))
        # The runtime driver selects compilers by their versioned names.
        (bin_dir / "clang++-23").symlink_to("clang++")
        compiler = bin_dir / "clang++-23"
        version = subprocess.check_output([str(compiler), "--version"], text=True, timeout=30)
        if not re.search(r"clang version 23\.", version):
            raise RuntimeError("Extracted compiler is not LLVM23")
        probe = prefix / "flag-probe.cc"
        probe.write_text("int main() { return 0; }\n")
        subprocess.run([str(compiler), "-Werror", "-fsyntax-only", *FLAGS, str(probe)],
                       check=True, timeout=60)
        linker = bin_dir / "ld.lld"
        linker_version = subprocess.check_output([str(linker), "--version"], text=True, timeout=30)
        if not re.search(r"LLD 23\.", linker_version):
            raise RuntimeError("Extracted linker is not LLVM23")
        executable = prefix / "link-probe"
        subprocess.run([str(compiler), "-Werror", *FLAGS, "-fuse-ld=" + str(linker),
                        str(probe), "-o", str(executable)], check=True, timeout=60)
        subprocess.run([str(executable)], check=True, timeout=30)
        receipt.update(status="passed", compiler=version.splitlines()[0], accepted_flags=FLAGS,
                       linker=linker_version.strip(), compile_link_execute_probe=True,
                       bin=str(bin_dir))
        print(json.dumps({"bin": str(bin_dir)}))
    except Exception as error:
        receipt.update(status="failed", error=str(error))
        raise
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
