#!/usr/bin/env python3
"""Extract digest-pinned official LLVM packages privately; never run maintainer scripts."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ["-fdiagnostics-show-inlining-chain", "-fno-lifetime-dse",
         "-fsanitize-ignore-for-ubsan-feature=array-bounds",
         "-fsanitize-ignore-for-ubsan-feature=return"]
BASE = "https://apt.llvm.org/resolute/"


def validate_manifest(manifest):
    if manifest.get("version") != 1 or manifest.get("compiler_major") != 23:
        raise ValueError("Unsupported LLVM manifest")
    packages = manifest.get("packages", [])
    if not 1 <= len(packages) <= 20:
        raise ValueError("Unbounded package list")
    names = set()
    total = 0
    for package in packages:
        name = package["name"]
        relative = package["filename"]
        if name in names or not re.fullmatch(r"[a-z0-9+.-]+", name):
            raise ValueError("Invalid or duplicate package")
        names.add(name)
        if not relative.startswith("pool/main/l/llvm-toolchain-23/") or ".." in relative:
            raise ValueError("Package must come from the official pinned LLVM23 pool")
        if not re.fullmatch(r"[a-zA-Z0-9_./+~%-]+\.deb", relative):
            raise ValueError("Invalid package filename")
        if not re.fullmatch(r"[0-9a-f]{64}", package["sha256"]):
            raise ValueError("Invalid package digest")
        size = package["size"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= 256 * 1024**2:
            raise ValueError("Invalid package size")
        total += size
    if total > 512 * 1024**2:
        raise ValueError("LLVM package download budget exceeded")
    return packages


def self_test():
    good = {"version": 1, "compiler_major": 23, "packages": [{"name": "clang-23",
            "filename": "pool/main/l/llvm-toolchain-23/clang-23_23_amd64.deb",
            "sha256": "a" * 64, "size": 8}]}
    assert len(validate_manifest(good)) == 1
    for field, value in (("filename", "../outside.deb"), ("sha256", "bad"), ("size", -1)):
        bad = json.loads(json.dumps(good))
        bad["packages"][0][field] = value
        try:
            validate_manifest(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid manifest accepted")
    print("PASS isolated LLVM manifest validation; no installation or download performed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--manifest", type=Path, default=ROOT / "tools/native-llvm23-packages.json")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.prefix is None or args.receipt is None:
        parser.error("--prefix and --receipt are required")
    manifest_bytes = args.manifest.read_bytes()
    packages = validate_manifest(json.loads(manifest_bytes))
    prefix = args.prefix.resolve()
    if prefix.exists():
        raise ValueError("Use a fresh private prefix; never overwrite an existing toolchain")
    prefix.mkdir(parents=True)
    if shutil.disk_usage(prefix).free < 4 * 1024**3:
        raise RuntimeError("Need 4GiB free for private LLVM extraction")
    receipt = {"status": "installing", "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
               "prefix": str(prefix), "packages": [], "system_installation": False}
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="llvm-packages-", dir=prefix.parent) as downloads:
            for package in packages:
                archive = Path(downloads) / (package["name"] + ".deb")
                digest = hashlib.sha256()
                received = 0
                with urllib.request.urlopen(BASE + package["filename"], timeout=120) as source, archive.open("wb") as output:
                    while data := source.read(1024 * 1024):
                        received += len(data)
                        if received > package["size"]:
                            raise ValueError("Package exceeded pinned size")
                        digest.update(data)
                        output.write(data)
                if received != package["size"] or digest.hexdigest() != package["sha256"]:
                    raise ValueError("Package identity mismatch: " + package["name"])
                subprocess.run(["dpkg-deb", "--extract", str(archive), str(prefix)], check=True)
                receipt["packages"].append(package)
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.pathsep.join((str(prefix / "usr/lib/x86_64-linux-gnu"),
                                                  str(prefix / "usr/lib/llvm-23/lib")))
        compiler = prefix / "usr/bin/clang++-23"
        version = subprocess.check_output([str(compiler), "--version"], env=env, text=True, timeout=30)
        if not re.search(r"clang version 23\.", version):
            raise RuntimeError("Extracted compiler is not LLVM23")
        probe = prefix / "flag-probe.cc"
        probe.write_text("int main() { return 0; }\n")
        subprocess.run([str(compiler), "-Werror", "-fsyntax-only", *FLAGS, str(probe)],
                       env=env, check=True, timeout=60)
        receipt.update(status="passed", compiler=version.splitlines()[0], accepted_flags=FLAGS)
        print(json.dumps({"bin": str(prefix / "usr/bin"), "ld_library_path": env["LD_LIBRARY_PATH"]}))
    except Exception as error:
        receipt.update(status="failed", error=str(error))
        raise
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
