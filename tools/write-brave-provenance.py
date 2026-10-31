#!/usr/bin/env python3
"""Write the provenance JSON for a packaged Brave distribution ZIP.

Deterministic and offline: the same inputs always produce the same bytes. The
pins come from browser/config/*.rev at the build source commit, not from the
working tree, so the record describes exactly what was built.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


SCHEMA = "reb-brave-distribution-provenance-v1"
ARCHIVE = re.compile(r"Brave-Browser-Development-(v[0-9]+\.[0-9]+\.[0-9]+)-macos-arm64\.zip")
PINS = {
    "brave_core": "browser/config/brave-core.rev",
    "chromium": "browser/config/chromium.rev",
    "v8": "browser/config/v8.rev",
    "depot_tools": "browser/config/depot_tools.rev",
}
# The same distribution contract scripts/package-brave-distribution.sh enforces.
REQUIRED_ARGS = {
    "is_component_build": False,
    "is_official_build": False,
    "is_debug": False,
    "target_cpu": "arm64",
    "brave_channel": "development",
    "skip_signing": True,
    "enable_updater": False,
    "enable_sparkle": False,
}
# Build arguments are published. Never copy a credential or a local home path.
SECRET_NAME = re.compile(r"(?:^|_)(?:key|secret|token|password|credential|client_id)(?:_|$)")
LOCAL_PATH = re.compile(r"/(?:Users|home)/")
ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S.*?)")
IMPORT = re.compile(r'import\("(//[^"]+)"\)')


def load_services():
    spec = importlib.util.spec_from_file_location(
        "check_brave_services", Path(__file__).with_name("check-brave-services.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SERVICES = load_services()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def literal(value):
    if value in ("true", "false"):
        return value == "true"
    if re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    match = re.fullmatch(r'"((?:[^"\\$]|\\.)*)"', value)
    return match.group(1) if match else value


def read_build_args(path, source_root, seen=None):
    """Effective project-level assignments: last one wins, //out/ imports followed.

    Other imports (Brave's own defaults) are recorded by name; the brave_core pin
    fixes their content. Anything beyond single-line assignments fails closed.
    """
    seen = set() if seen is None else seen
    if path.is_symlink() or not path.is_file() or path.resolve() in seen:
        raise ValueError(f"Build arguments must be regular files without cycles: {path.name}")
    seen.add(path.resolve())
    values, imports = {}, []
    text = SERVICES.strip_gn_comments(path.read_text())
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if match := IMPORT.fullmatch(line):
            target = match.group(1)
            if ".." in target.split("/"):
                raise ValueError(f"Unsupported build argument import at {path.name}:{number}")
            if target.startswith("//out/"):
                nested, nested_imports = read_build_args(source_root / target[2:], source_root, seen)
                values.update(nested)
                imports.extend(nested_imports)
            else:
                imports.append(target)
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match is None:
            raise ValueError(f"Unsupported build argument syntax at {path.name}:{number}")
        values[match.group(1)] = literal(match.group(2))
    return values, imports


def published_args(values):
    enabled = [name for name in SERVICES.SERVICE_ARGS if values.get(name) is True]
    if enabled or values.get(SERVICES.OPT_IN) is True:
        raise ValueError("Build arguments re-enable bundled Brave services: " + ", ".join(enabled))
    for name, expected in REQUIRED_ARGS.items():
        if values.get(name) != expected:
            raise ValueError(f"Not a distribution build: {name} must be {json.dumps(expected)}")
    published = {}
    for name in sorted(values):
        value = values[name]
        if SECRET_NAME.search(name) and value not in ("", False):
            value = "<redacted: credential>"
        elif isinstance(value, str) and LOCAL_PATH.search(value):
            value = "<redacted: local path>"
        published[name] = value
    return published


def pins_at(root, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("The build source must be a full 40-character commit SHA")
    pins = {}
    for name, path in PINS.items():
        result = subprocess.run(
            ["git", "show", f"{commit}:{path}"], cwd=root, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise ValueError(f"Cannot read {path} at {commit}: {result.stderr.strip()}")
        value = result.stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise ValueError(f"Unexpected pin in {path}")
        pins[name] = value
    return pins


def browser_version(output, pins):
    match = re.fullmatch(r"(?:.*\s)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*", output, re.DOTALL)
    if match is None:
        raise ValueError("The executable version must end with a four-part version")
    version = match.group(1)
    # Brave reports <Chromium major>.<Brave major>.<Brave minor>.<build>.
    brave = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.[0-9]+", pins["brave_core"])
    chromium = re.fullmatch(r"([0-9]+)\.[0-9]+\.[0-9]+\.[0-9]+", pins["chromium"])
    if brave is None or chromium is None:
        raise ValueError("Brave and Chromium pins must be version tags to cross-check the browser")
    if not version.startswith(f"{chromium.group(1)}.{brave.group(1)}.{brave.group(2)}."):
        raise ValueError(f"Browser version {version} does not match the pinned Brave and Chromium")
    return version


def provenance(root, options):
    archive = Path(options.zip)
    match = ARCHIVE.fullmatch(archive.name)
    if match is None or archive.is_symlink() or not archive.is_file():
        raise ValueError("Expected a regular Brave-Browser-Development-vX.Y.Z-macos-arm64.zip")
    sha256 = digest(archive)
    if options.sha256 != sha256:
        raise ValueError("The ZIP SHA-256 differs from the packager's printed hash")
    if not re.fullmatch(r"[0-9a-f]{40}", options.cdhash):
        raise ValueError("The app CDHash must be 40 lowercase hexadecimal characters")
    build_args = Path(options.build_args)
    values, imports = read_build_args(build_args, build_args.resolve().parents[2])
    pins = pins_at(root, options.source_commit)
    return {
        "schema": SCHEMA,
        "release": match.group(1),
        "artifact": archive.name,
        "sha256": sha256,
        "size_bytes": archive.stat().st_size,
        "platform": "macOS arm64",
        "browser_version": browser_version(options.executable_version, pins),
        "app_cdhash": options.cdhash,
        "build_source_commit": options.source_commit,
        "pins": pins,
        "build_args": published_args(values),
        "build_args_imports": imports,
        "build_origin": (
            "Local macOS arm64 workstation build of the pinned sources with the "
            "project's Brave overlays and patches (out/Static_arm64). Not built by "
            "clean CI and not an official Brave release."
        ),
        "signing": "Ad-hoc; not Developer ID signed or Apple-notarized",
        "packaging": (
            "scripts/package-brave-distribution.sh: strict signature, internal "
            "symlinks, extracted bundle signature and executable --version"
        ),
        "bundled_brave_services": "Off: patch 0014 defaults, not re-enabled by the build arguments",
        "proxy_and_worker_foundations": "Dormant; live proxy routing is not implemented.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--zip", required=True, help="packaged Brave ZIP")
    parser.add_argument("--sha256", required=True, help="SHA-256 printed by the packager")
    parser.add_argument("--source-commit", required=True, help="commit the browser was built from")
    parser.add_argument("--build-args", required=True, help="out/Static_arm64/args.gn")
    parser.add_argument("--executable-version", required=True,
                        help="output of the extracted browser's --version")
    parser.add_argument("--cdhash", required=True, help="CDHash of the extracted app")
    parser.add_argument("--output", help="defaults to the ZIP path with .provenance.json")
    options = parser.parse_args(argv)
    record = provenance(Path(__file__).resolve().parents[1], options)
    output = Path(options.output or str(Path(options.zip))[: -len(".zip")] + ".provenance.json")
    with output.open("x") as target:
        target.write(json.dumps(record, indent=2) + "\n")
    print(f"{digest(output)}  {output.name}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileExistsError) as error:
        sys.exit(f"write-brave-provenance: {error}")
