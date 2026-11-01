#!/usr/bin/env python3
"""Record the tested companion/browser pair and its release notes."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess


REPOSITORY = "https://github.com/sunghoojung/reverse-engineering-browser"
PIN_SCRIPT = "scripts/prepare-release-brave.sh"
PIN_BEGIN = "# BEGIN reviewed paired browser pin"
PIN_END = "# END reviewed paired browser pin"
PIN_SHAPES = {
    "brave_name": r"Brave-Browser-Development-v[0-9]+\.[0-9]+\.[0-9]+-macos-arm64",
    "source_url": re.escape(REPOSITORY) + r"/releases/download/[A-Za-z0-9._-]+",
    "brave_sha256": r"[0-9a-f]{64}",
    "provenance_sha256": r"[0-9a-f]{64}",
    "build_source": r"[0-9a-f]{40}",
}
PROVENANCE_SCHEMA = "reb-brave-distribution-provenance-v1"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def pin_block(text):
    """Parse the one reviewed pin block that prepare-release-brave.sh also uses."""
    if text.count(PIN_BEGIN) != 1 or text.count(PIN_END) != 1:
        raise ValueError("The paired browser pin block is missing or repeated")
    block = text.split(PIN_BEGIN, 1)[1].split(PIN_END, 1)[0]
    values = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"readonly ([a-z0-9_]+)=([^\s'\"$`]+)", line)
        if match is None or match.group(1) in values:
            raise ValueError("The paired browser pin block has an unexpected line")
        values[match.group(1)] = match.group(2)
    if set(values) != set(PIN_SHAPES):
        raise ValueError("The paired browser pin block has unexpected names")
    return values


def browser_pin(root):
    values = pin_block((root / PIN_SCRIPT).read_text())
    unfinished = [name for name, shape in PIN_SHAPES.items() if not re.fullmatch(shape, values[name])]
    if unfinished:
        raise ValueError("The paired browser pin is unfinished: " + ", ".join(unfinished))
    return values


def notes_text(tag, source_sha, run_url, assets, browser):
    origin, brave, provenance, pair, sums = assets
    downloads = f"{REPOSITORY}/releases/download/{tag}"
    pins = browser["pins"]
    return (
        f"Origin Trace {tag} is a paired macOS Apple silicon release: the Origin Trace "
        "app and a new Brave Browser Development build that carries its native probes.\n\n"
        f"Download both [Origin Trace]({downloads}/{origin.name}) and "
        f"[Brave Browser Development for Apple silicon]({downloads}/{brave.name}). "
        "Extract the app bundles beside each other, or install Brave Browser "
        "Development in `/Applications`.\n\n"
        "## Changes since v0.3.2\n\n"
        "- **Native capture on by default.** Opening Origin Trace now also turns on "
        "every native capture switch that needs no researcher input: quiet mode "
        "(page `debugger;` statements are ignored) and Wasm `br_table` and "
        "`call_indirect` dispatch capture. Set `REB_NATIVE_QUIET_MODE`, "
        "`REB_NATIVE_WASM_DISPATCH` or `REB_NATIVE_WASM_CALL_INDIRECT` to `0` to "
        "opt out. Wasm dispatch capture compiles Wasm with Liftoff only.\n"
        "- **Wasm guest-state capture** with a researcher-supplied adapter recipe: "
        "typed locals and bounded memory snapshots at up to eight adapter sites, "
        "with the exact parent dispatch of nested guests. Recipes are evidence "
        "inputs, not proof of guest semantics.\n"
        "- **JavaScript dispatch-site capture** with a researcher-supplied site file: "
        "at most eight static interpreter-candidate sites. It records selector kinds and "
        "integer low bits, script IDs, source positions and the site's source digest, "
        "never argument, receiver or string contents.\n"
        "- **VM analysis:** structural dispatch-site classification, handler claims "
        "for array, rotated, aliased, helper-fetched and threaded interpreters, and "
        "observed runtime claims compared with static claims, including nested VMs.\n"
        "- **Native-only capture:** CDP transport, injected hooks and the live "
        "debugger are removed. Saved historical evidence stays inert.\n"
        "- **Interface:** a quieter Origin Trace shell and screens, and VM workspace "
        "layout fixes at narrow and short window sizes.\n"
        "- **Browser build:** depot_tools is pinned and a backported Brave init patch "
        "lets a fresh pinned checkout initialize again. The native integration "
        "now compiles in the full Brave build.\n\n"
        "## Live sessions\n\n"
        "Opening Origin Trace starts a live session directly with the Brave Browser "
        "Development build it finds, with no pairing prompt. This release was validated "
        f"with the Brave build published here (code signature CDHash `{browser['app_cdhash']}`). "
        "Another build starts only if it defines every native V8 flag the session "
        "requests: V8 ignores an unknown `--js-flags` entry and every later one, so "
        "Origin Trace refuses such a build and lists the missing flags. Set "
        "`REB_NATIVE_QUIET_MODE=0`, `REB_NATIVE_WASM_DISPATCH=0` and "
        "`REB_NATIVE_WASM_CALL_INDIRECT=0` to start it without those capture modes.\n\n"
        "## Release boundaries\n\n"
        "- Brave Browser Development was built locally on a macOS arm64 workstation "
        f"from pinned Brave {pins['brave_core']} and Chromium {pins['chromium']} "
        "sources with this project's overlays and patches. It is not an official "
        "Brave release and was not built in clean CI. "
        f"[Browser provenance]({downloads}/{provenance.name}) records the build "
        "commit, pins, build arguments and executable version.\n"
        "- Both app bundles are ad-hoc signed, not Apple-notarized.\n"
        "- Bundled Brave consumer services (Leo, News, Rewards, Talk, VPN and "
        "Wallet) stay off in this build.\n"
        "- Worker and proxy foundations remain dormant; live proxy routing is not "
        "implemented.\n"
        "- Before publishing, a fresh live session with this browser build on a local "
        "fixture recorded Wasm `br_table` and `call_indirect` observations, the Canvas "
        "readback image, network and fingerprint surfaces, and the native Console "
        "runtime check passed on the extracted ZIP. Guest-state adapters, JavaScript "
        "dispatch sites and Finder automatic launch were not exercised live.\n\n"
        f"Source: `{source_sha}`. [Validation pipeline]({run_url}). "
        f"[Pair provenance]({downloads}/{pair.name}). "
        f"[Checksums]({downloads}/{sums.name}).\n"
    )


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "build/release-pair"
    with (root / "apps/research-ui/macos/Info.plist").open("rb") as source:
        info = plistlib.load(source)
    version = info["CFBundleShortVersionString"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Invalid application version")
    tag = f"v{version}"
    if os.environ.get("RELEASE_TAG", tag) != tag:
        raise ValueError("Requested release does not match the application version")
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        if os.environ["GITHUB_REF_NAME"] != tag:
            raise ValueError("Tag does not match the packaged application version")
    if info.get("OriginTraceReleaseType") != "paired":
        raise ValueError("Only a paired application can be recorded as a release pair")
    pin = browser_pin(root)
    name = f"Brave-Browser-Development-{tag}-macos-arm64"
    if pin["brave_name"] != name:
        raise ValueError("The paired browser was not built for this release")
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    origin = output / f"Origin-Trace-{tag}-macos.zip"
    source_brave = output / "source" / f"{name}.zip"
    source_provenance = output / "source" / f"{name}.provenance.json"
    if (digest(source_brave) != pin["brave_sha256"]
            or digest(source_provenance) != pin["provenance_sha256"]):
        raise ValueError("Pinned Brave bytes or provenance changed")
    browser = json.loads(source_provenance.read_text())
    expected = {
        "schema": PROVENANCE_SCHEMA, "release": tag, "artifact": f"{name}.zip",
        "sha256": pin["brave_sha256"], "build_source_commit": pin["build_source"],
    }
    if any(browser.get(key) != value for key, value in expected.items()):
        raise ValueError("Brave provenance does not describe this pinned archive")
    if not re.fullmatch(r"[0-9a-f]{40}", str(browser.get("app_cdhash", ""))):
        raise ValueError("Brave provenance does not record the app CDHash")
    brave = output / f"{name}.zip"
    provenance = output / f"{name}.provenance.json"
    for path in (brave, provenance):
        if path.exists():
            raise FileExistsError(path)
    shutil.copyfile(source_brave, brave)
    shutil.copyfile(source_provenance, provenance)
    if digest(brave) != pin["brave_sha256"]:
        raise ValueError("Copied Brave bytes differ")
    run_url = f"{REPOSITORY}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    manifest = {
        "schema": "origin-trace-release-pair-v2",
        "release": tag,
        "source_commit": source_sha,
        "validation_run": run_url,
        "origin_trace": {
            "artifact": origin.name,
            "sha256": digest(origin),
            "size_bytes": origin.stat().st_size,
            "build_origin": "Pull-request macOS CI preview" if os.environ.get(
                "GITHUB_EVENT_NAME"
            ) == "pull_request" else "macOS release CI build",
        },
        "brave": {
            "artifact": brave.name,
            "sha256": pin["brave_sha256"],
            "size_bytes": brave.stat().st_size,
            "cdhash": browser["app_cdhash"],
            "build_source_commit": pin["build_source"],
            "hosted_source": f"{pin['source_url']}/{brave.name}",
            "provenance": browser,
            "provenance_artifact": provenance.name,
        },
        "pairing": {
            "platform": "macOS arm64",
            "installation": "Extract both app bundles into the same directory",
            "source_equivalence": (
                "Browser inputs and protocol bytes match the browser build source"
            ),
            "checks": [
                "Pinned Brave ZIP and provenance SHA256 from the hosted source",
                "Strict signatures, Brave CDHash equal to its provenance record, and "
                "extracted Brave executable version",
                "Real packaged launcher with disposable Brave profile",
                "Broker/receiver readiness and relocated WebKit UI",
                "Launcher shutdown and browser-exit cleanup",
                "Full native close/Quit suite including five repeated attempts",
                "Live sessions start without a pairing prompt; startup failure, Retry, "
                "Continue Offline and reopen with an owned unsigned fake browser",
                "Rendered packaged UI with hosted XCTest",
            ],
            "limits": [
                "Ad-hoc signing, not Apple notarization",
                "Brave is a local workstation build, not clean CI or an official Brave release",
                "Guest-state adapters, JavaScript dispatch sites and Finder automatic "
                "launch were not exercised live",
                "Worker/proxy foundations remain dormant",
            ],
        },
    }
    pair = output / f"Origin-Trace-Brave-{tag}.provenance.json"
    pair.write_text(json.dumps(manifest, indent=2) + "\n")
    assets = [origin, brave, provenance, pair]
    sums = output / f"SHA256SUMS-{tag}.txt"
    sums.write_text("".join(f"{digest(path)}  {path.name}\n" for path in assets))
    (output / "release-notes.md").write_text(
        notes_text(tag, source_sha, run_url, [*assets, sums], browser)
    )


if __name__ == "__main__":
    main()
