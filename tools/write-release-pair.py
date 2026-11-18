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
import tempfile


REPOSITORY = "https://github.com/sunghoojung/reverse-engineering-browser"
PIN_SCRIPT = "scripts/prepare-release-brave.sh"
PIN_BEGIN = "# BEGIN reviewed paired browser pin"
PIN_END = "# END reviewed paired browser pin"
PIN_SHAPES = {
    "brave_name": r"Brave-Browser-Development-(v[0-9]+\.[0-9]+\.[0-9]+)-macos-arm64",
    "source_url": re.escape(REPOSITORY) + r"/releases/download/[A-Za-z0-9._-]+",
    "brave_sha256": r"[0-9a-f]{64}",
    "provenance_sha256": r"[0-9a-f]{64}",
    "build_source": r"[0-9a-f]{40}",
}
PROVENANCE_SCHEMA = "reb-brave-distribution-provenance-v1"
# The browser the previous release paired, for the notes' upgrade line.
PREVIOUS_BROWSER = "Brave v1.95.52 on Chromium 151.0.7922.108"
# What the notes may say the new browser build captures. Each claim is behavior
# a live session on that exact build has to show, so it starts here, pending,
# and stays out of the notes. The build-day runbook in
# docs/development/paired-release.md runs each one; move a claim to
# ACCEPTED_LIVE only with that evidence, and delete one that did not hold.
# A pair is not recorded while any claim is still pending.
PENDING_LIVE = (
    "A fresh live session with this build on an owned local fixture recorded Wasm "
    "`br_table` and `call_indirect` observations, the Canvas readback image, network "
    "and fingerprint surfaces, and the native Console runtime check passed on the "
    "extracted ZIP.",
    "Every script V8 compiles is captured, so `eval` and `new Function` on a page "
    "with no CSP, and worker scripts, are recorded with their source.",
    "Request and response headers and each request's cookies are recorded natively, "
    "`document.cookie` reads are named per cookie, and every header block or cookie "
    "list that was not kept is counted by reason.",
    "Response bodies are kept with exact bytes or a stated reason, a memory-cache "
    "reuse links to the bytes that first loaded it, and streamed bodies are kept as "
    "they arrive.",
    "Full URLs and request bodies up to 16 MiB, including file, blob and stream "
    "bodies, are kept within the byte budget the start panel sets.",
    "Every Traffic request links to its browser tab, including worker, service "
    "worker, worklet, early-hints and prefetch requests; a request with no tab is "
    "counted with a reason.",
    "With request stacks on, a renderer request carries the JavaScript and Wasm "
    "stack that started it, in workers too, linked across message posts.",
    "Synchronous XHR, service-worker failures and memory-cache reuse finish their "
    "requests in the renderer.",
    "Debugger observations (watched requests, uncaught exceptions and rejections, "
    "listener dispatches, timers, CSP violations and DOM mutations) arrive from the "
    "page for an agent to wait on.",
    "Each Wasm `br_table` sample names its direct caller, and Wasm traps, calls still "
    "executing and dispatch scope gaps are recorded.",
)
ACCEPTED_LIVE = ()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_text_atomically(path, text):
    """Replace a derived output only with complete bytes."""
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as target:
        temporary = Path(target.name)
        target.write(text)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def place_pinned_copy(source, destination, sha256):
    """Copy a pinned file once. A rerun accepts only the identical pinned bytes."""
    if destination.is_symlink() or (destination.exists() and digest(destination) != sha256):
        raise FileExistsError(destination)
    if destination.exists():
        return
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=f".{destination.name}.",
                                     delete=False) as target:
        temporary = Path(target.name)
    try:
        shutil.copyfile(source, temporary)
        if digest(temporary) != sha256:
            raise ValueError(f"Copied bytes differ from the pin: {destination.name}")
        os.link(temporary, destination)  # Never replaces a file that appeared meanwhile.
    finally:
        temporary.unlink(missing_ok=True)


def version_key(tag):
    return tuple(int(part) for part in tag[1:].split("."))


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


def notes_text(tag, brave_tag, source_sha, run_url, assets, browser):
    origin, brave, provenance, pair, sums = assets
    downloads = f"{REPOSITORY}/releases/download/{tag}"
    pins = browser["pins"]
    reused = brave_tag != tag
    paired = (
        f"the unchanged Brave Browser Development build first published with {brave_tag}"
        if reused else "a new Brave Browser Development build that carries its native probes"
    )
    if reused:
        browser_change = (
            f"- **Browser:** the Brave build is the {brave_tag} build byte for byte: the same "
            "ZIP, provenance and code signature. Every input the Brave build reads matches its "
            "build commit.\n"
        )
        validation = (
            f"- Before {brave_tag} was published, a fresh live session with this browser "
            "build on a local fixture recorded Wasm `br_table` and `call_indirect` "
            "observations, the Canvas readback image, network and fingerprint surfaces, "
            "and the native Console runtime check passed on the extracted ZIP. "
            "Guest-state adapters, JavaScript dispatch sites and Finder automatic launch "
            "were not exercised live.\n"
        )
        accepted = ""
    else:
        browser_change = (
            f"- **Browser:** Brave {pins['brave_core']} on Chromium {pins['chromium']}, "
            f"up from {PREVIOUS_BROWSER}, with this project's overlays and patches "
            "carried onto it.\n"
        )
        validation = (
            "- Guest-state adapters, JavaScript dispatch sites and Finder automatic "
            "launch were not exercised live. The pausing debugger is built in but off: "
            "nothing in Origin Trace turns it on.\n"
        )
        accepted = "## Checked live on this build\n\n" + (
            "".join(f"- {claim}\n" for claim in ACCEPTED_LIVE) if ACCEPTED_LIVE
            else "- No browser capture beyond startup is claimed for this build.\n"
        ) + "\n"
    return (
        f"Origin Trace {tag} is a paired macOS Apple silicon release: the Origin Trace "
        f"app and {paired}.\n\n"
        f"Download both [Origin Trace]({downloads}/{origin.name}) and "
        f"[Brave Browser Development for Apple silicon]({downloads}/{brave.name}). "
        "Extract the app bundles beside each other, or install Brave Browser "
        "Development in `/Applications`.\n\n"
        "## Changes since v0.5.2\n\n"
        f"{browser_change}"
        "- **Traffic, Sources and debugger:** Headers, Payload, Preview, Response and "
        "Cookies tabs in Traffic; an entropy and kind map, a cross-references dock and "
        "a debugger sidebar with Threads in Sources; agents can wait on debugger "
        "observations and Traffic marks watched requests.\n"
        "- **Flow workspace:** a session flow graph with linked panes and focus mode, and "
        "Wasm and VM control flow drawn as basic-block graphs.\n"
        "- **Wasm analysis:** a readable lifted view of one function, toolchain and "
        "well-known function identification, names that persist across reads, a function "
        "match between two modules, value flow for one operand or local, and an offline "
        "run of one function in a stubbed interpreter.\n"
        "- **In-app agent:** a chat dock that works over the `reb-api` MCP with a Claude or "
        "ChatGPT API key, or a Claude, ChatGPT or Grok subscription, at one of four "
        "permission levels.\n"
        "- **Starting a session:** an in-window start panel replaces the startup alerts, "
        "with Content limits for the request and response budgets and media capture.\n"
        "- **Look:** one color system and a Rosé Pine Dawn light theme.\n\n"
        f"{accepted}"
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
        f"{validation}\n"
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
    requested = os.environ.get("RELEASE_TAG")
    if requested is None:
        raise ValueError("Set RELEASE_TAG to the release being recorded")
    if requested != tag:
        raise ValueError("Requested release does not match the application version")
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        if os.environ["GITHUB_REF_NAME"] != tag:
            raise ValueError("Tag does not match the packaged application version")
    if info.get("OriginTraceReleaseType") != "paired":
        raise ValueError("Only a paired application can be recorded as a release pair")
    pin = browser_pin(root)
    name = pin["brave_name"]
    # An unchanged browser build may be paired again; it keeps the name and
    # provenance of the release it was built for.
    brave_tag = re.fullmatch(PIN_SHAPES["brave_name"], name).group(1)
    if version_key(brave_tag) > version_key(tag):
        raise ValueError("The paired browser was built for a later release")
    if brave_tag == tag and PENDING_LIVE:
        raise ValueError(
            f"{len(PENDING_LIVE)} release note claims about the new browser build are still "
            "pending live acceptance. Run them on the paired build, then move each one to "
            "ACCEPTED_LIVE or delete it")
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
        "schema": PROVENANCE_SCHEMA, "release": brave_tag, "artifact": f"{name}.zip",
        "sha256": pin["brave_sha256"], "build_source_commit": pin["build_source"],
    }
    if any(browser.get(key) != value for key, value in expected.items()):
        raise ValueError("Brave provenance does not describe this pinned archive")
    if not re.fullmatch(r"[0-9a-f]{40}", str(browser.get("app_cdhash", ""))):
        raise ValueError("Brave provenance does not record the app CDHash")
    brave = output / f"{name}.zip"
    provenance = output / f"{name}.provenance.json"
    place_pinned_copy(source_brave, brave, pin["brave_sha256"])
    place_pinned_copy(source_provenance, provenance, pin["provenance_sha256"])
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
                "Every input the Brave build reads matches the browser build source"
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
    write_text_atomically(pair, json.dumps(manifest, indent=2) + "\n")
    assets = [origin, brave, provenance, pair]
    sums = output / f"SHA256SUMS-{tag}.txt"
    write_text_atomically(sums, "".join(f"{digest(path)}  {path.name}\n" for path in assets))
    write_text_atomically(output / "release-notes.md",
                          notes_text(tag, brave_tag, source_sha, run_url, [*assets, sums], browser))


if __name__ == "__main__":
    main()
