#!/usr/bin/env python3
"""Agentless DevTools observers only where no DevTools agent can tell.

protocol/native-network-v3.md ("Network-service binding at the pinned
Chromium"): capture never changes what a page or a real DevTools session
observes. An observer on a factory makes the network service mark each
response head `emitted_extra_info`, and a DevTools agent that sees the head
reports it as `hasExtraInfo`. So a Chromium patch may add
`NetworkServiceDevToolsObserver::MakeSelfOwned(std::string())` only in a
function listed here, whose response heads the contract shows reach no
DevTools agent, and only behind the `reb::NativeNetworkHeadersObserved()`
gate. Run with --self-test to check the checker.
"""

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHES = ROOT / "browser/integration/brave/patches/chromium"
AGENTLESS = "NetworkServiceDevToolsObserver::MakeSelfOwned(std::string())"
GATE = "reb::NativeNetworkHeadersObserved()"
# (file, function in the hunk header): why no DevTools agent sees the head.
ALLOWED = {
    ("content/browser/url_loader_factory_params_helper.cc", "CreateForEarlyHintsPreload"):
        "early-hints preloads have no DevTools instrumentation or request ID; "
        "PreloadURLLoaderClient reads two cache flags of the head",
}
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$")


def problems(patch_dir: Path) -> list:
    found = []
    for patch in sorted(patch_dir.glob("*.patch")):
        path, function, recent = None, "", []
        for number, line in enumerate(patch.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("+++ b/"):
                path, function, recent = line[6:], "", []
                continue
            header = HUNK.match(line)
            if header:
                function, recent = header.group(1), []
                continue
            if line.startswith(("-", "\\")):
                continue
            text = line[1:]
            if line.startswith("+") and AGENTLESS in text:
                key = next((key for key in ALLOWED if key[0] == path and key[1] in function), None)
                if key is None:
                    found.append(f"{patch.name}:{number}: agentless observer in {path} ({function.strip() or 'unknown function'}), "
                                 "where a DevTools agent may see the response head")
                elif not any(GATE in previous for previous in recent[-3:]):
                    found.append(f"{patch.name}:{number}: agentless observer without the {GATE} gate")
            # Context and added lines, so a gate on the line before counts.
            recent.append(text)
    return found


def self_test() -> None:
    allowed = (
        "+++ b/content/browser/url_loader_factory_params_helper.cc\n"
        "@@ -392,6 +393,18 @@ URLLoaderFactoryParamsHelper::CreateForEarlyHintsPreload(\n"
        "+  if (reb::NativeNetworkHeadersObserved()) {\n"
        "+    devtools_observer =\n"
        f"+        {AGENTLESS};\n")
    ungated = allowed.replace("reb::NativeNetworkHeadersObserved()", "true")
    worker = (
        "+++ b/content/browser/worker_host/shared_worker_host.cc\n"
        "@@ -545,6 +545,17 @@ SharedWorkerHost::CreateNetworkFactoryParamsForSubresources() {\n"
        "+  if (reb::NativeNetworkHeadersObserved()) {\n"
        f"+    devtools_observer = {AGENTLESS};\n")
    for text, expected in ((allowed, 0), (ungated, 1), (worker, 1)):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "0001-case.patch").write_text(text, encoding="utf-8")
            assert len(problems(Path(directory))) == expected, (text, problems(Path(directory)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        print("PASS header observer patch checker self-test")
        return 0
    found = problems(PATCHES)
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        return 1
    print("PASS agentless DevTools observers only on early-hints preloads, behind the header gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
