"""The guest sampler's tables: samples and host parents past 256 are all kept.

The renderer took at most 256 samples of a Wasm guest, and the browser routed
at most 256 host records to their guest dispatch parents and held at most 64
waiting for one. The pinned public QuickJS build runs under the fixture
adapter with a sample limit of 65536, and the guest calls canvas.measureText
through its host import 300 times. Every dispatch it took must be a sample,
past 256, and every host call one canvas record whose parent is a retained
dispatch of its process, with no sampling or host-parent gap.

Needs the fixture's packages: `npm ci --ignore-scripts --prefix
tools/quickjs-native-fixture` (tools/quickjs-native-fixture/README.md).
"""

from __future__ import annotations

import json
from pathlib import Path

from live_acceptance.evidence import summary_checks
from live_acceptance.fixture import Fixture, Request, Response, bytes_response, text_response
from live_acceptance.run import Options, Run

ISSUE = "Guest tables"
NAME = "guest-tables"
FIXTURE = Path(__file__).resolve().parents[1] / "quickjs-native-fixture"
MODULE = FIXTURE / "node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.wasm"
SAMPLE_LIMIT = 65536
# Each visit calls the host this many times, and the guest visits twice.
VISITS = 150
HOSTS = 2 * VISITS
OLD_LIMIT = 256
HOST_GAPS = ("native_guest_host_parent_budget", "native_guest_host_parent_omitted", "native_guest_host_parent_lost")
KINDS = {".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
         ".json": "application/json"}
SOURCE = (f"function visit(n){{for(let i=0;i<n;i++){{if((i&1)===0)hostProbe(100+i);else hostProbe(200+i);}}}} "
          f"visit({VISITS});visit({VISITS});'complete';")

PAGE = f"""<!doctype html><meta charset="utf-8"><title>guest tables</title>
<script src="/__lib.js"></script>
<script type="importmap">{{"imports":{{"quickjs-emscripten-core":"./node_modules/quickjs-emscripten-core/dist/index.mjs","@jitl/quickjs-ffi-types":"./node_modules/@jitl/quickjs-ffi-types/dist/index.mjs","@jitl/quickjs-wasmfile-debug-sync":"./node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/index.mjs","@jitl/quickjs-wasmfile-debug-sync/emscripten-module":"./node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.browser.mjs"}}}}</script>
<script type="module">
import {{newQuickJSWASMModuleFromVariant}} from 'quickjs-emscripten-core';
import variant from '@jitl/quickjs-wasmfile-debug-sync';
REB.run('guest-tables:hosts', async () => {{
  const QuickJS = await newQuickJSWASMModuleFromVariant(variant), vm = QuickJS.newContext(), calls = [];
  const context = document.createElement('canvas').getContext('2d');
  const host = vm.newFunction('hostProbe', value => {{
    calls.push(vm.getNumber(value));
    context.measureText(String(calls.at(-1)));
  }});
  vm.setProp(vm.global, 'hostProbe', host);
  host.dispose();
  const result = vm.evalCode({json.dumps(SOURCE)}, 'reb-guest-tables.js');
  const value = result.error ? {{error: vm.dump(result.error)}} : vm.dump(result.value);
  (result.error || result.value).dispose();
  vm.dispose();
  return {{value, calls: calls.length}};
}});
</script>
"""


def adapter() -> str:
    """The fixture recipe with a sample limit far past 256, as canonical JSON."""
    recipe = json.loads((FIXTURE / "adapter.json").read_text(encoding="utf-8"))
    recipe["sample_limit"] = SAMPLE_LIMIT
    return json.dumps(recipe, sort_keys=True, separators=(",", ":"))


def arguments(root: Path) -> list[str]:
    path = root / "guest-adapter.json"
    path.write_text(adapter(), encoding="utf-8")
    return ["--guest-adapter", str(path)]


def packaged(request: Request) -> Response:
    """A file of the QuickJS fixture's installed packages, and nothing outside them."""
    relative = request.path.removeprefix("/guest-tables/")
    path = (FIXTURE / relative).resolve()
    if (FIXTURE / "node_modules").resolve() not in path.parents or not path.is_file():
        return text_response(f"no fixture file {request.path}\n", "text/plain", status=404)
    return bytes_response(path.read_bytes(), KINDS.get(path.suffix, "application/octet-stream"))


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/guest-tables/index.html", PAGE)
    fx.route_prefix("/guest-tables/node_modules/", packaged)


def drive(run: Run) -> None:
    if not MODULE.is_file():
        run.report.failed(ISSUE, "QuickJS packages",
                          "run `npm ci --ignore-scripts --prefix tools/quickjs-native-fixture` first")
        return
    run.open("/guest-tables/index.html")
    run.wait(ISSUE, ["guest-tables:hosts"], 120)


def text(event: dict) -> str:
    try:
        return bytes.fromhex(event.get("payload", "")).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def verify(run: Run) -> None:
    report = run.report
    if not MODULE.is_file():
        return
    ok, value = run.result("guest-tables:hosts")
    if not ok or not isinstance(value, dict) or value.get("value") != "complete" or value.get("calls") != HOSTS:
        report.failed(ISSUE, "QuickJS page", f"the page answered {value}")
        return
    dispatches = run.api.events("wasm_guest_dispatch")
    retained = {(event["process_id"], event["sequence_number"]) for event in dispatches}
    gaps = {check.get("reason"): check for check in summary_checks(run.api.summary(), "named_gap", category="vm")
            if str(check.get("reason", "")).startswith("native_guest_")}
    problems = []
    if len(dispatches) <= OLD_LIMIT:
        problems.append(f"{len(dispatches)} guest samples, not past {OLD_LIMIT}")
    if "native_guest_sample_limit" in gaps and len(dispatches) != SAMPLE_LIMIT:
        problems.append(f"a sample limit gap after {len(dispatches)} of {SAMPLE_LIMIT} samples")
    report.check(ISSUE, "every guest sample", problems,
                 f"{len(dispatches):,} guest dispatch samples under a limit of {SAMPLE_LIMIT:,}")

    hosts = [event for event in run.api.events("api_call", category="canvas") if text(event) == "canvas.measureText"]
    problems = []
    if len(hosts) != HOSTS:
        problems.append(f"{len(hosts)} canvas.measureText records for {HOSTS} host calls")
    orphans = [event["sequence_number"] for event in hosts
               if (event["process_id"], event["parent_event_id"]) not in retained]
    if orphans:
        problems.append(f"{len(orphans)} host records without a retained dispatch parent, first {orphans[:5]}")
    named = sorted(reason for reason in gaps if reason in HOST_GAPS)
    if named:
        problems.append(f"host parent gaps {named}")
    report.check(ISSUE, "every host parented", problems,
                 f"{len(hosts)} host records, past the old {OLD_LIMIT} routed and 64 held, each parented by a "
                 "retained guest dispatch")
