"""Tracked functions past the one-byte slot: every call of every site is kept.

The session arms 300 functions of one served script, more than the 256 sites a
one-byte slot named, and the page calls each of them three times. Every site
must then be armed, and every call one start and one settle in its own slot,
with that site's ordinals 0, 1 and 2, the site's exact key, and no invocation
gap of any kind.
"""

from __future__ import annotations

from collections import defaultdict
import importlib.util
from pathlib import Path

from live_acceptance.evidence import summary_checks
from live_acceptance.fixture import Fixture
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "Tracked functions"
NAME = "tracked"
SITES = 300
CALLS = 3
SCRIPT_PATH = "/tracked/sites.js"
SITE_TOOL = Path(__file__).resolve().parents[1] / "native-js-invocation-site.py"


def function_name(index: int) -> str:
    return f"rebTracked{index}"


SCRIPT = "\n".join([*(f"function {function_name(index)}(value){{return value+{index};}}" for index in range(SITES)),
                    "window.rebTracked=[" + ",".join(function_name(index) for index in range(SITES)) + "];", ""])

INDEX = document("tracked functions", f"""<script src="{SCRIPT_PATH}"></script>
<script>
REB.run('tracked:calls', async () => {{
  let calls = 0, sum = 0;
  for (let round = 0; round < {CALLS}; round++) {{
    for (const tracked of window.rebTracked) {{
      sum += tracked(round);
      calls++;
    }}
  }}
  return {{calls, sum}};
}});
</script>""")


def site_tool():
    spec = importlib.util.spec_from_file_location("native_js_invocation_site", SITE_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sites() -> list[dict]:
    """One site per function, by the `(` of its parameter list, in slot order."""
    tool = site_tool()
    raw = SCRIPT.encode()
    found = []
    for index in range(SITES):
        offset = raw.index(f"function {function_name(index)}(".encode()) + len(f"function {function_name(index)}")
        found.append(tool.site_from_bytes(raw, "1", offset))
    return found


def arguments(root: Path) -> list[str]:
    """The site file the session arms at launch, written beside its evidence."""
    path = root / "tracked-sites.json"
    path.write_text(site_tool().sites_text(sites()), encoding="utf-8")
    return ["--js-invocation-sites", str(path)]


def install(fx: Fixture, _options: Options) -> None:
    fx.script(SCRIPT_PATH, SCRIPT)
    fx.page("/tracked/index.html", INDEX)


def drive(run: Run) -> None:
    run.open("/tracked/index.html")
    run.wait(ISSUE, ["tracked:calls"], 60)


def verify(run: Run) -> None:
    report = run.report
    ok, value = run.result("tracked:calls")
    if not ok or not isinstance(value, dict) or value.get("calls") != SITES * CALLS:
        report.failed(ISSUE, "tracked page", f"the page answered {value}")
        return
    armed = (run.api.get("/api/js-invocation-sites").get("session") or {})
    report.check(ISSUE, "every site armed",
                 [] if armed.get("state") == "armed" and armed.get("count") == SITES
                 else [f"get_js_invocation_sites session state {armed.get('state')} count {armed.get('count')}"],
                 f"{SITES} sites armed, past the 256 of a one-byte slot")

    want = sites()
    starts: dict[int, list[int]] = defaultdict(list)
    settles: dict[int, int] = defaultdict(int)
    problems = []
    for event in run.api.events("js_invocation_start,js_invocation_settle"):
        decoded = event.get("js_invocation") or {}
        if decoded.get("status") != "decoded":
            problems.append(f"{event['type']} {event['sequence_number']} is {decoded.get('status')}")
            continue
        slot = decoded["site_slot"]
        if not 0 <= slot < SITES:
            problems.append(f"{event['type']} {event['sequence_number']} names slot {slot}")
            continue
        if decoded["kind"] == "settle":
            settles[slot] += 1
            continue
        site = want[slot]
        if (decoded["source_sha256"], decoded["anchor_offset"]) != (site["source_sha256"], site["anchor_offset"]):
            problems.append(f"slot {slot} start names {decoded['anchor_offset']}, site {site['anchor_offset']}")
        starts[slot].append(decoded["site_sample_index"])
    for slot in range(SITES):
        if sorted(starts.get(slot, [])) != list(range(CALLS)):
            problems.append(f"slot {slot} start ordinals {sorted(starts.get(slot, []))}")
        if settles.get(slot, 0) != CALLS:
            problems.append(f"slot {slot} has {settles.get(slot, 0)} settles")
    report.check(ISSUE, "every call of every site", problems[:20] + ([f"{len(problems) - 20} more"] if
                                                                      len(problems) > 20 else []),
                 f"{sum(len(found) for found in starts.values())} starts and {sum(settles.values())} settles "
                 f"over slots 0 to {SITES - 1}, ordinals 0 to {CALLS - 1} in each")

    gaps = sorted({check.get("reason") for check in summary_checks(run.api.summary(), "named_gap", category="vm")
                   if str(check.get("reason", "")).startswith("native_js_invocation")})
    report.check(ISSUE, "no invocation gap", [f"vm named gaps {gaps}"] if gaps else [],
                 "no native_js_invocation gap: no site refused, unsupported or compiled before arming")
