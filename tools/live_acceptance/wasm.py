"""Wasm sampling is paced per one-second window and keeps recording.

A hot loop runs 40 br_table functions through one call_indirect for longer than
three windows. Each renderer keeps at most 1024 full records per stream in a
window, and each function 64 by default, so the page outruns both limits. The
records must go on past the first window with one ordinal per stream, stay
within each limit, name the paced remainder as a sampling gap, and answer a
mid-loop reset_wasm_sample_budgets.
"""

from __future__ import annotations

import hashlib
import time

from live_acceptance.binary import MAGIC, _body, _function_names, _name, _section, _uleb, _vec
from live_acceptance.evidence import ApiError, summary_checks
from live_acceptance.fixture import Fixture, bytes_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "Wasm sampling"
NAME = "wasm"
FUNCTIONS = 40
RUN_INDEX = FUNCTIONS
LOOP_MS = 3500
RECORDS_PER_WINDOW = 1024
SAMPLES_PER_FUNCTION = 64
SECOND_NS = 1_000_000_000
# The driver resets the window once the loop has run this long.
RESET_AFTER = 1.2

INDEX = document("wasm sampling", f"""<script>
REB.run('wasm:hot', async () => {{
  const {{instance}} = await WebAssembly.instantiateStreaming(fetch('/wasm/paced.wasm'));
  const run = instance.exports.run;
  await REB.beacon('wasm:started', true);
  const end = performance.now() + {LOOP_MS};
  let calls = 0;
  while (performance.now() < end) {{
    for (let i = 0; i < 4000; i++) run(i);
    calls += 4000;
    // Yield, so the beacon and the page stay responsive.
    await new Promise(resolve => setTimeout(resolve, 0));
  }}
  return calls;
}});
</script>""")


def paced_module() -> bytes:
    """Functions 0..39 each run one br_table; `run(i)` calls function i % 40 through call_indirect."""
    i32_to_i32 = b"\x60\x01\x7f\x01\x7f"
    branch = (
        b"\x02\x40\x02\x40"          # block, block
        b"\x20\x00\x0e\x01\x00\x01"  # local.get 0; br_table [0] default 1
        b"\x0b\x41\x01\x0f\x0b"      # end; i32.const 1; return; end
        b"\x41\x02"                  # i32.const 2
    )
    run = (
        b"\x20\x00"                  # local.get 0 (the callee's argument)
        b"\x20\x00\x41" + _uleb(FUNCTIONS) + b"\x70"  # local.get 0; i32.const 40; i32.rem_u
        + b"\x11\x00\x00"            # call_indirect (type 0) table 0
    )
    return b"".join([
        MAGIC,
        _section(1, _vec([i32_to_i32])),
        _section(3, _vec([b"\x00"] * (FUNCTIONS + 1))),
        _section(4, _vec([b"\x70\x00" + _uleb(FUNCTIONS)])),
        _section(7, _vec([_name("run") + b"\x00" + _uleb(RUN_INDEX)])),
        _section(9, _vec([b"\x00\x41\x00\x0b" + _vec([_uleb(index) for index in range(FUNCTIONS)])])),
        _section(10, _vec([_body(branch)] * FUNCTIONS + [_body(run)])),
        _function_names({**{index: f"reb_branch_{index}" for index in range(FUNCTIONS)}, RUN_INDEX: "reb_run"}),
    ])


MODULE = paced_module()
MODULE_SHA256 = hashlib.sha256(MODULE).hexdigest()


class State:
    def __init__(self) -> None:
        self.reset: object = None
        self.reset_error: str | None = None


STATE = State()


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/wasm/index.html", INDEX)
    fx.route("/wasm/paced.wasm", lambda _r: bytes_response(MODULE, "application/wasm"))


def drive(run: Run) -> None:
    global STATE
    STATE = State()
    run.open("/wasm/index.html")
    if not run.wait(ISSUE, ["wasm:started"], 60):
        return
    time.sleep(RESET_AFTER)
    try:
        STATE.reset = run.api.action({"action": "reset_wasm_sample_budgets"})
    except (ApiError, OSError) as error:
        STATE.reset_error = str(error)
    run.wait(ISSUE, ["wasm:hot"], 60)


def observations(run: Run, kind: str) -> list[dict]:
    module = {artifact["artifact_id"] for artifact in run.api.artifacts()
              if artifact.get("sha256") == MODULE_SHA256}
    found = []
    for event in run.api.events(kind):
        decoded = event.get("wasm_observation") or {}
        if event.get("artifact_id") in module and decoded.get("status") == "decoded":
            found.append({**decoded, "time": int(event["monotonic_time_ns"]), "process": event["process_id"]})
    return found


def paced(rows: list[dict], label: str, per_function: int) -> list[str]:
    """Problems with one stream's records: one window or less, broken ordinals, or a limit exceeded."""
    problems: list[str] = []
    if len(rows) <= RECORDS_PER_WINDOW + 16 and label == "br_table":
        problems.append(f"{len(rows)} {label} records, expected more than one window of {RECORDS_PER_WINDOW}")
    if not rows:
        return problems or [f"no {label} records"]
    span = (max(row["time"] for row in rows) - min(row["time"] for row in rows)) / SECOND_NS
    if span < 2:
        problems.append(f"{label} records span {span:.2f} s of a {LOOP_MS / 1000} s loop; sampling stopped")
    for process in {row["process"] for row in rows}:
        indexes = sorted(row["sample_index"] for row in rows if row["process"] == process)
        if len(set(indexes)) != len(indexes):
            problems.append(f"{label} sample_index repeats in process {process}")
        if indexes and indexes[-1] < len(indexes) - 1:
            problems.append(f"{label} sample_index ends at {indexes[-1]} after {len(indexes)} records")
    # A one-second interval overlaps at most two windows.
    start = min(row["time"] for row in rows)
    buckets: dict[tuple[int, int], int] = {}
    totals: dict[int, int] = {}
    for row in rows:
        second = (row["time"] - start) // SECOND_NS
        key = (second, row["function_index"])
        buckets[key] = buckets.get(key, 0) + 1
        totals[second] = totals.get(second, 0) + 1
    worst = max(buckets.values())
    if worst > 2 * per_function:
        problems.append(f"a {label} function kept {worst} records in one second, past twice its {per_function}")
    if max(totals.values()) > 2 * RECORDS_PER_WINDOW:
        problems.append(f"{max(totals.values())} {label} records in one second, past two windows")
    return problems


def verify(run: Run) -> None:
    report = run.report
    ok, value = run.result("wasm:hot")
    if not ok:
        report.failed(ISSUE, "hot loop page", str(value))
        return
    sampling = (run.api.context().get("capture_options") or {}).get("wasm_sampling")
    want = {"version": 1, "streams": ["br_table", "call_indirect"], "window_ms": 1000, "every_record": False,
            "records_per_window": RECORDS_PER_WINDOW, "samples_per_function": None,
            "samples_per_indirect_site": None, "function_allow_count": 0, "function_deny_count": 0,
            "module_allowlist": False, "reset": "available"}
    report.check(ISSUE, "session context wasm_sampling",
                 [] if sampling == want else [f"capture_options.wasm_sampling {sampling}, expected {want}"],
                 "capture_options.wasm_sampling names both streams, the window and the reset")

    # The paced page cost, beside the wasm-every area's every-record figure.
    run.notes.append(f"{ISSUE}: page {value:,} calls in {LOOP_MS:,} ms ({value / LOOP_MS * 1000:,.0f} calls/s), paced")
    dispatch = observations(run, "wasm_dispatch_observation")
    problems = paced(dispatch, "br_table", SAMPLES_PER_FUNCTION)
    functions = {row["function_index"] for row in dispatch}
    if len(functions) < FUNCTIONS:
        problems.append(f"br_table records name {len(functions)} of {FUNCTIONS} functions")
    report.check(ISSUE, "br_table paced per window", problems,
                 f"{len(dispatch)} br_table records over {value} calls, {len(functions)} functions, "
                 f"sample_index to {max((row['sample_index'] for row in dispatch), default=0)}")

    indirect = observations(run, "wasm_indirect_observation")
    problems = paced(indirect, "call_indirect", SAMPLES_PER_FUNCTION)
    if len(indirect) <= SAMPLES_PER_FUNCTION:
        problems.append(f"{len(indirect)} call_indirect records, expected more than one window's {SAMPLES_PER_FUNCTION}")
    if any(row["function_index"] != RUN_INDEX for row in indirect):
        problems.append("a call_indirect record names a caller other than run")
    report.check(ISSUE, "call_indirect paced per window", problems,
                 f"{len(indirect)} call_indirect records from run, at most {SAMPLES_PER_FUNCTION} a window")

    summary = run.api.summary()
    gaps = {check.get("reason") for check in summary_checks(summary, "named_gap", category="vm")}
    expected = {"native_wasm_dispatch_budget_incomplete", "native_wasm_dispatch_function_budget_incomplete"}
    overflow = run.api.events("wasm_dispatch_overflow")
    problems = [] if gaps & expected else [f"vm named gaps {sorted(gaps)} name no br_table sampling budget"]
    if not overflow:
        problems.append("no wasm_dispatch_overflow identity for the paced remainder")
    report.check(ISSUE, "paced remainder is named", problems,
                 f"{', '.join(sorted(gaps & expected))}; {len(overflow)} overflow records")

    reset = STATE.reset if isinstance(STATE.reset, dict) else {}
    generation = reset.get("generation")
    problems = []
    if STATE.reset_error:
        problems.append(STATE.reset_error)
    elif reset.get("ok") is not True or not isinstance(generation, int) or generation < 1:
        problems.append(f"reset answered {STATE.reset}")
    report.check(ISSUE, "reset_wasm_sample_budgets mid-loop", problems, f"reset generation {generation}")
