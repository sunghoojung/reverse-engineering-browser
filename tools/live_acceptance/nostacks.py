"""Session without --request-stacks (#429): no stack walk runs."""

from __future__ import annotations

from live_acceptance.evidence import find_rows, request_stack
from live_acceptance.fixture import Fixture, cors, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#429"
NAME = "no-stacks"
STACK_TYPES = "request_initiator_stack,async_task_stack,navigation_initiator_stack"
TARGETS = ("/nostacks/inline?r=1", "/nostacks/network?r=1", "/nostacks/eval?r=1", "/nostacks/await?r=1")

INDEX = document("no stacks", """<script src="/nostacks/network.js"></script>
<script>
fetch('/nostacks/inline?r=1');
eval("fetch('/nostacks/eval?r=1')");
REB.run('nostacks', async () => {
  await REB.sleep(5);
  await fetch('/nostacks/await?r=1');
});
</script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/nostacks/index.html", INDEX)
    fx.script("/nostacks/network.js", "fetch('/nostacks/network?r=1');\n")
    for target in TARGETS:
        fx.route(target.split("?")[0], lambda r: text_response("ok\n", "text/plain", cors(r)))


def drive(run: Run) -> None:
    run.open("/nostacks/index.html")
    run.wait(ISSUE, ["nostacks"], 60)


def verify(run: Run) -> None:
    problems: list[str] = []
    walked = run.api.events(STACK_TYPES)
    if walked:
        problems.append(f"{len(walked)} stack records: {sorted({event['type'] for event in walked})}")
    stored = run.api.artifacts(kind="stack")
    if stored:
        problems.append(f"{len(stored)} stack artifacts")
    for target in TARGETS:
        rows = find_rows(run.rows(), target=target)
        if len(rows) != 1:
            problems.append(f"{target}: {len(rows)} rows")
            continue
        stack = request_stack(run.api, rows[0])
        if stack.get("status") != "not_recorded" or rows[0].get("initiator_frame"):
            problems.append(f"{target}: stack {stack.get('status')}, initiator_frame {rows[0].get('initiator_frame')}")
    run.report.check(ISSUE, "no stack walk without --request-stacks", problems,
                     f"no stack records or artifacts; {len(TARGETS)} script requests read not_recorded")
