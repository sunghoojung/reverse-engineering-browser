"""#436 and #428 budgets: kept until the 1 MiB budget runs out, then shown.

A session of its own, started with 1 MiB request and response budgets, so the
content session's cases are not cut short by an exhausted budget.
"""

from __future__ import annotations

from collections import Counter

from live_acceptance.evidence import find_rows, for_row, summary_checks
from live_acceptance.fixture import Fixture, bytes_response, payload, sha256, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#436"
NAME = "budget"
BUDGET_MIB = 1
POSTS = 5000
RESPONSES, RESPONSE_SIZE = 12, 128 * 1024
BUDGET_CASE = "not_captured_session_budget"
# The artifact queue holds at most 288 opens and the writer waits for the
# receiver to accept each one, so on a loaded host some POST bodies are refused
# before the budget runs out, shown and counted, not lost. The page sends one
# POST at a time; three runs at load 17 to 47 refused none. More refusals than
# the queue holds means the receiver fell a whole queue behind: a regression.
TRANSFER_REFUSED_LIMIT = 288
TRANSFER_REFUSED = "not_captured_transfer_refused"

INDEX = document("budgets", f"""<script>
(async () => {{
  await REB.run('budget:responses', async () => {{
    const sizes = [];
    for (let i = 0; i < {RESPONSES}; i++) {{
      sizes.push((await (await fetch('/budget/response?i=' + i)).arrayBuffer()).byteLength);
    }}
    return sizes;
  }});
  await REB.run('budget:posts', async () => {{
    const pad = 'p'.repeat(400);
    for (let i = 0; i < {POSTS}; i++) await fetch('/budget/post', {{method: 'POST', body: 'reb-post-' + i + '-' + pad}});
    return {POSTS};
  }});
}})();
</script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/budget/index.html", INDEX)
    fx.route("/budget/response", lambda r: bytes_response(
        payload(f"budget-response-{r.query.get('i')}", RESPONSE_SIZE), "application/octet-stream"))
    fx.route("/budget/post", lambda r: text_response("ok\n", "text/plain"))


def drive(run: Run) -> None:
    run.open("/budget/index.html")
    run.wait(ISSUE, ["budget:responses"], 120)
    run.wait(ISSUE, ["budget:posts"], 900)


def ordered(states: list[str], kept: str, refused: tuple[str, ...] = ()) -> list[str]:
    """Problems with a sequence that should keep, then refuse for the budget.

    A `refused` state may appear only before the budget runs out."""
    problems = []
    if kept not in states or BUDGET_CASE not in states:
        problems.append(f"states {dict(Counter(states))}: expected some {kept}, then {BUDGET_CASE}")
        return problems
    first = states.index(BUDGET_CASE)
    late = [i for i, state in enumerate(states) if i > first and state != BUDGET_CASE]
    other = {state for state in states if state not in (kept, BUDGET_CASE, *refused)}
    if late:
        problems.append(f"{len(late)} kept after the budget ran out at #{first}")
    if other:
        problems.append(f"other states {sorted(other)}")
    return problems


def budget_shown(run: Run, category: str, problems: list[str]) -> str:
    checks = summary_checks(run.api.summary(), "request_content_not_retained", category=category, reason=BUDGET_CASE)
    if not checks:
        problems.append(f"get_session_summary has no request_content_not_retained {category} {BUDGET_CASE}")
        return ""
    check = checks[0]
    if check.get("budget_mib") != BUDGET_MIB:
        problems.append(f"budget_mib {check.get('budget_mib')}, expected {BUDGET_MIB}")
    if int(check.get("retained_bytes") or 0) > BUDGET_MIB * 1024 * 1024:
        problems.append(f"retained_bytes {check.get('retained_bytes')} over the budget")
    return f"{check.get('count')} refused, {check.get('retained_bytes')} bytes retained of {BUDGET_MIB} MiB"


def verify(run: Run) -> None:
    report, fx, rows = run.report, run.fixture, run.rows()

    problems: list[str] = []
    cases = []
    for index in range(RESPONSES):
        found = find_rows(rows, target=f"/budget/response?i={index}")
        body = (found[0].get("response_body") or {}) if len(found) == 1 else {}
        cases.append(body.get("case", f"{len(found)} rows"))
        expected = payload(f"budget-response-{index}", RESPONSE_SIZE)
        if body.get("case") == "captured" and body.get("sha256") != sha256(expected):
            problems.append(f"response {index}: the kept digest differs from the server's")
    problems += ordered(cases, "captured")
    shown = budget_shown(run, "response_body", problems)
    report.check("#428", "response budget shown when it runs out", problems,
                 f"{cases.count('captured')} of {RESPONSES} kept, then {BUDGET_CASE}; {shown}")

    problems = []
    posts = find_rows(rows, target="/budget/post", method="POST")
    served = fx.receipts("/budget/post")
    if len(posts) != POSTS or len(served) != POSTS:
        problems.append(f"{len(posts)} rows and {len(served)} receipts, expected {POSTS} of each")
    records = [for_row(run.records()[0], row) for row in posts]
    if any(len(found) != 1 for found in records):
        problems.append(f"{sum(len(found) != 1 for found in records)} rows without exactly one request_body record")
    bodies = [found[0] for found in records if len(found) == 1]
    states = [body.state for body in bodies]
    problems += ordered(states, "captured", (TRANSFER_REFUSED,))
    if Counter(body.sha256 for body in bodies) != Counter(sha256(r.request.body) for r in served):
        problems.append("the recorded body digests are not the bodies the server received")
    kept = {body.sha256 for body in bodies if body.state == "captured"}
    stored = {artifact["sha256"] for artifact in run.api.artifacts(kind="request_body")}
    if not kept <= stored:
        problems.append(f"{len(kept - stored)} captured bodies have no request_body artifact")
    shown = budget_shown(run, "request_body", problems)
    refused = states.count(TRANSFER_REFUSED)
    if refused > TRANSFER_REFUSED_LIMIT:
        problems.append(f"{refused} bodies {TRANSFER_REFUSED}, more than the {TRANSFER_REFUSED_LIMIT} the artifact queue holds")
    if refused:
        checks = summary_checks(run.api.summary(), "request_content_not_retained",
                                category="request_body", reason=TRANSFER_REFUSED)
        counted = int(checks[0].get("count") or 0) if checks else 0
        if counted != refused:
            problems.append(f"get_session_summary counts {counted} {TRANSFER_REFUSED}, the records {refused}")
    report.check(ISSUE, f"{POSTS} small POSTs until the request budget runs out", problems,
                 f"{states.count('captured')} kept and {refused} refused by the artifact queue, "
                 f"then {states.count(BUDGET_CASE)} {BUDGET_CASE}; {shown}")
