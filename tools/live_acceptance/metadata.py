"""Metadata session (#427, #429, #430): no header, cookie or body value is recorded."""

from __future__ import annotations

import os
from pathlib import Path

from live_acceptance.evidence import SENSITIVE_KINDS, find_rows, for_row, per_request, request_stack
from live_acceptance.fixture import Fixture, cors, html_response, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#427 #429 #430"
NAME = "metadata"
# Values only this page sends or sets; none may reach the session's files.
SECRETS = ("reb-secret-header-value", "reb-secret-body-value", "reb-secret-js-cookie",
           "reb-secret-server-cookie", "reb-secret-query-value")
CONTENT_TYPES = "request_headers,response_headers,cookie_list,script_cookie,response_body,request_target"


def index_page(cross_origin: str) -> str:
    return document("metadata", f"""<script>
document.cookie = 'meta_js=reb-secret-js-cookie; path=/';
REB.run('metadata', async () => {{
  await fetch('/meta/echo?q=reb-secret-query-value', {{
    method: 'POST', headers: {{'X-Reb-Probe': 'reb-secret-header-value'}}, body: 'reb-secret-body-value',
  }});
  await fetch('/meta/echo?r=2');
  eval("fetch('{cross_origin}/meta/eval', {{mode: 'no-cors'}})");
  await REB.sleep(500);
}});
</script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.route("/meta/index.html", lambda _r: html_response(index_page(fx.cross_site_origin)))
    fx.route("/meta/echo", lambda r: text_response(
        "echo\n", "text/plain", [*cors(r), ("Set-Cookie", "meta_srv=reb-secret-server-cookie; Path=/")]))
    fx.route("/meta/eval", lambda r: text_response("eval\n", "text/plain", cors(r)))


def drive(run: Run) -> None:
    run.open("/meta/index.html")
    run.wait(ISSUE, ["metadata"], 60)


def scan_files(root: Path) -> list[str]:
    """Session files that hold a fixture secret, which only a value capture writes.

    The browser's own profile keeps its cookie jar and cache, which are not
    evidence, so it is not searched.
    """
    found = []
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name != "brave-profile"]
        for name in names:
            path = Path(directory) / name
            try:
                data = path.read_bytes()
            except OSError:
                continue
            found += [f"{path.relative_to(root)} holds {secret}" for secret in SECRETS if secret.encode() in data]
    return found


def verify(run: Run) -> None:
    report = run.report
    problems: list[str] = []
    recorded = run.api.events(CONTENT_TYPES)
    if recorded:
        problems.append(f"{len(recorded)} value records: {sorted({event['type'] for event in recorded})}")
    kept = [a for a in run.api.artifacts(kind=",".join(sorted(SENSITIVE_KINDS)))]
    if kept:
        problems.append(f"{len(kept)} sensitive artifacts: {sorted({a['kind'] for a in kept})}")
    rows = [row for row in run.rows() if row.get("host") == f"127.0.0.1:{run.fixture.port}" and row.get("method") == "POST"]
    with_path = [row for row in run.rows() if row.get("target")]
    if with_path:
        problems.append(f"{len(with_path)} rows keep a path, e.g. {with_path[0].get('target')}")
    for row in rows:
        if per_request(run.api, "/api/request-headers", row).get("hops"):
            problems.append("get_request_headers returned header blocks")
        if per_request(run.api, "/api/request-cookies", row).get("hops"):
            problems.append("get_request_cookies returned cookie lists")
    bodies = [body for row in rows for body in for_row(run.records()[0], row)]
    if any(body.state != "metadata_only" for body in bodies):
        problems.append(f"request body states {[body.state for body in bodies]}")
    session_dir = Path(run.session.document.get("session_dir", ""))
    if session_dir.is_dir():
        problems += scan_files(session_dir)
    else:
        problems.append(f"session directory {session_dir} is missing")
    report.check(ISSUE, "no header, cookie or body value recorded", problems,
                 f"no value records or sensitive artifacts, {len(bodies)} POST body records metadata_only, "
                 f"and no session file holds any of {len(SECRETS)} fixture values")

    problems = []
    found = find_rows(run.rows(), host=f"localhost:{run.fixture.port}")
    if len(found) != 1:
        problems.append(f"{len(found)} rows for the eval's request to localhost")
    else:
        stack = request_stack(run.api, found[0])
        frames = stack.get("frames") or []
        top = frames[0] if frames else {}
        resolution = top.get("resolution") or {}
        if stack.get("status") != "recorded" or not top.get("eval") or resolution.get("reason") != "source_not_retained":
            problems.append(f"stack {stack.get('status')}, top frame eval {top.get('eval')} resolution {resolution}")
    report.check("#429", "eval frame in a metadata session", problems, "reports source_not_retained")
