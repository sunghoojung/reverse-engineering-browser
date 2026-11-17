"""#430: sent, received and blocked cookies match the server; a JS write links to its position."""

from __future__ import annotations

from live_acceptance.evidence import find_rows, per_request
from live_acceptance.fixture import Fixture, Receipt, Request, Response, cors, html_response, sha256, text_response
from live_acceptance.pages import document, locate
from live_acceptance.run import Options, Run

ISSUE = "#430"
NAME = "cookies"
JS_WRITE = "document.cookie = 'js_lax=from-script; path=/; SameSite=Lax';"
# Name, value and attributes; cross-site sets add `_x` to every name.
VARIANTS = [
    ("srv_lax", "lax", "Path=/; SameSite=Lax"),
    ("srv_strict", "strict", "Path=/; SameSite=Strict"),
    ("srv_none_secure", "none-secure", "Path=/; SameSite=None; Secure"),
    ("srv_none_insecure", "none-insecure", "Path=/; SameSite=None"),
    ("srv_secure", "secure", "Path=/; Secure"),
    ("srv_plain", "plain", "Path=/"),
    ("srv_httponly", "httponly", "Path=/; HttpOnly"),
]
SAME_SITE = {"lax": "Lax", "strict": "Strict", "none": "None"}


def index_page(cross_origin: str) -> str:
    return document("cookies", f"""<script>
{JS_WRITE}
REB.run('cookies:same', async () => {{
  await fetch('/cookies/set?r=same');
  await fetch('/cookies/echo?r=same');
  const frame = document.createElement('iframe');
  frame.src = '{cross_origin}/cookies/cross.html';
  document.body.append(frame);
  await REB.wait('cookies:cross-done', 60);
  await fetch('/cookies/echo?r=after');
}});
</script>""")


def cross_page(origin: str) -> str:
    return document("cross-site cookies", f"""<script>
REB.run('cookies:cross', async () => {{
  await fetch('{origin}/cookies/echo?r=cross', {{credentials: 'include'}});
  await fetch('{origin}/cookies/set?r=cross', {{credentials: 'include'}});
}});
</script>""")


def set_cookie_lines(token: str) -> list[str]:
    suffix = "_x" if token == "cross" else ""
    return [f"{name}{suffix}={value}; {attributes}" for name, value, attributes in VARIANTS]


def _set(request: Request) -> Response:
    lines = set_cookie_lines(request.query.get("r", ""))
    return text_response("set\n", "text/plain", [*cors(request), *(("Set-Cookie", line) for line in lines)])


def install(fx: Fixture, _options: Options) -> None:
    fx.route("/cookies/index.html", lambda _r: html_response(index_page(fx.cross_site_origin)))
    fx.route("/cookies/cross.html", lambda _r: html_response(cross_page(fx.origin)))
    fx.route("/cookies/set", _set)
    fx.route("/cookies/echo", lambda r: text_response("echo\n", "text/plain", cors(r)))


def drive(run: Run) -> None:
    run.open("/cookies/index.html")
    if run.wait(ISSUE, ["cookies:cross"], 60):
        run.fixture.release("cookies:cross-done")
    run.wait(ISSUE, ["cookies:same"], 30)


def server_cookies(receipt: Receipt) -> list[tuple[str, str]]:
    """The name and value pairs of the Cookie header the server received."""
    pairs = []
    for name, value in receipt.request.headers:
        if name.lower() == "cookie":
            for part in value.split(";"):
                key, _, item = part.strip().partition("=")
                if key:
                    pairs.append((key, item))
    return pairs


def parse_set_cookie(line: str) -> dict:
    pair, *attributes = [part.strip() for part in line.split(";")]
    name, _, value = pair.partition("=")
    keys = {attribute.split("=")[0].lower(): attribute.partition("=")[2] for attribute in attributes}
    return {"name": name, "value": value, "secure": "secure" in keys, "http_only": "httponly" in keys,
            "same_site": SAME_SITE.get(keys.get("samesite", "").lower(), "Unspecified")}


def cookie_lists(run: Run, row: dict, side: str) -> tuple[list[dict], list[str]]:
    answer = per_request(run.api, "/api/request-cookies", row)
    cookies, problems = [], []
    for hop in answer.get("hops", []):
        if hop.get(f"{side}_missing"):
            problems.append(f"{side} list missing: {hop[f'{side}_missing']}")
        for listed in hop.get(side, []):
            if listed.get("state") not in ("captured", "captured_shared", "empty"):
                problems.append(f"{side} list state {listed.get('state')}")
            elif listed.get("state") != "empty" and listed.get("artifact") != "verified":
                problems.append(f"{side} list artifact {listed.get('artifact')}")
            cookies += listed.get("cookies", [])
    return cookies, problems


def check_sent(run: Run, token: str, problems: list[str]) -> list[dict]:
    receipts = run.fixture.receipts("/cookies/echo")
    receipt = next((r for r in receipts if r.request.query.get("r") == token), None)
    rows = find_rows(run.rows(), target=f"/cookies/echo?r={token}")
    if receipt is None or len(rows) != 1:
        problems.append(f"echo {token}: {len(rows)} rows, receipt {'seen' if receipt else 'missing'}")
        return []
    cookies, listed = cookie_lists(run, rows[0], "sent")
    problems += [f"echo {token}: {p}" for p in listed]
    seen = sorted((name, sha256(value.encode())) for name, value in server_cookies(receipt))
    sent = sorted((c.get("name"), c.get("value_sha256")) for c in cookies if not c.get("blocked"))
    if sent != seen:
        problems.append(f"echo {token}: recorded sent {[n for n, _ in sent]}, the server got {[n for n, _ in seen]}")
    for cookie in cookies:
        if cookie.get("blocked"):
            if cookie.get("name") in {name for name, _ in seen}:
                problems.append(f"echo {token}: {cookie.get('name')} is blocked but the server received it")
            if not cookie.get("exclusion_reasons"):
                problems.append(f"echo {token}: blocked {cookie.get('name')} names no reason")
    return cookies


def check_received(run: Run, token: str, later: set[str], later_blocked: set[str],
                   problems: list[str]) -> list[dict]:
    receipts = [r for r in run.fixture.receipts("/cookies/set") if r.request.query.get("r") == token]
    rows = find_rows(run.rows(), target=f"/cookies/set?r={token}")
    if len(receipts) != 1 or len(rows) != 1:
        problems.append(f"set {token}: {len(rows)} rows and {len(receipts)} receipts")
        return []
    cookies, listed = cookie_lists(run, rows[0], "received")
    problems += [f"set {token}: {p}" for p in listed]
    served = [parse_set_cookie(value) for name, value in receipts[0].response_headers if name.lower() == "set-cookie"]
    by_name = {cookie.get("name"): cookie for cookie in cookies if cookie.get("parsed")}
    if len(cookies) != len(served):
        problems.append(f"set {token}: {len(cookies)} received cookies, the server sent {len(served)}")
    for want in served:
        got = by_name.get(want["name"])
        if got is None:
            problems.append(f"set {token}: {want['name']} not recorded")
            continue
        for key in ("secure", "http_only", "same_site"):
            if got.get(key) != want[key]:
                problems.append(f"set {token}: {want['name']} {key} {got.get(key)}, the server sent {want[key]}")
        if got.get("value_sha256") != sha256(want["value"].encode()):
            problems.append(f"set {token}: {want['name']} value digest differs from the server's value")
        if got.get("blocked") and not got.get("exclusion_reasons"):
            problems.append(f"set {token}: blocked {want['name']} names no reason")
        if got.get("blocked") and want["name"] in later:
            problems.append(f"set {token}: {want['name']} was blocked on receipt but sent later")
        if token == "same" and not got.get("blocked") and want["name"] not in later | later_blocked:
            problems.append(f"set {token}: {want['name']} was stored, but the next same-site request "
                            "neither sent it nor recorded it as blocked")
    insecure = by_name.get("srv_none_insecure" + ("_x" if token == "cross" else ""))
    if insecure is not None and "samesite_none_insecure" not in insecure.get("exclusion_reasons", []) \
            and not insecure.get("blocked"):
        problems.append(f"set {token}: SameSite=None without Secure was stored")
    return cookies


def describe(cookies: list[dict]) -> str:
    blocked = [f"{c.get('name')}({','.join(c.get('exclusion_reasons', []))})" for c in cookies if c.get("blocked")]
    return "blocked " + (", ".join(blocked) if blocked else "none")


def verify(run: Run) -> None:
    report = run.report
    problems: list[str] = []
    sent = {token: check_sent(run, token, problems) for token in ("same", "cross", "after")}
    after = next((r for r in run.fixture.receipts("/cookies/echo") if r.request.query.get("r") == "after"), None)
    later = {name for name, _ in server_cookies(after)} if after else set()
    later_blocked = {c.get("name") for c in sent["after"] if c.get("blocked")}
    received_same = check_received(run, "same", later, later_blocked, problems)
    received_cross = check_received(run, "cross", later, later_blocked, problems)
    report.check(ISSUE, "sent, received and blocked match the server", problems,
                 f"same-site set {describe(received_same)}; cross-site set {describe(received_cross)}; "
                 f"cross-site send {describe(sent['cross'])}")

    problems = []
    provenance = run.api.get("/api/cookie-provenance", session_id=run.session.session_id, name="js_lax")
    writes = [s for s in provenance.get("script", []) if s.get("api") == "document.cookie set"]
    line, column = locate(index_page(run.fixture.cross_site_origin), JS_WRITE)
    if not writes:
        problems.append(f"no 'document.cookie set' for js_lax: {provenance.get('script')}")
    for write in writes:
        frames = (write.get("stack") or {}).get("frames") or []
        resolution = frames[0].get("resolution", {}) if frames else {}
        if resolution.get("status") != "resolved":
            problems.append(f"the write's frame is {resolution or write.get('script_frame')}")
        elif resolution.get("line") != line or not column <= resolution.get("column", 0) <= column + len(JS_WRITE):
            problems.append(f"the write resolves to {resolution.get('line')}:{resolution.get('column')}, "
                            f"the statement is at {line}:{column}")
        elif not (resolution.get("url") or "").endswith("/cookies/index.html"):
            problems.append(f"the write resolves to {resolution.get('url')}")
    linked = [c for c in provenance.get("sent_with", []) if c.get("written_by_script")]
    if not linked:
        problems.append("no sent js_lax cookie links to its script write (written_by_script)")
    report.check(ISSUE, "JS write links to its script position", problems,
                 f"document.cookie set of js_lax at {line}:{column} of /cookies/index.html, linked to {len(linked)} sends")

    report.manual(ISSUE, "Secure and SameSite=None on HTTPS",
                  "loopback serves plain http, where Chromium treats 127.0.0.1 and localhost as trustworthy, so "
                  "Secure is not exercised as on a real site. On an authorized https fixture repeat /cookies/set "
                  "and a cross-site https iframe, and check that Secure cookies are sent only over https and that "
                  "get_request_cookies blocked reasons match DevTools' Cookies tab (hasExtraInfo)")
