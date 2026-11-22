"""#434 phase 1: an agent waits for the next fetch, click handler and CSP violation.

Then it keeps rules for later documents of the page's origin: a new tab's top
document records from its first script, its same-origin iframe (another frame
kind) records nothing, and once unwatch forgets them a new document records
nothing either.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from live_acceptance.evidence import ApiError
from live_acceptance.fixture import Fixture, cors, html_response, text_response
from live_acceptance.pages import document, line_of
from live_acceptance.run import Options, Run

ISSUE = "#434"
NAME = "debugger"
TYPES = ("request_watch_match", "listener_dispatch", "csp_violation")
CSP = ("Content-Security-Policy", "img-src 'self'")
# A frame or site reads one of these until its script's source artifact is
# stored. On a loaded host that can land after the observation itself, so the
# reads wait for it; a source that never lands still fails with its reason.
PENDING = ("source_artifact_missing", "script_identity_missing", "script_identity_outside_scan")
SETTLE_SECONDS = 30
KEPT_TYPES = ("request_watch_match", "listener_dispatch")
# A kept document's records arrive while it loads; once its beacons did, a wait
# this long that returns nothing ends the read.
QUIET_MS = 2000


def index_page(cross_origin: str) -> str:
    return document("debugger observation", f"""<button id=target>watched button</button>
<script>
function onWatchedClick() {{
  REB.beacon('debugger:clicked');
}}
document.getElementById('target').addEventListener('click', onWatchedClick);
REB.beacon('debugger:ready');
REB.wait('debugger:armed', 180).then(async () => {{
  await REB.sleep(300);
  fetch('/api/x?r=1');
  await REB.sleep(300);
  document.getElementById('target').click();
  await REB.sleep(300);
  const image = new Image();
  image.src = '{cross_origin}/debugger/blocked.png';
  await REB.sleep(300);
  REB.beacon('debugger:done');
}});
</script>""")


# Both run their rules' triggers in their first own script, before anything
# could arm them from outside the page.
KEPT_PAGE = document("kept debugger rules", """<button id=kept>kept button</button>
<script>
function onKeptClick() {}
document.getElementById('kept').addEventListener('click', onKeptClick);
document.getElementById('kept').click();
fetch('/api/kept?top=1');
REB.beacon('debugger:kept:' + new URLSearchParams(location.search).get('n'));
</script>
<iframe src="/debugger/kept-child.html"></iframe>""")
KEPT_CHILD = document("kept debugger rules child", """<button id=child>child button</button>
<script>
function onChildClick() {}
document.getElementById('child').addEventListener('click', onChildClick);
document.getElementById('child').click();
fetch('/api/kept?child=1');
REB.beacon('debugger:kept-child:' + new URLSearchParams(parent.location.search).get('n'));
</script>""")


def install(fx: Fixture, _options: Options) -> None:
    fx.route("/debugger/index.html", lambda _r: html_response(index_page(fx.cross_site_origin), [CSP]))
    fx.route("/debugger/kept.html", lambda _r: html_response(KEPT_PAGE))
    fx.route("/debugger/kept-child.html", lambda _r: html_response(KEPT_CHILD))
    fx.route("/api/x", lambda r: text_response("x\n", "text/plain", cors(r)))
    fx.route("/api/kept", lambda r: text_response("kept\n", "text/plain", cors(r)))
    fx.route("/debugger/blocked.png", lambda _r: text_response("never loaded\n", "text/plain"))


class State:
    def __init__(self) -> None:
        self.error = ""
        self.observed: dict[str, dict] = {}
        self.stack: dict | None = None
        self.kept_error = ""
        self.kept_reply: object = None
        self.kept_state: object = None
        # (type, the resolved position its stack or site names) per record.
        self.kept_records: list[tuple[str, dict]] = []
        self.cleared_state: object = "not read"
        self.after_clear: list[dict] = []


STATE = State()


def console_target(run: Run, url: str) -> tuple[dict, dict] | None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        listing = run.api.get("/api/native-console")
        for target in listing.get("targets", []):
            if target.get("url") == url and target.get("frame", "top") == "top":
                return listing, target
        time.sleep(1)
    return None


def settle(read, resolution, timeout: float = SETTLE_SECONDS, interval: float = 0.5):
    """read() again until resolution(value) no longer waits on a source artifact."""
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if (resolution(value) or {}).get("reason") not in PENDING or time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def top_frame(stack: dict | None) -> dict:
    frames = (stack or {}).get("frames") or []
    return frames[0].get("resolution", {}) if frames else {}


def listener_site(event: dict | None) -> dict:
    site = ((event or {}).get("debugger_observation") or {}).get("site") or {}
    return site.get("resolution", site)


def pending(resolutions: list[dict]) -> dict:
    """The first position still waiting on a source artifact, for settle()."""
    return next((r for r in resolutions if r.get("reason") in PENDING), {})


def collect(run: Run, cursor: str) -> list[dict]:
    """Every kept-type record after cursor, until a wait returns nothing."""
    found: list[dict] = []
    while True:
        events, cursor = run.api.wait(",".join(KEPT_TYPES), cursor, QUIET_MS)
        if not events:
            return found
        found += events


def positions(run: Run, events: list[dict]) -> list[tuple[str, dict]]:
    """Each record's position: a request's stack top frame, a listener's site."""
    out = []
    for event in events:
        read = (event.get("debugger_observation") or {}).get("stack_read")
        if event["type"] == "request_watch_match" and read:
            out.append((event["type"], top_frame(settle(lambda: run.api.get("/api/request-stack", **read), top_frame))))
        else:
            out.append((event["type"], listener_site(event)))
    return out


def drive_kept(run: Run, console: str, target: dict) -> None:
    """Keep rules for the origin, open it in new tabs, then forget them."""
    kept = run.api.post("/api/native-console/actions", {
        "action": "runtime", "session_id": console, "target_id": target["id"],
        "command": {"operation": "watch", "keep": True, "rules": {
            "requests": [{"url_contains": "/api/kept"}], "events": ["click"]}}})
    runtime = kept.get("runtime") or {}
    if runtime.get("status") != "ok":
        STATE.kept_error = f"watch with keep was not armed: {runtime}"
        return
    STATE.kept_reply = runtime.get("kept")
    STATE.kept_state = (run.api.get("/api/native-debugger").get("watch") or {}).get("kept")
    cursor = run.api.cursor(",".join(KEPT_TYPES))
    if not run.open("/debugger/kept.html?n=1") or not run.wait(ISSUE, ["debugger:kept:1", "debugger:kept-child:1"], 30):
        STATE.kept_error = "the kept page did not load"
        return
    events = collect(run, cursor)
    # Listener sites resolve again on a filtered read once their source landed.
    sites = settle(lambda: run.api.get("/api/events", type="listener_dispatch", after=cursor, limit=16)["events"],
                   lambda found: pending([listener_site(event) for event in found]))
    events = [event for event in events if event["type"] != "listener_dispatch"] + sites
    STATE.kept_records = positions(run, events)
    run.api.post("/api/native-console/actions", {
        "action": "runtime", "session_id": console, "target_id": target["id"],
        "command": {"operation": "unwatch"}})
    STATE.cleared_state = (run.api.get("/api/native-debugger").get("watch") or {}).get("kept")
    cursor = run.api.cursor(",".join(KEPT_TYPES))
    if not run.open("/debugger/kept.html?n=2") or not run.wait(ISSUE, ["debugger:kept:2", "debugger:kept-child:2"], 30):
        STATE.kept_error = "the kept page did not load after unwatch"
        return
    STATE.after_clear = collect(run, cursor)


def drive(run: Run) -> None:
    global STATE
    STATE = State()
    url = run.url("/debugger/index.html")
    run.open("/debugger/index.html")
    if not run.wait(ISSUE, ["debugger:ready"], 30):
        return
    found = console_target(run, url)
    if found is None:
        STATE.error = f"get_native_console never listed {url}"
        return
    listing, target = found
    console = None
    try:
        connected = run.api.post("/api/native-console/actions", {
            "action": "connect_live", "binding_id": listing.get("binding_id"), "target_id": target["id"],
            "confirm_live": True})
        console = connected.get("session_id")
        armed = run.api.post("/api/native-console/actions", {
            "action": "runtime", "session_id": console, "target_id": target["id"],
            "command": {"operation": "watch", "rules": {
                "requests": [{"url_contains": "/api/x"}], "events": ["click"], "csp": True}}})
        if (armed.get("runtime") or {}).get("status") != "ok":
            STATE.error = f"watch was not armed: {armed.get('runtime')}"
            return
        start = cursor = run.api.cursor(",".join(TYPES))
        run.fixture.release("debugger:armed")
        deadline = time.monotonic() + 60
        while len(STATE.observed) < len(TYPES) and time.monotonic() < deadline:
            events, cursor = run.api.wait(",".join(TYPES), cursor, 10000)
            for event in events:
                STATE.observed.setdefault(event["type"], event)
        request = STATE.observed.get("request_watch_match")
        read = ((request or {}).get("debugger_observation") or {}).get("stack_read")
        if read:
            STATE.stack = settle(lambda: run.api.get("/api/request-stack", **read), top_frame)
        dispatch = STATE.observed.get("listener_dispatch")
        if dispatch is not None:
            # A filtered events read resolves a waiting site again once the manifest grew.
            STATE.observed["listener_dispatch"] = settle(lambda: (run.api.get(
                "/api/events", type="listener_dispatch", after=start, limit=1)["events"] or [dispatch])[0],
                listener_site)
        if not run.wait(ISSUE, ["debugger:done"], 30):
            STATE.kept_error = "not run: the first page never finished"
            return
        try:
            drive_kept(run, console, target)
        except ApiError as error:
            STATE.kept_error = str(error)
    except ApiError as error:
        STATE.error = str(error)
    finally:
        if console:
            try:
                run.api.post("/api/native-console/actions", {"action": "stop", "session_id": console})
            except ApiError:
                pass


def verify(run: Run) -> None:
    report = run.report
    if STATE.error:
        report.failed(ISSUE, "arm a watch", STATE.error)
        return
    page = index_page(run.fixture.cross_site_origin)

    problems: list[str] = []
    match = STATE.observed.get("request_watch_match")
    if match is None:
        problems.append("no request_watch_match for /api/x")
    else:
        if (match.get("debugger_observation") or {}).get("status") != "decoded":
            problems.append(f"observation {match.get('debugger_observation')}")
        resolution = top_frame(STATE.stack)
        want = line_of(page, "fetch('/api/x")
        if resolution.get("status") != "resolved" or resolution.get("line") != want:
            problems.append(f"its stack's top frame is {resolution or STATE.stack}, expected line {want}")
    report.check(ISSUE, "wait for the next fetch to /api/x and read its stack", problems,
                 "the match arrived and its stack starts at the fetch")

    problems = []
    dispatch = STATE.observed.get("listener_dispatch")
    observation = (dispatch or {}).get("debugger_observation") or {}
    detail = observation.get("detail") or {}
    want = line_of(page, "function onWatchedClick")
    resolution = listener_site(dispatch)
    if dispatch is None:
        problems.append("no listener_dispatch for click")
    elif detail.get("event_type") != "click" or resolution.get("line") != want:
        problems.append(f"event {detail.get('event_type')}, listener at {resolution}, expected line {want}")
    report.check(ISSUE, "wait for the next click handler and its position", problems,
                 f"the click listener resolves to line {want}")

    problems = []
    violation = STATE.observed.get("csp_violation")
    detail = ((violation or {}).get("debugger_observation") or {}).get("detail") or {}
    if violation is None:
        problems.append("no csp_violation")
    elif detail.get("directive") != "img-src" or detail.get("blocked_host") != "localhost":
        problems.append(f"directive {detail.get('directive')}, blocked host {detail.get('blocked_host')}")
    report.check(ISSUE, "wait for the next CSP violation", problems,
                 f"img-src blocked {detail.get('blocked_host')}, disposition {detail.get('disposition')}")

    origin = run.fixture.origin
    problems = []
    if STATE.kept_error:
        problems.append(STATE.kept_error)
    if STATE.kept_reply != {"origin": origin, "frame": "top"}:
        problems.append(f"the reply kept {STATE.kept_reply}")
    kept = STATE.kept_state if isinstance(STATE.kept_state, dict) else {}
    if (kept.get("origin"), kept.get("frame"), "dom" in (kept.get("rules") or {})) != (origin, "top", False):
        problems.append(f"get_native_debugger kept {STATE.kept_state}")
    report.check(ISSUE, "keep the rules for later documents of the origin", problems,
                 f"kept for {origin} top-frame documents")

    problems = []
    want = {("request_watch_match", "/debugger/kept.html", line_of(KEPT_PAGE, "fetch('/api/kept")),
            ("listener_dispatch", "/debugger/kept.html", line_of(KEPT_PAGE, "function onKeptClick"))}
    seen = set()
    for kind, resolution in STATE.kept_records:
        path = urlsplit(resolution.get("url") or "").path
        if resolution.get("status") != "resolved" or path not in ("/debugger/kept.html", "/debugger/kept-child.html"):
            problems.append(f"{kind} at {resolution}")
        elif path == "/debugger/kept-child.html":
            problems.append(f"{kind} from the child frame at line {resolution.get('line')}: another frame kind")
        else:
            seen.add((kind, path, resolution.get("line")))
    problems += [f"no {kind} at {path} line {line}" for kind, path, line in sorted(want - seen)]
    problems += [f"unexpected {kind} at {path} line {line}" for kind, path, line in sorted(seen - want)]
    report.check(ISSUE, "kept rules arm a new tab's document before its own scripts", problems,
                 "its first script's click and fetch recorded; its same-origin iframe recorded nothing")

    problems = []
    if STATE.cleared_state is not None:
        problems.append(f"get_native_debugger kept {STATE.cleared_state} after unwatch")
    if STATE.after_clear:
        problems.append(f"{len(STATE.after_clear)} records after unwatch: "
                        + ", ".join(sorted({event['type'] for event in STATE.after_clear})))
    report.check(ISSUE, "unwatch forgets the kept rules", problems,
                 "nothing kept, and a new document of the origin recorded nothing")
