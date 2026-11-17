"""#434 phase 1: an agent waits for the next fetch, click handler and CSP violation."""

from __future__ import annotations

import time

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


def install(fx: Fixture, _options: Options) -> None:
    fx.route("/debugger/index.html", lambda _r: html_response(index_page(fx.cross_site_origin), [CSP]))
    fx.route("/api/x", lambda r: text_response("x\n", "text/plain", cors(r)))
    fx.route("/debugger/blocked.png", lambda _r: text_response("never loaded\n", "text/plain"))


class State:
    def __init__(self) -> None:
        self.error = ""
        self.observed: dict[str, dict] = {}
        self.stack: dict | None = None


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
        run.wait(ISSUE, ["debugger:done"], 30)
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
