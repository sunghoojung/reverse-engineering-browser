"""The Console's browser tables: every activity record and every document ID is kept.

The browser kept the latest 64 resource completions of the Console's
documents, dropping older ones, and remembered the IDs of 256 documents that
are not targets, giving the oldest a new ID when it reported again. Through
the agent Console route, the top document fetches 600 resources, and the
Traffic reads must return every completion, page by page while `more` says
so, with no drop. A browser may return them all in one reply. Then a child-frame document-start rule runs in 300 frames, and the
first, the 41st and the last frame report again: each must keep the document
ID of its first report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time

from live_acceptance.evidence import ApiError
from live_acceptance.fixture import Fixture, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "Console tables"
NAME = "console-tables"
RESOURCES = 600
FRAMES = 300
# Frame 0 and 40 had their IDs recycled once 256 other documents reported.
AGAIN = (0, 40, FRAMES - 1)
SNIPPET = ("report('start ' + location.search);"
           "addEventListener('message', () => report('again ' + location.search));")

INDEX = document("console tables", """<script>
REB.beacon('console-tables:ready', true);
</script>""")
FRAME = document("console tables frame", "")


@dataclass
class Measured:
    error: str | None = None
    fetched: str = ""
    events: list[dict] = field(default_factory=list)
    replies: int = 0
    paged: bool = False
    dropped: int = 0
    first: dict[int, str] = field(default_factory=dict)
    again: dict[int, str] = field(default_factory=dict)
    records_dropped: int = 0


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/console-tables/index.html", INDEX)
    fx.page("/console-tables/frame.html", FRAME)
    fx.route("/console-tables/resource", lambda _request: text_response("ok", "text/plain"))


def records(run: Run, after: str) -> tuple[list[dict], str, int]:
    """Every retained document-start record after the cursor, paging to the end."""
    found, dropped = [], 0
    while True:
        output = run.api.get("/api/native-console/document-start", after_sequence=after)["document_start"]["output"]
        dropped = int(output.get("dropped", 0))
        page = output["records"]
        if not page:
            return found, after, dropped
        found += page
        after = page[-1]["sequence"]


def reports(found: list[dict], word: str) -> dict[int, str]:
    by_frame = {}
    for record in found:
        text = record.get("text", "")
        if record.get("record") == "report" and text.startswith(word + " ?"):
            by_frame[int(text.split("?", 1)[1])] = record["document_id"]
    return by_frame


def drive(run: Run) -> None:
    measured = Measured()
    run.measurements[NAME] = measured
    run.open("/console-tables/index.html")
    if not run.wait(ISSUE, ["console-tables:ready"], 60):
        measured.error = "the page never loaded"
        return
    page = run.url("/console-tables/index.html")
    deadline = time.monotonic() + 30
    while True:
        listing = run.api.get("/api/native-console")
        top = next((target for target in listing.get("targets", [])
                    if target.get("url") == page and target.get("frame") == "top"), None)
        if listing.get("live_available") and top:
            break
        if time.monotonic() > deadline:
            measured.error = f"no live Console target for {page}: {listing}"
            return
        time.sleep(0.5)
    def console(body: dict) -> dict:
        return run.api.post("/api/native-console/actions", body)

    try:
        session = console({"action": "connect_live", "binding_id": listing["binding_id"], "target_id": top["id"],
                           "confirm_live": True})["session_id"]
    except ApiError as error:
        measured.error = f"connect_live: {error}"
        return
    target = {"session_id": session, "target_id": top["id"]}
    try:
        # Activity: every completion waits until Traffic reads it. A plain
        # evaluate has no top-level await, so the page counts its own fetches.
        console({"action": "evaluate", **target, "source": (
            f"window.rebFetched = 0; for (let i = 0; i < {RESOURCES}; i++) "
            "fetch('/console-tables/resource?' + i, {cache: 'no-store'}).then(r => r.text())"
            ".then(() => window.rebFetched++); 'started'")})
        deadline = time.monotonic() + 30
        while measured.fetched != str(RESOURCES) and time.monotonic() < deadline:
            time.sleep(0.2)
            measured.fetched = console({"action": "evaluate", **target,
                                        "source": "String(window.rebFetched)"}).get("text", "")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            reply = console({"action": "runtime", **target, "command": {"operation": "traffic"}})["runtime"]
            measured.replies += 1
            measured.events += reply.get("events", [])
            measured.dropped += int(reply.get("dropped", 0))
            measured.paged |= bool(reply.get("more"))
            if len(measured.events) >= RESOURCES and not reply.get("more"):
                break
            if not reply.get("more"):
                time.sleep(0.2)

        # Documents: 300 child frames report, then three of them again.
        console({"action": "arm_document_start", "session_id": session, "confirm_document_start": True,
                 "scripts": [{"origin": run.fixture.origin, "frame": "child", "path_prefix": "/console-tables/frame",
                              "source": SNIPPET}]})
        console({"action": "evaluate", **target, "source": (
            f"for (let i = 0; i < {FRAMES}; i++) {{ const frame = document.createElement('iframe'); "
            "frame.src = '/console-tables/frame.html?' + i; document.body.append(frame); } 'created'")})
        found, cursor = [], "0"
        deadline = time.monotonic() + 90
        while len(reports(found, "start")) < FRAMES and time.monotonic() < deadline:
            page_records, cursor, measured.records_dropped = records(run, cursor)
            found += page_records
            time.sleep(0.5)
        measured.first = reports(found, "start")
        console({"action": "evaluate", **target,
                 "source": f"for (const i of {list(AGAIN)}) frames[i].postMessage('again', '*'); 'sent'"})
        deadline = time.monotonic() + 30
        while len(reports(found, "again")) < len(AGAIN) and time.monotonic() < deadline:
            page_records, cursor, measured.records_dropped = records(run, cursor)
            found += page_records
            time.sleep(0.5)
        measured.again = reports(found, "again")
    except ApiError as error:
        measured.error = str(error)
    finally:
        for body in ({"action": "clear_document_start", "session_id": session}, {"action": "stop", "session_id": session}):
            try:
                console(body)
            except ApiError:
                pass


def verify(run: Run) -> None:
    report = run.report
    measured = run.measurements.get(NAME)
    if not isinstance(measured, Measured) or measured.error:
        report.failed(ISSUE, "console page", getattr(measured, "error", None) or "the drive did not run")
        return
    ids = {event.get("event_id") for event in measured.events}
    completions = [event for event in measured.events if event.get("operation") == "resource_load_complete"]
    problems = []
    if measured.fetched != str(RESOURCES):
        problems.append(f"the page fetched {measured.fetched!r}, expected {RESOURCES}")
    if len(completions) < RESOURCES:
        problems.append(f"{len(completions)} resource completions for {RESOURCES} fetches")
    if len(ids) != len(measured.events):
        problems.append(f"{len(measured.events) - len(ids)} repeated activity event IDs")
    if measured.dropped:
        problems.append(f"Traffic reported {measured.dropped} dropped")
    # A reply's page is a byte size, not a record count, so 600 completions may
    # fit in one; reading on while `more` says so is what is required.
    report.check(ISSUE, "every Console activity record", problems,
                 f"{len(completions)} completions in {measured.replies} Traffic replies"
                 f"{', paged' if measured.paged else ''}, past the old 64, none dropped")

    problems = []
    if len(measured.first) != FRAMES:
        problems.append(f"{len(measured.first)} of {FRAMES} frames reported")
    if len(set(measured.first.values())) != len(measured.first):
        problems.append("two frames share a document ID")
    for frame in AGAIN:
        if measured.again.get(frame) is None:
            problems.append(f"frame {frame} did not report again")
        elif measured.again[frame] != measured.first.get(frame):
            problems.append(f"frame {frame} reported as document {measured.again[frame]}, "
                            f"first as {measured.first.get(frame)}")
    if measured.records_dropped:
        problems.append(f"document-start output dropped {measured.records_dropped}")
    report.check(ISSUE, "every Console document ID kept", problems,
                 f"{len(measured.first)} child documents, past the old 256; frames {list(AGAIN)} kept their IDs")
