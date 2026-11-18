"""#428 and #436 disk reserve: a body the receiver cannot store is named, never lost.

The free-disk reserve is the only bound on what a content session stores
(services/artifact-receiver/README.md#disk-reserve). This session's receiver
is told to keep 1 TiB more free space than the volume has, so it refuses every
artifact, and each refused body must say so in its record, its row and the
session summary.
"""

from __future__ import annotations

import os
from pathlib import Path
import re

from live_acceptance.evidence import find_rows, for_row, summary_checks
from live_acceptance.fixture import Fixture, bytes_response, payload, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#436"
NAME = "reserve"
MIB = 1024 * 1024
ABOVE_FREE_MIB = 1024 * 1024
REQUEST_SIZE, RESPONSE_SIZE = 256 * 1024, MIB
REFUSED = "not_captured_disk_reserve"

INDEX = document("reserve", f"""<script>
(async () => {{
  await REB.run('reserve:response', async () => (await (await fetch('/reserve/response')).arrayBuffer()).byteLength);
  await REB.run('reserve:request', async () => {{
    const body = new Uint8Array({REQUEST_SIZE});
    crypto.getRandomValues(body.subarray(0, 65536));
    return (await fetch('/reserve/request', {{method: 'POST', body}})).status;
  }});
}})();
</script>""")
RESULTS = ["reserve:response", "reserve:request"]


def environment(root: Path) -> dict[str, str]:
    """A reserve above the free space of the volume that holds the session's store."""
    stats = os.statvfs(root)
    free = stats.f_bavail * stats.f_frsize // MIB
    return {"REB_ARTIFACT_DISK_RESERVE_MIB": str(free + ABOVE_FREE_MIB)}


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/reserve/index.html", INDEX)
    fx.route("/reserve/response", lambda _r: bytes_response(payload("reserve-response", RESPONSE_SIZE),
                                                            "application/octet-stream"))
    fx.route("/reserve/request", lambda r: text_response(f"received {len(r.body)} bytes\n", "text/plain"))


def drive(run: Run) -> None:
    run.open("/reserve/index.html")
    run.wait(ISSUE, RESULTS, 120)


def counted(run: Run, category: str, problems: list[str]) -> str:
    checks = summary_checks(run.api.summary(), "request_content_not_retained", category=category, reason=REFUSED)
    count = int(checks[0].get("count") or 0) if checks else 0
    if count < 1:
        problems.append(f"get_session_summary counts no {category} {REFUSED}")
    return f"{count} {category}"


def verify(run: Run) -> None:
    report = run.report
    for name in RESULTS:
        ok, error = run.result(name)
        if not ok:
            report.failed(ISSUE, f"page step {name}", str(error))

    problems: list[str] = []
    session_dir = Path(run.session.document["session_dir"])
    try:
        text = (session_dir / "artifact-receiver.log").read_text(errors="replace")
    except OSError as error:
        text = ""
        problems.append(f"no receiver log: {error}")
    named = re.search(r"Artifact store: disk reserve ([0-9]+) bytes", text)
    reserve = int(named[1]) if named else 0
    stats = os.statvfs(session_dir)
    free = stats.f_bavail * stats.f_frsize
    if not named:
        problems.append("the receiver log names no disk reserve")
    elif reserve <= free:
        problems.append(f"the reserve {reserve} bytes is not above the {free} bytes free")
    report.check(ISSUE, "receiver disk reserve", problems,
                 f"the receiver keeps {reserve / 2**30:.0f} GiB free, above the volume's {free / 2**30:.0f} GiB")

    problems = []
    rows = find_rows(run.rows(), target="/reserve/response")
    body = (rows[0].get("response_body") or {}) if len(rows) == 1 else {}
    if len(rows) != 1:
        problems.append(f"{len(rows)} response rows")
    elif body.get("case") != REFUSED or body.get("artifact_id") not in (None, "0"):
        problems.append(f"response case {body.get('case')}, artifact {body.get('artifact_id')}")
    rows = find_rows(run.rows(), target="/reserve/request", method="POST")
    records = for_row(run.records()[0], rows[0]) if len(rows) == 1 else []
    if len(records) != 1:
        problems.append(f"{len(rows)} request rows with {len(records)} request_body records")
    elif (records[0].state, records[0].artifact_id, records[0].sha256) != (REFUSED, "0", None):
        problems.append(f"request body state {records[0].state}, artifact {records[0].artifact_id}, "
                        f"digest {'present' if records[0].sha256 else 'absent'}")
    stored = run.api.artifacts(kind="request_body,response_body")
    if stored:
        problems.append(f"{len(stored)} request or response bodies were stored past the reserve")
    shown = ", ".join([counted(run, "request_body", problems), counted(run, "response_body", problems)])
    report.check(ISSUE, "bodies refused for the disk reserve", problems,
                 f"the request and response bodies are {REFUSED}, none is stored, and the summary counts "
                 f"them apart from other refusals ({shown})")
