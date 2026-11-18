"""#428 and #436 volume: every body kept whole, far past what older browsers kept.

A content session of its own moves more than 256 MiB of request bodies and
more than 512 MiB of response bodies, each over 64 MiB, a script over 16 MiB
and 5,000 small POSTs, and measures the browser process's memory while they
pass. Older browsers stopped at a 256 MiB request and a 512 MiB response
budget and kept at most 16 MiB of a body. Current capture has no such limit:
the 32 MiB in-flight pool bounds what the browser holds, so a fast body waits
for the artifact receiver instead of piling up in memory.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time

from live_acceptance.evidence import Session, find_rows, for_row, summary_checks
from live_acceptance.fixture import Fixture, bytes_response, payload, text_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "#436"
NAME = "volume"
MIB = 1024 * 1024
REQUESTS, REQUEST_SIZE = 4, 72 * MIB
RESPONSES, RESPONSE_SIZE = 6, 96 * MIB
# Hex doubles it: a 24 MiB source.
SCRIPT_BYTES = 12 * MIB
POSTS = 5000
# The artifact queue holds at most 288 opens and the writer waits for the
# receiver to accept each one, so on a loaded host some small POST bodies are
# refused, shown and counted, not lost. The page sends one POST at a time.
# More refusals than the queue holds means the receiver fell a whole queue
# behind: a regression.
TRANSFER_REFUSED_LIMIT = 288
TRANSFER_REFUSED = "not_captured_transfer_refused"
# The browser's own memory follows what a page sends and receives: the same
# Brave without a session keeps hundreds of MiB after these uploads. So the
# same phases first run in that Brave without a session, and capture's share
# is the session's growth less that one. The pool holds 32 MiB; a capture
# that kept a body after its request, or copied one, adds a whole body, so
# each phase's share stays under one of its bodies.
SHARE_LIMITS = {"responses": RESPONSE_SIZE, "requests": REQUEST_SIZE}
SAMPLE_SECONDS = 0.25
BASELINE_SECONDS = 3
# What the session must move past: the budgets older browsers stopped at.
REQUEST_TOTAL_MIN, RESPONSE_TOTAL_MIN = 256 * MIB, 512 * MIB
# What older browsers stopped at; the summary must name none of it.
OLDER_LIMITS = {"not_captured_session_budget", "not_retained_session_budget", "captured_truncated"}
# The same phases without capture, at their own paths and beacons.
REFERENCE = "volume-reference"
PHASES = ("responses", "requests", "script")


def page(name: str, base: str, posts: bool) -> str:
    post_step = f"""
  await REB.run('{name}:posts', async () => {{
    const pad = 'p'.repeat(400);
    for (let i = 0; i < {POSTS}; i++) await fetch('{base}/post', {{method: 'POST', body: 'reb-post-' + i + '-' + pad}});
    return {POSTS};
  }});""" if posts else ""
    return document(name, f"""<script>
function bytes(length, seed) {{
  const out = new Uint8Array(length);
  const words = new Uint32Array(out.buffer);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < words.length; i++) {{
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
    words[i] = x >>> 0;
  }}
  return out;
}}
(async () => {{
  // The driver reads the browser's memory at rest first.
  await REB.beacon('{name}:ready');
  await REB.wait('{name}:go', 120);
  await REB.run('{name}:responses', async () => {{
    const sizes = [];
    for (let i = 0; i < {RESPONSES}; i++) {{
      sizes.push((await (await fetch('{base}/response?i=' + i)).arrayBuffer()).byteLength);
    }}
    return sizes;
  }});
  await REB.run('{name}:requests', async () => {{
    for (let i = 0; i < {REQUESTS}; i++) {{
      await fetch('{base}/request?i=' + i, {{method: 'POST', body: bytes({REQUEST_SIZE}, 1000 + i)}});
    }}
    return {REQUESTS};
  }});
  await REB.run('{name}:script', () => new Promise((resolve, reject) => {{
    const script = document.createElement('script');
    script.src = '{base}/script.js';
    script.onload = () => resolve(globalThis.rebVolumeScript);
    script.onerror = () => reject(new Error('the volume script failed'));
    document.head.append(script);
  }}));{post_step}
}})();
</script>""")


INDEX = page(NAME, "/volume", posts=True)
RESULTS = [f"{NAME}:{phase}" for phase in PHASES] + [f"{NAME}:posts"]


def script_source() -> bytes:
    return _script(SCRIPT_BYTES)


@cache
def _script(size: int) -> bytes:
    return f"globalThis.rebVolumeScript = '{payload('volume-script', size).hex()}'.length;\n".encode()


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/volume/index.html", INDEX)
    fx.page("/volume/reference/index.html", page(REFERENCE, "/volume/reference", posts=False))
    for base in ("/volume", "/volume/reference"):
        fx.route(f"{base}/response", lambda r: bytes_response(
            payload(f"volume-response-{r.query.get('i')}", RESPONSE_SIZE), "application/octet-stream"),
            keep_bodies=False)
        fx.route(f"{base}/request", lambda r: text_response(f"received {len(r.body)} bytes\n", "text/plain"),
                 keep_bodies=False)
        fx.route(f"{base}/script.js", lambda _r: bytes_response(script_source(), "text/javascript"),
                 keep_bodies=False)
    fx.route("/volume/post", lambda r: text_response("ok\n", "text/plain"))


# Browser memory -----------------------------------------------------------------


def browser_pid(session: Session) -> int | None:
    """The capture browser's main process: the one with the session's profile and no --type."""
    profile = f"--user-data-dir={session.document['session_dir']}/brave-profile"
    listed = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True,
                            check=False).stdout
    for line in listed.splitlines():
        pid, _, command = line.strip().partition(" ")
        if profile in command and " --type=" not in command:
            return int(pid)
    return None


FOOTPRINT = re.compile(r"Footprint: ([0-9.]+) (KB|MB|GB)")


def footprint_kib(pid: int) -> int | None:
    """The process's physical footprint, the memory macOS charges it for.

    Resident size also counts pages the allocator has freed but not yet
    returned, so it would charge capture for memory nothing holds.
    """
    out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True, check=False).stdout
    found = FOOTPRINT.search(out)
    if not found:
        return None
    return round(float(found[1]) * {"KB": 1, "MB": 1024, "GB": 1024 * 1024}[found[2]])


@dataclass
class Memory:
    """Physical footprint samples of a browser process, in KiB, by page phase."""

    pid: int
    baseline: list[int] = field(default_factory=list)
    phases: dict[str, list[int]] = field(default_factory=dict)
    phase: str = PHASES[0]
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def rest(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if (kib := footprint_kib(self.pid)) is not None:
                self.baseline.append(kib)
            time.sleep(SAMPLE_SECONDS)

    def start(self) -> None:
        def sample() -> None:
            while not self._stop.is_set():
                if (kib := footprint_kib(self.pid)) is not None:
                    self.phases.setdefault(self.phase, []).append(kib)
                self._stop.wait(SAMPLE_SECONDS)

        self._thread = threading.Thread(target=sample, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()

    def growth(self, phase: str) -> int | None:
        """The phase's peak over the median at rest, in bytes."""
        samples = self.phases.get(phase)
        if not self.baseline or not samples:
            return None
        return (max(samples) - sorted(self.baseline)[len(self.baseline) // 2]) * 1024


def measure(run: Run, name: str, pid: int) -> Memory:
    """Samples one browser through the page's phases; each ends when the page reports it."""
    memory = Memory(pid)
    run.fixture.wait_beacons([f"{name}:ready"], 120)
    memory.rest(BASELINE_SECONDS)
    memory.start()
    run.fixture.release(f"{name}:go")
    try:
        for phase, after in zip(PHASES, PHASES[1:] + ("",)):
            run.wait(ISSUE, [f"{name}:{phase}"], 900)
            memory.phase = after
    finally:
        memory.stop()
    return memory


def reference(run: Run) -> Memory | str:
    """The same phases in the same Brave without a session, or why they did not run."""
    if run.options.brave is None:
        return "no Brave executable to run the page without a session"
    with tempfile.TemporaryDirectory(prefix="reb-volume-reference-") as profile:
        browser = subprocess.Popen(
            [str(run.options.brave), f"--user-data-dir={Path(profile) / 'profile'}", "--no-first-run",
             "--no-default-browser-check", run.url("/volume/reference/index.html")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            return measure(run, REFERENCE, browser.pid)
        finally:
            browser.terminate()
            try:
                browser.wait(60)
            except subprocess.TimeoutExpired:
                browser.kill()
                browser.wait()


def drive(run: Run) -> None:
    # Before the session's page, so the two browsers never pass bodies at once.
    run.measurements[REFERENCE] = reference(run)
    run.open("/volume/index.html")
    pid = browser_pid(run.session)
    if pid is None:
        run.measurements[NAME] = None
        run.fixture.release(f"{NAME}:go")
        for phase in PHASES:
            run.wait(ISSUE, [f"{NAME}:{phase}"], 900)
    else:
        run.measurements[NAME] = measure(run, NAME, pid)
    run.wait(ISSUE, [f"{NAME}:posts"], 900)


# Verification ----------------------------------------------------------------


def kept_whole(run: Run, artifact_id: str, length: int, digest: str, problems: list[str], label: str) -> None:
    """The stored artifact holds exactly this many bytes with this digest."""
    if artifact_id in (None, "0"):
        problems.append(f"{label}: no artifact")
        return
    stored = run.api.content_digest(artifact_id)
    if stored != (length, digest):
        problems.append(f"{label}: the artifact holds {stored[0]} bytes {stored[1][:12]}, "
                        f"the server's body {length} bytes {digest[:12]}")


def check_responses(run: Run) -> None:
    problems: list[str] = []
    total = 0
    for index in range(RESPONSES):
        target = f"/volume/response?i={index}"
        served = [r for r in run.fixture.receipts("/volume/response") if r.request.query.get("i") == str(index)]
        rows = find_rows(run.rows(), target=target)
        if len(served) != 1 or len(rows) != 1:
            problems.append(f"{target}: {len(rows)} rows and {len(served)} receipts")
            continue
        body, sent = rows[0].get("response_body") or {}, served[0]
        total += sent.decoded_length
        if (body.get("case"), body.get("body_length"), body.get("captured_length"), body.get("sha256")) != (
                "captured", str(sent.decoded_length), str(sent.decoded_length), sent.decoded_sha256):
            problems.append(f"{target}: case {body.get('case')}, {body.get('captured_length')} of "
                            f"{body.get('body_length')} bytes, the server sent {sent.decoded_length}")
            continue
        kept_whole(run, body.get("artifact_id"), sent.decoded_length, sent.decoded_sha256, problems, target)
    if total <= RESPONSE_TOTAL_MIN:
        problems.append(f"only {total / MIB:.0f} MiB of response bodies were served")
    run.report.check("#428", "response bodies past 512 MiB", problems,
                     f"{RESPONSES} bodies of {RESPONSE_SIZE / MIB:.0f} MiB, {total / MIB:.0f} MiB, each kept whole "
                     "with the server's bytes and digest")


def check_requests(run: Run) -> None:
    problems: list[str] = []
    total = 0
    bodies = run.records()[0]
    for index in range(REQUESTS):
        target = f"/volume/request?i={index}"
        served = [r for r in run.fixture.receipts("/volume/request") if r.request.query.get("i") == str(index)]
        rows = find_rows(run.rows(), target=target, method="POST")
        if len(served) != 1 or len(rows) != 1:
            problems.append(f"{target}: {len(rows)} rows and {len(served)} receipts")
            continue
        records, sent = for_row(bodies, rows[0]), served[0].request
        total += sent.length
        if len(records) != 1:
            problems.append(f"{target}: {len(records)} request_body records")
            continue
        record = records[0]
        if (record.state, record.body_length, record.captured_length, record.sha256) != (
                "captured", sent.length, sent.length, sent.sha256):
            problems.append(f"{target}: state {record.state}, {record.captured_length} of {record.body_length} "
                            f"bytes, the server received {sent.length}")
            continue
        kept_whole(run, record.artifact_id, sent.length, sent.sha256, problems, target)
    if total <= REQUEST_TOTAL_MIN:
        problems.append(f"only {total / MIB:.0f} MiB of request bodies reached the server")
    run.report.check(ISSUE, "request bodies past 256 MiB", problems,
                     f"{REQUESTS} bodies of {REQUEST_SIZE / MIB:.0f} MiB, {total / MIB:.0f} MiB, each kept whole "
                     "with the bytes and digest the server received")


def check_script(run: Run) -> None:
    problems: list[str] = []
    served = run.fixture.receipts("/volume/script.js")
    rows = find_rows(run.rows(), target="/volume/script.js")
    ok, value = run.result("volume:script")
    if not ok or value != SCRIPT_BYTES * 2:
        problems.append(f"the page ran the script: {value}")
    if len(served) != 1 or len(rows) != 1:
        problems.append(f"{len(rows)} rows and {len(served)} receipts")
    else:
        sent = served[0]
        case = (rows[0].get("response_body") or {}).get("case")
        found = run.api.artifacts(kind="javascript", sha256=sent.decoded_sha256)
        if case != "source_artifact":
            problems.append(f"case {case}, expected source_artifact")
        if len(found) != 1 or found[0].get("byte_size") != sent.decoded_length:
            problems.append(f"{len(found)} javascript artifacts with the served digest, sizes "
                            f"{[a.get('byte_size') for a in found]}, the server sent {sent.decoded_length}")
        else:
            kept_whole(run, found[0]["artifact_id"], sent.decoded_length, sent.decoded_sha256, problems, "script")
    run.report.check(ISSUE, "compiled script past 16 MiB", problems,
                     f"a {len(script_source()) / MIB:.0f} MiB script is kept whole as its compiled source")


def check_posts(run: Run) -> None:
    problems: list[str] = []
    rows = find_rows(run.rows(), target="/volume/post", method="POST")
    served = run.fixture.receipts("/volume/post")
    if len(rows) != POSTS or len(served) != POSTS:
        problems.append(f"{len(rows)} rows and {len(served)} receipts, expected {POSTS} of each")
    records = [for_row(run.records()[0], row) for row in rows]
    if any(len(found) != 1 for found in records):
        problems.append(f"{sum(len(found) != 1 for found in records)} rows without exactly one request_body record")
    bodies = [found[0] for found in records if len(found) == 1]
    states = Counter(body.state for body in bodies)
    other = set(states) - {"captured", TRANSFER_REFUSED}
    if other:
        problems.append(f"states {dict(states)}: expected only captured and {TRANSFER_REFUSED}")
    if Counter(body.sha256 for body in bodies) != Counter(r.request.sha256 for r in served):
        problems.append("the recorded body digests are not the bodies the server received")
    kept = {body.sha256 for body in bodies if body.state == "captured"}
    stored = {artifact["sha256"] for artifact in run.api.artifacts(kind="request_body")}
    if not kept <= stored:
        problems.append(f"{len(kept - stored)} captured bodies have no request_body artifact")
    refused = states[TRANSFER_REFUSED]
    if refused > TRANSFER_REFUSED_LIMIT:
        problems.append(f"{refused} bodies {TRANSFER_REFUSED}, more than the {TRANSFER_REFUSED_LIMIT} "
                        "the artifact queue holds")
    if refused:
        checks = summary_checks(run.api.summary(), "request_content_not_retained",
                                category="request_body", reason=TRANSFER_REFUSED)
        counted = int(checks[0].get("count") or 0) if checks else 0
        if counted != refused:
            problems.append(f"get_session_summary counts {counted} {TRANSFER_REFUSED}, the records {refused}")
    run.report.check(ISSUE, f"{POSTS} small POSTs", problems,
                     f"{states['captured']} kept and {refused} refused by the artifact queue; no count limit")


def check_no_older_limit(run: Run) -> None:
    checks = [check for check in summary_checks(run.api.summary(), "request_content_not_retained")
              if check.get("reason") in OLDER_LIMITS or "budget_mib" in check or "retained_bytes" in check]
    problems = [f"get_session_summary names {check.get('category')} {check.get('reason')}" for check in checks]
    run.report.check(ISSUE, "no content budget or size limit", problems,
                     "the session summary names no budget, truncation or budget figures")


def check_memory(run: Run) -> None:
    case = "browser memory while the bodies pass"
    memory: Memory | None = run.measurements.get(NAME)
    without: Memory | str = run.measurements.get(REFERENCE) or "it did not run"
    if memory is None:
        run.report.failed("#428 #436", case, "the capture browser's process was not found")
        return
    if isinstance(without, str):
        run.report.failed("#428 #436", case, f"the same page without a session: {without}")
        return
    problems: list[str] = []
    shown = []
    for phase, moved in (("responses", RESPONSES * RESPONSE_SIZE), ("requests", REQUESTS * REQUEST_SIZE),
                         ("script", len(script_source()))):
        grew, alone = memory.growth(phase), without.growth(phase)
        if grew is None or alone is None:
            problems.append(f"no {phase} samples: {len(memory.phases.get(phase) or [])} with capture, "
                            f"{len(without.phases.get(phase) or [])} without")
            continue
        share = grew - alone
        shown.append(f"{phase} ({moved / MIB:.0f} MiB) +{grew / MIB:.0f} MiB with capture, "
                     f"+{alone / MIB:.0f} MiB without, capture's share {share / MIB:+.0f} MiB")
        limit = SHARE_LIMITS.get(phase)
        if limit is not None and share >= limit:
            problems.append(f"capture added {share / MIB:.0f} MiB while the {phase} passed, at least one "
                            f"{limit // MIB} MiB body")
    rest = sorted(memory.baseline)[len(memory.baseline) // 2] if memory.baseline else 0
    measured = (f"browser process {memory.pid} footprint {rest / 1024:.0f} MiB at rest; " + "; ".join(shown)
                + f"; sampled every {SAMPLE_SECONDS} s")
    run.notes.append(f"volume memory: {measured}")
    run.report.check("#428 #436", case, problems, measured)


def verify(run: Run) -> None:
    for name in RESULTS:
        ok, error = run.result(name)
        if not ok:
            run.report.failed(ISSUE, f"page step {name}", str(error))
    check_responses(run)
    check_requests(run)
    check_script(run)
    check_posts(run)
    check_no_older_limit(run)
    check_memory(run)
