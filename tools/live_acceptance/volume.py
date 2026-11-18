"""#428 and #436 volume: every body kept whole, far past what older browsers kept.

A content session of its own moves more than 256 MiB of request bodies and
more than 512 MiB of response bodies, each over 64 MiB, a script over 16 MiB
and 5,000 small POSTs, and samples the browser process's memory while they
pass. Older browsers stopped at a 256 MiB request and a 512 MiB response
budget and kept at most 16 MiB of a body. Current capture has no such limit:
the 32 MiB in-flight pool bounds what the browser holds, so a fast body waits
for the artifact receiver instead of piling up in memory.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from functools import cache
import subprocess
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
# Response bodies stream from the network service through the browser's tee
# to the renderer, so Chromium itself holds none of them in the browser
# process: while they pass it may grow by less than one body. A browser that
# held a whole body would grow by at least 96 MiB; the in-flight pool is
# 32 MiB, and the rest is its own working set.
RESPONSE_GROWTH_LIMIT = RESPONSE_SIZE
# Chromium itself keeps an in-memory request body in the browser process
# while its request runs, so that phase may grow by one body and still less
# than a second: capture that held its own copy would reach two.
REQUEST_GROWTH_LIMIT = 2 * REQUEST_SIZE
SAMPLE_SECONDS = 0.25
BASELINE_SECONDS = 3
# What the session must move past: the budgets older browsers stopped at.
REQUEST_TOTAL_MIN, RESPONSE_TOTAL_MIN = 256 * MIB, 512 * MIB
# What older browsers stopped at; the summary must name none of it.
OLDER_LIMITS = {"not_captured_session_budget", "not_retained_session_budget", "captured_truncated"}

INDEX = document("volume", f"""<script>
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
  await REB.wait('volume:go', 120);
  await REB.run('volume:responses', async () => {{
    const sizes = [];
    for (let i = 0; i < {RESPONSES}; i++) {{
      sizes.push((await (await fetch('/volume/response?i=' + i)).arrayBuffer()).byteLength);
    }}
    return sizes;
  }});
  await REB.run('volume:requests', async () => {{
    for (let i = 0; i < {REQUESTS}; i++) {{
      await fetch('/volume/request?i=' + i, {{method: 'POST', body: bytes({REQUEST_SIZE}, 1000 + i)}});
    }}
    return {REQUESTS};
  }});
  await REB.run('volume:script', () => new Promise((resolve, reject) => {{
    const script = document.createElement('script');
    script.src = '/volume/script.js';
    script.onload = () => resolve(globalThis.rebVolumeScript);
    script.onerror = () => reject(new Error('the volume script failed'));
    document.head.append(script);
  }}));
  await REB.run('volume:posts', async () => {{
    const pad = 'p'.repeat(400);
    for (let i = 0; i < {POSTS}; i++) await fetch('/volume/post', {{method: 'POST', body: 'reb-post-' + i + '-' + pad}});
    return {POSTS};
  }});
}})();
</script>""")
RESULTS = ["volume:responses", "volume:requests", "volume:script", "volume:posts"]


def script_source() -> bytes:
    return _script(SCRIPT_BYTES)


@cache
def _script(size: int) -> bytes:
    return f"globalThis.rebVolumeScript = '{payload('volume-script', size).hex()}'.length;\n".encode()


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/volume/index.html", INDEX)
    fx.route("/volume/response", lambda r: bytes_response(
        payload(f"volume-response-{r.query.get('i')}", RESPONSE_SIZE), "application/octet-stream"),
        keep_bodies=False)
    fx.route("/volume/request", lambda r: text_response(f"received {len(r.body)} bytes\n", "text/plain"),
             keep_bodies=False)
    fx.route("/volume/script.js", lambda _r: bytes_response(script_source(), "text/javascript"), keep_bodies=False)
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


def resident_kib(pid: int) -> int | None:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True,
                         check=False).stdout.strip()
    return int(out) if out.isdigit() else None


@dataclass
class Memory:
    """Resident memory samples of the browser process, in KiB, by page phase."""

    pid: int
    baseline: list[int] = field(default_factory=list)
    phases: dict[str, list[int]] = field(default_factory=dict)
    phase: str = "responses"
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def rest(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if (kib := resident_kib(self.pid)) is not None:
                self.baseline.append(kib)
            time.sleep(SAMPLE_SECONDS)

    def start(self) -> None:
        def sample() -> None:
            while not self._stop.is_set():
                if (kib := resident_kib(self.pid)) is not None:
                    self.phases.setdefault(self.phase, []).append(kib)
                self._stop.wait(SAMPLE_SECONDS)

        self._thread = threading.Thread(target=sample, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()


def drive(run: Run) -> None:
    run.open("/volume/index.html")
    pid = browser_pid(run.session)
    memory = Memory(pid) if pid else None
    run.measurements[NAME] = memory
    if memory:
        memory.rest(BASELINE_SECONDS)
        memory.start()
    run.fixture.release("volume:go")
    try:
        # Each phase ends when the page reports it, so a sample is charged to
        # the bodies that were passing when it was taken.
        for name, after in (("volume:responses", "requests"), ("volume:requests", "script")):
            run.wait(ISSUE, [name], 900)
            if memory:
                memory.phase = after
        run.wait(ISSUE, ["volume:script"], 300)
    finally:
        if memory:
            memory.stop()
    run.wait(ISSUE, ["volume:posts"], 900)


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
    memory: Memory | None = run.measurements.get(NAME)
    case = "browser memory while the bodies pass"
    if memory is None:
        run.report.failed(ISSUE, case, "the capture browser's process was not found")
        return
    if not memory.baseline or not memory.phases.get("responses") or not memory.phases.get("requests"):
        counts = {phase: len(samples) for phase, samples in memory.phases.items()}
        run.report.failed(ISSUE, case, f"{len(memory.baseline)} samples at rest and {counts} while they passed")
        return
    rest = sorted(memory.baseline)[len(memory.baseline) // 2]
    problems: list[str] = []
    shown = []
    for phase, limit, moved in (("responses", RESPONSE_GROWTH_LIMIT, RESPONSES * RESPONSE_SIZE),
                                ("requests", REQUEST_GROWTH_LIMIT, REQUESTS * REQUEST_SIZE),
                                ("script", None, len(script_source()))):
        samples = memory.phases.get(phase) or []
        if not samples:
            continue
        growth = (max(samples) - rest) * 1024
        shown.append(f"{phase} ({moved / MIB:.0f} MiB): peak {max(samples) / 1024:.0f} MiB "
                     f"(+{growth / MIB:.1f} MiB, {len(samples)} samples)")
        if limit is not None and growth >= limit:
            problems.append(f"the browser grew by {growth / MIB:.1f} MiB while the {phase} passed, "
                            f"at least {limit // MIB} MiB")
    run.report.check("#428 #436", case, problems,
                     f"browser process {memory.pid} resident {rest / 1024:.0f} MiB at rest; " + "; ".join(shown)
                     + f"; sampled every {SAMPLE_SECONDS} s")


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
