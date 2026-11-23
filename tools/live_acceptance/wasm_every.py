"""Every Wasm record: the paced fixture's hot loop with no window at all.

The `wasm` area's 40 br_table functions run through one call_indirect for the
same 3.5 s, in a session started with `--wasm-every-record`. Every execution
must then be one full record on each stream, with one unbroken ordinal per
renderer and no sampling gap, overflow identity or transport loss, however long
the broker takes to drain them. The area also measures what that costs: the
page's calls per second (the `wasm` area's count is the paced figure), how fast
the records reach the evidence store, how long after the loop the last one
lands, and the browser process's footprint while they flow.

It reads the session's events.jsonl as the broker appends it instead of paging
the API, which would decode millions of records twice. While the records flow
it only counts them, at C speed, so the reader never paces the broker; the
records are decoded once the store holds them all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import time

from live_acceptance import volume, wasm
from live_acceptance.evidence import summary_checks
from live_acceptance.fixture import Fixture, bytes_response
from live_acceptance.pages import document
from live_acceptance.run import Options, Run

ISSUE = "Wasm every record"
NAME = "wasm-every"
# The store must hold every record by then; a broker that stalls fails here
# instead of hanging the run.
DRAIN_SECONDS = 900
POLL_SECONDS = 0.5
STREAMS = {"wasm_dispatch_observation": ("br_table", 20), "wasm_indirect_observation": ("call_indirect", 28)}
LOSSES = ("wasm_dispatch_overflow", "wasm_indirect_overflow")

INDEX = document("wasm every record", f"""<script>
REB.run('wasm-every:hot', async () => {{
  const {{instance}} = await WebAssembly.instantiateStreaming(fetch('/wasm-every/paced.wasm'));
  const run = instance.exports.run;
  await REB.beacon('wasm-every:started', true);
  const start = performance.now(), end = start + {wasm.LOOP_MS};
  let calls = 0;
  while (performance.now() < end) {{
    for (let i = 0; i < 4000; i++) run(i);
    calls += 4000;
    await new Promise(resolve => setTimeout(resolve, 0));
  }}
  return {{calls, ms: performance.now() - start}};
}});
</script>""")


@dataclass
class Stream:
    count: int = 0
    first_ns: int | None = None
    last_ns: int | None = None
    # One bit per sample index of each renderer process.
    seen: dict[int, bytearray] = field(default_factory=dict)
    repeats: int = 0

    def add(self, process: int, index: int, time_ns: int) -> None:
        self.count += 1
        self.first_ns = time_ns if self.first_ns is None else min(self.first_ns, time_ns)
        self.last_ns = time_ns if self.last_ns is None else max(self.last_ns, time_ns)
        bits = self.seen.setdefault(process, bytearray())
        byte, bit = divmod(index, 8)
        if byte >= len(bits):
            bits.extend(bytes(byte + 1 - len(bits) + (1 << 16)))
        if bits[byte] >> bit & 1:
            self.repeats += 1
        bits[byte] |= 1 << bit

    def holes(self) -> dict[int, int]:
        """Each process's sample indexes missing below its highest one."""
        found = {}
        for process, bits in self.seen.items():
            kept = sum(bin(value).count("1") for value in bits)
            top = max((8 * byte + bit for byte, value in enumerate(bits) if value
                       for bit in range(8) if value >> bit & 1), default=-1)
            if top + 1 != kept:
                found[process] = top + 1 - kept
        return found


@dataclass
class Tail:
    """How many records of both streams the store holds, counted as the broker appends them."""
    path: Path
    offset: int = 0
    partial: bytes = b""
    counted: int = 0

    def read(self) -> None:
        try:
            with self.path.open("rb") as store:
                store.seek(self.offset)
                while chunk := store.read(64 * 2**20):
                    self.offset += len(chunk)
                    whole, _, self.partial = (self.partial + chunk).rpartition(b"\n")
                    self.counted += sum(whole.count(b'"type":"%s"' % kind.encode()) for kind in STREAMS)
        except OSError:
            pass


@dataclass
class Decoded:
    streams: dict[str, Stream] = field(default_factory=lambda: {kind: Stream() for kind in STREAMS})
    losses: dict[str, int] = field(default_factory=dict)

    def total(self) -> int:
        return sum(stream.count for stream in self.streams.values())


def decode(path: Path) -> Decoded:
    """Each stream's records in the store, by renderer and sample index, and any overflow identity."""
    decoded = Decoded()
    with path.open("rb") as store:
        for line in store:
            start = line.find(b'"type":"')
            if start < 0:
                continue
            kind = line[start + 8:line.index(b'"', start + 8)].decode()
            if kind in LOSSES:
                decoded.losses[kind] = decoded.losses.get(kind, 0) + 1
            if kind not in STREAMS:
                continue
            record = json.loads(line)
            offset = STREAMS[kind][1]
            index = int.from_bytes(bytes.fromhex(record["payload"][2 * offset:2 * offset + 8]), "little")
            decoded.streams[kind].add(int(record["process_id"]), index, int(record["monotonic_time_ns"]))
    return decoded


@dataclass
class Measured:
    calls: int = 0
    page_ms: float = 0
    tail: Tail | None = None
    decoded: Decoded | None = None
    started: float = 0
    looped: float = 0
    drained: float | None = None
    peak_rate: float = 0
    footprint_kib: list[int] = field(default_factory=list)
    error: str | None = None


def install(fx: Fixture, _options: Options) -> None:
    fx.page("/wasm-every/index.html", INDEX)
    fx.route("/wasm-every/paced.wasm", lambda _r: bytes_response(wasm.MODULE, "application/wasm"))


def drive(run: Run) -> None:
    measured = Measured(tail=Tail(Path(run.session.document["session_dir"]) / "events.jsonl"))
    run.measurements[NAME] = measured
    pid = volume.browser_pid(run.session)
    tail = measured.tail
    tail.read()
    run.open("/wasm-every/index.html")
    if not run.wait(ISSUE, ["wasm-every:started"], 60):
        return
    measured.started = time.monotonic()
    before = tail.counted
    last, last_at = before, measured.started
    want = None
    # Count from the loop's start, so the rate is the store's, not one late read.
    while time.monotonic() < measured.started + 120 + DRAIN_SECONDS:
        tail.read()
        now, total = time.monotonic(), tail.counted - before
        if now > last_at:
            measured.peak_rate = max(measured.peak_rate, (total - last) / (now - last_at))
        last, last_at = total, now
        if pid is not None and (kib := volume.footprint_kib(pid)) is not None:
            measured.footprint_kib.append(kib)
        if want is None and run.fixture.beacon("wasm-every:hot") is not None:
            measured.looped = now
            ok, value = run.result("wasm-every:hot")
            if not ok or not isinstance(value, dict):
                measured.error = str(value)
                return
            measured.calls, measured.page_ms = int(value["calls"]), float(value["ms"])
            # Every call is one br_table and one call_indirect record.
            want = 2 * measured.calls
        if want is not None and total >= want:
            measured.drained = now
            break
        if want is None and now > measured.started + 120:
            measured.error = "the hot loop never answered"
            return
        time.sleep(POLL_SECONDS)
    measured.decoded = decode(tail.path)


def verify(run: Run) -> None:
    report = run.report
    measured = run.measurements.get(NAME)
    if not isinstance(measured, Measured) or measured.error or not measured.calls:
        report.failed(ISSUE, "hot loop page", getattr(measured, "error", None) or "the page did not finish")
        return
    sampling = (run.api.context().get("capture_options") or {}).get("wasm_sampling")
    want = {"version": 1, "streams": ["br_table", "call_indirect"], "window_ms": 1000, "every_record": True,
            "records_per_window": None, "samples_per_function": None, "samples_per_indirect_site": None,
            "function_allow_count": 0, "function_deny_count": 0, "module_allowlist": False, "reset": "available"}
    report.check(ISSUE, "session context wasm_sampling",
                 [] if sampling == want else [f"capture_options.wasm_sampling {sampling}, expected {want}"],
                 "capture_options.wasm_sampling says every record, with no window or allowance")

    decoded = measured.decoded
    for kind, (label, _offset) in STREAMS.items():
        stream = decoded.streams[kind]
        problems = []
        if stream.count != measured.calls:
            problems.append(f"{stream.count} {label} records for {measured.calls} calls")
        if stream.repeats:
            problems.append(f"{stream.repeats} repeated {label} sample indexes")
        for process, missing in stream.holes().items():
            problems.append(f"{missing} {label} sample indexes missing in process {process}")
        report.check(ISSUE, f"every {label} record kept", problems,
                     f"{stream.count:,} {label} records for {measured.calls:,} calls, one unbroken ordinal")

    summary = run.api.summary()
    gaps = sorted({check.get("reason") for check in summary_checks(summary, "named_gap", category="vm")
                   if str(check.get("reason", "")).startswith("native_wasm_")})
    problems = [f"vm named gaps {gaps}"] if gaps else []
    problems += [f"{count} {kind} records" for kind, count in sorted(decoded.losses.items())]
    report.check(ISSUE, "no sampling gap or overflow", problems,
                 "no Wasm budget, browser ceiling or transport gap and no overflow identity")

    finished = measured.drained or measured.looped + DRAIN_SECONDS
    elapsed = finished - measured.started
    records = decoded.total()
    span = [(stream.first_ns, stream.last_ns) for stream in decoded.streams.values() if stream.first_ns is not None]
    produced = (max(last for _, last in span) - min(first for first, _ in span)) / 1e9 if span else 0
    peak = max(measured.footprint_kib, default=0)
    shown = (f"page {measured.calls:,} calls in {measured.page_ms:,.0f} ms "
             f"({measured.calls / measured.page_ms * 1000:,.0f} calls/s); "
             f"{records:,} records produced over {produced:.2f} s and stored {elapsed:.1f} s after the loop began "
             f"({records / elapsed:,.0f} records/s, peak {measured.peak_rate:,.0f}/s), the last "
             f"{finished - measured.looped:.1f} s after the loop ended; "
             f"store {measured.tail.offset / 2**20:,.0f} MiB; browser footprint peak "
             f"{peak / 1024:,.0f} MiB over {len(measured.footprint_kib)} samples")
    run.notes.append(f"{ISSUE}: {shown}")
    report.check(ISSUE, "every record drained",
                 [] if measured.drained else [f"{records:,} of {2 * measured.calls:,} records after {DRAIN_SECONDS} s"],
                 shown)
