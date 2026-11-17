"""Session kinds, their start flags and areas, and one run per kind."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback
from types import ModuleType
import urllib.error
import urllib.request

from live_acceptance import (baseline, bodies, budget, cookies, debugger, headers, limits, metadata, nostacks,
                             stacks, tabs)
from live_acceptance.evidence import Session, StartError, start_session
from live_acceptance.fixture import Fixture
from live_acceptance.pages import document
from live_acceptance.report import Report
from live_acceptance.run import Options, Run, brotli_encoder

# The step 7 start command of docs/development/paired-release.md.
CONTENT_FLAGS = ["--localhost-only", "--request-content", "--confirm-sensitive-capture", "--canvas-images",
                 "--request-stacks", "--document-start", "--wasm-dispatch", "--wasm-call-indirect"]
METADATA_DROPS = {"--request-content", "--confirm-sensitive-capture", "--canvas-images"}
SETTLE_SECONDS = 3
# A session always turns the probes on, so the inactive path is measured outside one.
INACTIVE_STEPS = ("launch the same Brave without a session (every probe disabled), serve the pages with "
                  "`check-live-acceptance.py --serve`, and profile the renderer and browser while "
                  "/tabs/index.html, /headers/index.html, /debugger/index.html and /limits/index.html load "
                  "(Instruments Time Profiler and Allocations): each probe entry costs one atomic load and "
                  "allocates nothing; record how it was measured")


@dataclass(frozen=True)
class Kind:
    flags: list[str]
    environment: dict[str, str]
    areas: list[ModuleType]
    duration: int


KINDS = {
    "content": Kind(CONTENT_FLAGS, {"REB_NATIVE_PROMISE_STACKS": "1"},
                    [baseline, stacks, headers, cookies, bodies, limits, debugger, tabs], 3600),
    "budget": Kind([*CONTENT_FLAGS, "--request-content-budget-mib", str(budget.BUDGET_MIB),
                    "--response-body-budget-mib", str(budget.BUDGET_MIB)],
                   {"REB_NATIVE_PROMISE_STACKS": "1"}, [budget], 1800),
    "metadata": Kind([flag for flag in CONTENT_FLAGS if flag not in METADATA_DROPS],
                     {"REB_NATIVE_PROMISE_STACKS": "1"}, [metadata], 900),
    "no-stacks": Kind([flag for flag in CONTENT_FLAGS if flag != "--request-stacks"],
                      {"REB_NATIVE_PROMISE_STACKS": "0"}, [nostacks], 900),
}
AREAS = {area.NAME: area for kind in KINDS.values() for area in kind.areas}


def index_page(areas: list[ModuleType]) -> str:
    links = "\n".join(f'<li><a href="/{area.NAME}/index.html">{area.ISSUE} {area.NAME}</a></li>'
                      for area in areas if area.NAME not in ("metadata", "no-stacks"))
    return document("REB live acceptance", f"<h1>REB live acceptance fixture</h1>\n<ul>\n{links}\n</ul>")


def build_fixture(areas: list[ModuleType], options: Options) -> Fixture:
    fixture = Fixture()
    fixture.page("/", index_page(areas))
    for area in areas:
        area.install(fixture, options)
    return fixture


def check_context(run: Run) -> None:
    context = run.api.context()
    options = context.get("capture_options") or {}
    want = {"request_content": run.kind != "metadata", "canvas_images": run.kind != "metadata",
            "request_stacks": run.kind != "no-stacks", "document_start": "permitted"}
    problems = [f"capture_options.{key} {options.get(key)!r}, expected {value!r}"
                for key, value in want.items() if options.get(key) != value]
    limits = options.get("content_limits")
    if run.kind == "metadata" and limits is not None:
        problems.append(f"content_limits {limits}, expected null")
    if run.kind == "budget":
        for key in ("request_content_budget_mib", "response_body_budget_mib"):
            if (limits or {}).get(key) != budget.BUDGET_MIB:
                problems.append(f"content_limits.{key} {(limits or {}).get(key)}, expected {budget.BUDGET_MIB}")
    log = run.session.log_text
    promise = "promise_stacks=1" in log
    if run.kind != "no-stacks" and not promise:
        problems.append("the launch log does not say promise_stacks=1")
    if run.kind == "no-stacks" and promise:
        problems.append("the launch log says promise_stacks=1 without request stacks")
    run.report.check("setup", "session context", problems,
                     f"get_session_context capture_options match the {run.kind} start"
                     + ("; promise stacks on" if promise else ""))


def ended(session: Session, timeout: float = 30) -> None:
    """Wait until the backend stops answering, so its files can be removed, then close its window."""
    session.end()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(session.api.endpoint + "/api/health", timeout=2).close()
        except (urllib.error.URLError, OSError):
            break
        time.sleep(0.5)
    session.close_app()


def guarded(report: Report, issue: str, step: str, work) -> None:
    """Run one step; an error fails that step and the run goes on to the next."""
    try:
        work()
    except Exception as error:  # A driver bug or an unexpected answer must not stop the other cases.
        frame = traceback.extract_tb(error.__traceback__)[-1]
        report.failed(issue, step, f"{type(error).__name__}: {error} at {Path(frame.filename).name}:{frame.lineno}")


def run_kind(name: str, args: argparse.Namespace, options: Options) -> Report:
    kind = KINDS[name]
    areas = [area for area in kind.areas if not args.only or area.NAME in args.only]
    report = Report(name)
    if not areas:
        return report
    fixture = build_fixture(areas, options).start()
    print(f"START {name} session against {fixture.origin}/ ({', '.join(a.NAME for a in areas)})", flush=True)
    keep = args.sessions_root / name if args.sessions_root else None
    holder = nullcontext(str(keep)) if keep else tempfile.TemporaryDirectory(
        prefix=f"reb-live-{name}-", ignore_cleanup_errors=True)
    with holder as root:
        Path(root).mkdir(parents=True, exist_ok=True)
        arguments = ["--url", fixture.origin + "/", *kind.flags, "--brave-binary", str(args.brave),
                     "--sessions-root", str(Path(root).absolute()), "--duration-seconds", str(kind.duration)]
        try:
            session = start_session(args.reb_api, arguments, kind.environment)
        except (StartError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            report.failed("setup", "session start", str(error))
            fixture.stop()
            print(report.summary(), flush=True)
            return report
        run = Run(name, fixture, report, session, options)
        try:
            guarded(report, "setup", "session context", lambda: check_context(run))
            for area in areas:
                guarded(report, area.ISSUE, f"{area.NAME} drive", lambda area=area: area.drive(run))
            time.sleep(SETTLE_SECONDS)
            # A drive may read rows mid-page; verification reads them after every page ran.
            run.forget()
            for area in areas:
                guarded(report, area.ISSUE, f"{area.NAME} verify", lambda area=area: area.verify(run))
            if name == "content":
                report.manual("#425 #427 #434 #436", "inactive probe path cost", INACTIVE_STEPS)
        finally:
            ended(session)
            fixture.stop()
        for note in run.notes:
            print(f"NOTE {note}", flush=True)
        if keep:
            print(f"NOTE {name} evidence kept in {keep}", flush=True)
    print(report.summary(), flush=True)
    return report


def serve(options: Options, port: int) -> int:
    """Serve every fixture page for the MANUAL steps, until interrupted."""
    areas = list(AREAS.values())
    fixture = build_fixture(areas, options).start(port)
    print(f"SERVING {fixture.origin}/ (cross-site origin {fixture.cross_site_origin}); Ctrl-C stops", flush=True)
    for area in areas:
        print(f"  {area.ISSUE} {area.NAME}: {fixture.origin}/{area.NAME}/index.html", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        fixture.stop()
    return 0


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="check-live-acceptance.py",
        description="Run the paired-release live acceptance (docs/development/paired-release.md step 7) "
                    "against owned loopback fixtures, through a Brave built from this tree.")
    parser.add_argument("--reb-api", type=Path, default=Path("apps/origin-trace-backend/target/debug/reb-api"))
    parser.add_argument("--brave", default=os.environ.get("REB_BRAVE_BINARY"),
                        help="the Brave Browser Development executable (default: REB_BRAVE_BINARY)")
    parser.add_argument("--session", choices=[*KINDS, "all"], default="all")
    parser.add_argument("--only", type=lambda text: set(text.split(",")), default=set(),
                        help=f"comma-separated areas: {', '.join(AREAS)}")
    parser.add_argument("--sessions-root", type=lambda text: Path(text).absolute(),
                        help="keep each session's evidence under this directory instead of a temporary one")
    parser.add_argument("--serve", action="store_true", help="only serve the fixture pages, for MANUAL steps")
    parser.add_argument("--port", type=int, default=0, help="the --serve port (default: any free port)")
    args = parser.parse_args(argv)
    unknown = args.only - set(AREAS)
    if unknown:
        parser.error(f"unknown areas: {', '.join(sorted(unknown))}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    encoder, source = brotli_encoder()
    options = Options(encoder, source)
    if args.serve:
        return serve(options, args.port)
    if not args.brave:
        print("UNAVAILABLE: set REB_BRAVE_BINARY or pass --brave to a Brave built from this tree", file=sys.stderr)
        return 2
    args.brave = Path(args.brave).expanduser().absolute()
    if not (args.brave.is_file() and os.access(args.brave, os.X_OK)):
        print(f"UNAVAILABLE: no Brave executable at {args.brave}", file=sys.stderr)
        return 2
    if not args.reb_api.is_file():
        print(f"UNAVAILABLE: no reb-api at {args.reb_api}; run make origin-trace-backend", file=sys.stderr)
        return 2
    names = list(KINDS) if args.session == "all" else [args.session]
    reports = [run_kind(name, args, options) for name in names]
    failed = sum(report.count("FAIL") for report in reports)
    manual = sum(report.count("MANUAL") for report in reports)
    passed = sum(report.count("PASS") for report in reports)
    print(f"RESULT {args.session}: {passed} passed, {failed} failed, {manual} manual", flush=True)
    return 1 if failed else 0
