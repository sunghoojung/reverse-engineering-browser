#!/usr/bin/env python3
"""Drive a capture browser through every way a script reaches V8.

Needs a Brave built from this tree. Serves an owned loopback fixture, starts a
visibly labeled content-capture session for that fixture only, and compares the
stored records and artifacts with the exact source of each case. See
protocol/native-compiled-scripts-v1.md.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

KIND_SCRIPT, KIND_FUNCTION_CONSTRUCTOR, KIND_EVAL = 1, 5, 4
QUEUED, DUPLICATE, NETWORK_FETCHED = 1, 2, 3
REPORT_ONLY = ("Content-Security-Policy-Report-Only", "script-src 'self' 'unsafe-inline'")
UNSAFE_EVAL = ("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval'")


@dataclass(frozen=True)
class Case:
    name: str
    source: str
    kind: int
    fetched: bool = False
    worker: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source.encode()).hexdigest()


def function_source(params: str, body: str) -> str:
    return f"(function anonymous({params}\n) {{\n{body}\n}})"


def text(name: str, tail: str = "") -> str:
    return f"/*{name}*/ globalThis.ran = '{name}'; {tail}"


def build_fixture() -> tuple[dict[str, tuple[str, tuple[str, str] | None]], list[Case], set[str]]:
    direct = text("direct_eval")
    indirect = text("indirect_eval")
    delayed = text("delayed_eval")
    inner = text("nested_inner")
    outer = f"/*nested_outer*/ eval({json.dumps(inner)});"
    body = text("new_function", "return a + 1;")
    timer = text("set_timeout_string")
    inserted = text("inserted_script")
    blob = text("blob_script")
    blob_worker = text("blob_worker", "postMessage('ok');")
    inline = text("inline_script")
    external = text("external_script") + "\n"
    worker_eval = text("worker_eval")
    worker_body = text("worker_new_function", "return 4;")
    worker_import = text("worker_import") + "\n"
    worker = (
        "/*worker_entry*/\nimportScripts('/worker-import.js');\n"
        f"eval({json.dumps(worker_eval)});\nnew Function({json.dumps(worker_body)})();\n"
        "postMessage('ok');\n"
    )
    service_eval = text("service_worker_eval")
    service_body = text("service_worker_new_function", "return 6;")
    service_import = text("service_worker_import") + "\n"
    service = (
        "/*service_worker_entry*/\nimportScripts('/sw-import.js');\n"
        f"eval({json.dumps(service_eval)});\nnew Function({json.dumps(service_body)})();\n"
        "self.addEventListener('install', () => self.skipWaiting());\n"
        "self.addEventListener('activate', e => e.waitUntil(clients.claim()));\n"
    )
    report_only_eval = text("report_only_eval")
    report_only_body = text("report_only_new_function", "return 8;")
    unsafe_eval = text("unsafe_eval")

    index = f"""<!doctype html><meta charset=utf-8><title>compiled scripts</title>
<script>{inline}</script>
<script src="/external.js"></script>
<script>
const seen = m => fetch('/beacon?m=' + m).catch(() => 0);
async function run() {{
  setTimeout(() => {{ eval({json.dumps(delayed)}); seen('delayed'); }}, 3000);
  eval({json.dumps(direct)});
  (0, eval)({json.dumps(indirect)});
  eval({json.dumps(outer)});
  new Function('a', {json.dumps(body)})(1);
  setTimeout({json.dumps(timer)}, 0);
  const s = document.createElement('script');
  s.textContent = {json.dumps(inserted)};
  document.head.append(s);
  const b = document.createElement('script');
  b.src = URL.createObjectURL(new Blob([{json.dumps(blob)}], {{type: 'text/javascript'}}));
  document.head.append(b);
  const w = new Worker('/worker.js');
  w.onmessage = () => seen('worker');
  const u = URL.createObjectURL(new Blob([{json.dumps(blob_worker)}], {{type: 'text/javascript'}}));
  new Worker(u).onmessage = () => seen('blob_worker');
  await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  seen('service_worker');
}}
run();
</script>
"""
    report_only_page = f"""<!doctype html><script>
eval({json.dumps(report_only_eval)}); new Function({json.dumps(report_only_body)})();
fetch('/beacon?m=report_only');
</script>"""
    unsafe_eval_page = f"""<!doctype html><script>
eval({json.dumps(unsafe_eval)});
fetch('/beacon?m=unsafe_eval');
</script>"""

    pages = {
        "/index.html": (index, None),
        "/report-only.html": (report_only_page, REPORT_ONLY),
        "/unsafe-eval.html": (unsafe_eval_page, UNSAFE_EVAL),
        "/external.js": (external, None),
        "/worker.js": (worker, None),
        "/worker-import.js": (worker_import, None),
        "/sw.js": (service, None),
        "/sw-import.js": (service_import, None),
    }
    cases = [
        Case("direct_eval", direct, KIND_EVAL),
        Case("indirect_eval", indirect, KIND_EVAL),
        Case("delayed_eval", delayed, KIND_EVAL),
        Case("nested_outer", outer, KIND_EVAL),
        Case("nested_inner", inner, KIND_EVAL),
        Case("new_function", function_source("a", body), KIND_FUNCTION_CONSTRUCTOR),
        Case("set_timeout_string", timer, KIND_SCRIPT),
        Case("inline_script", inline, KIND_SCRIPT),
        Case("inserted_script", inserted, KIND_SCRIPT),
        Case("blob_script", blob, KIND_SCRIPT),
        Case("blob_worker", blob_worker, KIND_SCRIPT, worker=True),
        Case("worker_eval", worker_eval, KIND_EVAL, worker=True),
        Case("worker_new_function", function_source("", worker_body), KIND_FUNCTION_CONSTRUCTOR, worker=True),
        Case("service_worker_eval", service_eval, KIND_EVAL, worker=True),
        Case("service_worker_new_function", function_source("", service_body), KIND_FUNCTION_CONSTRUCTOR, worker=True),
        Case("report_only_eval", report_only_eval, KIND_EVAL),
        Case("report_only_new_function", function_source("", report_only_body), KIND_FUNCTION_CONSTRUCTOR),
        Case("unsafe_eval", unsafe_eval, KIND_EVAL),
        Case("external_script", external, KIND_SCRIPT, fetched=True),
        Case("worker_entry", worker, KIND_SCRIPT, fetched=True, worker=True),
        Case("worker_import", worker_import, KIND_SCRIPT, fetched=True, worker=True),
        Case("service_worker_entry", service, KIND_SCRIPT, fetched=True, worker=True),
        Case("service_worker_import", service_import, KIND_SCRIPT, fetched=True, worker=True),
    ]
    beacons = {"delayed", "worker", "blob_worker", "service_worker", "report_only", "unsafe_eval"}
    return pages, cases, beacons


def serve(pages, seen: set[str]) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path == "/beacon":
                seen.add(query.removeprefix("m="))
            body, header = pages.get(path, ("", None))
            status = 200 if path in pages or path == "/beacon" else 404
            encoded = body.encode()
            self.send_response(status)
            kind = "text/html" if path.endswith(".html") else "text/javascript"
            self.send_header("Content-Type", f"{kind}; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            if header:
                self.send_header(*header)
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def api(endpoint: str, instance: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        endpoint + path,
        data=data,
        headers={"Content-Type": "application/json", "x-reb-expected-instance": instance},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def decode(event: dict) -> dict:
    payload = bytes.fromhex(event["payload"])
    return {
        "kind": payload[4],
        "retention": payload[5],
        "script_id": int.from_bytes(payload[8:12], "little"),
        "creator": int.from_bytes(payload[20:24], "little"),
        "context": int.from_bytes(payload[24:32], "little"),
        "sha256": payload[40:72].hex(),
        "thread": event["thread_id"],
        "frame": event["frame_id"],
    }


def verify(cases: list[Case], records: list[dict], artifacts: list[dict]) -> list[str]:
    failures = []
    by_digest = {}
    for record in records:
        by_digest.setdefault(record["sha256"], []).append(record)
    retained = {artifact["sha256"] for artifact in artifacts}
    for case in cases:
        matches = by_digest.get(case.sha256, [])
        if not matches:
            failures.append(f"{case.name}: no script_compiled record")
            continue
        record = matches[0]
        allowed = (NETWORK_FETCHED,) if case.fetched else (QUEUED, DUPLICATE)
        if record["kind"] != case.kind or record["retention"] not in allowed:
            failures.append(f"{case.name}: kind {record['kind']} retention {record['retention']}")
        if case.sha256 not in retained:
            failures.append(f"{case.name}: source not retained")
        if case.worker != (record["frame"] == "0"):
            failures.append(f"{case.name}: frame {record['frame']}")
    named = {case.name: by_digest.get(case.sha256, [{}])[0] for case in cases}
    inner, outer = named["nested_inner"], named["nested_outer"]
    if not outer or not inner or inner.get("creator") != outer.get("script_id"):
        failures.append("nested_inner: creator does not name nested_outer")
    elif not outer["creator"]:
        failures.append("nested_outer: no creator")
    return failures


def wait_for(seen: set[str], expected: set[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not expected <= seen and time.monotonic() < deadline:
        time.sleep(0.2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reb-api", required=True, type=Path)
    parser.add_argument("--brave", default=os.environ.get("REB_BRAVE_BINARY"))
    args = parser.parse_args()
    if not args.brave:
        print("UNAVAILABLE: set REB_BRAVE_BINARY to a Brave built from this tree", file=sys.stderr)
        return 2

    pages, cases, beacons = build_fixture()
    seen: set[str] = set()
    server = serve(pages, seen)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    with tempfile.TemporaryDirectory() as root:
        started = subprocess.run(
            [str(args.reb_api), "session", "start", "--url", f"{origin}/index.html",
             "--localhost-only", "--request-content",
             "--confirm-sensitive-capture", "--brave-binary", args.brave, "--sessions-root", root,
             "--duration-seconds", "300"],
            capture_output=True, text=True, timeout=240, check=False,
        )
        if started.returncode != 0:
            print(f"FAIL session did not start: {started.stderr.strip()}", file=sys.stderr)
            return 1
        session = json.loads(started.stdout)
        endpoint, instance = session["endpoint"], session["instance_id"]
        try:
            for page in ("report-only.html", "unsafe-eval.html"):
                api(endpoint, instance, "/api/session/actions",
                    {"action": "open_url", "url": f"{origin}/{page}"})
            wait_for(seen, beacons, 30)
            time.sleep(2)
            events = api(endpoint, instance, "/api/events?type=script_compiled&limit=5000")["events"]
            artifacts = api(endpoint, instance, "/api/artifacts?kind=javascript&limit=5000")["artifacts"]
        finally:
            api(endpoint, instance, "/api/session/actions", {"action": "end", "confirm": True})
            server.shutdown()

    failures = [f"page beacon never arrived: {name}" for name in sorted(beacons - seen)]
    failures += verify(cases, [decode(event) for event in events], artifacts)
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if not failures:
        print(f"PASS {len(cases)} compiled script cases through a real capture browser")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
