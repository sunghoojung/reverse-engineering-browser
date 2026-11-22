#!/usr/bin/env python3
"""Offline checks of the live acceptance fixtures and drivers; no browser runs.

The fixture routes are requested over loopback and must answer what each case
expects. Page scripts are syntax-checked, and the stack cases' expected frames
are compared with the frames V8 itself records, when Node.js is installed. The
evidence readers and case checks run against a stand-in backend that answers
with the JSON shapes of apps/origin-trace-backend, built from fixture receipts,
so each check is seen to pass on matching evidence and fail on a difference.
"""

from __future__ import annotations

import contextlib
import gzip
import http.client
import http.server
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from live_acceptance import (baseline, bodies, cookies, debugger, driver, headers, limits, metadata,
                             nostacks, reserve, stacks, tabs, volume)
from live_acceptance.evidence import Api, ApiError, Session, decode_request_body, decode_request_target, parse_header_block
from live_acceptance.fixture import POLL_SECONDS, payload, sha256
from live_acceptance.pages import line_of, locate
from live_acceptance.report import Report
from live_acceptance.run import Options, Run, brotli_encoder

TOOLS = Path(__file__).resolve().parent
NODE = shutil.which("node")
ENCODER, ENCODER_SOURCE = brotli_encoder()
OPTIONS = Options(ENCODER, ENCODER_SOURCE)
INSTANCE = "instance-for-tests"


def fixture_for_all():
    return driver.build_fixture(list(driver.AREAS.values()), OPTIONS).start()


def request(port: int, path: str, method: str = "GET", body=None, headers: dict | None = None,
            host: str = "127.0.0.1"):
    connection = http.client.HTTPConnection(host, port, timeout=20)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, response.getheaders(), data


def header_values(pairs, name):
    return [value for key, value in pairs if key.lower() == name.lower()]


def raw_get(port: int, target: str) -> socket.socket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    raw.sendall(f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    return raw


def read_to_end(raw: socket.socket, data: bytes = b"") -> bytes:
    while chunk := raw.recv(65536):
        data += chunk
    raw.close()
    return data


def dechunk(data: bytes) -> bytes:
    out = []
    while True:
        size_line, _, data = data.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            return b"".join(out)
        out.append(data[:size])
        data = data[size + 2:]


class FixtureRoutes(unittest.TestCase):
    """Each case's routes answer as the live drivers expect."""

    @classmethod
    def setUpClass(cls):
        cls.fx = fixture_for_all()
        cls.port = cls.fx.port

    @classmethod
    def tearDownClass(cls):
        cls.fx.stop()

    def get(self, path, **kwargs):
        return request(self.port, path, **kwargs)

    def test_index_links_every_page_area(self):
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        for name in ("baseline", "stacks", "headers", "cookies", "bodies", "limits", "debugger", "tabs", "volume",
                     "reserve"):
            self.assertIn(f"/{name}/index.html".encode(), body)

    def test_header_hops_redirect_twice_with_repeated_headers(self):
        status, sent, _ = self.get("/headers/hop1?r=1", headers={"X-Reb-Probe": "one"})
        self.assertEqual((status, header_values(sent, "Location")), (302, ["/headers/hop2?r=1"]))
        self.assertEqual(header_values(sent, "X-Reb-Multi"), ["first", "second"])
        self.assertEqual(header_values(sent, "Set-Cookie"), ["hdr_hop1=one; Path=/"])
        status, sent, _ = self.get("/headers/hop2?r=1", headers={"X-Reb-Probe": "one"})
        self.assertEqual((status, header_values(sent, "Location")), (307, ["/headers/final?r=1"]))
        status, sent, body = self.get("/headers/final?r=1", headers={"X-Reb-Probe": "one"})
        self.assertEqual(status, 200)
        self.assertIn(b"X-Reb-Probe: one", body)
        receipt = self.fx.receipts("/headers/final")[-1]
        self.assertIn(("X-Reb-Probe", "one"), receipt.request.headers)
        self.assertEqual(receipt.response_headers, sent)

    def test_large_response_header_block_stays_below_chromium_limit(self):
        _, sent, _ = self.get("/headers/large?r=1")
        receipt = self.fx.receipts("/headers/large")[-1]
        self.assertGreaterEqual(receipt.head_bytes, headers.LARGE_BLOCK_MIN)
        self.assertLess(receipt.head_bytes, 256 * 1024)
        self.assertEqual(len(header_values(sent, "X-Reb-Large-07")[0]), headers.LARGE_VALUE)
        self.assertEqual(receipt.response_headers, sent)

    def test_set_cookie_variants_and_cross_site_names(self):
        _, sent, _ = self.get("/cookies/set?r=same")
        parsed = [cookies.parse_set_cookie(line) for line in header_values(sent, "Set-Cookie")]
        self.assertEqual([c["name"] for c in parsed], [variant[0] for variant in cookies.VARIANTS])
        by_name = {c["name"]: c for c in parsed}
        self.assertEqual((by_name["srv_none_secure"]["same_site"], by_name["srv_none_secure"]["secure"]), ("None", True))
        self.assertTrue(by_name["srv_httponly"]["http_only"])
        self.assertEqual(by_name["srv_plain"]["same_site"], "Unspecified")
        origin = f"http://localhost:{self.port}"
        _, sent, _ = self.get("/cookies/set?r=cross", headers={"Origin": origin}, host="localhost")
        self.assertTrue(all(cookies.parse_set_cookie(line)["name"].endswith("_x")
                            for line in header_values(sent, "Set-Cookie")))
        self.assertEqual(header_values(sent, "Access-Control-Allow-Origin"), [origin])
        self.assertEqual(header_values(sent, "Access-Control-Allow-Credentials"), ["true"])

    def test_preflight_only_for_known_routes(self):
        asked = {"Origin": f"http://localhost:{self.port}", "Access-Control-Request-Method": "GET",
                 "Access-Control-Request-Headers": "x-reb-probe"}
        status, sent, _ = self.get("/headers/hop1", method="OPTIONS", headers=asked)
        self.assertEqual((status, header_values(sent, "Access-Control-Allow-Headers")), (204, ["x-reb-probe"]))
        self.assertEqual(self.get("/nowhere", method="OPTIONS", headers=asked)[0], 404)

    def test_pages_name_the_live_cross_site_origin(self):
        _, _, body = self.get("/cookies/index.html")
        self.assertIn(f"http://localhost:{self.port}/cookies/cross.html".encode(), body)
        _, sent, body = self.get("/debugger/index.html")
        self.assertEqual(header_values(sent, "Content-Security-Policy"), ["img-src 'self'"])
        self.assertIn(f"http://localhost:{self.port}/debugger/blocked.png".encode(), body)
        _, _, body = self.get("/meta/index.html")
        self.assertIn(f"http://localhost:{self.port}/meta/eval".encode(), body)

    def test_gzip_and_brotli_decode_to_the_recorded_bytes(self):
        _, sent, body = self.get("/bodies/gzip?r=1")
        self.assertEqual(header_values(sent, "Content-Encoding"), ["gzip"])
        self.assertEqual(gzip.decompress(body), bodies.GZIP_TEXT)
        self.assertEqual(self.fx.receipts("/bodies/gzip")[-1].decoded_body, bodies.GZIP_TEXT)
        if ENCODER is None:
            self.skipTest(f"the brotli case is not served: {ENCODER_SOURCE}")
        _, sent, body = self.get("/bodies/brotli?r=1")
        self.assertEqual(header_values(sent, "Content-Encoding"), ["br"])
        decoder = shutil.which("brotli")
        if decoder:
            plain = subprocess.run([decoder, "-d", "-c"], input=body, capture_output=True, check=True).stdout
        else:
            import brotli  # type: ignore[import-not-found]
            plain = brotli.decompress(body)
        self.assertEqual(plain, bodies.BROTLI_TEXT)

    def test_chunked_and_event_stream_bodies(self):
        head, _, wire = read_to_end(raw_get(self.port, "/bodies/chunked?r=1")).partition(b"\r\n\r\n")
        self.assertIn(b"Transfer-Encoding: chunked", head)
        self.assertEqual(dechunk(wire), b"".join(bodies.CHUNKS))
        _, sent, body = self.get("/bodies/sse?r=1")
        self.assertEqual(header_values(sent, "Content-Type"), ["text/event-stream"])
        self.assertTrue(body.startswith(b"retry: 3600000\n\n"))
        self.assertTrue(body.endswith(b"event: end\ndata: done\n\n"))
        self.assertEqual(self.fx.receipts("/bodies/sse")[-1].decoded_body, body)

    def test_redirect_and_revalidation(self):
        status, sent, _ = self.get("/bodies/redirect?r=1")
        self.assertEqual((status, header_values(sent, "Location")), (302, ["/bodies/redirect-target?r=1"]))
        status, sent, _ = self.get("/bodies/etag?r=1")
        self.assertEqual((status, header_values(sent, "ETag")), (200, [bodies.ETAG]))
        status, _, body = self.get("/bodies/etag?r=1", headers={"If-None-Match": bodies.ETAG})
        self.assertEqual((status, body), (304, b""))

    def test_aborted_download_stops_mid_body(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", "/bodies/abort-download?r=1")
        response = connection.getresponse()
        self.assertIn("attachment", response.getheader("Content-Disposition"))
        self.assertEqual(response.getheader("Content-Length"), str(1024 * 1024))
        with self.assertRaises(http.client.IncompleteRead) as cut:
            response.read()
        connection.close()
        self.assertEqual(len(cut.exception.partial), 64 * 1024)
        receipt = self.fx.receipts("/bodies/abort-download")[-1]
        self.assertTrue(receipt.aborted)
        self.assertFalse(receipt.completed)
        self.assertEqual(receipt.decoded_body, payload("aborted-download", 1024 * 1024)[:64 * 1024])

    def test_parallel_bodies_are_distinct(self):
        digests = {sha256(self.get(f"/bodies/parallel?i={i}")[2]) for i in range(bodies.PARALLEL)}
        self.assertEqual(len(digests), bodies.PARALLEL)

    def test_burst_then_silence_until_released(self):
        gate = "bodies:burst-release"
        self.fx.gate(gate).clear()
        raw = raw_get(self.port, "/bodies/burst?r=1")
        first_chunk = f"{bodies.BURST:x}\r\n".encode() + payload("burst", bodies.BURST) + b"\r\n"
        data = b""
        while b"\r\n\r\n" not in data or len(data.partition(b"\r\n\r\n")[2]) < len(first_chunk):
            data += raw.recv(65536)
        self.assertEqual(data.partition(b"\r\n\r\n")[2], first_chunk)
        self.assertEqual(select.select([raw], [], [], 0.5)[0], [], "the server kept writing before the release")
        self.fx.release(gate)
        wire = read_to_end(raw, data).partition(b"\r\n\r\n")[2]
        self.assertEqual(dechunk(wire), payload("burst", bodies.BURST) + payload("burst-tail", 4096))
        self.fx.gate(gate).clear()

    def test_service_worker_scripts_and_preload(self):
        for path in ("/tabs/sw/sw.js", "/tabs/sw/import.js", "/bodies/sw/sw.js"):
            status, sent, _ = self.get(path)
            self.assertEqual(status, 200)
            self.assertTrue(header_values(sent, "Content-Type")[0].startswith("text/javascript"))
        _, _, body = self.get("/bodies/sw/preload.html", headers={"Service-Worker-Navigation-Preload": "true"})
        self.assertEqual(body, bodies.PRELOAD)
        receipt = self.fx.receipts("/bodies/sw/preload.html")[-1]
        self.assertEqual(receipt.request.header("Service-Worker-Navigation-Preload"), "true")

    def test_request_bodies_and_long_targets(self):
        large = payload("five-mib", 5 * 1024 * 1024 + 7)
        self.assertEqual(self.get("/limits/json", method="POST", body=large)[0], 200)
        self.assertEqual(self.fx.receipts("/limits/json")[-1].request.body, large)
        parts = [payload("stream-a", 65536), payload("stream-b", 1000)]
        self.get("/limits/stream", method="POST", body=iter(parts))
        receipt = self.fx.receipts("/limits/stream")[-1]
        self.assertTrue(receipt.request.chunked)
        self.assertEqual(receipt.request.body, b"".join(parts))
        target = "/limits/graphql?query=" + "f" * 8200
        self.get(target)
        self.assertEqual(self.fx.receipts("/limits/graphql")[-1].request.target, target)
        status, sent, _ = self.get("/limits/post-307", method="POST", body=b"again")
        self.assertEqual((status, header_values(sent, "Location")), (307, ["/limits/post-307-target"]))
        _, _, body = self.get("/limits/script?i=3")
        self.assertEqual(body.decode(), limits.script_source(3))

    def test_tabs_routes(self):
        status, sent, _ = self.get("/tabs/redirect?n=2&r=nav")
        self.assertEqual((status, header_values(sent, "Location")), (302, ["/tabs/redirect?n=1&r=nav"]))
        _, _, body = self.get("/tabs/redirect?n=0&r=nav")
        self.assertIn(b"tabs:redirect-nav", body)
        _, sent, _ = self.get("/tabs/download?r=1")
        self.assertIn("attachment", header_values(sent, "Content-Disposition")[0])
        _, _, body = self.get(f"/tabs/sw/many-frame.html?i={tabs.MANY_TABS - 1}")
        self.assertIn(b"tabs:all-open", body)
        _, _, body = self.get("/tabs/sw/many-frame.html?i=0")
        self.assertNotIn(b"tabs:all-open", body)
        _, _, body = self.get("/tabs/sw/last.html?r=popup")
        self.assertIn(b"window.close()", body)

    def test_beacons_and_gates(self):
        self.get("/__beacon?m=probe", method="POST", body=json.dumps({"ok": True, "value": 3}).encode())
        self.assertEqual(self.fx.beacon("probe"), {"ok": True, "value": 3})
        self.assertEqual(self.fx.wait_beacons(["probe", "absent"], 0.2), {"absent"})
        status, _, body = self.get("/__wait?k=never&t=0.2")
        self.assertEqual((status, body), (504, b"timeout"))
        self.fx.release("now")
        status, _, body = self.get("/__wait?k=now&t=5")
        self.assertEqual((status, body), (200, b"go"))
        self.assertEqual(self.fx.receipts("/__beacon"), [])
        self.assertEqual(self.get("/nowhere")[0], 404)

    def test_metadata_route_sets_a_fixture_secret(self):
        _, sent, _ = self.get("/meta/echo?r=2")
        self.assertIn("reb-secret-server-cookie", header_values(sent, "Set-Cookie")[0])

    @unittest.skipUnless(NODE, "Node.js is not installed")
    def test_wasm_modules_validate_and_run(self):
        from live_acceptance.binary import wasm_dispatch, wasm_import_caller
        script = """
const [dispatch, caller] = process.argv.slice(1).map(hex => Buffer.from(hex, 'hex'));
const {pick} = new WebAssembly.Instance(new WebAssembly.Module(dispatch)).exports;
let stack = '';
const imports = {env: {f: () => { stack = new Error().stack; }}};
new WebAssembly.Instance(new WebAssembly.Module(caller), imports).exports.run();
console.log(JSON.stringify({picks: [0, 1, 2, 3].map(pick), stack}));
"""
        out = subprocess.run([NODE, "-e", script, wasm_dispatch().hex(), wasm_import_caller().hex()],
                             capture_output=True, text=True, check=True).stdout
        result = json.loads(out)
        self.assertEqual(result["picks"], baseline.PICKS)
        self.assertRegex(result["stack"], r"reb_inner[\s\S]*reb_run")


SCRIPT = re.compile(r"<script(?P<attributes>[^>]*)>(?P<body>[\s\S]*?)</script>")
# Pages served only with a query, beside every exact .html route.
QUERY_PAGES = ("/", "/tabs/sw/last.html?r=popup", "/tabs/sw/last.html?r=nav", "/tabs/many.html?i=1",
               f"/tabs/sw/many-frame.html?i={tabs.MANY_TABS - 1}", "/tabs/redirect?n=0&r=nav")


@unittest.skipUnless(NODE, "Node.js is not installed")
class PageScripts(unittest.TestCase):
    """Every page script parses, and V8 records the frames the stack cases expect."""

    @classmethod
    def setUpClass(cls):
        cls.fx = fixture_for_all()

    @classmethod
    def tearDownClass(cls):
        cls.fx.stop()

    def test_every_page_and_served_script_parses(self):
        pages = sorted({*QUERY_PAGES, *(path for path in self.fx.paths() if path.endswith(".html"))})
        served = [path for path in self.fx.paths() if path.endswith(".js")] + ["/__lib.js", "/limits/script?i=1"]
        with tempfile.TemporaryDirectory() as directory:
            files = []

            def keep(name: str, text: bytes) -> None:
                path = Path(directory) / (re.sub(r"[^A-Za-z0-9]+", "_", name) + ".js")
                path.write_bytes(text)
                files.append(path)

            for page in pages:
                status, _, body = request(self.fx.port, page)
                self.assertEqual(status, 200, page)
                for index, match in enumerate(SCRIPT.finditer(body.decode())):
                    if "src=" in match["attributes"]:
                        continue
                    if "speculationrules" in match["attributes"]:
                        json.loads(match["body"])
                        continue
                    keep(f"{page}_{index}", match["body"].encode())
            for path in served:
                status, _, body = request(self.fx.port, path)
                self.assertEqual(status, 200, path)
                keep(path, body)
            for path in files:
                checked = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True, check=False)
                self.assertEqual(checked.returncode, 0, f"{path.name}: {checked.stderr}")
            self.assertGreater(len(files), 40)

    def frames(self, source: str, filename: str) -> list:
        """The frames V8 records in this script at its fetch call: (file, line, async)."""
        runner = f"""
const vm = require('vm');
Error.stackTraceLimit = Infinity;
const captured = [];
const sandbox = {{
  fetch() {{
    const saved = Error.prepareStackTrace;
    Error.prepareStackTrace = (_, sites) => sites;
    const sites = new Error().stack;
    Error.prepareStackTrace = saved;
    captured.push(sites.filter(site => site.getFileName() === {json.dumps(filename)})
      .map(site => [site.getFileName(), site.getLineNumber(), site.isAsync()]));
    return Promise.resolve();
  }},
  REB: {{sleep: ms => new Promise(resolve => setTimeout(resolve, ms)), run: (_, work) => work(), beacon() {{}}}},
}};
vm.runInNewContext({json.dumps(source)}, sandbox, {{filename: {json.dumps(filename)}}});
setTimeout(() => console.log(JSON.stringify(captured)), 200);
"""
        out = subprocess.run([NODE, "-e", runner], capture_output=True, text=True, check=True).stdout
        captured = json.loads(out)
        self.assertEqual(len(captured), 1, f"{filename} called fetch {len(captured)} times")
        return captured[0]

    def test_150_frame_expectation_matches_v8(self):
        observed = self.frames(stacks.DEEP, "/stacks/deep.js")
        self.assertEqual(len(observed), 150)
        self.assertEqual([(name, line) for name, line, _ in observed], stacks.expected_deep())

    def test_recursion_expectation_matches_v8(self):
        observed = self.frames(stacks.RECURSIVE, "/stacks/recursion.js")
        self.assertEqual(len(observed), 5000)
        self.assertEqual([(name, line) for name, line, _ in observed], stacks.expected_recursion())
        kept = stacks.kept_frames(stacks.expected_recursion())
        self.assertEqual((len(kept), kept[0], kept[-1]), (stacks.FRAME_LIMIT, tuple(observed[0][:2]),
                                                          tuple(observed[-1][:2])))

    def test_await_expectation_matches_v8(self):
        observed = self.frames(stacks.AWAITS, "/stacks/await.js")
        self.assertEqual([line for _, line, is_async in observed if is_async], stacks.expected_await_lines())


class FakeBackend:
    """A stand-in for the Origin Trace backend that answers with its JSON shapes."""

    def __init__(self):
        self.rows, self.events = [], []
        self.artifacts: dict[str, tuple[dict, bytes]] = {}
        self.answers: dict[tuple[str, str], dict] = {}
        self.summary = {"checks": [], "request_tabs": {"unresolved": "0", "rows": "0"}}
        self.context = {"capture_options": {}}
        backend = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, status, body, extra=()):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                for name, value in extra:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.headers.get("x-reb-expected-instance") != INSTANCE:
                    return self.reply(409, {"error": "the backend instance changed", "code": "state_conflict",
                                            "details": {}})
                parts = urlsplit(self.path)
                query = {key: values[0] for key, values in parse_qs(parts.query).items()}
                self.reply(*backend.answer(parts.path, query))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, args=(POLL_SECONDS,), daemon=True).start()
        self.api = Api(f"http://127.0.0.1:{self.server.server_address[1]}", INSTANCE)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def artifact(self, kind: str, data: bytes, **fields) -> str:
        artifact_id = str(len(self.artifacts) + 1)
        self.artifacts[artifact_id] = ({"artifact_id": artifact_id, "kind": kind, "sha256": sha256(data),
                                        "byte_size": len(data), **fields}, data)
        return artifact_id

    @staticmethod
    def page(items, query, key):
        start, limit = int(query.get("after", "0")), int(query.get("limit", "500"))
        chosen = items[start:start + limit]
        return {"count": len(chosen), key: chosen,
                "query": {"limited": start + limit < len(items), "next_after": str(start + len(chosen))}}

    def answer(self, path, query):
        if path == "/api/requests":
            limit, offset = int(query.get("limit", "100")), int(query.get("offset", "0"))
            through = int(query.get("through", len(self.rows)))
            chosen = self.rows[offset:min(offset + limit, through)]
            return 200, {"format": "reb-request-index-v2", "total": len(self.rows), "through": through,
                         "offset": offset, "limit": limit, "returned": len(chosen),
                         "next_offset": offset + limit if offset + limit < through else None, "requests": chosen}
        if path in ("/api/events", "/api/events/wait"):
            types = set(query.get("type", "").split(","))
            found = [event for event in self.events if event["type"] in types
                     and all(str(event.get(key)) == query[key] for key in ("process_id", "request_id") if key in query)]
            return 200, self.page(found, query, "events")
        if path == "/api/artifacts":
            kinds = set(query["kind"].split(",")) if "kind" in query else None
            found = [meta for meta, _ in self.artifacts.values()
                     if (kinds is None or meta["kind"] in kinds)
                     and query.get("sha256", meta["sha256"]) == meta["sha256"]
                     and query.get("artifact_id", meta["artifact_id"]) == meta["artifact_id"]]
            return 200, self.page(found, query, "artifacts")
        if path.startswith("/api/artifacts/") and path.endswith("/content"):
            _, data = self.artifacts[path.split("/")[3]]
            offset, limit = int(query.get("offset", "0")), int(query.get("limit", str(2 * 1024 * 1024)))
            return 200, data[offset:offset + limit], [("x-artifact-total-bytes", str(len(data)))]
        if path == "/api/session/summary":
            return 200, self.summary
        if path == "/api/session/context":
            return 200, self.context
        key = query.get("request_id") or query.get("name") or ""
        if (path, key) in self.answers:
            return 200, self.answers[(path, key)]
        if path == "/api/request-stack":
            return 200, {"status": "not_recorded"}
        return 200, {"hops": []}


class Builder:
    """The evidence a correct capture would hold, in the backend's shapes."""

    def __init__(self, backend: FakeBackend):
        self.backend = backend
        self.next_request = 100

    def row(self, target: str | None, method: str = "GET", **fields) -> dict:
        self.next_request += 1
        request_id = str(self.next_request)
        row = {"id": f"1:7:{request_id}", "method": method, "target": target[:116] if target else None,
               "host": "127.0.0.1:1", "url_truncated": bool(target) and len(target) > 116,
               "target_length": len(target) if target else None, "tab_id": "1", "tab_ids": ["1"],
               "tab_link": None, "tab_reason": None, "initiator": "script", "initiator_frame": None,
               "root": {"session_id": "1", "process_id": 7, "sequence_number": "1", "request_id": request_id},
               "members": [{"session_id": "1", "process_id": 7, "request_id": request_id, "records": 3}],
               "response_body": {"case": "no_record"}, **fields}
        self.backend.rows.append(row)
        return row

    def kept_body(self, row: dict, data: bytes) -> None:
        row["response_body"] = {"case": "captured", "artifact_id": self.backend.artifact("response_body", data),
                                "body_length": str(len(data)), "captured_length": str(len(data)),
                                "sha256": sha256(data)}

    def block(self, source: str, pairs, status: int | None = None) -> dict:
        first = f"HTTP/1.1 {status} OK" if status else "GET /x HTTP/1.1"
        data = ("\r\n".join([first, *(f"{name}: {value}" for name, value in pairs)]) + "\r\n\r\n").encode("latin-1")
        kind = "response_headers" if status else "request_headers"
        block = {"source": source, "state": "captured", "artifact": "verified", "block_bytes": len(data),
                 "header_count": len(pairs), "artifact_id": self.backend.artifact(kind, data),
                 "headers": [{"name": name, "value": value} for name, value in pairs]}
        if status:
            block["status_code"] = status
        return block

    def stack(self, row: dict, frames: list, **fields) -> None:
        self.backend.answers[("/api/request-stack", row["root"]["request_id"])] = {
            "status": "recorded", "state": "captured", "frames": frames, **fields}

    def request_body(self, row: dict, state: int, data: bytes, kind: int = 1, flags: int = 0x13,
                     version: int = 2) -> None:
        """A request_body record (native network v2 and v3); flag bit 1 carries the digest."""
        artifact = "0"
        captured = 0
        if state in (4, 5):
            captured = len(data) if state == 4 else 16 * 1024 * 1024
            artifact = self.backend.artifact("request_body", data[:captured])
        digest = bytes.fromhex(sha256(data)) if flags & 0x02 else bytes(32)
        record = (version.to_bytes(2, "little") + b"\x80\x00" + bytes([kind, state, flags, 0])
                  + len(data).to_bytes(8, "little")
                  + captured.to_bytes(8, "little") + bytes(8) + digest + bytes(64))
        self.event("request_body", row, record, artifact)

    def request_target(self, row: dict, target: bytes, retention: int = 1) -> None:
        artifact = self.backend.artifact("request_target", target)
        record = (b"\x01\x00\x80\x00" + len(target).to_bytes(4, "little") + bytes([0, retention, 0, 0])
                  + target[:116].ljust(116, b"\x00"))
        self.event("request_target", row, record, artifact)

    def event(self, kind: str, row: dict, record: bytes, artifact: str) -> None:
        self.backend.events.append({"type": kind, "process_id": 7, "request_id": row["root"]["request_id"],
                                    "sequence_number": str(len(self.backend.events) + 1),
                                    "artifact_id": artifact, "payload": record.hex()})


def frame(index, url, line, kind="javascript", **fields):
    return {"index": index, "kind": kind, "resolution": {"status": "resolved", "url": f"http://127.0.0.1:1{url}",
                                                          "line": line, "column": 5, "artifact_id": "1"}, **fields}


class Evidence(unittest.TestCase):
    """The case checks pass on evidence that matches the server, and fail on a difference."""

    def setUp(self):
        self.backend = FakeBackend()
        self.build = Builder(self.backend)
        self.fx = fixture_for_all()
        self.report = Report("test")
        document = {"session_id": "1", "endpoint": self.backend.api.endpoint, "instance_id": INSTANCE,
                    "log_file": "/nonexistent/launch.log", "session_dir": "/nonexistent"}
        self.run_ = Run("content", self.fx, self.report, Session(document, self.backend.api), OPTIONS)
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.addCleanup(quiet.close)
        self.addCleanup(self.fx.stop)
        self.addCleanup(self.backend.stop)

    def statuses(self):
        return {line.case: line.status for line in self.report.lines}

    def get(self, path, **kwargs):
        return request(self.fx.port, path, **kwargs)

    def test_api_pages_rows_events_and_artifact_ranges(self):
        for index in range(1203):
            self.build.row(f"/r?i={index}")
        self.assertEqual([row["target"] for row in self.backend.api.rows()], [f"/r?i={i}" for i in range(1203)])
        self.backend.events = [{"type": "request_body", "process_id": 7, "request_id": str(i)} for i in range(7001)]
        self.assertEqual(len(self.backend.api.events("request_body")), 7001)
        self.assertEqual(len(self.backend.api.events("request_body", request_id="9")), 1)
        data = payload("big", 5 * 1024 * 1024 + 3)
        self.assertEqual(self.backend.api.content(self.backend.artifact("request_body", data)), data)
        with self.assertRaises(ApiError) as refused:
            Api(self.backend.api.endpoint, "another instance").rows()
        self.assertEqual((refused.exception.status, refused.exception.code), (409, "state_conflict"))

    def test_payload_decoders(self):
        row = self.build.row("/limits/blob", "POST")
        self.build.request_body(row, 12, b"abc", kind=3, flags=0x49)
        body = decode_request_body(self.backend.events[-1])
        self.assertEqual((body.state, body.kind, body.body_length, body.sha256, body.read),
                         ("not_captured_read_incomplete", 3, 3, None, True))
        self.build.request_body(row, 4, b"abc")
        body = decode_request_body(self.backend.events[-1])
        self.assertEqual((body.state, body.captured_length, body.sha256, body.read), ("captured", 3, sha256(b"abc"), False))
        target = b"/limits/graphql?query=" + b"q" * 200
        self.build.request_target(row, target)
        decoded = decode_request_target(self.backend.events[-1])
        self.assertEqual((decoded.length, decoded.retention, decoded.prefix), (len(target), "retained", target[:116]))
        self.assertEqual(parse_header_block(b"HTTP/1.1 200 OK\r\nA: 1\r\nB:  two \r\n\r\n"), [("A", "1"), ("B", "two")])

    def headers_evidence(self, mutate=None):
        for path in headers.HOPS:
            self.get(f"{path}?r=1", headers={"X-Reb-Probe": "one"})
        self.get("/headers/large?r=1")
        row = self.build.row("/headers/final?r=1")
        hops = []
        for index, path in enumerate(headers.HOPS):
            receipt = self.fx.receipts(path)[-1]
            sent = mutate(receipt.response_headers) if mutate and index == 1 else receipt.response_headers
            hops.append({"hop": index, "network_block_missing": None,
                         "request": [self.build.block("network", receipt.request.headers)],
                         "response": [self.build.block("browser", sent, receipt.status),
                                      self.build.block("network", sent, receipt.status)]})
        self.backend.answers[("/api/request-headers", row["root"]["request_id"])] = {"hops": hops}
        large = self.fx.receipts("/headers/large")[-1]
        row = self.build.row("/headers/large?r=1")
        self.backend.answers[("/api/request-headers", row["root"]["request_id"])] = {"hops": [{
            "hop": 0, "request": [], "response": [self.build.block("network", large.response_headers, 200)]}]}

    def test_headers_pass_when_equal_to_the_server(self):
        self.headers_evidence()
        headers.verify(self.run_)
        self.assertEqual(self.statuses(), {"headers across two redirect hops": "PASS",
                                           "200 KiB response header block": "PASS",
                                           "DevTools shows the same headers": "MANUAL"}, self.report.lines)

    def test_headers_fail_on_a_changed_value(self):
        self.headers_evidence(lambda sent: [(n, "changed" if n == "X-Reb-Hop" else v) for n, v in sent])
        headers.verify(self.run_)
        self.assertEqual(self.statuses()["headers across two redirect hops"], "FAIL")

    def cookie_evidence(self, broken=False):
        origin = f"http://localhost:{self.fx.port}"
        _, sent_same, _ = self.get("/cookies/set?r=same")
        jar = {c["name"]: c for c in map(cookies.parse_set_cookie, header_values(sent_same, "Set-Cookie"))}
        stored = {name: c for name, c in jar.items() if name != "srv_none_insecure"}
        stored["js_lax"] = {"name": "js_lax", "value": "from-script"}
        cookie_header = "; ".join(f"{name}={c['value']}" for name, c in stored.items())
        self.get("/cookies/echo?r=same", headers={"Cookie": cookie_header})
        self.get("/cookies/echo?r=cross", headers={"Cookie": "srv_none_secure=none-secure", "Origin": origin},
                 host="localhost")
        _, sent_cross, _ = self.get("/cookies/set?r=cross", headers={"Origin": origin}, host="localhost")
        self.get("/cookies/echo?r=after", headers={"Cookie": cookie_header})

        def received(lines, reasons_for):
            out = []
            for c in map(cookies.parse_set_cookie, lines):
                reasons = reasons_for(c["name"])
                out.append({"parsed": True, "name": c["name"], "value_sha256": sha256(c["value"].encode()),
                            "secure": c["secure"], "http_only": c["http_only"], "same_site": c["same_site"],
                            "blocked": bool(reasons), "exclusion_reasons": reasons})
            return [{"state": "captured", "artifact": "verified", "cookies": out}]

        def sent(names, blocked=()):
            listed = [{"parsed": True, "name": n, "value_sha256": sha256(stored[n]["value"].encode()),
                       "blocked": False, "exclusion_reasons": []} for n in names]
            listed += [{"parsed": True, "name": n, "value_sha256": sha256(stored[n]["value"].encode()),
                        "blocked": True, "exclusion_reasons": [reason]} for n, reason in blocked]
            return [{"state": "captured", "artifact": "verified", "cookies": listed}]

        lists = {
            "/cookies/set?r=same": {"received": received(
                header_values(sent_same, "Set-Cookie"),
                lambda n: ["samesite_none_insecure"] if n == "srv_none_insecure" else [])},
            "/cookies/set?r=cross": {"received": received(
                header_values(sent_cross, "Set-Cookie"), lambda _n: ["third_party_phaseout"])},
            "/cookies/echo?r=same": {"sent": sent(list(stored))},
            "/cookies/echo?r=cross": {"sent": sent(["srv_none_secure"] + (["srv_lax"] if broken else []),
                                                   [("srv_strict", "samesite_strict")])},
            "/cookies/echo?r=after": {"sent": sent(list(stored))},
        }
        for target, sides in lists.items():
            row = self.build.row(target)
            self.backend.answers[("/api/request-cookies", row["root"]["request_id"])] = {"hops": [{
                "hop": 0, "sent": sides.get("sent", []), "received": sides.get("received", []),
                "sent_missing": None, "received_missing": None}]}
        line, _ = locate(cookies.index_page(origin), cookies.JS_WRITE)
        self.backend.answers[("/api/cookie-provenance", "js_lax")] = {
            "script": [{"api": "document.cookie set",
                        "stack": {"frames": [frame(0, "/cookies/index.html", line + (1 if broken else 0))]}}],
            "sent_with": [{"name": "js_lax", "written_by_script": [{"process_id": 7, "sequence_number": "4"}]}]}

    def test_cookies_pass_when_lists_match_the_server(self):
        self.cookie_evidence()
        cookies.verify(self.run_)
        self.assertEqual(self.statuses(), {"sent, received and blocked match the server": "PASS",
                                           "JS write links to its script position": "PASS",
                                           "Secure and SameSite=None on HTTPS": "MANUAL"}, self.report.lines)

    def test_cookies_fail_on_a_cookie_the_server_never_got(self):
        self.cookie_evidence(broken=True)
        cookies.verify(self.run_)
        self.assertEqual(self.statuses()["sent, received and blocked match the server"], "FAIL")
        self.assertEqual(self.statuses()["JS write links to its script position"], "FAIL")

    def test_stack_depth_recursion_and_dedup(self):
        deep = self.build.row("/stacks/deep?r=1")
        self.build.stack(deep, [frame(i, url, line) for i, (url, line) in enumerate(stacks.expected_deep())],
                         total_depth=150, recorded=150, omitted=0)
        recursion = self.build.row("/stacks/recursion?r=1")
        kept = stacks.kept_frames(stacks.expected_recursion())
        self.build.stack(recursion, [frame(i, url, line) for i, (url, line) in enumerate(kept)],
                         total_depth=5000, recorded=1024, omitted=3976, omitted_after_index=511)
        digest = "d" * 64
        self.backend.artifact("stack", b"one stack", sha256=digest)
        for index in range(stacks.REPEATS):
            row = self.build.row(f"/stacks/repeat?i={index}")
            self.build.stack(row, [frame(0, "/stacks/repeat.js", 2)], digest=digest)
        stacks.verify(self.run_)
        statuses = self.statuses()
        self.assertEqual(statuses["150-frame stack through wrappers"], "PASS", self.report.lines)
        self.assertEqual(statuses["5,000-deep recursion"], "PASS", self.report.lines)
        self.assertEqual(statuses["one call site's stack sent once"], "PASS", self.report.lines)
        self.assertEqual(statuses["fetch from a Wasm import"], "FAIL")
        self.assertEqual(statuses["stacks match DevTools frame for frame"], "MANUAL")
        self.assertEqual(statuses["stack walk cost"], "MANUAL")

    def test_stack_with_a_wrong_line_or_a_second_artifact_fails(self):
        deep = self.build.row("/stacks/deep?r=1")
        frames = [frame(i, url, line) for i, (url, line) in enumerate(stacks.expected_deep())]
        frames[70]["resolution"]["line"] += 1
        self.build.stack(deep, frames, total_depth=150, recorded=150, omitted=0)
        digest = "d" * 64
        self.backend.artifact("stack", b"one stack", sha256=digest)
        self.backend.artifact("stack", b"the same stack again", sha256=digest)
        for index in range(stacks.REPEATS):
            self.build.stack(self.build.row(f"/stacks/repeat?i={index}"), [], digest=digest)
        stacks.verify(self.run_)
        self.assertEqual(self.statuses()["150-frame stack through wrappers"], "FAIL")
        self.assertEqual(self.statuses()["one call site's stack sent once"], "FAIL")

    def test_body_kept_compares_bytes_and_digest(self):
        row = self.build.row("/bodies/json?r=1")
        self.build.kept_body(row, bodies.JSON_BODY)
        problems = []
        bodies.kept(self.run_, "/bodies/json?r=1", bodies.JSON_BODY, problems)
        self.assertEqual(problems, [])
        self.build.kept_body(row, bodies.JSON_BODY[:-1])
        self.run_.rows(refresh=True)
        bodies.kept(self.run_, "/bodies/json?r=1", bodies.JSON_BODY, problems)
        self.assertEqual(len(problems), 1, problems)

    def test_web_font_load_after_its_cache_probe(self):
        # Blink first asks only the cache for a web font and loads it again on a miss.
        self.build.row("/bodies/font.woff2?r=1", failed=True, error_code=bodies.CACHE_MISS,
                       response_body={"case": "failed_before_response"})
        self.build.kept_body(self.build.row("/bodies/font.woff2?r=1"), bodies.FONT)
        problems = []
        bodies.kept(self.run_, "/bodies/font.woff2?r=1", bodies.FONT, problems, cache_probe=True)
        self.assertEqual(problems, [])
        bodies.kept(self.run_, "/bodies/font.woff2?r=1", bodies.FONT, problems)
        self.assertEqual(problems, ["/bodies/font.woff2?r=1: 2 rows"])

    def test_limits_long_target_and_password_form(self):
        target = "/limits/graphql?query=" + "f" * 8200
        self.get(target)
        row = self.build.row(target)
        self.build.request_target(row, target.encode())
        form = b"user=reb&secret=not-a-real-password"
        self.get("/limits/password", method="POST", body=form)
        password = self.build.row("/limits/password", "POST")
        # A content session reads a password form post whole, keeps it and marks it.
        self.build.request_body(password, 4, form, flags=0xD3)
        limits.verify(self.run_)
        self.assertEqual(self.statuses()["8 KB GraphQL GET URL"], "PASS", self.report.lines)
        self.assertEqual(self.statuses()["password form post"], "PASS", self.report.lines)
        self.assertEqual(self.statuses()["page step limits:json"], "FAIL")
        # An older browser's credential-form refusal, or a kept body without the
        # mark or the read flag, fails.
        for state, flags, version in ((11, 0x11, 1), (4, 0x53, 2), (4, 0x93, 2), (4, 0xD3, 1)):
            self.report.lines.clear()
            self.backend.events.clear()
            self.build.request_body(password, state, form, flags=flags, version=version)
            self.run_.records(refresh=True)
            limits.verify(self.run_)
            self.assertEqual(self.statuses()["password form post"], "FAIL", (state, flags, version))
        # The cleared events took the full target with them.
        self.assertEqual(self.statuses()["8 KB GraphQL GET URL"], "FAIL")

    def volume_evidence(self, memory=(100_000, 120_000)):
        """Rows, records and artifacts a correct capture keeps for the volume page, at small sizes."""
        connection = http.client.HTTPConnection("127.0.0.1", self.fx.port, timeout=20)

        def send(method, target, body=None):
            connection.request(method, target, body=body)
            return connection.getresponse().read()

        for index in range(volume.RESPONSES):
            target = f"/volume/response?i={index}"
            self.build.kept_body(self.build.row(target), send("GET", target))
        for index in range(volume.REQUESTS):
            data = payload(f"request-{index}", volume.REQUEST_SIZE)
            target = f"/volume/request?i={index}"
            send("POST", target, data)
            self.build.request_body(self.build.row(target, "POST"), 4, data, flags=0x53)
        source = send("GET", "/volume/script.js")
        self.backend.artifact("javascript", source)
        self.build.row("/volume/script.js", response_body={"case": "source_artifact"})
        self.fx._beacons.update({name: [{"ok": True, "value": volume.REQUESTS}] for name in volume.RESULTS})
        self.fx._beacons["volume:script"] = [{"ok": True, "value": volume.SCRIPT_BYTES * 2}]
        for index in range(volume.POSTS):
            data = f"reb-post-{index}-".encode() + b"p" * 400
            send("POST", "/volume/post", data)
            # Two bodies the artifact queue refused.
            self.build.request_body(self.build.row("/volume/post", "POST"), 8 if index in (3, 4) else 4, data,
                                    flags=0x53)
        connection.close()
        self.backend.summary = {"checks": [{"code": "request_content_not_retained", "category": "request_body",
                                            "reason": volume.TRANSFER_REFUSED, "count": "2"}]}
        rest, peak = memory
        self.run_.measurements[volume.NAME] = volume.Memory(
            4242, [rest] * 8, {"responses": [rest, peak, rest], "requests": [rest, peak], "script": [rest]})
        # The same Brave without a session grows by half as much.
        alone = rest + (peak - rest) // 2
        self.run_.measurements[volume.REFERENCE] = volume.Memory(
            4343, [rest] * 8, {"responses": [rest, alone], "requests": [alone], "script": [rest]})

    def test_volume_bodies_script_posts_and_memory(self):
        sizes = {"RESPONSE_SIZE": 64 * 1024, "REQUEST_SIZE": 48 * 1024, "SCRIPT_BYTES": 4096, "POSTS": 40,
                 "RESPONSE_TOTAL_MIN": 256 * 1024, "REQUEST_TOTAL_MIN": 128 * 1024}
        with contextlib.ExitStack() as patches:
            for name, value in sizes.items():
                patches.enter_context(mock.patch.object(volume, name, value))
            self.volume_evidence()
            volume.verify(self.run_)
            cases = ["response bodies past 512 MiB", "request bodies past 256 MiB", "compiled script past 16 MiB",
                     "40 small POSTs", "no content budget or size limit", "browser memory while the bodies pass"]
            self.assertEqual(self.statuses(), {case: "PASS" for case in cases}, self.report.lines)
            self.assertIn("responses (0 MiB) +20 MiB with capture, +10 MiB without, capture's share +10 MiB",
                          self.report.lines[-1].detail)
            self.assertTrue(any(note.startswith("volume memory: ") for note in self.run_.notes), self.run_.notes)

            # A body cut at an older browser's 16 MiB, a summary naming a budget, an
            # uncounted refusal and a browser that held a whole body each fail.
            self.backend.rows[0]["response_body"]["captured_length"] = "16"
            self.backend.summary["checks"][0]["count"] = "1"
            self.backend.summary["checks"].append({"code": "request_content_not_retained", "category": "response_body",
                                                   "reason": "not_captured_session_budget", "count": "1"})
            self.run_.measurements[volume.NAME].phases["responses"].append(
                110_000 + volume.SHARE_LIMITS["responses"] // 1024)
            self.report.lines.clear()
            self.run_.rows(refresh=True)
            volume.verify(self.run_)
            failed = {"response bodies past 512 MiB", "40 small POSTs", "no content budget or size limit",
                      "browser memory while the bodies pass"}
            self.assertEqual({case for case, status in self.statuses().items() if status == "FAIL"}, failed,
                             self.report.lines)

    def test_volume_needs_the_browser_process(self):
        self.run_.measurements[volume.NAME] = None
        volume.check_memory(self.run_)
        self.assertEqual(self.report.lines[-1].status, "FAIL")
        self.assertIn("not found", self.report.lines[-1].detail)

    def test_volume_memory_samples_every_phase_at_its_end(self):
        # Phases that end before the first interval sample still have one.
        with mock.patch.object(volume, "footprint_kib", return_value=100_000), \
                mock.patch.object(volume, "BASELINE_SECONDS", 0), \
                mock.patch.object(volume, "SAMPLE_SECONDS", 3600), \
                mock.patch.object(self.run_, "wait", return_value=True), \
                mock.patch.object(self.run_.fixture, "wait_beacons"), \
                mock.patch.object(self.run_.fixture, "release"):
            memory = volume.measure(self.run_, volume.NAME, 4242)
        self.assertTrue(all(memory.phases.get(phase) for phase in volume.PHASES), memory.phases)

    def test_volume_memory_needs_the_page_without_a_session(self):
        self.run_.measurements[volume.NAME] = volume.Memory(4242, [100_000] * 8, {"responses": [120_000]})
        self.run_.measurements[volume.REFERENCE] = "no Brave executable to run the page without a session"
        volume.check_memory(self.run_)
        self.assertEqual(self.report.lines[-1].status, "FAIL")
        self.assertIn("without a session: no Brave executable", self.report.lines[-1].detail)

    def test_reserve_refusals_are_named_and_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_.session.document["session_dir"] = directory
            stats = os.statvfs(directory)
            above = stats.f_bavail * stats.f_frsize + 2**40
            log = Path(directory) / "artifact-receiver.log"
            log.write_text(f"Artifact store ready\nArtifact store: disk reserve {above} bytes; an artifact ...\n")
            response = self.build.row("/reserve/response", response_body={"case": reserve.REFUSED})
            request_row = self.build.row("/reserve/request", "POST")
            self.build.request_body(request_row, 13, b"x" * 1000, flags=0x51)
            self.fx._beacons.update({name: [{"ok": True, "value": 1}] for name in reserve.RESULTS})
            self.backend.summary = {"checks": [{"code": "request_content_not_retained", "category": category,
                                                "reason": reserve.REFUSED, "count": "1"}
                                               for category in ("request_body", "response_body")]}
            reserve.verify(self.run_)
            cases = {"receiver disk reserve": "PASS", "bodies refused for the disk reserve": "PASS"}
            self.assertEqual(self.statuses(), cases, self.report.lines)

            # A stored body, a reserve below the free space or an uncounted refusal fails.
            response["response_body"] = {"case": "captured", "artifact_id": "9"}
            self.backend.artifact("response_body", b"kept")
            log.write_text("Artifact store: disk reserve 1 bytes; an artifact ...\n")
            self.backend.summary["checks"].pop()
            self.report.lines.clear()
            self.run_.rows(refresh=True)
            reserve.verify(self.run_)
            self.assertEqual(self.statuses(), {case: "FAIL" for case in cases}, self.report.lines)
            detail = self.report.lines[-1].detail
            for problem in ("response case captured", "1 request or response bodies were stored",
                            "counts no response_body"):
                self.assertIn(problem, detail)

    def test_reserve_environment_is_above_the_free_space(self):
        with tempfile.TemporaryDirectory() as directory:
            stats = os.statvfs(directory)
            free = stats.f_bavail * stats.f_frsize // 2**20
            reserved = int(reserve.environment(Path(directory))["REB_ARTIFACT_DISK_RESERVE_MIB"])
            self.assertGreaterEqual(reserved, free + reserve.ABOVE_FREE_MIB - 64)
            self.assertLessEqual(len(str(reserved)), 10, "the launcher takes at most ten digits")

    def test_tabs_unresolved_fails_and_nothing_passes_without_rows(self):
        self.backend.summary = {"checks": [], "request_tabs": {"unresolved": "2", "unresolved_reasons": {"worker": "2"}}}
        tabs.verify(self.run_)
        self.assertEqual(self.statuses()["zero unresolved"], "FAIL")
        self.report.lines.clear()
        self.backend.summary = {"checks": [], "request_tabs": {"unresolved": "0", "rows": "12"}}
        tabs.verify(self.run_)
        self.assertEqual(self.statuses()["zero unresolved"], "PASS")
        self.assertNotIn("PASS", {line.status for line in self.report.lines if line.case != "zero unresolved"})
        self.assertEqual(self.statuses()["window.open first document and a closed last tab"], "MANUAL")
        self.assertEqual(self.statuses()["speculation-rules prefetch and prerender"], "MANUAL")

    def test_metadata_session_finds_a_leaked_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "brave-profile").mkdir()
            (root / "brave-profile" / "Cookies").write_bytes(b"reb-secret-js-cookie")
            (root / "events.jsonl").write_text("{}\n")
            self.run_.session.document["session_dir"] = directory
            # A metadata row keeps only its host, without the port, in domain and path.
            host_only = {"host": None, "target_kind": "host"}
            post = self.build.row(None, "POST", domain="127.0.0.1", path="127.0.0.1", **host_only)
            self.build.request_body(post, 3, b"reb-secret-body-value", flags=0)
            row = self.build.row(None, domain="localhost", path="localhost", **host_only)
            self.build.stack(row, [{"index": 0, "kind": "javascript", "eval": True,
                                    "resolution": {"status": "unresolved", "reason": "source_not_retained"}}])
            metadata.verify(self.run_)
            self.assertEqual(self.statuses(), {"no header, cookie or body value recorded": "PASS",
                                               "eval frame in a metadata session": "PASS"}, self.report.lines)
            self.report.lines.clear()
            (root / "artifacts").mkdir()
            (root / "artifacts" / "1.bin").write_bytes(b"x reb-secret-body-value x")
            metadata.verify(self.run_)
            self.assertEqual(self.statuses()["no header, cookie or body value recorded"], "FAIL")

    def test_no_stacks_session(self):
        for target in nostacks.TARGETS:
            self.build.row(target)
        nostacks.verify(self.run_)
        self.assertEqual(self.statuses(), {"no stack walk with --request-stacks=false": "PASS"}, self.report.lines)
        self.report.lines.clear()
        self.backend.events.append({"type": "request_initiator_stack", "process_id": 7, "request_id": "101"})
        nostacks.verify(self.run_)
        self.assertEqual(self.statuses()["no stack walk with --request-stacks=false"], "FAIL")

    def test_session_context_matches_each_kind(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log") as log:
            log.write("Native switches: request_stacks=1 promise_stacks=1\n")
            log.flush()
            self.run_.session.document["log_file"] = log.name
            self.backend.context = {"capture_options": {"request_content": True, "canvas_images": True,
                                                        "request_stacks": True, "document_start": "permitted"}}
            driver.check_context(self.run_)
            self.assertEqual(self.report.lines[-1].status, "PASS")
            self.run_.kind = "metadata"
            driver.check_context(self.run_)
            self.assertEqual(self.report.lines[-1].status, "FAIL")
            for kind in ("volume", "reserve"):
                self.run_.kind = kind
                driver.check_context(self.run_)
                self.assertEqual(self.report.lines[-1].status, "PASS", kind)
            # A backend that still reports content limits is stale.
            self.backend.context["capture_options"]["content_limits"] = {"request_content_budget_mib": 256}
            driver.check_context(self.run_)
            self.assertIn("capture_options.content_limits", self.report.lines[-1].detail)

    def test_debugger_observations(self):
        page = debugger.index_page(self.fx.cross_site_origin)
        debugger.STATE = debugger.State()
        debugger.STATE.observed = {
            "request_watch_match": {"debugger_observation": {"status": "decoded"}},
            "listener_dispatch": {"debugger_observation": {"detail": {"event_type": "click"}, "site": {
                "resolution": {"status": "resolved", "line": line_of(page, "function onWatchedClick")}}}},
            "csp_violation": {"debugger_observation": {"detail": {"directive": "img-src", "blocked_host": "localhost"}}},
        }
        debugger.STATE.stack = {"frames": [frame(0, "/debugger/index.html", line_of(page, "fetch('/api/x"))]}
        debugger.verify(self.run_)
        self.assertEqual(set(self.statuses().values()), {"PASS"}, self.report.lines)
        self.assertEqual(len(self.report.lines), 3)
        self.report.lines.clear()
        debugger.STATE = debugger.State()
        debugger.STATE.error = "get_native_console never listed the page"
        debugger.verify(self.run_)
        self.assertEqual(self.statuses(), {"arm a watch": "FAIL"})

    def test_debugger_settle_waits_only_for_a_pending_source(self):
        waiting = {"frames": [{"resolution": {"status": "unresolved", "reason": "source_artifact_missing"}}]}
        resolved = {"frames": [{"resolution": {"status": "resolved", "line": 14}}]}
        reads = iter([waiting, waiting, resolved])
        self.assertIs(debugger.settle(lambda: next(reads), debugger.top_frame, 5, 0), resolved)
        never = {"frames": [{"resolution": {"status": "unresolved", "reason": "source_not_retained"}}]}
        calls = []
        self.assertIs(debugger.settle(lambda: calls.append(1) or never, debugger.top_frame, 5, 0), never)
        self.assertEqual(len(calls), 1)
        self.assertIs(debugger.settle(lambda: waiting, debugger.top_frame, 0, 0), waiting)
        site = {"debugger_observation": {"site": {"resolution": {"status": "resolved", "line": 7}}}}
        self.assertEqual(debugger.listener_site(site), {"status": "resolved", "line": 7})

    def test_report_never_passes_a_manual_or_skipped_case(self):
        report = Report("x")
        report.manual("#1", "a", "steps")
        report.skipped("#1", "b", "why")
        self.assertEqual((report.exit_code, report.count("PASS")), (0, 0))
        self.assertFalse(report.check("#1", "c", ["broken"], "fine"))
        self.assertEqual(report.exit_code, 1)
        with self.assertRaises(ValueError):
            report.add("OK", "#1", "d", "not a status")


class Unavailable(unittest.TestCase):
    """Without a browser the entry point says UNAVAILABLE and exits 2, never PASS."""

    def run_entry(self, *arguments):
        environment = {key: value for key, value in os.environ.items() if key != "REB_BRAVE_BINARY"}
        return subprocess.run([sys.executable, str(TOOLS / "check-live-acceptance.py"), *arguments],
                              capture_output=True, text=True, env=environment, timeout=60, check=False)

    def test_no_browser(self):
        result = self.run_entry("--session", "content")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.startswith("UNAVAILABLE: set REB_BRAVE_BINARY"), result.stderr)
        self.assertEqual(result.stdout, "")

    def test_a_missing_browser(self):
        result = self.run_entry("--brave", "/nonexistent/Brave Browser Development", "--session", "metadata")
        self.assertEqual(result.returncode, 2)
        self.assertIn("UNAVAILABLE: no Brave executable", result.stderr)

    def test_a_missing_reb_api(self):
        result = self.run_entry("--brave", sys.executable, "--reb-api", "/nonexistent/reb-api")
        self.assertEqual(result.returncode, 2)
        self.assertIn("UNAVAILABLE: no reb-api", result.stderr)

    def test_an_unknown_area_is_refused(self):
        result = self.run_entry("--only", "nonsense")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown areas: nonsense", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=1)
