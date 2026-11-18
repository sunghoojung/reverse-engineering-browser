"""The owned loopback fixture server.

It listens on 127.0.0.1 only, and on [::1] at the same port when that port is
free, so `localhost` is a second site for the SameSite cases. Every request it
answers is kept as a receipt of what the browser sent and what the server sent
back. Cases compare stored evidence with these receipts, the wire, rather than
with what a case meant to send.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.server
import json
import socket
import threading
import time
from typing import Callable, Iterable
from urllib.parse import parse_qs, urlsplit

# Chromium stops reading a response header block at 256 KiB; the large-header
# case stays below that, and request lines here are far below Python's 64 KiB.
# A guard against a runaway request, well above the volume case's largest body.
MAX_REQUEST_BODY = 512 * 1024 * 1024
CONTROL_PREFIX = "/__"
# How often a server checks for stop(); stop() waits up to this long per server.
POLL_SECONDS = 0.05


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload(name: str, size: int) -> bytes:
    """Incompressible, deterministic bytes that differ for every name."""
    return hashlib.shake_256(name.encode()).digest(size)


@dataclass(frozen=True)
class Pause:
    """Stop writing a streamed body for this many seconds."""

    seconds: float


@dataclass(frozen=True)
class Gate:
    """Stop writing a streamed body until the driver releases this name."""

    name: str
    timeout: float = 60.0


@dataclass
class Request:
    method: str
    target: str
    path: str
    query: dict[str, str]
    headers: list[tuple[str, str]]
    body: bytes
    chunked: bool
    # The received body's length and SHA-256, kept when a route keeps no bytes.
    length: int = 0
    sha256: str = ""

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)


@dataclass
class Response:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    # The bytes the page reads after content decoding, when they differ from
    # the wire body (gzip, brotli).
    decoded: bytes | None = None
    # A streamed body: written with chunked transfer coding, in order, with
    # pauses and driver gates between its parts.
    chunks: list[bytes | Pause | Gate] | None = None
    # Send this many body bytes of a declared length, then close.
    abort_after: int | None = None
    reason: str | None = None


@dataclass
class Receipt:
    sequence: int
    started: float
    request: Request
    status: int = 0
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    head_bytes: int = 0
    wire_length: int = 0
    wire_sha256: str = ""
    decoded_body: bytes = b""
    completed: bool = False
    aborted: bool = False
    # Set when a route keeps no bytes: the decoded body's length and SHA-256.
    kept_length: int | None = None
    kept_sha256: str = ""

    @property
    def decoded_length(self) -> int:
        return len(self.decoded_body) if self.kept_length is None else self.kept_length

    @property
    def decoded_sha256(self) -> str:
        return self.kept_sha256 or sha256(self.decoded_body)


Handler = Callable[[Request], Response]


class Fixture:
    """Routes, receipts, page beacons and driver gates for one session."""

    def __init__(self) -> None:
        self._routes: dict[str, Handler] = {}
        # Routes whose receipts keep only lengths and digests, so a volume case
        # does not hold every body it moved in this process.
        self._digests_only: set[str] = set()
        self._prefixes: list[tuple[str, Handler]] = []
        self._receipts: list[Receipt] = []
        self._beacons: dict[str, list[object]] = {}
        self._gates: dict[str, threading.Event] = {}
        self._changed = threading.Condition()
        self._servers: list[http.server.ThreadingHTTPServer] = []
        self.port = 0

    # Routing -----------------------------------------------------------------

    def route(self, path: str, handler: Handler, keep_bodies: bool = True) -> None:
        if path in self._routes:
            raise ValueError(f"duplicate fixture route {path}")
        self._routes[path] = handler
        if not keep_bodies:
            self._digests_only.add(path)

    def route_prefix(self, prefix: str, handler: Handler) -> None:
        self._prefixes.append((prefix, handler))

    def page(self, path: str, html: str, headers: Iterable[tuple[str, str]] = ()) -> None:
        self.route(path, lambda _request, h=list(headers): html_response(html, h))

    def script(self, path: str, source: str, headers: Iterable[tuple[str, str]] = ()) -> None:
        extra = list(headers)
        self.route(path, lambda _request: text_response(source, "text/javascript", extra))

    def paths(self) -> list[str]:
        """Every exact route path."""
        return sorted(self._routes)

    def handle(self, request: Request) -> Response:
        if request.path.startswith(CONTROL_PREFIX):
            return self._control(request)
        handler = self._routes.get(request.path)
        if handler is None:
            handler = next((h for prefix, h in self._prefixes if request.path.startswith(prefix)), None)
        if request.method == "OPTIONS" and handler is not None:
            return preflight(request)
        if handler is None:
            return text_response(f"no fixture route {request.path}\n", "text/plain", status=404)
        return handler(request)

    # Page and driver coordination --------------------------------------------

    def _control(self, request: Request) -> Response:
        if request.path == "/__beacon":
            name = request.query.get("m", "")
            try:
                value = json.loads(request.body) if request.body else request.query.get("v")
            except ValueError:
                value = {"malformed": request.body[:200].decode(errors="replace")}
            with self._changed:
                self._beacons.setdefault(name, []).append(value)
                self._changed.notify_all()
            return text_response("ok", "text/plain", cors(request))
        if request.path == "/__wait":
            name = request.query.get("k", "")
            timeout = min(float(request.query.get("t", "60")), 300.0)
            released = self.gate(name).wait(timeout)
            return text_response("go" if released else "timeout", "text/plain", cors(request),
                                 status=200 if released else 504)
        if request.path == "/__lib.js":
            return text_response(PAGE_LIBRARY, "text/javascript")
        return text_response("unknown control\n", "text/plain", status=404)

    def gate(self, name: str) -> threading.Event:
        with self._changed:
            return self._gates.setdefault(name, threading.Event())

    def release(self, name: str) -> None:
        self.gate(name).set()

    def beacons(self, name: str) -> list[object]:
        with self._changed:
            return list(self._beacons.get(name, []))

    def beacon(self, name: str) -> object | None:
        values = self.beacons(name)
        return values[-1] if values else None

    def wait_beacons(self, names: Iterable[str], timeout: float) -> set[str]:
        """Wait until every name has reported; return the names still missing."""
        wanted = set(names)
        deadline = time.monotonic() + timeout
        with self._changed:
            while True:
                missing = {name for name in wanted if name not in self._beacons}
                remaining = deadline - time.monotonic()
                if not missing or remaining <= 0:
                    return missing
                self._changed.wait(min(remaining, 0.5))

    def wait_receipts(self, predicate: Callable[[Receipt], bool], count: int, timeout: float) -> list[Receipt]:
        deadline = time.monotonic() + timeout
        while True:
            found = [receipt for receipt in self.receipts() if predicate(receipt)]
            if len(found) >= count or time.monotonic() >= deadline:
                return found
            time.sleep(0.1)

    # Receipts ----------------------------------------------------------------

    def _begin(self, request: Request) -> Receipt:
        with self._changed:
            receipt = Receipt(len(self._receipts) + 1, time.time(), request)
            self._receipts.append(receipt)
            self._changed.notify_all()
            return receipt

    def receipts(self, path: str | None = None, prefix: str | None = None,
                 include_control: bool = False) -> list[Receipt]:
        with self._changed:
            found = list(self._receipts)
        if not include_control:
            found = [r for r in found if not r.request.path.startswith(CONTROL_PREFIX)]
        if path is not None:
            found = [r for r in found if r.request.path == path]
        if prefix is not None:
            found = [r for r in found if r.request.path.startswith(prefix)]
        return found

    # Serving -----------------------------------------------------------------

    def start(self, port: int = 0) -> Fixture:
        handler = _handler_class(self)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
        self._servers.append(server)
        self.port = server.server_address[1]
        try:
            self._servers.append(_V6Server(("::1", self.port), handler))
        except OSError:
            pass
        for each in self._servers:
            threading.Thread(target=each.serve_forever, args=(POLL_SECONDS,), daemon=True).start()
        return self

    def stop(self) -> None:
        for gate in list(self._gates.values()):
            gate.set()
        for server in self._servers:
            server.shutdown()
            server.server_close()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def cross_site_origin(self) -> str:
        """Another site on the same server: `localhost` is not 127.0.0.1's site."""
        return f"http://localhost:{self.port}"

    def __enter__(self) -> Fixture:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()


class _V6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _handler_class(fixture: Fixture) -> type[http.server.BaseHTTPRequestHandler]:
    class FixtureHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_one_request(self) -> None:
            try:
                super().handle_one_request()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def _serve(self) -> None:
            body, chunked = self._read_body()
            target = self.path
            parts = urlsplit(target)
            query = {key: values[0] for key, values in parse_qs(parts.query, keep_blank_values=True).items()}
            request = Request(self.command, target, parts.path, query, list(self.headers.items()), body, chunked,
                              len(body), sha256(body))
            receipt = fixture._begin(request)
            try:
                response = fixture.handle(request)
            except Exception as error:  # A fixture bug must still answer the page.
                response = text_response(f"fixture error: {error!r}\n", "text/plain", status=500)
            self._send(receipt, response)
            if parts.path in fixture._digests_only:
                receipt.kept_length, receipt.kept_sha256 = len(receipt.decoded_body), receipt.decoded_sha256
                request.body = b""
                receipt.decoded_body = b""

        do_GET = do_POST = do_PUT = do_OPTIONS = do_DELETE = _serve

        def _read_body(self) -> tuple[bytes, bool]:
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                parts, total = [], 0
                while True:
                    size = int(self.rfile.readline(1024).split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                            pass
                        return b"".join(parts), True
                    total += size
                    if total > MAX_REQUEST_BODY:
                        raise ValueError("request body over the fixture limit")
                    parts.append(self.rfile.read(size))
                    self.rfile.readline(3)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_REQUEST_BODY:
                raise ValueError("request body over the fixture limit")
            return (self.rfile.read(length) if length else b""), False

        def _send(self, receipt: Receipt, response: Response) -> None:
            headers = list(response.headers)
            names = {name.lower() for name, _ in headers}
            if response.chunks is not None:
                headers.append(("Transfer-Encoding", "chunked"))
            elif "content-length" not in names and response.status not in (204, 304):
                headers.append(("Content-Length", str(len(response.body))))
            reason = response.reason or self.responses.get(response.status, ("",))[0]
            head = f"HTTP/1.1 {response.status} {reason}\r\n"
            head += "".join(f"{name}: {value}\r\n" for name, value in headers) + "\r\n"
            receipt.status = response.status
            receipt.response_headers = headers
            receipt.head_bytes = len(head.encode("latin-1"))
            digest = hashlib.sha256()
            self.wfile.write(head.encode("latin-1"))
            # A client that has read the whole response can read its receipt at
            # once, so the receipt names what is sent before the last bytes
            # leave. Only `completed` waits for the write to succeed.
            if response.chunks is not None:
                written = []
                for part in response.chunks:
                    if isinstance(part, Pause):
                        self.wfile.flush()
                        time.sleep(part.seconds)
                    elif isinstance(part, Gate):
                        self.wfile.flush()
                        fixture.gate(part.name).wait(part.timeout)
                    elif part:
                        self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                        self.wfile.flush()
                        digest.update(part)
                        written.append(part)
                        receipt.wire_length += len(part)
                receipt.decoded_body = b"".join(written)
                receipt.wire_sha256 = digest.hexdigest()
                self.wfile.write(b"0\r\n\r\n")
            elif response.abort_after is not None:
                sent = response.body[: response.abort_after]
                digest.update(sent)
                receipt.wire_length = len(sent)
                receipt.decoded_body = sent
                receipt.wire_sha256 = digest.hexdigest()
                receipt.aborted = True
                self.close_connection = True
                self.wfile.write(sent)
            else:
                digest.update(response.body)
                receipt.wire_length = len(response.body)
                receipt.decoded_body = response.body if response.decoded is None else response.decoded
                receipt.wire_sha256 = digest.hexdigest()
                if self.command != "HEAD":
                    self.wfile.write(response.body)
            self.wfile.flush()
            receipt.completed = not receipt.aborted

        def log_message(self, *_args) -> None:
            pass

    return FixtureHandler


# Response helpers -------------------------------------------------------------


def text_response(text: str, kind: str, headers: Iterable[tuple[str, str]] = (), status: int = 200) -> Response:
    body = text.encode()
    return Response(status, [("Content-Type", f"{kind}; charset=utf-8"), ("Cache-Control", "no-store"),
                             *headers], body)


def html_response(html: str, headers: Iterable[tuple[str, str]] = ()) -> Response:
    return text_response(html, "text/html", headers)


def bytes_response(body: bytes, kind: str, headers: Iterable[tuple[str, str]] = (), status: int = 200) -> Response:
    return Response(status, [("Content-Type", kind), ("Cache-Control", "no-store"), *headers], body)


def cors(request: Request) -> list[tuple[str, str]]:
    origin = request.header("Origin")
    if not origin:
        return []
    return [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin")]


def preflight(request: Request) -> Response:
    asked = request.header("Access-Control-Request-Headers") or ""
    headers = cors(request) + [("Access-Control-Allow-Methods", "GET, POST, PUT"),
                               ("Access-Control-Max-Age", "0")]
    if asked:
        headers.append(("Access-Control-Allow-Headers", asked))
    return Response(204, headers)


def redirect(location: str, status: int = 302, headers: Iterable[tuple[str, str]] = ()) -> Response:
    return Response(status, [("Location", location), ("Cache-Control", "no-store"), *headers],
                    f"redirect to {location}\n".encode())


# Every fixture page loads this first. Beacons report to the server, never to
# the backend, so the driver's oracle stays independent of what it checks.
PAGE_LIBRARY = r"""
const REB = {
  beacon(name, value) {
    return fetch('/__beacon?m=' + encodeURIComponent(name), {
      method: 'POST', keepalive: true,
      body: JSON.stringify(value === undefined ? null : value),
    }).catch(() => 0);
  },
  wait(name, seconds) {
    return fetch('/__wait?k=' + encodeURIComponent(name) + '&t=' + (seconds || 60))
      .then(response => response.ok);
  },
  sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); },
  async run(name, work) {
    try {
      const value = await work();
      await REB.beacon(name, {ok: true, value: value === undefined ? null : value});
    } catch (error) {
      await REB.beacon(name, {ok: false, error: String((error && error.stack) || error)});
    }
  },
  async digest(bytes) {
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
  },
};
globalThis.REB = REB;
"""
