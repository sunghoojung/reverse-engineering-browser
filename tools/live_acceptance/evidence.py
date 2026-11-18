"""The live session and its loopback evidence API, read as the backend writes it.

The shapes here are the backend's hand-built JSON (apps/origin-trace-backend);
protocol/openapi.json is the contract. Payload offsets are those of
protocol/native-network-v2.md.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.error
from urllib.parse import urlencode
import urllib.request

ARTIFACT_RANGE = 2 * 1024 * 1024
ROWS_PAGE = 500
EVENTS_PAGE = 5000

REQUEST_BODY_STATES = {
    1: "no_body", 2: "empty", 3: "metadata_only", 4: "captured", 5: "captured_truncated",
    6: "not_captured_body_kind", 7: "not_captured_artifact_unavailable",
    8: "not_captured_transfer_refused", 9: "not_captured_url", 10: "not_captured_session_budget",
    11: "not_captured_credential_form", 12: "not_captured_read_incomplete", 13: "not_captured_disk_reserve",
}
REQUEST_TARGET_RETENTION = {
    0: "complete", 1: "retained", 2: "not_retained_artifact_unavailable",
    3: "not_retained_transfer_refused", 4: "not_retained_session_budget", 5: "not_retained_url",
}
SENSITIVE_KINDS = {"request_body", "request_target", "request_headers", "response_headers",
                   "cookie_list", "response_body", "canvas_data_url"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"HTTP {status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class Api:
    def __init__(self, endpoint: str, instance: str) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.instance = instance

    def _open(self, path: str, data: bytes | None = None, timeout: float = 70):
        headers = {"x-reb-expected-instance": self.instance}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.endpoint + path, data=data, headers=headers)
        try:
            return urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read())
            except ValueError:
                body = {}
            raise ApiError(error.code, body.get("code", ""), body.get("error", error.reason)) from None

    def get(self, path: str, **params: object) -> dict:
        query = urlencode({k: v for k, v in params.items() if v is not None})
        with self._open(path + (f"?{query}" if query else "")) as response:
            return json.load(response)

    def post(self, path: str, body: dict) -> dict:
        with self._open(path, json.dumps(body).encode()) as response:
            return json.load(response)

    def action(self, body: dict) -> dict:
        return self.post("/api/session/actions", body)

    def open_url(self, url: str) -> dict:
        """Opens url in a new tab; the backend has no other navigation."""
        return self.action({"action": "open_url", "url": url})

    def content(self, artifact_id: str, limit: int | None = None) -> bytes:
        parts, offset = [], 0
        while True:
            size = ARTIFACT_RANGE if limit is None else min(ARTIFACT_RANGE, limit - offset)
            with self._open(f"/api/artifacts/{artifact_id}/content?offset={offset}&limit={size}") as response:
                chunk = response.read()
                total = int(response.headers.get("x-artifact-total-bytes", "0"))
            parts.append(chunk)
            offset += len(chunk)
            if not chunk or offset >= total or (limit is not None and offset >= limit):
                return b"".join(parts)

    def content_digest(self, artifact_id: str) -> tuple[int, str]:
        """An artifact's length and SHA-256, read in ranges without holding it whole."""
        digest, offset = hashlib.sha256(), 0
        while True:
            with self._open(f"/api/artifacts/{artifact_id}/content?offset={offset}&limit={ARTIFACT_RANGE}") as response:
                chunk = response.read()
                total = int(response.headers.get("x-artifact-total-bytes", "0"))
            digest.update(chunk)
            offset += len(chunk)
            if not chunk or offset >= total:
                return offset, digest.hexdigest()

    def artifact(self, artifact_id: str) -> dict | None:
        found = self.get("/api/artifacts", artifact_id=artifact_id)["artifacts"]
        return found[0] if found else None

    def artifacts(self, **filters: object) -> list[dict]:
        found, after = [], None
        while True:
            page = self.get("/api/artifacts", limit=5000, after=after, **filters)
            found += page["artifacts"]
            query = page.get("query") or {}
            if not query.get("limited") or not page["artifacts"]:
                return found
            after = query["next_after"]

    def rows(self) -> list[dict]:
        """Every get_requests row, with the row count frozen at the first page."""
        rows, offset, through = [], 0, None
        while True:
            page = self.get("/api/requests", limit=ROWS_PAGE, offset=offset, through=through,
                            sort="start", order="asc")
            through = page["through"]
            rows += page["requests"]
            if page["next_offset"] is None:
                return rows
            offset = page["next_offset"]

    def events(self, types: str, **filters: object) -> list[dict]:
        found, after = [], "0"
        while True:
            page = self.get("/api/events", type=types, limit=EVENTS_PAGE, after=after, **filters)
            found += page["events"]
            query = page["query"]
            if not query["limited"] or not page["events"]:
                return found
            after = query["next_after"]

    def cursor(self, types: str) -> str:
        """The store position a later wait_for_events reads from."""
        return self.get("/api/events/wait", type=types, timeout_ms=1)["query"]["next_after"]

    def wait(self, types: str, after: str, timeout_ms: int = 30000) -> tuple[list[dict], str]:
        """Records of these types written after the cursor, and the next cursor."""
        page = self.get("/api/events/wait", type=types, after=after, timeout_ms=timeout_ms)
        return page["events"], page["query"]["next_after"]

    def summary(self) -> dict:
        return self.get("/api/session/summary")

    def context(self) -> dict:
        return self.get("/api/session/context")


# Rows -----------------------------------------------------------------------


def row_target(row: dict) -> str | None:
    return row.get("target")


def find_rows(rows: list[dict], target: str | None = None, prefix: str | None = None,
              host: str | None = None, method: str | None = None) -> list[dict]:
    """Rows by their recorded path and query (at most 116 bytes) or host."""
    found = []
    for row in rows:
        recorded = row.get("target") or ""
        if target is not None and recorded != target[:116]:
            continue
        if prefix is not None and not recorded.startswith(prefix):
            continue
        if host is not None and row.get("host") != host:
            continue
        if method is not None and row.get("method") != method:
            continue
        found.append(row)
    return found


def row_tabs(row: dict) -> set[str]:
    tabs = set(row.get("tab_ids") or [])
    if row.get("tab_id") not in (None, "0"):
        tabs.add(row["tab_id"])
    return tabs


def members(row: dict) -> list[dict]:
    listed = list(row.get("members") or [])
    root = row.get("root")
    if root and not any(m["process_id"] == root["process_id"] and m["request_id"] == root["request_id"]
                        for m in listed):
        listed.insert(0, {"session_id": root["session_id"], "process_id": root["process_id"],
                          "request_id": root["request_id"]})
    return listed


def request_stack(api: Api, row: dict) -> dict:
    """The first recorded stack among the row's requests, else the last answer."""
    answer: dict = {"status": "not_recorded"}
    for member in members(row):
        if member["request_id"] in ("0", None):
            continue
        try:
            answer = api.get("/api/request-stack", session_id=member["session_id"],
                             process_id=member["process_id"], request_id=member["request_id"])
        except ApiError as error:
            answer = {"status": "error", "error": str(error)}
            continue
        if answer.get("status") == "recorded":
            return answer
    return answer


def per_request(api: Api, path: str, row: dict) -> dict:
    """get_request_headers or get_request_cookies for the row's browser request."""
    last: dict = {"hops": []}
    for member in members(row):
        try:
            last = api.get(path, session_id=member["session_id"], request_id=member["request_id"])
        except ApiError as error:
            last = {"hops": [], "error": str(error)}
            continue
        if last.get("hops"):
            return last
    return last


# Request records ---------------------------------------------------------------


@dataclass(frozen=True)
class RequestBody:
    version: int
    sequence: str
    process_id: int
    request_id: str
    artifact_id: str
    kind: int
    state: str
    flags: int
    body_length: int
    captured_length: int
    sha256: str | None

    @property
    def read(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def credential_form(self) -> bool:
        """Payload version 2: Chromium marked the body as a password form post."""
        return self.version >= 2 and bool(self.flags & 0x80)


@dataclass(frozen=True)
class RequestTarget:
    sequence: str
    process_id: int
    request_id: str
    artifact_id: str
    length: int
    retention: str
    prefix: bytes


def decode_request_body(event: dict) -> RequestBody:
    payload = bytes.fromhex(event["payload"])
    flags = payload[6]
    digest = payload[32:64]
    return RequestBody(
        int.from_bytes(payload[0:2], "little"), event["sequence_number"], event["process_id"], event["request_id"], event.get("artifact_id", "0"),
        payload[4], REQUEST_BODY_STATES.get(payload[5], f"state_{payload[5]}"), flags,
        int.from_bytes(payload[8:16], "little"), int.from_bytes(payload[16:24], "little"),
        digest.hex() if any(digest) else None,
    )


def decode_request_target(event: dict) -> RequestTarget:
    payload = bytes.fromhex(event["payload"])
    length = int.from_bytes(payload[4:8], "little")
    return RequestTarget(
        event["sequence_number"], event["process_id"], event["request_id"], event.get("artifact_id", "0"),
        length, REQUEST_TARGET_RETENTION.get(payload[9], f"retention_{payload[9]}"),
        payload[12:12 + min(length, 116)],
    )


def request_records(api: Api) -> tuple[dict[tuple[int, str], list[RequestBody]], dict[tuple[int, str], list[RequestTarget]]]:
    bodies: dict[tuple[int, str], list[RequestBody]] = {}
    targets: dict[tuple[int, str], list[RequestTarget]] = {}
    for event in api.events("request_body,request_target"):
        key = (event["process_id"], event["request_id"])
        if event["type"] == "request_body":
            bodies.setdefault(key, []).append(decode_request_body(event))
        else:
            targets.setdefault(key, []).append(decode_request_target(event))
    return bodies, targets


def for_row(records: dict[tuple[int, str], list], row: dict) -> list:
    found = []
    for member in members(row):
        found += records.get((member["process_id"], member["request_id"]), [])
    return found


def summary_checks(summary: dict, code: str, **fields: object) -> list[dict]:
    return [check for check in summary.get("checks", [])
            if check.get("code") == code and all(check.get(k) == v for k, v in fields.items())]


def parse_header_block(data: bytes) -> list[tuple[str, str]]:
    """A header block artifact: `Name: value` CRLF lines, any status line skipped."""
    headers = []
    for line in data.decode("latin-1").split("\r\n"):
        if not line or line.startswith("HTTP/") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name, value.strip(" \t")))
    return headers


# The session ---------------------------------------------------------------


class StartError(Exception):
    pass


@dataclass
class Session:
    document: dict
    api: Api

    @property
    def session_id(self) -> str:
        return self.document["session_id"]

    @property
    def log_text(self) -> str:
        try:
            return Path(self.document["log_file"]).read_text(errors="replace")
        except OSError:
            return ""

    def end(self) -> None:
        try:
            self.api.action({"action": "end", "confirm": True})
        except (ApiError, OSError):
            pass

    def close_app(self) -> None:
        """Quit the Origin Trace instance the launcher opened for this session.

        The launcher leaves it open after the session ends, as a person reading the evidence wants;
        a run of four sessions would otherwise leave four windows. Only the instance reading this
        session's store is matched, so another Origin Trace window stays open.
        """
        store = f"--store {Path(self.document['session_dir']) / 'events.jsonl'} "
        listed = subprocess.run(["ps", "-axww", "-o", "pid=,command="], capture_output=True, text=True,
                                check=False).stdout
        for line in listed.splitlines():
            pid, _, command = line.strip().partition(" ")
            if "/Contents/MacOS/OriginTrace " in command and store in command:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (OSError, ValueError):
                    pass


def start_session(reb_api: Path, arguments: list[str], environment: dict[str, str],
                  timeout: float = 300) -> Session:
    env = {**os.environ, **environment}
    started = subprocess.run([str(reb_api), "session", "start", *arguments], capture_output=True,
                             text=True, timeout=timeout, check=False, env=env)
    if started.returncode != 0:
        raise StartError(started.stderr.strip() or f"reb-api exited {started.returncode}")
    document = json.loads(started.stdout)
    session = Session(document, Api(document["endpoint"], document["instance_id"]))
    if document.get("url_opened") is False:
        session.end()
        raise StartError(f"the fixture page did not open: {document.get('url_error', 'unknown')}")
    return session


def wait_until(predicate, timeout: float, interval: float = 0.5):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(interval)
