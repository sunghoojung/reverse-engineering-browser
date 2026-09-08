#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import stat
import threading
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from api_collection import (
    MAX_API_COLLECTION_BYTES,
    ApiCollectionConflict,
    ApiCollectionError,
    ApiCollectionStore,
)
from debugger_bridge import DebuggerBridge, DebuggerBridgeError, ProtocolError
from decoder_service import (
    MAX_DECODER_ACTION_BYTES,
    DecoderError,
    DecoderProtocolError,
    DecoderService,
    DecoderTimeout,
    DecoderUnavailable,
)
from evidence_store import (
    CANONICAL_UINT64,
    MAX_EVENT_JSON_BYTES,
    decode_event_line,
    is_artifact,
    is_canonical_uint,
    is_request_signal_profile,
    parse_event,
    read_recent_json_lines,
)
from local_analyst import (
    MAX_ANALYST_DOCUMENT_BYTES,
    MAX_ANALYST_INPUT_BYTES,
    LocalAnalystBusy,
    LocalAnalystConflict,
    LocalAnalystError,
    LocalAnalystProtocolError,
    LocalAnalystRunner,
    LocalAnalystStore,
    local_analyst_limits,
)
from origin_trace import OriginTraceError, build_origin_trace
from vm_analyzer import (
    AnalysisError,
    analyze_store,
    verify_analysis_document,
    write_analysis,
)

MAX_ARTIFACT_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TRACE_EDGE_JSON_BYTES = 2 * 1024
MAX_SIGNAL_PROFILE_JSON_BYTES = 8 * 1024
MAX_ARTIFACT_JSON_BYTES = 8 * 1024
MAX_DEBUGGER_ACTION_BYTES = 128 * 1024
MAX_API_COLLECTION_ACTION_BYTES = MAX_API_COLLECTION_BYTES + 64 * 1024
MAX_LOCAL_ANALYST_ACTION_BYTES = (
    max(MAX_ANALYST_DOCUMENT_BYTES, MAX_ANALYST_INPUT_BYTES) + 64 * 1024
)
MAX_DEBUGGER_WAIT_MS = 25_000
MAX_TRACE_EVENT_WINDOW = 10_000
MAX_TRACE_EDGE_WINDOW = 30_000
MAX_TRACE_ARTIFACT_WINDOW = 10_000
MAX_SIGNAL_PROFILE_WINDOW = 10_000
PUBLIC_ARTIFACT_FIELDS = (
    "protocol_version",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "parent_artifact_id",
    "creator_event_id",
    "execution_context_id",
    "capture_origin",
    "kind",
    "url",
    "mime_type",
    "byte_size",
    "sha256",
    "sensitive",
)


class LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer performs a reverse-DNS lookup during bind. The research UI
        # validates request hosts independently and does not use server_name for
        # routing, so that lookup adds no value and can stall startup.
        TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


class ResearchHandler(SimpleHTTPRequestHandler):
    ui_directory: Path
    event_store: Path
    trace_store: Path
    signal_store: Path
    artifact_store: Path
    api_collection_store = ApiCollectionStore(
        Path("build/sessions/api-collection-v1.json").resolve()
    )
    local_analyst_store = LocalAnalystStore(
        Path("build/sessions/local-analyst-workspace-v1.json").resolve()
    )
    local_analyst_runner = LocalAnalystRunner(Path(__file__).resolve().parent)
    decoder_service = DecoderService(Path("build/reb-decoder").resolve())
    broker_socket: Optional[Path] = None
    debugger: Optional[DebuggerBridge] = None
    analysis_lock = threading.Lock()
    analysis_signature: Optional[str] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(self.ui_directory), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") and not self.is_trusted_local_request():
            self.send_json(
                {"error": "Local request origin rejected"}, HTTPStatus.FORBIDDEN
            )
            return
        if parsed.path == "/api/health":
            self.send_json(
                {
                    "status": "ok",
                    "store": str(self.event_store),
                    "store_exists": self.event_store.exists(),
                    "trace_store": str(self.trace_store),
                    "trace_store_exists": self.trace_store.exists(),
                    "signal_store": str(self.signal_store),
                    "signal_store_exists": self.signal_store.exists(),
                    "artifact_store": str(self.artifact_store),
                    "artifact_store_exists": self.artifact_store.exists(),
                    "api_collection_store": str(self.api_collection_store.path),
                    "api_collection_store_exists": self.api_collection_store.path.exists(),
                    "local_analyst_store": str(self.local_analyst_store.path),
                    "local_analyst_store_exists": self.local_analyst_store.path.exists(),
                    "local_analyst_runner_available": self.local_analyst_runner.available(),
                    "decoder_available": self.decoder_service.available(),
                    "broker_connected": self.broker_connected(),
                    "debugger_state": self.debugger_state(),
                }
            )
            return
        if parsed.path == "/api/decoder":
            self.send_json(self.decoder_service.state())
            return
        if parsed.path == "/api/api-collection":
            try:
                collection = self.api_collection_store.load()
            except (ApiCollectionError, OSError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            etag = f'"api-collection-{collection["generation"]}"'
            if self.send_not_modified(etag):
                return
            self.send_json(collection, etag=etag)
            return
        if parsed.path == "/api/local-analyst":
            try:
                workspace = self.local_analyst_store.load()
            except (LocalAnalystError, OSError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            etag = f'"local-analyst-{workspace["generation"]}"'
            if self.send_not_modified(etag):
                return
            self.send_json(workspace, etag=etag)
            return
        if parsed.path == "/api/local-analyst/runner":
            self.send_json(
                {
                    "protocol_version": 1,
                    "available": self.local_analyst_runner.available(),
                    "active_run_id": self.local_analyst_runner.active_run_id(),
                    "limits": local_analyst_limits(),
                }
            )
            return
        if parsed.path == "/api/debugger":
            query = parse_qs(parsed.query, keep_blank_values=True)
            wait_values = query.get("wait_ms", ["0"])
            if (
                len(wait_values) != 1
                or not CANONICAL_UINT64.fullmatch(wait_values[0])
                or int(wait_values[0]) > MAX_DEBUGGER_WAIT_MS
            ):
                self.send_json(
                    {"error": "Debugger wait must be between 0 and 25000 milliseconds"},
                    HTTPStatus.BAD_REQUEST,
                )
                return
            wait_seconds = int(wait_values[0]) / 1_000
            generation = self.debugger_generation()
            etag = f'"debugger-{generation}"'
            if (
                wait_seconds > 0
                and self.debugger is not None
                and self.headers.get("If-None-Match") == etag
            ):
                generation = self.debugger.wait_for_change(generation, wait_seconds)
                etag = f'"debugger-{generation}"'
            if self.send_not_modified(etag):
                return
            snapshot = self.debugger_snapshot()
            etag = f'"debugger-{snapshot["generation"]}"'
            self.send_json(snapshot, etag=etag)
            return
        if parsed.path == "/api/debugger/source":
            query = parse_qs(parsed.query)
            script_id = query.get("script_id", [None])[0]
            if script_id is None:
                self.send_json(
                    {"error": "Script ID is required"}, HTTPStatus.BAD_REQUEST
                )
                return
            try:
                if self.debugger is None:
                    raise DebuggerBridgeError("Live debugging is not enabled")
                source = self.debugger.get_script_source(script_id)
            except DebuggerBridgeError as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.CONFLICT)
                return
            self.send_json(source)
            return
        if parsed.path == "/api/origin-trace":
            query = parse_qs(parsed.query)
            request_id = query.get("request_id", [None])[0]
            root_process_id = query.get("root_process_id", [None])[0]
            root_sequence_number = query.get("root_sequence_number", [None])[0]
            try:
                if request_id is None:
                    raise ValueError("Request ID is required")
                if (
                    not CANONICAL_UINT64.fullmatch(request_id)
                    or int(request_id) >= 2**64
                ):
                    raise ValueError(
                        "Request ID must be a canonical unsigned 64-bit integer"
                    )
                if (root_process_id is None) != (root_sequence_number is None):
                    raise ValueError(
                        "Root process ID and sequence number must be supplied together"
                    )
                if root_process_id is not None:
                    parsed_process_id = int(root_process_id)
                    if (
                        str(parsed_process_id) != root_process_id
                        or parsed_process_id < 0
                        or parsed_process_id >= 2**32
                    ):
                        raise ValueError(
                            "Root process ID must be a canonical unsigned 32-bit integer"
                        )
                else:
                    parsed_process_id = None
                if root_sequence_number is not None and (
                    not CANONICAL_UINT64.fullmatch(root_sequence_number)
                    or int(root_sequence_number) >= 2**64
                ):
                    raise ValueError(
                        "Root sequence number must be a canonical unsigned 64-bit integer"
                    )
            except ValueError as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
                return
            try:
                signature = ":".join(
                    (
                        self.resource_etag(self.event_store),
                        self.resource_etag(self.trace_store),
                        self.resource_etag(self.artifact_store / "manifest.jsonl"),
                        request_id,
                        root_process_id or "auto",
                        root_sequence_number or "auto",
                    )
                )
                etag = f'"{hashlib.sha256(signature.encode()).hexdigest()}"'
                if self.send_not_modified(etag):
                    return
                document = build_origin_trace(
                    self.load_events(MAX_TRACE_EVENT_WINDOW),
                    self.load_trace_edges(MAX_TRACE_EDGE_WINDOW),
                    self.load_recent_artifacts(MAX_TRACE_ARTIFACT_WINDOW),
                    request_id,
                    root_process_id=parsed_process_id,
                    root_sequence_number=root_sequence_number,
                )
            except (
                OSError,
                UnicodeDecodeError,
                OriginTraceError,
                ValueError,
                json.JSONDecodeError,
            ) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            self.send_json(document, etag=etag)
            return
        if parsed.path == "/api/request-signal-profile":
            query = parse_qs(parsed.query)
            session_id = query.get("session_id", [None])[0]
            request_id = query.get("request_id", [None])[0]
            root_process_id = query.get("root_process_id", [None])[0]
            root_sequence_number = query.get("root_sequence_number", [None])[0]
            try:
                if not all(
                    value is not None
                    for value in (
                        session_id,
                        request_id,
                        root_process_id,
                        root_sequence_number,
                    )
                ):
                    raise ValueError(
                        "Complete request signal profile identity is required"
                    )
                if not is_canonical_uint(session_id, 64, nonzero=True):
                    raise ValueError(
                        "Session ID must be a nonzero unsigned 64-bit integer"
                    )
                if not is_canonical_uint(request_id, 64, nonzero=True):
                    raise ValueError(
                        "Request ID must be a nonzero unsigned 64-bit integer"
                    )
                if not is_canonical_uint(root_process_id, 32):
                    raise ValueError(
                        "Root process ID must be an unsigned 32-bit integer"
                    )
                if not is_canonical_uint(root_sequence_number, 64, nonzero=True):
                    raise ValueError(
                        "Root sequence number must be a nonzero unsigned 64-bit integer"
                    )
            except ValueError as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
                return
            try:
                etag = self.resource_etag(
                    self.signal_store,
                    ":".join(
                        (
                            session_id,
                            request_id,
                            root_process_id,
                            root_sequence_number,
                        )
                    ),
                )
                if self.send_not_modified(etag):
                    return
                profiles = self.load_request_signal_profiles(MAX_SIGNAL_PROFILE_WINDOW)
                document = next(
                    (
                        profile
                        for profile in reversed(profiles)
                        if profile["session_id"] == session_id
                        and profile["request_id"] == request_id
                        and str(profile["root_event"]["process_id"]) == root_process_id
                        and profile["root_event"]["sequence_number"]
                        == root_sequence_number
                    ),
                    None,
                )
            except (
                OSError,
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            if document is None:
                self.send_json(
                    {"error": "No request signal profile matches the selected request"},
                    HTTPStatus.NOT_FOUND,
                    etag=etag,
                )
                return
            self.send_json(document, etag=etag)
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["500"])[0]), 5000))
                broker_connected = self.broker_connected()
                etag = self.resource_etag(
                    self.event_store, f"{int(broker_connected)}-{limit}"
                )
                if self.send_not_modified(etag):
                    return
                events = self.load_events(limit)
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            self.send_json(
                {
                    "count": len(events),
                    "events": events,
                    "broker_connected": broker_connected,
                },
                etag=etag,
            )
            return
        if parsed.path == "/api/artifacts":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["500"])[0]), 5000))
                etag = self.resource_etag(
                    self.artifact_store / "manifest.jsonl", str(limit)
                )
                if self.send_not_modified(etag):
                    return
                artifacts = self.load_artifacts()[-limit:]
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            public_artifacts = [
                {field: artifact[field] for field in PUBLIC_ARTIFACT_FIELDS}
                for artifact in artifacts
            ]
            self.send_json(
                {"count": len(public_artifacts), "artifacts": public_artifacts},
                etag=etag,
            )
            return
        if parsed.path == "/api/analysis/vm":
            query = parse_qs(parsed.query)
            request_id = query.get("request_id", [None])[0]
            try:
                if request_id is not None and (
                    not CANONICAL_UINT64.fullmatch(request_id)
                    or int(request_id) >= 2**64
                ):
                    raise ValueError(
                        "Request ID must be a canonical unsigned 64-bit integer"
                    )
                document = self.load_vm_analysis()
                if request_id is not None:
                    document = dict(document)
                    document["selection"] = {
                        "kind": "request",
                        "request_id": request_id,
                        "edge_semantics": "correlated-not-causal",
                    }
                    document["results"] = [
                        result
                        for result in document["results"]
                        if request_id in result.get("related_request_ids", [])
                    ]
                    document["mixed_findings"] = [
                        finding
                        for finding in document["mixed_findings"]
                        if any(
                            request_id in result.get("related_request_ids", [])
                            for result in document["results"]
                            if result.get("artifact_id")
                            in finding.get("artifact_ids", [])
                        )
                    ]
                etag = f'"{document["document_digest"]}-{request_id or "all"}"'
                if self.send_not_modified(etag):
                    return
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            self.send_json(document, etag=etag)
            return
        artifact_match = re.fullmatch(r"/api/artifacts/([^/]+)/content", parsed.path)
        if artifact_match is not None:
            try:
                artifact_id = artifact_match.group(1)
                query = parse_qs(parsed.query)
                offset = max(0, int(query.get("offset", ["0"])[0]))
                limit = max(
                    1,
                    min(
                        int(query.get("limit", [str(MAX_ARTIFACT_RESPONSE_BYTES)])[0]),
                        MAX_ARTIFACT_RESPONSE_BYTES,
                    ),
                )
                artifact, content_path = self.find_artifact(artifact_id)
                total_size = artifact["byte_size"]
                if offset > total_size:
                    raise ValueError("Artifact content offset exceeds byte size")
                with content_path.open("rb") as stream:
                    stream.seek(offset)
                    body = stream.read(limit)
            except FileNotFoundError:
                self.send_json({"error": "Artifact not found"}, HTTPStatus.NOT_FOUND)
                return
            except (OSError, ValueError, json.JSONDecodeError) as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            self.send_artifact_bytes(body, total_size, offset)
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if not self.is_trusted_local_request():
            self.send_json(
                {"error": "Local request origin rejected"}, HTTPStatus.FORBIDDEN
            )
            return
        if parsed.path == "/api/decoder/actions":
            try:
                request = self.read_json_body(MAX_DECODER_ACTION_BYTES)
                self.send_json(self.decoder_service.action(request))
            except DecoderUnavailable as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.SERVICE_UNAVAILABLE
                )
            except DecoderTimeout as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.REQUEST_TIMEOUT)
            except DecoderProtocolError as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.UNPROCESSABLE_ENTITY
                )
            except DecoderError as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
            return
        if parsed.path == "/api/api-collection/actions":
            try:
                request = self.read_json_body(MAX_API_COLLECTION_ACTION_BYTES)
                collection = self.api_collection_store.replace(request)
            except ApiCollectionConflict as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.CONFLICT)
                return
            except (ApiCollectionError, ValueError) as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
                return
            except OSError as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
            self.send_json(
                collection, etag=f'"api-collection-{collection["generation"]}"'
            )
            return
        if parsed.path == "/api/local-analyst/actions":
            try:
                request = self.read_json_body(MAX_LOCAL_ANALYST_ACTION_BYTES)
                action = request.get("action")
                if action == "replace_local_analyst_workspace":
                    response = self.local_analyst_store.replace(request)
                    self.send_json(
                        response,
                        etag=f'"local-analyst-{response["generation"]}"',
                    )
                    return
                if action == "run_local_analyst_script":
                    workspace = self.local_analyst_store.load()
                    self.send_json(self.local_analyst_runner.run(request, workspace))
                    return
                if action == "cancel_local_analyst_script":
                    if set(request) != {"action", "run_id"}:
                        raise LocalAnalystError(
                            "Analyst cancellation action is invalid"
                        )
                    delivered = self.local_analyst_runner.cancel(request.get("run_id"))
                    self.send_json(
                        {
                            "ok": True,
                            "run_id": request.get("run_id"),
                            "cancel_requested": delivered,
                        }
                    )
                    return
                raise LocalAnalystError("Analyst workspace action is invalid")
            except LocalAnalystConflict as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.CONFLICT)
                return
            except LocalAnalystBusy as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.CONFLICT)
                return
            except LocalAnalystProtocolError as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.UNPROCESSABLE_ENTITY
                )
                return
            except (LocalAnalystError, ValueError) as exception:
                self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
                return
            except OSError as exception:
                self.send_json(
                    {"error": str(exception)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
                return
        if parsed.path != "/api/debugger/actions":
            self.send_json(
                {"error": "Application resource not found"}, HTTPStatus.NOT_FOUND
            )
            return
        try:
            request = self.read_json_body(MAX_DEBUGGER_ACTION_BYTES)
            if self.debugger is None:
                raise DebuggerBridgeError("Live debugging is not enabled")
            response = self.debugger.action(request)
        except ValueError as exception:
            self.send_json({"error": str(exception)}, HTTPStatus.BAD_REQUEST)
            return
        except ProtocolError as exception:
            self.send_json({"error": str(exception)}, HTTPStatus.UNPROCESSABLE_ENTITY)
            return
        except DebuggerBridgeError as exception:
            self.send_json({"error": str(exception)}, HTTPStatus.CONFLICT)
            return
        self.send_json(response)

    def read_json_body(self, max_bytes: int) -> dict:
        content_length = self.headers.get("Content-Length")
        if content_length is None or not content_length.isdigit():
            raise ValueError("A valid content length is required")
        length = int(content_length)
        if length <= 0 or length > max_bytes:
            raise ValueError("The request body size is invalid")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ValueError("The request body is malformed JSON") from exception
        if not isinstance(value, dict):
            raise ValueError("The request body must be an object")
        return value

    def load_events(self, limit: Optional[int] = None) -> list[dict]:
        if not self.event_store.exists():
            return []
        if limit is not None:
            return [parse_event(line) for line in self.read_recent_lines(limit)]
        events = []
        with self.event_store.open("rb") as stream:
            for encoded_line in stream:
                if encoded_line.strip():
                    if encoded_line.endswith(b"\n"):
                        encoded_line = encoded_line[:-1]
                    events.append(
                        parse_event(decode_event_line(encoded_line))
                    )
        return events

    def read_recent_lines(self, limit: int) -> list[str]:
        return read_recent_json_lines(
            self.event_store, limit, MAX_EVENT_JSON_BYTES, "event"
        )


    def load_trace_edges(self, limit: int) -> list[dict]:
        return [
            json.loads(line)
            for line in read_recent_json_lines(
                self.trace_store, limit, MAX_TRACE_EDGE_JSON_BYTES, "origin trace edge"
            )
        ]

    def load_request_signal_profiles(self, limit: int) -> list[dict]:
        profiles = [
            json.loads(line)
            for line in read_recent_json_lines(
                self.signal_store,
                limit,
                MAX_SIGNAL_PROFILE_JSON_BYTES,
                "request signal profile",
            )
        ]
        if not all(is_request_signal_profile(profile) for profile in profiles):
            raise ValueError(
                "The request signal profile store contains a malformed record"
            )
        return profiles


    def load_recent_artifacts(self, limit: int) -> list[dict]:
        manifest = self.artifact_store / "manifest.jsonl"
        artifacts = [
            json.loads(line)
            for line in read_recent_json_lines(
                manifest, limit, MAX_ARTIFACT_JSON_BYTES, "artifact"
            )
        ]
        if not all(is_artifact(artifact) for artifact in artifacts):
            raise ValueError("The artifact manifest contains a malformed record")
        identifiers = [artifact["artifact_id"] for artifact in artifacts]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("The artifact manifest contains a duplicate artifact ID")
        return artifacts

    def load_artifacts(self) -> list[dict]:
        manifest = self.artifact_store / "manifest.jsonl"
        if not manifest.exists():
            return []
        artifacts = []
        seen_ids = set()
        with manifest.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                artifact = json.loads(line)
                if not is_artifact(artifact):
                    raise ValueError(
                        "The artifact manifest contains a malformed record"
                    )
                if artifact["artifact_id"] in seen_ids:
                    raise ValueError(
                        "The artifact manifest contains a duplicate artifact ID"
                    )
                seen_ids.add(artifact["artifact_id"])
                artifacts.append(artifact)
        return artifacts


    def find_artifact(self, artifact_id: str) -> tuple[dict, Path]:
        if not CANONICAL_UINT64.fullmatch(artifact_id) or int(artifact_id) >= 2**64:
            raise FileNotFoundError(artifact_id)
        artifact = next(
            (
                item
                for item in self.load_artifacts()
                if item["artifact_id"] == artifact_id
            ),
            None,
        )
        if artifact is None:
            raise FileNotFoundError(artifact_id)
        store_root = self.artifact_store.resolve()
        content_path = (store_root / artifact["content_path"]).resolve()
        if not content_path.is_relative_to(store_root):
            raise ValueError("Artifact content path escapes the artifact store")
        if (
            not content_path.is_file()
            or content_path.stat().st_size != artifact["byte_size"]
        ):
            raise ValueError("Artifact content does not match its manifest")
        return artifact, content_path

    def load_vm_analysis(self) -> dict:
        manifest = self.artifact_store / "manifest.jsonl"
        event_state = self.resource_etag(self.event_store)
        manifest_state = self.resource_etag(manifest)
        signature = f"{self.artifact_store.resolve()}:{manifest_state}:{event_state}"
        with self.analysis_lock:
            if type(self).analysis_signature != signature:
                document = analyze_store(self.artifact_store, self.event_store)
                write_analysis(document, self.artifact_store)
                type(self).analysis_signature = signature
                return document
            path = self.artifact_store / "analysis" / "vm-analysis-v1.json"
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                verify_analysis_document(document)
            except (OSError, UnicodeDecodeError, AnalysisError, json.JSONDecodeError):
                document = analyze_store(self.artifact_store, self.event_store)
                write_analysis(document, self.artifact_store)
            return document

    def broker_connected(self) -> bool:
        if self.broker_socket is None:
            return True
        try:
            return stat.S_ISSOCK(self.broker_socket.stat().st_mode)
        except OSError:
            return False

    def debugger_snapshot(self) -> dict:
        if self.debugger is not None:
            return self.debugger.snapshot()
        return {
            "protocol_version": 1,
            "state": "unavailable",
            "generation": 0,
            "error": None,
            "target": None,
            "targets": [],
            "scripts": [],
            "paused": None,
            "breakpoints": [],
            "watches": [],
            "console": [],
            "heap_diff_baseline": None,
            "memory_origin_trace": DebuggerBridge._empty_memory_origin_trace(),
            "action_scope": DebuggerBridge._empty_action_scope(),
            "request_interception": DebuggerBridge._empty_request_interception(),
            "object_experiment": DebuggerBridge._empty_object_experiment(),
            "runtime_hooks": DebuggerBridge._empty_runtime_hooks(),
            "automation_recipes": DebuggerBridge._empty_automation_recipes(),
            "repeater": DebuggerBridge._empty_repeater(),
            "settings": {
                "breakpoints_active": True,
                "pause_on_exceptions": "none",
                "xhr_breakpoints": [],
                "event_breakpoints": [],
            },
            "limits": {
                "scripts": 5000,
                "call_frames": 64,
                "scope_properties": 2000,
                "console_entries": 500,
                "source_bytes": MAX_ARTIFACT_RESPONSE_BYTES,
            },
        }

    def debugger_state(self) -> str:
        if self.debugger is not None:
            return self.debugger.state()
        return "unavailable"

    def debugger_generation(self) -> int:
        if self.debugger is not None:
            return self.debugger.generation()
        return 0

    def is_trusted_local_request(self) -> bool:
        host_header = self.headers.get("Host")
        if not host_header:
            return False
        try:
            parsed_host = urlparse(f"//{host_header}")
            host_port = parsed_host.port
        except ValueError:
            return False
        if parsed_host.hostname not in {"127.0.0.1", "localhost", "::1"}:
            return False
        expected_port = int(self.server.server_address[1])
        if host_port != expected_port:
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        try:
            parsed_origin = urlparse(origin)
            origin_port = parsed_origin.port
        except ValueError:
            return False
        return (
            parsed_origin.scheme == "http"
            and parsed_origin.hostname in {"127.0.0.1", "localhost", "::1"}
            and origin_port == expected_port
            and parsed_origin.username is None
            and parsed_origin.password is None
            and parsed_origin.path in {"", "/"}
            and not parsed_origin.params
            and not parsed_origin.query
            and not parsed_origin.fragment
        )

    @staticmethod
    def resource_etag(path: Path, state: str = "") -> str:
        try:
            metadata = path.stat()
            identity = (
                f"{metadata.st_dev:x}-{metadata.st_ino:x}-{metadata.st_size:x}-"
                f"{metadata.st_mtime_ns:x}"
            )
        except FileNotFoundError:
            identity = "missing"
        return f'"{identity}-{state}"'

    def send_not_modified(self, etag: str) -> bool:
        if self.headers.get("If-None-Match") != etag:
            return False
        self.send_response(HTTPStatus.NOT_MODIFIED)
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return True

    def send_json(
        self,
        value: dict,
        status: HTTPStatus = HTTPStatus.OK,
        etag: Optional[str] = None,
    ) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if etag is not None:
            self.send_header("ETag", etag)
        self.end_headers()
        self.write_response_body(body)

    def send_artifact_bytes(self, body: bytes, total_size: int, offset: int) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "sandbox")
        self.send_header("Content-Disposition", 'attachment; filename="artifact.bin"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Artifact-Total-Bytes", str(total_size))
        self.send_header("X-Artifact-Offset", str(offset))
        self.send_header(
            "X-Artifact-Truncated", "1" if offset + len(body) < total_size else "0"
        )
        self.end_headers()
        self.write_response_body(body)

    def write_response_body(self, body: bytes) -> None:
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Conditional debugger requests are intentionally long-lived. A tab
            # close or refresh may end the loopback connection before a change.
            return

    def log_message(self, format: str, *args) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local REB research UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7319)
    parser.add_argument("--store", type=Path, default=Path("build/sessions/demo.jsonl"))
    parser.add_argument(
        "--trace-store",
        type=Path,
        default=Path("build/sessions/origin-trace.jsonl"),
    )
    parser.add_argument(
        "--signal-store",
        type=Path,
        default=Path("build/sessions/request-signals.jsonl"),
    )
    parser.add_argument(
        "--artifacts", type=Path, default=Path("build/sessions/artifacts")
    )
    parser.add_argument(
        "--api-collection",
        type=Path,
        default=Path("build/sessions/api-collection-v1.json"),
    )
    parser.add_argument(
        "--local-analyst",
        type=Path,
        default=Path("build/sessions/local-analyst-workspace-v1.json"),
    )
    parser.add_argument("--decoder", type=Path, default=Path("build/reb-decoder"))
    parser.add_argument("--socket", type=Path)
    parser.add_argument("--devtools-active-port", type=Path)
    parser.add_argument("--debugger-transport", type=Path)
    parser.add_argument("--endpoint-file", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ResearchHandler.ui_directory = Path(__file__).resolve().parent
    ResearchHandler.event_store = args.store.resolve()
    ResearchHandler.trace_store = args.trace_store.resolve()
    ResearchHandler.signal_store = args.signal_store.resolve()
    ResearchHandler.artifact_store = args.artifacts.resolve()
    ResearchHandler.api_collection_store = ApiCollectionStore(
        args.api_collection.resolve()
    )
    ResearchHandler.local_analyst_store = LocalAnalystStore(
        args.local_analyst.resolve()
    )
    ResearchHandler.local_analyst_runner = LocalAnalystRunner(
        Path(__file__).resolve().parent
    )
    ResearchHandler.decoder_service = DecoderService(args.decoder.resolve())
    ResearchHandler.broker_socket = args.socket.resolve() if args.socket else None
    debugger = DebuggerBridge(
        args.devtools_active_port.resolve() if args.devtools_active_port else None,
        debugger_transport_binary=(
            args.debugger_transport.resolve() if args.debugger_transport else None
        ),
    )
    ResearchHandler.debugger = debugger
    server = LoopbackThreadingHTTPServer((args.host, args.port), ResearchHandler)
    bound_port = int(server.server_address[1])
    endpoint = f"http://{args.host}:{bound_port}"
    if args.endpoint_file is not None:
        endpoint_file = args.endpoint_file.resolve()
        endpoint_file.parent.mkdir(parents=True, exist_ok=True)
        endpoint_file.write_text(endpoint + "\n", encoding="utf-8")
        os.chmod(endpoint_file, 0o600)
    else:
        endpoint_file = None
    print(f"Research UI: {endpoint}")
    print(f"Event store: {ResearchHandler.event_store}")
    print(f"Origin trace store: {ResearchHandler.trace_store}")
    print(f"Request signal profile store: {ResearchHandler.signal_store}")
    print(f"Artifact store: {ResearchHandler.artifact_store}")
    print(f"API Collection store: {ResearchHandler.api_collection_store.path}")
    print(f"Local analyst store: {ResearchHandler.local_analyst_store.path}")
    debugger.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        ResearchHandler.local_analyst_runner.stop()
        debugger.stop()
        if endpoint_file is not None:
            try:
                endpoint_file.unlink()
            except FileNotFoundError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
