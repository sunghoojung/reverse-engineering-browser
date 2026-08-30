from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_TARGETS = 128
MAX_SCRIPTS = 5_000
MAX_BREAKPOINTS = 1_000
MAX_BREAKPOINT_LOCATIONS = 256
MAX_WATCHES = 100
MAX_WATCH_EXPRESSION_BYTES = 4_096
MAX_CONSOLE_ENTRIES = 500
MAX_CONSOLE_ARGUMENTS = 32
MAX_CALL_FRAMES = 64
MAX_ASYNC_STACK_DEPTH = 32
MAX_SCOPES_PER_FRAME = 12
MAX_SCOPE_PROPERTIES = 100
MAX_TOTAL_SCOPE_PROPERTIES = 2_000
MAX_SCRIPT_SOURCE_BYTES = 2 * 1024 * 1024
MAX_BREAKPOINT_TEXT_BYTES = 4_096
MAX_XHR_BREAKPOINTS = 100
MAX_EVENT_BREAKPOINTS = 256
MAX_LIVE_OBJECT_RESULTS = 50
MAX_LIVE_OBJECT_SCAN = 25_000
MAX_LIVE_OBJECT_QUERY_BYTES = 512
MAX_LIVE_OBJECT_SHAPE_BYTES = 4_096
MAX_LIVE_OBJECT_PREVIEW_PROPERTIES = 16
LIVE_OBJECT_SEARCH_TIMEOUT_MS = 750
MAX_ACTIVE_PORT_BYTES = 4_096
MAX_TARGET_LIST_BYTES = 2 * 1024 * 1024
MAX_TARGET_ID_BYTES = 4_096
MAX_TARGET_TYPE_BYTES = 128
MAX_TARGET_URL_BYTES = 64 * 1024
MAX_REMOTE_TEXT_BYTES = 4_096


LIVE_OBJECT_SEARCH_FUNCTION = r"""function(criteria) {
  const started = Date.now();
  const deadline = started + criteria.timeoutMs;
  const hasQuery = value => typeof value === "string" && value.length > 0;
  const compile = value => {
    if (!hasQuery(value)) return null;
    if (!criteria.regex) {
      const needle = criteria.caseSensitive ? value : value.toLowerCase();
      return input => {
        const text = criteria.caseSensitive ? String(input) : String(input).toLowerCase();
        return text.includes(needle);
      };
    }
    const expression = new RegExp(value, criteria.caseSensitive ? "" : "i");
    return input => expression.test(String(input));
  };
  const propertyMatches = compile(criteria.propertyQuery);
  const valueMatches = compile(criteria.valueQuery);
  const classMatches = compile(criteria.classQuery);
  const boundedText = value => {
    let text;
    try { text = String(value); } catch { return "<unavailable>"; }
    return text.length > 160 ? `${text.slice(0, 160)}...` : text;
  };
  const className = value => {
    if (Array.isArray(value)) return "Array";
    try {
      const prototype = Object.getPrototypeOf(value);
      const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, "constructor");
      const name = descriptor && "value" in descriptor && descriptor.value && descriptor.value.name;
      return typeof name === "string" && name ? name.slice(0, 160) : "Object";
    } catch { return "Object"; }
  };
  const primitiveType = value => value === null ? "null" : typeof value;
  const tokenSet = (root, includeValues) => {
    const tokens = [];
    const seen = new WeakSet();
    const walk = (value, path, depth) => {
      if (tokens.length >= 256 || depth > 3) return;
      if ((typeof value !== "object" && typeof value !== "function") || value === null) {
        const type = primitiveType(value);
        tokens.push(includeValues ? `${path}:${type}=${boundedText(value)}` : `${path}:${type}`);
        return;
      }
      if (seen.has(value)) {
        tokens.push(`${path}:circular`);
        return;
      }
      seen.add(value);
      let descriptors;
      try { descriptors = Object.getOwnPropertyDescriptors(value); } catch { return; }
      const names = Object.keys(descriptors).sort().slice(0, 96);
      if (names.length === 0) tokens.push(`${path}:empty`);
      for (const name of names) {
        if (tokens.length >= 256) break;
        const descriptor = descriptors[name];
        const childPath = path ? `${path}.${name}` : name;
        if (!descriptor || !("value" in descriptor)) {
          tokens.push(`${childPath}:accessor`);
          continue;
        }
        walk(descriptor.value, childPath, depth + 1);
      }
    };
    walk(root, "", 0);
    return new Set(tokens);
  };
  const shapeTokens = criteria.shape === null
    ? null
    : tokenSet(criteria.shape, criteria.includeShapeValues);
  const similarity = candidate => {
    if (shapeTokens === null) return null;
    const candidateTokens = tokenSet(candidate, criteria.includeShapeValues);
    let intersection = 0;
    for (const token of candidateTokens) if (shapeTokens.has(token)) intersection += 1;
    const union = candidateTokens.size + shapeTokens.size - intersection;
    return union === 0 ? 1 : intersection / union;
  };
  const preview = (descriptors, names) => names.slice(0, criteria.previewProperties).map(name => {
    const descriptor = descriptors[name];
    if (!descriptor || !("value" in descriptor)) {
      return {name: name.slice(0, 256), type: "accessor", value: "<getter not invoked>"};
    }
    const value = descriptor.value;
    const type = primitiveType(value);
    if ((typeof value === "object" && value !== null) || typeof value === "function") {
      return {name: name.slice(0, 256), type, value: `[${className(value)}]`};
    }
    return {name: name.slice(0, 256), type, value: boundedText(value)};
  });

  let totalObjects = 0;
  try { totalObjects = Number(this.length) || 0; } catch { totalObjects = 0; }
  const scanLimit = Math.min(totalObjects, criteria.scanLimit);
  const results = [];
  let analyzed = 0;
  let visited = 0;
  let timedOut = false;
  for (let index = 0; index < scanLimit; index += 1) {
    if (Date.now() >= deadline) {
      timedOut = true;
      break;
    }
    visited += 1;
    let candidate;
    let descriptors;
    try {
      candidate = this[index];
      if ((typeof candidate !== "object" && typeof candidate !== "function") || candidate === null) continue;
      descriptors = Object.getOwnPropertyDescriptors(candidate);
    } catch { continue; }
    analyzed += 1;
    const names = Object.keys(descriptors);
    const candidateClass = className(candidate);
    if (propertyMatches && !names.some(propertyMatches)) continue;
    if (classMatches && !classMatches(candidateClass)) continue;
    if (valueMatches && !names.some(name => {
      const descriptor = descriptors[name];
      if (!descriptor || !("value" in descriptor)) return false;
      const value = descriptor.value;
      if ((typeof value === "object" && value !== null) || typeof value === "function") return false;
      return valueMatches(boundedText(value));
    })) continue;
    const score = similarity(candidate);
    if (score !== null && score < criteria.similarityThreshold) continue;
    results.push({
      id: String(index),
      className: candidateClass,
      propertyCount: names.length,
      propertiesTruncated: names.length > criteria.previewProperties,
      similarity: score,
      preview: preview(descriptors, names)
    });
    if (results.length >= criteria.resultLimit) break;
  }
  return {
    protocolVersion: 1,
    analyzed,
    totalObjects,
    results,
    resultLimit: criteria.resultLimit,
    resultLimitReached: results.length >= criteria.resultLimit,
    scanLimitReached: totalObjects > scanLimit || visited < scanLimit,
    timedOut,
    durationMs: Math.max(0, Date.now() - started)
  };
}"""


class DebuggerBridgeError(RuntimeError):
    pass


class ProtocolError(DebuggerBridgeError):
    pass


class WebSocketClosed(DebuggerBridgeError):
    pass


@dataclass
class PendingCommand:
    event: threading.Event
    response: Optional[dict[str, Any]] = None
    error: Optional[BaseException] = None


class WebSocketClient:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        try:
            hostname = parsed.hostname
            port = parsed.port or 80
        except ValueError as exception:
            raise DebuggerBridgeError(
                "The debugger WebSocket URL is malformed"
            ) from exception
        if parsed.scheme != "ws" or hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise DebuggerBridgeError("The debugger WebSocket must use loopback ws://")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise DebuggerBridgeError("The debugger WebSocket URL is malformed")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in path):
            raise DebuggerBridgeError("The debugger WebSocket URL is malformed")
        connection = socket.create_connection((hostname, port), timeout=2.0)
        connection.settimeout(2.0)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        host = hostname
        if hostname == "::1":
            host = "[::1]"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        connection.sendall(request)
        response = self._read_http_headers(connection)
        status_line, *header_lines = response.split("\r\n")
        if not status_line.startswith("HTTP/1.1 101 "):
            connection.close()
            raise DebuggerBridgeError(
                f"Debugger WebSocket rejected the connection: {status_line}"
            )
        headers = {}
        for line in header_lines:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if (
            headers.get("sec-websocket-accept") != expected
            or headers.get("upgrade", "").lower() != "websocket"
            or "upgrade"
            not in {
                token.strip()
                for token in headers.get("connection", "").lower().split(",")
            }
        ):
            connection.close()
            raise DebuggerBridgeError(
                "Debugger WebSocket returned an invalid handshake"
            )
        connection.settimeout(None)
        self._connection = connection
        self._send_lock = threading.Lock()
        self._closed = False

    @staticmethod
    def _read_http_headers(connection: socket.socket) -> str:
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4_096)
            if not chunk:
                raise DebuggerBridgeError("Debugger WebSocket closed during handshake")
            response.extend(chunk)
            if len(response) > 64 * 1024:
                raise DebuggerBridgeError("Debugger WebSocket handshake is oversized")
        header, remainder = bytes(response).split(b"\r\n\r\n", 1)
        if remainder:
            raise DebuggerBridgeError("Debugger WebSocket sent data during handshake")
        return header.decode("iso-8859-1")

    def send_json(self, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        if len(body) > 16 * 1024 * 1024:
            raise DebuggerBridgeError("Debugger command is oversized")
        with self._send_lock:
            if self._closed:
                raise WebSocketClosed("Debugger WebSocket is closed")
            self._connection.sendall(self._encode_frame(0x1, body))

    def receive_json(self, timeout: float = 0.5) -> Optional[dict[str, Any]]:
        while True:
            ready, _, _ = select.select([self._connection], [], [], timeout)
            if not ready:
                return None
            opcode, payload = self._receive_frame()
            if opcode == 0x8:
                raise WebSocketClosed("Debugger WebSocket closed")
            if opcode == 0x9:
                with self._send_lock:
                    self._connection.sendall(self._encode_frame(0xA, payload))
                continue
            if opcode == 0xA:
                continue
            if opcode != 0x1:
                raise DebuggerBridgeError("Debugger WebSocket sent a non-text message")
            try:
                value = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exception:
                raise DebuggerBridgeError(
                    "Debugger WebSocket sent malformed JSON"
                ) from exception
            if not isinstance(value, dict):
                raise DebuggerBridgeError(
                    "Debugger WebSocket sent a non-object message"
                )
            return value

    def close(self) -> None:
        with self._send_lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._connection.close()

    @staticmethod
    def _encode_frame(opcode: int, payload: bytes) -> bytes:
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
        elif length < 2**16:
            header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
        mask = os.urandom(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return header + mask + masked

    def _receive_frame(self) -> tuple[int, bytes]:
        first, second = self._receive_exact(2)
        final = (first & 0x80) != 0
        opcode = first & 0x0F
        masked = (second & 0x80) != 0
        length = second & 0x7F
        if not final or opcode == 0x0:
            raise DebuggerBridgeError("Fragmented debugger messages are not supported")
        if masked:
            raise DebuggerBridgeError("Debugger server sent a masked frame")
        if length == 126:
            length = struct.unpack("!H", self._receive_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._receive_exact(8))[0]
        if length > 64 * 1024 * 1024:
            raise DebuggerBridgeError("Debugger WebSocket message is oversized")
        return opcode, self._receive_exact(length)

    def _receive_exact(self, length: int) -> bytes:
        body = bytearray()
        while len(body) < length:
            chunk = self._connection.recv(length - len(body))
            if not chunk:
                raise WebSocketClosed("Debugger WebSocket closed")
            body.extend(chunk)
        return bytes(body)


class DebuggerBridge:
    def __init__(self, active_port_path: Optional[Path] = None) -> None:
        self.active_port_path = active_port_path
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._connection: Optional[WebSocketClient] = None
        self._pending: dict[int, PendingCommand] = {}
        self._next_command_id = 1
        self._generation = 0
        self._state = "unavailable" if active_port_path is None else "waiting"
        self._error: Optional[str] = None
        self._target: Optional[dict[str, str]] = None
        self._targets: list[dict[str, str]] = []
        self._preferred_target_id: Optional[str] = None
        self._scripts: dict[str, dict[str, Any]] = {}
        self._paused: Optional[dict[str, Any]] = None
        self._pause_serial = 0
        self._breakpoints: dict[str, dict[str, Any]] = {}
        self._watches: list[dict[str, Any]] = []
        self._watch_frame_id: Optional[str] = None
        self._next_watch_id = 1
        self._console: list[dict[str, Any]] = []
        self._next_console_id = 1
        self._breakpoints_active = True
        self._pause_on_exceptions = "none"
        self._xhr_breakpoints: list[str] = []
        self._event_breakpoints: list[str] = []

    def start(self) -> None:
        if self.active_port_path is None or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="reb-debugger-bridge", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._condition:
            connection = self._connection
            self._condition.notify_all()
        if connection is not None:
            connection.close()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._fail_pending(DebuggerBridgeError("Debugger bridge stopped"))

    def generation(self) -> int:
        with self._lock:
            return self._generation

    def state(self) -> str:
        with self._lock:
            return self._state

    def wait_for_change(self, generation: int, timeout: float) -> int:
        with self._condition:
            self._condition.wait_for(
                lambda: self._generation != generation or self._stop.is_set(),
                timeout=max(0.0, timeout),
            )
            return self._generation

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "protocol_version": 1,
                "state": self._state,
                "generation": self._generation,
                "error": self._error,
                "target": dict(self._target) if self._target is not None else None,
                "targets": [
                    {key: target[key] for key in ("id", "type", "title", "url")}
                    for target in self._targets
                ],
                # Script records contain only scalar values, so copying each mapping
                # preserves snapshot isolation without a full recursive traversal.
                "scripts": [dict(script) for script in self._scripts.values()],
                "paused": copy.deepcopy(self._paused),
                "breakpoints": copy.deepcopy(list(self._breakpoints.values())),
                "watches": copy.deepcopy(self._watches),
                "console": copy.deepcopy(self._console),
                "settings": {
                    "breakpoints_active": self._breakpoints_active,
                    "pause_on_exceptions": self._pause_on_exceptions,
                    "xhr_breakpoints": list(self._xhr_breakpoints),
                    "event_breakpoints": list(self._event_breakpoints),
                },
                "limits": {
                    "scripts": MAX_SCRIPTS,
                    "call_frames": MAX_CALL_FRAMES,
                    "scope_properties": MAX_TOTAL_SCOPE_PROPERTIES,
                    "console_entries": MAX_CONSOLE_ENTRIES,
                    "source_bytes": MAX_SCRIPT_SOURCE_BYTES,
                },
            }

    def action(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if not isinstance(action, str):
            raise DebuggerBridgeError("Debugger action is required")
        if action == "pause":
            self._command("Debugger.pause")
        elif action == "resume":
            self._command("Debugger.resume")
        elif action == "step_over":
            self._command("Debugger.stepOver")
        elif action == "step_into":
            self._command("Debugger.stepInto", {"breakOnAsyncCall": True})
        elif action == "step_out":
            self._command("Debugger.stepOut")
        elif action == "restart_frame":
            frame_id = self._required_text(request, "call_frame_id", 4_096)
            self._command(
                "Debugger.restartFrame", {"callFrameId": frame_id, "mode": "StepInto"}
            )
        elif action == "set_breakpoint":
            return self._set_breakpoint(request)
        elif action == "remove_breakpoint":
            breakpoint_id = self._required_text(
                request, "breakpoint_id", MAX_BREAKPOINT_TEXT_BYTES
            )
            self._command("Debugger.removeBreakpoint", {"breakpointId": breakpoint_id})
            with self._lock:
                self._breakpoints.pop(breakpoint_id, None)
                self._changed()
        elif action == "update_breakpoint":
            breakpoint_id = self._required_text(
                request, "breakpoint_id", MAX_BREAKPOINT_TEXT_BYTES
            )
            with self._lock:
                existing = self._breakpoints.get(breakpoint_id)
            if existing is None:
                raise DebuggerBridgeError("Breakpoint is unavailable")
            replacement = self._set_breakpoint(
                {
                    "url": existing["url"],
                    "script_id": existing["script_id"],
                    "line": existing["line"],
                    "column": existing["column"],
                    "kind": request.get("kind"),
                    "expression": request.get("expression"),
                },
                replacing=breakpoint_id,
            )
            self._command("Debugger.removeBreakpoint", {"breakpointId": breakpoint_id})
            with self._lock:
                self._breakpoints.pop(breakpoint_id, None)
                self._changed()
            return replacement
        elif action == "set_breakpoints_active":
            active = request.get("active")
            if not isinstance(active, bool):
                raise DebuggerBridgeError("Breakpoint active state must be boolean")
            self._command("Debugger.setBreakpointsActive", {"active": active})
            with self._lock:
                self._breakpoints_active = active
                self._changed()
        elif action == "set_pause_on_exceptions":
            mode = request.get("mode")
            if mode not in {"none", "uncaught", "all"}:
                raise DebuggerBridgeError("Pause-on-exceptions mode is invalid")
            self._command("Debugger.setPauseOnExceptions", {"state": mode})
            with self._lock:
                self._pause_on_exceptions = mode
                self._changed()
        elif action == "add_watch":
            expression = self._required_text(
                request, "expression", MAX_WATCH_EXPRESSION_BYTES
            )
            with self._lock:
                if len(self._watches) >= MAX_WATCHES:
                    raise DebuggerBridgeError("Watch expression limit reached")
                watch = {
                    "id": str(self._next_watch_id),
                    "expression": expression,
                    "result": None,
                    "error": None,
                }
                self._next_watch_id += 1
                self._watches.append(watch)
                watch_frame_id = self._watch_frame_id
                self._changed()
            if watch_frame_id is not None:
                self._evaluate_watches_async(watch_frame_id)
        elif action == "remove_watch":
            watch_id = self._required_text(request, "watch_id", 32)
            with self._lock:
                self._watches = [
                    watch for watch in self._watches if watch["id"] != watch_id
                ]
                self._changed()
        elif action == "evaluate_watches":
            frame_id = self._required_text(request, "call_frame_id", 4_096)
            with self._lock:
                valid_frame = self._paused is not None and any(
                    frame["id"] == frame_id for frame in self._paused["call_frames"]
                )
            if not valid_frame:
                raise DebuggerBridgeError("Call frame is unavailable")
            with self._lock:
                self._watch_frame_id = frame_id
            self._evaluate_watches(frame_id)
        elif action == "set_xhr_breakpoint":
            self._set_xhr_breakpoint(request)
        elif action == "remove_xhr_breakpoint":
            pattern = self._required_text(
                request, "pattern", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
            )
            self._command("DOMDebugger.removeXHRBreakpoint", {"url": pattern})
            with self._lock:
                self._xhr_breakpoints = [
                    value for value in self._xhr_breakpoints if value != pattern
                ]
                self._changed()
        elif action == "set_event_breakpoint":
            event_name = self._required_text(request, "event_name", 256)
            with self._lock:
                if (
                    event_name not in self._event_breakpoints
                    and len(self._event_breakpoints) >= MAX_EVENT_BREAKPOINTS
                ):
                    raise DebuggerBridgeError("Event breakpoint limit reached")
            self._command(
                "DOMDebugger.setEventListenerBreakpoint", {"eventName": event_name}
            )
            with self._lock:
                if event_name not in self._event_breakpoints:
                    self._event_breakpoints.append(event_name)
                self._changed()
        elif action == "remove_event_breakpoint":
            event_name = self._required_text(request, "event_name", 256)
            self._command(
                "DOMDebugger.removeEventListenerBreakpoint", {"eventName": event_name}
            )
            with self._lock:
                self._event_breakpoints = [
                    value for value in self._event_breakpoints if value != event_name
                ]
                self._changed()
        elif action == "select_target":
            target_id = self._required_text(request, "target_id", 4_096)
            with self._lock:
                if not any(target["id"] == target_id for target in self._targets):
                    raise DebuggerBridgeError("Debugger target is unavailable")
                self._preferred_target_id = target_id
                connection = self._connection
            if connection is not None:
                connection.close()
        elif action == "search_live_objects":
            return self._search_live_objects(request)
        elif action == "clear_console":
            with self._lock:
                self._console = []
                self._changed()
        else:
            raise DebuggerBridgeError("Debugger action is not allowed")
        return {"ok": True, "generation": self.generation()}

    def get_script_source(self, script_id: str) -> dict[str, Any]:
        if not script_id or len(script_id.encode("utf-8")) > 4_096:
            raise DebuggerBridgeError("Script ID is invalid")
        with self._lock:
            script = self._scripts.get(script_id)
            if script is None:
                raise DebuggerBridgeError("Script is unavailable")
            if script["length"] > MAX_SCRIPT_SOURCE_BYTES:
                raise DebuggerBridgeError("Live script exceeds the 2 MiB viewer limit")
        result = self._command(
            "Debugger.getScriptSource", {"scriptId": script_id}, timeout=5.0
        )
        source = result.get("scriptSource")
        if not isinstance(source, str):
            bytecode = result.get("bytecode")
            if not isinstance(bytecode, str):
                raise DebuggerBridgeError("Debugger returned malformed script source")
            source = bytecode
        encoded = source.encode("utf-8")
        truncated = len(encoded) > MAX_SCRIPT_SOURCE_BYTES
        if truncated:
            encoded = encoded[:MAX_SCRIPT_SOURCE_BYTES]
            source = encoded.decode("utf-8", errors="replace")
        return {
            "protocol_version": 1,
            "script_id": script_id,
            "source": source,
            "truncated": truncated,
        }

    def _search_live_objects(self, request: dict[str, Any]) -> dict[str, Any]:
        property_query = self._optional_search_text(request, "property_query")
        value_query = self._optional_search_text(request, "value_query")
        class_query = self._optional_search_text(request, "class_query")
        regex = request.get("regex", False)
        case_sensitive = request.get("case_sensitive", False)
        include_shape_values = request.get("include_shape_values", False)
        if not all(
            isinstance(value, bool)
            for value in (regex, case_sensitive, include_shape_values)
        ):
            raise DebuggerBridgeError("Live object search options must be boolean")

        shape_text = request.get("shape", "")
        if not isinstance(shape_text, str):
            raise DebuggerBridgeError("Live object shape must be JSON text")
        if len(shape_text.encode("utf-8")) > MAX_LIVE_OBJECT_SHAPE_BYTES:
            raise DebuggerBridgeError("Live object shape exceeds the 4 KiB limit")
        shape: Optional[Any] = None
        if shape_text.strip():
            try:
                shape = json.loads(shape_text)
            except json.JSONDecodeError as exception:
                raise DebuggerBridgeError(
                    "Live object shape must be valid JSON"
                ) from exception
            if not isinstance(shape, (dict, list)):
                raise DebuggerBridgeError("Live object shape must be an object or array")

        threshold = request.get("similarity_threshold", 0.75)
        if (
            not self._is_finite_protocol_number(threshold)
            or isinstance(threshold, bool)
            or threshold < 0
            or threshold > 1
        ):
            raise DebuggerBridgeError(
                "Live object similarity threshold must be between 0 and 1"
            )
        if not any((property_query, value_query, class_query, shape is not None)):
            raise DebuggerBridgeError("Live object search requires at least one criterion")

        criteria = {
            "propertyQuery": property_query,
            "valueQuery": value_query,
            "classQuery": class_query,
            "regex": regex,
            "caseSensitive": case_sensitive,
            "shape": shape,
            "includeShapeValues": include_shape_values,
            "similarityThreshold": float(threshold),
            "resultLimit": MAX_LIVE_OBJECT_RESULTS,
            "scanLimit": MAX_LIVE_OBJECT_SCAN,
            "previewProperties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
            "timeoutMs": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
        }
        prototype_id: Optional[str] = None
        objects_id: Optional[str] = None
        try:
            prototype = self._command(
                "Runtime.evaluate",
                {
                    "expression": "Object.prototype",
                    "objectGroup": "reb-live-object-search",
                    "silent": True,
                },
            )
            prototype_id = self._runtime_result_object_id(prototype, "prototype")
            objects = self._command(
                "Runtime.queryObjects", {"prototypeObjectId": prototype_id}, timeout=5.0
            )
            objects_id = self._runtime_result_object_id(objects, "object collection")
            evaluated = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": objects_id,
                    "functionDeclaration": LIVE_OBJECT_SEARCH_FUNCTION,
                    "arguments": [{"value": criteria}],
                    "returnByValue": True,
                    "silent": True,
                    "awaitPromise": False,
                    "userGesture": False,
                    "throwOnSideEffect": True,
                    "timeout": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                },
                timeout=3.0,
            )
        finally:
            for object_id in (objects_id, prototype_id):
                if object_id is None:
                    continue
                try:
                    self._command("Runtime.releaseObject", {"objectId": object_id})
                except DebuggerBridgeError:
                    pass

        if isinstance(evaluated.get("exceptionDetails"), dict):
            raise DebuggerBridgeError("Live object search failed in the target")
        remote = evaluated.get("result")
        document = remote.get("value") if isinstance(remote, dict) else None
        return self._normalize_live_object_search(document)

    def _optional_search_text(self, request: dict[str, Any], field: str) -> str:
        value = request.get(field, "")
        if not isinstance(value, str):
            raise DebuggerBridgeError("Live object search criteria must be text")
        if len(value.encode("utf-8")) > MAX_LIVE_OBJECT_QUERY_BYTES:
            raise DebuggerBridgeError("Live object search criterion exceeds 512 bytes")
        return value

    @staticmethod
    def _runtime_result_object_id(result: dict[str, Any], label: str) -> str:
        remote = result.get("result")
        object_id = remote.get("objectId") if isinstance(remote, dict) else None
        if not isinstance(object_id, str) or not object_id:
            raise ProtocolError(f"Debugger returned a malformed {label}")
        return object_id

    def _normalize_live_object_search(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocolVersion") != 1:
            raise ProtocolError("Debugger returned a malformed live object search")
        integer_fields = (
            "analyzed",
            "totalObjects",
            "resultLimit",
            "durationMs",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Debugger returned invalid live object search counts")
        if value["resultLimit"] != MAX_LIVE_OBJECT_RESULTS:
            raise ProtocolError("Debugger returned an invalid live object result limit")
        boolean_fields = (
            "resultLimitReached",
            "scanLimitReached",
            "timedOut",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Debugger returned invalid live object coverage")
        raw_results = value.get("results")
        if not isinstance(raw_results, list) or len(raw_results) > MAX_LIVE_OBJECT_RESULTS:
            raise ProtocolError("Debugger returned too many live object results")
        results = []
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                raise ProtocolError("Debugger returned a malformed live object result")
            result_id = raw_result.get("id")
            class_name = raw_result.get("className")
            property_count = raw_result.get("propertyCount")
            properties_truncated = raw_result.get("propertiesTruncated")
            similarity = raw_result.get("similarity")
            preview = raw_result.get("preview")
            if (
                not isinstance(result_id, str)
                or not isinstance(class_name, str)
                or not isinstance(property_count, int)
                or isinstance(property_count, bool)
                or property_count < 0
                or property_count > 2**31 - 1
                or not isinstance(properties_truncated, bool)
                or (
                    similarity is not None
                    and (
                        not self._is_finite_protocol_number(similarity)
                        or isinstance(similarity, bool)
                        or similarity < 0
                        or similarity > 1
                    )
                )
                or not isinstance(preview, list)
                or len(preview) > MAX_LIVE_OBJECT_PREVIEW_PROPERTIES
            ):
                raise ProtocolError("Debugger returned a malformed live object result")
            properties = []
            for raw_property in preview:
                if not isinstance(raw_property, dict) or any(
                    not isinstance(raw_property.get(field), str)
                    for field in ("name", "type", "value")
                ):
                    raise ProtocolError(
                        "Debugger returned a malformed live object preview"
                    )
                properties.append(
                    {
                        "name": self._truncate_text(raw_property["name"]),
                        "type": self._truncate_text(raw_property["type"], 128),
                        "value": self._truncate_text(raw_property["value"]),
                    }
                )
            results.append(
                {
                    "id": self._truncate_text(result_id, 128),
                    "class_name": self._truncate_text(class_name, 256),
                    "property_count": property_count,
                    "properties_truncated": properties_truncated,
                    "similarity": float(similarity)
                    if similarity is not None
                    else None,
                    "preview": properties,
                }
            )
        return {
            "ok": True,
            "search": {
                "protocol_version": 1,
                "analyzed": value["analyzed"],
                "total_objects": value["totalObjects"],
                "result_limit": value["resultLimit"],
                "result_limit_reached": value["resultLimitReached"],
                "scan_limit_reached": value["scanLimitReached"],
                "timed_out": value["timedOut"],
                "duration_ms": value["durationMs"],
                "results": results,
            },
            "generation": self.generation(),
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                targets = self._discover_targets()
                with self._lock:
                    current_targets = targets[:MAX_TARGETS]
                    if current_targets != self._targets:
                        self._targets = current_targets
                        self._changed()
                pages = [
                    target
                    for target in targets
                    if target["type"] in {"page", "webview"}
                ]
                if not pages:
                    self._set_state("waiting", None)
                    self._stop.wait(0.5)
                    continue
                with self._lock:
                    preferred = self._preferred_target_id
                target = next(
                    (item for item in pages if item["id"] == preferred), pages[0]
                )
                self._serve_target(target)
            except (
                OSError,
                ValueError,
                DebuggerBridgeError,
                json.JSONDecodeError,
            ) as exception:
                if self._stop.is_set():
                    break
                self._set_state("waiting", str(exception))
                self._stop.wait(0.5)

    def _discover_targets(self) -> list[dict[str, str]]:
        if self.active_port_path is None or not self.active_port_path.is_file():
            raise DebuggerBridgeError("Waiting for the authorized browser debugger")
        with self.active_port_path.open("rb") as active_port_file:
            active_port_body = active_port_file.read(MAX_ACTIVE_PORT_BYTES + 1)
        if len(active_port_body) > MAX_ACTIVE_PORT_BYTES:
            raise DebuggerBridgeError("The browser debugger endpoint is oversized")
        lines = active_port_body.decode("utf-8").splitlines()
        if len(lines) < 2 or not lines[0].isdigit():
            raise DebuggerBridgeError("The browser debugger endpoint is incomplete")
        port = int(lines[0])
        if port <= 0 or port >= 2**16:
            raise DebuggerBridgeError("The browser debugger port is invalid")
        request = Request(
            f"http://127.0.0.1:{port}/json/list", headers={"Accept": "application/json"}
        )
        with urlopen(request, timeout=2.0) as response:
            target_body = response.read(MAX_TARGET_LIST_BYTES + 1)
        if len(target_body) > MAX_TARGET_LIST_BYTES:
            raise DebuggerBridgeError("The browser target list is oversized")
        body = json.loads(target_body)
        if not isinstance(body, list) or len(body) > MAX_TARGETS * 4:
            raise DebuggerBridgeError("The browser returned a malformed target list")
        targets = []
        for value in body:
            if not isinstance(value, dict):
                continue
            target_id = value.get("id")
            target_type = value.get("type")
            web_socket = value.get("webSocketDebuggerUrl")
            if not all(
                isinstance(item, str) and item
                for item in (target_id, target_type, web_socket)
            ):
                continue
            if (
                len(target_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
                or len(target_type.encode("utf-8")) > MAX_TARGET_TYPE_BYTES
                or len(web_socket.encode("utf-8")) > MAX_TARGET_URL_BYTES
            ):
                continue
            title = value.get("title") if isinstance(value.get("title"), str) else ""
            target_url = value.get("url") if isinstance(value.get("url"), str) else ""
            if (
                len(title.encode("utf-8")) > MAX_TARGET_URL_BYTES
                or len(target_url.encode("utf-8")) > MAX_TARGET_URL_BYTES
            ):
                continue
            targets.append(
                {
                    "id": target_id,
                    "type": target_type,
                    "title": title,
                    "url": target_url,
                    "web_socket_url": web_socket,
                }
            )
        return targets

    def _serve_target(self, target: dict[str, str]) -> None:
        self._set_state("connecting", None)
        connection = WebSocketClient(target["web_socket_url"])
        public_target = {key: target[key] for key in ("id", "type", "title", "url")}
        with self._lock:
            self._connection = connection
            self._target = public_target
            self._scripts = {}
            self._paused = None
            self._watch_frame_id = None
            self._pause_serial += 1
            self._changed()
        reader = threading.Thread(
            target=self._read_messages,
            args=(connection,),
            name="reb-debugger-reader",
            daemon=True,
        )
        self._reader_thread = reader
        reader.start()
        try:
            self._command("Runtime.enable")
            self._command(
                "Debugger.enable", {"maxScriptsCacheSize": float(100 * 1024 * 1024)}
            )
            self._command(
                "Debugger.setAsyncCallStackDepth", {"maxDepth": MAX_ASYNC_STACK_DEPTH}
            )
            self._command("Log.enable")
            self._restore_settings()
            with self._lock:
                already_paused = self._paused is not None
            if not already_paused:
                self._set_state("running", None)
            next_target_refresh = 0.0
            while reader.is_alive() and not self._stop.wait(0.25):
                if time.monotonic() < next_target_refresh:
                    continue
                next_target_refresh = time.monotonic() + 1.0
                try:
                    targets = self._discover_targets()[:MAX_TARGETS]
                except (OSError, ValueError, DebuggerBridgeError, json.JSONDecodeError):
                    continue
                with self._lock:
                    if targets != self._targets:
                        self._targets = targets
                        current = next(
                            (item for item in targets if item["id"] == target["id"]),
                            None,
                        )
                        if current is not None:
                            self._target = {
                                key: current[key]
                                for key in ("id", "type", "title", "url")
                            }
                        self._changed()
        finally:
            connection.close()
            reader.join(timeout=1.0)
            with self._lock:
                if self._connection is connection:
                    self._connection = None
                    self._target = None
                    self._scripts = {}
                    self._paused = None
                    self._state = "waiting"
                    self._watch_frame_id = None
                    self._pause_serial += 1
                    self._changed()

    def _read_messages(self, connection: WebSocketClient) -> None:
        error: Optional[BaseException] = None
        try:
            while not self._stop.is_set():
                message = connection.receive_json()
                if message is None:
                    continue
                command_id = message.get("id")
                if isinstance(command_id, int):
                    with self._lock:
                        pending = self._pending.pop(command_id, None)
                    if pending is not None:
                        pending.response = message
                        pending.event.set()
                    continue
                method = message.get("method")
                params = message.get("params", {})
                if isinstance(method, str) and isinstance(params, dict):
                    self._handle_event(method, params)
        except (OSError, DebuggerBridgeError, json.JSONDecodeError) as exception:
            error = exception
        finally:
            self._fail_pending(error or WebSocketClosed("Debugger target disconnected"))
            connection.close()

    def _handle_event(self, method: str, params: dict[str, Any]) -> None:
        if method == "Debugger.scriptParsed":
            script = self._parse_script(params)
            if script is not None:
                with self._lock:
                    if (
                        len(self._scripts) >= MAX_SCRIPTS
                        and script["script_id"] not in self._scripts
                    ):
                        oldest = next(iter(self._scripts))
                        self._scripts.pop(oldest, None)
                    self._scripts[script["script_id"]] = script
                    self._changed()
            return
        if method == "Debugger.paused":
            paused = self._parse_pause(params)
            with self._lock:
                self._pause_serial += 1
                pause_serial = self._pause_serial
                self._paused = paused
                self._watch_frame_id = (
                    paused["call_frames"][0]["id"] if paused["call_frames"] else None
                )
                self._state = "paused"
                self._error = None
                self._changed()
            self._enrich_pause_async(pause_serial)
            return
        if method == "Debugger.resumed":
            with self._lock:
                self._pause_serial += 1
                self._paused = None
                self._watch_frame_id = None
                self._state = "running"
                self._error = None
                self._changed()
            return
        if method == "Debugger.breakpointResolved":
            breakpoint_id = params.get("breakpointId")
            location = self._parse_location(params.get("location"))
            if isinstance(breakpoint_id, str) and location is not None:
                with self._lock:
                    breakpoint = self._breakpoints.get(breakpoint_id)
                    if (
                        breakpoint is not None
                        and location not in breakpoint["locations"]
                    ):
                        if len(breakpoint["locations"]) < MAX_BREAKPOINT_LOCATIONS:
                            breakpoint["locations"].append(location)
                        else:
                            breakpoint["locations_truncated"] = True
                        self._changed()
            return
        if method == "Runtime.consoleAPICalled":
            self._append_console(
                params.get("type", "log"),
                params.get("timestamp"),
                params.get("args"),
                params.get("stackTrace"),
            )
            return
        if method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails")
            if isinstance(details, dict):
                value = details.get("exception")
                if not isinstance(value, dict):
                    value = {
                        "type": "string",
                        "value": details.get("text", "Exception"),
                    }
                self._append_console(
                    "error", params.get("timestamp"), [value], details.get("stackTrace")
                )
            return
        if method == "Log.entryAdded":
            entry = params.get("entry")
            if isinstance(entry, dict):
                value = {"type": "string", "value": entry.get("text", "")}
                self._append_console(
                    entry.get("level", "info"),
                    entry.get("timestamp"),
                    [value],
                    entry.get("stackTrace"),
                )

    def _command(
        self, method: str, params: Optional[dict[str, Any]] = None, timeout: float = 3.0
    ) -> dict[str, Any]:
        with self._lock:
            connection = self._connection
            if connection is None:
                raise DebuggerBridgeError("The browser debugger is not attached")
            command_id = self._next_command_id
            self._next_command_id += 1
            pending = PendingCommand(threading.Event())
            self._pending[command_id] = pending
        try:
            connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except BaseException:
            with self._lock:
                self._pending.pop(command_id, None)
            raise
        if not pending.event.wait(timeout):
            with self._lock:
                self._pending.pop(command_id, None)
            raise DebuggerBridgeError(f"Debugger command timed out: {method}")
        if pending.error is not None:
            raise DebuggerBridgeError(str(pending.error))
        response = pending.response or {}
        error = response.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            raise ProtocolError(
                message
                if isinstance(message, str)
                else f"Debugger command failed: {method}"
            )
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise ProtocolError(f"Debugger returned malformed command result: {method}")
        return result

    def _set_breakpoint(
        self, request: dict[str, Any], replacing: Optional[str] = None
    ) -> dict[str, Any]:
        url = self._required_text(
            request, "url", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
        )
        script_id_value = request.get("script_id")
        script_id = None
        if script_id_value == "" and url:
            script_id_value = None
        if script_id_value is not None:
            script_id = self._required_text(request, "script_id", MAX_TARGET_ID_BYTES)
        if not url and script_id is None:
            raise DebuggerBridgeError("Breakpoint URL or script ID is required")
        line = request.get("line")
        column = request.get("column", 0)
        kind = request.get("kind")
        if kind is None:
            kind = "conditional" if request.get("condition") else "line"
        if kind not in {"line", "conditional", "logpoint"}:
            raise DebuggerBridgeError("Breakpoint kind is invalid")
        expression = request.get("expression", request.get("condition", ""))
        if (
            not isinstance(line, int)
            or isinstance(line, bool)
            or line < 0
            or line >= 2**31
        ):
            raise DebuggerBridgeError("Breakpoint line is invalid")
        if (
            not isinstance(column, int)
            or isinstance(column, bool)
            or column < 0
            or column >= 2**31
        ):
            raise DebuggerBridgeError("Breakpoint column is invalid")
        if (
            not isinstance(expression, str)
            or len(expression.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES
        ):
            raise DebuggerBridgeError("Breakpoint expression is invalid")
        if kind != "line" and not expression:
            raise DebuggerBridgeError("Breakpoint expression is required")
        condition = "" if kind == "line" else expression
        if kind == "logpoint":
            condition = f"console.log({expression}), false"
        if len(condition.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES:
            raise DebuggerBridgeError("Breakpoint condition is invalid")
        with self._lock:
            if (
                len(self._breakpoints) >= MAX_BREAKPOINTS
                and replacing not in self._breakpoints
            ):
                raise DebuggerBridgeError("Breakpoint limit reached")
            if not url and script_id not in self._scripts:
                raise DebuggerBridgeError("Breakpoint script is unavailable")
        if url:
            result = self._command(
                "Debugger.setBreakpointByUrl",
                {
                    "lineNumber": line,
                    "url": url,
                    "columnNumber": column,
                    "condition": condition,
                },
            )
            locations = result.get("locations", [])
        else:
            result = self._command(
                "Debugger.setBreakpoint",
                {
                    "location": {
                        "scriptId": script_id,
                        "lineNumber": line,
                        "columnNumber": column,
                    },
                    "condition": condition,
                },
            )
            actual_location = result.get("actualLocation")
            locations = [actual_location] if actual_location is not None else []
        breakpoint_id = result.get("breakpointId")
        if (
            not isinstance(breakpoint_id, str)
            or len(breakpoint_id.encode("utf-8")) > MAX_BREAKPOINT_TEXT_BYTES
            or not isinstance(locations, list)
        ):
            raise ProtocolError("Debugger returned a malformed breakpoint")
        parsed_locations = []
        locations_truncated = False
        for value in locations:
            location = self._parse_location(value)
            if location is None:
                continue
            if len(parsed_locations) >= MAX_BREAKPOINT_LOCATIONS:
                locations_truncated = True
                break
            parsed_locations.append(location)
        record = {
            "id": breakpoint_id,
            "url": url,
            "script_id": script_id or "",
            "line": line,
            "column": column,
            "condition": condition,
            "kind": kind,
            "expression": expression,
            "locations": parsed_locations,
            "locations_truncated": locations_truncated,
        }
        with self._lock:
            self._breakpoints[breakpoint_id] = record
            self._changed()
        return {
            "ok": True,
            "breakpoint": record,
            "generation": self.snapshot()["generation"],
        }

    def _set_xhr_breakpoint(self, request: dict[str, Any]) -> None:
        pattern = self._required_text(
            request, "pattern", MAX_BREAKPOINT_TEXT_BYTES, allow_empty=True
        )
        with self._lock:
            if (
                pattern not in self._xhr_breakpoints
                and len(self._xhr_breakpoints) >= MAX_XHR_BREAKPOINTS
            ):
                raise DebuggerBridgeError("XHR breakpoint limit reached")
        self._command("DOMDebugger.setXHRBreakpoint", {"url": pattern})
        with self._lock:
            if pattern not in self._xhr_breakpoints:
                self._xhr_breakpoints.append(pattern)
            self._changed()

    def _restore_settings(self) -> None:
        with self._lock:
            active = self._breakpoints_active
            pause_mode = self._pause_on_exceptions
            breakpoints = list(self._breakpoints.values())
            xhr_breakpoints = list(self._xhr_breakpoints)
            event_breakpoints = list(self._event_breakpoints)
            self._breakpoints = {}
        self._command("Debugger.setBreakpointsActive", {"active": active})
        self._command("Debugger.setPauseOnExceptions", {"state": pause_mode})
        for breakpoint in breakpoints:
            try:
                self._set_breakpoint(breakpoint)
            except DebuggerBridgeError:
                continue
        for pattern in xhr_breakpoints:
            try:
                self._command("DOMDebugger.setXHRBreakpoint", {"url": pattern})
            except DebuggerBridgeError:
                continue
        for event_name in event_breakpoints:
            try:
                self._command(
                    "DOMDebugger.setEventListenerBreakpoint", {"eventName": event_name}
                )
            except DebuggerBridgeError:
                continue

    def _parse_script(self, params: dict[str, Any]) -> Optional[dict[str, Any]]:
        script_id = params.get("scriptId")
        url = params.get("url")
        script_hash = params.get("hash") if isinstance(params.get("hash"), str) else ""
        source_map_url = (
            params.get("sourceMapURL")
            if isinstance(params.get("sourceMapURL"), str)
            else ""
        )
        if (
            not isinstance(script_id, str)
            or not isinstance(url, str)
            or len(script_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or len(url.encode("utf-8")) > MAX_TARGET_URL_BYTES
            or len(script_hash.encode("utf-8")) > MAX_TARGET_URL_BYTES
            or len(source_map_url.encode("utf-8")) > MAX_TARGET_URL_BYTES
        ):
            return None
        return {
            "script_id": script_id,
            "url": url,
            "start_line": self._bounded_integer(params.get("startLine")),
            "start_column": self._bounded_integer(params.get("startColumn")),
            "end_line": self._bounded_integer(params.get("endLine")),
            "end_column": self._bounded_integer(params.get("endColumn")),
            "execution_context_id": self._bounded_integer(
                params.get("executionContextId")
            ),
            "hash": script_hash,
            "source_map_url": source_map_url,
            "has_source_url": params.get("hasSourceURL") is True,
            "is_module": params.get("isModule") is True,
            "length": self._bounded_integer(params.get("length")),
            "language": params.get("scriptLanguage")
            if params.get("scriptLanguage") in {"JavaScript", "WebAssembly"}
            else "JavaScript",
        }

    def _parse_pause(self, params: dict[str, Any]) -> dict[str, Any]:
        raw_frames = params.get("callFrames")
        frames = []
        if isinstance(raw_frames, list):
            frames = [
                frame
                for value in raw_frames[:MAX_CALL_FRAMES]
                if (frame := self._parse_call_frame(value)) is not None
            ]
        reason = (
            params.get("reason") if isinstance(params.get("reason"), str) else "other"
        )
        reason = self._truncate_text(reason, 256)
        description = None
        data = params.get("data")
        if isinstance(data, dict):
            raw_description = data.get("description") or data.get("message")
            if isinstance(raw_description, str):
                description = self._truncate_text(raw_description)
        async_stack = self._parse_async_stack(params.get("asyncStackTrace"))
        hit_breakpoints = params.get("hitBreakpoints", [])
        if not isinstance(hit_breakpoints, list):
            hit_breakpoints = []
        bounded_hit_breakpoints = []
        for value in hit_breakpoints:
            if (
                isinstance(value, str)
                and len(value.encode("utf-8")) <= MAX_BREAKPOINT_TEXT_BYTES
            ):
                bounded_hit_breakpoints.append(value)
                if len(bounded_hit_breakpoints) >= MAX_BREAKPOINTS:
                    break
        return {
            "reason": reason,
            "description": description,
            "call_frames": frames,
            "async_stack": async_stack,
            "hit_breakpoints": bounded_hit_breakpoints,
            "scope_coverage": {
                "status": "loading",
                "properties": 0,
                "limit": MAX_TOTAL_SCOPE_PROPERTIES,
            },
        }

    def _parse_call_frame(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict):
            return None
        frame_id = value.get("callFrameId")
        function_name = value.get("functionName")
        url = value.get("url")
        location = self._parse_location(value.get("location"))
        if (
            not isinstance(frame_id, str)
            or not isinstance(function_name, str)
            or not isinstance(url, str)
            or len(frame_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or location is None
        ):
            return None
        scopes = []
        raw_scopes = value.get("scopeChain")
        if isinstance(raw_scopes, list):
            for raw_scope in raw_scopes[:MAX_SCOPES_PER_FRAME]:
                if not isinstance(raw_scope, dict):
                    continue
                scope_type = raw_scope.get("type")
                remote_object = raw_scope.get("object")
                if not isinstance(scope_type, str) or not isinstance(
                    remote_object, dict
                ):
                    continue
                parsed_object = self._remote_object(remote_object)
                if parsed_object is None:
                    continue
                scopes.append(
                    {
                        "type": self._truncate_text(scope_type, 256),
                        "name": self._truncate_text(raw_scope.get("name"))
                        if isinstance(raw_scope.get("name"), str)
                        else "",
                        "object": parsed_object,
                        "location": self._parse_location(
                            raw_scope.get("startLocation")
                        ),
                        "properties": [],
                    }
                )
        return {
            "id": frame_id,
            "function_name": self._truncate_text(function_name) or "(anonymous)",
            "url": self._truncate_text(url, MAX_TARGET_URL_BYTES),
            "location": location,
            "function_location": self._parse_location(value.get("functionLocation")),
            "this": self._remote_object(value.get("this")),
            "return_value": self._remote_object(value.get("returnValue")),
            "scopes": scopes,
        }

    def _parse_async_stack(self, value: Any) -> list[dict[str, Any]]:
        stacks = []
        depth = 0
        while isinstance(value, dict) and depth < MAX_ASYNC_STACK_DEPTH:
            description = (
                value.get("description")
                if isinstance(value.get("description"), str)
                else "Async"
            )
            description = self._truncate_text(description)
            raw_frames = value.get("callFrames")
            frames = []
            if isinstance(raw_frames, list):
                for raw_frame in raw_frames[:MAX_CALL_FRAMES]:
                    if not isinstance(raw_frame, dict):
                        continue
                    function_name = raw_frame.get("functionName")
                    url = raw_frame.get("url")
                    script_id = raw_frame.get("scriptId")
                    line = raw_frame.get("lineNumber")
                    column = raw_frame.get("columnNumber")
                    if (
                        all(
                            isinstance(item, str)
                            for item in (function_name, url, script_id)
                        )
                        and all(
                            isinstance(item, int) and not isinstance(item, bool)
                            for item in (line, column)
                        )
                        and (
                            len(script_id.encode("utf-8")) <= MAX_TARGET_ID_BYTES
                            and 0 <= line < 2**31
                            and 0 <= column < 2**31
                        )
                    ):
                        frames.append(
                            {
                                "function_name": self._truncate_text(function_name)
                                or "(anonymous)",
                                "url": self._truncate_text(url, MAX_TARGET_URL_BYTES),
                                "location": {
                                    "script_id": script_id,
                                    "line": line,
                                    "column": column,
                                },
                            }
                        )
            stacks.append({"description": description, "call_frames": frames})
            value = value.get("parent")
            depth += 1
        return stacks

    def _parse_location(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict):
            return None
        script_id = value.get("scriptId")
        line = value.get("lineNumber")
        column = value.get("columnNumber", 0)
        if (
            not isinstance(script_id, str)
            or len(script_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
            or not all(
                isinstance(item, int) and not isinstance(item, bool)
                for item in (line, column)
            )
        ):
            return None
        if line < 0 or line >= 2**31 or column < 0 or column >= 2**31:
            return None
        return {"script_id": script_id, "line": line, "column": column}

    def _enrich_pause_async(self, pause_serial: int) -> None:
        thread = threading.Thread(
            target=self._enrich_pause,
            args=(pause_serial,),
            name="reb-debugger-scopes",
            daemon=True,
        )
        thread.start()

    def _enrich_pause(self, pause_serial: int) -> None:
        with self._lock:
            paused = self._paused
            if paused is None or pause_serial != self._pause_serial:
                return
            enriched = copy.deepcopy(paused)
            frames = enriched["call_frames"]
        total_properties = 0
        partial = False
        for frame in frames:
            for scope in frame["scopes"]:
                object_id = scope["object"].get("object_id")
                if not object_id or total_properties >= MAX_TOTAL_SCOPE_PROPERTIES:
                    partial = partial or total_properties >= MAX_TOTAL_SCOPE_PROPERTIES
                    continue
                try:
                    result = self._command(
                        "Runtime.getProperties",
                        {
                            "objectId": object_id,
                            "ownProperties": True,
                            "accessorPropertiesOnly": False,
                            "generatePreview": True,
                        },
                    )
                except DebuggerBridgeError:
                    partial = True
                    continue
                properties = result.get("result")
                if not isinstance(properties, list):
                    partial = True
                    continue
                remaining = MAX_TOTAL_SCOPE_PROPERTIES - total_properties
                selected = properties[: min(MAX_SCOPE_PROPERTIES, remaining)]
                scope["properties"] = [
                    property_value
                    for value in selected
                    if (property_value := self._parse_property(value)) is not None
                ]
                total_properties += len(scope["properties"])
                partial = partial or len(properties) > len(selected)
        with self._lock:
            watch_frame_id = self._watch_frame_id
        self._evaluate_watches(watch_frame_id)
        with self._lock:
            if self._paused is not paused or pause_serial != self._pause_serial:
                return
            enriched["scope_coverage"] = {
                "status": "partial" if partial else "complete",
                "properties": total_properties,
                "limit": MAX_TOTAL_SCOPE_PROPERTIES,
            }
            self._paused = enriched
            self._changed()

    def _evaluate_watches(self, frame_id: Optional[str]) -> None:
        if frame_id is None:
            return
        with self._lock:
            watches = [dict(watch) for watch in self._watches]
        for watch in watches:
            try:
                result = self._command(
                    "Debugger.evaluateOnCallFrame",
                    {
                        "callFrameId": frame_id,
                        "expression": watch["expression"],
                        "silent": True,
                        "returnByValue": False,
                        "generatePreview": True,
                        "throwOnSideEffect": True,
                        "timeout": 500,
                    },
                )
                exception = result.get("exceptionDetails")
                if isinstance(exception, dict):
                    watch["result"] = None
                    watch["error"] = str(exception.get("text", "Evaluation failed"))[
                        :4_096
                    ]
                else:
                    watch["result"] = self._remote_object(result.get("result"))
                    watch["error"] = None
            except DebuggerBridgeError as exception:
                watch["result"] = None
                watch["error"] = str(exception)[:4_096]
        with self._lock:
            current_by_id = {watch["id"]: watch for watch in self._watches}
            for watch in watches:
                current = current_by_id.get(watch["id"])
                if current is not None:
                    current["result"] = watch["result"]
                    current["error"] = watch["error"]
            self._changed()

    def _evaluate_watches_async(self, frame_id: str) -> None:
        thread = threading.Thread(
            target=self._evaluate_watches,
            args=(frame_id,),
            name="reb-debugger-watches",
            daemon=True,
        )
        thread.start()

    def _parse_property(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            return None
        return {
            "name": self._truncate_text(value["name"]),
            "value": self._remote_object(value.get("value")),
            "get": self._remote_object(value.get("get")),
            "set": self._remote_object(value.get("set")),
            "writable": value.get("writable") is True,
            "enumerable": value.get("enumerable") is True,
            "configurable": value.get("configurable") is True,
        }

    def _remote_object(self, value: Any) -> Optional[dict[str, Any]]:
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            return None
        value_type = value["type"]
        if len(value_type.encode("utf-8")) > 256:
            return None
        object_id = value.get("objectId")
        if (
            not isinstance(object_id, str)
            or len(object_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            object_id = None
        result = {
            "type": value_type,
            "subtype": self._truncate_text(value.get("subtype"), 256)
            if isinstance(value.get("subtype"), str)
            else None,
            "class_name": self._truncate_text(value.get("className"))
            if isinstance(value.get("className"), str)
            else None,
            "description": self._truncate_text(value.get("description"))
            if isinstance(value.get("description"), str)
            else None,
            "object_id": object_id,
            "unserializable_value": self._truncate_text(
                value.get("unserializableValue")
            )
            if isinstance(value.get("unserializableValue"), str)
            else None,
            "value": None,
            "value_truncated": False,
        }
        primitive = value.get("value")
        if isinstance(primitive, str):
            result["value_truncated"] = (
                len(primitive.encode("utf-8")) > MAX_REMOTE_TEXT_BYTES
            )
            result["value"] = self._truncate_text(primitive)
        elif primitive is None or isinstance(primitive, bool):
            result["value"] = primitive
        elif self._is_finite_protocol_number(primitive):
            result["value"] = primitive
        preview = value.get("preview")
        if isinstance(preview, dict):
            result["preview"] = {
                "description": self._truncate_text(preview.get("description"))
                if isinstance(preview.get("description"), str)
                else None,
                "overflow": preview.get("overflow") is True,
            }
        return result

    def _append_console(
        self, entry_type: Any, timestamp: Any, raw_arguments: Any, stack_trace: Any
    ) -> None:
        if not isinstance(entry_type, str):
            entry_type = "log"
        arguments = []
        if isinstance(raw_arguments, list):
            arguments = [
                argument
                for value in raw_arguments[:MAX_CONSOLE_ARGUMENTS]
                if (argument := self._remote_object(value)) is not None
            ]
        frames = []
        if isinstance(stack_trace, dict) and isinstance(
            stack_trace.get("callFrames"), list
        ):
            for raw_frame in stack_trace["callFrames"][:MAX_CALL_FRAMES]:
                if not isinstance(raw_frame, dict):
                    continue
                function_name = raw_frame.get("functionName")
                url = raw_frame.get("url")
                line = raw_frame.get("lineNumber")
                column = raw_frame.get("columnNumber")
                if (
                    isinstance(function_name, str)
                    and isinstance(url, str)
                    and all(
                        isinstance(item, int) and not isinstance(item, bool)
                        for item in (line, column)
                    )
                    and 0 <= line < 2**31
                    and 0 <= column < 2**31
                ):
                    frames.append(
                        {
                            "function_name": self._truncate_text(function_name)
                            or "(anonymous)",
                            "url": self._truncate_text(url, MAX_TARGET_URL_BYTES),
                            "line": line,
                            "column": column,
                        }
                    )
        with self._lock:
            entry = {
                "id": str(self._next_console_id),
                "type": entry_type[:64],
                "timestamp": timestamp
                if self._is_finite_protocol_number(timestamp)
                else None,
                "arguments": arguments,
                "stack": frames,
            }
            self._next_console_id += 1
            self._console.append(entry)
            if len(self._console) > MAX_CONSOLE_ENTRIES:
                self._console = self._console[-MAX_CONSOLE_ENTRIES:]
            self._changed()

    def _fail_pending(self, error: BaseException) -> None:
        with self._lock:
            pending_commands = list(self._pending.values())
            self._pending.clear()
        for pending in pending_commands:
            pending.error = error
            pending.event.set()

    def _set_state(self, state: str, error: Optional[str]) -> None:
        with self._lock:
            if self._state == state and self._error == error:
                return
            self._state = state
            self._error = error[:4_096] if error else None
            self._changed()

    def _changed(self) -> None:
        self._generation += 1
        self._condition.notify_all()

    @staticmethod
    def _bounded_integer(value: Any) -> int:
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 2**53
        ):
            return value
        return 0

    @staticmethod
    def _is_finite_protocol_number(value: Any) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return abs(value) <= 2**53
        return isinstance(value, float) and math.isfinite(value)

    @staticmethod
    def _truncate_text(value: str, max_bytes: int = MAX_REMOTE_TEXT_BYTES) -> str:
        encoded = value.encode("utf-8")
        if len(encoded) <= max_bytes:
            return value
        return encoded[:max_bytes].decode("utf-8", errors="ignore")

    @staticmethod
    def _required_text(
        request: dict[str, Any], field: str, max_bytes: int, allow_empty: bool = False
    ) -> str:
        value = request.get(field)
        if (
            not isinstance(value, str)
            or (not allow_empty and not value)
            or len(value.encode("utf-8")) > max_bytes
        ):
            raise DebuggerBridgeError(f"Debugger {field.replace('_', ' ')} is invalid")
        return value
