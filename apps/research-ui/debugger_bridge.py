from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import os
import re
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse
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
MAX_LIVE_OBJECT_SEARCH_PROPERTIES = 256
LIVE_OBJECT_SEARCH_TIMEOUT_MS = 750
MAX_HEAP_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_HEAP_SNAPSHOT_CHUNK_BYTES = 8 * 1024 * 1024
MAX_HEAP_SNAPSHOT_RESULTS = 50
MAX_HEAP_RETAINING_PATH = 12
MAX_HEAP_INCOMING_REFERENCES = 12
HEAP_SNAPSHOT_CAPTURE_TIMEOUT_SECONDS = 60.0
HEAP_SNAPSHOT_SEARCH_TIMEOUT_SECONDS = 20.0
HEAP_SNAPSHOT_DIFF_TIMEOUT_SECONDS = 60.0
HEAP_SNAPSHOT_PROBE_TIMEOUT_SECONDS = 20.0
MAX_MEMORY_ORIGIN_TRACE_STEPS = 32
MAX_MEMORY_ORIGIN_TRACE_BEFORE_STEPS = 8
MAX_MEMORY_ORIGIN_TRACE_AFTER_STEPS = 16
MEMORY_ORIGIN_TRACE_IDLE_TIMEOUT_SECONDS = 2.5
MEMORY_ORIGIN_TRACE_TIMEOUT_SECONDS = 5 * 60.0
MAX_ACTIVE_PORT_BYTES = 4_096
MAX_TARGET_LIST_BYTES = 2 * 1024 * 1024
MAX_TARGET_ID_BYTES = 4_096
MAX_TARGET_TYPE_BYTES = 128
MAX_TARGET_URL_BYTES = 64 * 1024
MAX_REMOTE_TEXT_BYTES = 4_096
MAX_INTERCEPTION_URL_BYTES = 8 * 1024
MAX_INTERCEPTION_PATTERN_BYTES = 2 * 1024
MAX_INTERCEPTION_METHOD_BYTES = 32
MAX_INTERCEPTION_HEADERS = 64
MAX_INTERCEPTION_HEADER_NAME_BYTES = 128
MAX_INTERCEPTION_HEADER_VALUE_BYTES = 2 * 1024
MAX_INTERCEPTION_HEADER_BYTES = 16 * 1024
MAX_INTERCEPTION_BODY_BYTES = 64 * 1024
MAX_INTERCEPTION_RESPONSE_BYTES = 64 * 1024
MAX_INTERCEPTION_AUDIT_ENTRIES = 128
MAX_INTERCEPTION_PENDING_REQUESTS = 16
INTERCEPTION_RUN_TIMEOUT_SECONDS = 15.0
MAX_REPEATER_HISTORY_ENTRIES = 24
MAX_REPEATER_HISTORY_BYTES = 512 * 1024
MAX_REPEATER_VARIABLES = 32
MAX_REPEATER_VARIABLE_NAME_BYTES = 64
MAX_REPEATER_VARIABLE_VALUE_BYTES = 4 * 1024
MAX_REPEATER_VARIABLE_BYTES = 32 * 1024
MAX_REPEATER_TEMPLATE_METHOD_BYTES = 256
MIN_REPEATER_TIMEOUT_MS = 100
MAX_REPEATER_TIMEOUT_MS = 30_000
MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES = 128
MAX_OBJECT_EXPERIMENT_MUTATIONS = 256
MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES = 256
MAX_OBJECT_EXPERIMENT_VALUE_BYTES = 16 * 1024
MAX_OBJECT_EXPERIMENT_VALUE_DEPTH = 8
MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES = 256
MAX_OBJECT_EXPERIMENT_STRING_BYTES = 4 * 1024
OBJECT_EXPERIMENT_NAVIGATION_TIMEOUT_SECONDS = 15.0

REPEATER_VARIABLE_TOKEN = re.compile(r"\{\{(=)?([^{}]+)\}\}")
REPEATER_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")

SENSITIVE_INTERCEPTION_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
}

FORBIDDEN_OBJECT_EXPERIMENT_PROPERTIES = {
    "__proto__",
    "constructor",
    "prototype",
}

MEMORY_ORIGIN_TRACE_FRAMEWORK_PATTERNS = (
    "/node_modules/",
    "react",
    "react-dom",
    "redux",
    "vue",
    "angular",
    "jquery",
    "lodash",
    "rxjs",
    "core-js",
    "regenerator-runtime",
    "polyfill",
    "webpack",
    "vite",
    "rollup",
    "parcel",
    "zone.js",
)


# V8's side-effect checker rejects this inspector's local arrays and counters.
# Safety instead comes from fixed source that reads own descriptors, never values
# behind accessors, and returns only bounded by-value metadata.
LIVE_OBJECT_SEARCH_FUNCTION = r"""function(criteria) {
  const started = Date.now();
  const deadline = started + criteria.timeoutMs;
  let propertyLimitReached = false;
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
      if (tokens.length >= 256 || depth > 3) {
        propertyLimitReached = true;
        return;
      }
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
      let names;
      try { names = Object.getOwnPropertyNames(value); } catch { return; }
      if (names.length > 96) propertyLimitReached = true;
      names = names.slice(0, 96).sort();
      if (names.length === 0) tokens.push(`${path}:empty`);
      for (const name of names) {
        if (tokens.length >= 256) break;
        let descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(value, name); } catch { continue; }
        if (name.length > 160) propertyLimitReached = true;
        const boundedName = name.slice(0, 160);
        const childPath = path ? `${path}.${boundedName}` : boundedName;
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
  const preview = (candidate, names) => names.slice(0, criteria.previewProperties).map(name => {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch {}
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
    let names;
    try {
      candidate = this[index];
      if ((typeof candidate !== "object" && typeof candidate !== "function") || candidate === null) continue;
      names = Object.getOwnPropertyNames(candidate);
    } catch { continue; }
    analyzed += 1;
    if (names.length > criteria.propertyScanLimit) propertyLimitReached = true;
    const inspectedNames = names.slice(0, criteria.propertyScanLimit);
    const candidateClass = className(candidate);
    if (propertyMatches && !inspectedNames.some(name => {
      if (name.length > 512) propertyLimitReached = true;
      return propertyMatches(name.slice(0, 512));
    })) continue;
    if (classMatches && !classMatches(candidateClass)) continue;
    if (valueMatches && !inspectedNames.some(name => {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch { return false; }
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
      preview: preview(candidate, inspectedNames)
    });
    if (results.length >= criteria.resultLimit) break;
  }
  return {
    protocolVersion: 2,
    analyzed,
    totalObjects,
    results,
    resultLimit: criteria.resultLimit,
    resultLimitReached: results.length >= criteria.resultLimit,
    scanLimitReached: totalObjects > scanLimit || visited < scanLimit,
    propertyLimitReached,
    timedOut,
    durationMs: Math.max(0, Date.now() - started)
  };
}"""

OBJECT_EXPERIMENT_MUTATE_FUNCTION = r"""function(config) {
  const boundedText = value => {
    let text;
    try { text = String(value); } catch { return "<unavailable>"; }
    return text.length > 160 ? `${text.slice(0, 160)}...` : text;
  };
  const valueType = value => value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
  const className = value => {
    if (Array.isArray(value)) return "Array";
    try {
      const prototype = Object.getPrototypeOf(value);
      const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, "constructor");
      const name = descriptor && "value" in descriptor && descriptor.value && descriptor.value.name;
      return typeof name === "string" && name ? name.slice(0, 160) : "Object";
    } catch { return "Object"; }
  };
  const descriptorSummary = descriptor => {
    if (!descriptor) return {exists: false, type: "missing", className: "", writable: false, configurable: false};
    if (!("value" in descriptor)) {
      return {exists: true, type: "accessor", className: "", writable: false, configurable: descriptor.configurable === true};
    }
    const value = descriptor.value;
    const type = valueType(value);
    return {
      exists: true,
      type,
      className: (type === "object" || type === "array" || type === "function") && value !== null ? className(value) : "",
      writable: descriptor.writable === true,
      configurable: descriptor.configurable === true,
      preview: (type === "object" || type === "array" || type === "function") && value !== null
        ? `[${className(value)}]`
        : boundedText(value)
    };
  };
  const inspect = candidate => {
    let names;
    try { names = Object.getOwnPropertyNames(candidate).sort(); }
    catch { names = []; }
    const preview = [];
    for (const name of names.slice(0, config.previewProperties)) {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch {}
      if (!descriptor || !("value" in descriptor)) {
        preview.push({name: name.slice(0, 256), type: "accessor", value: "<getter not invoked>"});
        continue;
      }
      const value = descriptor.value;
      const type = value === null ? "null" : typeof value;
      preview.push({
        name: name.slice(0, 256),
        type,
        value: ((typeof value === "object" && value !== null) || typeof value === "function")
          ? `[${className(value)}]`
          : boundedText(value)
      });
    }
    return {
      id: config.resultId,
      className: className(candidate),
      propertyCount: names.length,
      propertiesTruncated: names.length > config.previewProperties,
      similarity: config.similarity,
      preview
    };
  };

  try {
    const beforeDescriptor = Object.getOwnPropertyDescriptor(this, config.property);
    const before = descriptorSummary(beforeDescriptor);
    let outcome;
    if (beforeDescriptor && !("value" in beforeDescriptor)) {
      return {protocolVersion: 1, ok: false, error: "Accessor properties cannot be patched", outcome: "accessor", before, after: before, object: inspect(this)};
    }
    if (config.operation === "delete") {
      if (!beforeDescriptor) {
        return {protocolVersion: 1, ok: false, error: "The selected own property does not exist", outcome: "missing", before, after: before, object: inspect(this)};
      }
      if (!beforeDescriptor.configurable) {
        return {protocolVersion: 1, ok: false, error: "The selected own property is not configurable", outcome: "non_configurable", before, after: before, object: inspect(this)};
      }
      if (!Reflect.deleteProperty(this, config.property)) {
        return {protocolVersion: 1, ok: false, error: "The selected own property could not be deleted", outcome: "rejected", before, after: before, object: inspect(this)};
      }
      outcome = "deleted";
    } else {
      if (beforeDescriptor && !beforeDescriptor.writable) {
        return {protocolVersion: 1, ok: false, error: "The selected own property is not writable", outcome: "non_writable", before, after: before, object: inspect(this)};
      }
      if (!beforeDescriptor && !Object.isExtensible(this)) {
        return {protocolVersion: 1, ok: false, error: "The selected object is not extensible", outcome: "non_extensible", before, after: before, object: inspect(this)};
      }
      const descriptor = beforeDescriptor
        ? {...beforeDescriptor, value: config.value}
        : {value: config.value, writable: true, enumerable: true, configurable: true};
      Object.defineProperty(this, config.property, descriptor);
      outcome = beforeDescriptor ? "updated" : "created";
    }
    const after = descriptorSummary(Object.getOwnPropertyDescriptor(this, config.property));
    return {protocolVersion: 1, ok: true, error: null, outcome, before, after, object: inspect(this)};
  } catch (error) {
    return {
      protocolVersion: 1,
      ok: false,
      error: boundedText(error && error.message ? error.message : error),
      outcome: "error",
      before: {exists: false, type: "unknown", className: "", writable: false, configurable: false},
      after: {exists: false, type: "unknown", className: "", writable: false, configurable: false},
      object: null
    };
  }
}"""

REQUEST_INTERCEPTION_FUNCTION = r"""async function(config) {
  const started = performance.now();
  const registry = config.controllerRegistryKey
    ? globalThis[config.controllerRegistryKey]
    : null;
  const controller = registry instanceof Map
    ? registry.get(config.executionId)
    : new AbortController();
  if (!(controller instanceof AbortController)) {
    return {
      protocolVersion: 1,
      ok: false,
      error: "Request controller is unavailable",
      durationMs: 0,
      cancelled: false,
      timedOut: false
    };
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, config.timeoutMs);
  try {
    const options = {
      method: config.method,
      headers: config.headers,
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    };
    if (config.body !== "") options.body = config.body;
    const response = await fetch(config.url, options);
    const decoder = new TextDecoder();
    const bodyParts = [];
    let bodyBytes = 0;
    let bodyTruncated = false;
    if (response.body) {
      const reader = response.body.getReader();
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        const remaining = Math.max(0, config.responseByteLimit - bodyBytes);
        if (value.byteLength > remaining) {
          if (remaining > 0) {
            bodyParts.push(decoder.decode(value.subarray(0, remaining), {stream: true}));
            bodyBytes += remaining;
          }
          bodyTruncated = true;
          try { await reader.cancel(); } catch {}
          break;
        }
        bodyParts.push(decoder.decode(value, {stream: true}));
        bodyBytes += value.byteLength;
        if (bodyBytes === config.responseByteLimit) {
          const next = await reader.read();
          if (!next.done) {
            bodyTruncated = true;
            try { await reader.cancel(); } catch {}
          }
          break;
        }
      }
      bodyParts.push(decoder.decode());
    }
    const headers = [];
    const headerEncoder = new TextEncoder();
    let headerBytes = 0;
    let headersTruncated = false;
    for (const [name, value] of response.headers.entries()) {
      if (["set-cookie", "set-cookie2"].includes(name.toLowerCase())) continue;
      if (headers.length >= config.headerLimit) {
        headersTruncated = true;
        break;
      }
      const encodedValue = headerEncoder.encode(value);
      const boundedValue = encodedValue.byteLength <= config.headerValueLimit
        ? value
        : new TextDecoder().decode(encodedValue.subarray(0, config.headerValueLimit));
      const entryBytes = headerEncoder.encode(name).byteLength + headerEncoder.encode(boundedValue).byteLength;
      if (headerBytes + entryBytes > config.headerTotalLimit) {
        headersTruncated = true;
        break;
      }
      headerBytes += entryBytes;
      headers.push({name, value: boundedValue});
      if (encodedValue.byteLength > config.headerValueLimit) headersTruncated = true;
    }
    return {
      protocolVersion: 1,
      ok: true,
      status: response.status,
      statusText: response.statusText.slice(0, 256),
      url: response.url,
      headers,
      headersTruncated,
      body: bodyParts.join(""),
      bodyTruncated,
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      cancelled: false,
      timedOut: false
    };
  } catch (error) {
    let message = "Request failed";
    try { message = String(error && error.message ? error.message : error); } catch {}
    const cancelled = controller.signal.aborted && !timedOut;
    return {
      protocolVersion: 1,
      ok: false,
      error: (timedOut ? "Request timed out" : cancelled ? "Request cancelled" : message).slice(0, 512),
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      cancelled,
      timedOut
    };
  } finally {
    clearTimeout(timer);
    if (registry instanceof Map) {
      registry.delete(config.executionId);
      if (registry.size === 0) {
        try { delete globalThis[config.controllerRegistryKey]; } catch {}
      }
    }
  }
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


@dataclass
class HeapSnapshotCollector:
    path: Path
    stream: Any
    byte_count: int = 0
    chunk_count: int = 0
    error: Optional[str] = None

    def append(self, chunk: Any) -> None:
        if self.error is not None:
            return
        if not isinstance(chunk, str):
            self.error = "Debugger returned a malformed heap snapshot chunk"
            return
        encoded = chunk.encode("utf-8")
        if len(encoded) > MAX_HEAP_SNAPSHOT_CHUNK_BYTES:
            self.error = "Debugger returned an oversized heap snapshot chunk"
            return
        if self.byte_count + len(encoded) > MAX_HEAP_SNAPSHOT_BYTES:
            self.error = "Heap snapshot exceeds the 256 MiB capture limit"
            return
        try:
            self.stream.write(encoded)
        except OSError:
            self.error = "Heap snapshot could not be written to local temporary storage"
            return
        self.byte_count += len(encoded)
        self.chunk_count += 1

    def close(self) -> None:
        try:
            self.stream.close()
        except OSError:
            if self.error is None:
                self.error = "Heap snapshot temporary storage could not be closed"


@dataclass(frozen=True)
class HeapSnapshotCapture:
    path: Path
    target_id: str
    byte_count: int
    captured_at_ms: int


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
    def __init__(
        self,
        active_port_path: Optional[Path] = None,
        heap_snapshot_binary: Optional[Path] = None,
    ) -> None:
        self.active_port_path = active_port_path
        self.heap_snapshot_binary = heap_snapshot_binary or (
            Path(__file__).resolve().parents[2] / "build" / "reb-heap-snapshot"
        )
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
        self._heap_snapshot_collector: Optional[HeapSnapshotCollector] = None
        self._heap_diff_baseline: Optional[HeapSnapshotCapture] = None
        self._heap_diff_busy = False
        self._next_memory_origin_trace_id = 1
        self._memory_origin_trace = self._empty_memory_origin_trace()
        self._memory_origin_trace_started = 0.0
        self._memory_origin_trace_processing = False
        self._memory_origin_trace_stop_requested = False
        self._memory_origin_trace_added_click_breakpoint = False
        self._memory_origin_trace_timer: Optional[threading.Timer] = None
        self._next_request_interception_id = 1
        self._next_request_interception_audit_id = 1
        self._request_interception = self._empty_request_interception()
        self._request_interception_rule = self._default_request_interception_rule()
        self._request_interception_context_id: Optional[str] = None
        self._request_interception_return_target_id: Optional[str] = None
        self._request_interception_pending: set[str] = set()
        self._next_object_experiment_navigation_id = 1
        self._next_object_experiment_search_id = 1
        self._next_object_experiment_audit_id = 1
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment_group: Optional[str] = None
        self._object_experiment_objects_id: Optional[str] = None
        self._object_experiment_result_indices: set[int] = set()
        self._next_repeater_execution_id = 1
        self._repeater = self._empty_repeater()
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id: Optional[int] = None
        self._repeater_cancel_requested = False
        self._repeater_controller_key = (
            f"__reb_repeater_controllers_{os.urandom(16).hex()}"
        )

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
            self._cancel_memory_origin_trace_timer_locked()
            self._condition.notify_all()
        if connection is not None:
            connection.close()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._fail_pending(DebuggerBridgeError("Debugger bridge stopped"))
        self._clear_heap_diff_baseline(force=True)
        self._dispose_request_interception_context(preserve_result=False, force=True)

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
                "heap_diff_baseline": self._heap_diff_baseline_metadata(),
                "memory_origin_trace": copy.deepcopy(self._memory_origin_trace),
                "request_interception": copy.deepcopy(self._request_interception),
                "object_experiment": copy.deepcopy(self._object_experiment),
                "repeater": copy.deepcopy(self._repeater),
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
        with self._lock:
            origin_trace_active = self._memory_origin_trace_active_locked()
            request_interception_running = (
                self._request_interception["state"] == "running"
            )
            repeater_running = self._repeater_active_execution_id is not None
            object_experiment_running = self._object_experiment["state"] in {
                "navigating",
                "searching",
                "mutating",
            }
        if origin_trace_active and action != "stop_memory_origin_trace":
            raise DebuggerBridgeError(
                "Memory Origin Trace controls the debugger until it finishes or is stopped"
            )
        if request_interception_running:
            raise DebuggerBridgeError(
                "The isolated experiment controls the debugger until its request finishes"
            )
        if repeater_running and action != "cancel_repeater_request":
            raise DebuggerBridgeError(
                "Repeater controls the isolated debugger target until its request finishes or is cancelled"
            )
        if object_experiment_running:
            raise DebuggerBridgeError(
                "Object Lab controls the isolated debugger target until its action finishes"
            )
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
                if self._heap_diff_busy:
                    raise DebuggerBridgeError("Heap snapshot comparison is running")
                self._preferred_target_id = target_id
                connection = self._connection
            self._clear_heap_diff_baseline()
            if connection is not None:
                connection.close()
        elif action == "search_live_objects":
            return self._search_live_objects(request)
        elif action == "search_heap_snapshot":
            return self._search_heap_snapshot(request)
        elif action == "start_memory_origin_trace":
            return self._start_memory_origin_trace(request)
        elif action == "stop_memory_origin_trace":
            return self._stop_memory_origin_trace()
        elif action == "clear_memory_origin_trace":
            with self._lock:
                self._memory_origin_trace = self._empty_memory_origin_trace()
                self._changed()
        elif action == "create_request_interception_experiment":
            return self._create_request_interception_experiment()
        elif action == "navigate_object_experiment":
            return self._navigate_object_experiment(request)
        elif action == "search_object_experiment":
            return self._search_object_experiment(request)
        elif action == "mutate_object_experiment":
            return self._mutate_object_experiment(request)
        elif action == "configure_request_interception":
            return self._configure_request_interception(request)
        elif action == "run_request_interception":
            return self._run_request_interception(request)
        elif action == "dispose_request_interception_experiment":
            return self._dispose_request_interception_experiment()
        elif action == "clear_request_interception_result":
            return self._clear_request_interception_result()
        elif action == "configure_repeater_variables":
            return self._configure_repeater_variables(request)
        elif action == "run_repeater_request":
            return self._run_repeater_request(request)
        elif action == "cancel_repeater_request":
            return self._cancel_repeater_request()
        elif action == "compare_repeater_history":
            return self._compare_repeater_history(request)
        elif action == "clear_repeater_history":
            return self._clear_repeater_history()
        elif action == "capture_heap_diff_baseline":
            return self._capture_heap_diff_baseline()
        elif action == "compare_heap_diff":
            return self._compare_heap_diff()
        elif action == "clear_heap_diff_baseline":
            self._clear_heap_diff_baseline()
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
        criteria = self._live_object_search_criteria(request)
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
            objects_id = self._runtime_result_object_id(
                objects, "object collection", field="objects"
            )
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

    def _live_object_search_criteria(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
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

        return {
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
            "propertyScanLimit": MAX_LIVE_OBJECT_SEARCH_PROPERTIES,
            "timeoutMs": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
        }

    def _optional_search_text(self, request: dict[str, Any], field: str) -> str:
        value = request.get(field, "")
        if not isinstance(value, str):
            raise DebuggerBridgeError("Live object search criteria must be text")
        if len(value.encode("utf-8")) > MAX_LIVE_OBJECT_QUERY_BYTES:
            raise DebuggerBridgeError("Live object search criterion exceeds 512 bytes")
        return value

    @staticmethod
    def _runtime_result_object_id(
        result: dict[str, Any], label: str, *, field: str = "result"
    ) -> str:
        remote = result.get(field)
        object_id = remote.get("objectId") if isinstance(remote, dict) else None
        if not isinstance(object_id, str) or not object_id:
            raise ProtocolError(f"Debugger returned a malformed {label}")
        return object_id

    def _normalize_live_object_search(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocolVersion") != 2:
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
            "propertyLimitReached",
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
                "protocol_version": 2,
                "analyzed": value["analyzed"],
                "total_objects": value["totalObjects"],
                "result_limit": value["resultLimit"],
                "result_limit_reached": value["resultLimitReached"],
                "scan_limit_reached": value["scanLimitReached"],
                "property_limit_reached": value["propertyLimitReached"],
                "timed_out": value["timedOut"],
                "duration_ms": value["durationMs"],
                "results": results,
            },
            "generation": self.generation(),
        }

    def _clear_object_experiment_search_locked(self) -> Optional[str]:
        group = self._object_experiment_group
        releasable_group = (
            group
            if group is not None
            and self._connection is not None
            and self._target is not None
            and self._target["id"] == self._object_experiment.get("target_id")
            else None
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()
        self._object_experiment["search_id"] = 0
        self._object_experiment["search"] = None
        self._object_experiment["results"] = []
        self._object_experiment["last_mutation"] = None
        return releasable_group

    def _release_object_experiment_group(self, group: Optional[str]) -> None:
        if group is not None:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass

    def _release_object_experiment_search(self) -> None:
        with self._lock:
            group = self._clear_object_experiment_search_locked()
        self._release_object_experiment_group(group)

    def _require_object_experiment_target_locked(
        self, require_navigation: bool
    ) -> None:
        if self._object_experiment["state"] in {
            "navigating",
            "searching",
            "mutating",
        }:
            raise DebuggerBridgeError(
                "Object Lab is already running an isolated-page action"
            )
        if (
            self._request_interception_context_id is None
            or not self._object_experiment["isolated"]
            or self._object_experiment["target_id"] is None
            or self._target is None
            or self._target["id"] != self._object_experiment["target_id"]
            or self._state not in {"running", "paused"}
        ):
            raise DebuggerBridgeError(
                "Object Lab requires its attached disposable Experiment page"
            )
        if self._request_interception_pending:
            raise DebuggerBridgeError(
                "Wait for paused Experiment requests before using Object Lab"
            )
        if require_navigation and (
            self._object_experiment["navigation_id"] <= 0
            or not self._object_experiment["url"]
        ):
            raise DebuggerBridgeError(
                "Open an HTTP or HTTPS page in Object Lab before searching"
            )

    def _navigate_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        url = self._required_text(
            request, "url", MAX_INTERCEPTION_URL_BYTES
        ).strip()
        self._validate_request_interception_url(url)
        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=False)
            stale_group = self._clear_object_experiment_search_locked()
            navigation_id = self._next_object_experiment_navigation_id
            self._next_object_experiment_navigation_id += 1
            self._object_experiment["state"] = "navigating"
            self._object_experiment["navigation_id"] = navigation_id
            self._object_experiment["url"] = self._redacted_request_url(url)
            self._object_experiment["message"] = (
                "Opening one credential-free page inside the disposable context."
            )
            self._changed()
        self._release_object_experiment_group(stale_group)

        try:
            navigation = self._command(
                "Page.navigate", {"url": url}, timeout=5.0
            )
            error_text = navigation.get("errorText")
            if isinstance(error_text, str) and error_text:
                raise DebuggerBridgeError(
                    self._truncate_text(f"Object Lab navigation failed: {error_text}", 512)
                )
            deadline = time.monotonic() + OBJECT_EXPERIMENT_NAVIGATION_TIMEOUT_SECONDS
            loaded_url = url
            while True:
                if time.monotonic() >= deadline:
                    raise DebuggerBridgeError(
                        "Object Lab page did not become interactive within 15 seconds"
                    )
                try:
                    evaluated = self._command(
                        "Runtime.evaluate",
                        {
                            "expression": (
                                "({protocolVersion:1,readyState:document.readyState,"
                                "url:location.href})"
                            ),
                            "returnByValue": True,
                            "silent": True,
                            "throwOnSideEffect": True,
                        },
                        timeout=2.0,
                    )
                    if isinstance(evaluated.get("exceptionDetails"), dict):
                        raise DebuggerBridgeError("Navigation is still replacing the page")
                    remote = evaluated.get("result")
                    status = remote.get("value") if isinstance(remote, dict) else None
                    if (
                        isinstance(status, dict)
                        and status.get("protocolVersion") == 1
                        and status.get("readyState") in {"interactive", "complete"}
                        and isinstance(status.get("url"), str)
                    ):
                        loaded_url = status["url"]
                        break
                except DebuggerBridgeError:
                    pass
                time.sleep(0.05)
            final_url = urlunparse(urlparse(loaded_url)._replace(fragment=""))
            self._validate_request_interception_url(final_url)
        except DebuggerBridgeError as exception:
            with self._lock:
                if self._object_experiment["navigation_id"] == navigation_id:
                    self._object_experiment["state"] = "error"
                    self._object_experiment["message"] = self._truncate_text(
                        str(exception), 512
                    )
                    self._changed()
            raise

        with self._lock:
            if self._object_experiment["navigation_id"] != navigation_id:
                raise DebuggerBridgeError("Object Lab navigation became stale")
            self._object_experiment["state"] = "loaded"
            self._object_experiment["url"] = self._redacted_request_url(loaded_url)
            self._object_experiment["message"] = (
                "Isolated page loaded. Run a bounded live-object search."
            )
            self._changed()
            experiment = copy.deepcopy(self._object_experiment)
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }

    def _search_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        criteria = self._live_object_search_criteria(request)
        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=True)
            stale_group = self._clear_object_experiment_search_locked()
            search_id = self._next_object_experiment_search_id
            self._next_object_experiment_search_id += 1
            session_id = self._object_experiment["session_id"]
            navigation_id = self._object_experiment["navigation_id"]
            target_id = self._object_experiment["target_id"]
            group = f"reb-object-experiment-{session_id}-{navigation_id}-{search_id}"
            self._object_experiment["state"] = "searching"
            self._object_experiment["message"] = (
                "Searching the isolated page without invoking property getters."
            )
            self._changed()
        self._release_object_experiment_group(stale_group)

        prototype_id: Optional[str] = None
        objects_id: Optional[str] = None
        try:
            prototype = self._command(
                "Runtime.evaluate",
                {
                    "expression": "Object.prototype",
                    "objectGroup": group,
                    "silent": True,
                },
            )
            prototype_id = self._runtime_result_object_id(prototype, "prototype")
            objects = self._command(
                "Runtime.queryObjects",
                {"prototypeObjectId": prototype_id, "objectGroup": group},
                timeout=5.0,
            )
            objects_id = self._runtime_result_object_id(
                objects, "object collection", field="objects"
            )
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
                    "timeout": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                },
                timeout=3.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Live object search failed in Object Lab")
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            normalized = self._normalize_live_object_search(document)["search"]
            indices: set[int] = set()
            for result in normalized["results"]:
                if not result["id"].isdigit():
                    raise ProtocolError("Object Lab returned an invalid result identifier")
                index = int(result["id"])
                if index >= normalized["total_objects"] or index in indices:
                    raise ProtocolError("Object Lab returned a stale result identifier")
                indices.add(index)
        except DebuggerBridgeError as exception:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass
            with self._lock:
                if (
                    self._object_experiment["session_id"] == session_id
                    and self._object_experiment["navigation_id"] == navigation_id
                ):
                    self._object_experiment["state"] = "error"
                    self._object_experiment["message"] = self._truncate_text(
                        str(exception), 512
                    )
                    self._changed()
            raise
        finally:
            if prototype_id is not None:
                try:
                    self._command("Runtime.releaseObject", {"objectId": prototype_id})
                except DebuggerBridgeError:
                    pass

        stale = False
        with self._lock:
            stale = (
                self._object_experiment["session_id"] != session_id
                or self._object_experiment["navigation_id"] != navigation_id
                or self._object_experiment["target_id"] != target_id
            )
            if not stale:
                self._object_experiment_group = group
                self._object_experiment_objects_id = objects_id
                self._object_experiment_result_indices = indices
                self._object_experiment["state"] = "loaded"
                self._object_experiment["search_id"] = search_id
                self._object_experiment["search"] = {
                    key: value for key, value in normalized.items() if key != "results"
                }
                self._object_experiment["results"] = normalized["results"]
                self._object_experiment["message"] = (
                    f"Found {len(normalized['results'])} matching live objects in the isolated page."
                )
                self._changed()
                experiment = copy.deepcopy(self._object_experiment)
        if stale:
            try:
                self._command("Runtime.releaseObjectGroup", {"objectGroup": group})
            except DebuggerBridgeError:
                pass
            raise DebuggerBridgeError("Object Lab search became stale")
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }

    def _mutate_object_experiment(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        operation = request.get("operation")
        if operation not in {"set", "delete"}:
            raise DebuggerBridgeError("Object Lab mutation operation is invalid")
        if request.get("confirmed") is not True:
            raise DebuggerBridgeError("Object Lab mutation requires explicit confirmation")
        search_id = request.get("search_id")
        if (
            not isinstance(search_id, int)
            or isinstance(search_id, bool)
            or search_id <= 0
            or search_id > 2**53 - 1
        ):
            raise DebuggerBridgeError("Object Lab search identifier is invalid")
        result_id = self._required_text(request, "result_id", 128)
        if not result_id.isdigit():
            raise DebuggerBridgeError("Object Lab result identifier is invalid")
        result_index = int(result_id)
        property_name = self._required_text(
            request, "property", MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES
        )
        if (
            property_name in FORBIDDEN_OBJECT_EXPERIMENT_PROPERTIES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in property_name)
        ):
            raise DebuggerBridgeError("Object Lab property name is not allowed")

        value: Any = None
        value_bytes = 0
        value_digest: Optional[str] = None
        if operation == "set":
            if "value" not in request:
                raise DebuggerBridgeError("Object Lab set requires a JSON value")
            value, canonical = self._normalize_object_experiment_value(request["value"])
            value_bytes = len(canonical)
            value_digest = hashlib.sha256(canonical).hexdigest()
        elif "value" in request:
            raise DebuggerBridgeError("Object Lab delete does not accept a value")

        with self._lock:
            self._require_object_experiment_target_locked(require_navigation=True)
            if (
                self._object_experiment["search_id"] != search_id
                or self._object_experiment_objects_id is None
                or self._object_experiment_group is None
                or result_index not in self._object_experiment_result_indices
            ):
                raise DebuggerBridgeError(
                    "Object Lab result is stale; run the live-object search again"
                )
            if (
                self._object_experiment["mutation_attempts"]
                >= MAX_OBJECT_EXPERIMENT_MUTATIONS
            ):
                raise DebuggerBridgeError(
                    "Object Lab reached the 256-attempt session limit"
                )
            selected = next(
                (
                    result
                    for result in self._object_experiment["results"]
                    if result["id"] == result_id
                ),
                None,
            )
            if selected is None:
                raise DebuggerBridgeError("Object Lab result is unavailable")
            objects_id = self._object_experiment_objects_id
            group = self._object_experiment_group
            session_id = self._object_experiment["session_id"]
            navigation_id = self._object_experiment["navigation_id"]
            target_class = selected["class_name"]
            similarity = selected["similarity"]
            self._object_experiment["mutation_attempts"] += 1
            self._object_experiment["state"] = "mutating"
            self._object_experiment["message"] = (
                f"Applying one confirmed {operation} operation inside Object Lab."
            )
            self._changed()

        candidate_id: Optional[str] = None
        try:
            candidate = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": objects_id,
                    "functionDeclaration": (
                        "function(index){const value=this[index];"
                        "if((typeof value!==\"object\"&&typeof value!==\"function\")||value===null)"
                        "throw new TypeError(\"Object Lab result is unavailable\");return value;}"
                    ),
                    "arguments": [{"value": result_index}],
                    "returnByValue": False,
                    "objectGroup": group,
                    "silent": True,
                },
            )
            if isinstance(candidate.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Object Lab result is no longer available")
            candidate_id = self._runtime_result_object_id(candidate, "object result")
            config: dict[str, Any] = {
                "operation": operation,
                "property": property_name,
                "previewProperties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
                "resultId": result_id,
                "similarity": similarity,
            }
            if operation == "set":
                config["value"] = value
            evaluated = self._command(
                "Runtime.callFunctionOn",
                {
                    "objectId": candidate_id,
                    "functionDeclaration": OBJECT_EXPERIMENT_MUTATE_FUNCTION,
                    "arguments": [{"value": config}],
                    "returnByValue": True,
                    "silent": True,
                    "awaitPromise": False,
                    "userGesture": False,
                    "timeout": 1_000,
                },
                timeout=3.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError("Object Lab mutation failed in the target")
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            mutation = self._normalize_object_experiment_mutation(document)
        except DebuggerBridgeError as exception:
            mutation = {
                "ok": False,
                "outcome": "error",
                "error": self._truncate_text(str(exception), 512),
                "before": self._empty_object_experiment_descriptor("unknown"),
                "after": self._empty_object_experiment_descriptor("unknown"),
                "object": None,
            }
        finally:
            if candidate_id is not None:
                try:
                    self._command("Runtime.releaseObject", {"objectId": candidate_id})
                except DebuggerBridgeError:
                    pass

        with self._lock:
            if (
                self._object_experiment["session_id"] != session_id
                or self._object_experiment["navigation_id"] != navigation_id
            ):
                raise DebuggerBridgeError("Object Lab mutation became stale")
            search_invalidated = self._object_experiment["search_id"] != search_id
            audit = self._append_object_experiment_audit_locked(
                operation=operation,
                property_name=property_name,
                result_id=result_id,
                search_id=search_id,
                target_class=target_class,
                mutation=mutation,
                value_bytes=value_bytes,
                value_digest=value_digest,
            )
            if mutation["object"] is not None and not search_invalidated:
                self._object_experiment["results"] = [
                    mutation["object"] if result["id"] == result_id else result
                    for result in self._object_experiment["results"]
                ]
            if not search_invalidated:
                self._object_experiment["state"] = "loaded"
            self._object_experiment["last_mutation"] = {
                "audit_id": audit["id"],
                "ok": mutation["ok"],
                "operation": operation,
                "property": property_name,
                "result_id": result_id,
                "outcome": mutation["outcome"],
                "error": mutation["error"],
                "before": mutation["before"],
                "after": mutation["after"],
                "value_bytes": value_bytes,
                "value_digest": value_digest,
            }
            self._object_experiment["message"] = (
                f"Object Lab {operation} completed and audit entry {audit['id']} was recorded."
                if mutation["ok"]
                else f"Object Lab rejected the mutation: {mutation['error']}"
            )
            if search_invalidated:
                self._object_experiment["message"] += (
                    " The target disconnected, so run the search again."
                )
            self._changed()
            experiment = copy.deepcopy(self._object_experiment)
        return {
            "ok": True,
            "object_experiment": experiment,
            "generation": self.generation(),
        }

    def _normalize_object_experiment_value(
        self, value: Any
    ) -> tuple[Any, bytes]:
        entries = 0

        def validate(candidate: Any, depth: int) -> None:
            nonlocal entries
            if depth > MAX_OBJECT_EXPERIMENT_VALUE_DEPTH:
                raise DebuggerBridgeError("Object Lab JSON value exceeds depth 8")
            if candidate is None or isinstance(candidate, bool):
                return
            if isinstance(candidate, int):
                if abs(candidate) > 2**53 - 1:
                    raise DebuggerBridgeError(
                        "Object Lab integer exceeds JavaScript's exact range"
                    )
                return
            if isinstance(candidate, float):
                if not math.isfinite(candidate):
                    raise DebuggerBridgeError("Object Lab number must be finite")
                return
            if isinstance(candidate, str):
                if len(candidate.encode("utf-8")) > MAX_OBJECT_EXPERIMENT_STRING_BYTES:
                    raise DebuggerBridgeError("Object Lab JSON string exceeds 4 KiB")
                return
            if isinstance(candidate, list):
                entries += len(candidate)
                if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                    raise DebuggerBridgeError("Object Lab JSON value exceeds 256 entries")
                for item in candidate:
                    validate(item, depth + 1)
                return
            if isinstance(candidate, dict):
                entries += len(candidate)
                if entries > MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES:
                    raise DebuggerBridgeError("Object Lab JSON value exceeds 256 entries")
                for key, item in candidate.items():
                    if (
                        not isinstance(key, str)
                        or len(key.encode("utf-8"))
                        > MAX_OBJECT_EXPERIMENT_STRING_BYTES
                    ):
                        raise DebuggerBridgeError(
                            "Object Lab JSON object key exceeds 4 KiB"
                        )
                    validate(item, depth + 1)
                return
            raise DebuggerBridgeError("Object Lab set value must be JSON data")

        validate(value, 0)
        try:
            canonical = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as exception:
            raise DebuggerBridgeError("Object Lab set value must be valid JSON") from exception
        if len(canonical) > MAX_OBJECT_EXPERIMENT_VALUE_BYTES:
            raise DebuggerBridgeError("Object Lab JSON value exceeds 16 KiB")
        return value, canonical

    @staticmethod
    def _empty_object_experiment_descriptor(value_type: str) -> dict[str, Any]:
        return {
            "exists": False,
            "type": value_type,
            "class_name": "",
            "writable": False,
            "configurable": False,
            "preview": None,
        }

    def _normalize_object_experiment_descriptor(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ProtocolError("Object Lab returned a malformed property descriptor")
        exists = value.get("exists")
        value_type = value.get("type")
        class_name = value.get("className", "")
        writable = value.get("writable")
        configurable = value.get("configurable")
        preview = value.get("preview")
        if (
            not isinstance(exists, bool)
            or not isinstance(value_type, str)
            or not value_type
            or len(value_type.encode("utf-8")) > 128
            or not isinstance(class_name, str)
            or len(class_name.encode("utf-8")) > 256
            or not isinstance(writable, bool)
            or not isinstance(configurable, bool)
            or (preview is not None and not isinstance(preview, str))
        ):
            raise ProtocolError("Object Lab returned an invalid property descriptor")
        return {
            "exists": exists,
            "type": value_type,
            "class_name": class_name,
            "writable": writable,
            "configurable": configurable,
            "preview": self._truncate_text(preview, 512)
            if isinstance(preview, str)
            else None,
        }

    def _normalize_object_experiment_mutation(self, value: Any) -> dict[str, Any]:
        outcomes = {
            "created",
            "updated",
            "deleted",
            "missing",
            "non_configurable",
            "rejected",
            "accessor",
            "non_writable",
            "non_extensible",
            "error",
        }
        if (
            not isinstance(value, dict)
            or value.get("protocolVersion") != 1
            or not isinstance(value.get("ok"), bool)
            or value.get("outcome") not in outcomes
        ):
            raise ProtocolError("Object Lab returned a malformed mutation result")
        error = value.get("error")
        if error is not None and (
            not isinstance(error, str) or len(error.encode("utf-8")) > 512
        ):
            raise ProtocolError("Object Lab returned an invalid mutation error")
        if value["ok"] != (error is None):
            raise ProtocolError("Object Lab returned an inconsistent mutation result")
        before = self._normalize_object_experiment_descriptor(value.get("before"))
        after = self._normalize_object_experiment_descriptor(value.get("after"))
        raw_object = value.get("object")
        normalized_object = None
        if raw_object is not None:
            synthetic = {
                "protocolVersion": 2,
                "analyzed": 1,
                "totalObjects": 1,
                "resultLimit": MAX_LIVE_OBJECT_RESULTS,
                "resultLimitReached": False,
                "scanLimitReached": False,
                "propertyLimitReached": False,
                "timedOut": False,
                "durationMs": 0,
                "results": [raw_object],
            }
            normalized_object = self._normalize_live_object_search(synthetic)["search"][
                "results"
            ][0]
        if value["ok"] and normalized_object is None:
            raise ProtocolError("Object Lab omitted the patched object preview")
        return {
            "ok": value["ok"],
            "outcome": value["outcome"],
            "error": error,
            "before": before,
            "after": after,
            "object": normalized_object,
        }

    def _append_object_experiment_audit_locked(
        self,
        *,
        operation: str,
        property_name: str,
        result_id: str,
        search_id: int,
        target_class: str,
        mutation: dict[str, Any],
        value_bytes: int,
        value_digest: Optional[str],
    ) -> dict[str, Any]:
        entry = {
            "id": self._next_object_experiment_audit_id,
            "occurred_at_ms": int(time.time() * 1_000),
            "session_id": self._object_experiment["session_id"],
            "navigation_id": self._object_experiment["navigation_id"],
            "search_id": search_id,
            "result_id": result_id,
            "operation": operation,
            "property": property_name,
            "target_class": self._truncate_text(target_class, 256),
            "outcome": mutation["outcome"],
            "success": mutation["ok"],
            "before_type": mutation["before"]["type"],
            "after_type": mutation["after"]["type"],
            "value_bytes": value_bytes,
            "value_digest": value_digest,
            "url": self._object_experiment["url"],
        }
        self._next_object_experiment_audit_id += 1
        audit = self._object_experiment["audit"]
        audit.append(entry)
        if len(audit) > MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES:
            del audit[: len(audit) - MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES]
            self._object_experiment["audit_evictions"] += 1
        return entry

    def _search_heap_snapshot(self, request: dict[str, Any]) -> dict[str, Any]:
        query = self._optional_search_text(request, "query").strip()
        case_sensitive = request.get("case_sensitive", False)
        scope = request.get("scope", "all")
        if not query:
            raise DebuggerBridgeError("Heap snapshot search requires a value")
        if not isinstance(case_sensitive, bool):
            raise DebuggerBridgeError("Heap snapshot search options must be boolean")
        if not isinstance(scope, str) or scope not in {
            "all",
            "reachable",
            "unreachable",
        }:
            raise DebuggerBridgeError("Heap snapshot reference scope is invalid")
        binary = self._heap_snapshot_binary()

        capture = self._capture_heap_snapshot()
        try:
            command = [
                str(binary),
                "--snapshot",
                str(capture.path),
                "--query",
                query,
                "--scope",
                scope,
                "--limit",
                str(MAX_HEAP_SNAPSHOT_RESULTS),
            ]
            if case_sensitive:
                command.append("--case-sensitive")
            document = self._run_native_heap_snapshot(
                command,
                HEAP_SNAPSHOT_SEARCH_TIMEOUT_SECONDS,
                "search",
            )
            return self._normalize_heap_snapshot_search(document)
        finally:
            capture.path.unlink(missing_ok=True)

    @staticmethod
    def _empty_memory_origin_trace() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "trace_id": 0,
            "state": "idle",
            "target_id": None,
            "query": "",
            "scope": "all",
            "case_sensitive": False,
            "before_steps": 0,
            "after_steps": 0,
            "step_limit": MAX_MEMORY_ORIGIN_TRACE_STEPS,
            "step_count": 0,
            "first_match_step": None,
            "started_at_ms": 0,
            "elapsed_ms": 0,
            "partial": False,
            "limit_reason": None,
            "message": "Enter a value and arm a trace.",
            "steps": [],
        }

    def _memory_origin_trace_active_locked(self) -> bool:
        return self._memory_origin_trace["state"] in {
            "armed",
            "capturing",
            "stepping",
            "stopping",
        }

    def _cancel_memory_origin_trace_timer_locked(self) -> None:
        timer = self._memory_origin_trace_timer
        self._memory_origin_trace_timer = None
        if timer is not None:
            timer.cancel()

    def _start_memory_origin_trace(self, request: dict[str, Any]) -> dict[str, Any]:
        query = self._optional_search_text(request, "query").strip()
        scope = request.get("scope", "all")
        case_sensitive = request.get("case_sensitive", False)
        before_steps = request.get("before_steps", 3)
        after_steps = request.get("after_steps", 8)
        if not query:
            raise DebuggerBridgeError("Memory Origin Trace requires a value")
        if not isinstance(scope, str) or scope not in {
            "all",
            "reachable",
            "unreachable",
        }:
            raise DebuggerBridgeError("Memory Origin Trace reference scope is invalid")
        if not isinstance(case_sensitive, bool):
            raise DebuggerBridgeError("Memory Origin Trace options must be boolean")
        if (
            not isinstance(before_steps, int)
            or isinstance(before_steps, bool)
            or before_steps < 0
            or before_steps > MAX_MEMORY_ORIGIN_TRACE_BEFORE_STEPS
            or not isinstance(after_steps, int)
            or isinstance(after_steps, bool)
            or after_steps < 0
            or after_steps > MAX_MEMORY_ORIGIN_TRACE_AFTER_STEPS
        ):
            raise DebuggerBridgeError("Memory Origin Trace tolerance window is invalid")
        self._heap_snapshot_binary()

        with self._lock:
            if self._state != "running" or self._target is None:
                raise DebuggerBridgeError(
                    "Memory Origin Trace requires a running debugger target"
                )
            if self._heap_diff_busy or self._heap_snapshot_collector is not None:
                raise DebuggerBridgeError("A heap snapshot operation is already running")
            trace_id = self._next_memory_origin_trace_id
            self._next_memory_origin_trace_id += 1
            target_id = self._target["id"]
            self._memory_origin_trace_started = time.monotonic()
            self._memory_origin_trace_processing = False
            self._memory_origin_trace_stop_requested = False
            self._memory_origin_trace_added_click_breakpoint = (
                not any(
                    event_name in {"click", "listener:click"}
                    for event_name in self._event_breakpoints
                )
            )
            self._memory_origin_trace = {
                "protocol_version": 1,
                "trace_id": trace_id,
                "state": "armed",
                "target_id": target_id,
                "query": query,
                "scope": scope,
                "case_sensitive": case_sensitive,
                "before_steps": before_steps,
                "after_steps": after_steps,
                "step_limit": MAX_MEMORY_ORIGIN_TRACE_STEPS,
                "step_count": 0,
                "first_match_step": None,
                "started_at_ms": int(time.time() * 1_000),
                "elapsed_ms": 0,
                "partial": False,
                "limit_reason": None,
                "message": "Trace armed. Click the page action that creates the value.",
                "steps": [],
            }
            self._changed()
            add_click_breakpoint = self._memory_origin_trace_added_click_breakpoint
        try:
            if add_click_breakpoint:
                self._command(
                    "DOMDebugger.setEventListenerBreakpoint",
                    {"eventName": "click", "targetName": "*"},
                )
        except BaseException as exception:
            self._complete_memory_origin_trace(
                trace_id,
                "error",
                self._truncate_text(str(exception), 512),
                resume=False,
            )
            raise
        with self._lock:
            trace = copy.deepcopy(self._memory_origin_trace)
        return {"ok": True, "trace": trace, "generation": self.generation()}

    def _stop_memory_origin_trace(self) -> dict[str, Any]:
        with self._lock:
            if not self._memory_origin_trace_active_locked():
                raise DebuggerBridgeError("Memory Origin Trace is not running")
            trace_id = self._memory_origin_trace["trace_id"]
            self._memory_origin_trace_stop_requested = True
            self._cancel_memory_origin_trace_timer_locked()
            if self._memory_origin_trace_processing:
                self._memory_origin_trace["state"] = "stopping"
                self._memory_origin_trace["message"] = (
                    "Stopping after the current bounded snapshot finishes."
                )
                self._changed()
                return {"ok": True, "generation": self._generation}
        self._complete_memory_origin_trace(trace_id, "aborted", "Trace stopped.")
        return {"ok": True, "generation": self.generation()}

    def _start_memory_origin_trace_pause_async(
        self, pause_serial: int, paused: dict[str, Any]
    ) -> None:
        with self._lock:
            if (
                not self._memory_origin_trace_active_locked()
                or self._memory_origin_trace["state"] == "stopping"
                or self._memory_origin_trace_processing
            ):
                return
            self._cancel_memory_origin_trace_timer_locked()
            self._memory_origin_trace_processing = True
            self._memory_origin_trace["state"] = "capturing"
            self._memory_origin_trace["message"] = (
                "Capturing and probing the bounded heap at this debugger pause."
            )
            trace_id = self._memory_origin_trace["trace_id"]
            self._changed()
        thread = threading.Thread(
            target=self._process_memory_origin_trace_pause,
            args=(trace_id, pause_serial, paused),
            name="reb-memory-origin-trace",
            daemon=True,
        )
        thread.start()

    def _process_memory_origin_trace_pause(
        self, trace_id: int, pause_serial: int, paused: dict[str, Any]
    ) -> None:
        capture: Optional[HeapSnapshotCapture] = None
        try:
            with self._lock:
                trace = dict(self._memory_origin_trace)
            capture = self._capture_heap_snapshot()
            if capture.target_id != trace["target_id"]:
                raise DebuggerBridgeError(
                    "Debugger target changed during Memory Origin Trace"
                )
            command = [
                str(self._heap_snapshot_binary()),
                "--snapshot",
                str(capture.path),
                "--query",
                trace["query"],
                "--scope",
                trace["scope"],
                "--probe",
            ]
            if trace["case_sensitive"]:
                command.append("--case-sensitive")
            document = self._run_native_heap_snapshot(
                command,
                HEAP_SNAPSHOT_PROBE_TIMEOUT_SECONDS,
                "probe",
            )
            probe = self._normalize_heap_snapshot_probe(document)
            if probe["scope"] != trace["scope"]:
                raise ProtocolError(
                    "Native heap snapshot probe returned an unexpected scope"
                )
        except BaseException as exception:
            with self._lock:
                stopped = self._memory_origin_trace_stop_requested
            self._complete_memory_origin_trace(
                trace_id,
                "aborted" if stopped else "error",
                "Trace stopped."
                if stopped
                else self._truncate_text(str(exception), 512),
            )
            return
        finally:
            if capture is not None:
                capture.path.unlink(missing_ok=True)

        location = self._memory_origin_trace_location(paused)
        finish: Optional[tuple[str, str, bool, Optional[str]]] = None
        should_step = False
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or not self._memory_origin_trace_active_locked()
            ):
                return
            self._memory_origin_trace_processing = False
            if self._memory_origin_trace_stop_requested:
                finish = ("aborted", "Trace stopped.", False, None)
            elif pause_serial != self._pause_serial or self._state != "paused":
                finish = (
                    "error",
                    "Debugger pause changed before the heap probe completed.",
                    False,
                    None,
                )
            else:
                trace = self._memory_origin_trace
                trace["step_count"] += 1
                step_number = trace["step_count"]
                coverage_partial = any(
                    probe[field]
                    for field in (
                        "node_limit_reached",
                        "edge_limit_reached",
                        "string_limit_reached",
                    )
                )
                if coverage_partial:
                    trace["partial"] = True
                    trace["limit_reason"] = "snapshot_coverage"
                step = {
                    "id": f"origin-{trace_id}-{step_number}",
                    "step": step_number,
                    "captured_at_ms": int(time.time() * 1_000),
                    "capture_bytes": capture.byte_count,
                    "duration_ms": probe["duration_ms"],
                    "analyzed_nodes": probe["analyzed_nodes"],
                    "total_nodes": probe["total_nodes"],
                    "indexed_edges": probe["indexed_edges"],
                    "total_edges": probe["total_edges"],
                    "matched": probe["match_found"],
                    "coverage_partial": coverage_partial,
                    "is_first_match": False,
                    "location": location,
                    "match": probe["match"],
                }
                if probe["match_found"] and trace["first_match_step"] is None:
                    trace["first_match_step"] = step_number
                    step["is_first_match"] = True
                trace["steps"].append(step)
                if trace["first_match_step"] is None:
                    while len(trace["steps"]) > trace["before_steps"]:
                        trace["steps"].pop(0)
                elapsed = max(
                    0,
                    int((time.monotonic() - self._memory_origin_trace_started) * 1_000),
                )
                trace["elapsed_ms"] = elapsed
                after_captured = (
                    step_number - trace["first_match_step"]
                    if trace["first_match_step"] is not None
                    else 0
                )
                if (
                    trace["first_match_step"] is not None
                    and after_captured >= trace["after_steps"]
                ):
                    finish = (
                        "found",
                        f"First appearance found at debugger step {trace['first_match_step']}.",
                        trace["partial"],
                        trace["limit_reason"],
                    )
                elif step_number >= trace["step_limit"]:
                    finish = (
                        "found" if trace["first_match_step"] is not None else "not_found",
                        "Trace reached its 32-step limit.",
                        True,
                        "step_limit",
                    )
                elif elapsed >= int(MEMORY_ORIGIN_TRACE_TIMEOUT_SECONDS * 1_000):
                    finish = (
                        "found" if trace["first_match_step"] is not None else "not_found",
                        "Trace reached its five-minute limit.",
                        True,
                        "time_limit",
                    )
                else:
                    trace["state"] = "stepping"
                    trace["message"] = (
                        "First appearance found; collecting the requested after-window."
                        if trace["first_match_step"] is not None
                        else "Value not present yet; stepping out to the next function boundary."
                    )
                    should_step = True
                    self._changed()

        if finish is not None:
            self._complete_memory_origin_trace(trace_id, *finish)
            return
        if should_step:
            try:
                self._command("Debugger.stepOut")
            except BaseException as exception:
                self._complete_memory_origin_trace(
                    trace_id,
                    "error",
                    self._truncate_text(str(exception), 512),
                    resume=False,
                )
                return
            self._schedule_memory_origin_trace_idle_timeout(trace_id)

    def _schedule_memory_origin_trace_idle_timeout(self, trace_id: int) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or self._memory_origin_trace["state"] != "stepping"
            ):
                return
            self._cancel_memory_origin_trace_timer_locked()
            expected_step = self._memory_origin_trace["step_count"]
            timer = threading.Timer(
                MEMORY_ORIGIN_TRACE_IDLE_TIMEOUT_SECONDS,
                self._memory_origin_trace_idle_timeout,
                args=(trace_id, expected_step),
            )
            timer.daemon = True
            self._memory_origin_trace_timer = timer
        timer.start()

    def _memory_origin_trace_idle_timeout(
        self, trace_id: int, expected_step: int
    ) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or self._memory_origin_trace["state"] != "stepping"
                or self._memory_origin_trace["step_count"] != expected_step
                or self._memory_origin_trace_processing
            ):
                return
            self._memory_origin_trace_timer = None
            found = self._memory_origin_trace["first_match_step"] is not None
            requested_after = self._memory_origin_trace["after_steps"]
            captured_after = (
                expected_step - self._memory_origin_trace["first_match_step"]
                if found
                else 0
            )
            incomplete_after = found and captured_after < requested_after
            first_match_step = self._memory_origin_trace["first_match_step"]
        self._complete_memory_origin_trace(
            trace_id,
            "found" if found else "not_found",
            "Execution returned before another function-boundary pause."
            if incomplete_after
            else "Execution returned before the value appeared."
            if not found
            else f"First appearance found at debugger step {first_match_step}.",
            partial=incomplete_after,
            limit_reason="execution_quiet" if incomplete_after else None,
            resume=False,
        )

    def _complete_memory_origin_trace(
        self,
        trace_id: int,
        state: str,
        message: str,
        partial: bool = False,
        limit_reason: Optional[str] = None,
        resume: bool = True,
    ) -> None:
        with self._lock:
            if (
                self._memory_origin_trace["trace_id"] != trace_id
                or not self._memory_origin_trace_active_locked()
            ):
                return
            if self._memory_origin_trace_stop_requested and state != "aborted":
                state = "aborted"
                message = "Trace stopped."
                limit_reason = None
            self._cancel_memory_origin_trace_timer_locked()
            self._memory_origin_trace_processing = False
            self._memory_origin_trace_stop_requested = False
            self._memory_origin_trace["state"] = state
            self._memory_origin_trace["message"] = self._truncate_text(message, 512)
            self._memory_origin_trace["elapsed_ms"] = max(
                0,
                int((time.monotonic() - self._memory_origin_trace_started) * 1_000),
            )
            self._memory_origin_trace["partial"] = (
                self._memory_origin_trace["partial"] or partial
            )
            if limit_reason is not None:
                self._memory_origin_trace["limit_reason"] = limit_reason
            remove_click_breakpoint = self._memory_origin_trace_added_click_breakpoint
            self._memory_origin_trace_added_click_breakpoint = False
            should_resume = resume and self._state == "paused"
            self._changed()
        if remove_click_breakpoint:
            try:
                self._command(
                    "DOMDebugger.removeEventListenerBreakpoint",
                    {"eventName": "click", "targetName": "*"},
                )
            except DebuggerBridgeError:
                pass
        if should_resume:
            try:
                self._command("Debugger.resume")
            except DebuggerBridgeError:
                pass

    def _memory_origin_trace_location(
        self, paused: dict[str, Any]
    ) -> dict[str, Any]:
        frames = paused.get("call_frames", [])
        selected = frames[0] if frames else None
        filtered = False
        for frame in frames:
            url = frame.get("url", "")
            if not url:
                with self._lock:
                    script = self._scripts.get(frame["location"]["script_id"])
                if script is not None:
                    url = script["url"]
            lower_url = url.lower()
            if (
                lower_url.startswith(("chrome-extension:", "devtools:", "extensions::"))
                or any(
                    pattern in lower_url
                    for pattern in MEMORY_ORIGIN_TRACE_FRAMEWORK_PATTERNS
                )
            ):
                filtered = True
                continue
            selected = frame
            break
        if selected is None:
            return {
                "script_id": "",
                "url": "",
                "function_name": "(unknown)",
                "line": 0,
                "column": 0,
                "framework_filtered": filtered,
            }
        location = selected["location"]
        url = selected.get("url", "")
        if not url:
            with self._lock:
                script = self._scripts.get(location["script_id"])
            if script is not None:
                url = script["url"]
        return {
            "script_id": location["script_id"],
            "url": self._truncate_text(url, MAX_TARGET_URL_BYTES),
            "function_name": self._truncate_text(
                selected.get("function_name", "(anonymous)"), 512
            ),
            "line": location["line"],
            "column": location["column"],
            "framework_filtered": filtered,
        }

    @staticmethod
    def _default_request_interception_rule() -> dict[str, Any]:
        return {
            "mode": "continue",
            "url_pattern": "*",
            "method_filter": "",
            "rewrite_url": "",
            "rewrite_method": "",
            "rewrite_headers": [],
            "rewrite_body": "",
            "response_code": 200,
            "response_headers": [],
            "response_body": "",
        }

    @classmethod
    def _public_request_interception_rule(cls, rule: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": rule["mode"],
            "url_pattern": rule["url_pattern"],
            "method_filter": rule["method_filter"],
            "rewrite_url": cls._redacted_request_url(rule["rewrite_url"])
            if rule["rewrite_url"]
            else "",
            "rewrite_method": rule["rewrite_method"],
            "rewrite_header_count": len(rule["rewrite_headers"]),
            "rewrite_body_bytes": len(rule["rewrite_body"].encode("utf-8")),
            "response_code": rule["response_code"],
            "response_header_count": len(rule["response_headers"]),
            "response_body_bytes": len(rule["response_body"].encode("utf-8")),
        }

    @classmethod
    def _empty_request_interception(cls) -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "experiment_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "created_at_ms": 0,
            "disposed_at_ms": 0,
            "rule": cls._public_request_interception_rule(
                cls._default_request_interception_rule()
            ),
            "last_request": None,
            "result": None,
            "audit": [],
            "audit_evictions": 0,
            "pending_requests": 0,
            "message": "Create an isolated experiment to intercept a request.",
            "limits": {
                "audit_entries": MAX_INTERCEPTION_AUDIT_ENTRIES,
                "pending_requests": MAX_INTERCEPTION_PENDING_REQUESTS,
                "headers": MAX_INTERCEPTION_HEADERS,
                "body_bytes": MAX_INTERCEPTION_BODY_BYTES,
                "response_bytes": MAX_INTERCEPTION_RESPONSE_BYTES,
            },
        }

    @staticmethod
    def _empty_object_experiment() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "isolated": False,
            "target_id": None,
            "url": "",
            "navigation_id": 0,
            "search_id": 0,
            "search": None,
            "results": [],
            "last_mutation": None,
            "audit": [],
            "audit_evictions": 0,
            "mutation_attempts": 0,
            "message": "Create an isolated Experiment context to use Object Lab.",
            "limits": {
                "search_results": MAX_LIVE_OBJECT_RESULTS,
                "search_candidates": MAX_LIVE_OBJECT_SCAN,
                "search_timeout_ms": LIVE_OBJECT_SEARCH_TIMEOUT_MS,
                "preview_properties": MAX_LIVE_OBJECT_PREVIEW_PROPERTIES,
                "mutation_attempts": MAX_OBJECT_EXPERIMENT_MUTATIONS,
                "audit_entries": MAX_OBJECT_EXPERIMENT_AUDIT_ENTRIES,
                "property_bytes": MAX_OBJECT_EXPERIMENT_PROPERTY_BYTES,
                "value_bytes": MAX_OBJECT_EXPERIMENT_VALUE_BYTES,
                "value_depth": MAX_OBJECT_EXPERIMENT_VALUE_DEPTH,
                "value_entries": MAX_OBJECT_EXPERIMENT_VALUE_ENTRIES,
                "value_string_bytes": MAX_OBJECT_EXPERIMENT_STRING_BYTES,
            },
        }

    @staticmethod
    def _empty_repeater() -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "session_id": 0,
            "state": "idle",
            "variables": [],
            "history": [],
            "history_bytes": 0,
            "history_evictions": 0,
            "active_execution": None,
            "comparison": None,
            "message": "Create an isolated request-lab context to use Repeater.",
            "limits": {
                "history_entries": MAX_REPEATER_HISTORY_ENTRIES,
                "history_bytes": MAX_REPEATER_HISTORY_BYTES,
                "variables": MAX_REPEATER_VARIABLES,
                "variable_bytes": MAX_REPEATER_VARIABLE_BYTES,
                "request_bytes": MAX_INTERCEPTION_BODY_BYTES,
                "response_bytes": MAX_INTERCEPTION_RESPONSE_BYTES,
                "timeout_ms": MAX_REPEATER_TIMEOUT_MS,
            },
        }

    def _begin_repeater_session_locked(self, session_id: int) -> None:
        self._repeater = self._empty_repeater()
        self._repeater.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "message": "Waiting for the disposable page debugger to attach.",
            }
        )
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id = None
        self._repeater_cancel_requested = False

    def _begin_object_experiment_session_locked(self, session_id: int) -> None:
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment.update(
            {
                "session_id": session_id,
                "state": "attaching",
                "message": "Waiting for the disposable Object Lab page to attach.",
            }
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()

    def _dispose_object_experiment_locked(self, session_id: int) -> None:
        self._object_experiment = self._empty_object_experiment()
        self._object_experiment.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "message": (
                    "Disposable context deleted. Object references, mutation values, "
                    "previews, and audit records were cleared."
                ),
            }
        )
        self._object_experiment_group = None
        self._object_experiment_objects_id = None
        self._object_experiment_result_indices.clear()

    def _dispose_repeater_locked(self, session_id: int) -> None:
        self._repeater = self._empty_repeater()
        self._repeater.update(
            {
                "session_id": session_id,
                "state": "disposed",
                "message": (
                    "Disposable context deleted. Repeater variables, request bodies, "
                    "responses, and history were cleared."
                ),
            }
        )
        self._repeater_history_bytes = 0
        self._repeater_active_execution_id = None
        self._repeater_cancel_requested = False

    def _repeater_context_ready_locked(self) -> bool:
        return (
            self._request_interception_context_id is not None
            and self._request_interception["target_id"] is not None
            and self._target is not None
            and self._target["id"] == self._request_interception["target_id"]
            and self._request_interception["state"] in {"ready", "error"}
            and self._repeater["state"] in {"ready", "error"}
        )

    @staticmethod
    def _normalize_repeater_variables(value: Any) -> list[dict[str, str]]:
        if not isinstance(value, dict) or len(value) > MAX_REPEATER_VARIABLES:
            raise DebuggerBridgeError("Repeater variables must be a bounded object")
        total_bytes = 0
        variables = []
        for name, variable_value in sorted(value.items()):
            if not isinstance(name, str) or not isinstance(variable_value, str):
                raise DebuggerBridgeError("Repeater variable names and values must be text")
            name_bytes = len(name.encode("utf-8"))
            value_bytes = len(variable_value.encode("utf-8"))
            if (
                not REPEATER_VARIABLE_NAME.fullmatch(name)
                or name_bytes > MAX_REPEATER_VARIABLE_NAME_BYTES
                or value_bytes > MAX_REPEATER_VARIABLE_VALUE_BYTES
            ):
                raise DebuggerBridgeError("Repeater variable is invalid or oversized")
            total_bytes += name_bytes + value_bytes
            if total_bytes > MAX_REPEATER_VARIABLE_BYTES:
                raise DebuggerBridgeError("Repeater variables exceed 32 KiB")
            variables.append({"name": name, "value": variable_value})
        return variables

    @classmethod
    def _resolve_repeater_text(
        cls, value: str, variables: dict[str, str]
    ) -> tuple[str, set[str]]:
        used: set[str] = set()
        missing: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            escaped = match.group(1) == "="
            name = match.group(2)
            if (
                not REPEATER_VARIABLE_NAME.fullmatch(name)
                or len(name.encode("utf-8")) > MAX_REPEATER_VARIABLE_NAME_BYTES
            ):
                raise DebuggerBridgeError("Repeater request contains an invalid variable")
            if escaped:
                return "{{" + name + "}}"
            used.add(name)
            if name not in variables:
                missing.add(name)
                return match.group(0)
            return variables[name]

        resolved = REPEATER_VARIABLE_TOKEN.sub(replace, value)
        if missing:
            names = ", ".join(sorted(missing)[:8])
            raise DebuggerBridgeError(f"Unresolved Repeater variables: {names}")
        return resolved, used

    def _normalize_repeater_template(self, request: dict[str, Any]) -> dict[str, Any]:
        url = self._required_text(request, "url", MAX_INTERCEPTION_URL_BYTES).strip()
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
            raise DebuggerBridgeError("Repeater request URL is invalid")
        method = request.get("method", "GET")
        if (
            not isinstance(method, str)
            or not method.strip()
            or len(method.strip().encode("utf-8")) > MAX_REPEATER_TEMPLATE_METHOD_BYTES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in method)
        ):
            raise DebuggerBridgeError("Repeater request method template is invalid")
        headers = self._normalize_request_interception_headers(
            request.get("headers", {}), "Repeater request"
        )
        body = request.get("body", "")
        if (
            not isinstance(body, str)
            or len(body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
        ):
            raise DebuggerBridgeError("Repeater request body exceeds 64 KiB")
        timeout_ms = request.get("timeout_ms", MAX_REPEATER_TIMEOUT_MS)
        if (
            not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or timeout_ms < MIN_REPEATER_TIMEOUT_MS
            or timeout_ms > MAX_REPEATER_TIMEOUT_MS
        ):
            raise DebuggerBridgeError("Repeater timeout must be between 100 and 30000 ms")
        collection_request_id = request.get("collection_request_id")
        if collection_request_id is not None and (
            not isinstance(collection_request_id, int)
            or isinstance(collection_request_id, bool)
            or collection_request_id <= 0
            or collection_request_id > 2**53 - 1
        ):
            raise DebuggerBridgeError("Repeater collection request ID is invalid")
        return {
            "url": url,
            "method": method.strip(),
            "headers": headers,
            "body": body,
            "timeout_ms": timeout_ms,
            "collection_request_id": collection_request_id,
        }

    def _resolve_repeater_request(
        self, template: dict[str, Any], variables: list[dict[str, str]]
    ) -> tuple[dict[str, Any], list[str]]:
        variable_map = {entry["name"]: entry["value"] for entry in variables}
        url, used = self._resolve_repeater_text(template["url"], variable_map)
        method, method_used = self._resolve_repeater_text(
            template["method"], variable_map
        )
        used.update(method_used)
        body, body_used = self._resolve_repeater_text(template["body"], variable_map)
        used.update(body_used)
        resolved_headers: dict[str, str] = {}
        for header in template["headers"]:
            header_value, header_used = self._resolve_repeater_text(
                header["value"], variable_map
            )
            used.update(header_used)
            resolved_headers[header["name"]] = header_value
        resolved = self._normalize_request_interception_request(
            {
                "url": url,
                "method": method,
                "headers": resolved_headers,
                "body": body,
            }
        )
        resolved["timeout_ms"] = template["timeout_ms"]
        return resolved, sorted(used)

    def _configure_repeater_variables(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        variables = self._normalize_repeater_variables(request.get("variables", {}))
        with self._lock:
            if not self._repeater_context_ready_locked():
                raise DebuggerBridgeError("The isolated Repeater target is not ready")
            self._repeater["variables"] = variables
            self._repeater["state"] = "ready"
            self._repeater["message"] = (
                f"{len(variables)} session-scoped Repeater "
                f"{'variable is' if len(variables) == 1 else 'variables are'} ready."
            )
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _install_repeater_controller(self, execution_id: int) -> None:
        key = json.dumps(self._repeater_controller_key)
        identifier = json.dumps(str(execution_id))
        expression = f"""(() => {{
          const key = {key};
          const id = {identifier};
          let registry = globalThis[key];
          if (!(registry instanceof Map)) {{
            registry = new Map();
            Object.defineProperty(globalThis, key, {{value: registry, configurable: true}});
          }}
          if (registry.size >= 1 || registry.has(id)) return false;
          registry.set(id, new AbortController());
          return true;
        }})()"""
        evaluated = self._command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": False,
                "silent": True,
                "userGesture": False,
            },
            timeout=3.0,
        )
        remote = evaluated.get("result")
        installed = remote.get("value") if isinstance(remote, dict) else None
        if installed is not True:
            raise DebuggerBridgeError("Repeater could not reserve a request controller")

    def _run_repeater_request(self, request: dict[str, Any]) -> dict[str, Any]:
        template = self._normalize_repeater_template(request)
        with self._lock:
            variables = copy.deepcopy(self._repeater["variables"])
        resolved, variable_names = self._resolve_repeater_request(template, variables)
        with self._lock:
            if not self._repeater_context_ready_locked():
                raise DebuggerBridgeError("The isolated Repeater target is not ready")
            if self._repeater_active_execution_id is not None:
                raise DebuggerBridgeError("A Repeater request is already running")
            execution_id = self._next_repeater_execution_id
            self._next_repeater_execution_id += 1
            session_id = self._repeater["session_id"]
            started_at_ms = int(time.time() * 1_000)
            self._repeater_active_execution_id = execution_id
            self._repeater_cancel_requested = False
            self._repeater["state"] = "running"
            self._repeater["active_execution"] = {
                "execution_id": execution_id,
                "started_at_ms": started_at_ms,
                "request": copy.deepcopy(template),
                "resolved_url": self._redacted_request_url(resolved["url"]),
                "resolved_method": resolved["method"],
                "variable_names": variable_names,
                "collection_request_id": template["collection_request_id"],
                "cancel_requested": False,
            }
            self._repeater["message"] = (
                "Sending one credential-free Repeater request through the disposable page."
            )
            self._changed()
        try:
            self._install_repeater_controller(execution_id)
        except BaseException as exception:
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_active_execution_id = None
                    self._repeater["active_execution"] = None
                    self._repeater["state"] = "error"
                    self._repeater["message"] = self._truncate_text(str(exception), 512)
                    self._changed()
            raise

        worker = threading.Thread(
            target=self._execute_repeater_request,
            args=(
                session_id,
                execution_id,
                started_at_ms,
                template,
                resolved,
                variable_names,
            ),
            name="reb-repeater-request",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError as exception:
            try:
                self._abort_repeater_controller(execution_id)
            except DebuggerBridgeError:
                pass
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_active_execution_id = None
                    self._repeater["active_execution"] = None
                    self._repeater["state"] = "error"
                    self._repeater["message"] = self._truncate_text(
                        f"Repeater worker could not start: {exception}", 512
                    )
                    self._changed()
            raise DebuggerBridgeError("Repeater worker could not start") from exception
        with self._lock:
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _execute_repeater_request(
        self,
        session_id: int,
        execution_id: int,
        started_at_ms: int,
        template: dict[str, Any],
        resolved: dict[str, Any],
        variable_names: list[str],
    ) -> None:
        configuration = {
            "url": resolved["url"],
            "method": resolved["method"],
            "headers": {
                header["name"]: header["value"] for header in resolved["headers"]
            },
            "body": resolved["body"],
            "timeoutMs": resolved["timeout_ms"],
            "headerLimit": MAX_INTERCEPTION_HEADERS,
            "headerValueLimit": MAX_INTERCEPTION_HEADER_VALUE_BYTES,
            "headerTotalLimit": MAX_INTERCEPTION_HEADER_BYTES,
            "responseByteLimit": MAX_INTERCEPTION_RESPONSE_BYTES,
            "controllerRegistryKey": self._repeater_controller_key,
            "executionId": str(execution_id),
        }
        expression = (
            f"({REQUEST_INTERCEPTION_FUNCTION})"
            f"({json.dumps(configuration, separators=(',', ':'))})"
        )
        try:
            evaluated = self._command(
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "silent": True,
                    "userGesture": False,
                    "timeout": resolved["timeout_ms"],
                },
                timeout=resolved["timeout_ms"] / 1_000.0 + 2.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError(
                    "The isolated Repeater runner failed before returning a result"
                )
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            result = self._normalize_repeater_result(document)
        except BaseException as exception:
            with self._lock:
                cancelled = (
                    self._repeater_active_execution_id == execution_id
                    and self._repeater_cancel_requested
                )
            duration_ms = max(0, int(time.time() * 1_000) - started_at_ms)
            result = {
                "protocol_version": 1,
                "ok": False,
                "status": 0,
                "status_text": "",
                "url": "",
                "headers": [],
                "headers_truncated": False,
                "body": "",
                "body_truncated": False,
                "error": self._truncate_text(
                    "Request cancelled" if cancelled else str(exception), 512
                ),
                "duration_ms": duration_ms,
                "cancelled": cancelled,
                "timed_out": False,
                "body_sha256": hashlib.sha256(b"").hexdigest(),
            }
        self._complete_repeater_execution(
            session_id,
            execution_id,
            started_at_ms,
            template,
            resolved,
            variable_names,
            result,
        )

    def _normalize_repeater_result(self, value: Any) -> dict[str, Any]:
        result = self._normalize_request_interception_result(value)
        duration_ms = value.get("durationMs") if isinstance(value, dict) else None
        cancelled = value.get("cancelled") if isinstance(value, dict) else None
        timed_out = value.get("timedOut") if isinstance(value, dict) else None
        if (
            not isinstance(duration_ms, int)
            or isinstance(duration_ms, bool)
            or duration_ms < 0
            or duration_ms > MAX_REPEATER_TIMEOUT_MS + 5_000
            or not isinstance(cancelled, bool)
            or not isinstance(timed_out, bool)
            or (cancelled and timed_out)
            or (result["ok"] and (cancelled or timed_out))
        ):
            raise ProtocolError("Debugger returned a malformed Repeater result")
        result.update(
            {
                "duration_ms": duration_ms,
                "cancelled": cancelled,
                "timed_out": timed_out,
                "body_sha256": hashlib.sha256(
                    result["body"].encode("utf-8")
                ).hexdigest(),
            }
        )
        return result

    def _complete_repeater_execution(
        self,
        session_id: int,
        execution_id: int,
        started_at_ms: int,
        template: dict[str, Any],
        resolved: dict[str, Any],
        variable_names: list[str],
        result: dict[str, Any],
    ) -> None:
        with self._lock:
            if (
                self._repeater["session_id"] != session_id
                or self._repeater_active_execution_id != execution_id
            ):
                return
            completed_at_ms = max(
                started_at_ms, int(time.time() * 1_000)
            )
            entry_state = (
                "complete"
                if result["ok"]
                else "cancelled"
                if result["cancelled"]
                else "timed_out"
                if result["timed_out"]
                else "error"
            )
            entry = {
                "id": execution_id,
                "started_at_ms": started_at_ms,
                "completed_at_ms": completed_at_ms,
                "state": entry_state,
                "collection_request_id": template["collection_request_id"],
                "variable_names": variable_names,
                "request": copy.deepcopy(template),
                "resolved_request": {
                    "url": resolved["url"],
                    "method": resolved["method"],
                    "headers": copy.deepcopy(resolved["headers"]),
                    "body": resolved["body"],
                    "timeout_ms": resolved["timeout_ms"],
                },
                "response": copy.deepcopy(result),
            }
            self._append_repeater_history_locked(entry)
            self._repeater_active_execution_id = None
            self._repeater_cancel_requested = False
            self._repeater["active_execution"] = None
            self._repeater["state"] = "ready"
            self._repeater["message"] = (
                f"Repeater request completed with status {result['status']}."
                if result["ok"]
                else "Repeater request was cancelled."
                if result["cancelled"]
                else "Repeater request reached its timeout."
                if result["timed_out"]
                else f"Repeater request failed: {result['error']}"
            )
            successful = [
                item for item in self._repeater["history"] if item["response"]["ok"]
            ]
            if len(successful) >= 2:
                self._repeater["comparison"] = self._compare_repeater_entries(
                    successful[-2], successful[-1]
                )
            self._changed()

    def _append_repeater_history_locked(self, entry: dict[str, Any]) -> None:
        stored_bytes = len(
            json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        entry["stored_bytes"] = stored_bytes
        history = self._repeater["history"]
        while history and (
            len(history) >= MAX_REPEATER_HISTORY_ENTRIES
            or self._repeater_history_bytes + stored_bytes
            > MAX_REPEATER_HISTORY_BYTES
        ):
            evicted = history.pop(0)
            self._repeater_history_bytes -= evicted["stored_bytes"]
            self._repeater["history_evictions"] += 1
        history.append(entry)
        self._repeater_history_bytes += stored_bytes
        self._repeater["history_bytes"] = self._repeater_history_bytes
        comparison = self._repeater.get("comparison")
        retained_ids = {item["id"] for item in history}
        if comparison is not None and (
            comparison["baseline_id"] not in retained_ids
            or comparison["current_id"] not in retained_ids
        ):
            self._repeater["comparison"] = None

    def _abort_repeater_controller(self, execution_id: int) -> bool:
        key = json.dumps(self._repeater_controller_key)
        identifier = json.dumps(str(execution_id))
        expression = f"""(() => {{
          const registry = globalThis[{key}];
          const controller = registry instanceof Map ? registry.get({identifier}) : null;
          if (!(controller instanceof AbortController)) return false;
          controller.abort();
          return true;
        }})()"""
        evaluated = self._command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": False,
                "silent": True,
                "userGesture": False,
            },
            timeout=3.0,
        )
        remote = evaluated.get("result")
        value = remote.get("value") if isinstance(remote, dict) else None
        if not isinstance(value, bool):
            raise ProtocolError("Debugger returned a malformed cancellation result")
        return value

    def _cancel_repeater_request(self) -> dict[str, Any]:
        with self._lock:
            execution_id = self._repeater_active_execution_id
            if execution_id is None:
                raise DebuggerBridgeError("No Repeater request is running")
            self._repeater_cancel_requested = True
            self._repeater["state"] = "cancelling"
            if self._repeater["active_execution"] is not None:
                self._repeater["active_execution"]["cancel_requested"] = True
            self._repeater["message"] = "Cancelling the active Repeater request."
            self._changed()
        try:
            delivered = self._abort_repeater_controller(execution_id)
        except BaseException:
            with self._lock:
                if self._repeater_active_execution_id == execution_id:
                    self._repeater_cancel_requested = False
                    self._repeater["state"] = "running"
                    if self._repeater["active_execution"] is not None:
                        self._repeater["active_execution"]["cancel_requested"] = False
                    self._repeater["message"] = (
                        "Cancellation could not be delivered; the request is still running."
                    )
                    self._changed()
            raise
        with self._lock:
            if self._repeater_active_execution_id == execution_id and not delivered:
                self._repeater_cancel_requested = False
                self._repeater["state"] = "running"
                if self._repeater["active_execution"] is not None:
                    self._repeater["active_execution"]["cancel_requested"] = False
                self._repeater["message"] = (
                    "The request completed before cancellation was delivered."
                )
                self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    @staticmethod
    def _compare_repeater_entries(
        baseline: dict[str, Any], current: dict[str, Any]
    ) -> dict[str, Any]:
        baseline_response = baseline["response"]
        current_response = current["response"]

        def header_map(response: dict[str, Any]) -> dict[str, str]:
            return {
                header["name"].lower(): header["value"]
                for header in response["headers"]
            }

        before_headers = header_map(baseline_response)
        after_headers = header_map(current_response)
        before_names = set(before_headers)
        after_names = set(after_headers)
        changed = sorted(
            name
            for name in before_names & after_names
            if before_headers[name] != after_headers[name]
        )
        baseline_body_bytes = len(baseline_response["body"].encode("utf-8"))
        current_body_bytes = len(current_response["body"].encode("utf-8"))
        return {
            "protocol_version": 1,
            "baseline_id": baseline["id"],
            "current_id": current["id"],
            "baseline_status": baseline_response["status"],
            "current_status": current_response["status"],
            "status_changed": baseline_response["status"]
            != current_response["status"],
            "duration_delta_ms": current_response["duration_ms"]
            - baseline_response["duration_ms"],
            "baseline_body_bytes": baseline_body_bytes,
            "current_body_bytes": current_body_bytes,
            "body_bytes_delta": current_body_bytes - baseline_body_bytes,
            "baseline_body_sha256": baseline_response["body_sha256"],
            "current_body_sha256": current_response["body_sha256"],
            "body_changed": baseline_response["body_sha256"]
            != current_response["body_sha256"],
            "headers_added": sorted(after_names - before_names),
            "headers_removed": sorted(before_names - after_names),
            "headers_changed": changed,
            "partial": any(
                (
                    baseline_response["headers_truncated"],
                    baseline_response["body_truncated"],
                    current_response["headers_truncated"],
                    current_response["body_truncated"],
                )
            ),
        }

    def _compare_repeater_history(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        baseline_id = request.get("baseline_id")
        current_id = request.get("current_id")
        if (
            not isinstance(baseline_id, int)
            or isinstance(baseline_id, bool)
            or baseline_id <= 0
            or not isinstance(current_id, int)
            or isinstance(current_id, bool)
            or current_id <= 0
            or baseline_id == current_id
        ):
            raise DebuggerBridgeError("Repeater comparison identifiers are invalid")
        with self._lock:
            entries = {entry["id"]: entry for entry in self._repeater["history"]}
            baseline = entries.get(baseline_id)
            current = entries.get(current_id)
            if (
                baseline is None
                or current is None
                or not baseline["response"]["ok"]
                or not current["response"]["ok"]
            ):
                raise DebuggerBridgeError(
                    "Repeater comparison requires two retained successful responses"
                )
            self._repeater["comparison"] = self._compare_repeater_entries(
                baseline, current
            )
            self._repeater["message"] = (
                f"Compared Repeater runs {baseline_id} and {current_id}."
            )
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _clear_repeater_history(self) -> dict[str, Any]:
        with self._lock:
            if self._repeater_active_execution_id is not None:
                raise DebuggerBridgeError(
                    "Cancel or finish the active Repeater request before clearing history"
                )
            self._repeater["history"] = []
            self._repeater["history_bytes"] = 0
            self._repeater["history_evictions"] = 0
            self._repeater["comparison"] = None
            self._repeater_history_bytes = 0
            self._repeater["message"] = "Repeater history and comparisons were cleared."
            self._changed()
            repeater = copy.deepcopy(self._repeater)
        return {"ok": True, "repeater": repeater, "generation": self.generation()}

    def _create_request_interception_experiment(self) -> dict[str, Any]:
        with self._lock:
            if self._state not in {"running", "paused"} or self._target is None:
                raise DebuggerBridgeError(
                    "Request interception requires a running debugger target"
                )
            if self._request_interception_context_id is not None:
                raise DebuggerBridgeError(
                    "An isolated request interception experiment already exists"
                )
            if self._heap_diff_busy or self._heap_snapshot_collector is not None:
                raise DebuggerBridgeError(
                    "A heap snapshot operation is already running"
                )
            experiment_id = self._next_request_interception_id
            self._next_request_interception_id += 1
            return_target_id = self._target["id"]
            self._request_interception = self._empty_request_interception()
            self._request_interception.update(
                {
                    "experiment_id": experiment_id,
                    "state": "creating",
                    "created_at_ms": int(time.time() * 1_000),
                    "message": "Creating a disposable browser context with no shared cookies or storage.",
                }
            )
            self._request_interception_rule = self._default_request_interception_rule()
            self._request_interception_return_target_id = return_target_id
            self._begin_repeater_session_locked(experiment_id)
            self._begin_object_experiment_session_locked(experiment_id)
            self._changed()

        context_id: Optional[str] = None
        try:
            context_result = self._browser_command("Target.createBrowserContext")
            context_id = self._required_protocol_identifier(
                context_result.get("browserContextId"), "browser context"
            )
            target_result = self._browser_command(
                "Target.createTarget",
                {
                    "url": "about:blank",
                    "browserContextId": context_id,
                    "background": True,
                },
            )
            target_id = self._required_protocol_identifier(
                target_result.get("targetId"), "experiment target"
            )
        except BaseException as exception:
            cleanup_error: Optional[BaseException] = None
            if context_id is not None:
                try:
                    self._browser_command(
                        "Target.disposeBrowserContext",
                        {"browserContextId": context_id},
                    )
                except DebuggerBridgeError as cleanup_exception:
                    cleanup_error = cleanup_exception
            with self._lock:
                self._request_interception_return_target_id = None
                self._request_interception["state"] = "error"
                if cleanup_error is not None:
                    self._request_interception_context_id = context_id
                    self._request_interception["isolated"] = True
                    message = (
                        f"{exception}. The partial disposable context could not be "
                        f"confirmed as deleted: {cleanup_error}"
                    )
                else:
                    message = str(exception)
                self._request_interception["message"] = self._truncate_text(
                    message, 512
                )
                self._repeater["state"] = "error"
                self._repeater["message"] = self._truncate_text(message, 512)
                self._object_experiment["state"] = "error"
                self._object_experiment["isolated"] = cleanup_error is not None
                self._object_experiment["message"] = self._truncate_text(message, 512)
                self._changed()
            raise

        with self._lock:
            self._request_interception_context_id = context_id
            self._request_interception["isolated"] = True
            self._request_interception["target_id"] = target_id
            self._request_interception["message"] = (
                "Isolated context created. Attaching its disposable page."
            )
            self._object_experiment["isolated"] = True
            self._object_experiment["target_id"] = target_id
            self._object_experiment["message"] = (
                "Isolated context created. Attaching the Object Lab page."
            )
            self._preferred_target_id = target_id
            connection = self._connection
            self._changed()
        if connection is not None:
            connection.close()
        return {
            "ok": True,
            "experiment": copy.deepcopy(self._request_interception),
            "object_experiment": copy.deepcopy(self._object_experiment),
            "repeater": copy.deepcopy(self._repeater),
            "generation": self.generation(),
        }

    def _configure_request_interception(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        rule = self._normalize_request_interception_rule(request)
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] is None
                or self._target is None
                or self._target["id"] != self._request_interception["target_id"]
                or self._request_interception["state"] not in {"ready", "error"}
                or self._request_interception_pending
            ):
                raise DebuggerBridgeError(
                    "The isolated request interception target is not ready"
                )
        self._command(
            "Fetch.enable",
            {
                "patterns": [
                    {
                        "urlPattern": rule["url_pattern"],
                        "requestStage": "Request",
                    }
                ],
                "handleAuthRequests": False,
            },
        )
        with self._lock:
            self._request_interception_rule = rule
            self._request_interception["rule"] = self._public_request_interception_rule(
                rule
            )
            self._request_interception["state"] = "ready"
            self._request_interception["result"] = None
            self._request_interception["message"] = (
                "Interception rule armed inside the disposable context."
            )
            self._changed()
            experiment = copy.deepcopy(self._request_interception)
        return {"ok": True, "experiment": experiment, "generation": self.generation()}

    def _run_request_interception(self, request: dict[str, Any]) -> dict[str, Any]:
        replay = self._normalize_request_interception_request(request)
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] is None
                or self._target is None
                or self._target["id"] != self._request_interception["target_id"]
                or self._request_interception["state"] not in {"ready", "error"}
                or self._request_interception_pending
            ):
                raise DebuggerBridgeError(
                    "The isolated request interception target is not ready"
                )
            self._request_interception["state"] = "running"
            self._request_interception["result"] = None
            self._request_interception["last_request"] = {
                "url": self._redacted_request_url(replay["url"]),
                "method": replay["method"],
                "header_count": len(replay["headers"]),
                "body_bytes": len(replay["body"].encode("utf-8")),
            }
            self._request_interception["message"] = (
                "Sending one credential-free request through the armed rule."
            )
            self._changed()

        configuration = {
            "url": replay["url"],
            "method": replay["method"],
            "headers": {
                header["name"]: header["value"] for header in replay["headers"]
            },
            "body": replay["body"],
            "timeoutMs": int(INTERCEPTION_RUN_TIMEOUT_SECONDS * 1_000),
            "headerLimit": MAX_INTERCEPTION_HEADERS,
            "headerValueLimit": MAX_INTERCEPTION_HEADER_VALUE_BYTES,
            "headerTotalLimit": MAX_INTERCEPTION_HEADER_BYTES,
            "responseByteLimit": MAX_INTERCEPTION_RESPONSE_BYTES,
        }
        expression = (
            f"({REQUEST_INTERCEPTION_FUNCTION})"
            f"({json.dumps(configuration, separators=(',', ':'))})"
        )
        try:
            evaluated = self._command(
                "Runtime.evaluate",
                {
                    "expression": expression,
                    "returnByValue": True,
                    "awaitPromise": True,
                    "silent": True,
                    "userGesture": False,
                    "timeout": int(INTERCEPTION_RUN_TIMEOUT_SECONDS * 1_000),
                },
                timeout=INTERCEPTION_RUN_TIMEOUT_SECONDS + 2.0,
            )
            if isinstance(evaluated.get("exceptionDetails"), dict):
                raise DebuggerBridgeError(
                    "The isolated request runner failed before returning a result"
                )
            remote = evaluated.get("result")
            document = remote.get("value") if isinstance(remote, dict) else None
            result = self._normalize_request_interception_result(document)
        except BaseException as exception:
            with self._lock:
                self._request_interception["state"] = "error"
                self._request_interception["message"] = self._truncate_text(
                    str(exception), 512
                )
                self._changed()
            raise

        with self._lock:
            self._request_interception["state"] = "ready"
            self._request_interception["result"] = result
            self._request_interception["message"] = (
                f"Experiment request completed with status {result['status']}."
                if result["ok"]
                else f"Experiment request finished with an error: {result['error']}"
            )
            self._changed()
            experiment = copy.deepcopy(self._request_interception)
        return {"ok": True, "experiment": experiment, "generation": self.generation()}

    def _dispose_request_interception_experiment(self) -> dict[str, Any]:
        self._dispose_request_interception_context(preserve_result=True)
        with self._lock:
            experiment = copy.deepcopy(self._request_interception)
            object_experiment = copy.deepcopy(self._object_experiment)
            repeater = copy.deepcopy(self._repeater)
        return {
            "ok": True,
            "experiment": experiment,
            "object_experiment": object_experiment,
            "repeater": repeater,
            "generation": self.generation(),
        }

    def _dispose_request_interception_context(
        self, preserve_result: bool, force: bool = False
    ) -> None:
        self._release_object_experiment_search()
        with self._lock:
            context_id = self._request_interception_context_id
            if context_id is None:
                if not preserve_result:
                    self._request_interception = self._empty_request_interception()
                    self._request_interception_rule = (
                        self._default_request_interception_rule()
                    )
                    self._request_interception_pending.clear()
                    self._repeater = self._empty_repeater()
                    self._repeater_history_bytes = 0
                    self._repeater_active_execution_id = None
                    self._repeater_cancel_requested = False
                    self._object_experiment = self._empty_object_experiment()
                    self._object_experiment_group = None
                    self._object_experiment_objects_id = None
                    self._object_experiment_result_indices.clear()
                    self._changed()
                return
            if not force and (
                self._request_interception["state"] == "running"
                or self._request_interception_pending
                or self._repeater_active_execution_id is not None
            ):
                raise DebuggerBridgeError(
                    "Finish or cancel active request-lab work before disposing its context"
                )
            repeater_session_id = self._repeater["session_id"]
            object_session_id = self._object_experiment["session_id"]
            self._request_interception["state"] = "disposing"
            self._request_interception["message"] = (
                "Disposing the isolated browser context and all of its storage."
            )
            target_id = self._request_interception["target_id"]
            self._object_experiment["state"] = "disposing"
            self._object_experiment["message"] = (
                "Disposing Object Lab and releasing all live references."
            )
            connection = (
                self._connection
                if self._target is not None and self._target["id"] == target_id
                else None
            )
            return_target_id = self._request_interception_return_target_id
            self._changed()
        if connection is not None:
            connection.close()
        try:
            self._browser_command(
                "Target.disposeBrowserContext",
                {"browserContextId": context_id},
            )
        except DebuggerBridgeError as exception:
            with self._lock:
                self._request_interception["state"] = "error"
                self._request_interception["message"] = self._truncate_text(
                    f"The disposable context could not be confirmed as deleted: {exception}",
                    512,
                )
                self._repeater["state"] = "error"
                self._repeater["message"] = self._request_interception["message"]
                self._object_experiment["state"] = "error"
                self._object_experiment["message"] = self._request_interception[
                    "message"
                ]
                self._changed()
            if preserve_result:
                raise
            return
        with self._lock:
            self._request_interception_context_id = None
            self._request_interception_return_target_id = None
            self._request_interception_pending.clear()
            self._preferred_target_id = return_target_id
            self._request_interception_rule = self._default_request_interception_rule()
            if preserve_result:
                self._request_interception["state"] = "disposed"
                self._request_interception["isolated"] = False
                self._request_interception["target_id"] = None
                self._request_interception["disposed_at_ms"] = int(time.time() * 1_000)
                self._request_interception["pending_requests"] = 0
                self._request_interception["message"] = (
                    "Disposable context deleted. The ephemeral result and audit remain visible."
                )
                self._dispose_repeater_locked(repeater_session_id)
                self._dispose_object_experiment_locked(object_session_id)
            else:
                self._request_interception = self._empty_request_interception()
                self._repeater = self._empty_repeater()
                self._object_experiment = self._empty_object_experiment()
                self._repeater_history_bytes = 0
                self._repeater_active_execution_id = None
                self._repeater_cancel_requested = False
            self._changed()

    def _clear_request_interception_result(self) -> dict[str, Any]:
        with self._lock:
            if self._request_interception_context_id is not None:
                raise DebuggerBridgeError(
                    "Dispose the isolated context before clearing its result"
                )
            self._request_interception = self._empty_request_interception()
            self._request_interception_rule = self._default_request_interception_rule()
            self._request_interception_pending.clear()
            self._repeater = self._empty_repeater()
            self._repeater_history_bytes = 0
            self._repeater_active_execution_id = None
            self._repeater_cancel_requested = False
            self._object_experiment = self._empty_object_experiment()
            self._object_experiment_group = None
            self._object_experiment_objects_id = None
            self._object_experiment_result_indices.clear()
            self._changed()
        return {"ok": True, "generation": self.generation()}

    def _normalize_request_interception_rule(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        mode = request.get("mode")
        if mode not in {"continue", "block", "drop", "rewrite", "fulfill"}:
            raise DebuggerBridgeError("Request interception mode is invalid")
        pattern = self._required_text(
            request, "url_pattern", MAX_INTERCEPTION_PATTERN_BYTES
        )
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in pattern):
            raise DebuggerBridgeError("Request interception URL pattern is invalid")
        if pattern != "*" and not pattern.startswith(("http://", "https://")):
            raise DebuggerBridgeError(
                "Request interception URL pattern must use HTTP, HTTPS, or *"
            )
        method_filter = request.get("method_filter", "")
        if not isinstance(method_filter, str):
            raise DebuggerBridgeError("Request interception method filter is invalid")
        method_filter = method_filter.strip().upper()
        if method_filter:
            self._validate_request_interception_method(method_filter)

        rule = self._default_request_interception_rule()
        rule.update(
            {"mode": mode, "url_pattern": pattern, "method_filter": method_filter}
        )
        if mode == "rewrite":
            rewrite_url = request.get("rewrite_url", "")
            if not isinstance(rewrite_url, str):
                raise DebuggerBridgeError("Request rewrite URL is invalid")
            rewrite_url = rewrite_url.strip()
            if rewrite_url:
                self._validate_request_interception_url(rewrite_url)
            rewrite_method = request.get("rewrite_method", "")
            if not isinstance(rewrite_method, str):
                raise DebuggerBridgeError("Request rewrite method is invalid")
            rewrite_method = rewrite_method.strip().upper()
            if rewrite_method:
                self._validate_request_interception_method(rewrite_method)
            rewrite_headers = self._normalize_request_interception_headers(
                request.get("rewrite_headers", {}), "rewrite"
            )
            rewrite_body = request.get("rewrite_body", "")
            if (
                not isinstance(rewrite_body, str)
                or len(rewrite_body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
            ):
                raise DebuggerBridgeError("Request rewrite body exceeds 64 KiB")
            if not any((rewrite_url, rewrite_method, rewrite_headers, rewrite_body)):
                raise DebuggerBridgeError(
                    "Request rewrite requires at least one bounded override"
                )
            rule.update(
                {
                    "rewrite_url": rewrite_url,
                    "rewrite_method": rewrite_method,
                    "rewrite_headers": rewrite_headers,
                    "rewrite_body": rewrite_body,
                }
            )
        elif mode == "fulfill":
            response_code = request.get("response_code", 200)
            if (
                not isinstance(response_code, int)
                or isinstance(response_code, bool)
                or response_code < 100
                or response_code > 599
            ):
                raise DebuggerBridgeError("Synthetic response status is invalid")
            response_headers = self._normalize_request_interception_headers(
                request.get("response_headers", {}), "response"
            )
            response_body = request.get("response_body", "")
            if (
                not isinstance(response_body, str)
                or len(response_body.encode("utf-8")) > MAX_INTERCEPTION_RESPONSE_BYTES
            ):
                raise DebuggerBridgeError("Synthetic response body exceeds 64 KiB")
            if not response_headers:
                response_headers = [
                    {"name": "content-type", "value": "text/plain; charset=utf-8"},
                ]
            if not any(
                header["name"].lower() == "access-control-allow-origin"
                for header in response_headers
            ):
                if len(response_headers) >= MAX_INTERCEPTION_HEADERS:
                    raise DebuggerBridgeError(
                        "Synthetic response headers must include access-control-allow-origin at the 64-header limit"
                    )
                response_headers.append(
                    {"name": "access-control-allow-origin", "value": "*"}
                )
            rule.update(
                {
                    "response_code": response_code,
                    "response_headers": response_headers,
                    "response_body": response_body,
                }
            )
        return rule

    def _normalize_request_interception_request(
        self, request: dict[str, Any]
    ) -> dict[str, Any]:
        url = self._required_text(request, "url", MAX_INTERCEPTION_URL_BYTES).strip()
        self._validate_request_interception_url(url)
        method = request.get("method", "GET")
        if not isinstance(method, str):
            raise DebuggerBridgeError("Experiment request method is invalid")
        method = method.strip().upper()
        self._validate_request_interception_method(method)
        headers = self._normalize_request_interception_headers(
            request.get("headers", {}), "request"
        )
        body = request.get("body", "")
        if (
            not isinstance(body, str)
            or len(body.encode("utf-8")) > MAX_INTERCEPTION_BODY_BYTES
        ):
            raise DebuggerBridgeError("Experiment request body exceeds 64 KiB")
        if method in {"GET", "HEAD"} and body:
            raise DebuggerBridgeError(
                "GET and HEAD experiment requests cannot include a body"
            )
        return {"url": url, "method": method, "headers": headers, "body": body}

    @staticmethod
    def _validate_request_interception_url(url: str) -> None:
        try:
            parsed = urlparse(url)
            _ = parsed.port
        except ValueError as exception:
            raise DebuggerBridgeError(
                "Experiment request URL is invalid"
            ) from exception
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise DebuggerBridgeError(
                "Experiment request URL must be credential-free HTTP or HTTPS"
            )

    @staticmethod
    def _validate_request_interception_method(method: str) -> None:
        allowed = frozenset(
            "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        if (
            not method
            or len(method.encode("ascii", errors="ignore"))
            != len(method.encode("utf-8"))
            or len(method) > MAX_INTERCEPTION_METHOD_BYTES
            or method[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or any(character not in allowed for character in method)
        ):
            raise DebuggerBridgeError("Experiment request method is invalid")

    @staticmethod
    def _normalize_request_interception_headers(
        value: Any, label: str
    ) -> list[dict[str, str]]:
        if not isinstance(value, dict) or len(value) > MAX_INTERCEPTION_HEADERS:
            raise DebuggerBridgeError(
                f"Request interception {label} headers are invalid"
            )
        token_characters = frozenset(
            "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        )
        forbidden = SENSITIVE_INTERCEPTION_HEADERS | {
            "connection",
            "content-length",
            "host",
            "transfer-encoding",
        }
        total_bytes = 0
        headers = []
        for name, header_value in value.items():
            if not isinstance(name, str) or not isinstance(header_value, str):
                raise DebuggerBridgeError(
                    f"Request interception {label} headers must be text"
                )
            name_bytes = len(name.encode("utf-8"))
            value_bytes = len(header_value.encode("utf-8"))
            if (
                not name
                or name_bytes > MAX_INTERCEPTION_HEADER_NAME_BYTES
                or value_bytes > MAX_INTERCEPTION_HEADER_VALUE_BYTES
                or any(character not in token_characters for character in name)
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in header_value
                )
                or name.lower() in forbidden
            ):
                raise DebuggerBridgeError(
                    f"Request interception {label} header is forbidden or invalid"
                )
            total_bytes += name_bytes + value_bytes
            if total_bytes > MAX_INTERCEPTION_HEADER_BYTES:
                raise DebuggerBridgeError(
                    f"Request interception {label} headers exceed 16 KiB"
                )
            headers.append({"name": name, "value": header_value})
        return headers

    def _normalize_request_interception_result(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocolVersion") != 1:
            raise ProtocolError("Debugger returned a malformed experiment result")
        ok = value.get("ok")
        if not isinstance(ok, bool):
            raise ProtocolError("Debugger returned a malformed experiment result")
        if not ok:
            error = value.get("error")
            if not isinstance(error, str):
                raise ProtocolError("Debugger returned a malformed experiment error")
            return {
                "protocol_version": 1,
                "ok": False,
                "status": 0,
                "status_text": "",
                "url": "",
                "headers": [],
                "headers_truncated": False,
                "body": "",
                "body_truncated": False,
                "error": self._truncate_text(error, 512),
            }
        status = value.get("status")
        status_text = value.get("statusText")
        response_url = value.get("url")
        raw_headers = value.get("headers")
        headers_truncated = value.get("headersTruncated")
        body = value.get("body")
        body_truncated = value.get("bodyTruncated")
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or status < 0
            or status > 599
            or not isinstance(status_text, str)
            or not isinstance(response_url, str)
            or not isinstance(raw_headers, list)
            or len(raw_headers) > MAX_INTERCEPTION_HEADERS
            or not isinstance(headers_truncated, bool)
            or not isinstance(body, str)
            or not isinstance(body_truncated, bool)
        ):
            raise ProtocolError("Debugger returned a malformed experiment result")
        headers = []
        header_bytes = 0
        for header in raw_headers:
            if (
                not isinstance(header, dict)
                or not isinstance(header.get("name"), str)
                or not isinstance(header.get("value"), str)
                or header["name"].lower() in SENSITIVE_INTERCEPTION_HEADERS
            ):
                raise ProtocolError("Debugger returned malformed experiment headers")
            headers_truncated = headers_truncated or (
                len(header["name"].encode("utf-8"))
                > MAX_INTERCEPTION_HEADER_NAME_BYTES
                or len(header["value"].encode("utf-8"))
                > MAX_INTERCEPTION_HEADER_VALUE_BYTES
            )
            name = self._truncate_text(
                header["name"], MAX_INTERCEPTION_HEADER_NAME_BYTES
            )
            header_value = self._truncate_text(
                header["value"], MAX_INTERCEPTION_HEADER_VALUE_BYTES
            )
            header_bytes += len(name.encode("utf-8")) + len(
                header_value.encode("utf-8")
            )
            if header_bytes > MAX_INTERCEPTION_HEADER_BYTES:
                raise ProtocolError("Debugger returned oversized experiment headers")
            headers.append({"name": name, "value": header_value})
        encoded_body = body.encode("utf-8")
        truncated_by_bridge = len(encoded_body) > MAX_INTERCEPTION_RESPONSE_BYTES
        return {
            "protocol_version": 1,
            "ok": True,
            "status": status,
            "status_text": self._truncate_text(status_text, 256),
            "url": self._redacted_request_url(response_url),
            "headers": headers,
            "headers_truncated": headers_truncated,
            "body": self._truncate_text(body, MAX_INTERCEPTION_RESPONSE_BYTES),
            "body_truncated": body_truncated or truncated_by_bridge,
            "error": None,
        }

    @staticmethod
    def _required_protocol_identifier(value: Any, label: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            raise ProtocolError(f"Browser returned an invalid {label} identifier")
        return value

    @classmethod
    def _redacted_request_url(cls, url: str) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            _ = parsed.port
        except ValueError:
            return ""
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
        path = parsed.path or "/"
        return cls._truncate_text(
            urlunparse((parsed.scheme, netloc, path, "", "", "")),
            MAX_INTERCEPTION_URL_BYTES,
        )

    def _handle_request_interception_pause_async(self, params: dict[str, Any]) -> None:
        request_id = params.get("requestId")
        request = params.get("request")
        if (
            not isinstance(request_id, str)
            or not request_id
            or len(request_id.encode("utf-8")) > MAX_TARGET_ID_BYTES
        ):
            return
        with self._lock:
            active = (
                self._request_interception_context_id is not None
                and self._target is not None
                and self._request_interception["target_id"] == self._target["id"]
                and self._request_interception["state"]
                in {"ready", "running", "error"}
            )
        if not active:
            self._command_without_wait(
                "Fetch.continueRequest", {"requestId": request_id}
            )
            return
        if not isinstance(request, dict):
            continued = self._command_without_wait(
                "Fetch.continueRequest", {"requestId": request_id}
            )
            self._append_request_interception_audit(
                request_id,
                {},
                params.get("resourceType"),
                "error",
                "Malformed paused request continued unchanged."
                if continued
                else "Malformed paused request could not be resumed.",
            )
            return
        with self._lock:
            if request_id in self._request_interception_pending:
                return
            if (
                len(self._request_interception_pending)
                >= MAX_INTERCEPTION_PENDING_REQUESTS
            ):
                overflow = True
            else:
                overflow = False
                self._request_interception_pending.add(request_id)
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()
        if overflow:
            continued = self._command_without_wait(
                "Fetch.continueRequest", {"requestId": request_id}
            )
            self._append_request_interception_audit(
                request_id,
                request,
                params.get("resourceType"),
                "overflow_continue" if continued else "error",
                "Pending interception limit reached; request continued unchanged."
                if continued
                else "Pending interception limit reached and the request could not be resumed.",
            )
            return
        thread = threading.Thread(
            target=self._process_request_interception_pause,
            args=(request_id, request, params.get("resourceType")),
            name="reb-request-interception",
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError as exception:
            continued = self._command_without_wait(
                "Fetch.continueRequest", {"requestId": request_id}
            )
            with self._lock:
                self._request_interception_pending.discard(request_id)
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()
            self._append_request_interception_audit(
                request_id,
                request,
                params.get("resourceType"),
                "error",
                self._truncate_text(
                    f"Interception worker could not start: {exception}. "
                    f"Request {'continued unchanged' if continued else 'could not be resumed'}.",
                    512,
                ),
            )

    def _process_request_interception_pause(
        self, request_id: str, request: dict[str, Any], resource_type: Any
    ) -> None:
        method = (
            request.get("method")
            if isinstance(request.get("method"), str)
            else "UNKNOWN"
        )
        with self._lock:
            rule = copy.deepcopy(self._request_interception_rule)
        outcome = "continued"
        detail = "Request continued unchanged."
        command = "Fetch.continueRequest"
        command_params: dict[str, Any] = {"requestId": request_id}
        preflight_headers = self._request_interception_preflight_headers(request, rule)
        if preflight_headers is not None:
            command = "Fetch.fulfillRequest"
            command_params.update(
                {
                    "responseCode": 204,
                    "responseHeaders": preflight_headers,
                    "body": "",
                }
            )
            outcome = "fulfilled"
            detail = "Synthetic credential-free CORS preflight returned."
        elif rule["method_filter"] and method.upper() != rule["method_filter"]:
            outcome = "bypassed"
            detail = "Request method did not match the armed rule."
        elif rule["mode"] == "block":
            command = "Fetch.failRequest"
            command_params["errorReason"] = "BlockedByClient"
            outcome = "blocked"
            detail = "Request failed with BlockedByClient."
        elif rule["mode"] == "drop":
            command = "Fetch.failRequest"
            command_params["errorReason"] = "Aborted"
            outcome = "dropped"
            detail = "Request failed with Aborted."
        elif rule["mode"] == "rewrite":
            if rule["rewrite_url"]:
                command_params["url"] = rule["rewrite_url"]
            if rule["rewrite_method"]:
                command_params["method"] = rule["rewrite_method"]
            if rule["rewrite_headers"]:
                command_params["headers"] = rule["rewrite_headers"]
            if rule["rewrite_body"]:
                command_params["postData"] = base64.b64encode(
                    rule["rewrite_body"].encode("utf-8")
                ).decode("ascii")
            outcome = "rewritten"
            detail = "Bounded request overrides applied."
        elif rule["mode"] == "fulfill":
            command = "Fetch.fulfillRequest"
            command_params.update(
                {
                    "responseCode": rule["response_code"],
                    "responseHeaders": rule["response_headers"],
                    "body": base64.b64encode(
                        rule["response_body"].encode("utf-8")
                    ).decode("ascii"),
                }
            )
            outcome = "fulfilled"
            detail = f"Synthetic response {rule['response_code']} returned."
        try:
            self._command(command, command_params, timeout=3.0)
        except DebuggerBridgeError as exception:
            outcome = "error"
            detail = self._truncate_text(str(exception), 512)
            try:
                self._command(
                    "Fetch.continueRequest", {"requestId": request_id}, timeout=1.0
                )
            except DebuggerBridgeError:
                pass
        finally:
            self._append_request_interception_audit(
                request_id, request, resource_type, outcome, detail
            )
            with self._lock:
                self._request_interception_pending.discard(request_id)
                self._request_interception["pending_requests"] = len(
                    self._request_interception_pending
                )
                self._changed()

    @classmethod
    def _request_interception_preflight_headers(
        cls, request: dict[str, Any], rule: dict[str, Any]
    ) -> Optional[list[dict[str, str]]]:
        if rule["mode"] != "fulfill" or request.get("method") != "OPTIONS":
            return None
        headers = request.get("headers")
        if not isinstance(headers, dict):
            return None
        requested_method = headers.get("Access-Control-Request-Method")
        if not isinstance(requested_method, str):
            requested_method = headers.get("access-control-request-method")
        if not isinstance(requested_method, str):
            return None
        requested_method = requested_method.strip().upper()
        try:
            cls._validate_request_interception_method(requested_method)
        except DebuggerBridgeError:
            return None
        if rule["method_filter"] and requested_method != rule["method_filter"]:
            return None

        requested_headers = headers.get("Access-Control-Request-Headers")
        if not isinstance(requested_headers, str):
            requested_headers = headers.get("access-control-request-headers", "")
        if not isinstance(requested_headers, str) or len(
            requested_headers.encode("utf-8")
        ) > MAX_INTERCEPTION_HEADER_VALUE_BYTES:
            return None
        token_characters = frozenset(
            "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        )
        header_names = (
            [name.strip().lower() for name in requested_headers.split(",")]
            if requested_headers.strip()
            else []
        )
        if any(
            not name
            or any(character not in token_characters for character in name)
            or name in SENSITIVE_INTERCEPTION_HEADERS
            for name in header_names
        ) or len(header_names) > MAX_INTERCEPTION_HEADERS:
            return None
        response_headers = [
            {"name": "access-control-allow-origin", "value": "*"},
            {
                "name": "access-control-allow-methods",
                "value": requested_method,
            },
        ]
        if requested_headers:
            response_headers.append(
                {
                    "name": "access-control-allow-headers",
                    "value": ", ".join(header_names),
                }
            )
        return response_headers

    def _append_request_interception_audit(
        self,
        request_id: str,
        request: dict[str, Any],
        resource_type: Any,
        outcome: str,
        detail: str,
    ) -> None:
        raw_url = request.get("url") if isinstance(request.get("url"), str) else ""
        method = request.get("method") if isinstance(request.get("method"), str) else ""
        with self._lock:
            audit = self._request_interception["audit"]
            if len(audit) >= MAX_INTERCEPTION_AUDIT_ENTRIES:
                audit.pop(0)
                self._request_interception["audit_evictions"] += 1
            audit.append(
                {
                    "id": self._next_request_interception_audit_id,
                    "occurred_at_ms": int(time.time() * 1_000),
                    "request_id": self._truncate_text(request_id, 256),
                    "method": self._truncate_text(
                        method, MAX_INTERCEPTION_METHOD_BYTES
                    ),
                    "url": self._redacted_request_url(raw_url),
                    "resource_type": self._truncate_text(
                        resource_type if isinstance(resource_type, str) else "Other",
                        128,
                    ),
                    "rule_mode": self._request_interception_rule["mode"],
                    "outcome": outcome,
                    "detail": self._truncate_text(detail, 512),
                }
            )
            self._next_request_interception_audit_id += 1
            self._changed()

    def _normalize_heap_snapshot_probe(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocol_version") != 1:
            raise ProtocolError("Native heap snapshot probe returned malformed output")
        integer_fields = (
            "file_bytes",
            "total_nodes",
            "analyzed_nodes",
            "reachable_nodes",
            "total_edges",
            "indexed_edges",
            "total_strings",
            "duration_ms",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Native heap snapshot probe returned invalid counts")
        boolean_fields = (
            "match_found",
            "reachability_indexed",
            "node_limit_reached",
            "edge_limit_reached",
            "string_limit_reached",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Native heap snapshot probe returned invalid limits")
        scope = value.get("scope")
        if (
            scope not in {"all", "reachable", "unreachable"}
            or value["file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["analyzed_nodes"] > value["total_nodes"]
            or value["reachable_nodes"] > value["total_nodes"]
            or value["indexed_edges"] > value["total_edges"]
            or (value["match_found"] and value["analyzed_nodes"] == 0)
            or (
                not value["match_found"]
                and not value["node_limit_reached"]
                and value["analyzed_nodes"] != value["total_nodes"]
            )
            or (
                scope == "all"
                and (
                    value["reachability_indexed"]
                    or value["reachable_nodes"] != 0
                    or value["indexed_edges"] != 0
                )
            )
            or (scope != "all" and not value["reachability_indexed"])
        ):
            raise ProtocolError("Native heap snapshot probe returned invalid coverage")
        raw_match = value.get("match")
        if value["match_found"] != isinstance(raw_match, dict):
            raise ProtocolError("Native heap snapshot probe returned a malformed match")
        match = None
        if isinstance(raw_match, dict):
            match_id = raw_match.get("id")
            self_size = raw_match.get("self_size")
            if (
                not isinstance(match_id, str)
                or not match_id.isascii()
                or not match_id.isdigit()
                or (len(match_id) > 1 and match_id.startswith("0"))
                or len(match_id) > 20
                or not isinstance(raw_match.get("type"), str)
                or not isinstance(raw_match.get("name"), str)
                or not isinstance(self_size, int)
                or isinstance(self_size, bool)
                or self_size < 0
                or self_size > 2**53 - 1
            ):
                raise ProtocolError("Native heap snapshot probe returned a malformed match")
            match = {
                "id": match_id,
                "type": self._truncate_text(raw_match["type"], 64),
                "name": self._truncate_text(raw_match["name"], 256),
                "self_size": self_size,
            }
        return {
            "protocol_version": 1,
            **{field: value[field] for field in integer_fields},
            **{field: value[field] for field in boolean_fields},
            "scope": scope,
            "match": match,
        }

    def _heap_snapshot_binary(self) -> Path:
        binary = self.heap_snapshot_binary.resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise DebuggerBridgeError(
                "Native heap snapshot analysis is unavailable; run make heap-snapshot"
            )
        return binary

    def _capture_heap_snapshot(self) -> HeapSnapshotCapture:
        temporary = tempfile.NamedTemporaryFile(
            mode="wb", prefix="reb-heap-", suffix=".heapsnapshot", delete=False
        )
        collector = HeapSnapshotCollector(Path(temporary.name), temporary)
        with self._lock:
            target_id = self._target["id"] if self._target is not None else None
            if target_id is None:
                collector.close()
                collector.path.unlink(missing_ok=True)
                raise DebuggerBridgeError("Debugger target is unavailable")
            if self._heap_snapshot_collector is not None:
                collector.close()
                collector.path.unlink(missing_ok=True)
                raise DebuggerBridgeError("A heap snapshot capture is already running")
            self._heap_snapshot_collector = collector
        try:
            self._command("HeapProfiler.enable")
            self._command(
                "HeapProfiler.takeHeapSnapshot",
                {
                    "reportProgress": False,
                    "captureNumericValue": True,
                    "exposeInternals": False,
                },
                timeout=HEAP_SNAPSHOT_CAPTURE_TIMEOUT_SECONDS,
            )
        except BaseException:
            collector.close()
            collector.path.unlink(missing_ok=True)
            with self._lock:
                connection = self._connection
            if connection is not None:
                connection.close()
            raise
        finally:
            with self._lock:
                if self._heap_snapshot_collector is collector:
                    self._heap_snapshot_collector = None
            collector.close()

        try:
            if collector.error is not None:
                raise DebuggerBridgeError(collector.error)
            if collector.chunk_count == 0 or collector.byte_count == 0:
                raise ProtocolError("Debugger returned an empty heap snapshot")
            return HeapSnapshotCapture(
                path=collector.path,
                target_id=target_id,
                byte_count=collector.byte_count,
                captured_at_ms=int(time.time() * 1_000),
            )
        except BaseException:
            collector.path.unlink(missing_ok=True)
            raise

    def _run_native_heap_snapshot(
        self, command: list[str], timeout: float, operation: str
    ) -> Any:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exception:
            raise DebuggerBridgeError(
                f"Native heap snapshot {operation} exceeded its {int(timeout)} second limit"
            ) from exception
        if completed.returncode != 0:
            detail = self._truncate_text(completed.stderr.strip(), 512)
            raise DebuggerBridgeError(
                detail or f"Native heap snapshot {operation} rejected the snapshot"
            )
        if len(completed.stdout.encode("utf-8")) > 512 * 1024:
            raise ProtocolError(
                f"Native heap snapshot {operation} returned oversized output"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exception:
            raise ProtocolError(
                f"Native heap snapshot {operation} returned malformed JSON"
            ) from exception

    def _heap_diff_baseline_metadata(self) -> Optional[dict[str, Any]]:
        baseline = self._heap_diff_baseline
        if baseline is None:
            return None
        return {
            "target_id": baseline.target_id,
            "file_bytes": baseline.byte_count,
            "captured_at_ms": baseline.captured_at_ms,
        }

    def _clear_heap_diff_baseline(self, force: bool = False) -> None:
        with self._lock:
            if self._heap_diff_busy and not force:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            baseline = self._heap_diff_baseline
            self._heap_diff_baseline = None
            if baseline is not None:
                self._changed()
        if baseline is not None:
            baseline.path.unlink(missing_ok=True)

    def _finish_heap_diff_operation(self) -> None:
        with self._lock:
            self._heap_diff_busy = False
            baseline = self._heap_diff_baseline
            target_id = self._target["id"] if self._target is not None else None
            if baseline is not None and baseline.target_id != target_id:
                self._heap_diff_baseline = None
                self._changed()
            else:
                baseline = None
        if baseline is not None:
            baseline.path.unlink(missing_ok=True)

    def _capture_heap_diff_baseline(self) -> dict[str, Any]:
        self._heap_snapshot_binary()
        with self._lock:
            if self._heap_diff_busy:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            self._heap_diff_busy = True
        capture: Optional[HeapSnapshotCapture] = None
        previous: Optional[HeapSnapshotCapture] = None
        try:
            capture = self._capture_heap_snapshot()
            with self._lock:
                previous = self._heap_diff_baseline
                self._heap_diff_baseline = capture
                metadata = self._heap_diff_baseline_metadata()
                self._changed()
            if previous is not None:
                previous.path.unlink(missing_ok=True)
            return {
                "ok": True,
                "baseline": metadata,
                "generation": self.generation(),
            }
        except BaseException:
            if capture is not None:
                capture.path.unlink(missing_ok=True)
            raise
        finally:
            self._finish_heap_diff_operation()

    def _compare_heap_diff(self) -> dict[str, Any]:
        binary = self._heap_snapshot_binary()
        with self._lock:
            if self._heap_diff_busy:
                raise DebuggerBridgeError("Heap snapshot comparison is running")
            baseline = self._heap_diff_baseline
            target_id = self._target["id"] if self._target is not None else None
            if baseline is None:
                raise DebuggerBridgeError("Capture a heap snapshot baseline first")
            if target_id != baseline.target_id:
                raise DebuggerBridgeError(
                    "Heap snapshot baseline belongs to a different debugger target"
                )
            self._heap_diff_busy = True
        current: Optional[HeapSnapshotCapture] = None
        try:
            current = self._capture_heap_snapshot()
            if current.target_id != baseline.target_id:
                raise DebuggerBridgeError(
                    "Debugger target changed during heap snapshot comparison"
                )
            document = self._run_native_heap_snapshot(
                [
                    str(binary),
                    "--baseline",
                    str(baseline.path),
                    "--current",
                    str(current.path),
                    "--limit",
                    str(MAX_HEAP_SNAPSHOT_RESULTS),
                ],
                HEAP_SNAPSHOT_DIFF_TIMEOUT_SECONDS,
                "comparison",
            )
            return self._normalize_heap_snapshot_diff(document)
        finally:
            if current is not None:
                current.path.unlink(missing_ok=True)
            self._finish_heap_diff_operation()

    def _normalize_heap_snapshot_search(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocol_version") != 2:
            raise ProtocolError("Native heap snapshot search returned malformed output")
        integer_fields = (
            "file_bytes",
            "total_nodes",
            "analyzed_nodes",
            "matched_nodes",
            "reachable_nodes",
            "total_edges",
            "indexed_edges",
            "total_strings",
            "duration_ms",
            "result_limit",
            "reference_limit",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Native heap snapshot search returned invalid counts")
        if (
            value["file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["analyzed_nodes"] > value["total_nodes"]
            or value["matched_nodes"] > value["analyzed_nodes"]
            or value["reachable_nodes"] > value["analyzed_nodes"]
            or value["indexed_edges"] > value["total_edges"]
            or value["result_limit"] != MAX_HEAP_SNAPSHOT_RESULTS
            or value["reference_limit"] != MAX_HEAP_INCOMING_REFERENCES
            or not isinstance(value.get("scope"), str)
            or value["scope"] not in {"all", "reachable", "unreachable"}
            or value.get("result_limit_reached")
            != (value["matched_nodes"] > value["result_limit"])
        ):
            raise ProtocolError("Native heap snapshot search returned invalid coverage")
        boolean_fields = (
            "result_limit_reached",
            "node_limit_reached",
            "edge_limit_reached",
            "string_limit_reached",
            "retaining_paths_partial",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Native heap snapshot search returned invalid limits")
        raw_results = value.get("results")
        if (
            not isinstance(raw_results, list)
            or len(raw_results) > MAX_HEAP_SNAPSHOT_RESULTS
            or len(raw_results) != min(value["matched_nodes"], value["result_limit"])
        ):
            raise ProtocolError("Native heap snapshot search returned too many results")
        results = []
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                raise ProtocolError("Native heap snapshot search returned a malformed result")
            result_id = raw_result.get("id")
            node_type = raw_result.get("type")
            node_name = raw_result.get("name")
            self_size = raw_result.get("self_size")
            reachable = raw_result.get("reachable")
            incoming_reference_count = raw_result.get("incoming_reference_count")
            incoming_reference_limit_reached = raw_result.get(
                "incoming_reference_limit_reached"
            )
            path_complete = raw_result.get("retaining_path_complete")
            raw_path = raw_result.get("retaining_path")
            raw_references = raw_result.get("incoming_references")
            if (
                not isinstance(result_id, str)
                or not result_id.isascii()
                or not result_id.isdigit()
                or (len(result_id) > 1 and result_id.startswith("0"))
                or len(result_id) > 20
                or not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or not isinstance(self_size, int)
                or isinstance(self_size, bool)
                or self_size < 0
                or self_size > 2**53 - 1
                or not isinstance(reachable, bool)
                or not isinstance(incoming_reference_count, int)
                or isinstance(incoming_reference_count, bool)
                or incoming_reference_count < 0
                or incoming_reference_count > 2**53 - 1
                or not isinstance(incoming_reference_limit_reached, bool)
                or not isinstance(path_complete, bool)
                or not isinstance(raw_path, list)
                or len(raw_path) > MAX_HEAP_RETAINING_PATH
                or not isinstance(raw_references, list)
                or len(raw_references) > MAX_HEAP_INCOMING_REFERENCES
                or incoming_reference_count < len(raw_references)
                or incoming_reference_limit_reached
                != (incoming_reference_count > len(raw_references))
                or (not reachable and (path_complete or raw_path))
                or (value["scope"] == "reachable" and not reachable)
                or (value["scope"] == "unreachable" and reachable)
            ):
                raise ProtocolError("Native heap snapshot search returned a malformed result")
            retaining_path = []
            for raw_step in raw_path:
                if not isinstance(raw_step, dict) or any(
                    not isinstance(raw_step.get(field), str)
                    for field in ("edge_type", "edge", "type", "name")
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed retaining path"
                    )
                retaining_path.append(
                    {
                        "edge": self._truncate_text(raw_step["edge"], 128),
                        "edge_type": self._truncate_text(raw_step["edge_type"], 32),
                        "type": self._truncate_text(raw_step["type"], 64),
                        "name": self._truncate_text(raw_step["name"], 256),
                    }
                )
            incoming_references = []
            for raw_reference in raw_references:
                if not isinstance(raw_reference, dict) or any(
                    not isinstance(raw_reference.get(field), str)
                    for field in (
                        "source_id",
                        "edge_type",
                        "edge",
                        "source_type",
                        "source_name",
                    )
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed incoming reference"
                    )
                source_id = raw_reference["source_id"]
                if (
                    not source_id.isascii()
                    or not source_id.isdigit()
                    or (len(source_id) > 1 and source_id.startswith("0"))
                    or len(source_id) > 20
                ):
                    raise ProtocolError(
                        "Native heap snapshot search returned a malformed incoming reference"
                    )
                incoming_references.append(
                    {
                        "source_id": source_id,
                        "edge_type": self._truncate_text(raw_reference["edge_type"], 32),
                        "edge": self._truncate_text(raw_reference["edge"], 128),
                        "source_type": self._truncate_text(raw_reference["source_type"], 64),
                        "source_name": self._truncate_text(raw_reference["source_name"], 256),
                    }
                )
            results.append(
                {
                    "id": result_id,
                    "type": self._truncate_text(node_type, 64),
                    "name": self._truncate_text(node_name, 256),
                    "self_size": self_size,
                    "reachable": reachable,
                    "incoming_reference_count": incoming_reference_count,
                    "incoming_reference_limit_reached": incoming_reference_limit_reached,
                    "retaining_path_complete": path_complete,
                    "retaining_path": retaining_path,
                    "incoming_references": incoming_references,
                }
            )
        return {
            "ok": True,
            "snapshot": {
                field: value[field]
                for field in (
                    "protocol_version",
                    *integer_fields,
                    *boolean_fields,
                    "scope",
                )
            }
            | {"results": results},
            "generation": self.generation(),
        }

    def _normalize_heap_snapshot_diff(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or value.get("protocol_version") != 1:
            raise ProtocolError("Native heap snapshot comparison returned malformed output")
        integer_fields = (
            "baseline_file_bytes",
            "current_file_bytes",
            "baseline_nodes",
            "current_nodes",
            "baseline_edges",
            "current_edges",
            "baseline_reachable_nodes",
            "current_reachable_nodes",
            "baseline_self_size",
            "current_self_size",
            "duration_ms",
            "result_limit",
        )
        if any(
            not isinstance(value.get(field), int)
            or isinstance(value.get(field), bool)
            or value[field] < 0
            or value[field] > 2**53 - 1
            for field in integer_fields
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid counts")
        self_size_delta = value.get("self_size_delta")
        if (
            not isinstance(self_size_delta, int)
            or isinstance(self_size_delta, bool)
            or abs(self_size_delta) > 2**53 - 1
            or self_size_delta
            != value["current_self_size"] - value["baseline_self_size"]
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid totals")
        if (
            value["baseline_file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["current_file_bytes"] > MAX_HEAP_SNAPSHOT_BYTES
            or value["baseline_reachable_nodes"] > value["baseline_nodes"]
            or value["current_reachable_nodes"] > value["current_nodes"]
            or value["result_limit"] != MAX_HEAP_SNAPSHOT_RESULTS
        ):
            raise ProtocolError("Native heap snapshot comparison returned invalid coverage")
        boolean_fields = (
            "group_result_limit_reached",
            "dominator_result_limit_reached",
            "aggregation_limit_reached",
            "baseline_node_limit_reached",
            "baseline_edge_limit_reached",
            "baseline_string_limit_reached",
            "current_node_limit_reached",
            "current_edge_limit_reached",
            "current_string_limit_reached",
            "retained_size_saturated",
        )
        if any(not isinstance(value.get(field), bool) for field in boolean_fields):
            raise ProtocolError("Native heap snapshot comparison returned invalid limits")

        raw_groups = value.get("groups")
        if not isinstance(raw_groups, list) or len(raw_groups) > MAX_HEAP_SNAPSHOT_RESULTS:
            raise ProtocolError("Native heap snapshot comparison returned too many groups")
        groups = []
        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed group"
                )
            node_type = raw_group.get("type")
            node_name = raw_group.get("name")
            baseline_count = raw_group.get("baseline_count")
            current_count = raw_group.get("current_count")
            count_delta = raw_group.get("count_delta")
            baseline_size = raw_group.get("baseline_self_size")
            current_size = raw_group.get("current_self_size")
            size_delta = raw_group.get("self_size_delta")
            unsigned_values = (
                baseline_count,
                current_count,
                baseline_size,
                current_size,
            )
            signed_values = (count_delta, size_delta)
            if (
                not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or item < 0
                    or item > 2**53 - 1
                    for item in unsigned_values
                )
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or abs(item) > 2**53 - 1
                    for item in signed_values
                )
                or count_delta != current_count - baseline_count
                or size_delta != current_size - baseline_size
                or baseline_count > value["baseline_nodes"]
                or current_count > value["current_nodes"]
            ):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed group"
                )
            groups.append(
                {
                    "type": self._truncate_text(node_type, 64),
                    "name": self._truncate_text(node_name, 256),
                    "baseline_count": baseline_count,
                    "current_count": current_count,
                    "count_delta": count_delta,
                    "baseline_self_size": baseline_size,
                    "current_self_size": current_size,
                    "self_size_delta": size_delta,
                }
            )

        raw_dominators = value.get("dominators")
        if (
            not isinstance(raw_dominators, list)
            or len(raw_dominators) > MAX_HEAP_SNAPSHOT_RESULTS
        ):
            raise ProtocolError(
                "Native heap snapshot comparison returned too many dominators"
            )
        dominators = []
        for raw_change in raw_dominators:
            if not isinstance(raw_change, dict):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed dominator"
                )
            node_id = raw_change.get("id")
            node_type = raw_change.get("type")
            node_name = raw_change.get("name")
            baseline_size = raw_change.get("baseline_retained_size")
            current_size = raw_change.get("current_retained_size")
            size_delta = raw_change.get("retained_size_delta")
            if (
                not isinstance(node_id, str)
                or not node_id.isdecimal()
                or len(node_id) > 20
                or not isinstance(node_type, str)
                or not isinstance(node_name, str)
                or any(
                    not isinstance(item, int)
                    or isinstance(item, bool)
                    or item < 0
                    or item > 2**53 - 1
                    for item in (baseline_size, current_size)
                )
                or not isinstance(size_delta, int)
                or isinstance(size_delta, bool)
                or abs(size_delta) > 2**53 - 1
                or size_delta != current_size - baseline_size
            ):
                raise ProtocolError(
                    "Native heap snapshot comparison returned a malformed dominator"
                )
            dominators.append(
                {
                    "id": node_id,
                    "type": self._truncate_text(node_type, 64),
                    "name": self._truncate_text(node_name, 256),
                    "baseline_retained_size": baseline_size,
                    "current_retained_size": current_size,
                    "retained_size_delta": size_delta,
                }
            )
        return {
            "ok": True,
            "diff": {
                field: value[field]
                for field in (
                    "protocol_version",
                    *integer_fields,
                    "self_size_delta",
                    *boolean_fields,
                )
            }
            | {"groups": groups, "dominators": dominators},
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

    def _devtools_endpoint(self) -> tuple[int, str]:
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
        browser_endpoint = lines[1]
        if browser_endpoint.startswith("/"):
            browser_url = f"ws://127.0.0.1:{port}{browser_endpoint}"
        elif browser_endpoint.startswith("ws://"):
            browser_url = browser_endpoint
        else:
            raise DebuggerBridgeError("The browser debugger endpoint is malformed")
        if len(browser_url.encode("utf-8")) > MAX_TARGET_URL_BYTES:
            raise DebuggerBridgeError("The browser debugger endpoint is oversized")
        return port, browser_url

    def _browser_command(
        self, method: str, params: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        _, browser_url = self._devtools_endpoint()
        connection = WebSocketClient(browser_url)
        try:
            connection.send_json({"id": 1, "method": method, "params": params or {}})
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                response = connection.receive_json(
                    timeout=min(0.5, max(0.0, deadline - time.monotonic()))
                )
                if response is None or response.get("id") != 1:
                    continue
                error = response.get("error")
                if isinstance(error, dict):
                    message = error.get("message")
                    raise DebuggerBridgeError(
                        self._truncate_text(
                            message
                            if isinstance(message, str)
                            else f"Browser command {method} failed",
                            512,
                        )
                    )
                result = response.get("result")
                if not isinstance(result, dict):
                    raise ProtocolError(
                        f"Browser command {method} returned malformed output"
                    )
                return result
            raise DebuggerBridgeError(f"Browser command {method} timed out")
        finally:
            connection.close()

    def _discover_targets(self) -> list[dict[str, str]]:
        port, _ = self._devtools_endpoint()
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
            self._restore_request_interception(target["id"])
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
                origin_trace_id = (
                    self._memory_origin_trace["trace_id"]
                    if self._memory_origin_trace_active_locked()
                    else None
                )
                clear_heap_baseline = (
                    self._connection is connection and not self._heap_diff_busy
                )
                if self._object_experiment.get("target_id") == target["id"]:
                    self._object_experiment_group = None
                    self._object_experiment_objects_id = None
                    self._object_experiment_result_indices.clear()
                    self._object_experiment["search_id"] = 0
                    self._object_experiment["search"] = None
                    self._object_experiment["results"] = []
                    self._object_experiment["last_mutation"] = None
                    if self._object_experiment["state"] not in {
                        "disposing",
                        "disposed",
                    }:
                        self._object_experiment["state"] = "error"
                        self._object_experiment["message"] = (
                            "Object Lab target disconnected. Reattach it and run the search again."
                        )
                if self._connection is connection:
                    self._connection = None
                    self._target = None
                    self._scripts = {}
                    self._paused = None
                    self._state = "waiting"
                    self._watch_frame_id = None
                    self._pause_serial += 1
                    self._changed()
            if origin_trace_id is not None:
                self._complete_memory_origin_trace(
                    origin_trace_id,
                    "error",
                    "Debugger target disconnected during Memory Origin Trace.",
                    resume=False,
                )
            if clear_heap_baseline:
                self._clear_heap_diff_baseline()

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
        if method == "Fetch.requestPaused":
            self._handle_request_interception_pause_async(params)
            return
        if method == "HeapProfiler.addHeapSnapshotChunk":
            with self._lock:
                collector = self._heap_snapshot_collector
            if collector is not None:
                collector.append(params.get("chunk"))
            return
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
                origin_trace_active = self._memory_origin_trace_active_locked()
                if origin_trace_active:
                    paused["scope_coverage"] = {
                        "status": "partial",
                        "properties": 0,
                        "limit": MAX_TOTAL_SCOPE_PROPERTIES,
                    }
                self._changed()
            if origin_trace_active:
                self._start_memory_origin_trace_pause_async(pause_serial, paused)
            else:
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

    def _command_without_wait(
        self, method: str, params: Optional[dict[str, Any]] = None
    ) -> bool:
        with self._lock:
            connection = self._connection
            if connection is None:
                return False
            command_id = self._next_command_id
            self._next_command_id += 1
        try:
            connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except DebuggerBridgeError:
            return False
        return True

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

    def _restore_request_interception(self, target_id: str) -> None:
        with self._lock:
            if (
                self._request_interception_context_id is None
                or self._request_interception["target_id"] != target_id
            ):
                return
            pattern = self._request_interception_rule["url_pattern"]
            was_running = self._request_interception["state"] == "running"
            object_was_running = self._object_experiment["state"] in {
                "navigating",
                "searching",
                "mutating",
            }
        self._command(
            "Fetch.enable",
            {
                "patterns": [{"urlPattern": pattern, "requestStage": "Request"}],
                "handleAuthRequests": False,
            },
        )
        with self._lock:
            if self._request_interception["target_id"] != target_id:
                return
            self._request_interception["state"] = "error" if was_running else "ready"
            self._request_interception["message"] = (
                "The experiment target reattached while a request was running; run it again."
                if was_running
                else "Disposable context ready. Configure a bounded interception rule."
            )
            if self._repeater_active_execution_id is None:
                self._repeater["state"] = "ready"
                self._repeater["message"] = (
                    "Repeater is ready inside the disposable credential-free context."
                )
            self._object_experiment["isolated"] = True
            self._object_experiment["target_id"] = target_id
            self._object_experiment["state"] = (
                "error"
                if object_was_running
                else "loaded"
                if self._object_experiment["url"]
                else "ready"
            )
            self._object_experiment["message"] = (
                "The Object Lab target reattached during an action; run that action again."
                if object_was_running
                else "Object Lab page reattached. Run the bounded search again."
                if self._object_experiment["url"]
                else "Object Lab is isolated and ready for an explicit page URL."
            )
            self._changed()

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
