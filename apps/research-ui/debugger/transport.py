from __future__ import annotations

import json
import os
import select
import struct
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from debugger.errors import (
    DebuggerBridgeError,
    ProtocolError,
    WebSocketClosed,
)
from debugger.limits import (
    MAX_NATIVE_TRANSPORT_ERROR_BYTES,
    NATIVE_TRANSPORT_PROTOCOL_HEADER,
    NATIVE_TRANSPORT_STARTUP_TIMEOUT_SECONDS,
    NATIVE_TRANSPORT_WRITE_TIMEOUT_SECONDS,
)


@dataclass
class PendingCommand:
    event: threading.Event
    response: Optional[dict[str, Any]] = None
    error: Optional[BaseException] = None


class NativeDebuggerConnection:
    def __init__(self, url: str, binary: Path) -> None:
        resolved_binary = binary.resolve()
        if not resolved_binary.is_file() or not os.access(resolved_binary, os.X_OK):
            raise DebuggerBridgeError(
                "Native debugger transport is unavailable; run make debugger-transport"
        )
        self._send_lock = threading.Lock()
        self._closed = False
        try:
            self._process = subprocess.Popen(
                [str(resolved_binary), "--url", url],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
            )
        except OSError as exception:
            raise DebuggerBridgeError(
                f"Native debugger transport could not start: {exception}"
            ) from exception
        try:
            if self._process.stdin is None or self._process.stdout is None:
                raise DebuggerBridgeError(
                    "Native debugger transport pipes are unavailable"
                )
            os.set_blocking(self._process.stdin.fileno(), False)
            ready = self._read_control_message(
                NATIVE_TRANSPORT_STARTUP_TIMEOUT_SECONDS
            )
            if ready is None:
                raise DebuggerBridgeError(
                    "Native debugger transport startup timed out"
                )
            if ready:
                raise DebuggerBridgeError(
                    "Native debugger transport returned a malformed startup frame"
                )
        except BaseException:
            self.close()
            raise

    def send_json(self, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        if len(body) > 16 * 1024 * 1024:
            raise DebuggerBridgeError("Debugger command is oversized")
        frame = (
            NATIVE_TRANSPORT_PROTOCOL_HEADER + struct.pack("!I", len(body)) + body
        )
        with self._send_lock:
            if self._closed or self._process.stdin is None:
                raise WebSocketClosed("Debugger WebSocket is closed")
            try:
                self._write_exact(self._process.stdin.fileno(), frame)
            except TimeoutError as exception:
                raise WebSocketClosed(str(exception)) from exception
            except OSError as exception:
                raise WebSocketClosed(self._failure_detail()) from exception

    def receive_json(self, timeout: float = 0.5) -> Optional[dict[str, Any]]:
        payload = self._read_control_message(timeout)
        if payload is None:
            return None
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise DebuggerBridgeError(
                "Debugger WebSocket sent malformed JSON"
            ) from exception
        if not isinstance(value, dict):
            raise DebuggerBridgeError("Debugger WebSocket sent a non-object message")
        return value

    def close(self) -> None:
        with self._send_lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=0.5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def _read_control_message(self, timeout: float) -> Optional[bytes]:
        if self._process.stdout is None:
            raise WebSocketClosed("Debugger WebSocket is closed")
        ready, _, _ = select.select([self._process.stdout], [], [], max(0.0, timeout))
        if not ready:
            return None
        header = self._read_exact(self._process.stdout.fileno(), 8)
        if header[:4] != NATIVE_TRANSPORT_PROTOCOL_HEADER:
            raise ProtocolError(
                "Native debugger transport returned an invalid protocol header"
            )
        length = struct.unpack("!I", header[4:])[0]
        if length > 64 * 1024 * 1024:
            raise DebuggerBridgeError("Debugger WebSocket message is oversized")
        return self._read_exact(self._process.stdout.fileno(), length)

    def _read_exact(self, descriptor: int, length: int) -> bytes:
        body = bytearray()
        while len(body) < length:
            chunk = os.read(descriptor, length - len(body))
            if not chunk:
                raise WebSocketClosed(self._failure_detail())
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _write_exact(descriptor: int, body: bytes) -> None:
        deadline = time.monotonic() + NATIVE_TRANSPORT_WRITE_TIMEOUT_SECONDS
        offset = 0
        while offset < len(body):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Native debugger transport command pipe timed out"
                )
            try:
                written = os.write(descriptor, body[offset:])
            except InterruptedError:
                continue
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Native debugger transport command pipe timed out"
                    )
                _, writable, _ = select.select([], [descriptor], [], remaining)
                if not writable:
                    raise TimeoutError(
                        "Native debugger transport command pipe timed out"
                    )
                continue
            if written == 0:
                raise BrokenPipeError("Native debugger transport pipe closed")
            offset += written

    def _failure_detail(self) -> str:
        fallback = "Debugger WebSocket closed"
        if self._process.stderr is None:
            return fallback
        ready, _, _ = select.select([self._process.stderr], [], [], 0.1)
        if not ready:
            return fallback
        try:
            body = os.read(
                self._process.stderr.fileno(), MAX_NATIVE_TRANSPORT_ERROR_BYTES + 1
            )
        except OSError:
            return fallback
        detail = body[:MAX_NATIVE_TRANSPORT_ERROR_BYTES].decode(
            "utf-8", errors="replace"
        )
        return detail.strip() or fallback


class ActionScopeTargetSession:
    """One bounded CDP client for mutable rules on an isolated page target."""

    def __init__(
        self,
        target: dict[str, str],
        event_handler: Any,
        close_handler: Any,
        debugger_transport_binary: Path,
    ) -> None:
        self.target = dict(target)
        self.target_id = target["id"]
        self._event_handler = event_handler
        self._close_handler = close_handler
        self._connection = NativeDebuggerConnection(
            target["web_socket_url"], debugger_transport_binary
        )
        self._lock = threading.RLock()
        self._pending: dict[int, PendingCommand] = {}
        self._next_command_id = 1
        self._closed = False
        self._ready = False
        self._reader = threading.Thread(
            target=self._read_messages,
            name=f"reb-action-scope-{self.target_id[:12]}",
            daemon=True,
        )

    def start(self) -> None:
        self._reader.start()
        try:
            self.command("Runtime.enable")
            self.command("Page.enable")
        except BaseException:
            self.close()
            raise
        with self._lock:
            if self._closed:
                raise DebuggerBridgeError("Action-scope target disconnected during setup")
            self._ready = True

    def ready(self) -> bool:
        with self._lock:
            return self._ready and not self._closed

    def command(
        self,
        method: str,
        params: Optional[dict[str, Any]] = None,
        timeout: float = 3.0,
    ) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise DebuggerBridgeError("Action-scope target is disconnected")
            command_id = self._next_command_id
            self._next_command_id += 1
            pending = PendingCommand(threading.Event())
            self._pending[command_id] = pending
        try:
            self._connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except BaseException:
            with self._lock:
                self._pending.pop(command_id, None)
            raise
        if not pending.event.wait(timeout):
            with self._lock:
                self._pending.pop(command_id, None)
            raise DebuggerBridgeError(f"Action-scope command timed out: {method}")
        if pending.error is not None:
            raise DebuggerBridgeError(str(pending.error))
        response = pending.response or {}
        error = response.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            raise ProtocolError(
                message
                if isinstance(message, str)
                else f"Action-scope command failed: {method}"
            )
        result = response.get("result", {})
        if not isinstance(result, dict):
            raise ProtocolError(
                f"Action-scope target returned malformed output: {method}"
            )
        return result

    def command_without_wait(
        self, method: str, params: Optional[dict[str, Any]] = None
    ) -> bool:
        with self._lock:
            if self._closed:
                return False
            command_id = self._next_command_id
            self._next_command_id += 1
        try:
            self._connection.send_json(
                {"id": command_id, "method": method, "params": params or {}}
            )
        except DebuggerBridgeError:
            return False
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._ready = False
            pending = list(self._pending.values())
            self._pending.clear()
        error = WebSocketClosed("Action-scope target disconnected")
        for command in pending:
            command.error = error
            command.event.set()
        self._connection.close()
        if threading.current_thread() is not self._reader:
            self._reader.join(timeout=1.0)

    def _read_messages(self) -> None:
        error: Optional[BaseException] = None
        try:
            while True:
                with self._lock:
                    if self._closed:
                        return
                message = self._connection.receive_json()
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
                    self._event_handler(self, method, params)
        except (OSError, DebuggerBridgeError, json.JSONDecodeError) as exception:
            error = exception
        finally:
            with self._lock:
                already_closed = self._closed
                self._closed = True
                self._ready = False
                pending = list(self._pending.values())
                self._pending.clear()
            failure = error or WebSocketClosed("Action-scope target disconnected")
            for command in pending:
                command.error = failure
                command.event.set()
            self._connection.close()
            if not already_closed:
                self._close_handler(self.target_id, failure)
