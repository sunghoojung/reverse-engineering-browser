import base64
import hashlib
import json
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from debugger_bridge import (
    LIVE_OBJECT_SEARCH_FUNCTION,
    DebuggerBridge,
    DebuggerBridgeError,
)


class FakeDebuggerWebSocket:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.commands = []
        self.connection = None
        self.breakpoint_index = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        self.listener.close()
        self.thread.join(timeout=2)

    def run(self) -> None:
        try:
            self.connection, _ = self.listener.accept()
            request = self.read_headers()
            key = next(
                line.split(":", 1)[1].strip()
                for line in request.split("\r\n")
                if line.lower().startswith("sec-websocket-key:")
            )
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            ).decode()
            self.connection.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode()
            )
            while True:
                message = self.receive_json()
                self.commands.append(message)
                self.respond(message)
        except (OSError, StopIteration):
            return

    def read_headers(self) -> str:
        body = bytearray()
        while b"\r\n\r\n" not in body:
            body.extend(self.connection.recv(4096))
        return bytes(body).split(b"\r\n\r\n", 1)[0].decode()

    def receive_json(self) -> dict:
        first, second = self.receive_exact(2)
        self.assert_frame(first & 0x0F == 1)
        self.assert_frame((second & 0x80) != 0)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.receive_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.receive_exact(8))[0]
        mask = self.receive_exact(4)
        body = self.receive_exact(length)
        decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(body))
        return json.loads(decoded)

    def receive_exact(self, length: int) -> bytes:
        body = bytearray()
        while len(body) < length:
            chunk = self.connection.recv(length - len(body))
            if not chunk:
                raise OSError("closed")
            body.extend(chunk)
        return bytes(body)

    def send_json(self, value: dict) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        if len(body) < 126:
            header = struct.pack("!BB", 0x81, len(body))
        elif len(body) < 2**16:
            header = struct.pack("!BBH", 0x81, 126, len(body))
        else:
            header = struct.pack("!BBQ", 0x81, 127, len(body))
        self.connection.sendall(header + body)

    def respond(self, command: dict) -> None:
        method = command["method"]
        result = {}
        if method == "Debugger.setBreakpointByUrl":
            self.breakpoint_index += 1
            result = {
                "breakpointId": f"breakpoint:{self.breakpoint_index}",
                "locations": [
                    {"scriptId": "script-1", "lineNumber": 3, "columnNumber": 0}
                ],
            }
        elif method == "Debugger.setBreakpoint":
            self.breakpoint_index += 1
            result = {
                "breakpointId": f"breakpoint:{self.breakpoint_index}",
                "actualLocation": command["params"]["location"],
            }
        elif method == "Debugger.getScriptSource":
            result = {"scriptSource": "function checkout(cart) { return cart; }"}
        elif method == "Runtime.evaluate":
            result = {
                "result": {
                    "type": "object",
                    "className": "Object",
                    "objectId": "prototype-1",
                }
            }
        elif method == "Runtime.queryObjects":
            result = {
                "result": {
                    "type": "object",
                    "subtype": "array",
                    "objectId": "objects-1",
                }
            }
        elif method == "Runtime.callFunctionOn":
            result = {
                "result": {
                    "type": "object",
                    "value": {
                        "protocolVersion": 1,
                        "analyzed": 17,
                        "totalObjects": 17,
                        "results": [
                            {
                                "id": "4",
                                "className": "CheckoutState",
                                "propertyCount": 2,
                                "propertiesTruncated": False,
                                "similarity": 0.875,
                                "preview": [
                                    {
                                        "name": "cart",
                                        "type": "object",
                                        "value": "[Object]",
                                    },
                                    {
                                        "name": "ready",
                                        "type": "boolean",
                                        "value": "true",
                                    },
                                ],
                            }
                        ],
                        "resultLimit": 50,
                        "resultLimitReached": False,
                        "scanLimitReached": False,
                        "timedOut": False,
                        "durationMs": 3,
                    },
                }
            }
        elif method == "Runtime.getProperties":
            result = {
                "result": [
                    {
                        "name": "cart",
                        "value": {
                            "type": "object",
                            "className": "Object",
                            "description": "Object",
                        },
                        "writable": True,
                        "enumerable": True,
                        "configurable": True,
                    }
                ]
            }
        elif method == "Debugger.evaluateOnCallFrame":
            result = {"result": {"type": "number", "value": 3, "description": "3"}}
        self.send_json({"id": command["id"], "result": result})
        if method == "Debugger.enable":
            self.send_json(
                {
                    "method": "Debugger.scriptParsed",
                    "params": {
                        "scriptId": "script-1",
                        "url": "https://checkout.test/cart.js",
                        "startLine": 0,
                        "startColumn": 0,
                        "endLine": 10,
                        "endColumn": 1,
                        "executionContextId": 1,
                        "hash": "abc",
                        "sourceMapURL": "cart.js.map",
                        "isModule": True,
                        "length": 42,
                        "scriptLanguage": "JavaScript",
                    },
                }
            )
        elif method == "Runtime.enable":
            self.send_json(
                {
                    "method": "Runtime.consoleAPICalled",
                    "params": {
                        "type": "log",
                        "timestamp": 1234.5,
                        "args": [{"type": "string", "value": "ready"}],
                        "stackTrace": {"callFrames": []},
                    },
                }
            )
        elif method == "Debugger.pause":
            self.send_json(
                {
                    "method": "Debugger.paused",
                    "params": {
                        "reason": "debugCommand",
                        "callFrames": [
                            {
                                "callFrameId": "frame-1",
                                "functionName": "checkout",
                                "url": "https://checkout.test/cart.js",
                                "location": {
                                    "scriptId": "script-1",
                                    "lineNumber": 3,
                                    "columnNumber": 2,
                                },
                                "scopeChain": [
                                    {
                                        "type": "local",
                                        "object": {
                                            "type": "object",
                                            "className": "Object",
                                            "description": "Local",
                                            "objectId": "scope-1",
                                        },
                                    }
                                ],
                                "this": {"type": "undefined"},
                            }
                        ],
                        "asyncStackTrace": {
                            "description": "Promise.then",
                            "callFrames": [
                                {
                                    "functionName": "submit",
                                    "scriptId": "script-1",
                                    "url": "https://checkout.test/cart.js",
                                    "lineNumber": 8,
                                    "columnNumber": 1,
                                }
                            ],
                        },
                        "hitBreakpoints": [],
                    },
                }
            )
        elif method in {
            "Debugger.resume",
            "Debugger.stepOver",
            "Debugger.stepInto",
            "Debugger.stepOut",
        }:
            self.send_json({"method": "Debugger.resumed", "params": {}})

    @staticmethod
    def assert_frame(condition: bool) -> None:
        if not condition:
            raise OSError("invalid frame")


class TargetHandler(BaseHTTPRequestHandler):
    web_socket_port = 0

    def do_GET(self) -> None:
        body = json.dumps(
            [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Checkout",
                    "url": "https://checkout.test/",
                    "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.web_socket_port}/devtools/page/page-1",
                }
            ]
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


class DebuggerBridgeTests(unittest.TestCase):
    def wait_for(self, predicate, timeout: float = 3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.01)
        self.fail("Timed out waiting for debugger state")

    def test_generation_wait_wakes_without_building_a_snapshot(self) -> None:
        bridge = DebuggerBridge()
        initial_generation = bridge.generation()
        started = threading.Event()
        result = []

        def wait_for_change() -> None:
            started.set()
            result.append(bridge.wait_for_change(initial_generation, 1.0))

        waiter = threading.Thread(target=wait_for_change)
        waiter.start()
        self.assertTrue(started.wait(timeout=1.0))
        bridge.action({"action": "clear_console"})
        waiter.join(timeout=1.0)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(result, [initial_generation + 1])
        self.assertEqual(bridge.state(), "unavailable")

    def test_real_protocol_state_drives_scripts_pause_scopes_watches_and_breakpoints(
        self,
    ) -> None:
        web_socket = FakeDebuggerWebSocket()
        TargetHandler.web_socket_port = web_socket.port
        target_server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_thread = threading.Thread(
            target=target_server.serve_forever, daemon=True
        )
        target_thread.start()
        with tempfile.TemporaryDirectory() as directory:
            active_port = Path(directory) / "DevToolsActivePort"
            active_port.write_text(
                f"{target_server.server_address[1]}\n/devtools/browser/test\n",
                encoding="utf-8",
            )
            bridge = DebuggerBridge(active_port)
            bridge.start()
            try:
                snapshot = self.wait_for(
                    lambda: (
                        (value := bridge.snapshot())["state"] == "running"
                        and value["scripts"]
                        and value
                    )
                )
                self.assertEqual(snapshot["target"]["title"], "Checkout")
                self.assertEqual(
                    snapshot["scripts"][0]["source_map_url"], "cart.js.map"
                )
                self.assertEqual(
                    snapshot["console"][0]["arguments"][0]["value"], "ready"
                )
                self.assertIn(
                    "Debugger.setAsyncCallStackDepth",
                    [command["method"] for command in web_socket.commands],
                )
                snapshot["scripts"][0]["url"] = "https://mutated.test/"
                snapshot["console"][0]["arguments"][0]["value"] = "mutated"
                snapshot["scripts"].clear()
                isolated = bridge.snapshot()
                self.assertEqual(len(isolated["scripts"]), 1)
                self.assertEqual(
                    isolated["scripts"][0]["url"],
                    "https://checkout.test/cart.js",
                )
                self.assertEqual(isolated["console"][0]["arguments"][0]["value"], "ready")

                bridge.action(
                    {"action": "add_watch", "expression": "cart.items.length"}
                )
                line_breakpoint = bridge.action(
                    {
                        "action": "set_breakpoint",
                        "url": "https://checkout.test/cart.js",
                        "line": 3,
                    }
                )
                anonymous = bridge.action(
                    {
                        "action": "set_breakpoint",
                        "url": "",
                        "script_id": "script-1",
                        "line": 4,
                    }
                )
                self.assertEqual(anonymous["breakpoint"]["script_id"], "script-1")
                bridge.action({"action": "pause"})
                paused = self.wait_for(
                    lambda: (
                        (value := bridge.snapshot())["state"] == "paused"
                        and value["paused"]["scope_coverage"]["status"] == "complete"
                        and value
                    )
                )
                self.assertEqual(
                    paused["paused"]["call_frames"][0]["function_name"], "checkout"
                )
                self.assertEqual(
                    paused["paused"]["call_frames"][0]["scopes"][0]["properties"][0][
                        "name"
                    ],
                    "cart",
                )
                self.assertEqual(
                    paused["paused"]["async_stack"][0]["description"], "Promise.then"
                )
                self.assertEqual(paused["watches"][0]["result"]["value"], 3)
                self.assertEqual(paused["breakpoints"][0]["locations"][0]["line"], 3)
                self.assertTrue(paused["limits"]["scope_properties"] > 0)

                source = bridge.get_script_source("script-1")
                self.assertIn("function checkout", source["source"])
                live_objects = bridge.action(
                    {
                        "action": "search_live_objects",
                        "property_query": "cart",
                        "shape": '{"cart":{},"ready":true}',
                        "similarity_threshold": 0.75,
                    }
                )
                self.assertEqual(live_objects["search"]["analyzed"], 17)
                self.assertEqual(
                    live_objects["search"]["results"][0]["class_name"],
                    "CheckoutState",
                )
                self.assertEqual(
                    live_objects["search"]["results"][0]["preview"][1],
                    {"name": "ready", "type": "boolean", "value": "true"},
                )
                methods = [command["method"] for command in web_socket.commands]
                self.assertIn("Runtime.queryObjects", methods)
                search_command = next(
                    command
                    for command in web_socket.commands
                    if command["method"] == "Runtime.callFunctionOn"
                )
                self.assertTrue(search_command["params"]["returnByValue"])
                self.assertTrue(search_command["params"]["silent"])
                self.assertTrue(search_command["params"]["throwOnSideEffect"])
                self.assertIn(
                    "Object.getOwnPropertyDescriptors",
                    search_command["params"]["functionDeclaration"],
                )
                self.assertIn("Runtime.releaseObject", methods)
                update = bridge.action(
                    {
                        "action": "update_breakpoint",
                        "breakpoint_id": line_breakpoint["breakpoint"]["id"],
                        "kind": "logpoint",
                        "expression": "cart.items.length",
                    }
                )
                updated = update["breakpoint"]
                self.assertEqual(updated["kind"], "logpoint")
                self.assertEqual(updated["expression"], "cart.items.length")
                bridge.action({"action": "step_over"})
                self.wait_for(lambda: bridge.snapshot()["state"] == "running")
            finally:
                bridge.stop()
        target_server.shutdown()
        target_server.server_close()
        target_thread.join(timeout=2)
        web_socket.close()

    def test_only_allowlisted_actions_and_known_scripts_are_accepted(self) -> None:
        bridge = DebuggerBridge()
        with self.assertRaisesRegex(DebuggerBridgeError, "not allowed"):
            bridge.action({"action": "Runtime.evaluate", "expression": "steal()"})
        with self.assertRaisesRegex(DebuggerBridgeError, "unavailable"):
            bridge.get_script_source("unknown")
        bridge._xhr_breakpoints = [f"xhr-{index}" for index in range(100)]
        with self.assertRaisesRegex(DebuggerBridgeError, "XHR breakpoint limit"):
            bridge.action({"action": "set_xhr_breakpoint", "pattern": "overflow"})
        bridge._event_breakpoints = [f"event-{index}" for index in range(256)]
        with self.assertRaisesRegex(DebuggerBridgeError, "Event breakpoint limit"):
            bridge.action({"action": "set_event_breakpoint", "event_name": "overflow"})
        remote = bridge._remote_object({"type": "string", "value": "é" * 4_096})
        self.assertTrue(remote["value_truncated"])
        self.assertLessEqual(len(remote["value"].encode("utf-8")), 4_096)
        nonfinite = bridge._remote_object({"type": "number", "value": float("inf")})
        self.assertIsNone(nonfinite["value"])

    def test_live_object_search_rejects_unbounded_or_empty_criteria(self) -> None:
        bridge = DebuggerBridge()
        with self.assertRaisesRegex(DebuggerBridgeError, "at least one criterion"):
            bridge.action({"action": "search_live_objects"})
        with self.assertRaisesRegex(DebuggerBridgeError, "valid JSON"):
            bridge.action({"action": "search_live_objects", "shape": "{"})
        with self.assertRaisesRegex(DebuggerBridgeError, "object or array"):
            bridge.action({"action": "search_live_objects", "shape": '"value"'})
        with self.assertRaisesRegex(DebuggerBridgeError, "between 0 and 1"):
            bridge.action(
                {
                    "action": "search_live_objects",
                    "property_query": "cart",
                    "similarity_threshold": 2,
                }
            )
        with self.assertRaisesRegex(DebuggerBridgeError, "512 bytes"):
            bridge.action(
                {"action": "search_live_objects", "property_query": "x" * 513}
            )

    def test_live_object_search_matches_shape_without_invoking_getters(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        exercise = f"""
const search = ({LIVE_OBJECT_SEARCH_FUNCTION});
const criteria = overrides => ({{
  propertyQuery: '', valueQuery: '', classQuery: '', regex: false,
  caseSensitive: false, shape: null, includeShapeValues: false,
  similarityThreshold: 0.75, resultLimit: 50, scanLimit: 25000,
  previewProperties: 16, timeoutMs: 750, ...overrides
}});
let getterCalls = 0;
const accessor = {{token: 'visible'}};
Object.defineProperty(accessor, 'secret', {{
  enumerable: true,
  get() {{ getterCalls += 1; return 'must-not-run'; }}
}});
const shaped = {{device: {{fingerprint: 'abc'}}, ready: true}};
const propertyResult = search.call([accessor], criteria({{propertyQuery: 'secret'}}));
const shapeResult = search.call([shaped], criteria({{
  shape: {{device: {{fingerprint: ''}}, ready: false}},
  similarityThreshold: 1
}}));
const boundedResult = search.call(
  Array.from({{length: 100}}, (_, index) => ({{match: index}})),
  criteria({{propertyQuery: 'match', resultLimit: 5, scanLimit: 10}})
);
process.stdout.write(JSON.stringify({{
  getterCalls,
  accessorPreview: propertyResult.results[0].preview.find(item => item.name === 'secret'),
  shapeMatches: shapeResult.results.length,
  similarity: shapeResult.results[0].similarity,
  partial: shapeResult.scanLimitReached || shapeResult.timedOut,
  boundedMatches: boundedResult.results.length,
  boundedAnalyzed: boundedResult.analyzed,
  resultLimitReached: boundedResult.resultLimitReached,
  boundedSearchIsPartial: boundedResult.scanLimitReached
}}));
"""
        completed = subprocess.run(
            [node, "-e", exercise],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "getterCalls": 0,
                "accessorPreview": {
                    "name": "secret",
                    "type": "accessor",
                    "value": "<getter not invoked>",
                },
                "shapeMatches": 1,
                "similarity": 1,
                "partial": False,
                "boundedMatches": 5,
                "boundedAnalyzed": 5,
                "resultLimitReached": True,
                "boundedSearchIsPartial": True,
            },
        )

    def test_live_object_search_rejects_oversized_target_results(self) -> None:
        bridge = DebuggerBridge()
        valid = {
            "protocolVersion": 1,
            "analyzed": 1,
            "totalObjects": 1,
            "results": [],
            "resultLimit": 50,
            "resultLimitReached": False,
            "scanLimitReached": False,
            "timedOut": False,
            "durationMs": 1,
        }
        oversized_results = dict(valid, results=[{}] * 51)
        with self.assertRaisesRegex(DebuggerBridgeError, "too many"):
            bridge._normalize_live_object_search(oversized_results)
        oversized_preview = dict(
            valid,
            results=[
                {
                    "id": "1",
                    "className": "Object",
                    "propertyCount": 17,
                    "propertiesTruncated": True,
                    "similarity": None,
                    "preview": [
                        {"name": "x", "type": "string", "value": "x"}
                    ]
                    * 17,
                }
            ],
        )
        with self.assertRaisesRegex(DebuggerBridgeError, "malformed"):
            bridge._normalize_live_object_search(oversized_preview)


if __name__ == "__main__":
    unittest.main()
