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
from typing import Optional

from debugger_bridge import (
    LIVE_OBJECT_SEARCH_FUNCTION,
    MAX_HEAP_SNAPSHOT_BYTES,
    REQUEST_INTERCEPTION_FUNCTION,
    DebuggerBridge,
    DebuggerBridgeError,
    HeapSnapshotCapture,
    HeapSnapshotCollector,
    ProtocolError,
)


HEAP_SNAPSHOT_FIXTURE = """{
  "snapshot":{"meta":{
    "node_fields":["type","name","id","self_size","edge_count"],
    "node_types":[["hidden","array","string","object","code","closure","synthetic"],"string","number","number","number"],
    "edge_fields":["type","name_or_index","to_node"],
    "edge_types":[["context","element","property","internal","hidden","shortcut","weak"],"string_or_number","node"]
  },"node_count":3,"edge_count":2},
  "nodes":[6,0,1,0,1,3,1,3,64,1,2,2,5,24,0],
  "edges":[2,3,5,2,4,10],
  "strings":["","CheckoutState","secret-value","app","token"]
}"""


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
            if 'credentials: "omit"' in command["params"].get("expression", ""):
                self.send_json(
                    {
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "protocol-intercept-1",
                            "resourceType": "Fetch",
                            "request": {
                                "url": "https://api.test/checkout?secret=hidden",
                                "method": "POST",
                                "headers": {"x-experiment": "1"},
                            },
                        },
                    }
                )
                result = {
                    "result": {
                        "type": "object",
                        "value": {
                            "protocolVersion": 1,
                            "ok": True,
                            "status": 202,
                            "statusText": "Accepted",
                            "url": "https://api.test/checkout?secret=hidden",
                            "headers": [
                                {"name": "content-type", "value": "application/json"}
                            ],
                            "headersTruncated": False,
                            "body": '{"accepted":true}',
                            "bodyTruncated": False,
                        },
                    }
                }
            else:
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
                        "protocolVersion": 2,
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
                        "propertyLimitReached": False,
                        "timedOut": False,
                        "durationMs": 3,
                    },
                }
            }
        elif method == "HeapProfiler.takeHeapSnapshot":
            self.send_json(
                {
                    "method": "HeapProfiler.addHeapSnapshotChunk",
                    "params": {"chunk": HEAP_SNAPSHOT_FIXTURE},
                }
            )
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
        elif (
            method == "DOMDebugger.setEventListenerBreakpoint"
            and command["params"].get("eventName") == "click"
        ):
            self.send_json(
                {
                    "method": "Debugger.paused",
                    "params": {
                        "reason": "EventListener",
                        "callFrames": [
                            {
                                "callFrameId": "origin-frame-1",
                                "functionName": "createCheckoutToken",
                                "url": "https://checkout.test/cart.js",
                                "location": {
                                    "scriptId": "script-1",
                                    "lineNumber": 7,
                                    "columnNumber": 4,
                                },
                                "scopeChain": [],
                                "this": {"type": "undefined"},
                            }
                        ],
                        "hitBreakpoints": [],
                    },
                }
            )

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
        self.addCleanup(web_socket.close)
        self.addCleanup(target_thread.join, timeout=2)
        self.addCleanup(target_server.server_close)
        self.addCleanup(target_server.shutdown)
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
                    "Object.getOwnPropertyNames",
                    search_command["params"]["functionDeclaration"],
                )
                self.assertIn(
                    "Object.getOwnPropertyDescriptor",
                    search_command["params"]["functionDeclaration"],
                )
                self.assertNotIn(
                    "Object.getOwnPropertyDescriptors",
                    search_command["params"]["functionDeclaration"],
                )
                self.assertEqual(
                    search_command["params"]["arguments"][0]["value"][
                        "propertyScanLimit"
                    ],
                    256,
                )
                self.assertIn("Runtime.releaseObject", methods)
                heap_snapshot = bridge.action(
                    {
                        "action": "search_heap_snapshot",
                        "query": "secret-value",
                        "case_sensitive": False,
                    }
                )
                self.assertEqual(heap_snapshot["snapshot"]["total_nodes"], 3)
                self.assertEqual(heap_snapshot["snapshot"]["protocol_version"], 2)
                self.assertEqual(heap_snapshot["snapshot"]["scope"], "all")
                self.assertEqual(
                    heap_snapshot["snapshot"]["results"][0]["name"],
                    "secret-value",
                )
                self.assertEqual(
                    [
                        step["edge"]
                        for step in heap_snapshot["snapshot"]["results"][0][
                            "retaining_path"
                        ]
                    ],
                    ["app", "token"],
                )
                self.assertTrue(
                    heap_snapshot["snapshot"]["results"][0]["reachable"]
                )
                self.assertEqual(
                    heap_snapshot["snapshot"]["results"][0][
                        "incoming_reference_count"
                    ],
                    1,
                )
                self.assertEqual(
                    heap_snapshot["snapshot"]["results"][0][
                        "incoming_references"
                    ][0]["edge"],
                    "token",
                )
                self.assertIn(
                    "HeapProfiler.takeHeapSnapshot",
                    [command["method"] for command in web_socket.commands],
                )
                baseline = bridge.action(
                    {"action": "capture_heap_diff_baseline"}
                )
                self.assertEqual(baseline["baseline"]["target_id"], "page-1")
                self.assertGreater(baseline["baseline"]["file_bytes"], 0)
                heap_diff = bridge.action({"action": "compare_heap_diff"})
                self.assertEqual(heap_diff["diff"]["self_size_delta"], 0)
                self.assertEqual(heap_diff["diff"]["groups"], [])
                self.assertEqual(heap_diff["diff"]["dominators"], [])
                bridge.action({"action": "clear_heap_diff_baseline"})
                self.assertIsNone(bridge.snapshot()["heap_diff_baseline"])
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
                started_trace = bridge.action(
                    {
                        "action": "start_memory_origin_trace",
                        "query": "secret-value",
                        "scope": "all",
                        "before_steps": 0,
                        "after_steps": 0,
                    }
                )
                self.assertIn(
                    started_trace["trace"]["state"], {"armed", "capturing", "found"}
                )
                traced = self.wait_for(
                    lambda: (
                        (value := bridge.snapshot())["memory_origin_trace"]["state"]
                        == "found"
                        and value
                    ),
                    timeout=10.0,
                )
                origin_trace = traced["memory_origin_trace"]
                self.assertEqual(origin_trace["first_match_step"], 1)
                self.assertEqual(origin_trace["step_count"], 1)
                self.assertEqual(len(origin_trace["steps"]), 1)
                self.assertTrue(origin_trace["steps"][0]["is_first_match"])
                self.assertEqual(
                    origin_trace["steps"][0]["location"]["function_name"],
                    "createCheckoutToken",
                )
                self.assertEqual(
                    origin_trace["steps"][0]["match"]["name"], "secret-value"
                )
                self.assertEqual(origin_trace["steps"][0]["indexed_edges"], 0)
                self.wait_for(
                    lambda: any(
                        command["method"]
                        == "DOMDebugger.removeEventListenerBreakpoint"
                        for command in web_socket.commands
                    )
                )
                methods = [command["method"] for command in web_socket.commands]
                self.assertIn("DOMDebugger.setEventListenerBreakpoint", methods)
                self.assertIn("DOMDebugger.removeEventListenerBreakpoint", methods)
                self.wait_for(lambda: bridge.snapshot()["state"] == "running")

                with bridge._lock:
                    bridge._request_interception_context_id = "context-protocol"
                    bridge._request_interception_return_target_id = "page-1"
                    bridge._request_interception = bridge._empty_request_interception()
                    bridge._request_interception.update(
                        {
                            "experiment_id": 1,
                            "state": "ready",
                            "isolated": True,
                            "target_id": "page-1",
                            "created_at_ms": 1,
                            "message": "Protocol fixture ready.",
                        }
                    )
                bridge._restore_request_interception("page-1")
                bridge.action(
                    {
                        "action": "configure_request_interception",
                        "mode": "fulfill",
                        "url_pattern": "https://api.test/*",
                        "method_filter": "POST",
                        "response_code": 202,
                        "response_headers": {"content-type": "application/json"},
                        "response_body": '{"accepted":true}',
                    }
                )
                experiment_result = bridge.action(
                    {
                        "action": "run_request_interception",
                        "url": "https://api.test/checkout?secret=hidden",
                        "method": "POST",
                        "headers": {"x-experiment": "1"},
                        "body": "{}",
                    }
                )["experiment"]
                self.assertEqual(experiment_result["result"]["status"], 202)
                self.assertEqual(
                    experiment_result["result"]["url"],
                    "https://api.test/checkout",
                )
                protocol_audit = self.wait_for(
                    lambda: (
                        (value := bridge.snapshot()["request_interception"])["audit"]
                        and value
                    )
                )["audit"][-1]
                self.assertEqual(protocol_audit["outcome"], "fulfilled")
                self.assertNotIn("secret", protocol_audit["url"])
                methods = [command["method"] for command in web_socket.commands]
                self.assertIn("Fetch.enable", methods)
                self.assertIn("Fetch.fulfillRequest", methods)
                with bridge._lock:
                    bridge._request_interception_context_id = None
                    bridge._request_interception_return_target_id = None
                    bridge._request_interception_pending.clear()
                    bridge._request_interception = bridge._empty_request_interception()
            finally:
                bridge.stop()

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
  previewProperties: 16, propertyScanLimit: 256, timeoutMs: 750, ...overrides
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
const propertyBounded = Object.fromEntries(
  Array.from({{length: 300}}, (_, index) => [`property${{index}}`, index])
);
const propertyBoundedResult = search.call(
  [propertyBounded], criteria({{propertyQuery: 'property299'}})
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
  boundedSearchIsPartial: boundedResult.scanLimitReached,
  propertyBoundedMatches: propertyBoundedResult.results.length,
  propertyLimitReached: propertyBoundedResult.propertyLimitReached
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
                "propertyBoundedMatches": 0,
                "propertyLimitReached": True,
            },
        )

    def test_live_object_search_rejects_oversized_target_results(self) -> None:
        bridge = DebuggerBridge()
        valid = {
            "protocolVersion": 2,
            "analyzed": 1,
            "totalObjects": 1,
            "results": [],
            "resultLimit": 50,
            "resultLimitReached": False,
            "scanLimitReached": False,
            "propertyLimitReached": False,
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

    def test_heap_snapshot_search_rejects_oversized_capture_and_native_output(
        self,
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="wb") as stream:
            collector = HeapSnapshotCollector(Path(stream.name), stream)
            collector.byte_count = MAX_HEAP_SNAPSHOT_BYTES - 1
            collector.append("xx")
            self.assertEqual(
                collector.error,
                "Heap snapshot exceeds the 256 MiB capture limit",
            )

        bridge = DebuggerBridge()
        valid = {
            "protocol_version": 2,
            "file_bytes": 10,
            "total_nodes": 1,
            "analyzed_nodes": 1,
            "matched_nodes": 0,
            "reachable_nodes": 1,
            "total_edges": 0,
            "indexed_edges": 0,
            "total_strings": 1,
            "duration_ms": 1,
            "result_limit": 50,
            "reference_limit": 12,
            "scope": "all",
            "result_limit_reached": False,
            "node_limit_reached": False,
            "edge_limit_reached": False,
            "string_limit_reached": False,
            "retaining_paths_partial": False,
            "results": [],
        }
        oversized_path = dict(
            valid,
            matched_nodes=1,
            results=[
                {
                    "id": "1",
                    "type": "string",
                    "name": "value",
                    "self_size": 10,
                    "reachable": True,
                    "incoming_reference_count": 0,
                    "incoming_reference_limit_reached": False,
                    "retaining_path_complete": False,
                    "retaining_path": [
                        {
                            "edge_type": "property",
                            "edge": "x",
                            "type": "object",
                            "name": "x",
                        }
                    ]
                    * 13,
                    "incoming_references": [],
                }
            ],
        )
        with self.assertRaisesRegex(DebuggerBridgeError, "malformed result"):
            bridge._normalize_heap_snapshot_search(oversized_path)

        with self.assertRaisesRegex(DebuggerBridgeError, "scope"):
            bridge._search_heap_snapshot({"query": "token", "scope": []})

        malformed_reference = dict(
            valid,
            matched_nodes=1,
            results=[
                {
                    "id": "1",
                    "type": "string",
                    "name": "value",
                    "self_size": 10,
                    "reachable": False,
                    "incoming_reference_count": 1,
                    "incoming_reference_limit_reached": False,
                    "retaining_path_complete": False,
                    "retaining_path": [],
                    "incoming_references": [
                        {
                            "source_id": "01",
                            "edge_type": "weak",
                            "edge": "value",
                            "source_type": "hidden",
                            "source_name": "owner",
                        }
                    ],
                }
            ],
        )
        with self.assertRaisesRegex(ProtocolError, "incoming reference"):
            bridge._normalize_heap_snapshot_search(malformed_reference)

        scope_mismatch = dict(malformed_reference, scope="reachable")
        scope_mismatch["results"] = [
            dict(malformed_reference["results"][0], incoming_references=[])
        ]
        scope_mismatch["results"][0]["incoming_reference_count"] = 0
        with self.assertRaisesRegex(ProtocolError, "malformed result"):
            bridge._normalize_heap_snapshot_search(scope_mismatch)

    def test_heap_snapshot_capture_failure_closes_debugger_connection(self) -> None:
        class RecordingConnection:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        class FailingCaptureBridge(DebuggerBridge):
            def _command(self, *_args, **_kwargs) -> dict:
                raise DebuggerBridgeError("capture failed")

        connection = RecordingConnection()
        bridge = FailingCaptureBridge(heap_snapshot_binary=Path("/usr/bin/true"))
        bridge._connection = connection
        bridge._target = {"id": "page-1"}

        with self.assertRaisesRegex(DebuggerBridgeError, "capture failed"):
            bridge._search_heap_snapshot({"query": "token"})

        self.assertTrue(connection.closed)
        self.assertIsNone(bridge._heap_snapshot_collector)

    def test_memory_origin_trace_rejects_invalid_limits_and_probe_documents(
        self,
    ) -> None:
        bridge = DebuggerBridge()
        with self.assertRaisesRegex(DebuggerBridgeError, "tolerance window"):
            bridge.action(
                {
                    "action": "start_memory_origin_trace",
                    "query": "token",
                    "before_steps": 9,
                }
            )

        valid = {
            "protocol_version": 1,
            "file_bytes": 10,
            "total_nodes": 4,
            "analyzed_nodes": 3,
            "reachable_nodes": 0,
            "total_edges": 3,
            "indexed_edges": 0,
            "total_strings": 7,
            "duration_ms": 1,
            "scope": "all",
            "match_found": True,
            "reachability_indexed": False,
            "node_limit_reached": False,
            "edge_limit_reached": False,
            "string_limit_reached": False,
            "match": {
                "id": "5",
                "type": "string",
                "name": "secret-value",
                "self_size": 24,
            },
        }
        normalized = bridge._normalize_heap_snapshot_probe(valid)
        self.assertTrue(normalized["match_found"])
        self.assertEqual(normalized["match"]["id"], "5")

        with self.assertRaisesRegex(ProtocolError, "invalid coverage"):
            bridge._normalize_heap_snapshot_probe(
                dict(valid, reachability_indexed=True, indexed_edges=3)
            )
        with self.assertRaisesRegex(ProtocolError, "malformed match"):
            bridge._normalize_heap_snapshot_probe(
                dict(valid, match={**valid["match"], "id": "05"})
            )
        with self.assertRaisesRegex(ProtocolError, "malformed match"):
            bridge._normalize_heap_snapshot_probe(
                dict(
                    valid,
                    match_found=False,
                    match=valid["match"],
                    analyzed_nodes=4,
                )
            )
        with self.assertRaisesRegex(ProtocolError, "invalid coverage"):
            bridge._normalize_heap_snapshot_probe(
                dict(
                    valid,
                    match_found=False,
                    match=None,
                    analyzed_nodes=3,
                )
            )

    def test_memory_origin_trace_keeps_bounded_before_and_after_window(self) -> None:
        def probe_document(found: bool) -> dict:
            return {
                "protocol_version": 1,
                "file_bytes": 10,
                "total_nodes": 4,
                "analyzed_nodes": 3 if found else 4,
                "reachable_nodes": 0,
                "total_edges": 3,
                "indexed_edges": 0,
                "total_strings": 7,
                "duration_ms": 1,
                "scope": "all",
                "match_found": found,
                "reachability_indexed": False,
                "node_limit_reached": False,
                "edge_limit_reached": False,
                "string_limit_reached": False,
                "match": {
                    "id": "5",
                    "type": "string",
                    "name": "secret-value",
                    "self_size": 24,
                }
                if found
                else None,
            }

        class TemporalBridge(DebuggerBridge):
            def __init__(self) -> None:
                super().__init__(heap_snapshot_binary=Path("/usr/bin/true"))
                self.documents = [
                    probe_document(False),
                    probe_document(False),
                    probe_document(False),
                    probe_document(True),
                    probe_document(True),
                ]
                self.capture_paths = []
                self.commands = []
                self._state = "running"
                self._target = {
                    "id": "page-1",
                    "type": "page",
                    "title": "Checkout",
                    "url": "https://checkout.test/",
                }

            def _heap_snapshot_binary(self) -> Path:
                return Path("/usr/bin/true")

            def _capture_heap_snapshot(self) -> HeapSnapshotCapture:
                temporary = tempfile.NamedTemporaryFile(delete=False)
                temporary.write(b"snapshot")
                temporary.close()
                path = Path(temporary.name)
                self.capture_paths.append(path)
                return HeapSnapshotCapture(path, "page-1", 8, 1)

            def _run_native_heap_snapshot(self, *_args, **_kwargs) -> dict:
                return self.documents.pop(0)

            def _command(self, method: str, *_args, **_kwargs) -> dict:
                self.commands.append(method)
                if method in {"Debugger.stepOut", "Debugger.resume"}:
                    self._handle_event("Debugger.resumed", {})
                return {}

        bridge = TemporalBridge()
        started = bridge.action(
            {
                "action": "start_memory_origin_trace",
                "query": "secret-value",
                "before_steps": 2,
                "after_steps": 1,
            }
        )
        self.assertEqual(started["trace"]["state"], "armed")

        def pause(step: int) -> None:
            bridge._handle_event(
                "Debugger.paused",
                {
                    "reason": "step",
                    "callFrames": [
                        {
                            "callFrameId": f"frame-{step}",
                            "functionName": f"boundary{step}",
                            "url": "https://checkout.test/cart.js",
                            "location": {
                                "scriptId": "script-1",
                                "lineNumber": step,
                                "columnNumber": 0,
                            },
                            "scopeChain": [],
                            "this": {"type": "undefined"},
                        }
                    ],
                    "hitBreakpoints": [],
                },
            )

        for step in range(1, 5):
            pause(step)
            self.wait_for(
                lambda: bridge.snapshot()["memory_origin_trace"]["step_count"]
                == step
                and bridge.snapshot()["memory_origin_trace"]["state"] == "stepping"
            )
        pause(5)
        trace = self.wait_for(
            lambda: (
                (value := bridge.snapshot()["memory_origin_trace"])["state"]
                == "found"
                and value
            )
        )
        self.assertEqual(trace["first_match_step"], 4)
        self.assertEqual(trace["step_count"], 5)
        self.assertEqual([step["step"] for step in trace["steps"]], [2, 3, 4, 5])
        self.assertEqual(
            [step["is_first_match"] for step in trace["steps"]],
            [False, False, True, False],
        )
        self.assertTrue(all(not path.exists() for path in bridge.capture_paths))
        self.assertEqual(bridge.documents, [])
        self.assertIn("DOMDebugger.removeEventListenerBreakpoint", bridge.commands)

    def test_request_interception_is_isolated_bounded_and_audited(self) -> None:
        class RecordingConnection:
            def __init__(self) -> None:
                self.closed = False

            def close(self) -> None:
                self.closed = True

        class InterceptionBridge(DebuggerBridge):
            def __init__(self) -> None:
                super().__init__()
                self.browser_commands = []
                self.commands = []
                self._state = "running"
                self._target = {
                    "id": "baseline-page",
                    "type": "page",
                    "title": "Baseline",
                    "url": "https://baseline.test/",
                }
                self.recording_connection = RecordingConnection()
                self._connection = self.recording_connection

            def _browser_command(self, method: str, params=None) -> dict:
                self.browser_commands.append((method, params or {}))
                if method == "Target.createBrowserContext":
                    return {"browserContextId": "context-1"}
                if method == "Target.createTarget":
                    return {"targetId": "experiment-page"}
                return {}

            def _command(self, method: str, params=None, timeout: float = 3.0) -> dict:
                self.commands.append((method, params or {}, timeout))
                if method == "Runtime.evaluate":
                    self._handle_request_interception_pause_async(
                        {
                            "requestId": "intercept-run",
                            "resourceType": "Fetch",
                            "request": {
                                "url": "https://api.test/private?token=secret",
                                "method": "POST",
                                "headers": {"x-visible": "yes"},
                            },
                        }
                    )
                    return {
                        "result": {
                            "value": {
                                "protocolVersion": 1,
                                "ok": True,
                                "status": 202,
                                "statusText": "Accepted",
                                "url": "https://api.test/private?token=secret",
                                "headers": [
                                    {"name": "content-type", "value": "text/plain"}
                                ],
                                "headersTruncated": False,
                                "body": "synthetic",
                                "bodyTruncated": False,
                            }
                        }
                    }
                return {}

        bridge = InterceptionBridge()
        created = bridge.action({"action": "create_request_interception_experiment"})
        self.assertTrue(created["experiment"]["isolated"])
        self.assertEqual(created["experiment"]["state"], "creating")
        self.assertTrue(bridge.recording_connection.closed)
        self.assertEqual(
            [method for method, _ in bridge.browser_commands[:2]],
            ["Target.createBrowserContext", "Target.createTarget"],
        )

        bridge._target = {
            "id": "experiment-page",
            "type": "page",
            "title": "about:blank",
            "url": "about:blank",
        }
        bridge._connection = RecordingConnection()
        bridge._restore_request_interception("experiment-page")
        self.assertEqual(bridge.snapshot()["request_interception"]["state"], "ready")

        cases = [
            ({"mode": "continue"}, "Fetch.continueRequest", None),
            ({"mode": "block"}, "Fetch.failRequest", "BlockedByClient"),
            ({"mode": "drop"}, "Fetch.failRequest", "Aborted"),
            (
                {
                    "mode": "rewrite",
                    "rewrite_method": "PUT",
                    "rewrite_headers": {"x-experiment": "1"},
                    "rewrite_body": "changed",
                },
                "Fetch.continueRequest",
                None,
            ),
            (
                {
                    "mode": "fulfill",
                    "response_code": 202,
                    "response_headers": {"content-type": "text/plain"},
                    "response_body": "synthetic",
                },
                "Fetch.fulfillRequest",
                None,
            ),
        ]
        for index, (rule, expected_method, expected_reason) in enumerate(cases, 1):
            bridge.action(
                {
                    "action": "configure_request_interception",
                    "url_pattern": "https://api.test/*",
                    "method_filter": "POST",
                    **rule,
                }
            )
            request_id = f"intercept-{index}"
            bridge._handle_request_interception_pause_async(
                {
                    "requestId": request_id,
                    "resourceType": "Fetch",
                    "request": {
                        "url": "https://api.test/private?token=secret",
                        "method": "POST",
                        "headers": {"authorization": "must-not-copy"},
                    },
                }
            )
            self.wait_for(
                lambda: bridge.snapshot()["request_interception"]["pending_requests"]
                == 0
                and bridge.snapshot()["request_interception"]["audit"][-1]["request_id"]
                == request_id
            )
            command = next(
                entry
                for entry in reversed(bridge.commands)
                if entry[1].get("requestId") == request_id
            )
            self.assertEqual(command[0], expected_method)
            self.assertEqual(command[1].get("errorReason"), expected_reason)
        rewrite_command = next(
            entry
            for entry in bridge.commands
            if entry[1].get("requestId") == "intercept-4"
        )
        self.assertEqual(rewrite_command[1]["method"], "PUT")
        self.assertEqual(base64.b64decode(rewrite_command[1]["postData"]), b"changed")

        bridge._handle_request_interception_pause_async(
            {
                "requestId": "intercept-preflight",
                "resourceType": "Fetch",
                "request": {
                    "url": "https://api.test/private?token=secret",
                    "method": "OPTIONS",
                    "headers": {
                        "access-control-request-method": "POST",
                        "access-control-request-headers": "content-type, x-test",
                    },
                },
            }
        )
        self.wait_for(
            lambda: bridge.snapshot()["request_interception"]["audit"][-1][
                "request_id"
            ]
            == "intercept-preflight"
        )
        preflight_command = next(
            entry
            for entry in bridge.commands
            if entry[1].get("requestId") == "intercept-preflight"
        )
        self.assertEqual(preflight_command[0], "Fetch.fulfillRequest")
        self.assertEqual(preflight_command[1]["responseCode"], 204)
        self.assertIn(
            {
                "name": "access-control-allow-headers",
                "value": "content-type, x-test",
            },
            preflight_command[1]["responseHeaders"],
        )

        completed = bridge.action(
            {
                "action": "run_request_interception",
                "url": "https://api.test/private?token=secret",
                "method": "POST",
                "headers": {"x-test": "1"},
                "body": "request",
            }
        )
        experiment = completed["experiment"]
        self.assertEqual(experiment["result"]["status"], 202)
        self.assertEqual(experiment["result"]["url"], "https://api.test/private")
        self.assertEqual(experiment["last_request"]["url"], "https://api.test/private")
        self.wait_for(
            lambda: bridge.snapshot()["request_interception"]["pending_requests"] == 0
        )
        self.assertTrue(
            all(
                "token" not in entry["url"]
                for entry in bridge.snapshot()["request_interception"]["audit"]
            )
        )

        disposed = bridge.action({"action": "dispose_request_interception_experiment"})
        self.assertEqual(disposed["experiment"]["state"], "disposed")
        self.assertFalse(disposed["experiment"]["isolated"])
        self.assertIsNone(disposed["experiment"]["target_id"])
        self.assertEqual(
            bridge.browser_commands[-1],
            (
                "Target.disposeBrowserContext",
                {"browserContextId": "context-1"},
            ),
        )
        bridge.action({"action": "clear_request_interception_result"})
        self.assertEqual(bridge.snapshot()["request_interception"]["state"], "idle")

    def test_request_interception_rejects_credentials_and_unbounded_rules(self) -> None:
        bridge = DebuggerBridge()
        self.assertEqual(
            bridge._redacted_request_url(
                "https://user:password@[2001:db8::1]:8443/private?token=secret"
            ),
            "https://[2001:db8::1]:8443/private",
        )
        self.assertEqual(
            bridge._normalize_request_interception_request(
                {"url": "https://example.test/", "method": "CUSTOM_METHOD"}
            )["method"],
            "CUSTOM_METHOD",
        )
        bridge._handle_request_interception_pause_async(
            {
                "requestId": "inactive-request",
                "resourceType": "Fetch",
                "request": {"url": "https://example.test/", "method": "GET"},
            }
        )
        self.assertEqual(bridge.snapshot()["request_interception"]["audit"], [])
        fulfill_rule = bridge._normalize_request_interception_rule(
            {
                "mode": "fulfill",
                "url_pattern": "*",
                "response_headers": {"content-type": "application/json"},
                "response_body": "{}",
            }
        )
        self.assertIn(
            {"name": "access-control-allow-origin", "value": "*"},
            fulfill_rule["response_headers"],
        )
        with self.assertRaisesRegex(DebuggerBridgeError, "credential-free"):
            bridge._normalize_request_interception_request(
                {
                    "url": "https://user:password@example.test/",
                    "method": "GET",
                }
            )
        with self.assertRaisesRegex(DebuggerBridgeError, "forbidden"):
            bridge._normalize_request_interception_request(
                {
                    "url": "https://example.test/",
                    "method": "GET",
                    "headers": {"Authorization": "secret"},
                }
            )
        with self.assertRaisesRegex(DebuggerBridgeError, "64 KiB"):
            bridge._normalize_request_interception_rule(
                {
                    "mode": "fulfill",
                    "url_pattern": "*",
                    "response_body": "x" * (64 * 1024 + 1),
                }
            )
        with self.assertRaisesRegex(DebuggerBridgeError, "at least one"):
            bridge._normalize_request_interception_rule(
                {"mode": "rewrite", "url_pattern": "*"}
            )
        with self.assertRaisesRegex(ProtocolError, "malformed"):
            bridge._normalize_request_interception_result(
                {
                    "protocolVersion": 1,
                    "ok": True,
                    "status": 200,
                    "statusText": "OK",
                    "url": "https://example.test/",
                    "headers": [{"name": "set-cookie", "value": "secret=1"}],
                    "headersTruncated": False,
                    "body": "ok",
                    "bodyTruncated": False,
                }
            )

    def test_partial_request_interception_context_remains_disposable(self) -> None:
        class PartialContextBridge(DebuggerBridge):
            def __init__(self) -> None:
                super().__init__()
                self._state = "running"
                self._target = {
                    "id": "baseline-page",
                    "type": "page",
                    "title": "Baseline",
                    "url": "https://baseline.test/",
                }
                self.cleanup_fails = True

            def _browser_command(self, method: str, params=None) -> dict:
                if method == "Target.createBrowserContext":
                    return {"browserContextId": "partial-context"}
                if method == "Target.createTarget":
                    raise DebuggerBridgeError("Target creation failed")
                if method == "Target.disposeBrowserContext" and self.cleanup_fails:
                    raise DebuggerBridgeError("Context disposal failed")
                return {}

        bridge = PartialContextBridge()
        with self.assertRaisesRegex(DebuggerBridgeError, "Target creation failed"):
            bridge.action({"action": "create_request_interception_experiment"})
        failed = bridge.snapshot()["request_interception"]
        self.assertEqual(failed["state"], "error")
        self.assertTrue(failed["isolated"])
        self.assertIsNone(failed["target_id"])
        self.assertIn("could not be confirmed as deleted", failed["message"])

        bridge.cleanup_fails = False
        disposed = bridge.action({"action": "dispose_request_interception_experiment"})[
            "experiment"
        ]
        self.assertEqual(disposed["state"], "disposed")
        self.assertFalse(disposed["isolated"])

    def test_request_interception_runner_streams_only_the_bounded_response(
        self,
    ) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        exercise = f"""
const run = ({REQUEST_INTERCEPTION_FUNCTION});
let reads = 0;
let cancellations = 0;
let capturedOptions = null;
globalThis.fetch = async (_url, options) => {{
  capturedOptions = options;
  const oversized = new Uint8Array(80 * 1024);
  oversized.fill(97);
  return {{
    status: 202,
    statusText: 'Accepted',
    url: 'https://api.test/result?private=1',
    headers: new Map([['content-type', 'text/plain']]),
    body: {{getReader() {{ return {{
      async read() {{ reads += 1; return {{done: false, value: oversized}}; }},
      async cancel() {{ cancellations += 1; }}
    }}; }}}}
  }};
}};
const result = await run({{
  url: 'https://api.test/result', method: 'POST', headers: {{'x-test': '1'}},
  body: 'request', timeoutMs: 1000, headerLimit: 64,
  headerValueLimit: 2048, headerTotalLimit: 16384, responseByteLimit: 65536
}});
process.stdout.write(JSON.stringify({{
  ok: result.ok,
  bodyBytes: new TextEncoder().encode(result.body).byteLength,
  truncated: result.bodyTruncated,
  headersTruncated: result.headersTruncated,
  reads,
  cancellations,
  credentials: capturedOptions.credentials,
  cache: capturedOptions.cache,
  referrerPolicy: capturedOptions.referrerPolicy
}}));
"""
        completed = subprocess.run(
            [node, "-e", exercise],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "ok": True,
                "bodyBytes": 65_536,
                "truncated": True,
                "headersTruncated": False,
                "reads": 1,
                "cancellations": 1,
                "credentials": "omit",
                "cache": "no-store",
                "referrerPolicy": "no-referrer",
            },
        )

    def test_repeater_resolves_cancels_compares_and_bounds_history(self) -> None:
        class RecordingConnection:
            def close(self) -> None:
                return

        class RepeaterBridge(DebuggerBridge):
            def __init__(self) -> None:
                super().__init__()
                self._state = "running"
                self._target = {
                    "id": "baseline-page",
                    "type": "page",
                    "title": "Baseline",
                    "url": "https://baseline.test/",
                }
                self._connection = RecordingConnection()
                self.browser_commands = []
                self.response_index = 0
                self.block_next = False
                self.request_started = threading.Event()
                self.cancelled = threading.Event()

            def _browser_command(self, method: str, params=None) -> dict:
                self.browser_commands.append((method, params or {}))
                if method == "Target.createBrowserContext":
                    return {"browserContextId": "repeater-context"}
                if method == "Target.createTarget":
                    return {"targetId": "repeater-page"}
                return {}

            def _command(self, method: str, params=None, timeout: float = 3.0) -> dict:
                if method != "Runtime.evaluate":
                    return {}
                expression = (params or {}).get("expression", "")
                if "registry.set(id, new AbortController())" in expression:
                    return {"result": {"value": True}}
                if not expression.startswith("(async function(config)"):
                    if "const controller = registry instanceof Map" in expression:
                        self.cancelled.set()
                        return {"result": {"value": True}}
                    return {}
                if self.block_next:
                    self.block_next = False
                    self.request_started.set()
                    self.cancelled.wait(timeout=2.0)
                    return {
                        "result": {
                            "value": {
                                "protocolVersion": 1,
                                "ok": False,
                                "error": "Request cancelled",
                                "durationMs": 4,
                                "cancelled": True,
                                "timedOut": False,
                            }
                        }
                    }
                self.response_index += 1
                status = 200 if self.response_index == 1 else 201
                body = "alpha" if self.response_index == 1 else "beta"
                headers = [{"name": "x-version", "value": str(self.response_index)}]
                if self.response_index > 1:
                    headers.append({"name": "x-added", "value": "yes"})
                return {
                    "result": {
                        "value": {
                            "protocolVersion": 1,
                            "ok": True,
                            "status": status,
                            "statusText": "OK",
                            "url": "https://api.test/orders/42?private=1",
                            "headers": headers,
                            "headersTruncated": False,
                            "body": body,
                            "bodyTruncated": False,
                            "durationMs": self.response_index + 2,
                            "cancelled": False,
                            "timedOut": False,
                        }
                    }
                }

        bridge = RepeaterBridge()
        bridge.action({"action": "create_request_interception_experiment"})
        bridge._target = {
            "id": "repeater-page",
            "type": "page",
            "title": "about:blank",
            "url": "about:blank",
        }
        bridge._connection = RecordingConnection()
        bridge._restore_request_interception("repeater-page")
        configured = bridge.action(
            {
                "action": "configure_repeater_variables",
                "variables": {"host": "api.test", "order": "42"},
            }
        )["repeater"]
        self.assertEqual(
            configured["variables"],
            [{"name": "host", "value": "api.test"}, {"name": "order", "value": "42"}],
        )

        def send(
            body: str = '{"id":"{{order}}"}',
            collection_request_id: Optional[int] = None,
        ) -> dict:
            before_history = bridge.snapshot()["repeater"]["history"]
            before_id = before_history[-1]["id"] if before_history else 0
            started = bridge.action(
                {
                    "action": "run_repeater_request",
                    "url": "https://{{host}}/orders/{{order}}?private=1",
                    "method": "POST",
                    "headers": {"x-order": "{{order}}"},
                    "body": body,
                    "timeout_ms": 500,
                    "collection_request_id": collection_request_id,
                }
            )
            self.assertTrue(started["ok"])

            def completed_entry():
                history = bridge.snapshot()["repeater"]["history"]
                return history[-1] if history and history[-1]["id"] > before_id else None

            return self.wait_for(completed_entry)

        first = send(collection_request_id=41)
        second = send()
        self.assertEqual(first["collection_request_id"], 41)
        self.assertEqual(first["request"]["url"], "https://{{host}}/orders/{{order}}?private=1")
        self.assertEqual(second["resolved_request"]["url"], "https://api.test/orders/42?private=1")
        self.assertEqual(second["variable_names"], ["host", "order"])
        comparison = bridge.snapshot()["repeater"]["comparison"]
        self.assertEqual((comparison["baseline_status"], comparison["current_status"]), (200, 201))
        self.assertTrue(comparison["body_changed"])
        self.assertEqual(comparison["headers_added"], ["x-added"])
        self.assertEqual(comparison["headers_changed"], ["x-version"])

        bridge.block_next = True
        bridge.request_started.clear()
        bridge.cancelled.clear()
        bridge.action(
            {
                "action": "run_repeater_request",
                "url": "https://{{host}}/slow",
                "method": "GET",
                "headers": {},
                "body": "",
                "timeout_ms": 500,
            }
        )
        self.assertTrue(bridge.request_started.wait(timeout=1.0))
        cancelling = bridge.action({"action": "cancel_repeater_request"})["repeater"]
        self.assertIn(cancelling["state"], {"cancelling", "ready"})
        cancelled_entry = self.wait_for(
            lambda: next(
                (
                    entry
                    for entry in bridge.snapshot()["repeater"]["history"]
                    if entry["state"] == "cancelled"
                ),
                None,
            )
        )
        self.assertTrue(cancelled_entry["response"]["cancelled"])

        for _ in range(26):
            send()
        bounded = bridge.snapshot()["repeater"]
        self.assertEqual(len(bounded["history"]), 24)
        self.assertGreaterEqual(bounded["history_evictions"], 5)
        self.assertLessEqual(bounded["history_bytes"], 512 * 1024)
        self.assertEqual(
            bounded["history_bytes"],
            sum(entry["stored_bytes"] for entry in bounded["history"]),
        )

        disposed = bridge.action(
            {"action": "dispose_request_interception_experiment"}
        )["repeater"]
        self.assertEqual(disposed["state"], "disposed")
        self.assertEqual(disposed["variables"], [])
        self.assertEqual(disposed["history"], [])

    def test_repeater_rejects_unresolved_sensitive_and_expanded_inputs(self) -> None:
        bridge = DebuggerBridge()
        variables = bridge._normalize_repeater_variables({"large": "x" * 4096})
        template = bridge._normalize_repeater_template(
            {
                "url": "https://example.test/{{missing}}",
                "method": "GET",
                "headers": {},
                "body": "",
                "timeout_ms": 100,
            }
        )
        with self.assertRaisesRegex(DebuggerBridgeError, "Unresolved"):
            bridge._resolve_repeater_request(template, variables)
        literal_template = bridge._normalize_repeater_template(
            {
                "url": "https://example.test/",
                "method": "POST",
                "headers": {},
                "body": "{{=large}}",
                "timeout_ms": 100,
            }
        )
        literal, literal_variables = bridge._resolve_repeater_request(
            literal_template, variables
        )
        self.assertEqual(literal["body"], "{{large}}")
        self.assertEqual(literal_variables, [])
        with self.assertRaisesRegex(DebuggerBridgeError, "forbidden"):
            bridge._normalize_repeater_template(
                {
                    "url": "https://example.test/",
                    "method": "GET",
                    "headers": {"Authorization": "{{large}}"},
                    "body": "",
                    "timeout_ms": 100,
                }
            )
        expanded = bridge._normalize_repeater_template(
            {
                "url": "https://example.test/",
                "method": "POST",
                "headers": {},
                "body": "{{large}}" * 17,
                "timeout_ms": 100,
            }
        )
        with self.assertRaisesRegex(DebuggerBridgeError, "64 KiB"):
            bridge._resolve_repeater_request(expanded, variables)
        with self.assertRaisesRegex(DebuggerBridgeError, "100 and 30000"):
            bridge._normalize_repeater_template(
                {
                    "url": "https://example.test/",
                    "method": "GET",
                    "headers": {},
                    "body": "",
                    "timeout_ms": 30_001,
                }
            )


if __name__ == "__main__":
    unittest.main()
