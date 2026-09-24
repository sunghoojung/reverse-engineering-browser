import queue
import time
import unittest
from pathlib import Path
from unittest import mock

from debugger.errors import WebSocketClosed
from debugger.transport import ActionScopeTargetSession
from debugger_bridge import DebuggerBridge


class FakeFlatConnection:
    def __init__(self, url, _binary):
        self.url = url
        self.sent = []
        self.incoming = queue.Queue()
        self.closed = False

    def send_json(self, message):
        self.sent.append(message)
        result = {"sessionId": "worker-session"} if message["method"] == "Target.attachToTarget" else {}
        self.incoming.put({"id": message["id"], "result": result})

    def receive_json(self, timeout=0.5):
        if self.closed:
            raise WebSocketClosed("closed")
        try:
            return self.incoming.get(timeout=min(timeout, 0.05))
        except queue.Empty:
            return None

    def close(self):
        self.closed = True


class FakeWorkerSession:
    instances = []

    def __init__(self, target, event_handler, close_handler, _binary, **options):
        self.target = target
        self.target_id = target["id"]
        self.event_handler = event_handler
        self.close_handler = close_handler
        self.options = options
        self.commands = []
        self.closed = False
        self.instances.append(self)

    def start(self):
        self.event_handler(self, "Debugger.scriptParsed", {
            "scriptId": "12",
            "url": "http://127.0.0.1:8766/signer-worker.js",
            "startLine": 0,
            "startColumn": 0,
            "endLine": 0,
            "endColumn": 5000,
            "length": 5000,
        })

    def ready(self):
        return not self.closed

    def command(self, method, params=None, timeout=3.0):
        self.commands.append((method, params or {}, timeout))
        if method == "Debugger.getScriptSource":
            return {"scriptSource": "self.onmessage = event => event.data;"}
        if method == "Debugger.getPossibleBreakpoints":
            return {"locations": [{
                "scriptId": "12", "lineNumber": 0, "columnNumber": 20,
                "type": "call",
            }]}
        if method == "Debugger.setBreakpoint":
            return {"breakpointId": "worker-breakpoint"}
        if method == "Runtime.evaluate":
            return {"result": {"type": "function", "objectId": "function-1"}}
        if method == "Debugger.setBreakpointOnFunctionCall":
            return {"breakpointId": "function-breakpoint"}
        return {}

    def command_without_wait(self, method, params=None):
        self.commands.append((method, params or {}, 0))
        return True

    def close(self):
        self.closed = True


class RuntimeHookWorkerTests(unittest.TestCase):
    def test_flattened_worker_session_routes_commands_and_events(self):
        connection = FakeFlatConnection("ws://127.0.0.1/devtools/browser/test", Path("/unused"))
        events = []
        closed = []
        with mock.patch("debugger.transport.NativeDebuggerConnection", return_value=connection):
            session = ActionScopeTargetSession(
                {"id": "worker-1", "web_socket_url": "ws://127.0.0.1/devtools/page/worker-1"},
                lambda _session, method, _params: events.append(method),
                lambda target_id, error: closed.append((target_id, error)),
                Path("/unused"), enable_page=False, enable_debugger=True,
                browser_url="ws://127.0.0.1/devtools/browser/test",
            )
            try:
                session.start()
                self.assertTrue(session.ready())
                self.assertEqual(connection.sent[0]["method"], "Target.attachToTarget")
                self.assertEqual(connection.sent[0]["params"], {"targetId": "worker-1", "flatten": True})
                self.assertNotIn("sessionId", connection.sent[0])
                self.assertTrue(all(command["sessionId"] == "worker-session" for command in connection.sent[1:]))
                self.assertEqual([command["method"] for command in connection.sent[1:]], ["Runtime.enable", "Debugger.enable"])
                connection.incoming.put({"sessionId": "unrelated", "method": "Debugger.scriptParsed", "params": {}})
                connection.incoming.put({"sessionId": "worker-session", "method": "Debugger.scriptParsed", "params": {}})
                connection.incoming.put({"method": "Target.detachedFromTarget", "params": {"sessionId": "worker-session"}})
                for _ in range(50):
                    if closed:
                        break
                    time.sleep(0.01)
                self.assertEqual(events, ["Debugger.scriptParsed"])
                self.assertEqual(closed[0][0], "worker-1")
                self.assertFalse(session.ready())
            finally:
                session.close()

    def setUp(self):
        FakeWorkerSession.instances = []
        self.bridge = DebuggerBridge()
        self.bridge._state = "running"
        self.bridge._target = {"id": "page-1", "type": "page", "title": "Fixture", "url": "http://127.0.0.1:8766/"}
        self.bridge._request_interception_context_id = "isolated-1"
        self.bridge._runtime_hooks.update({"state": "ready", "isolated": True, "target_id": "page-1", "session_id": 1})
        self.worker = {
            "id": "worker-1", "type": "worker", "title": "", "url": "",
            "web_socket_url": "ws://127.0.0.1/devtools/page/worker-1",
        }
        self.unrelated = {**self.worker, "id": "other-worker"}
        self.infos = [
            {"targetId": "worker-1", "type": "worker", "browserContextId": "isolated-1"},
            {"targetId": "other-worker", "type": "worker", "browserContextId": "unrelated"},
        ]
        self.bridge._devtools_endpoint = lambda: (12345, "ws://127.0.0.1/devtools/browser/test")
        self.bridge._browser_command = lambda method, params=None: {"targetInfos": self.infos}
        self.bridge._discover_targets = lambda: [self.worker, self.unrelated]
        self.session_patch = mock.patch("debugger_bridge.ActionScopeTargetSession", FakeWorkerSession)
        self.session_patch.start()

    def tearDown(self):
        self.bridge._close_runtime_hook_workers()
        self.session_patch.stop()

    def test_only_owned_worker_is_exposed_and_source_is_routed(self):
        self.bridge._refresh_runtime_hook_workers()
        hooks = self.bridge.snapshot()["runtime_hooks"]
        self.assertEqual([worker["id"] for worker in hooks["workers"]], ["worker-1"])
        self.assertEqual(hooks["worker_overflow"], 0)
        self.assertEqual(len(FakeWorkerSession.instances), 1)
        session = FakeWorkerSession.instances[0]
        self.assertEqual(session.options["browser_url"], "ws://127.0.0.1/devtools/browser/test")
        script = next(script for script in self.bridge.snapshot()["scripts"] if script.get("target_type") == "worker")
        self.assertEqual(script["target_id"], "worker-1")
        self.assertNotEqual(script["script_id"], script["cdp_script_id"])
        source = self.bridge.get_script_source(script["script_id"])
        self.assertIn("self.onmessage", source["source"])
        self.assertIn(("Debugger.getScriptSource", {"scriptId": "12"}, 5.0), session.commands)
        self.assertNotIn("other-worker", self.bridge._runtime_hook_worker_sessions)

    def test_worker_limit_and_detach_drop_stale_sources(self):
        candidates = [
            {**self.worker, "id": f"worker-{index}"}
            for index in range(10)
        ]
        self.infos = [
            {"targetId": worker["id"], "type": "worker", "browserContextId": "isolated-1"}
            for worker in candidates
        ]
        self.bridge._discover_targets = lambda: candidates
        self.bridge._refresh_runtime_hook_workers()
        self.assertEqual(len(self.bridge.snapshot()["runtime_hooks"]["workers"]), 8)
        self.assertEqual(self.bridge.snapshot()["runtime_hooks"]["worker_overflow"], 2)
        removed = self.bridge.snapshot()["runtime_hooks"]["workers"][0]["id"]
        self.infos = [info for info in self.infos if info["targetId"] != removed]
        self.bridge._refresh_runtime_hook_workers()
        self.assertTrue(all(
            script.get("target_id") != removed
            for script in self.bridge.snapshot()["scripts"]
        ))

    def test_malformed_worker_script_is_ignored(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        initial = len(self.bridge.snapshot()["scripts"])
        self.bridge._on_runtime_hook_worker_event(session, "Debugger.scriptParsed", {
            "scriptId": "x" * 5000, "url": "http://127.0.0.1/oversized.js"
        })
        self.assertEqual(len(self.bridge.snapshot()["scripts"]), initial)

    def test_worker_request_metadata_is_bounded_and_disposable(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        self.bridge._runtime_hooks["state"] = "armed"
        for index in range(130):
            self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
                "requestId": f"request-{index}", "type": "Fetch",
                "request": {"url": f"http://127.0.0.1:8766/api/submit?token={index}", "method": "POST"},
            })
        hooks = self.bridge.snapshot()["runtime_hooks"]
        self.assertEqual((len(hooks["requests"]), hooks["request_evictions"]), (128, 2))
        self.assertNotIn("token=", str(hooks["requests"]))
        self.bridge._runtime_hooks["state"] = "disarmed"
        self.bridge.action({"action": "clear_runtime_hook_hits"})
        self.assertEqual(self.bridge.snapshot()["runtime_hooks"]["requests"], [])

    @mock.patch("debugger_bridge.locate_function", return_value={
        "kind": "arrow_function", "start": {"line": 0, "column": 10},
        "end": {"line": 0, "column": 39}, "body_start": {"line": 0, "column": 20},
    })
    def test_hook_arms_and_records_hit_on_worker_target(self, _locator):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        script_id = next(iter(self.bridge._runtime_hook_worker_scripts))
        added = self.bridge.action({
            "action": "add_runtime_hook", "label": "worker signer", "script_id": script_id,
            "line": 0, "column": 25, "entry_enabled": True, "return_enabled": False,
        })["runtime_hooks"]
        self.assertEqual(added["definitions"][0]["target_id"], "worker-1")
        armed = self.bridge.action({"action": "arm_runtime_hooks", "confirmed": True})["runtime_hooks"]
        self.assertEqual(armed["active_points"], 1)
        possible = next(params for method, params, _ in session.commands if method == "Debugger.getPossibleBreakpoints")
        self.assertEqual(possible["start"]["scriptId"], "12")
        pause = {
            "hitBreakpoints": ["worker-breakpoint"],
            "callFrames": [{
                "callFrameId": "frame-1", "functionName": "", "scopeChain": [],
                "location": {"scriptId": "12", "lineNumber": 0, "columnNumber": 20},
            }],
        }
        self.assertFalse(self.bridge._handle_runtime_hook_pause_async(pause, "other-worker"))
        self.assertTrue(self.bridge._handle_runtime_hook_pause_async(pause, "worker-1"))
        for _ in range(50):
            if (
                self.bridge.snapshot()["runtime_hooks"]["total_hits"]
                and "Debugger.resume" in [method for method, _, _ in session.commands]
            ):
                break
            time.sleep(0.02)
        hit = self.bridge.snapshot()["runtime_hooks"]["hits"][0]
        self.assertEqual((hit["target_id"], hit["target_type"], hit["category"]), ("worker-1", "worker", "entry"))
        self.assertIn("Debugger.resume", [method for method, _, _ in session.commands])
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
            "requestId": "request-1", "type": "Fetch",
            "request": {"url": "http://127.0.0.1:8766/api/submit?private=value", "method": "POST"},
        })
        self.bridge._on_runtime_hook_worker_event(session, "Network.responseReceived", {
            "requestId": "request-1", "response": {"status": 200},
        })
        request = self.bridge.snapshot()["runtime_hooks"]["requests"][0]
        self.assertEqual(request["url"], "http://127.0.0.1:8766/api/submit")
        self.assertEqual(request["related_hit_ids"], [hit["id"]])
        self.assertEqual(request["relation"], "same-context temporal proximity, inferred")
        self.assertEqual(request["status"], 200)
        self.bridge.action({"action": "disarm_runtime_hooks"})
        self.assertIn("Debugger.removeBreakpoint", [method for method, _, _ in session.commands])

    def test_live_function_object_entry_is_side_effect_free(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        script_id = next(iter(self.bridge._runtime_hook_worker_scripts))
        definition = self.bridge.action({
            "action": "add_runtime_hook", "label": "message handler", "script_id": script_id,
            "line": 0, "column": 0, "entry_mode": "function",
            "function_expression": "self.onmessage", "entry_enabled": True,
            "return_enabled": False,
        })["runtime_hooks"]["definitions"][0]
        self.assertEqual(definition["function_kind"], "live_function_object")
        self.bridge.action({"action": "arm_runtime_hooks", "confirmed": True})
        evaluate = next(params for method, params, _ in session.commands if method == "Runtime.evaluate")
        self.assertEqual(evaluate["expression"], "self.onmessage")
        self.assertTrue(evaluate["throwOnSideEffect"])
        self.assertIn(
            ("Debugger.setBreakpointOnFunctionCall", {"objectId": "function-1"}, 3.0),
            session.commands,
        )
        self.bridge.action({"action": "disarm_runtime_hooks"})

    def test_worker_disconnect_clears_active_definition(self):
        self.bridge._refresh_runtime_hook_workers()
        script_id = next(iter(self.bridge._runtime_hook_worker_scripts))
        self.bridge.action({
            "action": "add_runtime_hook", "label": "message handler", "script_id": script_id,
            "line": 0, "column": 0, "entry_mode": "function",
            "function_expression": "self.onmessage", "entry_enabled": True,
            "return_enabled": False,
        })
        self.bridge.action({"action": "arm_runtime_hooks", "confirmed": True})
        self.bridge._on_runtime_hook_worker_closed("worker-1", RuntimeError("gone"))
        hooks = self.bridge.snapshot()["runtime_hooks"]
        self.assertEqual(hooks["state"], "error")
        self.assertEqual(hooks["definitions"], [])
        self.assertEqual(hooks["active_points"], 0)
        self.assertEqual(hooks["workers"], [])
        self.assertEqual(self.bridge._runtime_hook_worker_scripts, {})


if __name__ == "__main__":
    unittest.main()
