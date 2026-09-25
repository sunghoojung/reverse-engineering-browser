import queue
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from debugger.errors import DebuggerBridgeError, WebSocketClosed
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
        self.bridge._capture_network_content = True
        self.bridge._state = "running"
        self.bridge._target = {"id": "page-1", "type": "page", "title": "Fixture", "url": "http://127.0.0.1:8766/"}
        self.bridge._request_interception_context_id = "isolated-1"
        self.bridge._runtime_hooks.update({"state": "ready", "isolated": True, "target_id": "page-1", "session_id": 1})
        self.worker = {
            "id": "worker-1", "type": "worker", "title": "",
            "url": "http://127.0.0.1:8766/signer-worker.js",
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

    def test_page_auto_attach_initializes_workers_before_discovery(self):
        commands = []

        class PageSession:
            target_id = "page-1"

            def command(self, method, params=None):
                commands.append((method, params))

        session = PageSession()
        self.bridge._configure_action_scope_session(session)
        self.assertEqual(commands[0], (
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": False,
                "flatten": True,
                "filter": [{"type": "worker", "exclude": False}],
            },
        ))
        self.assertEqual(commands[1], ("Fetch.disable", None))

        scheduled = []
        self.bridge._schedule_runtime_hook_worker_refresh = lambda: scheduled.append(True)
        self.bridge._on_action_scope_event(session, "Target.attachedToTarget", {
            "targetInfo": {"type": "worker", "targetId": "worker-1"},
        })
        self.assertEqual(scheduled, [True])

    def test_uninitialized_worker_target_is_not_attached(self):
        self.worker["url"] = ""
        self.bridge._refresh_runtime_hook_workers()
        self.assertEqual(self.bridge.snapshot()["runtime_hooks"]["workers"], [])
        self.assertEqual(FakeWorkerSession.instances, [])
        self.assertIsNone(self.bridge.snapshot()["runtime_hooks"]["last_failure"])

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

    def test_breakpoint_setting_follows_page_toggles_after_worker_attachment(self):
        page_commands = []
        self.bridge._command = lambda method, params=None, timeout=3.0: (
            page_commands.append((method, params)) or {}
        )
        self.bridge.action({"action": "set_breakpoints_active", "active": False})
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        self.bridge.action({"action": "set_breakpoints_active", "active": True})
        self.assertEqual(
            [params for method, params in page_commands if method == "Debugger.setBreakpointsActive"],
            [{"active": False}, {"active": True}],
        )
        self.assertEqual(
            [params for method, params, _ in session.commands if method == "Debugger.setBreakpointsActive"],
            [{"active": False}, {"active": True}],
        )
        self.assertTrue(self.bridge.snapshot()["settings"]["breakpoints_active"])

    def test_failed_worker_setup_drops_scripts_and_backs_off_before_retry(self):
        original_command = FakeWorkerSession.command
        attempts = 0

        def fail_first_network(session, method, params=None, timeout=3.0):
            nonlocal attempts
            if method == "Network.enable":
                attempts += 1
                if attempts == 1:
                    raise DebuggerBridgeError("Network unavailable")
            return original_command(session, method, params, timeout)

        with mock.patch.object(FakeWorkerSession, "command", fail_first_network):
            self.bridge._refresh_runtime_hook_workers()
            self.assertEqual(self.bridge._runtime_hook_worker_sessions, {})
            self.assertEqual(self.bridge._runtime_hook_worker_scripts, {})
            self.assertIn("retrying in 2s", self.bridge.snapshot()["runtime_hooks"]["last_failure"])
            self.bridge._refresh_runtime_hook_workers()
            self.assertEqual(attempts, 1)
            self.assertEqual(len(FakeWorkerSession.instances), 1)
            self.bridge._runtime_hook_worker_retry["worker-1"] = (1, 0.0)
            self.bridge._refresh_runtime_hook_workers()
        self.assertEqual(attempts, 2)
        self.assertEqual(len(self.bridge._runtime_hook_worker_sessions), 1)
        self.assertEqual(len(self.bridge._runtime_hook_worker_scripts), 1)
        self.assertNotIn("worker-1", self.bridge._runtime_hook_worker_retry)

    def test_worker_refresh_is_background_and_does_not_overlap(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def slow_refresh():
            calls.append(1)
            entered.set()
            release.wait(1.0)

        self.bridge._refresh_runtime_hook_workers = slow_refresh
        try:
            self.bridge._schedule_runtime_hook_worker_refresh()
            self.assertTrue(entered.wait(1.0))
            self.bridge._schedule_runtime_hook_worker_refresh()
            self.assertEqual(len(calls), 1)
        finally:
            release.set()
        for _ in range(50):
            if not self.bridge._runtime_hook_worker_refreshing:
                break
            time.sleep(0.01)
        self.assertFalse(self.bridge._runtime_hook_worker_refreshing)

    def test_disposal_during_failed_attachment_cannot_restore_stale_state(self):
        entered = threading.Event()
        release = threading.Event()
        original_command = FakeWorkerSession.command

        def fail_after_disposal(session, method, params=None, timeout=3.0):
            if method == "Network.enable":
                entered.set()
                release.wait(1.0)
                raise DebuggerBridgeError("Network unavailable")
            return original_command(session, method, params, timeout)

        with mock.patch.object(FakeWorkerSession, "command", fail_after_disposal):
            thread = threading.Thread(target=self.bridge._refresh_runtime_hook_workers)
            thread.start()
            try:
                self.assertTrue(entered.wait(1.0))
                self.bridge._close_runtime_hook_workers()
            finally:
                release.set()
                thread.join(timeout=1.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.bridge._runtime_hook_worker_scripts, {})
        self.assertEqual(self.bridge._runtime_hook_worker_retry, {})
        self.assertIsNone(self.bridge.snapshot()["runtime_hooks"]["last_failure"])

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

    def test_field_test_requires_consent_and_compares_worker_intervention(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        configuration = {"action": "configure_runtime_field_test", "enabled": True,
                         "url": "http://127.0.0.1:8766/api/submit", "method": "POST",
                         "pointer": "/payload"}
        with self.assertRaisesRegex(DebuggerBridgeError, "confirmation"):
            self.bridge.action(configuration)
        with self.assertRaisesRegex(DebuggerBridgeError, "query"):
            self.bridge.action({**configuration, "confirmed": True,
                                "url": configuration["url"] + "?secret=1"})
        with self.assertRaisesRegex(DebuggerBridgeError, "supported"):
            self.bridge.action({**configuration, "confirmed": True, "kind": {"bad": True}})
        with self.assertRaisesRegex(DebuggerBridgeError, "header name"):
            self.bridge.action({**configuration, "confirmed": True,
                                "kind": "header", "pointer": "X-Test\nInjected"})
        self.bridge.action({**configuration, "confirmed": True})
        self.bridge._runtime_hooks["state"] = "armed"
        with mock.patch("debugger_bridge.extract_request_value", side_effect=[
            {"status": "available", "sha256": "a" * 64, "preview": '"before"', "bytes": 8},
            {"status": "available", "sha256": "b" * 64, "preview": '"after"', "bytes": 7},
        ]):
            self.bridge._runtime_hooks["hits"].append({
                "id": 1, "hook_id": 7, "target_id": "worker-1", "occurred_at_ms": int(time.time() * 1000),
                "operation": "observed", "category": "return", "source": "signer-worker.js",
                "function": "sign", "line": 3, "column": 4,
            })
            self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
                "requestId": "first", "type": "Fetch",
                "request": {"url": configuration["url"], "method": "POST",
                            "postData": '{"payload":"before","secret":"hidden"}'},
            })
            for _ in range(100):
                if self.bridge._runtime_hooks["field_test"]["observations"][0]["status"] != "pending":
                    break
                time.sleep(0.01)
            self.bridge._runtime_hooks["hits"].append({
                "id": 2, "hook_id": 8, "target_id": "worker-1", "occurred_at_ms": int(time.time() * 1000),
                "operation": "return_overridden", "category": "return", "source": "signer-worker.js",
                "function": "sign", "line": 3, "column": 4,
            })
            self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
                "requestId": "second", "type": "Fetch",
                "request": {"url": configuration["url"], "method": "POST",
                            "postData": '{"payload":"after","secret":"hidden"}'},
            })
            for _ in range(100):
                if self.bridge._runtime_hooks["field_test"]["observations"][1]["status"] != "pending":
                    break
                time.sleep(0.01)
        observations = self.bridge.snapshot()["runtime_hooks"]["field_test"]["observations"]
        self.assertEqual([item["status"] for item in observations], ["available", "available"])
        self.assertNotIn("hidden", str(observations))
        self.assertNotIn("payload", str(observations))
        with self.assertRaisesRegex(DebuggerBridgeError, "disarmed"):
            self.bridge.action({"action": "compare_runtime_field_test",
                                "baseline_id": observations[0]["id"],
                                "variant_id": observations[1]["id"]})
        self.bridge._runtime_hooks["state"] = "disarmed"
        comparison = self.bridge.action({"action": "compare_runtime_field_test",
                                         "baseline_id": observations[0]["id"],
                                         "variant_id": observations[1]["id"]})["runtime_hooks"]["field_test"]["comparison"]
        self.assertTrue(comparison["changed"])
        self.assertEqual(comparison["intervention_hit_id"], 2)
        self.assertEqual(comparison["interpretation"], "intervention-associated")
        retained = self.bridge._runtime_hooks["field_test"]["observations"]
        retained[1]["sha256"] = retained[0]["sha256"]
        comparison = self.bridge.action({"action": "compare_runtime_field_test",
                                         "baseline_id": observations[0]["id"],
                                         "variant_id": observations[1]["id"]})["runtime_hooks"]["field_test"]["comparison"]
        self.assertFalse(comparison["changed"])
        self.assertEqual(comparison["interpretation"], "inconclusive")
        retained[1]["sha256"] = "b" * 64
        self.bridge._runtime_hooks["hits"][0]["line"] = 99
        comparison = self.bridge.action({"action": "compare_runtime_field_test",
                                         "baseline_id": observations[0]["id"],
                                         "variant_id": observations[1]["id"]})["runtime_hooks"]["field_test"]["comparison"]
        self.assertEqual(comparison["interpretation"], "inconclusive")
        self.bridge._runtime_hooks["state"] = "disarmed"
        self.bridge.action({"action": "configure_runtime_field_test", "enabled": False})
        self.assertEqual(self.bridge.snapshot()["runtime_hooks"]["field_test"]["observations"], [])

    def test_page_query_value_compares_with_page_override(self):
        self.bridge._capture_network_content = False
        self.bridge._runtime_hook_page_network_enabled = True
        url = "https://example.test/api/send"
        self.bridge.action({"action": "configure_runtime_field_test", "enabled": True,
                            "url": url, "method": "GET", "kind": "query", "pointer": "payload",
                            "confirmed": True})
        self.bridge._runtime_hooks["state"] = "armed"
        with mock.patch.object(self.bridge, "_record_network_request"):
            for index, value in enumerate(("before", "after"), start=1):
                self.bridge._runtime_hooks["hits"].append({
                    "id": index, "hook_id": 7, "target_id": "page-1",
                    "occurred_at_ms": int(time.time() * 1000),
                    "operation": "observed" if index == 1 else "return_overridden",
                    "category": "return", "source": "https://example.test/app.js",
                    "function": "makePayload", "line": 3, "column": 4,
                })
                self.bridge._handle_event("Network.requestWillBeSent", {
                    "requestId": f"page-{index}", "type": "Fetch",
                    "request": {"url": f"{url}?payload={value}&private=hidden", "method": "GET"},
                })
                for _ in range(100):
                    observations = self.bridge._runtime_hooks["field_test"]["observations"]
                    if len(observations) == index and observations[-1]["status"] != "pending":
                        break
                    time.sleep(0.01)
        observations = self.bridge._runtime_hooks["field_test"]["observations"]
        self.assertEqual([item["preview"] for item in observations], ['"before"', '"after"'])
        self.assertTrue(all(item["target_type"] == "page" for item in observations))
        self.assertNotIn("hidden", str(observations))
        self.assertEqual([item["target_type"] for item in self.bridge._runtime_hooks["requests"]], ["page", "page"])
        self.bridge._runtime_hooks["state"] = "disarmed"
        comparison = self.bridge.action({"action": "compare_runtime_field_test",
                                         "baseline_id": observations[0]["id"],
                                         "variant_id": observations[1]["id"]})["runtime_hooks"]["field_test"]["comparison"]
        self.assertEqual(comparison["interpretation"], "intervention-associated")
        observations[1]["query_context_sha256"] = "f" * 64
        comparison = self.bridge.action({"action": "compare_runtime_field_test",
                                         "baseline_id": observations[0]["id"],
                                         "variant_id": observations[1]["id"]})["runtime_hooks"]["field_test"]["comparison"]
        self.assertFalse(comparison["same_query_context"])
        self.assertEqual(comparison["interpretation"], "inconclusive")

    def test_passive_page_value_needs_no_hook_and_stops_on_erase(self):
        self.bridge._capture_network_content = False
        url = "https://example.test/api/send"
        with mock.patch.object(self.bridge, "_command", return_value={}) as command:
            self.bridge.action({"action": "configure_runtime_field_test", "enabled": True,
                                "url": url, "method": "GET", "kind": "query",
                                "pointer": "payload", "confirmed": True})
        self.assertEqual(command.call_args.args[0], "Network.enable")
        self.assertTrue(self.bridge._runtime_hook_page_network_enabled)
        self.bridge._handle_event("Network.requestWillBeSent", {
            "requestId": "passive-1", "type": "Fetch",
            "request": {"url": url + "?payload=alpha&other=one", "method": "GET"},
        })
        for _ in range(100):
            observations = self.bridge._runtime_hooks["field_test"]["observations"]
            if observations and observations[0]["status"] != "pending":
                break
            time.sleep(0.01)
        self.assertEqual(observations[0]["preview"], '"alpha"')
        self.assertEqual(observations[0]["related_hit_ids"], [])
        self.bridge.action({"action": "configure_runtime_field_test", "enabled": False})
        self.bridge._handle_event("Network.requestWillBeSent", {
            "requestId": "passive-2", "type": "Fetch",
            "request": {"url": url + "?payload=beta", "method": "GET"},
        })
        self.assertEqual(self.bridge._runtime_hooks["field_test"]["observations"], [])

    def test_scoped_extra_headers_complete_missing_worker_header(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        url = "https://example.test/payload.json"
        self.bridge.action({"action": "configure_runtime_field_test", "enabled": True,
                            "url": url, "method": "GET", "kind": "header",
                            "pointer": "Accept", "confirmed": True})
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSentExtraInfo", {
            "requestId": "unrelated", "headers": {"Accept": "private-value"},
        })
        self.assertEqual(self.bridge._runtime_hooks["field_test"]["observations"], [])
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
            "requestId": "matched", "type": "Fetch",
            "request": {"url": url, "method": "GET", "headers": {}},
        })
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSentExtraInfo", {
            "requestId": "matched", "headers": {"Accept": "*/*", "Authorization": "private-value"},
        })
        observation = self.bridge._runtime_hooks["field_test"]["observations"][0]
        self.assertEqual(observation["status"], "available")
        self.assertEqual(observation["preview"], '"*/*"')
        self.assertNotIn("private-value", str(observation))
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
            "requestId": "extra-before-request", "type": "Fetch", "hasExtraInfo": True,
            "request": {"url": url, "method": "GET", "headers": {}},
        })
        for _ in range(100):
            second = self.bridge._runtime_hooks["field_test"]["observations"][1]
            if second["status"] != "pending":
                break
            time.sleep(0.01)
        self.assertEqual(second["status"], "unavailable")

    def test_field_test_missing_body_and_eviction_are_visible(self):
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        url = "http://127.0.0.1:8766/api/submit"
        self.bridge.action({"action": "configure_runtime_field_test", "enabled": True,
                            "url": url, "method": "POST", "pointer": "/payload",
                            "confirmed": True})
        self.bridge._runtime_hooks["state"] = "armed"
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
            "requestId": "queried", "type": "Fetch",
            "request": {"url": url + "/other?other=1", "method": "POST",
                        "postData": '{"payload":"wrong request"}'},
        })
        self.assertEqual(self.bridge._runtime_hooks["field_test"]["observations"], [])
        self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
            "requestId": "no-body", "type": "Fetch",
            "request": {"url": url, "method": "POST"},
        })
        test = self.bridge._runtime_hooks["field_test"]
        self.assertEqual(test["observations"][0]["status"], "uncaptured")
        original_command = session.command

        def command(method, params=None, timeout=3.0):
            if method == "Network.getRequestPostData":
                return {"postData": '{"payload":"found"}'}
            return original_command(method, params, timeout)

        session.command = command
        with mock.patch("debugger_bridge.extract_request_value", return_value={
            "status": "available", "sha256": "a" * 64, "preview": '"found"', "bytes": 7,
        }):
            self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
                "requestId": "cdp-body", "type": "Fetch",
                "request": {"url": url, "method": "POST", "hasPostData": True},
            })
            for _ in range(100):
                if test["observations"][1]["status"] != "pending":
                    break
                time.sleep(0.01)
        self.assertEqual(test["observations"][1]["status"], "available")
        test["comparison"] = {"baseline_id": 1, "variant_id": 2}
        for index in range(15):
            self.bridge._on_runtime_hook_worker_event(session, "Network.requestWillBeSent", {
                "requestId": f"overflow-{index}", "type": "Fetch",
                "request": {"url": url, "method": "POST"},
            })
        self.assertEqual((len(test["observations"]), test["observation_evictions"]), (16, 1))
        self.assertIsNone(test["comparison"])

    @mock.patch("debugger_bridge.locate_function", return_value={
        "kind": "arrow_function", "start": {"line": 0, "column": 10},
        "end": {"line": 0, "column": 39}, "body_start": {"line": 0, "column": 20},
    })
    def test_hook_arms_and_records_hit_on_worker_target(self, _locator):
        self.bridge._capture_network_content = False
        self.bridge._refresh_runtime_hook_workers()
        session = FakeWorkerSession.instances[0]
        script_id = next(iter(self.bridge._runtime_hook_worker_scripts))
        added = self.bridge.action({
            "action": "add_runtime_hook", "label": "worker signer", "script_id": script_id,
            "line": 0, "column": 25, "entry_enabled": True, "return_enabled": False,
        })["runtime_hooks"]
        self.assertEqual(added["definitions"][0]["target_id"], "worker-1")
        with mock.patch.object(self.bridge, "_command", return_value={}) as page_command:
            armed = self.bridge.action({"action": "arm_runtime_hooks", "confirmed": True})["runtime_hooks"]
        self.assertEqual(page_command.call_args.args[0], "Network.enable")
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
