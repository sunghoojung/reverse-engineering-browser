"""Keep the public HTTP description tied to routes and observable behavior."""

import ast
import copy
import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from api_collection import ApiCollectionStore
from local_analyst import LocalAnalystStore
from server import LoopbackThreadingHTTPServer, ResearchHandler
import server as server_module

ROOT = Path(__file__).resolve().parents[2]
SPEC = json.loads((ROOT / "protocol/openapi.json").read_text())


def walk_json(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


class OpenApiContractTest(unittest.TestCase):
    def test_paths_match_explicit_http_routes(self):
        tree = ast.parse((ROOT / "apps/research-ui/server.py").read_text())
        actual = set()
        for method in (node for node in ast.walk(tree)
                       if isinstance(node, ast.FunctionDef)
                       and node.name in {"do_GET", "do_POST"}):
            verb = method.name[3:].lower()
            for node in ast.walk(method):
                if not isinstance(node, ast.Compare):
                    continue
                if ast.unparse(node.left) != "parsed.path":
                    continue
                for other in node.comparators:
                    if isinstance(other, ast.Constant) and str(other.value).startswith("/api/"):
                        actual.add((other.value, verb))
            if verb == "get":
                self.assertIn('r"/api/artifacts/([^/]+)/content"',
                              (ROOT / "apps/research-ui/server.py").read_text())
                actual.add(("/api/artifacts/{artifact_id}/content", verb))
        documented = {(path, method) for path, item in SPEC["paths"].items()
                      for method in item}
        self.assertEqual(actual, documented)
        ids = [operation["operationId"] for item in SPEC["paths"].values()
               for operation in item.values()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(SPEC["security"], [])

    def test_debugger_actions_and_body_limits_match_implementation(self):
        tree = ast.parse((ROOT / "apps/research-ui/debugger_bridge.py").read_text())
        dispatch = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == "action")
        actions = set()
        for node in ast.walk(dispatch):
            if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                    and node.left.id == "action" and isinstance(node.ops[0], ast.Eq)
                    and isinstance(node.comparators[0], ast.Constant)):
                actions.add(node.comparators[0].value)
        variants = SPEC["components"]["schemas"]["DebuggerAction"]["oneOf"]
        self.assertEqual(actions, {item["properties"]["action"]["const"]
                                   for item in variants})
        for family, name in (("capture", "MAX_CAPTURE_ACTION_BYTES"),
                             ("decoder", "MAX_DECODER_ACTION_BYTES"),
                             ("api-collection", "MAX_API_COLLECTION_ACTION_BYTES"),
                             ("local-analyst", "MAX_LOCAL_ANALYST_ACTION_BYTES"),
                             ("debugger", "MAX_DEBUGGER_ACTION_BYTES")):
            operation = SPEC["paths"][f"/api/{family}/actions"]["post"]
            self.assertEqual(operation["x-max-body-bytes"], getattr(server_module, name))

    def test_references_resolve_and_embedded_schemas_do_not_drift(self):
        for node in walk_json(SPEC):
            if "$ref" not in node:
                continue
            self.assertTrue(node["$ref"].startswith("#/"))
            target = SPEC
            for component in node["$ref"][2:].split("/"):
                target = target[component.replace("~1", "/").replace("~0", "~")]
        for name in ("OriginTrace", "SignalProfile", "VmAnalysis"):
            embedded = copy.deepcopy(SPEC["components"]["schemas"][name])
            source = json.loads((ROOT / embedded.pop("x-source")).read_text())
            source.pop("$id", None)
            source.pop("$schema", None)
            for node in walk_json(embedded):
                if "$ref" in node:
                    node["$ref"] = node["$ref"].replace(
                        f"#/components/schemas/{name}/", "#/", 1)
            self.assertEqual(source, embedded)

    def test_typed_debugger_requests_match_pure_validators(self):
        from debugger.automation import normalize_automation_recipe
        from debugger.errors import DebuggerBridgeError
        from debugger.memory import live_object_search_criteria
        from debugger.requests import (
            normalize_repeater_template,
            normalize_request_interception_rule,
        )

        variants = {item["properties"]["action"]["const"]: item for item in
                    SPEC["components"]["schemas"]["DebuggerAction"]["oneOf"]}
        recipe_schema = variants["add_automation_recipe"]
        recipe = {"action": "add_automation_recipe", "label": "Observe",
                  "source": "return 1;"}
        self.assertEqual(set(recipe_schema["required"]), set(recipe))
        self.assertEqual(normalize_automation_recipe(recipe)["trigger"],
                         recipe_schema["properties"]["trigger"]["default"])
        maximum = recipe_schema["properties"]["source"]["x-max-utf8-bytes"]
        with self.assertRaises(DebuggerBridgeError):
            normalize_automation_recipe({**recipe, "source": "a" * (maximum + 1)})
        with self.assertRaises(DebuggerBridgeError):
            normalize_automation_recipe({**recipe, "trigger": "every-click"})

        search_schema = variants["search_live_objects"]
        self.assertIn("property_query", search_schema["properties"])
        self.assertEqual(live_object_search_criteria({"property_query": "value"})[
            "similarityThreshold"], search_schema["properties"]["similarity_threshold"]["default"])
        with self.assertRaises(DebuggerBridgeError):
            live_object_search_criteria({"shape": "42"})
        with self.assertRaises(DebuggerBridgeError):
            live_object_search_criteria({})

        repeater = variants["run_repeater_request"]
        self.assertIn("url", repeater["required"])
        normalized = normalize_repeater_template({"url": "https://example.invalid/"})
        self.assertEqual(normalized["timeout_ms"],
                         repeater["properties"]["timeout_ms"]["default"])
        with self.assertRaises(DebuggerBridgeError):
            normalize_repeater_template({"url": "https://example.invalid/",
                                         "timeout_ms": repeater["properties"]["timeout_ms"]["maximum"] + 1})
        interception = variants["configure_request_interception"]
        self.assertEqual(set(interception["required"]), {"action", "mode", "url_pattern"})
        # Unused mode fields are ignored, not globally constrained by the schema.
        accepted = normalize_request_interception_rule(
            {"mode": "continue", "url_pattern": "*", "response_code": "ignored"})
        self.assertEqual(accepted["mode"], "continue")
        self.assertEqual(interception["properties"]["response_code"], {})
        with self.assertRaises(DebuggerBridgeError):
            normalize_request_interception_rule(
                {"mode": "fulfill", "url_pattern": "*", "response_code": 600})

    def test_debugger_results_have_closed_mapped_envelopes(self):
        from debugger_bridge import DebuggerBridge

        schemas = SPEC["components"]["schemas"]
        results = schemas["DebuggerResult"]
        mapping = results["x-action-results"]
        actions = {v["properties"]["action"]["const"] for v in schemas["DebuggerAction"]["oneOf"]}
        self.assertEqual(set(mapping), actions)
        for name, component in schemas.items():
            for keyword in ("oneOf", "anyOf", "allOf"):
                for branch in component.get(keyword, []):
                    self.assertNotEqual(branch.get("$ref"),
                                        f"#/components/schemas/{name}")
        for reference in mapping.values():
            envelope = schemas[reference["$ref"].split("/")[-1]]
            self.assertEqual(envelope.get("type"), "object")
            self.assertFalse(any(key in envelope for key in ("oneOf", "anyOf", "allOf")))
        for reference in results["oneOf"]:
            schema = schemas[reference["$ref"].split("/")[-1]]
            self.assertFalse(schema["additionalProperties"])
            self.assertIn("ok", schema["required"])
            self.assertIn("generation", schema["required"])
        for action, expected in {
            "add_runtime_hook": {"ok", "runtime_hooks", "generation"},
            "compare_runtime_field_test": {"ok", "runtime_hooks", "generation"},
            "create_experiment_page": {"ok", "target_id", "action_scope", "generation"},
            "set_breakpoint": {"ok", "breakpoint", "generation"},
            "search_live_objects": {"ok", "search", "generation"},
        }.items():
            self.assertEqual(set(schemas[mapping[action]["$ref"].split("/")[-1]]["required"]), expected)
        bridge = DebuggerBridge(None)
        actual = bridge.action({"action": "clear_console"})
        schema = schemas[mapping["clear_console"]["$ref"].split("/")[-1]]
        self.assertEqual(set(actual), set(schema["required"]))
        self.assertIs(actual["ok"], True)

    def test_http_contract_locality_conditional_errors_and_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)

            class Handler(ResearchHandler):
                ui_directory = ROOT / "apps/research-ui"
                event_store = directory / "events.jsonl"
                trace_store = directory / "trace.jsonl"
                signal_store = directory / "signals.jsonl"
                artifact_store = directory / "artifacts"
                api_collection_store = ApiCollectionStore(directory / "collection.json")
                local_analyst_store = LocalAnalystStore(directory / "analyst.json")
                debugger = None
                broker_socket = None
                broker_pid = None
                capture_stopped = False

            Handler.artifact_store.mkdir()
            body = b"abcdef"
            digest = hashlib.sha256(body).hexdigest()
            (Handler.artifact_store / "blobs").mkdir()
            (Handler.artifact_store / "blobs" / f"{digest}.bin").write_bytes(body)
            artifact = {
                "protocol_version": 1, "artifact_id": "1", "session_id": "1",
                "navigation_id": "0", "frame_id": "0", "parent_artifact_id": "0",
                "creator_event_id": "0", "execution_context_id": "0",
                "capture_origin": "unknown", "kind": "javascript", "url": "https://example.invalid/code.js",
                "mime_type": "text/javascript", "byte_size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(), "sensitive": False,
                "content_path": f"blobs/{digest}.bin",
            }
            (Handler.artifact_store / "manifest.jsonl").write_text(json.dumps(artifact) + "\n")
            httpd = LoopbackThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{httpd.server_port}"

            def request(path, headers=None, data=None):
                req = urllib.request.Request(base + path, headers=headers or {}, data=data)
                try:
                    response = urllib.request.urlopen(req, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, response.headers, response.read()

            try:
                status, headers, raw = request("/api/events")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(raw)["events"], [])
                status, _, raw = request("/api/events", {"If-None-Match": headers["ETag"]})
                self.assertEqual((status, raw), (304, b""))
                status, _, raw = request("/api/health", {"Origin": "https://example.invalid"})
                self.assertEqual(status, 403)
                self.assertEqual(set(json.loads(raw)), {"error"})
                for path in ("/api/events?limit=invalid", "/api/artifacts?limit=invalid"):
                    status, _, raw = request(path)
                    self.assertEqual(status, 500)
                    self.assertEqual(set(json.loads(raw)), {"error"})
                status, _, raw = request("/api/debugger/actions", data=b'{"action":"pause"}')
                self.assertEqual(status, 409)
                self.assertEqual(set(json.loads(raw)), {"error"})
                status, headers, raw = request("/api/artifacts/1/content?offset=2&limit=2")
                self.assertEqual((status, raw), (200, b"cd"))
                self.assertEqual(headers["Content-Type"], "application/octet-stream")
                self.assertEqual(headers["X-Artifact-Offset"], "2")
                self.assertEqual(headers["X-Artifact-Total-Bytes"], "6")
                self.assertEqual(headers["X-Artifact-Truncated"], "1")
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
