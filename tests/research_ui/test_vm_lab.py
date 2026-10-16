import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ui_test_support import UI_DIRECTORY, read_ui_sources

FIXTURE = Path(__file__).parent / "fixtures" / "vm-opcode-workspace-v2.json"


class VmLabTests(unittest.TestCase):
    def run_evidence_model(self, exercise: str) -> dict:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed")
        model = (UI_DIRECTORY / "evidence_models.js").read_text(encoding="utf-8")
        completed = subprocess.run(
            [node],
            input=model + "\n" + exercise,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    def test_fixture_workspace_projects_rendered_handler_rows(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        result = self.run_evidence_model(
            f"""
const workspaceDocument = {json.dumps(fixture)};
const finding = {{findingId: 'analysis:c5e529342af22aafd3d7ddbc', sourceArtifactId: '302'}};
const workspace = vmOpcodeWorkspaceForFinding(workspaceDocument, finding);
process.stdout.write(JSON.stringify({{
  accepted: isVmOpcodeWorkspaceDocument(workspaceDocument),
  rows: vmOpcodeRows(workspace)
}}));
"""
        )

        self.assertTrue(result["accepted"])
        self.assertEqual(
            [row["state"] for row in result["rows"]],
            ["inferred", "observed", "correlated", "unknown"],
        )
        self.assertEqual(result["rows"][0]["samples"], 0)
        self.assertEqual(result["rows"][1]["opcode"], "0x07")
        self.assertEqual(result["rows"][1]["source"], "172 + 35 bytes")
        self.assertIn("PC 2 (instruction-index)", result["rows"][1]["positions"][0])
        self.assertIn("handler 1 · bytecode 401", result["rows"][1]["positions"][0])

        sources = read_ui_sources()
        self.assertIn("role', 'listbox'", sources)
        self.assertIn("aria-label', 'Opcode handlers'", sources)
        self.assertIn("role', 'option'", sources)
        self.assertIn("['ArrowUp', 'ArrowDown', 'Home', 'End']", sources)
        self.assertIn("Missing samples do not suppress inferred handlers", sources)

    def test_v2_rejects_missing_identity_forged_counts_and_malformed_rows(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        result = self.run_evidence_model(
            f"""
const valid = {json.dumps(fixture)};
const mutations = [
  value => value.contract_version = 1,
  value => delete value.workspaces[0].source_artifact_sha256,
  value => value.workspaces[0].samples[0].interpreter_artifact_id = '999',
  value => value.workspaces[0].samples[0].instruction_pointer_units = 'guessed',
  value => value.workspaces[0].samples[0].invocation_event = null,
  value => value.workspaces[0].samples[0].event.sequence_number = '0',
  value => value.workspaces[0].samples.push(value.workspaces[0].samples[0]),
  value => value.workspaces[0].sample_count = 1,
  value => value.summary.sample_count = 0,
  value => value.workspaces[0].coverage.attributions = [null],
  value => value.workspaces[0].coverage.complete = true,
  value => value.workspaces[0].traversal.instructions = [null],
  value => value.workspaces[0].traversal.complete = true,
  value => value.workspaces[0].handlers[0].effects = [null]
];
const rejected = mutations.map(mutate => {{
  const value = structuredClone(valid); mutate(value);
  try {{ return !isVmOpcodeWorkspaceDocument(value); }} catch {{ return false; }}
}});
process.stdout.write(JSON.stringify({{rejected}}));
"""
        )
        self.assertEqual(result["rejected"], [True] * 14)

    def test_webassembly_workspace_projects_dispatch_arms_and_non_vm_is_empty(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        workspace = fixture["workspaces"][0]
        workspace["runtime"] = "webassembly"
        workspace["model"] = "unknown"
        workspace["handlers"] = [
            {
                "opcode": 0, "state": "inferred", "sample_count": 0,
                "source": {"byte_offset": 45, "byte_size": 5},
                "label": "br_table selector 0", "operand_width": 0,
                "notes": "Guest opcode binding is unproven.", "effects": [],
            },
            {
                "opcode": None, "state": "unknown", "sample_count": 0,
                "source": {"byte_offset": 50, "byte_size": 3},
                "label": "call_indirect target", "operand_width": 0,
                "notes": "No static handler index or guest opcode binding is inferred.", "effects": [],
            },
        ]
        workspace["samples"] = []
        workspace["sample_count"] = 0
        workspace["coverage"]["handler_count"] = 2
        fixture["summary"]["handler_count"] = 2
        fixture["summary"]["sample_count"] = 0
        result = self.run_evidence_model(
            f"""
const document = {json.dumps(fixture)};
const finding = {{findingId: 'analysis:c5e529342af22aafd3d7ddbc', sourceArtifactId: '302'}};
const workspace = vmOpcodeWorkspaceForFinding(document, finding);
const rows = vmOpcodeRows(workspace);
const accepted = isVmOpcodeWorkspaceDocument(document);
const repeated = JSON.parse(JSON.stringify(document));
repeated.workspaces[0].handlers.push({{...repeated.workspaces[0].handlers[0], source: {{byte_offset: 70, byte_size: 5}}}});
repeated.workspaces[0].coverage.handler_count = 3;
repeated.summary.handler_count = 3;
const repeatedSelectorsAccepted = isVmOpcodeWorkspaceDocument(repeated);
const repeatedKeys = vmOpcodeRows(repeated.workspaces[0]).map(row => row.key);
const distinctSites = new Set(repeatedKeys).size === repeatedKeys.length;
const negative = {{...document, workspaces: []}};
const absent = vmOpcodeWorkspaceForFinding(negative, {{sourceArtifactId: 'non-vm'}});
document.workspaces[0].handlers[1].state = 'inferred';
const guessedIndexRejected = !isVmOpcodeWorkspaceDocument(document);
process.stdout.write(JSON.stringify({{accepted, rows, absent, guessedIndexRejected, repeatedSelectorsAccepted, distinctSites}}));
"""
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["rows"][0]["opcode"], "0x00")
        self.assertEqual(result["rows"][1]["opcode"], "unknown")
        self.assertEqual(result["rows"][1]["state"], "unknown")
        self.assertTrue(result["guessedIndexRejected"])
        self.assertTrue(result["repeatedSelectorsAccepted"])
        self.assertTrue(result["distinctSites"])
        self.assertIsNone(result["absent"])
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        self.assertIn("'WebAssembly · '", app)
        self.assertIn("dispatch-arm candidates", app)

    def session_presentation(self, state: dict) -> dict:
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        start = app.index("      function vmSessionPresentation")
        end = app.index("      function renderVmSessionStatus", start)
        return self.run_evidence_model(
            app[start:end]
            + f"\nprocess.stdout.write(JSON.stringify(vmSessionPresentation({json.dumps(state)})));"
        )

    def test_stored_capture_modes_survive_without_a_debugger(self) -> None:
        for mode, label in [
            ("native-stealth", "Native stealth"),
            ("cdp-attached", "CDP attached"),
            ("unknown", "Recorded evidence"),
        ]:
            with self.subTest(mode=mode):
                result = self.session_presentation({
                    "vmAnalysisDocument": {"capture_mode": mode},
                    "sessionMode": "live", "broker": "connected", "captureStopped": False,
                    "debuggerSession": {"state": "unavailable", "target": None},
                })
                self.assertEqual(result["label"], label)
                if mode == "native-stealth":
                    self.assertIn("does not establish", result["copy"])
                    self.assertIn("without the DevTools endpoint", result["copy"])
        unknown = self.session_presentation({
            "vmAnalysisDocument": {}, "sessionMode": "live", "broker": "connected",
            "captureStopped": False, "vmStealthSession": True,
            "debuggerSession": {"state": "unavailable", "target": None},
        })
        self.assertEqual(unknown["label"], "Recorded evidence")
        self.assertEqual(unknown["copy"], "Stored findings do not prove which live session mode produced them.")

    def test_current_debugger_does_not_relabel_stored_capture(self) -> None:
        result = self.session_presentation({
            "vmAnalysisDocument": {"capture_mode": "native-stealth"},
            "debuggerRefreshFailed": True,
            "debuggerSession": {"state": "paused", "target": "page-1"},
        })
        self.assertEqual(result["label"], "Native stealth")

    def test_exact_workspace_mode_overrides_mixed_aggregate_only_for_matching_analysis(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        fixture["workspaces"][0]["capture_mode"] = "cdp-attached"
        state = {
            "vmAnalysisDocument": {"capture_mode": "unknown", "document_digest": fixture["analysis_digest"]},
            "vmOpcodeWorkspace": fixture,
            "selectedVmFindingId": "analysis:c5e529342af22aafd3d7ddbc",
            "vmFindings": [{"findingId": "analysis:c5e529342af22aafd3d7ddbc", "sourceArtifactId": "302"}],
        }
        self.assertEqual(self.session_presentation(state)["label"], "CDP attached")
        state["vmAnalysisDocument"]["document_digest"] = "e" * 64
        self.assertEqual(self.session_presentation(state)["label"], "Recorded evidence")

    def test_live_launcher_records_exact_mode_privately(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("Bash is not installed")
        script = (UI_DIRECTORY.parents[1] / "scripts" / "run-live-session.sh").read_text(encoding="utf-8")
        start = script.index("# Persist the launch fact after startup succeeds.")
        end = script.index('if [[ "${embedded_session}" == 1 ]]; then', start)
        with tempfile.TemporaryDirectory() as temporary:
            for quiet, mode in [("1", "native-stealth"), ("0", "cdp-attached")]:
                subprocess.run([bash, "-c", script[start:end]], check=True, env={
                    **os.environ, "artifact_store_path": temporary,
                    "session_id": "18446744073709551615", "native_quiet_mode": quiet,
                })
                path = Path(temporary) / "capture-provenance-v1.json"
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {
                    "contract_version": 1,
                    "sessions": [{"session_id": "18446744073709551615", "capture_mode": mode}],
                })
                if os.name == "posix":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(list(Path(temporary).iterdir())), 1)

    def test_unrecognized_capture_modes_fail_validation(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        result = self.run_evidence_model(f"""
const workspace = {json.dumps(fixture)};
workspace.capture_mode = 'invisible';
const invalidDocument = !isVmOpcodeWorkspaceDocument(workspace);
workspace.capture_mode = 'unknown';
workspace.workspaces[0].capture_mode = 'invisible';
const invalidWorkspace = !isVmOpcodeWorkspaceDocument(workspace);
const analysis = {{contract_version:1, document_kind:'vm-analysis', document_digest:'a'.repeat(64),
  profile_digest:'b'.repeat(64), profile:{{profile_id:'anti-bot-vm-detection-v1'}},
  input_coverage:{{complete:true,omissions:[]}}, results:[], mixed_findings:[]}};
const legacyAccepted = isVmAnalysisDocument(analysis);
analysis.capture_mode = 'invisible';
const invalidAnalysis = !isVmAnalysisDocument(analysis);
process.stdout.write(JSON.stringify({{invalidDocument, invalidWorkspace, legacyAccepted, invalidAnalysis}}));
""")
        self.assertTrue(all(result.values()))

    def test_malformed_workspace_is_rejected_without_removing_findings(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        malformed = json.loads(json.dumps(fixture))
        malformed["workspaces"][0]["handlers"][0]["state"] = "confirmed"
        result = self.run_evidence_model(
            f"""
const valid = {json.dumps(fixture)};
const malformed = {json.dumps(malformed)};
const finding = {{findingId: 'analysis:c5e529342af22aafd3d7ddbc'}};
const targetState = {{
  lastValidVmOpcodeWorkspace: valid,
  vmOpcodeWorkspace: valid,
  vmFindings: [finding]
}};
const accepted = isVmOpcodeWorkspaceDocument(malformed);
if (!accepted) retainVmOpcodeWorkspaceOnFailure(targetState, 'malformed', 'bad state');
process.stdout.write(JSON.stringify({{
  accepted,
  status: targetState.vmOpcodeWorkspaceStatus,
  retainedWorkspace: targetState.vmOpcodeWorkspace === valid,
  findingCount: targetState.vmFindings.length
}}));
"""
        )

        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "malformed")
        self.assertTrue(result["retainedWorkspace"])
        self.assertEqual(result["findingCount"], 1)

    def test_vm_dispatch_sample_is_an_accepted_broker_event(self) -> None:
        result = self.run_evidence_model(
            """
const sample = {
  protocol_version: 2,
  session_id: '1', sequence_number: '14', monotonic_time_ns: '1000',
  navigation_id: '2', frame_id: '3', artifact_id: '401', parent_event_id: '13',
  request_id: '0', process_id: 1, thread_id: 20, initiator_request_id: 0,
  initiator_process_id: 0, encoded_data_length: '0', decoded_body_length: '0',
  resource_type: 0, flags: 0, status_code: 0, error_code: 0,
  payload_truncated: false, category: 'vm', type: 'vm_dispatch_sample',
  payload_size: 128, payload_encoding: 'hex', payload: '00'.repeat(128)
};
process.stdout.write(JSON.stringify({accepted: isBrokerEvent(sample)}));
"""
        )

        self.assertTrue(result["accepted"])

    def test_allocating_script_origin_requires_javascript_and_context(self) -> None:
        result = self.run_evidence_model("""
const artifact = {
  protocol_version: 1, artifact_id: '1', session_id: '1', navigation_id: '1',
  frame_id: '1', parent_artifact_id: '0', creator_event_id: '0',
  execution_context_id: '4', capture_origin: 'runtime_allocating_script',
  kind: 'javascript', url: 'fixture://owned/script.js', mime_type: 'text/javascript',
  byte_size: 32, sha256: 'a'.repeat(64), sensitive: false
};
process.stdout.write(JSON.stringify({
  valid: isArtifact(artifact),
  missingContext: isArtifact({...artifact, execution_context_id: '0'}),
  wrongKind: isArtifact({...artifact, kind: 'bytecode_buffer'})
}));
""")
        self.assertTrue(result["valid"])
        self.assertFalse(result["missingContext"])
        self.assertFalse(result["wrongKind"])

    def test_runtime_typed_array_artifact_requires_bytecode_and_context(self) -> None:
        result = self.run_evidence_model(
            """
const artifact = {
  protocol_version: 1,
  artifact_id: '1', session_id: '2', navigation_id: '0', frame_id: '3',
  parent_artifact_id: '0', creator_event_id: '0', execution_context_id: '4',
  capture_origin: 'runtime_typed_array', kind: 'bytecode_buffer',
  url: 'https://example.test/vm.js', mime_type: 'application/octet-stream',
  byte_size: 32, sha256: '0'.repeat(64), sensitive: false
};
const accepted = isArtifact(artifact);
artifact.kind = 'javascript';
const javascriptRejected = isArtifact(artifact);
artifact.kind = 'bytecode_buffer';
artifact.execution_context_id = '0';
const zeroContextRejected = isArtifact(artifact);
process.stdout.write(JSON.stringify({accepted, javascriptRejected, zeroContextRejected}));
"""
        )

        self.assertTrue(result["accepted"])
        self.assertFalse(result["javascriptRejected"])
        self.assertFalse(result["zeroContextRejected"])


if __name__ == "__main__":
    unittest.main()
