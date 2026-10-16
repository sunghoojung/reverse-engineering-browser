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

    def test_browser_startup_readiness_is_bounded_and_failures_are_visible(self) -> None:
        harness = (UI_DIRECTORY.parents[1] / "tools/check-vm-opcode-workspace-ui.mjs").read_text(encoding="utf-8")
        wait = harness[harness.index("  const until = async"):harness.index("  const send = ")]
        startup = harness[harness.index("    let port;"):harness.index("    const pages = ")]
        result = self.run_evidence_model(f"""
const {{runInNewContext}} = require('node:vm');
const waitSource = {json.dumps(wait)}, startupSource = {json.dumps(startup)};
async function exercise(options) {{
  let now = 0;
  const browser = {{exitCode:null,signalCode:null}};
  const startup = {{spawn_error:options.spawnError ?? null,port_file:'not checked',elapsed_ms:0}};
  const context = {{startup,browser,closed:false,diagnostics:'',startupStarted:0,profile:'owned-profile',
    Date:{{now:()=>now}},console:{{log:()=>{{}}}},join:()=>'',
    pause:async ms=>{{now+=ms;if(options.exitAt !== undefined && now>=options.exitAt) browser.exitCode=1;}},
    readFile:async()=>{{
      if(options.readError) throw Object.assign(new Error(options.readError),{{code:options.readError}});
      if(now<(options.readyAt ?? Infinity)) throw Object.assign(new Error('not ready'),{{code:'ENOENT'}});
      return options.port ?? '9222\\n/devtools/browser/owned';
    }} }};
  try {{
    await runInNewContext(waitSource+';(async()=>{{'+startupSource+'}})()',context);
    return {{ready:true,now,startup}};
  }} catch(error) {{return {{ready:false,now,startup,error:String(error)}};}}
}}
(async()=>{{
  const delayed = await exercise({{readyAt:12000}}), absent = await exercise({{}});
  const exited = await exercise({{exitAt:4000}}), failed = await exercise({{spawnError:'ENOENT: browser unavailable'}});
  const unreadable = await exercise({{readError:'EACCES'}}), invalid = await exercise({{readyAt:0,port:'65536'}});
  let now=0, uiError='';
  try {{await runInNewContext(waitSource+';until(()=>false,"UI assertion")',
    {{Date:{{now:()=>now}},pause:async ms=>{{now+=ms;}}}});}} catch(error) {{uiError=String(error);}}
  process.stdout.write(JSON.stringify({{delayed,absent,exited,failed,unreadable,invalid,ui:{{now,error:uiError}}}}));
}})().catch(error=>{{console.error(error);process.exitCode=1;}});
""")
        self.assertTrue(result["delayed"]["ready"])
        self.assertEqual(result["delayed"]["now"], 12000)
        self.assertEqual(result["delayed"]["startup"]["port_file"], "ready")
        for name in ("absent", "invalid"):
            self.assertFalse(result[name]["ready"])
            self.assertEqual(result[name]["now"], 30000)
            self.assertIn("Timed out: sandboxed Chromium startup", result[name]["error"])
        self.assertEqual(result["exited"]["now"], 4000)
        self.assertIn("Sandboxed Chromium startup failed", result["exited"]["error"])
        self.assertEqual(result["failed"]["now"], 0)
        self.assertIn("ENOENT: browser unavailable", result["failed"]["error"])
        self.assertEqual(result["unreadable"]["startup"]["port_file"], "EACCES")
        self.assertEqual(result["unreadable"]["now"], 0)
        self.assertEqual(result["ui"]["now"], 10000)
        self.assertIn("Timed out: UI assertion", result["ui"]["error"])

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

    def test_analysis_selection_is_artifact_scoped_and_ambiguous_bindings_fail_closed(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        presentation = app[app.index("      function vmSessionPresentation"):app.index("      function renderVmSessionStatus")]
        result = self.run_evidence_model(presentation + f"""
const document = {json.dumps(fixture)};
const first = document.workspaces[0], second = structuredClone(first);
first.capture_mode = 'native-stealth'; second.capture_mode = 'cdp-attached';
second.interpreter_artifact_id = '303'; second.samples = []; second.sample_count = 0; second.snapshots = [];
document.workspaces.push(second);
const analysisResult = workspace => ({{artifact_id:workspace.interpreter_artifact_id,
  artifact_sha256:workspace.source_artifact_sha256, finding_id:workspace.finding_id, runtime:'javascript',
  status:'complete',tier:'candidate',vm_score:20,anti_bot_score:0,evidence_families:[],observations:[],
  related_request_ids:[],coverage:{{complete:true}}}});
const analysis = {{contract_version:1,document_kind:'vm-analysis',document_digest:document.analysis_digest,
  profile_digest:'a'.repeat(64),profile:{{profile_id:'anti-bot-vm-detection-v1'}},
  input_coverage:{{complete:true,omissions:[]}},capture_mode:'unknown',
  results:[analysisResult(first),analysisResult(second)],mixed_findings:[]}};
const findings = vmFindingsFromAnalysis(analysis);
const labels = findings.map(finding => vmSessionPresentation({{vmAnalysisDocument:analysis,
  vmOpcodeWorkspace:document,vmFindings:findings,selectedVmFindingId:finding.findingId}}).label);
const snapshots = findings.map(finding => vmOpcodeWorkspaceForFinding(document,finding).snapshots.length);
const wrongHash = structuredClone(findings[0]); wrongHash.analysis.artifact_sha256 = '0'.repeat(64);
const wrongFinding = structuredClone(findings[0]); wrongFinding.analysis.finding_id = '0'.repeat(24);
const wrongArtifact = structuredClone(findings[0]); wrongArtifact.sourceArtifactId = '303';
const duplicate = {{...document,workspaces:[first,structuredClone(first)]}};
const native = {{findingId:'105',sourceArtifactId:'302'}};
const mixed = {{finding_id:first.finding_id,runtime:'mixed',tier:'candidate',artifact_ids:['302','401']}};
analysis.mixed_findings = [mixed,{{...mixed,artifact_ids:['302','402']}}];
const mixedRows = vmFindingsFromAnalysis(analysis).filter(row => row.analysis.runtime === 'mixed');
const invalidTuples = [undefined,null,'302',[],['302'],['302','401','402'],['0302','401']].map(artifact_ids => {{
  const bad = {{...analysis,mixed_findings:[{{...mixed,artifact_ids}}]}};
  try {{return !isVmAnalysisDocument(bad);}} catch {{return false;}}
}});
process.stdout.write(JSON.stringify({{
  distinct:new Set(findings.map(row => row.findingId)).size === 2, labels, snapshots,
  mixedDistinct:new Set(mixedRows.map(row => row.findingId)).size === 2,
  mixedBound:mixedRows.every(row => vmOpcodeWorkspaceForFinding(document,row) === first), invalidTuples,
  refusals:[wrongHash,wrongFinding,wrongArtifact].map(row => vmOpcodeWorkspaceForFinding(document,row) === null),
  ambiguous:vmOpcodeWorkspaceForFinding(duplicate,findings[0]) === null,
  nativeBound:vmOpcodeWorkspaceForFinding(document,native) === first,
  nativeAmbiguous:vmOpcodeWorkspaceForFinding(duplicate,native) === null,
  wrongSuffixRejected:vmOpcodeWorkspaceForFinding(document,{{findingId:`analysis:${{first.finding_id}}:artifact:999`,sourceArtifactId:'302'}}) === null,
  hashOnlyRejected:vmOpcodeWorkspaceForFinding(document,{{findingId:`analysis:${{first.finding_id}}`}}) === null
}}));
""")
        self.assertTrue(result["distinct"])
        self.assertEqual(result["labels"], ["Native stealth", "CDP attached"])
        self.assertEqual(result["snapshots"], [1, 0])
        self.assertEqual(result["refusals"], [True] * 3)
        self.assertEqual(result["invalidTuples"], [True] * 7)
        for key in ("mixedDistinct", "mixedBound", "ambiguous", "nativeBound", "nativeAmbiguous", "hashOnlyRejected", "wrongSuffixRejected"):
            self.assertTrue(result[key], key)

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

    def test_host_links_require_bound_source_and_retained_sample_identity(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        result = self.run_evidence_model(f"""
const workspace = {json.dumps(fixture)};
const source = workspace.workspaces[0], sample = source.samples[0];
const host = {{...sample.event, sequence_number:'50'}};
const position = {{sample_event:sample.event, invocation_event:sample.invocation_event,
  invocation_id:sample.invocation_id, instruction_pointer:sample.instruction_pointer,
  instruction_pointer_units:sample.instruction_pointer_units}};
const valid = {{contract_version:1, document_kind:'vm-host-links', workspace_document_digest:workspace.document_digest,
  document_digest:'e'.repeat(64), workspaces:[{{interpreter_artifact_id:source.interpreter_artifact_id,
  source_artifact_sha256:source.source_artifact_sha256, omissions:[], links:[{{host_event:host, category:'runtime', type:'api_call',
  state:'observed', reason:'direct-dispatch-parent', guest_position:position}}]}}]}};
const accepted = isVmHostLinksDocument(valid, workspace);
const mutations = [
  row => row.workspace_document_digest = 'f'.repeat(64),
  row => row.workspaces[0].source_artifact_sha256 = 'f'.repeat(64),
  row => row.workspaces[0].links[0].payload = 'not allowed',
  row => row.workspaces[0].links[0].host_event.sequence_number = '1',
  row => row.workspaces[0].links[0].guest_position.instruction_pointer = 999,
  row => row.workspaces[0].links[0].guest_position.invocation_id = '999',
  row => row.workspaces[0].links[0].guest_position.invocation_event = null,
  row => row.workspaces[0].links.push(row.workspaces[0].links[0])
];
const rejected = mutations.map(mutate => {{const copy=structuredClone(valid);mutate(copy);return !isVmHostLinksDocument(copy,workspace);}});
valid.workspaces[0].links[0].state='unknown';valid.workspaces[0].links[0].reason='dispatch-samples-unavailable';
valid.workspaces[0].links[0].guest_position=null;
process.stdout.write(JSON.stringify({{accepted,rejected,unknown:isVmHostLinksDocument(valid,workspace)}}));
""")
        self.assertTrue(result["accepted"])
        self.assertTrue(result["unknown"])
        self.assertEqual(result["rejected"], [True] * 8)

    def test_host_link_refresh_preserves_matching_evidence_and_rejects_late_reply(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        helper = app[app.index("      async function refreshVmHostLinks("):app.index("      async function refreshVmAnalysis(")]
        result = self.run_evidence_model(helper + f"""
const workspace = {json.dumps(fixture)};
const retained = {{contract_version:1, document_kind:'vm-host-links', workspace_document_digest:workspace.document_digest,
  workspaces:[], document_digest:'e'.repeat(64)}};
const state = {{vmOpcodeWorkspace:workspace,vmHostLinks:retained,vmHostLinksGeneration:0,vmHostLinksStatus:'ready'}};
let complete;
let fetch = () => new Promise(resolve => complete=resolve);
(async () => {{
 const pending = refreshVmHostLinks();
 state.vmOpcodeWorkspace = {{...workspace, document_digest:'f'.repeat(64)}};
 complete({{ok:true,json:async()=>retained}});await pending;
 const lateRejected = state.vmHostLinks === retained && state.vmHostLinksStatus === 'ready';
 state.vmOpcodeWorkspace = workspace;
 fetch = async () => ({{ok:false,status:500}});await refreshVmHostLinks();
 const failedRetained = state.vmHostLinks === retained && state.vmHostLinksStatus === 'unavailable';
 fetch = async () => ({{ok:true,json:async()=>({{...retained,workspace_document_digest:'f'.repeat(64)}})}});
 await refreshVmHostLinks();
 process.stdout.write(JSON.stringify({{lateRejected,failedRetained,staleRetained:state.vmHostLinks===retained}}));
}})().catch(error=>{{console.error(error);process.exitCode=1;}});
""")
        self.assertTrue(all(result.values()))

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

    def test_byte_coverage_complete_and_partial_fixtures_render_exact_fraction(self) -> None:
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        start = app.index("      function renderVmWorkspaceCoverage")
        end = app.index("      function renderVmWorkspaceUnknowns", start)
        renderer = app[start:end]
        for name, percent, uncharacterized, complete in [
            ("complete", 100, 0, True), ("partial", 75, 1, False)
        ]:
            fixture = json.loads((FIXTURE.parent / f"vm-byte-coverage-{name}-v2.json").read_text(encoding="utf-8"))
            result = self.run_evidence_model(
                """
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.style = {}; this.textContent = ''; }
  append(...items) { this.children.push(...items); }
  setAttribute(key, value) { this.attributes[key] = value; }
}
const document = {createElement: tag => new Element(tag), createTextNode: text => ({textContent: text, children: []})};
const textElement = (tag, cls, text) => { const node = new Element(tag); node.className = cls; node.textContent = text; return node; };
const flatten = node => [node, ...node.children.flatMap(flatten)];
""" + renderer + f"""
const fixture = {json.dumps(fixture)};
const rows = flatten(renderVmWorkspaceCoverage(fixture.workspaces[0]));
const bar = rows.find(row => row.attributes?.role === 'progressbar');
const old = JSON.parse(JSON.stringify(fixture)); old.contract_version = 1;
process.stdout.write(JSON.stringify({{
  accepted: isVmOpcodeWorkspaceDocument(fixture), oldAccepted: isVmOpcodeWorkspaceDocument(old),
  percent: Number(bar.attributes['aria-valuenow']),
  copy: rows.map(row => row.textContent).join(' '), complete: fixture.workspaces[0].coverage.complete
}}));
"""
            )
            self.assertTrue(result["accepted"])
            self.assertFalse(result["oldAccepted"])
            self.assertEqual(result["percent"], percent)
            self.assertEqual(result["complete"], complete)
            self.assertIn(f"{uncharacterized} uncharacterized bytes", result["copy"])
            self.assertIn("2 handler candidates", result["copy"])
            if not complete:
                self.assertIn("uncharacterized-bytecode", result["copy"])

    def test_declarative_effects_render_unknowns_and_preserve_contradictions(self) -> None:
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        start = app.index("      function vmEffectCellText")
        end = app.index("      function renderVmBytecode", start)
        fixture = json.loads((FIXTURE.parent / "vm-effects-contradicted-v2.json").read_text(encoding="utf-8"))
        result = self.run_evidence_model(
            """
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.textContent = ''; }
  append(...items) { this.children.push(...items); }
  setAttribute(key, value) { this.attributes[key] = value; }
}
const document = {createElement: tag => new Element(tag)};
const textElement = (tag, cls, text) => { const node = new Element(tag); node.className = cls; node.textContent = text; return node; };
const vmField = (key, value) => textElement('div', '', `${key}: ${value}`);
const flatten = node => [node, ...node.children.flatMap(flatten)];
""" + app[start:end] + f"""
const fixture = {json.dumps(fixture)};
const copy = flatten(renderVmEffects(fixture.workspaces[0])).map(row => row.textContent).join(' ');
const malicious = structuredClone(fixture);
malicious.workspaces[0].handlers[0].effects[0].expression = 'import("untrusted")';
const empty = structuredClone(fixture.workspaces[0]); empty.handlers.forEach(row => row.effects = []);
process.stdout.write(JSON.stringify({{
  accepted: isVmOpcodeWorkspaceDocument(fixture), malformedAccepted: isVmOpcodeWorkspaceDocument(malicious),
  selected: vmUniqueWorkspaceEffect(fixture.workspaces[0].handlers[0]), copy,
  unknownCell: vmEffectCellText({{space:'register',index:null,operand:null,value:null}}),
  emptyCopy: flatten(renderVmEffects(empty)).map(row => row.textContent).join(' ')
}}));
"""
        )
        self.assertTrue(result["accepted"])
        self.assertFalse(result["malformedAccepted"])
        self.assertIsNone(result["selected"])
        self.assertIn("conflicting effects", result["copy"])
        self.assertIn("inferred", result["copy"])
        self.assertIn("contradicted", result["copy"])
        self.assertIn("little-endian", result["copy"])
        self.assertEqual(result["unknownCell"], "register[unknown] = unknown")
        self.assertIn("No source-bound declarative effects", result["emptyCopy"])

    def test_reachable_graph_renders_both_edges_and_named_frontier(self) -> None:
        app = (UI_DIRECTORY / "app.js").read_text(encoding="utf-8")
        start = app.index("      function renderVmReachability")
        end = app.index("      function renderVmBytecode", start)
        for name in ("complete", "frontier"):
            fixture = json.loads((FIXTURE.parent / f"vm-reachability-{name}-v2.json").read_text(encoding="utf-8"))
            result = self.run_evidence_model(
                """
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.attributes = {}; this.textContent = ''; }
  append(...items) { this.children.push(...items); }
  setAttribute(key, value) { this.attributes[key] = value; }
}
const document = {createElement: tag => new Element(tag)};
const textElement = (tag, cls, text) => { const node = new Element(tag); node.className = cls; node.textContent = text; return node; };
const flatten = node => [node, ...node.children.flatMap(flatten)];
""" + app[start:end] + f"""
const fixture = {json.dumps(fixture)};
process.stdout.write(JSON.stringify({{
  accepted: isVmOpcodeWorkspaceDocument(fixture),
  copy: flatten(renderVmReachability(fixture.workspaces[0])).map(row => row.textContent).join(' ')
}}));
"""
            )
            self.assertTrue(result["accepted"])
            self.assertIn("branch_taken", result["copy"])
            self.assertIn("branch_not_taken", result["copy"])
            self.assertIn("byte 0", result["copy"])
            self.assertIn("without executing captured source", result["copy"])
            if name == "frontier":
                self.assertIn("frontier remains", result["copy"])
                self.assertIn("past-snapshot", result["copy"])
                self.assertIn("byte 99", result["copy"])
            else:
                self.assertIn("walk complete", result["copy"])

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
