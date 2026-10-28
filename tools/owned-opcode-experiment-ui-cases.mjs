// Authored native opcode fixture validation only; no browser control.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
export async function ownedOpcodeExperimentUiCase() {
  const root=new URL('../',import.meta.url);
  const document=JSON.parse(await readFile(new URL('tests/research_ui/fixtures/vm-opcode-workspace-v2.json',root),'utf8'));
  const metadata=JSON.parse(await readFile(new URL('tools/fixtures/vm-workspace-effects/native-register.json',root),'utf8'));
  const workspace=document.workspaces[0];
  workspace.source_artifact_sha256=metadata.source_sha256;workspace.runtime='javascript';workspace.samples=[];workspace.sample_count=0;workspace.snapshots=[];
  workspace.handlers=metadata.handlers.filter(h=>[2,7].includes(h.opcode)).map(h=>({...h,state:'inferred',source:{byte_offset:0,byte_size:1},operand_width:0,sample_count:0,notes:'Owned declaration, not universal confirmation.'}));
  workspace.machine_state={register_count:3,stack_observed:null};
  workspace.coverage={complete:false,handler_count:2,retained_snapshot_bytes:0,characterized_bytes:0,uncharacterized_bytes:0,attributions:[],omissions:[{reason:'snapshot-bytes-unavailable'}]};
  document.summary.handler_count=2;document.summary.sample_count=0;document.summary.snapshot_count=0;
  const model=await readFile(new URL('apps/research-ui/evidence_models.js',root),'utf8');
  assert(runInNewContext(model+';isVmOpcodeWorkspaceDocument(value)',{value:document,TextEncoder}));
  return document;
}
if(process.argv.includes('--validate-fixtures')) { await ownedOpcodeExperimentUiCase(); console.log('PASS owned opcode experiment authored UI case: strict v2 and explicit input form'); }
