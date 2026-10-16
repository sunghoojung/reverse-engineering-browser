// Authored interaction cases for the shared browser harness. No process lifecycle.
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
  workspace.coverage={complete:false,handler_count:2,retained_snapshot_bytes:0,characterized_bytes:0,uncharacterized_bytes:0,attributions:[],omissions:[{reason:'snapshot-bytes-unavailable'}]};
  document.summary.handler_count=2;document.summary.sample_count=0;document.summary.snapshot_count=0;
  const model=await readFile(new URL('apps/research-ui/evidence_models.js',root),'utf8');
  assert(runInNewContext(model+';isVmOpcodeWorkspaceDocument(value)',{value:document,TextEncoder}));
  return document;
}
// The shared harness supplies its own browser connection and screenshots.
// HTTP receipts here are authored UI fixtures; native execution has separate tests.
export async function checkOwnedOpcodeExperimentUi({evaluate,send}) {
  const fixture=await ownedOpcodeExperimentUiCase();
  await evaluate(`state.vmOpcodeWorkspace=${JSON.stringify(fixture)};state.vmOpcodeWorkspaceStatus='ready';render();
    window.__ownedOriginalFetch=window.fetch;window.__ownedRequests=[];window.fetch=async(url,options)=>{
      window.__ownedRequests.push([url,options]);throw new Error('Authored lost receipt; result unknown.');};`);
  try {
    assert.equal(await evaluate("document.querySelectorAll('.vm-experiment-form').length"),1);
    assert.equal(await evaluate('window.__ownedRequests.length'),0);
    await evaluate("document.querySelector('.vm-experiment-form input').focus()");
    for(const type of ['rawKeyDown','keyUp']) await send('Input.dispatchKeyEvent',{type,key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
    assert.equal(await evaluate("document.activeElement===document.querySelectorAll('.vm-experiment-form input')[1]"),true);
    await evaluate("document.querySelector('.vm-experiment-form button[type=submit]').focus()");
    for(const type of ['rawKeyDown','keyUp']) await send('Input.dispatchKeyEvent',{type,key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
    assert.equal(await evaluate('window.__ownedRequests.length'),1);
    assert((await evaluate('document.body.textContent')).includes('Authored lost receipt; result unknown.'));
    assert.equal(await evaluate("document.querySelector('.vm-experiment-form button[type=submit]').disabled"),false);
    assert.equal(await evaluate('document.documentElement.scrollWidth<=innerWidth'),true);
    assert((await evaluate('document.body.textContent')).includes('does not generalize'));
  } finally { await evaluate('window.fetch=window.__ownedOriginalFetch;delete window.__ownedOriginalFetch;delete window.__ownedRequests'); }
}
if(process.argv.includes('--validate-fixtures')) { await ownedOpcodeExperimentUiCase(); console.log('PASS owned opcode experiment authored UI case: strict v2 and explicit input form'); }
