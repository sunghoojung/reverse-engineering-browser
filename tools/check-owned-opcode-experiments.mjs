import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../apps/research-ui/evidence_models.js',import.meta.url),'utf8');
const {isVmOwnedExperimentRecord:valid,sameVmOwnedExperimentRequest:same}=new Function(source+'\nreturn {isVmOwnedExperimentRecord,sameVmOwnedExperimentRequest};')();
const effect={operation:'add_modulo_2_64',value:'12',next_pc:'3',branch_taken:null};
const request={command_id:'owned-test',fixture:'register',workspace_digest:'a'.repeat(64),source_artifact_sha256:'32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e',interpreter_artifact_id:'107',finding_id:'f-1',opcode:2,effect_id:'native-register-add_modulo_2_64-v1',inputs:{left:'7',right:'5'},expected:effect};
const row={request,effect_digest:'b'.repeat(64),fixture_revision:1,status:'confirmed',independent:effect,reason:'agreement-for-listed-inputs-only',observed:{backend_instance_id:'backend',session_id:'session',run_id:'run',run_generation:'1',invocation_id:'1',record_sequence:'3',build_id:'c'.repeat(64),program_sha256:'2e9f20bb3380e518db160b5da89e9a1530b03e31fb2bf094591b7ee5e0e1e778',opcode:2,handler_index:2,pc_before:'2',instruction_pointer_units:'instruction-index',inputs:request.inputs,effect}};
assert(valid(row));
for(const mutate of [r=>r.request.expected.value='13',r=>r.observed.effect.next_pc='4',r=>r.observed.pc_before='0',r=>r.observed.handler_index=7,r=>r.observed.instruction_pointer_units='byte-offset',r=>r.request.inputs.left='8',r=>r.observed=null,r=>r.independent=null,r=>r.expression='eval("x")',r=>r.request.inputs.right='18446744073709551616']) {const bad=JSON.parse(JSON.stringify(row));mutate(bad);assert.equal(valid(bad),false);}
assert.equal(valid(null),false);
const wrong=JSON.parse(JSON.stringify(row));wrong.status='mismatch';wrong.reason='expected-or-observed-effect-differs';wrong.request.expected.value='13';assert(valid(wrong));
const unsupported=JSON.parse(JSON.stringify(row));unsupported.status='unsupported';unsupported.reason='fixed-owned-inputs-only';unsupported.request.inputs.left='8';unsupported.independent=null;unsupported.observed=null;assert(valid(unsupported));
console.log('PASS owned opcode experiment records: input-specific confirmation, mismatch, unsupported, forged confirmation refusal');

assert(same(row.request,JSON.parse(JSON.stringify(row.request))));
for (const mutate of [r=>r.fixture='stack',r=>r.finding_id='another',r=>r.interpreter_artifact_id='108',r=>r.expected.value='13',r=>r.expected.next_pc='4',r=>r.expected.branch_taken=true,r=>r.inputs.left='8']) {const other=JSON.parse(JSON.stringify(row.request));mutate(other);assert.equal(same(row.request,other),false);}
console.log('PASS exact experiment receipt request ownership, including expected effect and input fields');

// The production form keeps a running or failed request's outcome after a
// poll rebuilds it: the message reaches the form now on screen.
{
  const {ownedOpcodeExperimentUiCase} = await import('./owned-opcode-experiment-ui-cases.mjs');
  const {runInNewContext} = await import('node:vm');
  const app=readFileSync(new URL('../apps/research-ui/app.js',import.meta.url),'utf8');
  const slice=(start,end)=>{const first=app.indexOf(start),last=app.indexOf(end,first);assert(first>=0&&last>first,start);return app.slice(first,last);};
  const attached=new Set();
  class Node {
    constructor(tag){this.tagName=tag;this.children=[];this.dataset={};this.listeners={};this.attributes={};this._text='';this.className='';this.value='';this.disabled=false;}
    get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
    set textContent(value){this._text=String(value);this.children=[];}
    append(...nodes){this.children.push(...nodes);} replaceChildren(...nodes){this._text='';this.children=[...nodes];}
    setAttribute(key,value){this.attributes[key]=String(value);} addEventListener(type,listener){this.listeners[type]=listener;}
    all(){return [this,...this.children.flatMap(child=>child.all?.() ?? [])];}
  }
  const document={createElement:tag=>new Node(tag),createTextNode:text=>({textContent:text}),
    querySelectorAll:selector=>[...attached].flatMap(root=>root.all()).filter(node=>selector==='.vm-experiment-output'?node.className==='vm-experiment-output':node.tagName==='button'&&node.attributes.type==='submit')};
  const workspaceDocument=await ownedOpcodeExperimentUiCase();
  const workspace=workspaceDocument.workspaces[0];
  let held;
  const ui=runInNewContext(source+slice('      function textElement(','      function counted(')+slice('      const ownedExperimentDrafts','      function renderVmHostLinks(')+';({renderVmOwnedExperiment})',
    {document,state:{vmOpcodeWorkspace:workspaceDocument},crypto:{randomUUID:()=>'owned-ui-test'},AbortSignal:{timeout:()=>undefined},TextEncoder,
      fetch:()=>new Promise((_,reject)=>{held=reject;})});
  const output=section=>section.all().find(node=>node.className==='vm-experiment-output');
  const first=ui.renderVmOwnedExperiment(workspace);attached.add(first);
  const form=first.all().find(node=>node.tagName==='form');
  const submit=form.listeners.submit({preventDefault(){}});
  assert.match(output(first).textContent,/Running the disposable owned fixture/);
  attached.delete(first);const second=ui.renderVmOwnedExperiment(workspace);attached.add(second);
  assert.match(output(second).textContent,/Running the disposable owned fixture/,'A rebuilt form shows the request still running');
  held(new Error('Outcome unknown or refused. Read saved results before trying another experiment.'));await submit;
  assert.match(output(second).textContent,/Outcome unknown or refused/,'The failure reaches the form on screen');
  const third=ui.renderVmOwnedExperiment(workspace);
  assert.match(output(third).textContent,/Outcome unknown or refused/,'The failure survives later rebuilds');
  console.log('PASS owned experiment form: running and unknown outcomes survive workspace re-renders and reach the visible form');
}
