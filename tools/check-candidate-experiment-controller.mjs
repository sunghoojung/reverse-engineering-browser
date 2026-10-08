// Production bridge-controller ownership tests with a bounded DOM model.
// These tests are not rendered-browser or native macOS acceptance.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';

function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
export async function checkCandidateExperimentController(root) {
  const source=await readFile(join(root,'apps/research-ui/field_provenance.js'),'utf8');
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const closeHooks=app.slice(app.indexOf('      function closeSourceHooks('),app.indexOf('      function pivotSourceToRuntimeHooks('));
  const controller=source.slice(source.indexOf('// One ephemeral owner.'));
  assert(controller.startsWith('// One ephemeral owner.'));
  const decoder=source.slice(source.indexOf('function provenanceDecoderBytes('),source.indexOf('\nfunction decodeProvenanceValue('));
  function fixture(options={}) {
    const nodes=new Map(),calls=[],confirmations=[];
    let load=options.load || (async()=>{}),action=options.action || (async()=>null),renders=0;
    class Node {
      constructor(id){this.id=id;this.dataset={};this.children=[];this.disabled=false;this.hidden=false;this.checked=false;this._value='';this.listeners={};}
      get value(){return this._value;}set value(v){this._value=v;}
      get options(){return this.children;}
      addEventListener(type,handler){this.listeners[type]=handler;}
      fire(type){return this.listeners[type]?.({target:this});}
      replaceChildren(...children){this.children=children;if(this.id==='candidate-experiment-target')this.value=children[0]?.value??'';}
      focus(){document.activeElement=this;}
      after(){}
      setAttribute(name,value){this[name]=value;}
    }
    const document={querySelector(selector){if(!nodes.has(selector))nodes.set(selector,new Node(selector.slice(1)));return nodes.get(selector);},createElement:tag=>new Node(tag),activeElement:null};
    const elements=Object.fromEntries(['hooksFieldUrl','hooksFieldMethod','hooksFieldKind','hooksFieldPointer','hooksFieldConfirm','hooksConfirm','hooksCreate','hooksHome','hooksWorkspace','hooksHitsHome','hooksHitsColumn','sourceHooksHits','sourceHooksNotice','sourceHookPivot'].map(key=>[key,new Node(key)]));
    elements.hooksFieldMethod.value='POST';elements.hooksFieldKind.value='json';
    const text='// 雪 😀\nfunction makePayload(input){return "fixture-observed";}\n';
    const script={kind:'javascript',script_id:'original-script',target_id:'original-page',hash:'opaque-cdp-hash',url:'http://127.0.0.1/candidate.js',start_line:0,start_column:0,target_type:'page'};
    const identity=value=>JSON.stringify([value.script_id,value.target_id,value.hash,value.url]);
    const loaded={identity:identity(script),content:text,sourceTextLength:text.length,loading:false,loadError:null,contentTruncated:false};
    const site={script_id:script.script_id,target_id:script.target_id,source_hash:script.hash,match_start_utf16:text.indexOf('fixture-observed'),match_end_utf16:text.indexOf('fixture-observed')+'fixture-observed'.length};
    const selection={url:'http://127.0.0.1/payload',value:'fixture-observed',kind:'json',selector:'/payload',request:{method:'POST',tabId:'original-page'},candidates:[site]};
    const hooks={isolated:false,target_id:null,state:'idle',session_id:0,definitions:[],hits:[],workers:[],field_test:{enabled:false,observations:[]}};
    const state={debuggerSession:{target:{id:'original-page',url:'http://127.0.0.1/candidate-page'},scripts:[script],runtime_hooks:hooks,object_experiment:{navigation_id:0},request_interception:{created_at_ms:0}},liveScriptContent:new Map([[script.script_id,loaded]]),sourceHooksOpen:false,experimentPending:false};
    const context={document,elements,state,fieldProvenanceSelection:selection,TextEncoder,TextDecoder,Uint8Array,setTimeout:options.setTimeout||setTimeout,clearTimeout:options.clearTimeout||clearTimeout,crypto:options.crypto||webcrypto,window:{confirm:message=>{confirmations.push(message);return options.confirm!==false;}},
      provenanceUI:{search:new Node('search')},liveScriptIdentity:identity,liveSources:()=>state.debuggerSession.scripts,
      loadScriptContent:item=>load(item),runtimeHooksState:()=>state.debuggerSession.runtime_hooks,
      experimentContextKey:()=>JSON.stringify([state.debuggerSession.runtime_hooks.session_id,state.debuggerSession.request_interception.created_at_ms,state.debuggerSession.target.id]),
      renderSourceSidebar:()=>{},renderFieldProvenance:()=>{renders++;},openSourceHooks:()=>{state.sourceHooksOpen=true;},
      showScreen:name=>{api.retire();document.querySelector('#screen-field-provenance').hidden=name!=='field-provenance';},
      renderRuntimeHooks:()=>api.render(),runExperimentAction:async request=>{calls.push(request);return action(request);},currentExperimentReceipt:value=>value};
    const api=runInNewContext(decoder+'\n'+closeHooks+'\n'+controller+'\n;({closeHooks:closeSourceHooks,start:startCandidateExperiment,source:candidateSourceText,prefill:prefillCandidateField,render:renderCandidateExperiment,bind:bindCandidateExperiment,retire:retireCandidateExperimentPending,get owner(){return candidateExperiment;},get selection(){return fieldProvenanceSelection;},set selection(value){fieldProvenanceSelection=value;}})',context);
    const node=name=>document.querySelector('#candidate-experiment-'+name);
    const disposable=()=>{
      state.debuggerSession.target={id:'disposable-page',url:'http://127.0.0.1/candidate-page'};
      state.debuggerSession.object_experiment.navigation_id=1;state.debuggerSession.request_interception.created_at_ms=101;
      Object.assign(hooks,{isolated:true,target_id:'disposable-page',state:'ready',session_id:1,workers:[{id:'worker-A',title:'Owned worker'}]});
      state.debuggerSession.scripts=[{...script,script_id:'replay-script',target_id:'disposable-page'}];api.render();
    };
    const choose=id=>{node('target').value=id;node('target').fire('change');};
    const definition=()=>({id:7,candidate_guard:{...api.owner.fingerprint,target_id:api.owner.target}});
    return {api,state,hooks,elements,script,loaded,text,site,selection,calls,confirmations,node,document,disposable,choose,definition,setLoad:value=>{load=value;},setAction:value=>{action=value;},get renders(){return renders;}};
  }
  let c=fixture();
  const original=c.api.source(c.script,c.loaded,'http://127.0.0.1/candidate-page');
  assert.equal(original.bytes.length,Buffer.byteLength(c.text));assert.equal(original.text,c.text);
  for(const patch of [{kind:'wasm'},{has_source_url:true},{start_line:1},{start_column:1},{url:'file:///candidate.js'},{url:'http://127.0.0.1/candidate-page'}])assert.throws(()=>c.api.source({...c.script,...patch},c.loaded,'http://127.0.0.1/candidate-page'),/Unsupported/);
  for(const patch of [{identity:'reused-id'},{loading:true},{loadError:'gone'},{contentTruncated:true},{sourceTextLength:undefined}])assert.throws(()=>c.api.source(c.script,{...c.loaded,...patch},'other'),/unavailable|changed/);
  for(const text of ['\uFEFF'+c.text,'\uFFFD','\ud800','x'.repeat(2*1024*1024+1),''])assert.throws(()=>c.api.source(c.script,{...c.loaded,content:text,sourceTextLength:text.length},'other'),/Unsupported/);
  c.elements.hooksConfirm.checked=true;c.elements.hooksFieldConfirm.checked=true;
  await c.api.start(c.site);assert(c.api.owner);assert.equal(c.elements.hooksConfirm.checked,false,'Candidate handoff retires old arming consent');assert.equal(c.calls.length,0,'Handoff never dispatches backend action');
  assert.equal(c.api.owner.fingerprint.start_byte,Buffer.byteLength(c.text.slice(0,c.site.match_start_utf16)));
  assert.equal(c.api.owner.originalText,c.text);assert.equal(c.elements.hooksFieldPointer.value,'/payload');assert.equal(c.elements.hooksFieldConfirm.checked,false);assert.equal(c.node('target').value,'');

  c=fixture({confirm:false});c.elements.hooksFieldUrl.value='http://127.0.0.1/dirty';c.elements.hooksFieldPointer.value='/other';
  await c.api.start(c.site);assert.equal(c.confirmations.length,1);assert.equal(c.api.owner,null);assert.equal(c.elements.hooksFieldUrl.value,'http://127.0.0.1/dirty');assert.equal(c.elements.hooksFieldPointer.value,'/other');assert.equal(c.calls.length,0);
  for(const interruption of ['navigate','new field','clear']){
    const held=deferred();c=fixture({load:()=>held.promise});const running=c.api.start(c.site);
    if(interruption==='navigate'){c.api.retire();c.document.querySelector('#screen-field-provenance').hidden=true;}
    else if(interruption==='new field')c.api.selection={...c.selection};
    else c.node('close').fire('click');
    held.resolve();await running;assert.equal(c.api.owner,null,interruption+' cannot accept late source');assert.equal(c.calls.length,0);
  }
  const digest=deferred();c=fixture({crypto:{subtle:{digest:()=>digest.promise}}});
  const preparing=c.api.start(c.site);await Promise.resolve();await Promise.resolve();c.state.debuggerSession.scripts=[{...c.script,hash:'changed'}];digest.resolve(new Uint8Array(32));await preparing;
  assert.equal(c.api.owner,null);assert.match(c.selection.error,/changed/);

  const appendedDigest=deferred();c=fixture({crypto:{subtle:{digest:()=>appendedDigest.promise}}});
  const appended=c.api.start(c.site);await new Promise(resolve=>setImmediate(resolve));
  c.loaded.content+='// appended after digest began';c.loaded.sourceTextLength=c.loaded.content.length;
  appendedDigest.resolve(new Uint8Array(32));await appended;assert.equal(c.api.owner,null,'Digest completion must revalidate complete source, not matching prefix');assert.match(c.selection.error,/changed|unavailable/);
  let expire;const heldSource=deferred();c=fixture({load:()=>heldSource.promise,setTimeout:(callback,ms)=>{assert(ms>=0&&ms<=15000);expire=callback;return 1;},clearTimeout:()=>{}});
  const timed=c.api.start(c.site);expire();await timed;assert.equal(c.api.owner,null);assert.match(c.selection.error,/15 seconds/);heldSource.resolve();await Promise.resolve();assert.equal(c.api.owner,null,'Late source after deadline cannot enter experiment');

  c=fixture();await c.api.start(c.site);c.disposable();
  c.hooks.workers=[{id:'worker-A',title:'Same worker URL'},{id:'worker-B',title:'Same worker URL'}];c.api.render();
  const workerOptions=c.node('target').options.filter(option=>option.value.startsWith('worker-'));
  assert.notEqual(workerOptions[0].textContent,workerOptions[1].textContent,'Same-title workers expose distinct target labels');
  for(const option of workerOptions){assert(option.textContent.includes(option.value));assert(option.title.includes(option.value));assert(option['aria-label'].includes(option.value));}
  const labelBefore=workerOptions[0].textContent.split(' · ').slice(0,2).join(' · ');
  c.hooks.workers.reverse();c.api.render();
  assert.equal(c.node('target').options.find(option=>option.value==='worker-A').textContent.split(' · ').slice(0,2).join(' · '),labelBefore,'Order refresh retains per-target display identity');
  c.choose('worker-A');c.hooks.workers.find(worker=>worker.id==='worker-A').title='Updated worker title';c.api.render();
  assert.equal(c.node('target').value,'worker-A','Presentation-only worker title changes retain exact selection');
  assert.equal(c.api.owner.target,'worker-A');
  const retiredAlias=c.api.owner.targetAliases.get('worker-A');
  c.hooks.workers=[{id:'identical-prefix-A',title:'same'},{id:'identical-prefix-B',title:'same'}];c.api.render();
  const collided=c.node('target').options.filter(option=>option.value.startsWith('identical-'));
  assert.notEqual(collided[0].textContent.split(' · ')[0],collided[1].textContent.split(' · ')[0],'Leading aliases remain distinct when truncated IDs collide');
  assert.equal(c.api.owner.targetAliases.size,2,'Only currently listed workers retain alias entries');
  c.hooks.workers=[{id:'worker-A',title:'Owned worker'}];c.api.render();
  assert.notEqual(c.api.owner.targetAliases.get('worker-A'),retiredAlias,'Removed display aliases are not reassigned when an ID returns');
  c.elements.hooksConfirm.checked=true;c.elements.hooksFieldConfirm.checked=true;c.choose('worker-A');
  assert.equal(c.elements.hooksConfirm.checked,false,'Target change retires arming consent');assert.equal(c.elements.hooksFieldConfirm.checked,false,'Target change retires field-capture consent');
  c.hooks.workers[0].title='http://127.0.0.1/candidate-worker.js';c.api.render();assert.equal(c.node('target').value,'worker-A','Title refresh retains exact selected worker ID');assert.equal(c.api.owner.target,'worker-A');assert.match(c.node('target').options.find(option=>option.value==='worker-A').textContent,/http:\/\/127\.0\.0\.1\/candidate-worker\.js/);assert.equal(c.calls.length,0,'Refreshing worker label does not bind or dispatch');
  c.choose('disposable-page');c.elements.hooksConfirm.checked=true;c.elements.hooksFieldConfirm.checked=true;c.setAction(async()=>{const definition=c.definition();c.hooks.definitions=[definition];return {runtime_hooks:c.hooks};});await c.api.bind();
  assert.equal(c.elements.hooksConfirm.checked,false,'Binding retires pre-bind arming consent');assert.equal(c.elements.hooksFieldConfirm.checked,false,'Binding retires pre-bind capture consent');
  assert.equal(c.calls.length,1);assert.equal(c.calls[0].action,'bind_runtime_candidate');assert.equal(c.api.owner.bound.id,7);assert.equal(c.node('target').disabled,true,'Bound definition keeps target fixed until explicit removal or expiry');assert.match(c.node('status').textContent,/bound/i);
  assert.equal(c.calls[0].target_id,'disposable-page');assert.equal(c.calls[0].source_sha256,c.api.owner.fingerprint.source_sha256);
  c.hooks.field_test={enabled:true,url:c.selection.url,method:'POST',kind:'json',pointer:'/payload',observations:[{target_id:'disposable-page',status:'available',related_hit_ids:[5],provenance:{candidates:[{hit_id:5,phase:'return',operation:'observed',matched_values:['original_return']}]}}]};
  c.hooks.hits=[{id:5,hook_id:7,category:'return',operation:'observed'}];c.api.render();assert.match(c.node('status').textContent,/Matched baseline/);
  c.hooks.field_test.observations[0].provenance.candidates[0].matched_values=[];c.api.render();assert.doesNotMatch(c.node('status').textContent,/Matched baseline/,'Temporal related hit without exact returned-value match is not a matched baseline');
  c.hooks.field_test.observations[0].provenance.candidates[0].matched_values=['original_return'];
  c.hooks.hits[0].hook_id=8;c.api.render();assert.doesNotMatch(c.node('status').textContent,/Matched baseline/,'Other hook cannot qualify baseline');
  c.hooks.hits[0].hook_id=7;c.hooks.field_test.pointer='/other';c.api.render();assert.doesNotMatch(c.node('status').textContent,/Matched baseline/,'Other selected field cannot qualify baseline');
  c.hooks.definitions=[];c.state.debuggerSession.object_experiment.navigation_id++;c.api.render();assert.equal(c.api.owner.bound,null);assert.equal(c.api.owner.target,'','Navigation requires explicit target reselection');

  for(const interruption of ['return','close','navigation','close Hooks panel','stop waiting']){
    const held=deferred();c=fixture({action:()=>held.promise});await c.api.start(c.site);c.disposable();c.choose('disposable-page');const retired=[];const actionOwner={transport:{retire:message=>{retired.push(message);}}};c.state.experimentPrimaryOwner=actionOwner;const owner=c.api.owner,definition=c.definition(),binding=c.api.bind();assert.equal(owner.pending.actionOwner,actionOwner,'Pending bridge retains actual action transport owner');assert.equal(c.node('cancel').hidden,false);
    if(interruption==='return')c.node('return').fire('click');else if(interruption==='close')c.node('close').fire('click');else if(interruption==='close Hooks panel')c.api.closeHooks();else if(interruption==='stop waiting')c.node('cancel').fire('click');else{c.state.debuggerSession.object_experiment.navigation_id++;c.api.retire();}
    assert.equal(retired.length,1,interruption+' retires the actual pending transport once');assert.match(retired[0],/Native completion is unknown/);
    c.hooks.definitions=[definition];held.resolve({runtime_hooks:c.hooks});await binding;
    assert.equal(c.calls.length,1,'Late response never retries');assert.equal(owner.bound,null,interruption+' cannot accept late binding');if(interruption!=='close')assert.equal(c.node('cancel').hidden,true,'Stop waiting hides after late transport settlement');
    if(interruption==='close')assert.equal(c.api.owner,null);else assert.match(c.api.owner.notice,/retired|changed|ownership/i);
    assert.equal(c.hooks.field_test.enabled,false,'No implicit capture after late reply');
  }
  console.log('PASS candidate bridge production controller: full UTF-8 ownership, unsupported source locations, inert handoff, dirty draft cancellation, late source/digest/bind rejection, explicit target/consent lifetime, exact baseline field/hook and return/close ownership (DOM model; not rendered QA)');
}
if(process.argv[1]===new URL(import.meta.url).pathname)await checkCandidateExperimentController(process.argv[2]||new URL('..',import.meta.url).pathname);
