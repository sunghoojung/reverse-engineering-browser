// Production bridge-controller ownership tests with a bounded DOM model.
// These tests are not rendered-browser or native macOS acceptance.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';
import {candidateTargetChoiceReady} from './check-candidate-experiment-journey.mjs';

function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}
export async function checkCandidateExperimentController(root) {
  await checkRuntimeHooksSnapshotReadiness(root);
  await checkCapturedDocumentHookControls(root);
  await checkCapturedHookActionLifecycle(root);
  const source=await readFile(join(root,'apps/research-ui/field_provenance.js'),'utf8');
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const closeHooks=app.slice(app.indexOf('      function closeSourceHooks('),app.indexOf('      function pivotSourceToRuntimeHooks('));
  const lifetimeKey=app.slice(app.indexOf('      function experimentLifetimeKey('),app.indexOf('      function experimentContextKey('));
  const synchronizer=app.slice(app.indexOf('      function clearExperimentLifetime('),app.indexOf('      async function runExperimentAction('));
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
    const api=runInNewContext(decoder+'\n'+closeHooks+'\n'+lifetimeKey+'\n'+synchronizer+'\n'+controller+'\n;({sync:syncExperimentSession,closeHooks:closeSourceHooks,start:startCandidateExperiment,source:candidateSourceText,prefill:prefillCandidateField,render:renderCandidateExperiment,bind:bindCandidateExperiment,retire:retireCandidateExperimentPending,get owner(){return candidateExperiment;},get selection(){return fieldProvenanceSelection;},set selection(value){fieldProvenanceSelection=value;}})',context);
    const node=name=>document.querySelector('#candidate-experiment-'+name);
    const disposable=()=>{
      state.debuggerSession.target={id:'disposable-page',url:'http://127.0.0.1/candidate-page'};
      state.debuggerSession.object_experiment.navigation_id=1;state.debuggerSession.request_interception.created_at_ms=101;
      Object.assign(hooks,{isolated:true,target_id:'disposable-page',state:'ready',session_id:1,workers:[{id:'worker-A',title:'Owned worker'}]});
      state.debuggerSession.scripts=[{...script,script_id:'replay-script',target_id:'disposable-page'}];api.render();
    };
    const choose=id=>{node('target').value=id;node('target').fire('change');};
    const definition=()=>({id:7,candidate_guard:{...api.owner.fingerprint,target_id:api.owner.target}});
    return {api,state,hooks,elements,script,loaded,text,site,selection,calls,confirmations,node,document,disposable,choose,definition,setLoad:value=>{load=value;},setAction:value=>{action=value;},setConfirm:value=>{options.confirm=value;},get renders(){return renders;}};
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

  c=fixture();await c.api.start(c.site);const retainedQuestion=c.api.owner;
  const creating={...c.state.debuggerSession,generation:1,request_interception:{experiment_id:1,created_at_ms:101,state:'creating',isolated:false,target_id:null}};
  c.state.debuggerSession=c.api.sync(c.state.debuggerSession,creating);const beforeReady=structuredClone(creating);
  c.disposable();const ready={...c.state.debuggerSession,generation:2,request_interception:{...creating.request_interception,state:'ready',isolated:true,target_id:'disposable-page'}};
  c.state.debuggerSession=c.api.sync(beforeReady,ready);c.api.render();
  assert.equal(c.elements.hooksFieldUrl.value,'','Actual creating-to-ready synchronizer erases value-test draft');assert.equal(c.elements.hooksFieldPointer.value,'');assert.equal(c.api.owner,retainedQuestion,'Original question survives ordinary new-lifetime draft clearing');assert.equal(c.calls.length,0);
  c.choose('disposable-page');c.setAction(async()=>{c.hooks.definitions=[c.definition()];return {runtime_hooks:c.hooks};});await c.api.bind();
  assert.equal(c.elements.hooksFieldUrl.value,c.selection.url,'Explicit Bind restores original field metadata after real lifetime transition');assert.equal(c.elements.hooksFieldPointer.value,'/payload');assert.equal(c.elements.hooksFieldConfirm.checked,false);assert.equal(c.elements.hooksConfirm.checked,false);assert.equal(c.calls.length,1);assert.equal(c.calls[0].action,'bind_runtime_candidate');assert(c.api.owner.bound);
  // A mutation receipt can precede a previously started debugger poll. The
  // real synchronizer preserves receipt groups but blocks another action until
  // a current snapshot arrives; the candidate controls must expose that gate.
  c=fixture();await c.api.start(c.site);c.disposable();c.choose('disposable-page');
  c.state.debuggerSession.generation=10;
  const previous=c.state.debuggerSession;
  c.state.experimentReceipt={generation:11,groups:['runtime_hooks']};
  const targetReadiness=()=>candidateTargetChoiceReady({present:true,disabled:c.node('target').disabled,
    receipt:Boolean(c.state.experimentReceipt),needsRefresh:Boolean(c.state.experimentNeedsRefresh),
    experimentPending:Boolean(c.state.experimentPending),debuggerActionPending:Boolean(c.state.debuggerActionPending)});
  assert.equal(c.node('target').disabled,false,'Action acknowledgement may leave target enabled before an older GET arrives');
  assert.equal(targetReadiness(),false,'Journey must wait on the receipt even before stale GET reconciliation disables the control');
  c.state.debuggerSession=c.api.sync(previous,{...previous,generation:10},null);
  assert.equal(c.state.experimentNeedsRefresh,true);
  c.api.render();assert.equal(c.node('bind').disabled,true);assert.equal(c.node('target').disabled,true);
  assert.match(c.node('status').textContent,/Waiting for a current debugger snapshot/);
  assert.equal(targetReadiness(),false,'Retained target option is not an actionable selection while reconciliation is pending');
  c.api.owner.bound={id:999,context:'expired'};c.api.render();
  assert.equal(c.api.owner.bound,null);assert.match(c.node('status').textContent,/Waiting for a current debugger snapshot/,'Expired binding still explains the active reconciliation gate');
  await c.api.bind();assert.equal(c.calls.length,0,'Stale poll cannot dispatch Bind');
  // The handler must also guard a stale rendered enabled control.
  c.node('bind').disabled=false;const beforeDraft=c.elements.hooksFieldUrl.value;
  await c.api.bind();assert.equal(c.calls.length,0);assert.equal(c.elements.hooksFieldUrl.value,beforeDraft);
  c.state.debuggerSession=c.api.sync(c.state.debuggerSession,{...previous,generation:11},c.state.experimentReceipt);
  c.api.render();assert.equal(c.state.experimentNeedsRefresh,false);assert.equal(c.node('bind').disabled,false);
  assert.equal(c.calls.length,0,'Reconciliation does not automatically retry');
  assert.equal(c.node('target').disabled,false);assert.equal(targetReadiness(),true,'Only current production snapshot recovery admits native target selection');
  c.state.debuggerActionPending=true;c.api.render();assert.equal(c.node('bind').disabled,true);
  assert.match(c.node('status').textContent,/Waiting for the current debugger action/);
  c.node('bind').disabled=false;await c.api.bind();assert.equal(c.calls.length,0);
  c.state.debuggerActionPending=false;c.api.render();
  c.setAction(async()=>{c.hooks.definitions=[c.definition()];return {runtime_hooks:c.hooks};});
  await c.api.bind();assert.equal(c.calls.length,1);assert(c.api.owner.bound,'Explicit Bind works after reconciliation');

  c=fixture({confirm:false});await c.api.start(c.site);c.disposable();c.choose('disposable-page');c.elements.hooksFieldUrl.value='http://127.0.0.1/user-draft';c.elements.hooksFieldPointer.value='/keep';c.elements.hooksFieldConfirm.checked=true;c.elements.hooksConfirm.checked=true;await c.api.bind();
  assert.equal(c.confirmations.length,1);assert.equal(c.calls.length,0,'Declining dirty metadata replacement must prevent binding POST');assert.equal(c.elements.hooksFieldUrl.value,'http://127.0.0.1/user-draft');assert.equal(c.elements.hooksFieldPointer.value,'/keep');assert.equal(c.elements.hooksFieldConfirm.checked,true);assert.equal(c.elements.hooksConfirm.checked,true);assert.equal(c.api.owner.bound,null);assert.match(c.api.owner.notice,/draft retained/);
  c.setConfirm(true);c.setAction(async()=>{c.hooks.definitions=[c.definition()];return {runtime_hooks:c.hooks};});await c.api.bind();assert.equal(c.calls.length,1,'Accepted explicit retry dispatches once');assert.equal(c.api.owner.selection.error,null,'Accepted original metadata replacement clears declined-draft warning');assert.equal(c.elements.hooksFieldUrl.value,c.selection.url);assert.equal(c.elements.hooksFieldPointer.value,'/payload');assert.equal(c.elements.hooksFieldConfirm.checked,false);assert.equal(c.elements.hooksConfirm.checked,false);

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
  for(const relevant of [false,true]) {
    const held=deferred();c=fixture({action:()=>held.promise});await c.api.start(c.site);c.disposable();c.choose('disposable-page');
    const definition=c.definition(),binding=c.api.bind();
    c.state.debuggerSession.scripts.push({...c.script,script_id:'later-script',target_id:relevant?'disposable-page':'unrelated-worker',hash:'new-hash'});
    c.hooks.definitions=[definition];held.resolve({runtime_hooks:c.hooks});await binding;
    assert.equal(c.api.owner.bound?.id??null,relevant?null:7,relevant?'Selected-target catalog churn rejects late binding':'Unrelated Worker discovery leaves Page acknowledgement current');
    assert.equal(c.elements.hooksConfirm.checked,false);
  }
  for(const changedTarget of ['worker-A','worker-B']) {
    const held=deferred();c=fixture({action:()=>held.promise});await c.api.start(c.site);c.disposable();
    c.state.debuggerSession.scripts.push({...c.script,script_id:'worker-source',target_id:'worker-A'});c.choose('worker-A');
    const definition=c.definition(),binding=c.api.bind();
    c.state.debuggerSession.scripts.push({...c.script,script_id:'later-worker-source',target_id:changedTarget,hash:'new-hash'});
    c.hooks.definitions=[definition];held.resolve({runtime_hooks:c.hooks});await binding;
    assert.equal(c.api.owner.bound?.id??null,changedTarget==='worker-A'?null:7,'Only the explicitly selected Worker owns its pending catalog');
  }
  console.log('PASS candidate bridge production controller: full UTF-8 ownership, unsupported source locations, inert handoff, dirty draft cancellation, late source/digest/bind rejection, explicit target/consent lifetime, exact baseline field/hook and return/close ownership (DOM model; not rendered QA)');
}
if(process.argv[1]===new URL(import.meta.url).pathname)await checkCandidateExperimentController(process.argv[2]||new URL('..',import.meta.url).pathname);

// Exercise the actual poll reconciler, complete Hooks renderer, navigation
// handler and fail-closed action dispatcher. Only DOM/transport are modeled.
async function checkRuntimeHooksSnapshotReadiness(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const section=(start,end)=>app.slice(app.indexOf(start),app.indexOf(end,app.indexOf(start)));
  const code=[
    section('      function experimentLifetimeKey(', '      function experimentContextKey('),
    section('      function clearExperimentLifetime(', '      async function runExperimentAction('),
    section('      async function runExperimentAction(', '      async function configureExperimentRule('),
    section('      function setExperimentNotice(', '      function renderActionScope('),
    section('      function renderRuntimeHookDefinitions(', '      function renderRuntimeHookHits('),
    section('      function renderRuntimeHooks(', '      function parseAutomationVariables('),
    section('      async function navigateRuntimeHooks(', '      async function navigateAutomationRecipes(')
  ].join('\n');
  const node=()=>({dataset:{},value:'',checked:false,firstChild:{},children:[],querySelectorAll:()=>[],
    replaceChildren(...children){this.children=children;},append(...children){this.children.push(...children);},setAttribute(){},addEventListener(){},focus(){}});
  const elements=new Proxy({}, {get(target,key){return target[key]??=(node());}}),calls=[];
  const state={sourceHooksOpen:true,experimentPending:false,debuggerActionPending:false,experimentNeedsRefresh:false,debuggerSession:{generation:10,state:'running',target:{id:'owned-page'},scripts:[],
    request_interception:{isolated:true,target_id:'owned-page',state:'ready',experiment_id:1,created_at_ms:101,pending_requests:0},
    object_experiment:{state:'ready',navigation_id:0,url:''},
    runtime_hooks:{isolated:true,target_id:'owned-page',session_id:1,state:'ready',message:'Ready',definitions:[],hits:[{}],requests:[]}}};
  let fieldReadiness;
  const context={state,elements,document:{createElement:node},requestInterception:()=>state.debuggerSession.request_interception,
    objectExperimentState:()=>state.debuggerSession.object_experiment,runtimeHooksState:()=>state.debuggerSession.runtime_hooks,
    repeaterState:()=>null,automationRecipesState:()=>null,sourceName:item=>item.url,
    textElement:()=>node(),renderRuntimeHookHits(){},renderRuntimeFieldTest:(hooks,editable,comparable)=>{fieldReadiness={editable,comparable};},
    experimentActionGroups:()=>['object_experiment'],experimentContextKey:()=> 'owned-lifetime',currentExperimentReceipt:value=>value,
    debuggerAction:async request=>{calls.push(request);return null;}};
  const api=runInNewContext(code+'\n;renderExperiment=renderRuntimeHooks;({sync:syncExperimentSession,render:renderRuntimeHooks,navigate:navigateRuntimeHooks})',context);
  const original=state.debuggerSession;
  elements.hooksPageUrl.value='http://127.0.0.1/owned-page';
  api.render();assert.equal(elements.hooksNavigate.disabled,false);
  const receipt={generation:11,groups:['request_interception','runtime_hooks','object_experiment']};
  state.experimentReceipt=receipt;
  state.debuggerSession=api.sync(original,{...original,generation:10},null);
  assert.equal(state.experimentNeedsRefresh,true);api.render();
  for(const control of ['hooksNavigate','hooksCreate','hooksDispose','hooksClear','hooksAdd','hooksArm','hooksDisarm'])
    assert.equal(elements[control].disabled,true,control+' must reflect the stale snapshot dispatch gate');
  assert.equal(fieldReadiness.editable,false);assert.equal(fieldReadiness.comparable,false);
  assert.equal(elements.sourceHooksNotice.hidden,false);
  assert.match(elements.sourceHooksNotice.textContent,/Waiting for a current debugger snapshot/);
  // Even a queued event from an earlier enabled rendering remains fail-closed.
  await api.navigate();assert.equal(calls.length,0);assert.match(state.experimentError,/No request was sent/);
  assert.equal(elements.hooksPageUrl.value,'http://127.0.0.1/owned-page','Refusal preserves the URL draft');
  state.experimentError=null;
  state.debuggerSession.runtime_hooks.state='armed';api.render();
  assert.equal(elements.hooksDisarm.disabled,false,'Cleanup remains available while a poll is stale');
  assert.match(elements.sourceHooksNotice.textContent,/Waiting for a current debugger snapshot/,'Armed status must not conceal the refusal reason');
  const hooks=state.debuggerSession.runtime_hooks;
  hooks.state='ready';hooks.definitions=[{id:1,label:'Owned',function_kind:'ordinary',entry_mode:'function',function_expression:'owned',target_id:'owned-page',target_type:'page',return_mode:'none',url:'http://127.0.0.1/owned.js'}];
  api.render();assert.equal(elements.hooksDefinitions.children[0].children[1].disabled,true,'Remove also refuses stale snapshots');
  state.debuggerSession=api.sync(state.debuggerSession,{...state.debuggerSession,generation:11},receipt);
  api.render();assert.equal(state.experimentNeedsRefresh,false);assert.equal(elements.hooksNavigate.disabled,false);
  assert.equal(elements.hooksDefinitions.children[0].children[1].disabled,false);
  assert.equal(calls.length,0,'Fresh reconciliation never retries a refused navigation');
  await api.navigate();assert.equal(calls.length,1);assert.equal(calls[0].action,'navigate_object_experiment');
  console.log('PASS Runtime Hooks stale-GET admission: new mutations disabled and cleanup retained, visible reason, retained draft, fail-closed event and explicit recovery (DOM model)');
}

async function checkCapturedDocumentHookControls(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const section = (start, end) => app.slice(app.indexOf(start), app.indexOf(end, app.indexOf(start)));
  const hooksCode = section('      function experimentLifetimeKey(', '      function experimentContextKey(') + section('      function renderRuntimeHooks(', '      function parseAutomationVariables(');
  const node = () => ({dataset: {}, value: '', checked: false, firstChild: {}, children: [], hidden: false, disabled: false,
    querySelectorAll: () => [], replaceChildren(...children) { this.children = children; }, append(...children) { this.children.push(...children); },
    setAttribute() {}, addEventListener() {}, focus() {}});
  const elements = new Proxy({}, {get(target, key) { return target[key] ??= node(); }});
  const script = {script_id: 'captured-script', language: 'JavaScript', url: 'http://127.0.0.1/captured.js', target_type: 'page', start_line: 0, end_line: 3, start_column: 0};
  const state = {sourceHooksOpen: true, experimentPending: false, debuggerActionPending: false, experimentNeedsRefresh: false, experimentError: null,
    debuggerSession: {state: 'running', target: {id: 'captured-page', title: 'Captured demo', url: 'http://127.0.0.1/captured'}, scripts: [script],
      request_interception: {isolated: false, target_id: null, state: 'idle', pending_requests: 0},
      object_experiment: {state: 'idle', navigation_id: 0, url: ''},
      runtime_hooks: {isolated: false, target_id: null, session_id: 0, state: 'idle', message: 'Idle', definitions: [], hits: [], requests: [], workers: [], total_hits: 0}}};
  const context = {state, elements, document: {createElement: node}, requestInterception: () => state.debuggerSession.request_interception,
    objectExperimentState: () => state.debuggerSession.object_experiment, runtimeHooksState: () => state.debuggerSession.runtime_hooks,
    repeaterState: () => null, automationRecipesState: () => null, sourceName: item => item.url, textElement: () => node(),
    renderRuntimeHookDefinitions() {}, renderRuntimeHookHits() {}, renderRuntimeFieldTest() {}, setExperimentNotice() {}};
  const api = runInNewContext(hooksCode + '\n;({render:renderRuntimeHooks,consent:hookConfirmationKey,pause:capturedPauseRequest})', context);
  elements.hooksScript.replaceChildren = function(...children) { this.children = children; this.value = children[0]?.value ?? ''; };
  elements.hooksLabel.value = 'Captured';
  elements.hooksScript.value = script.script_id;
  elements.hooksLine.value = '1';
  elements.hooksColumn.value = '1';
  elements.hooksEntryEnabled.checked = true;
  elements.hooksConfirm.checked = false;
  api.render();
  assert.equal(elements.hooksPauseLine.disabled, false, 'Captured page line can pause before an isolated context exists');
  assert.deepEqual(JSON.parse(JSON.stringify(api.pause())), {action:'set_breakpoint', url:'', script_id:script.script_id, line:0, column:0, kind:'line', condition:''});
  elements.hooksLine.value = '9'; api.render();
  assert.equal(elements.hooksPauseLine.disabled, true, 'A line outside the attached script cannot pause');
  elements.hooksLine.value = '1';
  const optionText = elements.hooksScript.children.map(option => option.textContent);
  assert(optionText.some(text => text.includes('http://127.0.0.1/captured.js')), 'Captured document source must be listed');
  assert(!optionText.every(text => text === 'No live JavaScript sources'));
  assert.equal(elements.hooksAdd.disabled, false);
  assert.equal(elements.hooksArm.disabled, true);
  assert.equal(elements.hooksConfirm.checked, false, 'Arming stays explicit');
  assert.equal(elements.hooksNavigate.disabled, true, 'Captured document must not enable disposable navigation');
  assert.equal(elements.hooksPageUrl.disabled, true);
  assert.equal(elements.hooksContextBadge.textContent, 'Captured demo');
  const hooks = state.debuggerSession.runtime_hooks;
  Object.assign(hooks, {captured_owner: {target_id:'captured-page'}, isolated: true, target_id: 'captured-page', session_id: 4, state: 'armed', definitions: [{id: 1}], total_hits: 0});
  api.render();
  assert.equal(elements.hooksContextBadge.textContent, 'Captured demo');
  assert.equal(elements.hooksDisarm.disabled, false);
  assert.equal(elements.hooksPauseLine.disabled, false, 'An armed hook does not remove the captured-page pause control');
  assert.equal(elements.hooksDispose.disabled, false);
  assert.equal(elements.hooksArm.disabled, true);
  assert.equal(elements.hooksConfirm.checked, false);
  assert.equal(elements.hooksStorageState.textContent, 'Hook records only; page storage persists');
  hooks.state = 'disarmed';
  state.hooksConfirmationOwner = api.consent(); elements.hooksConfirm.checked = true;
  api.render(); assert.equal(elements.hooksConfirm.checked, true);
  script.hash = 'replacement'; api.render();
  assert.equal(elements.hooksConfirm.checked, false, 'Source replacement invalidates explicit consent');
  assert.equal(elements.hooksScript.value, '', 'Reused script ID must not silently select replacement source');
  assert.equal(elements.hooksAdd.disabled, true);
  state.hooksSelectedSource = null; elements.hooksScript.value = script.script_id;
  api.render(); assert.equal(elements.hooksAdd.disabled, false, 'Explicit reselection recovers');
  hooks.state = 'armed';
  state.debuggerSession.state = 'waiting'; state.debuggerSession.scripts = [];
  state.debuggerSession.target = {id: 'other-page'};
  api.render();
  assert.equal(elements.hooksDispose.disabled, false, 'Closed or replaced captured target still permits erase');
  assert.equal(elements.hooksDisarm.disabled, false);
  assert.equal(elements.hooksPauseLine.disabled, true, 'A replaced target has no page script to pause');
  assert.equal(elements.hooksArm.disabled, true);
  assert.equal(elements.hooksAdd.disabled, true);
  Object.assign(hooks, {isolated:false, target_id:null, captured_owner:null, state:'disposed', definitions:[]});
  state.debuggerSession.state = 'running'; state.debuggerSession.scripts = [script];
  state.debuggerSession.target = {id:'captured-page',title:'Captured demo'};
  state.hooksSelectedSource = null; elements.hooksScript.value = script.script_id;
  api.render();
  assert.equal(elements.hooksAdd.disabled, false, 'Erase does not strand the still-open page');
  hooks.isolated = true; hooks.target_id = 'captured-page';
  state.debuggerSession.request_interception = {isolated: true, target_id: 'captured-page', state: 'ready', pending_requests: 0};
  hooks.state = 'armed'; hooks.captured_owner = null;
  api.render();
  assert.equal(elements.hooksContextBadge.textContent, 'Disposable context');
  assert.equal(elements.hooksDispose.disabled, false, 'Disposable dispose stays available while hooks are armed');
  assert.equal(elements.hooksDisarm.disabled, false);
  const experimentCode = section('      function renderExperiment(', '      function experimentLifetimeKey(');
  const experimentElements = new Proxy({}, {get(target, key) { return target[key] ??= node(); }});
  experimentElements.experimentModeButtons = [];
  const experimentState = {experimentMode: 'interceptor', experimentPending: false, debuggerActionPending: false, experimentError: null,
    requests: [], selectedRequestId: null, selectedField: null,
    debuggerSession: {state: 'running', target: {id: 'owned-page'},
      request_interception: {isolated: true, target_id: 'owned-page', state: 'ready', pending_requests: 0, experiment_id: 0, message: 'Ready'},
      runtime_hooks: {state: 'armed'}}};
  runInNewContext(experimentCode + '\n;renderExperiment()', {state: experimentState, elements: experimentElements, document: {createElement: node, querySelector: () => ({hidden: false})},
    localOverrideManager: {render() {}}, renderActionScope() {}, prefillExperimentRequest() {}, setExperimentRuleVisibility() {}, setExperimentNotice() {},
    renderExperimentResult() {}, renderExperimentAudit() {}, requestInterception: () => experimentState.debuggerSession.request_interception,
    runtimeHooksState: () => experimentState.debuggerSession.runtime_hooks, automationRecipesState: () => null});
  assert.equal(experimentElements.experimentDispose.disabled, false, 'Dispose context stays available while the hooks badge is armed');
  assert.equal(experimentElements.experimentRun.disabled, true, 'Other interceptor controls stay locked while hooks are armed');
  console.log('PASS captured-document Runtime Hooks controls: live source list, explicit arm, disarm and dispose (DOM model)');
}

// Exercise the actual POST controller, receipt validators and GET reconciler.
// Only the bridge transport and non-rendering DOM are modeled.
async function checkCapturedHookActionLifecycle(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const models = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
  const empty = JSON.parse(await readFile(join(root, 'apps/origin-trace-backend/assets/debugger-empty.json'), 'utf8'));
  const section = (start, end) => app.slice(app.indexOf(start), app.indexOf(end, app.indexOf(start)));
  const code = models + section('      function experimentLifetimeKey(', '      function currentExperimentReceipt(') +
    section('      function experimentActionGroups(', '      function clearExperimentLifetime(') +
    section('      function syncExperimentSession(', '      async function configureExperimentRule(');
  const owner = {instance_id:'fixture-instance',connection_epoch:1,document_epoch:2,target_id:'captured-A'};
  const definition = {id:1,label:'Owned',script_id:'7',cdp_script_id:'7',target_id:owner.target_id,target_type:'page',entry_mode:'source',function_expression:'',url:'https://example.test/a.js',line:0,column:13,
    function_kind:'function_declaration',function_start:{line:0,column:0},function_end:{line:0,column:23},target_line:0,target_column:13,
    entry_enabled:true,return_enabled:false,condition:'',entry_logic:'',return_logic:'',return_mode:'none',return_expression:'',return_value:null,return_value_bytes:0,resolved:null};
  function fixture(initialHooks = null) {
    const session=structuredClone(empty);
    Object.assign(session,{generation:10,state:'running',target:{id:owner.target_id},target_document_epoch:2});
    Object.assign(session.network,{instance_id:owner.instance_id,capture_epoch:1});
    if(initialHooks)session.runtime_hooks=structuredClone(initialHooks);
    const state={debuggerSession:session,experimentPending:false,experimentNeedsRefresh:false};
    const transport=deferred(),calls=[];
    const api=runInNewContext(code+';({run:runExperimentAction,sync:syncExperimentSession,consent:hookConfirmationKey})',{
      state,TextEncoder,URL,renderExperiment(){},clearExperimentLifetime(){},
      debuggerAction:request=>{calls.push(request);return transport.promise;}
    });
    return {state,api,calls,transport};
  }
  const adopted={...structuredClone(empty.runtime_hooks),session_id:4,target_id:owner.target_id,captured_owner:owner,isolated:true,state:'ready',definitions:[definition]};
  const add={action:'add_runtime_hook',expected_session_id:0,captured_source:{owner,script_id:'7',source_hash:'hash',execution_context_id:3}};
  for(const order of ['POST-first','GET-first']) {
    const f=fixture();const pending=f.api.run(add);
    if(order==='GET-first')f.state.debuggerSession=f.api.sync(f.state.debuggerSession,{...f.state.debuggerSession,generation:11,runtime_hooks:structuredClone(adopted)});
    f.transport.resolve({ok:true,generation:11,runtime_hooks:structuredClone(adopted)});
    assert(await pending,order+' first Add must accept its exact captured session');
    assert.equal(f.state.experimentError,null);assert.equal(f.state.debuggerSession.runtime_hooks.session_id,4);
    assert.equal(f.calls.length,1,'No duplicate bridge request');
    const e=fixture(adopted);const erase={action:'disarm_runtime_hooks',erase:true,expected_session_id:4};
    const disposed={...structuredClone(empty.runtime_hooks),session_id:4,state:'disposed'};
    const removal=e.api.run(erase);
    if(order==='GET-first') {
      e.state.debuggerSession=e.api.sync(e.state.debuggerSession,{...e.state.debuggerSession,generation:10,target:{id:'replacement-tab'}});
      e.state.debuggerSession=e.api.sync(e.state.debuggerSession,{...e.state.debuggerSession,generation:11,runtime_hooks:disposed});
    }
    e.transport.resolve({ok:true,generation:11,runtime_hooks:disposed});
    assert(await removal,order+' erase must accept its exact session tombstone');assert.equal(e.state.experimentError,null);
    const reuse=fixture(disposed);const reused={...adopted,session_id:5};
    const adding=reuse.api.run({...add,expected_session_id:4});reuse.transport.resolve({ok:true,generation:11,runtime_hooks:reused});
    assert(await adding,'Add after erase accepts a fresh captured session');
  }
  for(const mutation of ['target','document','session','unrelated-group']) {
    const f=fixture();const pending=f.api.run(add);
    const foreign=structuredClone(adopted);const next={...f.state.debuggerSession,generation:11,runtime_hooks:foreign};
    if(mutation==='target')foreign.target_id='captured-B';
    if(mutation==='document')foreign.captured_owner.document_epoch=99;
    if(mutation==='session') {
      f.state.debuggerSession=f.api.sync(f.state.debuggerSession,{...next,runtime_hooks:structuredClone(adopted)});
      foreign.session_id=5;
    }
    if(mutation==='unrelated-group')next.object_experiment={...next.object_experiment,session_id:77};
    f.state.debuggerSession=f.api.sync(f.state.debuggerSession,next);
    f.transport.resolve({ok:true,generation:11,runtime_hooks:foreign});
    assert.equal(await pending,null,mutation+' must expire instead of blanket lifecycle acceptance');
    assert.equal(f.calls.length,1);
  }
  const consent=fixture(adopted),before=consent.api.consent();
  consent.state.debuggerSession.target_document_epoch++;
  assert.notEqual(consent.api.consent(),before,'Document replacement invalidates confirmation');
  console.log('PASS captured Hooks production controller: POST-first/GET-first Add, erase, reuse, exact receipt ownership and stale consent (DOM/bridge model)');
}
