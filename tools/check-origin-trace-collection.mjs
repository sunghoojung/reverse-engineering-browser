import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';

export function collectionFixtureDocument() {
  return {contract_version:1,document_kind:'api-collection',generation:3,updated_at_ms:1000,
    folders:[{id:1,name:'API Collection',parent_id:null,variables:[]},{id:2,name:'API checks',parent_id:1,variables:[{name:'host',value:'fixture.invalid'}]},{id:3,name:'Regression',parent_id:1,variables:[]}],
    requests:[1,2].map(id=>({id,folder_id:2,name:id===1?'List catalog':'Submit sample',url:`https://{{host}}/catalog/${id}`,method:id===1?'GET':'POST',headers:[{name:'accept',value:'application/json'}],body:id===1?'':'{"name":"sample"}',timeout_ms:15000,variables:[],created_at_ms:1000,updated_at_ms:1000})),
    limits:{folders:32,requests:128,folder_depth:4,variables_per_scope:32,variable_bytes_per_scope:32768,request_body_bytes:65536,document_bytes:2097152}};
}

// Exercise real Collection controller functions without claiming rendered acceptance.
export async function checkCollectionController(root, fixtureOnly = false) {
  const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const models = await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8');
  const experimentContext = app.slice(app.indexOf('      function experimentLifetimeKey('), app.indexOf('      function currentExperimentReceipt('));
  const section = app.slice(app.indexOf('      function collectionFolder('),app.indexOf('      const analystExactKeys'));
  const document = {activeElement:null};
  class Node {
    constructor(tag='div') {this.tagName=tag;this.dataset={};this.attributes=new Map();this.children=[];this.listeners=new Map();this.style={setProperty(){}};this.value='';this.scrollTop=0;this._text='';}
    set textContent(value){this._text=String(value);this.children=[];}
    get textContent(){return this._text+this.children.map(node=>node.textContent).join('');}
    setAttribute(key,value){this.attributes.set(key,String(value));}
    getAttribute(key){return this.attributes.get(key);}
    append(...nodes){this.children.push(...nodes);nodes.forEach(node=>node.parentElement=this);}
    replaceChildren(...nodes){this.children=[];this._text='';this.append(...nodes);}
    addEventListener(key,fn){this.listeners.set(key,fn);}
    contains(node){return node===this||this.children.some(child=>child.contains(node));}
    matches(selector){if(selector.startsWith('.'))return this.className===selector.slice(1);const data=selector.match(/^\[data-([\w-]+)="([^"]+)"\]$/);if(data)return this.dataset[data[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]===data[2];return selector.split(', ').includes(this.tagName);}
    querySelectorAll(selector){return this.children.flatMap(node=>[...(node.matches(selector)?[node]:[]),...node.querySelectorAll(selector)]);}
    querySelector(selector){return this.querySelectorAll(selector)[0]??null;}
    focus(){document.activeElement=this;}
    click(){this.listeners.get('click')?.({currentTarget:this});}
  }
  document.createElement=tag=>new Node(tag);
  document.querySelectorAll=()=>[];
  const elements=Object.fromEntries([...new Set([...section.matchAll(/elements\.(collection\w+)/g)].map(match=>match[1]))].map(name=>[name,new Node()]));
  for(const suffix of ['Name','Folder','Url','Method','Timeout','Headers','Body','Variables']){const node=elements[`collectionRequest${suffix}`];node.tagName=['Body','Variables','Headers'].includes(suffix)?'textarea':suffix==='Folder'?'select':'input';elements.collectionRequestForm.append(node);}
  elements.collectionFolderForm=new Node();
  for(const suffix of ['Name','Parent','Variables']){const node=elements[`collectionFolder${suffix}`];node.tagName=suffix==='Variables'?'textarea':suffix==='Parent'?'select':'input';elements.collectionFolderForm.append(node);}
  const state={apiCollection:collectionFixtureDocument(),apiCollectionLoaded:true,apiCollectionVersion:0,apiCollectionStatus:'ready',apiCollectionMessage:'Loaded',apiCollectionEtag:null,collectionSelectedFolderId:2,collectionSelectedRequestId:1,collectionExpandedFolderIds:new Set([1,2]),collectionRequestDraftId:null,collectionDraftDirty:false,collectionFolderDraftId:null,collectionFolderDirty:false,collectionSelectedHistoryId:null,collectionResponseTab:'body',collectionSelectionVersion:0,collectionHistorySelectionVersion:0,collectionRunOwners:new Map(),collectionPendingSubmission:null,collectionPendingRunSelection:null,apiCollectionNeedsReload:false,
    debuggerSession:{state:'running',target:{id:'target-1'},request_interception:{experiment_id:1,state:'ready',isolated:true,target_id:'target-1'},repeater:{state:'ready',history:[]}}};
  const pending=[];const actions=[];let fireDeadline;
  let actionHandler=async request=>{actions.push(request);return {};};
  const textElement=(tag,className,text)=>{const node=new Node(tag);node.className=className;node.textContent=text;return node;};
  const context={state,elements,document,TextEncoder,TextDecoder,URL,Set,Map,AbortController,setTimeout:(callback,delay)=>{if(delay===15000)fireDeadline=callback;return setTimeout(callback,delay);},clearTimeout,location:{protocol:'http:'},requestAnimationFrame:fn=>fn(),
    isPlainObject:value=>value!==null&&typeof value==='object'&&!Array.isArray(value),utf8ByteLength:value=>Buffer.byteLength(value),parseExperimentHeaders:value=>value.trim()?JSON.parse(value):{},repeaterHeaderObject:headers=>Object.fromEntries(headers.map(header=>[header.name,header.value])),
    textElement,emptyListboxOption:(_,text)=>textElement('div','',text),experimentFact:(label,value)=>textElement('div','',label+value),
    requestInterception:()=>state.debuggerSession.request_interception,repeaterState:()=>state.debuggerSession.repeater,
    currentExperimentReceipt:response=>response,runExperimentAction:request=>actionHandler(request),fetch:(url,options)=>new Promise((resolve,reject)=>{pending.push({url,options,resolve});options.signal?.addEventListener('abort',()=>reject(new Error('Aborted')),{once:true});})};
  const ui=runInNewContext(models+'\n'+experimentContext+'\n'+section+'\n;({renderApiCollection,renderCollectionExecution,selectCollectionFolder,selectCollectionRequest,saveCollectionRequest,saveCollectionFolder,refreshApiCollection,runCollectionRequest,createCollectionRequest,deleteCollectionRequest,moveCollectionTreeSelection,collectionNextRequestId,collectionHistoryEntries,isApiCollection,createCollectionFolder,duplicateCollectionRequest,deleteCollectionFolder})',context);
  if (fixtureOnly) return {ui,state,elements,pending,actions,document,context,setActionHandler:handler=>actionHandler=handler};
  assert(ui.isApiCollection(state.apiCollection));
  state.debuggerSession.repeater.history=[{collection_request_id:4,started_at_ms:1000},{collection_request_id:1,started_at_ms:999},{collection_request_id:1,started_at_ms:1001}];
  assert.equal(ui.collectionNextRequestId(),5,'Deleted recipe IDs must not be reused while their runs exist');
  assert.equal(ui.collectionHistoryEntries().length,1,'Runs older than recipe creation cannot be attributed to a reused ID');
  state.debuggerSession.repeater.history=[];
  ui.renderApiCollection();
  elements.collectionRequestBody.value='{"unfinished":';elements.collectionRequestFolder.value='3';state.collectionDraftDirty=true;
  assert.equal(ui.selectCollectionRequest(1),true);assert.equal(elements.collectionRequestBody.value,'{"unfinished":');
  assert.equal(ui.selectCollectionRequest(2),false);assert.equal(state.collectionSelectedRequestId,1);
  ui.renderApiCollection();assert.equal(elements.collectionRequestFolder.value,'3','Refresh must retain the draft folder move');
  const draftFolders=state.apiCollection.folders;state.apiCollection.folders=draftFolders.filter(folder=>folder.id!==3);ui.renderApiCollection();assert.equal(elements.collectionRequestFolder.value,'3');assert.match(elements.collectionRequestFolder.textContent,/Unavailable folder #3/);state.apiCollection.folders=draftFolders;
  await ui.createCollectionRequest();await ui.deleteCollectionRequest();assert.equal(pending.length,0,'Unsaved navigation and mutations must not save or send');
  elements.collectionFolderParent.value='3';state.collectionFolderDirty=true;ui.renderApiCollection();assert.equal(elements.collectionFolderParent.value,'3');
  state.collectionFolderDirty=false;state.collectionDraftDirty=false;ui.renderApiCollection();
  const selected=elements.collectionTree.querySelector('[data-request-id="1"]');selected.focus();elements.collectionTree.scrollTop=40;ui.renderApiCollection();
  assert.equal(document.activeElement.dataset.requestId,'1');assert.equal(elements.collectionTree.scrollTop,40);
  ui.moveCollectionTreeSelection({key:'ArrowDown',currentTarget:document.activeElement,preventDefault(){}});assert.equal(state.collectionSelectedRequestId,2);assert.equal(document.activeElement.dataset.requestId,'2');
  ui.selectCollectionRequest(1);elements.collectionRequestBody.value='draft survives';state.collectionDraftDirty=true;
  const failed=ui.saveCollectionRequest();assert.equal(pending.length,1);pending.shift().resolve(Response.json({error:'Synthetic disk failure'},{status:503}));assert.equal(await failed,false);assert(state.collectionDraftDirty);assert.equal(elements.collectionRequestBody.value,'draft survives');assert.match(state.apiCollectionMessage,/Save could not be confirmed/);
  const conflict=ui.saveCollectionRequest();pending.shift().resolve(Response.json({error:'Generation conflict'},{status:409}));await new Promise(resolve=>setTimeout(resolve,0));
  const latest=collectionFixtureDocument();latest.generation=4;latest.requests[0].name='New server name';pending.shift().resolve(Response.json(latest));assert.equal(await conflict,false);assert.equal(state.apiCollection.generation,4);assert(state.collectionDraftDirty);assert.equal(elements.collectionRequestBody.value,'draft survives');
  const removed=ui.refreshApiCollection(true);const without=structuredClone(latest);without.generation=5;without.requests.shift();pending.shift().resolve(Response.json(without));assert.equal(await removed,false);assert.equal(state.apiCollection.requests.length,2);assert.match(state.apiCollectionMessage,/removed or replaced in another window/);
  assert.equal(await ui.saveCollectionRequest(),false);assert.equal(pending.length,0,'A known-stale owner cannot be written');
  state.collectionDraftDirty=false;const reload=ui.refreshApiCollection(true);pending.shift().resolve(Response.json(latest));assert.equal(await reload,true);
  elements.collectionRequestBody.value='draft survives';state.collectionDraftDirty=true;
  const timedOut=ui.saveCollectionRequest();pending.shift();fireDeadline();assert.equal(await timedOut,false);
  assert.equal(state.apiCollectionSaving,false);assert(state.collectionDraftDirty);assert.match(state.apiCollectionMessage,/timed out/);
  const loadTimeout=ui.refreshApiCollection(true);pending.shift();fireDeadline();assert.equal(await loadTimeout,false);assert.equal(state.apiCollectionRefreshing,false);assert.equal(elements.collectionRequestBody.value,'draft survives');
  // An older load may not replace a newer explicit save or clear its status.
  state.collectionDraftDirty=false;ui.renderApiCollection();const load=ui.refreshApiCollection(true);const stale=pending.shift();
  elements.collectionRequestName.value='Saved after load';state.collectionDraftDirty=true;const save=ui.saveCollectionRequest();const replacement=pending.shift();const savedDoc=structuredClone(state.apiCollection);savedDoc.generation=5;savedDoc.requests[0].name='Saved after load';replacement.resolve(Response.json(savedDoc));assert.equal(await save,true);stale.resolve(Response.json(latest));assert.equal(await load,false);assert.equal(state.apiCollection.generation,5);assert.equal(elements.collectionRequestName.value,'Saved after load');
  // Save & Run is explicit, singly submitted, and reports save success separately.
  elements.collectionRequestName.value='Saved before run failure';state.collectionDraftDirty=true;
  actionHandler=async request=>{actions.push(request);return null;};
  const saveRun=ui.runCollectionRequest();await ui.runCollectionRequest();assert.equal(pending.length,1,'Repeated Save & Run must share the initial operation');
  const savedRun=structuredClone(state.apiCollection);savedRun.generation=6;savedRun.requests[0].name='Saved before run failure';pending.shift().resolve(Response.json(savedRun));await saveRun;assert.equal(state.collectionDraftDirty,false);assert.match(state.apiCollectionMessage,/Edits saved\..*could not be configured/);assert.equal(actions.length,1);
  // Changing context between configuring and sending must stop the second action.
  let release;actions.length=0;actionHandler=request=>{actions.push(request);return new Promise(resolve=>{release=resolve;});};
  const switchedContext=ui.runCollectionRequest();state.debuggerSession.request_interception.experiment_id=2;release({});await switchedContext;assert.equal(actions.length,1);assert.match(state.apiCollectionMessage,/context changed/);
  // A later selection is not stolen by the old run; payload owns the submitted snapshot.
  actions.length=0;let deferred=0;actionHandler=request=>{actions.push(request);if(++deferred===1)return new Promise(resolve=>{release=resolve;});return Promise.resolve({repeater:{history:[{id:91,collection_request_id:1,started_at_ms:2000}]}});};
  const late=ui.runCollectionRequest();ui.selectCollectionRequest(2);release({});await late;assert.equal(actions.length,2);assert.equal(actions[1].collection_request_id,1);assert.equal(state.collectionSelectedRequestId,2);assert.notEqual(state.collectionSelectedHistoryId,91);
  assert.equal(state.collectionRunPending,false);
  const responseEntry={id:92,collection_request_id:2,started_at_ms:2000,completed_at_ms:2001,state:'complete',resolved_request:{method:'POST',url:'https://fixture.invalid/exact-submitted'},response:{ok:true,status:200,status_text:'OK',duration_ms:1,body:'<script>inert()</script>',body_truncated:true,headers:[]}};
  state.debuggerSession.repeater.history=[responseEntry];ui.renderCollectionExecution();const body=elements.collectionResponse.children[1];elements.collectionResponse.scrollTop=80;
  state.debuggerSession.repeater.state='running';state.debuggerSession.repeater.active_execution={collection_request_id:2,started_at_ms:3000};ui.renderCollectionExecution();
  assert.equal(elements.collectionResponse.children[1],body);assert.equal(elements.collectionResponse.scrollTop,80);assert.match(elements.collectionResponseMeta.textContent,/another run in progress/);
  assert.equal(body.textContent,'<script>inert()</script>');assert.match(elements.collectionResponse.textContent,/truncated/);
  await checkCollectionReceiptTransport(root);
  await checkCollectionOwnership(root);
  await checkCollectionPreAcknowledgement(root);
  await checkCollectionRetiredSubmission(root);
  console.log('PASS Collection selected-draft guard, folder moves, focus, failed/conflicting/removed saves, stale load, explicit Save & Run, repeat suppression and submitted identity (DOM/controller fixture; not rendered QA)');
}

// This function is installed verbatim in both Chromium and the browser-free
// regression. Only fetch is replaced: action receipts, ownership and polling
// continue through the production controllers and validators.
function installCollectionDebuggerFixture(empty) {
  clearTimeout(state.debuggerRefreshTimer);
  const server = structuredClone(empty);
  const target = {id:'fixture-target',type:'page',title:'Collection fixture',url:'about:blank'};
  Object.assign(server,{generation:10,state:'running',target,targets:[target]});
  Object.assign(server.request_interception,{experiment_id:1,created_at_ms:1000,state:'ready',isolated:true,target_id:target.id});
  for (const group of ['object_experiment','runtime_hooks','automation_recipes','repeater']) {
    Object.assign(server[group],{session_id:1,state:'ready'});
    if (group !== 'repeater') Object.assign(server[group],{isolated:true,target_id:target.id});
  }
  const validate = () => {
    if (!isDebuggerResponse(server)) throw new Error('Malformed Collection debugger fixture');
  };
  validate();
  state.debuggerSession = structuredClone(server);
  state.debuggerEtag = null;
  window.collectionActions = [];
  window.collectionRunCounter = 0;
  window.collectionTransportMode = 'ready';
  const originalFetch = window.fetch.bind(window);
  const receipt = () => ({ok:true,generation:server.generation,repeater:structuredClone(server.repeater)});
  const publish = async () => {
    validate();
    while (state.debuggerRefreshing) await new Promise(resolve => setTimeout(resolve, 0));
    await refreshDebugger(true);
    if (state.debuggerRefreshFailed) throw new Error(state.debuggerError);
    renderApiCollection();
  };
  window.collectionPublishExternalRun = async entry => {
    const retained = structuredClone(entry);
    delete retained.stored_bytes;
    retained.stored_bytes = new TextEncoder().encode(JSON.stringify(retained)).length;
    server.repeater.history.push(retained);
    server.repeater.history_bytes += retained.stored_bytes;
    server.generation++;
    await publish();
  };
  window.fetch = async (url, options = {}) => {
    if (String(url).startsWith('/api/debugger?')) {
      validate();
      return Response.json(server,{headers:{ETag:`"collection-${server.generation}"`}});
    }
    if (url !== '/api/debugger/actions') return originalFetch(url, options);
    const request = JSON.parse(options.body);
    window.collectionActions.push(structuredClone(request));
    if (window.collectionTransportMode === 'refused') return Response.json({ok:false,error:'Authored fixture refusal'});
    if (window.collectionTransportMode === 'malformed') return Response.json({ok:true});
    if (request.action === 'configure_repeater_variables') {
      server.repeater.variables = Object.entries(request.variables).map(([name,value]) => ({name,value}));
      server.generation++;
      validate();
      return Response.json(receipt());
    }
    if (request.action === 'cancel_repeater_request') {
      server.repeater.state = 'cancelling';
      server.repeater.active_execution.cancel_requested = true;
      server.generation++;
      validate();
      return Response.json(receipt());
    }
    if (request.action !== 'run_repeater_request') throw new Error(`Unexpected Collection fixture action: ${request.action}`);
    const id = ++window.collectionRunCounter;
    const template = {url:request.url,method:request.method,headers:Object.entries(request.headers).map(([name,value]) => ({name,value})),
      body:request.body,timeout_ms:request.timeout_ms,collection_request_id:request.collection_request_id};
    const resolved = {...structuredClone(template),url:template.url.replace('{{host}}','fixture.invalid')};
    const variableNames = template.url.includes('{{host}}') ? ['host'] : [];
    server.repeater.state = 'running';
    server.repeater.active_execution = {execution_id:id,started_at_ms:4000+id,collection_request_id:request.collection_request_id,
      request:template,resolved_url:resolved.url,resolved_method:resolved.method,variable_names:variableNames,cancel_requested:false};
    server.generation++;
    validate();
    window.collectionRelease = async () => {
      const body = '<script>window.collectionUnsafe=true</script>\n'+Array.from({length:80},(_,i) => 'Response line '+i).join('\n');
      const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(body))),byte => byte.toString(16).padStart(2,'0')).join('');
      const entry = {id,collection_request_id:request.collection_request_id,state:'complete',started_at_ms:4000+id,completed_at_ms:4001+id,
        variable_names:variableNames,request:template,resolved_request:resolved,response:{protocol_version:1,ok:true,status:200,status_text:'OK',
          url:resolved.url,duration_ms:17,body,body_truncated:true,headers_truncated:false,error:null,cancelled:false,timed_out:false,body_sha256:hash,
          headers:[{name:'content-type',value:'text/plain'},{name:'x-synthetic',value:'one'}]}};
      entry.stored_bytes = new TextEncoder().encode(JSON.stringify(entry)).length;
      Object.assign(server.repeater,{state:'ready',active_execution:null,history:[...server.repeater.history,entry],
        history_bytes:server.repeater.history_bytes+entry.stored_bytes});
      server.generation++;
      await publish();
    };
    const acknowledged = receipt();
    if (window.collectionHoldAcknowledgement) return new Promise(resolve => {
      window.collectionAcknowledge = success => resolve(success ? Response.json(acknowledged)
        : Response.json({error:'Authored lost acknowledgement'},{status:503}));
    });
    return Response.json(acknowledged);
  };
  renderApiCollection();
}

export async function collectionBrowserFixture(root) {
  const empty=JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/debugger-empty.json'),'utf8'));
  const fixture={document:collectionFixtureDocument(),mode:'ready',saveMode:'ready',writes:[],pending:[],
    debuggerScript:`(${installCollectionDebuggerFixture.toString()})(${JSON.stringify(empty)})`};
  fixture.handle=async(request,response)=>{
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(!['/api/api-collection','/api/api-collection/actions'].includes(path))return false;
    const json=(status,body)=>{if(!response.destroyed){response.writeHead(status,{'Content-Type':'application/json'});response.end(JSON.stringify(body));}};
    if(path.endsWith('/actions')){
      let text='';for await(const chunk of request)text+=chunk;
      const body=JSON.parse(text);fixture.writes.push(body);
      if(fixture.saveMode==='error'){json(503,{error:'Synthetic disk failure'});return true;}
      if(fixture.saveMode==='conflict'){fixture.document.generation++;fixture.saveMode='ready';json(409,{error:'Synthetic generation conflict'});return true;}
      if(body.expected_generation!==fixture.document.generation){json(409,{error:'Stale fixture generation'});return true;}
      fixture.document={...fixture.document,generation:fixture.document.generation+1,folders:body.folders,requests:body.requests.map(item=>({...item,created_at_ms:fixture.document.requests.find(previous=>previous.id===item.id)?.created_at_ms??3000,updated_at_ms:4000}))};json(200,fixture.document);return true;
    }
    if(fixture.mode==='pending')await new Promise(resolve=>fixture.pending.push(resolve));
    if(fixture.mode==='error')json(503,{error:'Synthetic store offline'});
    else if(fixture.mode==='malformed')json(200,{document_kind:'malformed'});
    else json(200,fixture.document);
    return true;
  };
  fixture.release=()=>{for(const resolve of fixture.pending.splice(0))resolve();};
  return fixture;
}

export async function checkCollectionInteractions({evaluate,viewport,click,key,wheel,type,screenshot,fixture}) {
  const wait=async expression=>{
    for(let attempt=0;attempt<150;attempt++){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,20));}
    assert(await evaluate(expression),`Timed out: ${expression}`);
  };
  const press=value=>key(value,value,{windowsVirtualKeyCode:{Enter:13,Escape:27,Home:36,End:35,ArrowDown:40,ArrowRight:39,ArrowLeft:37,Tab:9}[value]});
  const fill=async(selector,text)=>{await click(selector);await key('a','KeyA',{modifiers:2,windowsVirtualKeyCode:65});await type(text);};
  const narrowGeometry=[];
  const checkNarrowGeometry=async label=>{
    const geometry=await evaluate(`(()=>{
      const box=node=>{const r=node.getBoundingClientRect();return {id:node.id||node.className,top:r.top,bottom:r.bottom,left:r.left,right:r.right,height:r.height,clientHeight:node.clientHeight,scrollHeight:node.scrollHeight,overflowY:getComputedStyle(node).overflowY};};
      const library=document.querySelector('.collection-library'),editor=document.querySelector('.collection-editor-pane'),form=document.querySelector('#collection-request-form');
      return {viewport:[innerWidth,innerHeight],grid:box(document.querySelector('#collection-grid')),library:box(library),editor:box(editor),form:box(form),run:box(document.querySelector('.collection-run-pane')),
        libraryChildren:[...library.children].filter(node=>node.getClientRects().length).map(box),formChildren:[...form.children].filter(node=>node.getClientRects().length).map(box)};
    })()`);
    narrowGeometry.push({label,...geometry});
    const contains=(parent,child)=>child.top>=parent.top-1&&child.bottom<=parent.bottom+1;
    assert(geometry.libraryChildren.every(child=>contains(geometry.library,child)),`Collection library controls exceed their pane: ${JSON.stringify(geometry)}`);
    assert(contains(geometry.editor,geometry.form)&&geometry.formChildren.every(child=>contains(geometry.form,child)),`Collection editor controls exceed their pane: ${JSON.stringify(geometry)}`);
    assert(geometry.library.bottom<=geometry.editor.top+1&&geometry.editor.bottom<=geometry.run.top+1,`Collection panes overlap: ${JSON.stringify(geometry)}`);
    assert(geometry.grid.scrollHeight>geometry.grid.clientHeight,'Narrow authoring must use the outer workspace scroller');
  };
  // The stacked workspace owns scrolling. Native scrollbar-wheel input avoids
  // accidentally scrolling a nested textarea, tree or response under its center.
  const reveal=async selector=>{
    for(let attempt=0;attempt<20;attempt++){
      const delta=await evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(),g=document.querySelector('#collection-grid').getBoundingClientRect(),top=Math.max(0,g.top),bottom=Math.min(innerHeight,g.bottom);return r.top<top?r.top-top-8:r.bottom>bottom?r.bottom-bottom+8:0;})()`);
      if(!delta)return;await wheel('#collection-grid',delta,'scrollbar');
    }
    throw new Error(`Collection control could not be revealed: ${selector}`);
  };
  await click('.nav-button[data-screen="api-collection"]');await wait('state.apiCollectionLoaded && !state.apiCollectionRefreshing');
  await click('#collection-tree [data-folder-id="2"]');await press('ArrowRight');
  await click('#collection-tree [data-request-id="1"]');
  assert.equal(await evaluate('state.collectionSelectedRequestId'),1);
  assert.equal(fixture.writes.length,0,'Selection never persists or sends');
  await screenshot('collection-wide-authoring');
  await fill('#collection-request-url','https://{{host}}/draft');
  assert.equal(await evaluate('elements.collectionRun.textContent'),'Save & Run');
  await click('#collection-tree [data-request-id="2"]');assert.equal(await evaluate('state.collectionSelectedRequestId'),1);
  assert.equal(await evaluate('elements.collectionRequestUrl.value'),'https://{{host}}/draft');
  await screenshot('collection-unsaved-selection-guard');
  await click('#collection-discard-request');
  await click('#collection-tab-body');await press('ArrowRight');assert.equal(await evaluate('state.collectionRequestTab'),'variables');
  assert.equal(await evaluate('document.activeElement.id'),'collection-tab-variables');
  await press('Home');assert.equal(await evaluate('state.collectionRequestTab'),'headers');
  await fill('#collection-request-headers','{"unfinished":');await click('#collection-save-request');
  assert.equal(fixture.writes.length,0);assert.match(await evaluate('elements.collectionNotice.textContent'),/JSON object/);
  await fill('#collection-request-headers','{"accept":"text/plain"}');fixture.saveMode='error';await click('#collection-save-request');await wait('!state.apiCollectionSaving');
  assert.equal(await evaluate('state.collectionDraftDirty'),true);assert.match(await evaluate('elements.collectionNotice.textContent'),/Save could not be confirmed/);
  await screenshot('collection-save-failure');
  fixture.saveMode='conflict';await click('#collection-save-request');await wait('!state.apiCollectionSaving && !state.apiCollectionRefreshing');
  assert.equal(await evaluate('state.collectionDraftDirty'),true);assert.match(await evaluate('elements.collectionNotice.textContent'),/edits are retained/);
  await click('#collection-save-request');await wait('!state.apiCollectionSaving && !state.collectionDraftDirty');
  await fill('#collection-request-name','Original dirty recipe');
  fixture.document.generation++;fixture.document.requests[0]={...fixture.document.requests[0],name:'Replacement recipe',created_at_ms:3000,updated_at_ms:3000};
  await evaluate('refreshApiCollection(true)');assert.equal(await evaluate('elements.collectionRequestName.value'),'Original dirty recipe');
  assert.equal(await evaluate('elements.collectionSaveRequest.disabled'),true);assert.match(await evaluate('elements.collectionNotice.textContent'),/removed or replaced/);
  await screenshot('collection-replaced-draft-owner');await click('#collection-discard-request');await click('#collection-retry');await wait('!state.apiCollectionRefreshing');
  assert.equal(await evaluate('elements.collectionRequestName.value'),'Replacement recipe');
  // Replace only fetch with schema-valid authored responses. Production action,
  // receipt and poll owners still govern the actual Collection controls.
  await wait('!state.debuggerRefreshing');
  await evaluate(fixture.debuggerScript);
  await fill('#collection-request-url','https://{{host}}/saved-and-run');await click('#collection-run');await wait('typeof collectionRelease === "function"');
  assert.equal(await evaluate('state.collectionDraftDirty'),false);assert.equal(await evaluate('elements.collectionRun.disabled'),true);
  await click('#collection-run');assert.equal(await evaluate('collectionActions.length'),2);
  await click('#collection-tree [data-request-id="2"]');assert.equal(await evaluate('state.collectionSelectedRequestId'),2);
  await evaluate('collectionRelease()');await wait('!state.collectionRunPending');
  assert.match(await evaluate('elements.collectionResponse.textContent'),/Run this saved request/);
  await click('#collection-tree [data-request-id="1"]');assert.match(await evaluate('elements.collectionResponseMeta.textContent'),/saved-and-run/);
  assert.equal(await evaluate('window.collectionUnsafe === true'),false);
  await screenshot('collection-wide-response');
  await fill('#collection-request-url','https://{{host}}/second-submitted');await click('#collection-run');
  await wait('state.collectionPendingRunSelection?.executionId === 2 && !state.collectionRunPending');
  assert.equal(await evaluate('state.collectionSelectedHistoryId'),1,'Acknowledgement retains the previous displayed response until completion');
  await fill('#collection-request-url','https://fixture.invalid/newer-unsaved-draft');
  await evaluate('collectionRelease()');assert.equal(await evaluate('state.collectionSelectedHistoryId'),2);
  assert.equal(await evaluate('elements.collectionRequestUrl.value'),'https://fixture.invalid/newer-unsaved-draft');
  assert.match(await evaluate('elements.collectionResponseMeta.textContent'),/second-submitted/);
  await screenshot('collection-completion-preserves-newer-draft');await click('#collection-discard-request');
  await click('.collection-history-card summary');await click('#collection-run');await wait('state.collectionPendingRunSelection?.executionId === 3 && !state.collectionRunPending');
  await click('#collection-history [data-run-id="1"]');await evaluate('collectionRelease()');
  assert.equal(await evaluate('state.collectionSelectedHistoryId'),1,'Explicit history selection wins over the later completed run');
  await click('#collection-response-tab-headers');assert.match(await evaluate('elements.collectionResponse.textContent'),/x-synthetic/);
  await press('Home');assert.equal(await evaluate('state.collectionResponseTab'),'body');
  await wheel('#collection-response',150);const scroll=await evaluate('elements.collectionResponse.scrollTop');assert(scroll>0);
  await evaluate('renderApiCollection()');assert.equal(await evaluate('elements.collectionResponse.scrollTop'),scroll,'Polling must preserve response scroll');
  if(!await evaluate("document.querySelector('.collection-history-card').open"))await click('.collection-history-card summary');
  await click('#collection-history [data-run-id="1"]');await evaluate('renderApiCollection()');assert.equal(await evaluate('document.activeElement.dataset.runId'),'1');
  // Polling may complete an old recipe before its action acknowledgement.
  await evaluate('window.collectionHoldAcknowledgement=true');await click('#collection-run');await wait('typeof collectionAcknowledge === "function"');
  fixture.document.generation++;fixture.document.requests[0]={...fixture.document.requests[0],name:'New incarnation',url:'https://fixture.invalid/new-incarnation',created_at_ms:4003,updated_at_ms:4003};
  await evaluate('refreshApiCollection(true)');await evaluate('collectionRelease()');
  assert.equal(await evaluate('collectionHistoryEntries().length'),0);assert.equal(await evaluate('elements.collectionEditorTitle.textContent'),'New incarnation');
  await screenshot('collection-preack-owner-isolation');await evaluate('collectionAcknowledge(false)');await wait('!state.collectionRunPending');
  assert.equal(await evaluate('collectionHistoryEntries().length'),0,'A lost acknowledgement must not reassign the old response');
  await evaluate('window.collectionHoldAcknowledgement=false');await click('#collection-run');await wait('state.collectionPendingRunSelection?.executionId === 5 && !state.collectionRunPending');
  await evaluate('collectionRelease()');assert.equal(await evaluate('collectionHistoryEntries().length'),1);assert.equal(await evaluate('state.collectionSelectedHistoryId'),5);
  fixture.document.generation++;fixture.document.requests[0]={...fixture.document.requests[0],name:'Later replacement',url:'https://fixture.invalid/later-replacement',created_at_ms:4006,updated_at_ms:4006};
  await evaluate('refreshApiCollection(true)');
  await evaluate("const externalRun=structuredClone(state.debuggerSession.repeater.history.at(-1));Object.assign(externalRun,{id:6,started_at_ms:5000,completed_at_ms:5001});externalRun.resolved_request.url='https://fixture.invalid/later-replacement';collectionPublishExternalRun(externalRun)");
  assert.equal(await evaluate('collectionHistoryEntries().length'),1);assert.equal(await evaluate('state.collectionSelectedHistoryId'),6);
  assert.match(await evaluate('elements.collectionResponseMeta.textContent'),/later-replacement/);await screenshot('collection-retired-owner-new-run');
  // Read-only load failures preserve the current request and response.
  fixture.mode='malformed';await evaluate('refreshApiCollection(true)');assert.match(await evaluate('elements.collectionNotice.textContent'),/Malformed/);
  fixture.mode='error';await click('#collection-retry');await wait('!state.apiCollectionRefreshing');assert.equal(await evaluate('state.collectionSelectedRequestId'),1);
  await screenshot('collection-offline-retained-response');fixture.mode='ready';await click('#collection-retry');await wait('!state.apiCollectionRefreshing');
  for(const [width,height] of [[760,650],[360,740]]){
    await viewport(width,height);await checkNarrowGeometry(`${width} initial`);await reveal('#collection-tab-body');await click('#collection-tab-body');await press('ArrowRight');assert.equal(await evaluate('state.collectionRequestTab'),'variables');
    await checkNarrowGeometry(`${width} variables`);await screenshot(`collection-${width}-editor`);
    await reveal('.collection-response-card');await click('#collection-response-tab-headers');
    assert(await evaluate('document.documentElement.scrollWidth <= innerWidth'),'Collection must not overflow the viewport horizontally');
    assert(await evaluate("document.querySelector('#collection-response').getBoundingClientRect().height>=130"));
    await checkNarrowGeometry(`${width} response`);await screenshot(`collection-${width}-response`);
  }
  await viewport(1440,900);await evaluate("document.querySelector('#collection-grid').scrollTop=0");
  fixture.document.requests=[];fixture.document.folders=fixture.document.folders.slice(0,1);fixture.document.generation++;await evaluate('refreshApiCollection(true)');
  assert.equal(await evaluate('elements.collectionRequestForm.hidden'),true);assert.match(await evaluate('elements.collectionEditorEmpty.textContent'),/Start with a request/);
  await screenshot('collection-empty');
  return {status:'passed',path:'browser development Collection UI',source:'synthetic local collection store and scripted debugger transport; no target requests',viewports:[[1440,900],[760,650],[360,740]],narrow_geometry:narrowGeometry,checks:['hit-tested request selection and authoring','real keyboard input and tabs','explicit draft guard and discard','invalid/failed/conflicting saves retain edits','explicit Save & Run and duplicate-click suppression','backend-shaped immediate acknowledgement and later completion snapshot','completion before delayed/lost acknowledgement preserves recipe identity','resolved submission does not hide later replacement runs','newer draft and explicit history selection beat late results','recycled dirty-owner rejection and reload','submitted request identity after selection change','inert truncated response and independent scrolling','response/history focus retention','malformed/offline load and retry','intrinsic narrow pane/form containment with no overlap','real outer-scrollbar wheel revealing and hit-tested controls','narrow scrollable authoring and results','empty collection']};
}

async function checkCollectionOwnership(root) {
  const make=()=>checkCollectionController(root,true);
  const deliverWrite=async fixture=>{
    const write=fixture.pending.shift();assert(write,'Expected one explicit local write');
    const body=JSON.parse(write.options.body);const old=fixture.state.apiCollection;
    const result={...old,generation:old.generation+1,folders:body.folders,requests:body.requests.map(request=>({...request,created_at_ms:old.requests.find(item=>item.id===request.id)?.created_at_ms??3000,updated_at_ms:3000}))};
    write.resolve(Response.json(result));return body;
  };
  const entry=(id,requestId=1)=>({id,collection_request_id:requestId,started_at_ms:4000+id,completed_at_ms:4001+id,state:'complete',resolved_request:{method:'GET',url:`https://fixture.invalid/submitted-${id}`},response:{ok:true,status:200,status_text:'OK',duration_ms:1,body:`body-${id}`,body_truncated:false,headers:[]}});
  // A request move must never consume the raw draft owned by its old folder.
  const moved=await make();moved.ui.renderApiCollection();
  moved.elements.collectionFolderVariables.value='{"host":"unsaved-folder-value"}';moved.state.collectionFolderDirty=true;
  moved.elements.collectionRequestFolder.value='3';moved.state.collectionDraftDirty=true;
  assert.equal(await moved.ui.saveCollectionRequest(),false);assert.equal(moved.pending.length,0);
  assert.equal(moved.state.collectionFolderDraftId,2);assert.equal(moved.elements.collectionFolderVariables.value,'{"host":"unsaved-folder-value"}');
  const folderSave=moved.ui.saveCollectionFolder();await deliverWrite(moved);await folderSave;
  assert.equal(moved.state.collectionFolderDirty,false);assert.equal(moved.elements.collectionRequestFolder.value,'3');
  const requestSave=moved.ui.saveCollectionRequest();await deliverWrite(moved);assert.equal(await requestSave,true);
  assert.equal(moved.state.collectionSelectedFolderId,3);assert.equal(moved.state.collectionFolderDraftId,3);
  assert.equal(moved.state.apiCollection.folders.find(folder=>folder.id===2).variables[0].value,'unsaved-folder-value');
  // A new folder owns folder settings; an old selected request must be cleared.
  const created=await make();created.ui.renderApiCollection();created.elements.collectionNewFolderName.value='New folder';
  const createFolder=created.ui.createCollectionFolder();await deliverWrite(created);await createFolder;
  assert.equal(created.state.collectionSelectedRequestId,null);assert.equal(created.state.collectionSelectedFolderId,4);assert.equal(created.state.collectionFolderDraftId,4);
  // Dirty owner identity includes creation, even when another window reuses its ID.
  const reused=await make();reused.ui.renderApiCollection();reused.elements.collectionRequestName.value='Original raw draft';reused.state.collectionDraftDirty=true;
  const reload=reused.ui.refreshApiCollection(true);const replacement=structuredClone(reused.state.apiCollection);replacement.generation++;
  replacement.requests[0]={...replacement.requests[0],name:'Replacement recipe',created_at_ms:3000,updated_at_ms:3000};
  reused.pending.shift().resolve(Response.json(replacement));assert.equal(await reload,false);
  assert.equal(reused.state.apiCollection.requests[0].created_at_ms,1000);assert.equal(reused.elements.collectionRequestName.value,'Original raw draft');
  assert.equal(await reused.ui.saveCollectionRequest(),false);assert.equal(reused.pending.length,0);assert(reused.state.apiCollectionNeedsReload);
  reused.state.collectionDraftDirty=false;const afterDiscard=reused.ui.refreshApiCollection(true);reused.pending.shift().resolve(Response.json(replacement));assert.equal(await afterDiscard,true);assert.equal(reused.elements.collectionRequestName.value,'Replacement recipe');
  // Locally pending configuration owns/reserves a recipe incarnation before any
  // active_execution exists; deleting it cancels the later send, never rebinds it.
  const pending=await make();pending.ui.renderApiCollection();pending.ui.selectCollectionRequest(2);let release;
  pending.setActionHandler(request=>{pending.actions.push(request);return new Promise(resolve=>release=resolve);});
  const sending=pending.ui.runCollectionRequest();assert.equal(pending.ui.collectionNextRequestId(),3);
  await pending.ui.deleteCollectionRequest();const deletion=pending.ui.deleteCollectionRequest();await deliverWrite(pending);await deletion;
  const creation=pending.ui.createCollectionRequest();const payload=await deliverWrite(pending);const newId=await creation;
  assert.equal(newId,3);assert.equal(payload.requests.at(-1).id,3);
  release({});await sending;assert.equal(pending.actions.length,1,'Deleted submitted recipe must not reach run_repeater_request');
  assert.match(pending.state.apiCollectionMessage,/removed or replaced before sending/);assert.equal(pending.ui.collectionHistoryEntries().length,0);
  // Real backend acknowledgement comes before history; later polling follows
  // the submitted run while preserving a newer unsaved editor draft.
  const acknowledged=await make();acknowledged.ui.renderApiCollection();acknowledged.state.debuggerSession.repeater.history=[entry(1)];acknowledged.ui.renderCollectionExecution();
  const acknowledge=async fixture=>{
    fixture.setActionHandler(async request=>{
      if(request.action==='configure_repeater_variables')return {};
      fixture.state.debuggerSession.repeater.state='running';fixture.state.debuggerSession.repeater.active_execution={execution_id:2,collection_request_id:1,started_at_ms:4002};
      return {repeater:fixture.state.debuggerSession.repeater};
    });
    await fixture.ui.runCollectionRequest();
  };
  await acknowledge(acknowledged);assert.equal(acknowledged.state.collectionPendingRunSelection.executionId,2);assert.equal(acknowledged.state.collectionSelectedHistoryId,1);
  acknowledged.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(1)]};acknowledged.ui.renderCollectionExecution();
  assert.equal(acknowledged.state.collectionPendingRunSelection.executionId,2);assert(acknowledged.elements.collectionRun.disabled);assert.match(acknowledged.elements.collectionResponseMeta.textContent,/waiting for run 2/);
  acknowledged.elements.collectionRequestUrl.value='https://fixture.invalid/new-unsaved';acknowledged.state.collectionDraftDirty=true;
  acknowledged.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(1),entry(2)]};acknowledged.ui.renderApiCollection();
  assert.equal(acknowledged.state.collectionSelectedHistoryId,2);assert.match(acknowledged.elements.collectionResponseMeta.textContent,/submitted-2/);assert.equal(acknowledged.elements.collectionRequestUrl.value,'https://fixture.invalid/new-unsaved');assert(acknowledged.state.collectionDraftDirty);
  // An explicit history-row choice after acknowledgement cancels auto-follow.
  const chosen=await make();chosen.ui.renderApiCollection();chosen.state.debuggerSession.repeater.history=[entry(1)];chosen.ui.renderCollectionExecution();await acknowledge(chosen);
  chosen.elements.collectionHistory.querySelector('[data-run-id="1"]').click();
  chosen.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(1),entry(2)]};chosen.ui.renderApiCollection();
  assert.equal(chosen.state.collectionSelectedHistoryId,1);assert.match(chosen.elements.collectionResponseMeta.textContent,/submitted-1/);
  // New request selection wins over an acknowledged old request completion.
  const switched=await make();switched.ui.renderApiCollection();switched.state.debuggerSession.repeater.history=[entry(1)];switched.ui.renderCollectionExecution();await acknowledge(switched);switched.ui.selectCollectionRequest(2);
  switched.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(1),entry(2)]};switched.ui.renderApiCollection();assert.equal(switched.state.collectionSelectedRequestId,2);assert.equal(switched.state.collectionSelectedHistoryId,null);
  // A completed locally submitted run remains bound to its recipe incarnation,
  // even if another window replaced the numeric ID before execution began.
  const replacedRun=await make();replacedRun.ui.renderApiCollection();await acknowledge(replacedRun);
  const newDocument=structuredClone(replacedRun.state.apiCollection);newDocument.generation++;newDocument.requests[0].created_at_ms=3000;newDocument.requests[0].updated_at_ms=3000;
  const newLoad=replacedRun.ui.refreshApiCollection(true);replacedRun.pending.shift().resolve(Response.json(newDocument));await newLoad;
  replacedRun.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(2)]};replacedRun.ui.renderApiCollection();assert.equal(replacedRun.ui.collectionHistoryEntries().length,0);assert.equal(replacedRun.state.collectionSelectedHistoryId,null);
  console.log('PASS Collection review regressions: simultaneous folder/request drafts, folder creation selection, recycled dirty owner, reserved pre-send identity, immediate acknowledgement then polling, newer draft/history/request intent and exact run incarnation');
}

async function checkCollectionPreAcknowledgement(root) {
  const entry=(id,started)=>({id,collection_request_id:1,started_at_ms:started,completed_at_ms:started+1,state:'complete',resolved_request:{method:'GET',url:`https://fixture.invalid/submitted-${id}`},response:{ok:true,status:200,status_text:'OK',duration_ms:1,body:`body-${id}`,body_truncated:false,headers:[]}});
  for(const mode of ['delayed','lost','lost-before-poll'])for(const replaced of [false,true]){
    const fixture=await checkCollectionController(root,true);fixture.ui.renderApiCollection();
    fixture.state.debuggerSession.repeater.history=[entry(1,2000)];fixture.ui.renderCollectionExecution();let acknowledge;
    fixture.setActionHandler(async request=>request.action==='configure_repeater_variables'?{}:new Promise(resolve=>acknowledge=resolve));
    const running=fixture.ui.runCollectionRequest();await new Promise(resolve=>setTimeout(resolve,0));assert(acknowledge);
    assert.equal(fixture.state.collectionSubmittedOwners.length,1);assert.equal(fixture.state.collectionSubmittedOwners[0].afterExecutionId,1);
    // An already retained run is not claimed by the newer pending submission.
    assert.equal(fixture.ui.collectionHistoryEntries().length,1);
    assert.equal(fixture.state.collectionRunOwners.size,0);
    if(replaced){
      const replacement=structuredClone(fixture.state.apiCollection);replacement.generation++;replacement.requests[0]={...replacement.requests[0],name:'Replacement before delayed send',created_at_ms:3000,updated_at_ms:3000};
      const refresh=fixture.ui.refreshApiCollection(true);fixture.pending.shift().resolve(Response.json(replacement));assert.equal(await refresh,true);
    }
    if(mode==='lost-before-poll'){acknowledge(null);await running;assert.equal(fixture.state.collectionPendingSubmission,null);}
    fixture.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[entry(1,2000),entry(4,4000)]};fixture.ui.renderApiCollection();
    assert.equal(fixture.ui.collectionHistoryEntries().length,replaced?0:2,`${mode}: polled completion must belong to the submitted incarnation`);
    assert.equal(fixture.state.collectionRunOwners.get(JSON.stringify(['target-1',1,4])).createdAt,1000);
    if(replaced)assert.doesNotMatch(fixture.elements.collectionResponseMeta.textContent,/submitted-4/);
    else assert.match(fixture.elements.collectionResponseMeta.textContent,/submitted-1|submitted-4/);
    if(mode!=='lost-before-poll'){acknowledge(mode==='delayed'?{repeater:fixture.state.debuggerSession.repeater}:null);await running;}
    fixture.ui.renderApiCollection();assert.equal(fixture.ui.collectionHistoryEntries().length,replaced?0:2);
    if(replaced)assert.equal(fixture.state.collectionSelectedHistoryId,null);
  }
  // Submission metadata is context-scoped and bounded alongside 24 retained runs.
  const bounded=await checkCollectionController(root,true);bounded.ui.renderApiCollection();let id=0;
  bounded.setActionHandler(async request=>{
    if(request.action==='configure_repeater_variables')return {};
    bounded.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[...bounded.state.debuggerSession.repeater.history,entry(++id,4000+id)].slice(-24)};
    return {repeater:bounded.state.debuggerSession.repeater};
  });
  for(let index=0;index<30;index++)await bounded.ui.runCollectionRequest();
  assert.equal(bounded.state.collectionSubmittedOwners.length,25);assert.equal(bounded.state.collectionRunOwners.size,25);assert.equal(bounded.ui.collectionHistoryEntries().length,24);
  bounded.state.debuggerSession.request_interception.experiment_id=2;bounded.state.debuggerSession.repeater.history=[entry(1,5000)];
  assert.equal(bounded.ui.collectionHistoryEntries().length,1,'Prior-context submissions cannot claim a new context’s run');
  console.log('PASS Collection pre-ack/lost-ack ownership, completion after lost acknowledgement, unchanged-owner retained history, dispatch metadata bounds and context separation');
}

async function checkCollectionRetiredSubmission(root) {
  const entry=(id,started,url)=>({id,collection_request_id:1,started_at_ms:started,completed_at_ms:started+1,state:'complete',resolved_request:{method:'GET',url},response:{ok:true,status:200,status_text:'OK',duration_ms:1,body:'body',body_truncated:false,headers:[]}});
  for(const resolution of ['acknowledgement','poll-before-lost-ack','poll-after-lost-ack']){
    const fixture=await checkCollectionController(root,true);fixture.ui.renderApiCollection();let acknowledge;
    const first=entry(1,2000,'https://fixture.invalid/old-recipe');
    fixture.setActionHandler(async request=>{
      if(request.action==='configure_repeater_variables')return {};
      if(resolution==='acknowledgement'){
        fixture.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[first]};
        return {repeater:fixture.state.debuggerSession.repeater};
      }
      return new Promise(resolve=>acknowledge=resolve);
    });
    const running=fixture.ui.runCollectionRequest();await new Promise(resolve=>setTimeout(resolve,0));
    if(resolution==='poll-after-lost-ack'){acknowledge(null);await running;}
    if(resolution!=='acknowledgement'){
      fixture.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[first]};fixture.ui.renderApiCollection();
      if(resolution==='poll-before-lost-ack')acknowledge(null);
    }
    await running;
    assert.equal(fixture.state.collectionSubmittedOwners[0].executionId,1,`${resolution}: dispatch must be bounded after resolution`);
    assert.equal(fixture.state.collectionRunOwners.get(JSON.stringify(['target-1',1,1])).createdAt,1000);
    const replacement=structuredClone(fixture.state.apiCollection);replacement.generation++;replacement.requests[0]={...replacement.requests[0],name:'Legitimate replacement',url:'https://fixture.invalid/new-recipe',created_at_ms:3000,updated_at_ms:3000};
    const refresh=fixture.ui.refreshApiCollection(true);fixture.pending.shift().resolve(Response.json(replacement));assert.equal(await refresh,true);
    const second=entry(2,4000,'https://fixture.invalid/new-recipe');fixture.state.debuggerSession.repeater={state:'ready',active_execution:null,history:[first,second]};fixture.ui.renderApiCollection();
    assert.deepEqual(Array.from(fixture.ui.collectionHistoryEntries(),item=>item.id),[2],`${resolution}: resolved old submission cannot hide a later replacement run`);
    assert.equal(fixture.state.collectionRunOwners.has(JSON.stringify(['target-1',1,2])),false);
    assert.equal(fixture.state.collectionSelectedHistoryId,2);assert.match(fixture.elements.collectionResponseMeta.textContent,/new-recipe/);
  }
  console.log('PASS Collection acknowledgement/poll resolution retires open dispatch claims while preserving exact owners, lost-ack protection and later replacement history');
}

async function checkCollectionReceiptTransport(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const productionFunction=name=>{
    const start=app.search(new RegExp(`^      (?:async )?function ${name}\\(`,'m'));
    assert(start>=0,name);const end=/^      }$/m.exec(app.slice(start));assert(end,name);
    return app.slice(start,start+end.index+end[0].length);
  };
  const names=['experimentLifetimeKey','experimentContextKey','currentExperimentReceipt','experimentActionGroups',
    'experimentReceiptBounded','experimentRecordMatches','isExperimentReceipt','clearExperimentLifetime',
    'syncExperimentSession','runExperimentAction','debuggerAction','debuggerScriptCatalogSignature','refreshDebugger'];
  const fixtureScript=(await collectionBrowserFixture(root)).debuggerScript;
  const make=async()=>{
    const f=await checkCollectionController(root,true),c=f.context;
    Object.assign(f.state,{debuggerRefreshing:false,debuggerActionPending:false,debuggerEtag:null,openScriptIds:[],
      requests:[],selectedRequestId:null,selectedScriptId:null,editingBreakpointId:null});
    Object.assign(c,{Response,structuredClone,crypto:webcrypto,memoryOriginTraceActive:()=>false});
    c.window=c;
    c.document.hidden=false;c.document.querySelector=()=>({hidden:true});
    for(const name of ['renderDebugger','renderExperiment','scheduleDebuggerRefresh','rebuildTrafficRequests','syncMemorySession',
      'applyMemoryOriginTrace','renderLiveBrowserTabCount','pruneLiveScriptContent','renderShellStatus','renderNetworkNotice',
      'renderMemory','renderFieldProvenance'])c[name]=()=>{};
    const production=runInNewContext(names.map(productionFunction).join('\n')+'\n({'+names.join(',')+'})',c);
    runInNewContext(fixtureScript,c);
    for(const name of names)assert.equal(runInNewContext(name,c),production[name],`${name} must remain production code`);
    assert(runInNewContext('isDebuggerResponse(state.debuggerSession)',c));
    return {...f,c,production};
  };
  for(const mode of ['refused','malformed']){
    const f=await make();f.c.collectionTransportMode=mode;await f.ui.runCollectionRequest();
    assert.equal(f.c.collectionActions.length,1,'Rejected configuration cannot send');
    assert.equal(typeof f.c.collectionRelease,'undefined');assert.equal(f.state.collectionRunPending,false);
    assert.match(f.state.apiCollectionMessage,/refusal|invalid acknowledgement/);
  }
  const f=await make();
  f.elements.collectionRequestUrl.value='https://{{host}}/saved-and-run';f.state.collectionDraftDirty=true;
  const run=f.ui.runCollectionRequest();await f.ui.runCollectionRequest();
  assert.equal(f.pending.length,1,'Repeated Save & Run must retain one save');
  const save=f.pending.shift(),body=JSON.parse(save.options.body),saved={...f.state.apiCollection,
    generation:f.state.apiCollection.generation+1,folders:body.folders,
    requests:body.requests.map(request=>({...request,created_at_ms:1000,updated_at_ms:3000}))};
  save.resolve(Response.json(saved));await run;
  assert.deepEqual(Array.from(f.c.collectionActions,item=>item.action),['configure_repeater_variables','run_repeater_request']);
  assert.equal(f.state.collectionDraftDirty,false);assert.equal(f.state.collectionPendingRunSelection.executionId,1);
  assert.equal(typeof f.c.collectionRelease,'function');
  assert(f.state.experimentReceiptOwners instanceof WeakMap || Object.prototype.toString.call(f.state.experimentReceiptOwners)==='[object WeakMap]');
  f.elements.collectionRequestUrl.value='https://fixture.invalid/newer-unsaved';f.state.collectionDraftDirty=true;
  await f.c.collectionRelease();
  assert.equal(f.state.collectionSelectedHistoryId,1);assert.match(f.elements.collectionResponseMeta.textContent,/saved-and-run/);
  assert.equal(f.elements.collectionRequestUrl.value,'https://fixture.invalid/newer-unsaved');assert(f.state.collectionDraftDirty);
  assert.equal(f.c.collectionUnsafe,undefined);assert(runInNewContext('isDebuggerResponse(state.debuggerSession)',f.c));
  // A late/lost receipt still passes through real transport and ownership while
  // completion is read through the production debugger GET/poll path.
  const late=await make();late.c.collectionHoldAcknowledgement=true;
  const pending=late.ui.runCollectionRequest();
  for(let index=0;index<100&&typeof late.c.collectionAcknowledge!=='function';index++)await Promise.resolve();
  assert.equal(typeof late.c.collectionAcknowledge,'function');
  await late.c.collectionRelease();late.c.collectionAcknowledge(false);await pending;
  assert.equal(late.state.collectionRunPending,false);assert.equal(late.ui.collectionHistoryEntries().length,1);
  assert.equal(late.c.collectionActions.length,2,'Lost acknowledgement must not retry');
  const sequential=await make();
  await sequential.ui.runCollectionRequest();sequential.ui.selectCollectionRequest(2);await sequential.c.collectionRelease();
  assert.equal(sequential.state.collectionSelectedRequestId,2);assert.equal(sequential.ui.collectionHistoryEntries().length,0);
  sequential.ui.selectCollectionRequest(1);await sequential.ui.runCollectionRequest();
  assert.equal(sequential.state.collectionSelectedHistoryId,1);await sequential.c.collectionRelease();
  assert.equal(sequential.state.collectionSelectedHistoryId,2);
  await sequential.ui.runCollectionRequest();
  sequential.elements.collectionHistory.querySelector('[data-run-id="1"]').click();await sequential.c.collectionRelease();
  assert.equal(sequential.state.collectionSelectedHistoryId,1,'Explicit history selection survives the real poll');
  sequential.c.collectionHoldAcknowledgement=true;const oldRun=sequential.ui.runCollectionRequest();
  for(let index=0;index<100&&typeof sequential.c.collectionAcknowledge!=='function';index++)await Promise.resolve();
  assert.equal(typeof sequential.c.collectionAcknowledge,'function');
  const request=sequential.state.apiCollection.requests[0];
  Object.assign(request,{name:'New incarnation',url:'https://fixture.invalid/new-incarnation',created_at_ms:4003,updated_at_ms:4003});
  sequential.ui.renderApiCollection();await sequential.c.collectionRelease();
  assert.equal(sequential.ui.collectionHistoryEntries().length,0);
  sequential.c.collectionAcknowledge(false);await oldRun;sequential.c.collectionHoldAcknowledgement=false;
  await sequential.ui.runCollectionRequest();await sequential.c.collectionRelease();
  assert.equal(sequential.state.collectionSelectedHistoryId,5);
  Object.assign(request,{name:'Later replacement',created_at_ms:4006,updated_at_ms:4006});
  const external=structuredClone(sequential.state.debuggerSession.repeater.history.at(-1));
  Object.assign(external,{id:6,started_at_ms:5000,completed_at_ms:5001});external.resolved_request.url='https://fixture.invalid/later-replacement';
  await sequential.c.collectionPublishExternalRun(external);
  assert.equal(sequential.ui.collectionHistoryEntries().length,1);assert.equal(sequential.state.collectionSelectedHistoryId,6);
  assert.match(sequential.elements.collectionResponseMeta.textContent,/later-replacement/);
  const cancelled=await make();await cancelled.ui.runCollectionRequest();
  const cancel=await cancelled.production.runExperimentAction({action:'cancel_repeater_request'});
  assert(cancelled.production.currentExperimentReceipt(cancel));
  assert.equal(cancelled.state.debuggerSession.repeater.state,'cancelling');
  console.log('PASS exact Collection browser transport fixture through production action/receipt/poll owners: valid Save & Run, double-submit, retained draft, completion, refusal/malformed no-Send, lost acknowledgement and cancellation (not rendered QA)');
}
