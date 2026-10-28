import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';


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
  const experimentContext = '';
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
  const ui=runInNewContext(models+'\n'+experimentContext+'\n'+section+'\n;({renderApiCollection,selectCollectionFolder,selectCollectionRequest,saveCollectionRequest,saveCollectionFolder,refreshApiCollection,createCollectionRequest,deleteCollectionRequest,moveCollectionTreeSelection,collectionNextRequestId,isApiCollection,createCollectionFolder,duplicateCollectionRequest,deleteCollectionFolder})',context);
  if (fixtureOnly) return {ui,state,elements,pending,actions,document,context,setActionHandler:handler=>actionHandler=handler};
  assert(ui.isApiCollection(state.apiCollection));
  assert.equal(ui.collectionNextRequestId(),3);
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
  assert.equal(actions.length,0,'Collection authoring never invokes browser actions');
  console.log('PASS native-only Collection CRUD: drafts, folders, focus, failed/conflicting/removed saves, stale loads and deadlines; no browser execution');
}
