import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {notebookModels} from './check-investigation-notebook.mjs';

const copy = value => JSON.parse(JSON.stringify(value));
export function analystFixtureLibrary(empty) {
  return {...copy(empty()), generation: 1, updated_at_ms: 1000,
    folders: [{id:1,name:'Analyst Workspace',parent_id:null},{id:2,name:'Synthetic notes',parent_id:1},{id:3,name:'Another folder',parent_id:1}],
    files: [1,2].map(id => ({id,folder_id:2,name:`Note ${id}`,kind:'scratchpad',language:'text',content:`Saved note ${id}`,
      content_bytes:12,created_at_ms:1000,updated_at_ms:1000}))};
}
function replaced(library, request) {
  const unchanged = JSON.stringify(library.folders) === JSON.stringify(request.folders) &&
    library.files.length === request.files.length && request.files.every(file => {
      const old = library.files.find(item => item.id === file.id);
      return old && Object.keys(file).every(key => old[key] === file[key]);
    });
  if (unchanged) return copy(library);
  return {...copy(library),generation:library.generation+1,updated_at_ms:library.updated_at_ms+1,folders:copy(request.folders),
    files:request.files.map(file=>({...copy(file),content_bytes:Buffer.byteLength(file.content),
      created_at_ms:library.files.find(old=>old.id===file.id)?.created_at_ms??library.updated_at_ms+1,updated_at_ms:library.updated_at_ms+1}))};
}
async function controllerFixture(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const {empty}=await notebookModels(root);
  const document={activeElement:null};
  class Node {
    constructor(tag='div'){this.tagName=tag;this.dataset={};this.attributes=new Map();this.children=[];this.listeners=new Map();this.style={setProperty(){}};this.value='';this.scrollTop=0;this._text='';}
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
    select(){}
    click(){return this.listeners.get('click')?.({currentTarget:this});}
  }
  document.createElement=tag=>new Node(tag);
  const section=app.slice(app.indexOf('      const analystExactKeys'),app.indexOf('      function selectedAnalystArtifact'))+
    app.slice(app.indexOf('      function renderLocalAnalyst()'),app.indexOf('      const decoderNativeOperations'))+
    app.slice(app.indexOf('      async function createAnalystFolder()'),app.indexOf('      async function runLocalAnalystScript()'));
  const analystElements=Object.fromEntries([...new Set([...section.matchAll(/analystElements\.(\w+)/g)].map(match=>match[1]))].map(name=>[name,new Node()]));
  for(const name of ['name','folder','kind','language','content']){analystElements[name].tagName=name==='content'?'textarea':['folder','kind','language'].includes(name)?'select':'input';analystElements.editorForm.append(analystElements[name]);}
  const state={localAnalyst:analystFixtureLibrary(empty),localAnalystLoaded:true,localAnalystVersion:0,localAnalystNeedsReload:false,
    localAnalystPendingSave:null,localAnalystRefreshing:false,localAnalystSaving:false,localAnalystStatus:'ready',localAnalystMessage:'Loaded',
    analystSelectedFileId:1,analystSelectedFolderId:2,analystExpandedFolderIds:new Set([1,2]),analystDraftDirty:false,analystFolderDirty:false};
  const f={state,elements:analystElements,document,server:copy(state.localAnalyst),mode:'ready',calls:[],timers:new Set(),held:[]};
  const context={state,analystElements,document,console,TextEncoder,TextDecoder,Uint8Array,AbortController,Response,
    emptyLocalAnalystWorkspace:empty,location:{protocol:'http:'},formatByteSize:n=>`${n} B`,renderAnalystExecution(){},renderAnalystHistory(){},
    requestAnimationFrame:fn=>fn(),textElement:(tag,className,text)=>{const node=new Node(tag);node.className=className;node.textContent=text;return node;},
    setTimeout:(callback,delay)=>{const timer=setTimeout(callback,delay);if(delay===15000)f.timers.add({timer,callback});return timer;},
    clearTimeout:timer=>{clearTimeout(timer);for(const entry of f.timers)if(entry.timer===timer)f.timers.delete(entry);},
    fetch:async(url,options={})=>{
      f.calls.push({url,options});
      if(url.endsWith('/runner'))return Response.json({protocol_version:1,available:false,active_run_id:null,limits:empty().limits});
      const before=copy(f.server);
      if(options.method==='POST'){
        const request=JSON.parse(options.body);f.lastRequest=request;
        if(f.mode==='hold-post')await new Promise(resolve=>f.held.push(resolve));
        if(f.mode==='fail-before')throw new Error('Synthetic connection failure');
        if(f.mode==='busy'||request.expected_generation!==f.server.generation)return Response.json({error:'Workspace busy or stale'},{status:409});
        f.server=replaced(f.server,request);
        if(['commit-drop','commit-drop-read-fails'].includes(f.mode))throw new Error('Synthetic acknowledgement lost');
        if(f.mode==='committed-conflict')return Response.json({error:'Stale generation after lost acknowledgement'},{status:409});
        if(f.mode==='malformed-ack')return new Response('{');
        if(f.mode==='wrong-ack')return Response.json({...f.server,generation:f.server.generation+1});
        return Response.json(f.server);
      }
      if(f.mode==='hold-get')await new Promise(resolve=>f.held.push(resolve));
      if(['commit-drop-read-fails','read-fails'].includes(f.mode))throw new Error('Synthetic load failure');
      return Response.json(before);
    }};
  f.context=context;
  f.ui=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+'\n'+
    (await readFile(join(root,'apps/research-ui/source_facts.js'),'utf8'))+'\n'+section+
    '\n;({renderLocalAnalyst,selectAnalystFile,selectAnalystFolder,saveAnalystFile,saveAnalystFolder,createAnalystFile,createAnalystFolder,deleteAnalystFile,deleteAnalystFolder,refreshLocalAnalyst,discardAnalystDraft,moveAnalystTreeSelection,guardAnalystUnload,analystHasUnsavedWork,isLocalAnalystWorkspace})',context);
  assert(f.ui.isLocalAnalystWorkspace(f.server));f.ui.renderLocalAnalyst();
  f.edit=text=>{analystElements.content.value=text;state.analystDraftDirty=true;};
  f.postCount=()=>f.calls.filter(call=>call.options.method==='POST').length;
  return f;
}

export async function checkAnalystController(root) {
  let f=await controllerFixture(root),{ui,state,elements,document}=f;
  f.edit('Unsaved conclusion');elements.folder.value='3';elements.content.scrollTop=80;
  assert.equal(ui.selectAnalystFile(1),true);assert(state.analystDraftDirty);assert.equal(elements.content.value,'Unsaved conclusion');assert.equal(elements.content.scrollTop,80);
  assert.equal(ui.selectAnalystFile(2),false);assert.equal(ui.selectAnalystFolder(1),false);
  await ui.createAnalystFile('scratchpad');await ui.createAnalystFolder();await ui.deleteAnalystFile();assert.equal(f.postCount(),0);
  assert.equal(await ui.refreshLocalAnalyst(true),true);assert.equal(elements.content.value,'Unsaved conclusion');assert.equal(elements.folder.value,'3');
  const row=elements.tree.querySelector('[data-file-id="1"]');row.focus();elements.tree.scrollTop=60;ui.renderLocalAnalyst();
  assert.equal(document.activeElement.dataset.fileId,'1');assert.equal(elements.tree.scrollTop,60);
  ui.moveAnalystTreeSelection({key:'ArrowDown',currentTarget:document.activeElement,preventDefault(){}});assert.equal(state.analystSelectedFileId,1);assert.equal(document.activeElement.dataset.fileId,'1');
  let warned=false;ui.guardAnalystUnload({preventDefault(){warned=true;}});assert(warned);
  ui.discardAnalystDraft();assert.equal(elements.content.value,'Saved note 1');assert.equal(document.activeElement,elements.content);assert.equal(ui.selectAnalystFile(2),true);
  elements.folderName.value='Unfinished folder';elements.folderParent.value='3';state.analystFolderDirty=true;
  assert.equal(ui.selectAnalystFile(1),false);await ui.deleteAnalystFolder();assert.equal(f.postCount(),0);
  await ui.refreshLocalAnalyst(true);assert.equal(elements.folderName.value,'Unfinished folder');assert.equal(elements.folderParent.value,'3');
  ui.discardAnalystDraft(true);assert.equal(document.activeElement,elements.folderName);assert.equal(ui.analystHasUnsavedWork(),false);

  f=await controllerFixture(root);f.elements.folderName.value='Unsaved folder';f.state.analystFolderDirty=true;
  f.edit('File move');f.elements.folder.value='3';assert.equal(await f.ui.saveAnalystFile(),false);
  assert.equal(f.postCount(),0);assert.equal(f.elements.folderName.value,'Unsaved folder');assert.equal(f.state.analystSelectedFolderId,2);
  f.elements.folderName.tagName='input';f.elements.folderParent.tagName='select';f.elements.folderForm=f.document.createElement('form');
  f.elements.folderForm.append(f.elements.folderName,f.elements.folderParent);f.state.analystFolderDirty=false;f.ui.renderLocalAnalyst();
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  runInNewContext(app.slice(app.indexOf("      analystElements.folderForm.querySelectorAll('input, select')"),app.indexOf("      analystElements.deleteFolder.addEventListener")),f.context);
  f.elements.folderName.value='Immediate discard';f.elements.folderName.listeners.get('input')();assert.equal(f.elements.revertFolder.disabled,false);

  // The real Rust and Swift stores return the same generation for no-op saves.
  f=await controllerFixture(root);f.edit('Saved note 1');f.elements.name.value='  Note 1  ';
  assert.equal(await f.ui.saveAnalystFile(),true);assert.equal(f.state.analystDraftDirty,false);assert.equal(f.state.localAnalyst.generation,1);
  f.state.analystFolderDirty=true;await f.ui.saveAnalystFolder();assert.equal(f.state.analystFolderDirty,false);
  f=await controllerFixture(root);f.state.localAnalystEtag='"local-analyst-1"';let runnerCalls=0;
  f.context.fetch=async url=>url.endsWith('/runner')?(runnerCalls++,Response.json({protocol_version:1,available:true,active_run_id:null,limits:f.state.localAnalyst.limits})):new Response(null,{status:304});
  assert.equal(await f.ui.refreshLocalAnalyst(),true);assert.equal(runnerCalls,1);assert.equal(f.state.localAnalystRunner.available,true);

  // Keep the disabled editor lock across lost-ack creation recovery, so its
  // continuation cannot replace edits typed into a different selected owner.
  f=await controllerFixture(root);f.mode='commit-drop';let release,entered;const blocked=new Promise(resolve=>{entered=resolve;});
  let originalFetch=f.context.fetch;
  f.context.fetch=async(url,options={})=>{const response=await originalFetch(url,options);if(url==='/api/local-analyst'&&!options.method){entered();await new Promise(resolve=>{release=resolve;});}return response;};
  const creation=f.ui.createAnalystFile('scratchpad');await blocked;
  assert(f.state.localAnalystSaving);assert(f.elements.content.disabled);assert(f.elements.folderName.disabled);
  assert.equal(f.ui.selectAnalystFile(2),false);release();await creation;assert.equal(f.state.analystSelectedFileId,3);assert.equal(f.postCount(),1);

  f=await controllerFixture(root);f.mode='commit-drop';f.edit('Unsolicited 304');originalFetch=f.context.fetch;
  f.context.fetch=async(url,options={})=>url==='/api/local-analyst'&&!options.method?new Response(null,{status:304}):originalFetch(url,options);
  assert.equal(await f.ui.saveAnalystFile(),false);assert(f.state.analystDraftDirty);assert(f.state.localAnalystPendingSave);
  f=await controllerFixture(root);f.edit('Invalid metadata');f.elements.name.value='invalid/name';originalFetch=f.context.fetch;
  f.context.fetch=async(url,options={})=>options.method==='POST'?Response.json({error:'Name must not contain /'},{status:400}):originalFetch(url,options);
  assert.equal(await f.ui.saveAnalystFile(),false);assert.match(f.state.localAnalystMessage,/Name must not contain/);assert(f.state.analystDraftDirty);

  // Exact success receipts and committed-but-lost/malformed acknowledgements use
  // one POST. Recovery never resends a replacement.
  for(const mode of ['ready','commit-drop','committed-conflict','malformed-ack','wrong-ack']){
    f=await controllerFixture(root);f.edit(`Saved through ${mode}`);f.mode=mode;
    assert.equal(await f.ui.saveAnalystFile(),true,mode);assert.equal(f.postCount(),1);assert.equal(f.state.localAnalyst.generation,2);
    assert.equal(f.state.analystDraftDirty,false);assert.equal(f.elements.content.value,`Saved through ${mode}`);
    assert(!/was not changed|not saved/.test(f.state.localAnalystMessage));
  }
  f=await controllerFixture(root);f.edit('Retained uncertainty');f.mode='commit-drop-read-fails';
  assert.equal(await f.ui.saveAnalystFile(),false);assert(f.state.localAnalystPendingSave);assert(f.state.analystDraftDirty);assert.match(f.state.localAnalystMessage,/uncertain/);
  assert.equal(await f.ui.saveAnalystFile(),false);await f.ui.createAnalystFile('scratchpad');assert.equal(f.postCount(),1);
  f.mode='ready';assert.equal(await f.ui.refreshLocalAnalyst(true),true);assert.equal(f.state.analystDraftDirty,false);assert.equal(f.state.localAnalystPendingSave,null);assert.equal(f.postCount(),1);

  // A failed POST followed by the same original generation may be retried only
  // explicitly with that original generation. CAS guards a delayed first write.
  f=await controllerFixture(root);f.edit('Explicit retry');f.mode='fail-before';assert.equal(await f.ui.saveAnalystFile(),false);
  assert.equal(f.state.localAnalyst.generation,1);assert(f.state.analystDraftDirty);assert.equal(f.postCount(),1);
  f.mode='ready';assert.equal(await f.ui.saveAnalystFile(),true);assert.equal(f.lastRequest.expected_generation,1);assert.equal(f.postCount(),2);

  // A real concurrent change never advances the dirty owner's original base.
  for(const mode of ['busy','ready']){
    f=await controllerFixture(root);f.edit('Local conclusion');f.server.files[0].content='Remote conclusion';f.server.files[0].content_bytes=17;f.server.generation=2;f.mode=mode;
    if(mode==='busy'){assert.equal(await f.ui.saveAnalystFile(),false);assert(f.state.localAnalystNeedsReload);}
    assert.equal(await f.ui.refreshLocalAnalyst(true),false);assert.equal(f.state.localAnalyst.generation,1);assert.equal(f.elements.content.value,'Local conclusion');
    const count=f.postCount();assert.equal(await f.ui.saveAnalystFile(),false);assert.equal(f.postCount(),count);
    f.ui.discardAnalystDraft();assert.equal(await f.ui.refreshLocalAnalyst(true),true);assert.equal(f.elements.content.value,'Remote conclusion');
  }
  for(const change of ['deleted','reused','folder']){
    f=await controllerFixture(root);f.edit('Draft retained');f.server.generation=2;
    if(change==='deleted')f.server.files.shift();
    if(change==='reused')f.server.files[0].created_at_ms=999;
    if(change==='folder'){f.state.analystFolderDirty=true;f.elements.folderName.value='Draft name';f.server.folders[1].name='Remote name';}
    assert.equal(await f.ui.refreshLocalAnalyst(true),false,change);assert.equal(f.state.localAnalyst.generation,1);assert.equal(f.elements.content.value,'Draft retained');
  }
  f=await controllerFixture(root);f.edit('Draft move');f.elements.folder.value='3';f.server.folders.pop();f.server.generation=2;
  assert.equal(await f.ui.refreshLocalAnalyst(true),true);assert.equal(f.elements.folder.value,'3');assert.match(f.elements.folder.textContent,/Unavailable folder #3/);

  // An identical successful Reload cannot overwrite a newer dirty-navigation
  // warning. Repeating the same warning also changes ownership, not its text.
  for(const repeated of [false,true]){
    f=await controllerFixture(root);
    if(repeated){f.edit('Retained pending-reload draft');assert.equal(f.ui.selectAnalystFile(2),false);f.server.generation=2;f.server.files[1].content='Unrelated newer note';f.server.files[1].content_bytes=20;}
    f.mode='hold-get';const reload=f.ui.refreshLocalAnalyst(true);assert(f.state.localAnalystRefreshing);
    f.edit('Retained pending-reload draft');
    assert.equal(f.ui.selectAnalystFile(2),false);const warning=f.state.localAnalystMessage;assert.match(warning,/Unsaved edits/);
    f.held.shift()();assert.equal(await reload,true);
    assert.equal(f.state.localAnalystMessage,warning);assert.equal(f.elements.notice.textContent,warning);
    assert.equal(f.state.localAnalyst.generation,repeated?2:1,'Fresh nonconflicting data is admitted despite preserving the newer notice');
    assert.equal(f.state.analystSelectedFileId,1);assert(f.state.analystDraftDirty);assert.equal(f.elements.content.value,'Retained pending-reload draft');assert.equal(f.postCount(),0);
  }
  // No newer notice: the normal receipt still appears. A genuinely conflicting
  // response must still supersede the local warning with actionable conflict.
  f=await controllerFixture(root);assert.equal(await f.ui.refreshLocalAnalyst(true),true);assert.match(f.state.localAnalystMessage,/2 saved files loaded/);
  f=await controllerFixture(root);f.server.generation=2;f.server.files[0].content='Remote change';f.server.files[0].content_bytes=13;f.mode='hold-get';
  const conflictingReload=f.ui.refreshLocalAnalyst(true);f.edit('Local retained');assert.equal(f.ui.selectAnalystFile(2),false);
  f.held.shift()();assert.equal(await conflictingReload,false);assert.equal(f.state.localAnalystStatus,'conflict');assert.match(f.state.localAnalystMessage,/changed in another window/);assert.equal(f.elements.content.value,'Local retained');assert.equal(f.postCount(),0);

  // An older in-flight load cannot replace a successful new save.
  f=await controllerFixture(root);f.mode='hold-get';const load=f.ui.refreshLocalAnalyst(true);
  f.mode='ready';f.edit('Newer saved');assert.equal(await f.ui.saveAnalystFile(),true);f.held.shift()();assert.equal(await load,false);
  assert.equal(f.state.localAnalyst.generation,2);assert.equal(f.elements.content.value,'Newer saved');

  // A slow independent runner read cannot leave the visible editor based on a
  // different generation from the workspace used for the next save.
  f=await controllerFixture(root);f.server.generation=2;f.server.files[0].content='Remote important edit';f.server.files[0].content_bytes=21;
  let runnerEntered;const waitingRunner=new Promise(resolve=>{runnerEntered=resolve;});originalFetch=f.context.fetch;
  f.context.fetch=async(url,options={})=>{const response=await originalFetch(url,options);if(url.endsWith('/runner')){runnerEntered();await new Promise(resolve=>{release=resolve;});}return response;};
  const slowRunner=f.ui.refreshLocalAnalyst(true);await waitingRunner;
  assert.equal(f.state.localAnalyst.generation,2);assert.equal(f.elements.content.value,'Remote important edit');
  assert.equal(f.state.analystDraftBase.content,'Remote important edit');f.edit('Edit based on visible remote version');
  assert.equal(await f.ui.saveAnalystFile(),true);release();await slowRunner;assert.equal(f.state.localAnalyst.generation,3);
  // Independently reject an injected old form owner even if the displayed model
  // was changed by another integration without using the admission helper.
  f=await controllerFixture(root);f.edit('Old form edits');f.state.localAnalyst.files[0]={...f.state.localAnalyst.files[0],content:'Other owner'};
  assert.equal(await f.ui.saveAnalystFile(),false);assert.equal(f.postCount(),0);assert.match(f.state.localAnalystMessage,/no longer matches/);

  // While saving, a second submit or navigation cannot acquire the editor.
  f=await controllerFixture(root);f.edit('One save');f.mode='hold-post';const saving=f.ui.saveAnalystFile();
  assert.equal(await f.ui.saveAnalystFile(),false);assert.equal(f.ui.selectAnalystFile(2),false);assert.equal(f.ui.analystHasUnsavedWork(),true);
  f.mode='ready';f.held.shift()();assert.equal(await saving,true);assert.equal(f.postCount(),1);

  // Deadline retires a stuck body/header read without assuming it failed to commit.
  f=await controllerFixture(root);f.edit('Late original');f.mode='hold-post';const late=f.ui.saveAnalystFile();
  [...f.timers][0].callback();assert.equal(await late,false);assert(f.state.analystDraftDirty);assert.equal(f.state.localAnalyst.generation,1);
  f.mode='ready';f.held.shift()();await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(f.state.localAnalyst.generation,1,'Late acknowledgement must not mutate UI');
  assert.equal(await f.ui.saveAnalystFile(),true,'A 409 after the original delayed commit is reconciled to the exact saved snapshot');
  assert.equal(f.server.generation,2,'No duplicate commit');
  assert.equal(f.state.analystDraftDirty,false);assert.equal(f.postCount(),2,'Only the explicit retry sent another application POST');
  assert.equal(await f.ui.refreshLocalAnalyst(true),true);
  console.log('PASS Analyst dirty same-file/navigation/folder/unload guards, focus, exact receipts, uncertain reconciliation, conflict bases, stale replies, deadlines and duplicate-write suppression (controller fixture; not rendered QA)');
}
