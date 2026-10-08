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
  for(const mode of ['ready','commit-drop','malformed-ack','wrong-ack']){
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
  assert.equal(await f.ui.saveAnalystFile(),false,'Original delayed write makes explicit retry conflict');
  assert.equal(f.server.generation,2,'No duplicate commit');
  assert.equal(await f.ui.refreshLocalAnalyst(true),false,'Different saved base stays explicit until discarded');
  let reloads=0, reads=0;
  await reloadInvestigationDocument(async expression=>{
    if(expression==='performance.timeOrigin')return 100;
    reads++;
    return runInNewContext(expression,{performance:{timeOrigin:reads<3?100:200},document:{readyState:reads===3?'loading':'complete'},renderRequests(){}});
  },async()=>{reloads++;});
  assert.equal(reloads,1);assert.equal(reads,4,'Old-page readiness and incomplete new documents cannot finish reload');
  let evaluated=0;await reloadInvestigationDocument(async()=>{evaluated++;return 100;},async()=>{reloads++;},false);
  assert.equal(evaluated,1,'The intentional beforeunload cancellation path does not wait for a replacement document');
  console.log('PASS Analyst dirty same-file/navigation/folder/unload guards, focus, exact receipts, uncertain reconciliation, conflict bases, stale replies, deadlines and duplicate-write suppression (controller fixture; not rendered QA)');
}

// Page.reload acknowledges dispatch before document replacement. A readiness
// predicate on the old application is insufficient; bind it to a new document.
export async function reloadInvestigationDocument(evaluate, reload, waitForDocument = true) {
  const previous = await evaluate('performance.timeOrigin');
  await reload();
  if (!waitForDocument) return;
  const start = Date.now();
  while (Date.now() - start < 7000) {
    try {
      if (await evaluate(`performance.timeOrigin !== ${JSON.stringify(previous)} && document.readyState === 'complete' && typeof renderRequests === 'function'`)) return;
    } catch { /* The old execution context may disappear during replacement. */ }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.fail('The reloaded application did not reach a new, complete document');
}

export async function checkAnalystInteractions({evaluate,viewport,click,key,wheel,screenshot,typeText,fixture,reloadPage,beforeUnload}) {
  const f=fixture.notebook, original=copy(f.library), receipts=[];
  f.library=analystFixtureLibrary(()=>f.library);f.library.generation=original.generation+1;f.mode='ready';
  const until=async expression=>{const start=Date.now();while(Date.now()-start<7000){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail(expression);};
  const press=async name=>key(name,name,{windowsVirtualKeyCode:{Enter:13,Tab:9,ArrowDown:40}[name],...(name==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  const hit=async selector=>{
    for(let attempt=0;attempt<8;attempt++){
      const scroll=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)}),r=n.getBoundingClientRect();
        for(let p=n.parentElement;p;p=p.parentElement){const b=p.getBoundingClientRect(),style=getComputedStyle(p);
          if(!/(auto|scroll)/.test(style.overflowY)||p.scrollHeight<=p.clientHeight+1)continue;
          const top=Math.max(b.top,0)+8,bottom=Math.min(b.bottom,innerHeight)-8;
          const delta=r.top<top?r.top-top:r.bottom>bottom?Math.min(r.bottom-bottom,r.top-top):0;
          if(Math.abs(delta)>1)return {selector:p.id?'#'+p.id:'#screen-analyst .analyst-pane:nth-child('+(Array.from(p.parentElement.children).indexOf(p)+1)+')',delta};
        }return null;})()`);
      if(!scroll)break;await wheel(scroll.selector,scroll.delta,'edge');
    }
    await click(selector);
  };
  const type=async(selector,text)=>{await hit(selector);await key('a','KeyA',{windowsVirtualKeyCode:65,modifiers:2});await key('Backspace','Backspace',{windowsVirtualKeyCode:8});await typeText(text);};
  const enter=async()=>{await click('#advanced-navigation > summary');await click('#advanced-navigation [data-screen="analyst"]');await until('state.localAnalystLoaded && !state.localAnalystRefreshing');};
  const tree=id=>`#analyst-tree [data-file-id="${id}"]`;
  await viewport(1440,900);await enter();await hit('#analyst-reload');await until(`state.localAnalyst.generation===${f.library.generation}`);
  await hit('#analyst-tree [data-folder-id="2"]');await hit(tree(1));
  await type('#analyst-content','Synthetic unsaved conclusion. <img src=x onerror=alert(1)>');
  await hit(tree(1));assert.equal(await evaluate('analystElements.content.value'),'Synthetic unsaved conclusion. <img src=x onerror=alert(1)>');
  assert(await evaluate('state.analystDraftDirty'));await hit(tree(2));assert.equal(await evaluate('state.analystSelectedFileId'),1);
  assert.match(await evaluate('state.localAnalystMessage'),/Unsaved edits/);
  await hit(tree(1));await press('ArrowDown');assert.equal(await evaluate('document.activeElement.dataset.fileId'),'1');
  assert.equal(await evaluate('state.analystSelectedFileId'),1);assert.equal(await evaluate("document.querySelector('#screen-analyst img')"),null);
  await screenshot('analyst-wide-dirty-guard');
  await click('[data-screen="sources"]');await enter();assert(await evaluate('state.analystDraftDirty'));assert.match(await evaluate('analystElements.content.value'),/unsaved conclusion/);
  await hit('#analyst-reload');await until('!state.localAnalystRefreshing');assert.match(await evaluate('analystElements.content.value'),/unsaved conclusion/);
  const reloading=reloadPage(false);await beforeUnload(false);await reloading;
  assert(await evaluate('state.analystDraftDirty'));assert.match(await evaluate('analystElements.content.value'),/unsaved conclusion/);
  receipts.push({check:'Native browser reload cancelled; dirty content retained',generation:f.library.generation});

  // A file draft and folder draft can coexist without a file move replacing the
  // folder editor's unsaved name. Use genuine select and button keyboard input.
  await hit('#screen-analyst .analyst-storage > summary');await type('#analyst-folder-name','Unsaved folder rename');
  assert.equal(await evaluate('analystElements.revertFolder.disabled'),false);
  await hit('#analyst-folder');await key('Home','Home',{windowsVirtualKeyCode:36});await press('ArrowDown');await press('Enter');
  assert.equal(await evaluate('analystElements.folder.value'),'3');
  const beforeMove=f.calls.filter(call=>call.method==='POST').length;
  await hit('#analyst-save');await until("state.localAnalystMessage.includes('folder changes')");
  assert.equal(f.calls.filter(call=>call.method==='POST').length,beforeMove);assert.equal(await evaluate('analystElements.folderName.value'),'Unsaved folder rename');
  await hit('#analyst-revert-folder');assert.equal(await evaluate('document.activeElement.id'),'analyst-folder-name');
  await hit('#analyst-revert');assert.equal(await evaluate('document.activeElement.id'),'analyst-content');
  assert.equal(await evaluate('state.analystDraftDirty || state.analystFolderDirty'),false);

  for(const mode of ['commit-drop','malformed-ack']){
    f.mode=mode;await type('#analyst-content',`Saved after ${mode}`);const before=f.calls.filter(call=>call.method==='POST').length;
    await hit('#analyst-save');await until('!state.localAnalystSaving && !state.analystDraftDirty');
    assert.equal(f.calls.filter(call=>call.method==='POST').length,before+1);assert.equal(f.library.files[0].content,`Saved after ${mode}`);
    assert.match(await evaluate('state.localAnalystMessage'),/verified by reloading/);
    await screenshot(`analyst-${mode}-reconciled`);f.mode='ready';
  }
  f.mode='recover-hold';await hit('#analyst-new-note');
  const heldAt=Date.now();while(!f.pending.length&&Date.now()-heldAt<7000)await new Promise(resolve=>setTimeout(resolve,25));assert(f.pending.length);
  assert(await evaluate('state.localAnalystSaving && analystElements.content.disabled && analystElements.name.disabled'));
  await hit(tree(2));assert.equal(await evaluate('state.analystSelectedFileId'),1);
  f.release();f.mode='ready';await until('!state.localAnalystSaving && state.analystSelectedFileId!==1');
  await hit(tree(1));

  await type('#analyst-content','Local draft survives remote edit');
  f.library.files[0].content='Remote saved conclusion';f.library.files[0].content_bytes=Buffer.byteLength(f.library.files[0].content);f.library.generation++;
  await hit('#analyst-save');await until('!state.localAnalystSaving && state.localAnalystNeedsReload');
  const dirtyGeneration=await evaluate('state.localAnalyst.generation');await hit('#analyst-reload');await until('!state.localAnalystRefreshing');
  assert.equal(await evaluate('state.localAnalyst.generation'),dirtyGeneration);assert.equal(await evaluate('analystElements.content.value'),'Local draft survives remote edit');
  assert(await evaluate('analystElements.save.disabled'));await screenshot('analyst-concurrent-change-retained');
  await hit('#analyst-revert');await hit('#analyst-reload');await until('!state.localAnalystNeedsReload && !state.localAnalystRefreshing');
  assert.equal(await evaluate('analystElements.content.value'),'Remote saved conclusion');

  for(const [width,height] of [[760,560],[360,740]]){
    await viewport(width,height);await type('#analyst-content',`Keyboard draft at ${width}`);
    await hit('#analyst-revert');await press('Tab');
    assert.equal(await evaluate('document.activeElement.id'),'analyst-delete','Discard returns focus to content, then Tab skips disabled Save/Discard');
    await hit('#analyst-reload');await until('!state.localAnalystRefreshing');
    const geometry=await evaluate(`(()=>{const n=analystElements.reload,r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight,overflow:document.querySelector('#screen-analyst').scrollWidth-document.querySelector('#screen-analyst').clientWidth}})()`);
    assert(geometry.left>=0&&geometry.right<=width&&geometry.top>=0&&geometry.bottom<=height&&geometry.overflow<=1,JSON.stringify(geometry));
    receipts.push({check:`${width} Retry load remains visible and reachable`,...geometry});await screenshot(`analyst-${width}-recovery-controls`);
  }
  await viewport(1440,900);f.library={...original,generation:f.library.generation+1};f.mode='ready';
  await reloadPage();await until("typeof state!=='undefined' && state.requests.length===1 && state.artifacts.length===2");
  return {status:'passed',viewports:[[1440,900],[760,560],[360,740]],receipts,
    checks:['same-file no-op and dirty switching refusal','native arrow/Tab focus','workspace navigation and refresh retain draft','real beforeunload cancellation retains draft','simultaneous folder/file draft move guard','committed lost/malformed acknowledgement reread with one POST','create recovery keeps editor locked','concurrent change keeps original base until discard/reload','inert draft text','narrow recovery controls'],
    limitations:['Synthetic HTTP responses verify UI ownership, not disk durability.','Chromium lifecycle does not establish native macOS quit protection.']};
}
