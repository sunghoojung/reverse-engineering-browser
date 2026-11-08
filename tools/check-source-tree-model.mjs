import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {performance} from 'node:perf_hooks';
import {runInNewContext} from 'node:vm';

// Small inert DOM ownership model. Native activation, layout and scroll-clamping
// acceptance belong to the packaged-app rendered checks, not these deterministic checks.
class TreeNode {
  constructor(tag, document) {
    this.localName=tag;this.document=document;this.children=[];this.parentElement=null;
    this.attributes=new Map();this.dataset={};this.listeners=new Map();this.properties=new Map();
    this.style={setProperty:(name,value)=>this.properties.set(name,value)};
    this.textContent='';this.title='';this.className='';this.value='';this.scrollTop=0;this.tabIndex=-1;this.hidden=false;
  }
  setAttribute(name,value){this.attributes.set(name,String(value));}
  getAttribute(name){return this.attributes.get(name)??null;}
  append(...nodes){for(const node of nodes)this.insertBefore(node,null);}
  insertBefore(node,next){
    node.remove();const index=next===null?this.children.length:this.children.indexOf(next);
    assert(index>=0);this.children.splice(index,0,node);node.parentElement=this;
  }
  remove(){
    if(this.parentElement){const siblings=this.parentElement.children;siblings.splice(siblings.indexOf(this),1);this.parentElement=null;}
    if(this.contains(this.document.activeElement))this.document.activeElement=null;
  }
  contains(node){for(let current=node;current;current=current.parentElement)if(current===this)return true;return false;}
  addEventListener(name,handler){if(!this.listeners.has(name))this.listeners.set(name,[]);this.listeners.get(name).push(handler);}
  dispatch(name,event={}){for(const handler of this.listeners.get(name)??[])handler(event);}
  dispatchEvent(event){this.dispatch(event.type,event);}
  focus(){this.document.activeElement=this;this.dispatch('focus');}
}

export async function checkSourceTreeModel(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const syntax=await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8');
  const facts=await readFile(join(root,'apps/research-ui/source_facts.js'),'utf8');
  const tree=await readFile(join(root,'apps/research-ui/source_tree.js'),'utf8');
  const part=(text,start,end)=>{const from=text.indexOf(start),to=text.indexOf(end,from);assert(from>=0&&to>from,`Missing ${start}`);return text.slice(from,to);};
  // The production module and the production app.js wiring, including the Console hook.
  const program=part(facts,'const sourceFactsFields','function sourceFactsUnavailable')+
    part(syntax,'      function sourceName(','      function formatByteSize(')+
    part(app,'      function sourceIdentity(','      function retireSourceAnalysis(')+
    part(app,'      function sourceDisplayName(','      function selectedSource(')+
    part(app,'      function renderSourceTree(','      function renderSourceHealth(')+tree+
    part(app,'const sourceTreeView = createSourceTree({','// The Console')+
    part(app,"document.addEventListener('reb:console-documents'",'      const evidencePackagePanel')+
    ';({sourceTreeView,renderSourceTree,sourceTreeUrl,sourceTreeFileIcon,isSourceArtifact,sourceDisplayName,SOURCE_TREE_LIMITS})';
  const artifact=(id,url=`https://a.invalid/shared/nested/${id}.js`,extra={})=>({source_type:'artifact',artifact_id:String(id),url,
    protocol_version:1,session_id:'1',navigation_id:'2',frame_id:'3',parent_artifact_id:'0',creator_event_id:'0',execution_context_id:'0',
    capture_origin:'network_response',kind:'javascript',mime_type:'text/javascript',byte_size:8,sha256:'a'.repeat(64),sensitive:false,...extra});
  const fixture=(artifacts=[artifact(1),artifact(2),artifact(3,'https://b.invalid/shared/nested/3.js')],height=240)=>{
    const documentListeners=new Map();
    const document={activeElement:null,created:0,createElement(tag){this.created++;return new TreeNode(tag,this);},
      addEventListener:(name,handler)=>documentListeners.set(name,handler)};
    const controls=Object.fromEntries(['#source-tree-filter','#source-tree-expand','#source-tree-collapse'].map(id=>[id,new TreeNode(id==='#source-tree-filter'?'input':'button',document)]));
    document.querySelector=selector=>controls[selector]??null;
    const tree=new TreeNode('div',document);tree.clientHeight=height;
    const state={sourceCollection:'captured',artifacts,selectedArtifactId:'1',artifactCatalogLimit:0,consoleDocuments:null};
    const calls=[];
    const api=runInNewContext(program,{URL,Event,document,state,elements:{sourceTree:tree},
      selectArtifact:id=>calls.push(['artifact',id]),renderSourceHealth:()=>calls.push(['health'])});
    const nav=()=>api.sourceTreeView.state();
    return {document,documentListeners,controls,tree,state,api,calls,nav};
  };
  // Context-realm arrays compare by value.
  const same=(actual,expected,message)=>assert.deepEqual(JSON.parse(JSON.stringify(actual)),expected,message);
  const rows=t=>[...t.nav().rows.values()].map(entry=>entry.row);
  const labels=t=>t.nav().list.map(node=>node.label);
  const entry=(t,key)=>t.nav().rows.get(key);
  const node=(t,predicate)=>t.nav().list.find(predicate);
  const file=(t,id)=>node(t,value=>value.source?.artifact_id===String(id));
  const key=(row,value,modifiers={})=>{
    const event={key:value,prevented:false,preventDefault(){this.prevented=true;},stopPropagation(){this.stopped=true;},...modifiers};
    row.dispatch('keydown',event);return event;
  };
  const checkTabStop=t=>{
    assert.equal(rows(t).filter(row=>row.tabIndex===0).length,rows(t).length?1:0);
    assert.equal(t.tree.tabIndex,rows(t).length?-1:0);
  };

  // URLs: non-special schemes keep their host and extension ID.
  {
    const {api}=fixture([]);const url=value=>JSON.parse(JSON.stringify(api.sourceTreeUrl(value)));
    same([url('chrome://settings/strings.js').origin,url('chrome://settings/strings.js').parts],['chrome://settings',['strings.js']]);
    same([url('chrome-extension://abcdefghijklmnop/js/content.js').host,url('chrome-extension://abcdefghijklmnop/js/content.js').parts],['abcdefghijklmnop',['js','content.js']]);
    assert.equal(url('https://a.invalid/x.js?v=1').search,'?v=1');assert.equal(url('blob:https://a.invalid/0b2c').origin,'https://a.invalid');
    same(url('blob:https://a.invalid/0b2c').parts,['0b2c']);assert.equal(url('about:blank').origin,'about:');
    assert.equal(url('data:text/javascript,1').origin,'data:');assert.equal(url('not a url').origin,'(generated)');assert.equal(url('').origin,'(anonymous)');
    const icon=(kind,mime)=>api.sourceTreeFileIcon({kind,mime_type:mime});
    same([icon('javascript'),icon('wasm'),icon('source_map'),icon('wasm_guest_adapter'),icon('response_body','text/html; charset=utf-8'),
      icon('response_body','application/json'),icon('bytecode_buffer','application/octet-stream')],['js','wasm','map','json','html','json','file']);
  }
  // Structure: frames first (the frame seen first, then the rest by label),
  // then Workers, Dynamic, WebAssembly, Extensions and collapsed Browser internals.
  {
    const t=fixture([artifact(1),artifact(2),artifact(3,'https://cdn.invalid/lib/x.js'),
      artifact(4,'https://a.invalid/index.html',{capture_origin:'dynamic_javascript',execution_context_id:'4'}),
      artifact(5,'https://b.invalid/shared/nested/3.js',{frame_id:'9'}),
      artifact(6,'https://b.invalid/frame.html',{frame_id:'9',kind:'wasm',mime_type:'application/wasm',capture_origin:'webassembly_instantiate',execution_context_id:'5'}),
      artifact(7,'https://a.invalid/worker.js',{frame_id:'0'}),
      artifact(8,'chrome-extension://abcdefghijklmnop/js/content.js'),
      artifact(9,'chrome://settings/strings.js'),
      artifact(10,'fixture://native-guest',{capture_origin:'native_wasm_guest',kind:'bytecode_buffer',mime_type:'application/octet-stream',
        parent_artifact_id:'6',creator_event_id:'1',execution_context_id:'5'})]);
    t.api.renderSourceTree();
    same(labels(t),['top','a.invalid','a.invalid','shared/nested','1.js','2.js','cdn.invalid','lib','x.js',
      'b.invalid','b.invalid','shared/nested','3.js','Workers','a.invalid','worker.js','Dynamic (eval / new Function)','a.invalid','VM4',
      'WebAssembly','b.invalid','wasm webassembly instantiate','fixture://native-guest','fixture://native-guest',
      'Extensions','abcdefghijklmnop','js','content.js','Browser internals']);
    same(t.nav().list.map(value=>value.kind).slice(0,3),['root','frame','origin']);
    assert(!labels(t).some(label=>/artifact/.test(label)),'File rows show plain names');
    const internal=node(t,value=>value.label==='Browser internals');
    assert.equal(entry(t,internal.key).row.getAttribute('aria-expanded'),'false');assert.equal(entry(t,internal.key).detail.textContent,'1');
    assert.equal(entry(t,file(t,1).key).detail.textContent,'1','The muted meta column holds the artifact ID');
    assert.equal(entry(t,file(t,4).key).detail.textContent,'','A label that already names the ID repeats nothing');
    assert.equal(entry(t,t.nav().model.rootKey).detail.textContent,'10');
    const one=entry(t,file(t,1).key);
    assert.match(one.row.title,/^https:\/\/a\.invalid\/shared\/nested\/1\.js · artifact 1$/);assert.match(one.row.getAttribute('aria-label'),/^1\.js, JavaScript, artifact 1$/);
    assert.equal(one.icon.className,'source-file-icon');assert.equal(one.icon.dataset.icon,'js');assert.equal(one.icon.textContent,'JS');
    assert.equal(entry(t,file(t,10).key).icon.textContent,'BC');assert.equal(entry(t,file(t,6).key).icon.dataset.icon,'wasm');
    same(['frame','origin','folder','worker','dynamic','wasm-group','extension','internal'].map(icon=>t.nav().list.some(value=>value.icon===icon)),Array(8).fill(true));
    assert.equal(one.row.dataset.sourceTreeKind,'file');assert.equal(one.row.children[0],one.twisty,'Every row keeps its twisty cell so columns align');
    // A Console document listing names its frame and marks the top-level one.
    t.documentListeners.get('reb:console-documents')({detail:[{url:'https://b.invalid/frame.html',main_frame:true}]});
    same(t.nav().model.nodes.get(t.nav().model.rootKey).children.slice(0,2).map(value=>t.nav().model.nodes.get(value).label),['b.invalid/frame.html','a.invalid']);
    assert.match(node(t,value=>value.kind==='frame').title,/top-level document/);
    t.api.sourceTreeView.expandAll();assert(labels(t).includes('strings.js'),'Expand all opens Browser internals');
  }
  // Same-named siblings: a query, a session or nothing but the meta ID tells them apart.
  {
    const t=fixture([artifact(20,'https://a.invalid/app.js?v=1'),artifact(21,'https://a.invalid/app.js?v=2'),
      artifact(22,'https://a.invalid/lib.js',{frame_id:'0'}),artifact(23,'https://a.invalid/lib.js',{frame_id:'0',session_id:'2'}),
      artifact(24,'https://a.invalid/same.js'),artifact(25,'https://a.invalid/same.js',{sha256:'b'.repeat(64)}),
      artifact(26,'https://c.invalid/x.js',{frame_id:'8'}),artifact(27,'https://c.invalid/x.js',{frame_id:'7'})]);
    t.api.renderSourceTree();
    same([20,21,22,23,24,25].map(id=>file(t,id).suffix),['?v=1','?v=2','session 1','session 2','','']);
    same([24,25].map(id=>entry(t,file(t,id).key).detail.textContent),['24','25']);
    same(t.nav().list.filter(value=>value.kind==='frame').map(value=>`${value.label} ${value.suffix ?? ''}`.trim()),['frame frame 3','frame frame 7','frame frame 8']);
  }
  // Keyed refresh, focus, scroll anchoring and collapse without source actions.
  {
    const t=fixture();t.api.renderSourceTree();const nav=t.nav();
    assert.equal(nav.list.length,9);checkTabStop(t);
    const one=file(t,1),selectedRow=entry(t,one.key).row;
    assert.equal(selectedRow.getAttribute('aria-selected'),'true');assert.equal(selectedRow.tabIndex,0);
    for(const value of nav.list){
      const row=entry(t,value.key).row;assert.equal(row.getAttribute('aria-level'),String(value.depth+1));
      assert.equal(row.getAttribute('aria-posinset'),String(value.position));assert.equal(row.getAttribute('aria-setsize'),String(value.size));
      assert.equal(row.getAttribute('role'),'treeitem');assert.equal(row.properties.get('--source-row'),String(nav.index.get(value.key)));
      if(value.children)assert.equal(row.getAttribute('aria-expanded'),'true');else assert.equal(row.getAttribute('aria-expanded'),null);
    }
    selectedRow.focus();t.tree.scrollTop=111;
    t.api.renderSourceTree();assert.equal(entry(t,one.key).row,selectedRow);assert.equal(t.document.activeElement,selectedRow);assert.equal(t.tree.scrollTop,111);
    const created=t.document.created;for(let i=0;i<50;i++)t.api.renderSourceTree();
    assert.equal(t.document.created,created,'Unchanged refresh must not recreate tree rows');
    const folder=node(t,value=>value.kind==='folder'&&value.key.includes('a.invalid')),before=JSON.stringify(t.state.artifacts);
    assert.equal(folder.label,'shared/nested','A single-folder chain is one row');
    t.api.sourceTreeView.toggle(folder.key,false);
    assert.equal(t.state.selectedArtifactId,'1');assert.equal(JSON.stringify(t.state.artifacts),before);assert.equal(t.calls.length,0);
    assert.equal(nav.rows.has(one.key),false);assert.equal(t.document.activeElement,entry(t,folder.key).row);
    assert.equal(entry(t,folder.key).row.getAttribute('aria-expanded'),'false');checkTabStop(t);
    assert(file(t,3),'The same folder in another origin stays open');
    t.state.artifacts.push(artifact(5));t.api.renderSourceTree();
    assert.equal(entry(t,folder.key).row.getAttribute('aria-expanded'),'false','Catalog arrival must not reopen a collapsed branch');
    assert.equal(nav.model.nodes.get(folder.key).count,3);assert(!file(t,5));
    t.api.sourceTreeView.toggle(folder.key,true);assert(file(t,1));
    assert.equal(t.document.activeElement,entry(t,folder.key).row);assert.equal(t.calls.length,0);
    const focused=entry(t,folder.key).row;focused.focus();
    const anchorKey=nav.list[Math.floor(t.tree.scrollTop/24)].key,offset=t.tree.scrollTop%24;
    t.state.artifacts.reverse();t.state.artifacts.push(artifact(4,'https://a.invalid/a-new/4.js'));t.api.renderSourceTree();
    assert.equal(entry(t,folder.key).row,focused);assert.equal(t.document.activeElement,focused);
    assert.equal(t.tree.scrollTop,nav.index.get(anchorKey)*24+offset,'Rows inserted above keep the first visible row in place');
    t.state.artifacts=t.state.artifacts.filter(source=>source.artifact_id!=='1');t.api.renderSourceTree();
    assert.equal(t.document.activeElement,focused);
    entry(t,file(t,3).key).row.focus();
    t.state.artifacts=t.state.artifacts.filter(source=>source.artifact_id!=='3');t.api.renderSourceTree();
    assert.equal(t.document.activeElement.dataset.sourceTreeKind,'frame','A removed focused branch returns to its nearest surviving ancestor');
    const input=t.document.createElement('input');input.focus();t.api.renderSourceTree();assert.equal(t.document.activeElement,input);
    t.state.artifacts=[];t.api.renderSourceTree();assert.equal(rows(t).length,0);checkTabStop(t);assert.match(t.tree.children[0].textContent,/No source artifacts/);
    t.tree.focus();t.state.artifacts=[artifact(8)];t.api.renderSourceTree();assert(t.tree.contains(t.document.activeElement));checkTabStop(t);
    t.state.artifacts=[{...artifact(9),kind:'canvas_data_url'}];t.api.renderSourceTree();assert.equal(rows(t).length,0);assert.match(t.tree.children[0].textContent,/Canvas images/);
    // A retained request body is network evidence shown with its Traffic row
    // (native-network-v2.md). It never becomes a source file or origin branch.
    const body={...artifact(10,'https://api.example/getcaptcha?s=1'),kind:'request_body',capture_origin:'network_request',
      execution_context_id:'0',creator_event_id:'14',mime_type:'application/json',sensitive:true};
    t.state.artifacts=[body];t.api.renderSourceTree();assert.equal(rows(t).length,0);
    t.state.artifacts=[body,artifact(11)];t.api.renderSourceTree();
    const all=[...nav.model.nodes.values()].map(value=>`${value.label} ${value.title ?? ''}`).join('\n');
    assert.doesNotMatch(all,/api\.example|getcaptcha/);
    same(nav.list.filter(value=>value.source).map(value=>value.source.artifact_id),['11']);
    assert.equal(t.api.isSourceArtifact(body),false);assert.equal(t.api.isSourceArtifact(artifact(12)),true);
  }
  // Keyboard: arrows, Home/End, Right/Left, type-ahead; chords and native activation stay native.
  {
    const t=fixture();t.api.renderSourceTree();const nav=t.nav(),root=entry(t,nav.model.rootKey).row;root.focus();
    assert(key(root,'ArrowDown').prevented);assert.equal(t.document.activeElement.dataset.sourceTreeKind,'frame');
    assert(key(t.document.activeElement,'ArrowRight').prevented);assert.equal(t.document.activeElement.dataset.sourceTreeKind,'origin');
    assert(key(t.document.activeElement,'ArrowRight').prevented);assert.equal(t.document.activeElement.dataset.sourceTreeKind,'folder');
    const folderKey=t.document.activeElement.dataset.sourceTreeKey,folderRow=t.document.activeElement;
    assert(key(folderRow,'ArrowLeft').prevented);assert.equal(folderRow.getAttribute('aria-expanded'),'false');
    assert(key(folderRow,'ArrowRight').prevented);assert.equal(folderRow.getAttribute('aria-expanded'),'true');
    key(folderRow,'End');assert.equal(t.document.activeElement,entry(t,nav.list.at(-1).key).row);
    key(t.document.activeElement,'Home');assert.equal(t.document.activeElement,root);
    key(root,'ArrowUp');assert.equal(t.document.activeElement,root);
    for(const modifiers of [{altKey:true},{ctrlKey:true},{metaKey:true},{shiftKey:true}]){
      assert.equal(key(root,'ArrowLeft',modifiers).prevented,false);assert.equal(root.getAttribute('aria-expanded'),'true');
    }
    nav.typeahead.time=0;key(root,'b');assert.equal(t.document.activeElement.dataset.sourceTreeKey,node(t,value=>value.label==='b.invalid').key,'Type-ahead finds the next matching row');
    nav.typeahead.time=0;key(t.document.activeElement,'s');const firstShared=t.document.activeElement.dataset.sourceTreeKey;
    key(t.document.activeElement,'s');assert.notEqual(t.document.activeElement.dataset.sourceTreeKey,firstShared,'Repeating a letter cycles');
    assert.equal(nav.list.find(value=>value.key===t.document.activeElement.dataset.sourceTreeKey).label,'shared/nested');
    nav.typeahead.time=0;key(t.document.activeElement,'2');key(t.document.activeElement,'.');assert.equal(t.document.activeElement,entry(t,file(t,2).key).row);
    nav.typeahead.time=0;assert(key(t.document.activeElement,'A',{shiftKey:true}).prevented);assert.equal(nav.list[nav.index.get(t.document.activeElement.dataset.sourceTreeKey)].label,'a.invalid');
    folderRow.focus();
    for(const value of ['Enter',' ']){
      const old=folderRow.getAttribute('aria-expanded');assert.equal(key(folderRow,value).prevented,false);
      assert.equal(folderRow.getAttribute('aria-expanded'),old,'Key handler must not duplicate native button activation');
      folderRow.dispatch('click');assert.notEqual(folderRow.getAttribute('aria-expanded'),old);
    }
    t.api.sourceTreeView.toggle(folderKey,true);
    const row=entry(t,file(t,2).key).row;
    for(const value of ['Enter',' ']){const count=t.calls.length;assert.equal(key(row,value).prevented,false);assert.equal(t.calls.length,count);row.dispatch('click');assert.equal(t.calls.length,count+1);}
    const staleRow=entry(t,file(t,1).key).row;
    t.state.artifacts[0]={...t.state.artifacts[0],sha256:'b'.repeat(64)};staleRow.dispatch('click');assert.equal(t.calls.at(-1)[0],'health');
  }
  // Filter: matching files and their ancestors, a transient expansion, Escape restores.
  {
    const t=fixture([artifact(1),artifact(2),artifact(3,'https://b.invalid/shared/nested/3.js'),artifact(30,'https://c.invalid/deep/zeta.js')]);
    t.api.renderSourceTree();const nav=t.nav(),filter=t.controls['#source-tree-filter'];
    const aFolder=node(t,value=>value.kind==='folder'&&value.key.includes('a.invalid'));t.api.sourceTreeView.toggle(aFolder.key,false);
    const saved=JSON.stringify([...nav.scopes.get('captured').open]);
    filter.value='ZETA';filter.dispatch('input');
    same(labels(t),['top','frame','c.invalid','deep','zeta.js']);assert.equal(entry(t,nav.model.rootKey).detail.textContent,'1');
    entry(t,node(t,value=>value.label==='deep').key).row.dispatch('click');same(labels(t),['top','frame','c.invalid','deep']);
    filter.value='30';filter.dispatch('input');same(nav.list.filter(value=>value.source).map(value=>value.source.artifact_id),['30']);
    filter.value='nothing-matches';filter.dispatch('input');assert.equal(nav.list.length,0);assert.match(t.tree.children[0].textContent,/No files match “nothing-matches”/);
    filter.value='nested';filter.dispatch('input');const down=key(filter,'ArrowDown');assert(down.prevented);assert(t.tree.contains(t.document.activeElement));
    key(filter,'Escape');assert.equal(filter.value,'');
    assert.equal(JSON.stringify([...nav.scopes.get('captured').open]),saved,'Filtering never changes the saved expansion');
    assert(!file(t,1)&&file(t,3)&&file(t,30),'The saved expansion returns after the filter clears');
    assert.equal(JSON.stringify(t.state.artifacts.map(value=>value.artifact_id)),'["1","2","3","30"]');
  }
  // Expand all and Collapse all.
  {
    const t=fixture([artifact(1),artifact(2,'chrome://newtab/x.js')]);t.api.renderSourceTree();
    t.controls['#source-tree-collapse'].dispatch('click');same(labels(t),['top','frame','Browser internals']);
    t.controls['#source-tree-expand'].dispatch('click');same(labels(t),['top','frame','a.invalid','shared/nested','1.js','Browser internals','chrome://newtab','x.js']);
  }
  // Scale: 20,000 retained scripts are all reachable while about one window of rows is mounted.
  let timing;
  {
    const catalog=Array.from({length:20000},(_,i)=>artifact(i+1,`https://a${i%20}.invalid/d${i%7}/f${i}.js`));
    const t=fixture(catalog);const started=performance.now();t.api.renderSourceTree();timing=performance.now()-started;const nav=t.nav();
    assert.equal(nav.model.files.size,20000);assert.equal(nav.list.filter(value=>value.source).length,20000,'Every retained source has a row');
    const bound=10+2*t.api.SOURCE_TREE_LIMITS.overscan+1;
    assert(nav.rows.size<=bound,`Mounted rows stay near one window: ${nav.rows.size}`);
    assert.equal(t.tree.children.at(-1).properties.get('height'),`${nav.list.length*24}px`);
    t.tree.scrollTop=(nav.list.length-10)*24;t.tree.dispatch('scroll');
    assert(nav.rows.has(nav.list.at(-1).key));assert(nav.rows.size<=bound+1);
    entry(t,nav.list.at(-1).key).row.focus();t.tree.scrollTop=0;t.tree.dispatch('scroll');
    assert(nav.rows.has(nav.list.at(-1).key),'The focused row stays mounted while scrolled away');checkTabStop(t);
    key(t.document.activeElement,'Home');assert.equal(t.tree.scrollTop,0);assert.equal(t.document.activeElement,entry(t,nav.model.rootKey).row);
    key(t.document.activeElement,'End');assert.equal(t.document.activeElement,entry(t,nav.list.at(-1).key).row);
    assert.equal(t.tree.scrollTop,nav.list.length*24-240,'End scrolls the navigator to the last row');
    t.state.artifactCatalogLimit=50000;t.api.renderSourceTree();
    assert.match(t.tree.children[0].textContent,/More than 50,000 artifact records/);assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'));
  }
  // Hostile, long, deep and over-limit catalogs.
  {
    const t=fixture();const hostile='<img onerror=alert(1)> & "quoted"';
    t.state.artifacts=[artifact(1,hostile),artifact(2,'https://a.invalid/'+Array.from({length:100},(_,i)=>`d${i}`).join('/')+'/leaf.js'),artifact(3,'x'.repeat(4097)),
      artifact(4,`https://a.invalid/${'long-'.repeat(200)}.js`)];
    t.api.renderSourceTree();const nav=t.nav();
    assert(nav.list.some(value=>value.label.includes(hostile)));assert.equal(nav.model.limits.omitted,1);assert.equal(nav.model.limits.deep,1);
    assert(Math.max(...nav.list.map(value=>value.depth))<=20);assert.match(t.tree.children[0].textContent,/not listed/);assert.match(t.tree.children[0].textContent,/shortened/);
    for(const value of nav.rows.values()){assert.equal(value.row.children.length,4);assert.equal(value.raw.children.length,0,'Labels never create markup');}
    assert(entry(t,file(t,4).key).raw.textContent.length<=t.api.SOURCE_TREE_LIMITS.label);
    t.state.artifacts=Array.from({length:7000},(_,i)=>artifact(i,`https://a${i}.invalid/${Array.from({length:16},(_,j)=>`p${j}`).join('/')}/leaf.js`));t.api.renderSourceTree();
    assert(nav.model.limits.omitted>0);assert.match(t.tree.children[0].textContent,/node limit/);
    t.state.artifacts=[artifact(1),artifact(1)];t.api.renderSourceTree();assert.equal(nav.model.limits.ambiguous,1);assert.match(t.tree.children[0].textContent,/ambiguous/);
    assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'),'An ambiguous identity cannot claim a selected document');
    t.state.artifacts=[artifact(1),{...artifact(1),session_id:'99'}];t.api.renderSourceTree();
    assert.equal(nav.list.filter(value=>value.kind==='file').length,2,'Reused IDs in distinct sessions stay separate');
    assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'));
    t.state.artifacts=[artifact(1),{...artifact(1,'x'.repeat(4097)),session_id:'99'}];t.api.renderSourceTree();
    assert.equal(nav.model.limits.omitted,1);assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'),'An omitted raw-catalog collision must not create a false selection');
  }
  {
    const t=fixture([artifact(1,'https://a.invalid/a//nested/first.js'),artifact(2,'https://a.invalid/a/nested/second.js'),artifact(3,'https://a.invalid//a/nested/third.js')]);
    t.api.renderSourceTree();const nav=t.nav();
    const files=[...nav.model.files.values()];
    assert.equal(new Set(files.map(value=>value.parent)).size,3,'Interior and leading empty path segments must not alias');
    assert(nav.list.some(value=>value.label.includes('(empty path segment)')));
    t.api.sourceTreeView.toggle(file(t,1).parent,false);
    assert(!file(t,1));assert(file(t,2));assert(file(t,3));
  }
  {
    const t=fixture([{...artifact(5,'https://accounts.hcaptcha.com/hcaptcha.html'),kind:'wasm',mime_type:'application/wasm',capture_origin:'webassembly_instantiate',execution_context_id:'1'}]);
    t.api.renderSourceTree();
    assert.equal(file(t,5).label,'wasm webassembly instantiate');
    t.state.artifacts=[{...artifact(6,'https://cdn.invalid/path/Module.WASM'),kind:'wasm',capture_origin:'webassembly_instantiate',execution_context_id:'1'}];t.api.renderSourceTree();
    assert.equal(file(t,6).label,'Module.WASM');
    t.state.artifacts=[artifact(7,'https://accounts.hcaptcha.com/hcaptcha.html',{capture_origin:'dynamic_javascript',execution_context_id:'1'}),artifact(8,'https://accounts.hcaptcha.com/hcaptcha.html')];
    t.api.renderSourceTree();
    same([file(t,7).label,file(t,8).label],['VM7','hcaptcha.html']);
  }
  console.log(`PASS Sources navigator model and inert DOM: frames then Workers/Dynamic/WebAssembly/Extensions/Browser internals, hand-parsed non-special URLs, Console frame names, plain labels with meta IDs and duplicate suffixes, compact folder chains, typed icons, keyed refresh/focus/scroll anchoring, arrows/Home/End/type-ahead, filter and expand/collapse all, 20,000 sources reachable with one window mounted (model ${timing.toFixed(0)} ms), hostile/deep/limit catalogs (not rendered QA)`);
}
