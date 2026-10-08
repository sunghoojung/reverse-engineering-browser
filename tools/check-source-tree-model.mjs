import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Small inert DOM ownership model. Native activation, layout and scroll-clamping
// acceptance belong to the real browser mode, not these deterministic checks.
class TreeNode {
  constructor(tag, document) {
    this.localName=tag;this.document=document;this.children=[];this.parentElement=null;
    this.attributes=new Map();this.dataset={};this.listeners=new Map();this.style={setProperty(){}};
    this.textContent='';this.scrollTop=0;this.scrollLeft=0;this.tabIndex=-1;this.hidden=false;
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
  focus(){this.document.activeElement=this;this.dispatch('focus');}
  getBoundingClientRect(){return {top:0,bottom:24};}
}

export async function checkSourceTreeModel(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const syntax=await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8');
  const facts=await readFile(join(root,'apps/research-ui/source_facts.js'),'utf8');
  const part=(text,start,end)=>text.slice(text.indexOf(start),text.indexOf(end,text.indexOf(start)));
  const program=part(facts,'const sourceFactsFields','function sourceFactsUnavailable')+
    part(syntax,'      function sourceName(','      function formatByteSize(')+
    part(app,'      function liveScriptIdentity(','      function setSourceCursor(')+
    part(app,'      function sourceDisplayName(','      function markLiveSourceStale(')+
    part(app,'      const SOURCE_TREE_LIMITS','      function renderSourceHealth(')+
    ';({sourceTreeModel,sourceTreeVisible,renderSourceTree,toggleSourceTree,sourceTreeFocus,sourceTreeState,sourceTreeKeydown,SOURCE_TREE_LIMITS})';
  const artifact=(id,url=`https://a.invalid/shared/nested/${id}.js`)=>({source_type:'artifact',artifact_id:String(id),url,
    protocol_version:1,session_id:'1',navigation_id:'2',frame_id:'3',parent_artifact_id:'0',creator_event_id:'0',execution_context_id:'4',
    capture_origin:'dynamic_javascript',kind:'javascript',mime_type:'text/javascript',byte_size:8,sha256:'a'.repeat(64),sensitive:false});
  const fixture=()=>{
    const document={activeElement:null,created:0,createElement(tag){this.created++;return new TreeNode(tag,this);}};
    const tree=document.createElement('div');
    const state={sourceCollection:'captured',artifacts:[artifact(1),artifact(2),artifact(3,'https://b.invalid/shared/nested/3.js')],
      selectedArtifactId:'1',selectedScriptId:null,staleScriptIds:new Set(),debuggerSession:{target:{id:'page-a'},scripts:[]}};
    const calls=[];
    const api=runInNewContext(program,{URL,document,state,elements:{sourceTree:tree},
      selectArtifact:id=>calls.push(['artifact',id]),selectScript:id=>calls.push(['script',id]),renderSourceHealth:()=>calls.push(['health'])});
    return {document,tree,state,api,calls};
  };
  const rows=t=>[...t.api.sourceTreeState().rows.values()].map(value=>value.row);
  const branch=(t,label,origin='a.invalid')=>[...t.api.sourceTreeState().model.nodes.values()].find(node=>node.label===label&&node.key.includes(origin));
  const key=(t,row,value,modifiers={})=>{
    const event={key:value,prevented:false,preventDefault(){this.prevented=true;},stopPropagation(){this.stopped=true;},...modifiers};
    row.dispatch('keydown',event);return event;
  };
  const checkTabStop=t=>{
    assert.equal(rows(t).filter(row=>row.tabIndex===0).length,rows(t).length?1:0);
    assert.equal(t.tree.tabIndex,rows(t).length?-1:0);
  };
  {
    const t=fixture();t.api.renderSourceTree();const nav=t.api.sourceTreeState();
    assert.equal(nav.visible.length,10);checkTabStop(t);
    const file=nav.visible.find(node=>node.source?.artifact_id==='1');
    const selectedRow=nav.rows.get(file.key).row;
    assert.equal(selectedRow.getAttribute('aria-selected'),'true');assert.equal(selectedRow.tabIndex,0);
    for(const node of nav.visible){
      const entry=nav.rows.get(node.key);assert.equal(entry.row.getAttribute('aria-level'),String(node.depth+1));
      assert.equal(entry.row.getAttribute('aria-posinset'),String(node.position));
      assert.equal(entry.row.getAttribute('aria-setsize'),String(node.size));
      if(node.children){assert.equal(entry.row.getAttribute('aria-expanded'),'true');assert.equal(entry.row.getAttribute('aria-owns'),entry.group.id);assert.equal(entry.group.getAttribute('role'),'group');}
      else assert.equal(entry.row.getAttribute('aria-expanded'),null);
    }
    selectedRow.focus();t.tree.scrollTop=111;t.tree.scrollLeft=7;
    t.api.renderSourceTree();assert.equal(nav.rows.get(file.key).row,selectedRow);assert.equal(t.document.activeElement,selectedRow);
    assert.equal(t.tree.scrollTop,111);assert.equal(t.tree.scrollLeft,7);
    const created=t.document.created;for(let i=0;i<50;i++)t.api.renderSourceTree();
    assert.equal(t.document.created,created,'Unchanged refresh must not recreate tree rows or groups');
    const folder=branch(t,'shared'),before=JSON.stringify(t.state.artifacts);
    t.api.toggleSourceTree(folder.key,false);
    assert.equal(t.state.selectedArtifactId,'1');assert.equal(JSON.stringify(t.state.artifacts),before);assert.equal(t.calls.length,0);
    assert.equal(nav.rows.has(file.key),false);assert.equal(t.document.activeElement,nav.rows.get(folder.key).row);
    assert.equal(nav.rows.get(folder.key).row.getAttribute('aria-expanded'),'false');
    assert.equal(nav.rows.get(folder.key).group.children.length,0);checkTabStop(t);
    assert(nav.visible.some(node=>node.source?.artifact_id==='3'),'Same folder in another origin stays open');
    t.state.artifacts.push(artifact(5));t.api.renderSourceTree();
    assert.equal(nav.rows.get(folder.key).row.getAttribute('aria-expanded'),'false','Catalog arrival must not reopen a collapsed branch');
    assert.equal(nav.model.nodes.get(folder.key).count,3);assert(!nav.visible.some(node=>node.source?.artifact_id==='5'));
    t.api.toggleSourceTree(folder.key,true);assert(nav.visible.some(node=>node.key===file.key));
    assert.equal(t.document.activeElement,nav.rows.get(folder.key).row);assert.equal(t.calls.length,0);
    const focused=nav.rows.get(folder.key).row;focused.focus();
    t.state.artifacts.reverse();t.state.artifacts.push(artifact(4,'https://a.invalid/a-new/4.js'));t.api.renderSourceTree();
    assert.equal(nav.rows.get(folder.key).row,focused);assert.equal(t.document.activeElement,focused);assert.equal(t.tree.scrollTop,111);
    t.state.artifacts=t.state.artifacts.filter(source=>source.artifact_id!=='1');t.api.renderSourceTree();
    assert.equal(t.document.activeElement,focused);
    const bFile=nav.visible.find(node=>node.source?.artifact_id==='3');nav.rows.get(bFile.key).row.focus();
    t.state.artifacts=t.state.artifacts.filter(source=>source.artifact_id!=='3');t.api.renderSourceTree();
    assert.equal(t.document.activeElement,nav.rows.get(nav.model.rootKey).row,'A removed focused branch returns to its nearest surviving ancestor');
    const input=t.document.createElement('input');input.focus();t.api.renderSourceTree();assert.equal(t.document.activeElement,input);
    t.state.artifacts=[];t.api.renderSourceTree();assert.equal(rows(t).length,0);checkTabStop(t);assert.match(t.tree.children[0].textContent,/No source artifacts/);
    t.tree.focus();t.state.artifacts=[artifact(8)];t.api.renderSourceTree();assert(t.tree.contains(t.document.activeElement));checkTabStop(t);
    t.state.artifacts=[{...artifact(9),kind:'canvas_data_url'}];t.api.renderSourceTree();assert.equal(rows(t).length,0);assert.match(t.tree.children[0].textContent,/Canvas images/);
  }
  {
    const t=fixture();t.api.renderSourceTree();const nav=t.api.sourceTreeState(),root=nav.rows.get(nav.model.rootKey).row;root.focus();
    assert(key(t,root,'ArrowDown').prevented);assert.equal(t.document.activeElement.dataset.sourceTreeKind,'origin');
    assert(key(t,t.document.activeElement,'ArrowRight').prevented);assert.equal(t.document.activeElement.dataset.sourceTreeKind,'folder');
    const folderKey=t.document.activeElement.dataset.sourceTreeKey,folderRow=t.document.activeElement;
    assert(key(t,folderRow,'ArrowLeft').prevented);assert.equal(folderRow.getAttribute('aria-expanded'),'false');
    assert(key(t,folderRow,'ArrowRight').prevented);assert.equal(folderRow.getAttribute('aria-expanded'),'true');
    key(t,folderRow,'End');assert.equal(t.document.activeElement,nav.rows.get(nav.visible.at(-1).key).row);
    key(t,t.document.activeElement,'Home');assert.equal(t.document.activeElement,root);
    key(t,root,'ArrowUp');assert.equal(t.document.activeElement,root);
    for(const modifiers of [{altKey:true},{ctrlKey:true},{metaKey:true},{shiftKey:true}]){
      assert.equal(key(t,root,'ArrowLeft',modifiers).prevented,false);assert.equal(root.getAttribute('aria-expanded'),'true');
    }
    folderRow.focus();
    for(const value of ['Enter',' ']){
      const old=folderRow.getAttribute('aria-expanded');assert.equal(key(t,folderRow,value).prevented,false);
      assert.equal(folderRow.getAttribute('aria-expanded'),old,'Key handler must not duplicate native button activation');
      folderRow.dispatch('click');assert.notEqual(folderRow.getAttribute('aria-expanded'),old);
    }
    t.api.toggleSourceTree(folderKey,true);
    const file=nav.visible.find(node=>node.source?.artifact_id==='2'),row=nav.rows.get(file.key).row;
    for(const value of ['Enter',' ']){const count=t.calls.length;assert.equal(key(t,row,value).prevented,false);assert.equal(t.calls.length,count);row.dispatch('click');assert.equal(t.calls.length,count+1);}
    const stale=nav.visible.find(node=>node.source?.artifact_id==='1');const staleRow=nav.rows.get(stale.key).row;
    t.state.artifacts[0]={...t.state.artifacts[0],sha256:'b'.repeat(64)};staleRow.dispatch('click');assert.equal(t.calls.at(-1)[0],'health');
  }
  {
    const t=fixture();t.api.renderSourceTree();const captured=branch(t,'shared');t.api.toggleSourceTree(captured.key,false);
    t.state.debuggerSession.scripts=[{script_id:'live1',url:'https://a.invalid/shared/nested/1.js',hash:'v1',language:'JavaScript',length:8,execution_context_id:4}];
    t.state.sourceCollection='page';t.api.renderSourceTree();const live=branch(t,'shared');assert.notEqual(live.key,captured.key);
    assert.equal(t.api.sourceTreeState().rows.get(live.key).row.getAttribute('aria-expanded'),'true');
    t.state.sourceCollection='captured';t.api.renderSourceTree();assert.equal(t.api.sourceTreeState().rows.get(captured.key).row.getAttribute('aria-expanded'),'false');
    t.state.sourceCollection='page';t.state.staleScriptIds.add('live1');t.api.renderSourceTree();assert.equal(rows(t).length,0);assert.match(t.tree.children[0].textContent,/Detached/);
  }
  {
    const t=fixture();const hostile='<img onerror=alert(1)> & "quoted"';
    t.state.artifacts=[artifact(1,hostile),artifact(2,'https://a.invalid/'+Array.from({length:100},(_,i)=>`d${i}`).join('/')+'/leaf.js'),artifact(3,'x'.repeat(4097))];
    t.api.renderSourceTree();const nav=t.api.sourceTreeState();
    assert(nav.visible.some(node=>node.label.includes(hostile)));assert.equal(nav.model.limits.omitted,1);assert.equal(nav.model.limits.deep,1);
    assert(Math.max(...nav.visible.map(node=>node.depth))<=18);assert.match(t.tree.children[0].textContent,/not listed/);assert.match(t.tree.children[0].textContent,/shortened/);
    for(const entry of nav.rows.values())assert.equal(entry.row.children.length,3,'Labels never create markup');
    t.state.artifacts=Array.from({length:6000},(_,i)=>artifact(i,`https://a.invalid/${i}.js`));t.api.renderSourceTree();
    assert.equal(nav.model.limits.catalog,1000);assert.equal(nav.visible.length,1000);assert.equal(nav.rows.size,1000);
    assert.match(t.tree.children[0].textContent,/first 5,000/);assert.match(t.tree.children[0].textContent,/first 1,000 expanded rows/);checkTabStop(t);
    t.api.toggleSourceTree(nav.model.rootKey,false);assert.equal(nav.rows.size,1);assert.equal(nav.visible.length,1);
    t.state.artifacts=Array.from({length:5000},(_,i)=>artifact(i,`https://a${i}.invalid/${Array.from({length:16},(_,j)=>`p${j}`).join('/')}/leaf.js`));t.api.renderSourceTree();
    assert(nav.model.nodes.size<=t.api.SOURCE_TREE_LIMITS.nodes);
    assert(nav.model.limits.omitted>0);assert.match(t.tree.children[0].textContent,/node limit/);
    t.state.artifacts=[artifact(1),artifact(1)];t.api.renderSourceTree();t.api.toggleSourceTree(nav.model.rootKey,true);assert.equal(nav.model.limits.ambiguous,1);assert.match(t.tree.children[0].textContent,/ambiguous/);
    assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'),'An ambiguous identity cannot claim a selected document');
    t.state.artifacts=[artifact(1),{...artifact(1),session_id:'99'}];t.api.renderSourceTree();
    assert.equal(nav.visible.filter(node=>node.kind==='file').length,2,'Reused IDs in distinct sessions stay separate');
    assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'));
    t.state.artifacts=[artifact(1),{...artifact(1,'x'.repeat(4097)),session_id:'99'}];t.api.renderSourceTree();
    assert.equal(nav.model.limits.omitted,1);assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'),'An omitted raw-catalog collision must not create a false selection');
    t.state.artifacts=Array.from({length:5001},(_,i)=>artifact(i));t.api.renderSourceTree();
    assert(rows(t).every(row=>row.getAttribute('aria-selected')!=='true'),'A capped catalog cannot prove source uniqueness');
  }
  {
    const t=fixture();t.state.artifacts=[artifact(1,'https://a.invalid/a//nested/first.js'),artifact(2,'https://a.invalid/a/nested/second.js'),artifact(3,'https://a.invalid//a/nested/third.js')];
    t.api.renderSourceTree();const nav=t.api.sourceTreeState();
    const files=[...nav.model.nodes.values()].filter(node=>node.kind==='file');
    assert.equal(new Set(files.map(node=>node.parent)).size,3,'Interior and leading empty path segments must not alias');
    assert(nav.visible.some(node=>node.label==='(empty path segment)'));
    t.api.toggleSourceTree(files.find(node=>node.source.artifact_id==='1').parent,false);
    assert(!nav.visible.some(node=>node.source?.artifact_id==='1'));
    assert(nav.visible.some(node=>node.source?.artifact_id==='2'));assert(nav.visible.some(node=>node.source?.artifact_id==='3'));
  }
  console.log('PASS Sources navigator bounded model and inert DOM: exact scoped paths, hierarchy, keyed refresh/focus/scroll, collapse without source actions, arrows/native activation separation, empty/filtered/hostile/deep/large catalogs (not rendered QA)');
}
