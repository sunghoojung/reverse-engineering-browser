import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Authored HTTP catalogs and inert source bytes. The rendered checks below do
// not call product selection/refresh/render functions or substitute their state.
export async function sourcesTreeFixture(base) {
  base.artifacts.splice(0);base.documents.clear();
  const text=Array.from({length:160},(_,i)=>`// tree needle ${i}: ${'retained text '.repeat(12)}`).join('\n');
  const target=await base.addSource('100',text);target.url='https://a.tree.invalid/shared/nested/entry.js';
  const other=await base.addSource('101','// same folder at another origin');other.url='https://b.tree.invalid/shared/nested/entry.js';
  const sibling=await base.addSource('102','// selected branch sibling');sibling.url='https://a.tree.invalid/shared/sibling.js';
  const hostile=await base.addSource('103','// inert malformed URL label');hostile.url='<img src=x onerror="globalThis.__sourceTreeExecuted=true">';
  const long=await base.addSource('104','// bounded long label');long.url=`https://a.tree.invalid/${'long-label-'.repeat(90)}.js`;
  const deep=await base.addSource('105','// bounded deep path');deep.url=`https://a.tree.invalid/${Array.from({length:80},(_,i)=>`deep-${i}`).join('/')}/entry.js`;
  for(let i=0;i<48;i++){
    const source=await base.addSource(String(2000+i),`// navigator ${i}`);
    source.url=`https://z.tree.invalid/scroll/file-${String(i).padStart(2,'0')}.js`;
  }
  const live=base.addLiveSource('tree-live',text);live.url=target.url;
  const liveOther=base.addLiveSource('tree-other','// separate live origin');liveOther.url=other.url;
  const liveSibling=base.addLiveSource('tree-sibling','// live sibling');liveSibling.url=sibling.url;
  for(let i=0;i<48;i++){const source=base.addLiveSource(`tree-nav-${String(i).padStart(2,'0')}`,`// live navigator ${i}`);source.url=`https://z.tree.invalid/scroll/file-${String(i).padStart(2,'0')}.js`;}
  const fixture={...base,target,other,sibling,hostile,long,deep,live,text,catalogs:{artifacts:0,debugger:0}};
  fixture.handle=async(request,response)=>{
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(path==='/api/events'){
      // A genuinely empty live catalog must clear the UI; demo mode deliberately
      // preserves previous demo evidence when the catalog becomes empty.
      response.writeHead(200,{'Content-Type':'application/json'});
      response.end(JSON.stringify({count:0,events:[],capture_mode:'live',broker_connected:false,capture_controls_available:false}));return true;
    }
    if(path==='/api/artifacts')fixture.catalogs.artifacts++;
    if(path==='/api/debugger')fixture.catalogs.debugger++;
    return base.handle(request,response);
  };
  return fixture;
}

export async function checkSourcesTreeFixture(base,root) {
  const fixture=await sourcesTreeFixture(base);
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isArtifactResponse,isDebuggerResponse})',{TextEncoder});
  const request=async url=>{
    const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
    assert(await fixture.handle({url,method:'GET'},response));assert.equal(response.status,200);return response;
  };
  assert(model.isBrokerResponse(JSON.parse((await request('/api/events')).body)));
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  assert(model.isDebuggerResponse(JSON.parse((await request('/api/debugger')).body)));
  assert.equal((await request('/api/artifacts/100/content')).body.toString('utf8'),fixture.text);
  assert.equal(JSON.parse((await request('/api/debugger/source?script_id=tree-live')).body).source,fixture.text);
  assert.equal(fixture.target.url,fixture.live.url);
  assert.equal(new URL(fixture.target.url).pathname,new URL(fixture.other.url).pathname);
  const payloadBytes=fixture.artifacts.reduce((sum,row)=>sum+row.byte_size,0)+[...fixture.liveDocuments.values()].reduce((sum,row)=>sum+Buffer.byteLength(row.text),0);
  assert(fixture.artifacts.length<64&&fixture.debuggerState.scripts.length<64&&payloadBytes<64*1024,'Tree catalogs and total authored source bytes must remain bounded');
  fixture.artifacts.reverse();assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  fixture.artifacts.splice(0);assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  const canvas=await fixture.addSource('4000','data:image/png;base64,');
  Object.assign(canvas,{kind:'canvas_data_url',capture_origin:'canvas_to_data_url',execution_context_id:'0',sensitive:true,mime_type:'text/plain',url:'https://canvas.tree.invalid/filtered'});
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)),'Filtered canvas-only catalog must still pass the real HTTP validator');
  assert.equal(fixture.rejectedWrites.length,0);fixture.release();
  console.log('PASS Sources-tree HTTP fixture: admitted live/captured catalogs, scoped same-path sources, inert hostile/deep/long labels, bounded bytes, reorder and empty catalog (not rendered QA)');
}

export async function checkSourcesTreeInteractions({evaluate,viewport,click:nativeClick,key:nativeKey,wheel,typeText,screenshot,accessibilitySnapshot,fixture,record=()=>{}}) {
  const receipts=[],inputs=[];
  const until=async(predicate,label)=>{
    const deadline=Date.now()+7000;
    do{if(await(typeof predicate==='string'?evaluate(predicate):predicate()))return;await new Promise(resolve=>setTimeout(resolve,25));}while(Date.now()<deadline);
    assert.fail(label);
  };
  const frames=()=>evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const input=value=>{inputs.push(value);assert(inputs.length<=1024,'Native input receipt bound exceeded');};
  const click=async selector=>{await nativeClick(selector);input({type:'pointer',selector});await frames();};
  const press=async(value,modifiers=0)=>{
    const code=value===' '?'Space':value;
    await nativeKey(value,code,{windowsVirtualKeyCode:({ArrowLeft:37,ArrowUp:38,ArrowRight:39,ArrowDown:40,Home:36,End:35,Enter:13,' ':32,Tab:9,Escape:27})[value],modifiers,
      ...(['Enter',' '].includes(value)?{text:value==='Enter'?'\r':' ',unmodifiedText:value==='Enter'?'\r':' '}:{})});
    input({type:'key',key:value,code,modifiers});await frames();
  };
  const rows=()=>evaluate(`Array.from(elements.sourceTree.querySelectorAll('.source-tree-row')).filter(row=>row.getClientRects().length).map(row=>({key:row.dataset.sourceTreeKey,kind:row.dataset.sourceTreeKind,artifact:row.dataset.artifactId??null,script:row.dataset.scriptId??null,label:row.querySelector('.source-tree-name').textContent,level:Number(row.getAttribute('aria-level')),expanded:row.getAttribute('aria-expanded'),selected:row.getAttribute('aria-selected'),tabIndex:row.tabIndex,tag:row.tagName,role:row.getAttribute('role')}))`);
  const focused=()=>evaluate("document.activeElement.closest('#source-tree .source-tree-row')?.dataset.sourceTreeKey??null");
  const focusVisible=()=>evaluate("(()=>{const r=document.activeElement.getBoundingClientRect(),p=elements.sourceTree.getBoundingClientRect();return r.top>=p.top-1&&r.bottom<=p.bottom+1&&r.left>=p.left-1&&r.right<=p.right+1;})()");
  const anchor=()=>evaluate("(()=>{const pane=elements.sourceTree,p=pane.getBoundingClientRect(),row=[...pane.querySelectorAll('.source-tree-row')].find(value=>value.getBoundingClientRect().bottom>p.top+1);return row?{key:row.dataset.sourceTreeKey,offset:row.getBoundingClientRect().top-p.top}:null;})()");
  const sameAnchor=(before,after)=>{assert.equal(after?.key,before?.key,'A refresh must retain the first visible tree row');assert(Math.abs(after.offset-before.offset)<=1,'A refresh must retain the visible row offset');};
  const selector=key=>`#source-tree [data-source-tree-key=${JSON.stringify(key)}]`;
  const reads=()=>({captured:fixture.previewRequests.length,live:fixture.liveRequests.length,facts:fixture.requests.length,analysis:fixture.analysisRequests.length});
  const editor=()=>evaluate(`({identity:sourceIdentity(selectedSource()),artifact:state.selectedArtifactId,script:state.selectedScriptId,representation:state.sourceEditorView?.representation,flags:{formatted:state.sourceFormatted,deobfuscated:state.sourceDeobfuscated,wasm:state.sourceWasm},window:state.sourceEditorView?{start:state.sourceEditorView.window.start,end:state.sourceEditorView.window.end,line:state.sourceEditorView.window.line,column:state.sourceEditorView.window.column}:null,savedWindow:state.sourceWindow,cursor:state.sourceCursor,position:elements.sourcePosition.textContent,search:elements.sourceSearch.value,searchIndex:state.sourceSearchIndex,top:elements.sourceCodeWrap.scrollTop,left:elements.sourceCodeWrap.scrollLeft,content:elements.sourceCode.textContent})`);
  const summary=value=>{const {content,...rest}=value;return {...rest,renderedCharacters:content.length};};
  const addReceipt=(label,value)=>{const result={label,...value};receipts.push(result);record(result);};
  const accessibility=async(expanded,label)=>{
    // Chrome's accessibility tree verifies aria-owns reparenting, not merely
    // matching DOM attributes. Four bounded read-only snapshots cover initial
    // hierarchy and one collapsed root at each accepted viewport.
    const {nodes}=await accessibilitySnapshot(),byId=new Map(nodes.map(node=>[node.nodeId,node]));
    const role=node=>node?.role?.value,property=(node,name)=>node.properties?.find(value=>value.name===name)?.value?.value;
    const tree=nodes.find(node=>!node.ignored&&role(node)==='tree'&&node.name?.value==='Captured');
    assert(tree,'Chrome AX must expose the labeled Captured tree');
    const descendants=node=>{const found=[],pending=[...(node.childIds??[])],seen=new Set();while(pending.length){const id=pending.pop();if(seen.has(id))continue;seen.add(id);const child=byId.get(id);if(!child)continue;found.push(child);pending.push(...(child.childIds??[]));}return found;};
    const top=descendants(tree).find(node=>!node.ignored&&role(node)==='treeitem'&&node.name?.value==='top');
    assert(top,'Chrome AX must expose the top treeitem');assert.equal(property(top,'expanded'),expanded);
    assert.equal(property(top,'level'),1);
    const children=descendants(top).filter(node=>!node.ignored),items=children.filter(node=>role(node)==='treeitem');
    if(expanded){
      const group=(top.childIds??[]).map(id=>byId.get(id)).find(node=>!node?.ignored&&role(node)==='group');
      assert(group,'aria-owns must put the adjacent group under its branch in Chrome AX');
      const origin=descendants(group).find(node=>!node.ignored&&role(node)==='treeitem'&&node.name?.value==='a.tree.invalid');
      assert(origin,'Owned group must expose its origin treeitem');assert.equal(property(origin,'level'),2);
      assert((origin.childIds??[]).map(id=>byId.get(id)).some(node=>!node?.ignored&&role(node)==='group'),'Origin must own its nested path group');
      assert(items.length>3,'Expanded Chrome AX tree must expose real descendants');
    }else assert.equal(items.length,0,'Collapsed Chrome AX branch must not expose descendant treeitems');
    addReceipt(label,{expanded,treeRole:role(tree),rootRole:role(top),level:property(top,'level'),descendantTreeitems:items.length});
  };
  const treeClick=async target=>{
    // Move only the real bounded navigator with native wheel input, then let
    // the shared driver enforce its unchanged full visibility/hit-test checks.
    const delta=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(target)}),pane=elements.sourceTree;if(!node)throw Error('Missing Sources-tree control: '+${JSON.stringify(target)});const r=node.getBoundingClientRect(),b=pane.getBoundingClientRect();return r.top<b.top+3?r.top-b.top-3:r.bottom>b.bottom-3?r.bottom-b.bottom+3:0;})()`);
    if(delta){await wheel('#source-tree',delta);input({type:'wheel',selector:'#source-tree',delta});}
    await click(target);
  };
  const ancestors=(all,key)=>{
    const stack=[];
    for(const row of all){while(stack.length&&stack.at(-1).level>=row.level)stack.pop();if(row.key===key)return stack.slice();stack.push(row);}
    assert.fail('Missing row ancestry: '+key);
  };
  const invariant=async()=>{
    const all=await rows();assert.equal(new Set(all.map(row=>row.key)).size,all.length,'Visible rows need distinct stable scoped keys');
    for(const row of all){assert(row.key);assert.equal(row.tag,'BUTTON');assert.equal(row.role,'treeitem');assert(row.level>=1);assert([-1,0].includes(row.tabIndex));
      if(['root','origin','folder'].includes(row.kind))assert(['true','false'].includes(row.expanded));
      else {assert.equal(row.expanded,null,'Files are not expandable branches');assert(['true','false'].includes(row.selected));}}
    assert.equal(all.filter(row=>row.tabIndex===0).length,all.length?1:0,'Exactly one visible row is a native Tab stop');
    assert.equal(await evaluate('elements.sourceTree.tabIndex'),all.length?-1:0,'Only an empty tree itself is a Tab stop');return all;
  };
  const focusIs=async key=>{assert.equal(await focused(),key);await invariant();};
  const expand=async key=>{const row=(await rows()).find(value=>value.key===key);assert(row,'Branch was not visible');if(row.expanded==='false')await treeClick(selector(key));assert.equal((await rows()).find(value=>value.key===key)?.expanded,'true');};
  const selectedReady=async(kind,id)=>until(`${kind==='script'?`state.selectedScriptId===${JSON.stringify(id)}`:`state.selectedScriptId===null&&state.selectedArtifactId===${JSON.stringify(id)}`}&&selectedSource()?.content!==undefined&&!selectedSource().loading`,'Source preview did not finish: '+id);
  const collection=async kind=>{await click(`#source-tab-${kind}`);await until(`state.sourceCollection===${JSON.stringify(kind)}`,'Collection did not switch');await invariant();};
  const unchanged=async(before,count,label)=>{assert.deepEqual(await editor(),before,label+' changed the selected editor or logical position');assert.deepEqual(reads(),count,label+' fetched or analyzed source content');};
  const geometry=()=>evaluate(`(()=>{const box=node=>{const r=node.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};const tree=elements.sourceTree,active=document.activeElement,style=getComputedStyle(active);return {viewport:[innerWidth,innerHeight],tree:box(tree),editor:box(elements.sourceCodeWrap),documentWidth:document.documentElement.scrollWidth,treeWidth:tree.scrollWidth,treeClientWidth:tree.clientWidth,focus:{key:active.dataset.sourceTreeKey??null,visible:active.matches(':focus-visible'),outline:style.outlineStyle,outlineWidth:parseFloat(style.outlineWidth)},rows:tree.querySelectorAll('.source-tree-row').length};})()`);
  await until("state.artifacts.some(row=>row.artifact_id==='100')&&state.debuggerSession?.scripts.some(row=>row.script_id==='tree-live')",'Sources-tree fixture catalogs did not load');
  await click('.nav-button[data-screen="sources"]');
  await until("investigationScreen()==='sources'",'Sources workspace did not open');
  const initial=await invariant();assert(initial.filter(row=>['root','origin','folder'].includes(row.kind)).every(row=>row.expanded==='true'),'Every new branch defaults to expanded');
  await accessibility(true,'chrome-ax-expanded-hierarchy');
  assert(await evaluate("elements.sourceTree.querySelectorAll('img,script,iframe,svg').length===0&&globalThis.__sourceTreeExecuted===undefined"),'Captured labels must remain inert');
  assert((await rows()).some(row=>row.artifact==='103'&&row.label.includes('<img')),'Hostile URL must remain readable inert text');
  assert.match(await evaluate("elements.sourceTree.querySelector('[role=status]').textContent"),/paths are shortened after 16 folders/,'Deep-path bounds must be disclosed in the rendered tree');
  assert((await rows()).find(row=>row.artifact==='104').label.length<=512,'Long labels must be bounded');
  assert.equal(await evaluate("elements.sourceTree.querySelector('[data-artifact-id=\"104\"] .source-tree-name').title"),fixture.long.url,'Long-source tooltip must retain its exact URL');

  for(const size of [[1440,900],[760,560],[360,740]]){
    await viewport(...size);
    if(await evaluate("getComputedStyle(elements.sourceSidebar).position==='absolute'&&!elements.sourceSidebar.hidden"))await click('#source-sidebar-toggle');
    await collection('captured');
    // A previous width leaves the root expanded; explicit source reveal below
    // therefore exercises real navigator scrolling, including the phone layout.
    let all=await rows();await expand(all[0].key);
    for(const branch of all.filter(row=>row.expanded==='false'))await expand(branch.key);
    await treeClick('#source-tree [data-artifact-id="100"]');await selectedReady('artifact','100');
    all=await invariant();const leaf=all.find(row=>row.artifact==='100'),path=ancestors(all,leaf.key),folder=path.at(-1),shared=path.find(row=>row.label==='shared');
    assert(folder?.kind==='folder'&&shared,'Nested fixture path must create real folders');
    const otherLeaf=all.find(row=>row.artifact==='101'),otherShared=ancestors(all,otherLeaf.key).find(row=>row.label==='shared');
    assert.notEqual(shared.key,otherShared.key,'Same-name folders at different origins must be independent');
    if(size[0]===1440){
      await click('#source-search');await typeText('needle');await press('Enter');await press('Enter');
      assert.equal((await rows()).length,all.length,'Find in source must not filter the navigator');
      await wheel('#source-code-wrap',240);input({type:'wheel',selector:'#source-code-wrap',delta:240});
    }
    const before=await editor(),beforeReads=reads();
    await treeClick(selector(shared.key));
    assert.equal((await rows()).find(row=>row.key===shared.key)?.expanded,'false');
    assert(!(await rows()).some(row=>row.key===leaf.key),'Collapsed descendants must leave the visible tree');
    assert((await rows()).some(row=>row.artifact==='101'),'Collapsing one origin must retain the other origin');
    await unchanged(before,beforeReads,'Pointer branch collapse');await focusIs(shared.key);
    await screenshot(`sources-tree-${size[0]}-selected-hidden`);
    await press('Enter');assert.equal((await rows()).find(row=>row.key===shared.key)?.expanded,'true','Native Enter must toggle once');
    await press(' ');assert.equal((await rows()).find(row=>row.key===shared.key)?.expanded,'false','Native Space must toggle once');
    await press('ArrowRight');assert.equal((await rows()).find(row=>row.key===shared.key)?.expanded,'true');await focusIs(shared.key);
    await press('ArrowRight');await focusIs(folder.key);
    await press('ArrowLeft');assert.equal((await rows()).find(row=>row.key===folder.key)?.expanded,'false');await focusIs(folder.key);
    await press('ArrowLeft');await focusIs(shared.key);
    await press('ArrowRight');await focusIs(folder.key);
    await press('ArrowRight');assert.equal((await rows()).find(row=>row.key===folder.key)?.expanded,'true');await focusIs(folder.key);
    await press('ArrowRight');await focusIs(leaf.key);
    await press('ArrowLeft');await focusIs(folder.key);
    await press('Home');await focusIs((await rows())[0].key);
    await press('ArrowUp');await focusIs((await rows())[0].key);
    await press('End');const last=(await rows()).at(-1).key;await focusIs(last);
    await press('ArrowDown');await focusIs(last);
    await press('ArrowUp');await focusIs((await rows()).at(-2).key);
    await press('ArrowDown');await focusIs(last);
    // Modified arrows must not run the navigator's unmodified-key handler.
    await press('ArrowUp',8);await focusIs(last);
    await press('ArrowUp',2);await focusIs(last);
    await unchanged(before,beforeReads,'Keyboard tree navigation');
    await screenshot(`sources-tree-${size[0]}-keyboard-end`);
    await press('Home');await press('ArrowLeft');assert.equal((await rows()).length,1,'Root collapse must hide every descendant');
    await unchanged(before,beforeReads,'Root collapse');
    await accessibility(false,`chrome-ax-${size[0]}-collapsed`);
    await press('ArrowRight');await focusIs((await rows())[0].key);
    await press('Tab',8);assert.equal(await evaluate('document.activeElement.id'),'source-tab-captured','Shift+Tab must leave the roving tree for its collection tab');
    await press('Tab');await focusIs((await rows())[0].key);
    await press('Tab');assert.equal(await evaluate('elements.sourceTree.contains(document.activeElement)'),false,'One Tab must exit the whole tree');
    await press('Tab',8);await focusIs((await rows())[0].key);
    const measured=await geometry();assert(measured.documentWidth<=size[0],'Sources tree must not overflow the viewport');
    assert(measured.tree.width>=120&&measured.editor.width>=120&&measured.editor.height>=80,'Navigator and source editor must both remain usable');
    assert(measured.treeWidth<=measured.treeClientWidth+1,'Long/deep paths must not create a horizontal navigator scroll');
    assert(measured.focus.visible&&measured.focus.outline!=='none'&&measured.focus.outlineWidth>0,'Native keyboard focus must remain visible');
    await screenshot(`sources-tree-${size[0]}-expanded`);
    addReceipt(`${size[0]}-collapse-keyboard`,{viewport:size,before:summary(before),after:summary(await editor()),reads:reads(),geometry:measured,nativeInputs:inputs.length});
  }

  await viewport(1440,900);await collection('captured');
  let all=await rows(),target=all.find(row=>row.artifact==='100'),capturedShared=ancestors(all,target.key).find(row=>row.label==='shared');
  await treeClick(selector(capturedShared.key));assert.equal((await rows()).find(row=>row.key===capturedShared.key)?.expanded,'false');
  await collection('page');await selectedReady('script','tree-live');
  all=await rows();const liveLeaf=all.find(row=>row.script==='tree-live'),liveShared=ancestors(all,liveLeaf.key).find(row=>row.label==='shared');
  assert.notEqual(liveShared.key,capturedShared.key,'Page and Captured branch keys must be disjoint');assert.equal(liveShared.expanded,'true');
  const liveEditor=await editor(),liveReads=reads();await treeClick(selector(liveShared.key));await unchanged(liveEditor,liveReads,'Live branch collapse');
  await collection('captured');assert.equal((await rows()).find(row=>row.key===capturedShared.key)?.expanded,'false','Captured collapse must survive a Page visit');
  await expand(capturedShared.key);await collection('page');assert.equal((await rows()).find(row=>row.key===liveShared.key)?.expanded,'false','Captured expansion must not expand the Page branch');
  await expand(liveShared.key);await collection('captured');await treeClick('#source-tree [data-artifact-id="100"]');await selectedReady('artifact','100');
  addReceipt('scoped-branches',{captured:capturedShared.key,page:liveShared.key,reads:reads()});

  // A native End changes focus only. Keep the selected preview in another
  // branch while background catalog refreshes add, reorder and remove rows.
  await press('End');all=await rows();const end=all.at(-1),endParent=ancestors(all,end.key).at(-1),savedEditor=await editor(),savedReads=reads();
  assert.equal(end.artifact,'2047');const scroll=await evaluate('elements.sourceTree.scrollTop');assert(scroll>0);
  const unchangedCatalog=fixture.catalogs.artifacts;await until(()=>fixture.catalogs.artifacts>unchangedCatalog,'No ordinary catalog poll was observed');await frames();
  await focusIs(end.key);assert.equal(await evaluate('elements.sourceTree.scrollTop'),scroll,'Unchanged refresh moved the navigator');
  const keys=all.map(row=>row.key);fixture.artifacts.reverse();
  await until("state.artifacts[0]?.artifact_id==='2047'",'Reordered HTTP catalog was not admitted');
  assert.deepEqual((await rows()).map(row=>row.key),keys,'HTTP catalog order must not reorder logical branches');await focusIs(end.key);
  assert.equal(await evaluate('elements.sourceTree.scrollTop'),scroll,'Reorder moved the navigator');
  const added=await fixture.addSource('3000','// added below the retained focus');added.url='https://z.tree.invalid/scroll/zz-added.js';
  await until("state.artifacts.some(row=>row.artifact_id==='3000')",'Added HTTP catalog row was not admitted');await focusIs(end.key);
  assert.equal(await evaluate('elements.sourceTree.scrollTop'),scroll,'Adding a later sibling moved the navigator');await unchanged(savedEditor,savedReads,'Catalog reorder and addition');
  const capturedAnchor=await anchor(),preceding=await fixture.addSource('3002','// inserted before the visible captured window');preceding.url='https://z.tree.invalid/scroll/aaa-preceding.js';
  await until("state.artifacts.some(row=>row.artifact_id==='3002')",'Earlier captured sibling was not admitted');await focusIs(end.key);sameAnchor(capturedAnchor,await anchor());await unchanged(savedEditor,savedReads,'Catalog insertion above visible rows');
  fixture.artifacts.splice(fixture.artifacts.findIndex(row=>row.artifact_id==='2047'),1);
  await until("!state.artifacts.some(row=>row.artifact_id==='2047')",'Removed HTTP catalog row was not admitted');
  await focusIs(endParent.key);assert(await evaluate('document.activeElement.isConnected'),'Removed focused row needs a connected fallback');assert(await focusVisible(),'Removed focused row must reveal its surviving ancestor inside the navigator');await unchanged(savedEditor,savedReads,'Focused row removal');
  await screenshot('sources-tree-refresh-focus-fallback');
  await click('#source-search');const searchFocus=await evaluate('document.activeElement.id'),typingScroll=await evaluate('elements.sourceTree.scrollTop');
  const outside=await fixture.addSource('3001','// background catalog arrival');outside.url='https://z.tree.invalid/scroll/zzz-outside-focus.js';
  await until("state.artifacts.some(row=>row.artifact_id==='3001')",'Catalog arrival during Find was not admitted');
  assert.equal(await evaluate('document.activeElement.id'),searchFocus,'Background render stole Find focus');
  assert.equal(await evaluate('elements.sourceTree.scrollTop'),typingScroll,'Background render moved the navigator while Find had focus');
  await unchanged(savedEditor,savedReads,'Background refresh outside tree');
  addReceipt('refresh-add-remove-reorder',{retainedFocus:end.key,fallback:endParent.key,scroll,typingScroll,reads:reads(),catalogs:{...fixture.catalogs}});

  // Page uses the same controller but its normal debugger catalog refresh has
  // a separate lifetime. Exercise retained scroll/focus and fallback there too.
  await collection('page');await selectedReady('script','tree-live');
  await treeClick('#source-tree [data-script-id="tree-live"]');await press('End');
  const pageRows=await rows(),pageEnd=pageRows.at(-1),pageParent=ancestors(pageRows,pageEnd.key).at(-1),pageEditor=await editor(),pageReads=reads(),pageScroll=await evaluate('elements.sourceTree.scrollTop');
  assert.equal(pageEnd.script,'tree-nav-47');assert(pageScroll>0);
  fixture.debuggerState.scripts.reverse();fixture.debuggerState.generation++;
  await until("state.debuggerSession.scripts[0]?.script_id==='tree-nav-47'",'Reordered Page HTTP catalog was not admitted');
  assert.deepEqual((await rows()).map(row=>row.key),pageRows.map(row=>row.key));await focusIs(pageEnd.key);
  assert.equal(await evaluate('elements.sourceTree.scrollTop'),pageScroll,'Reordered Page catalog moved the navigator');
  const pageAnchor=await anchor(),pageAdded=fixture.addLiveSource('tree-before','// inserted before the live visible window');pageAdded.url='https://z.tree.invalid/scroll/aaa-preceding.js';
  await until("state.debuggerSession.scripts.some(row=>row.script_id==='tree-before')",'Added Page HTTP catalog row was not admitted');await focusIs(pageEnd.key);sameAnchor(pageAnchor,await anchor());
  fixture.debuggerState.scripts=fixture.debuggerState.scripts.filter(row=>row.script_id!=='tree-nav-47');fixture.debuggerState.generation++;
  await until("!state.debuggerSession.scripts.some(row=>row.script_id==='tree-nav-47')",'Removed Page HTTP catalog row was not admitted');
  await focusIs(pageParent.key);assert(await focusVisible(),'Removed Page focus must reveal its surviving ancestor');await unchanged(pageEditor,pageReads,'Page catalog changes');
  await screenshot('sources-tree-page-refresh-focus-fallback');
  addReceipt('page-refresh-add-remove-reorder',{retainedFocus:pageEnd.key,fallback:pageParent.key,scroll:pageScroll,anchor:pageAnchor,reads:reads(),catalogs:{...fixture.catalogs}});
  await collection('captured');

  // Activate two previously unread leaves through native Enter and Space.
  // Arrow movement must remain passive; each explicit activation reads once.
  await treeClick(selector(endParent.key));
  if((await rows()).find(row=>row.key===endParent.key)?.expanded==='false')await press('ArrowRight');
  await press('End');
  for(const activation of ['Enter',' ']){
    const focusedKey=await focused(),current=(await rows()).find(row=>row.key===focusedKey);
    assert(current?.artifact&&current.artifact!=='100','Keyboard activation needs a different file');
    const before=fixture.previewRequests.filter(id=>id===current.artifact).length;
    assert.equal(before,0,'Keyboard activation fixture must start unread');
    await press(activation);await selectedReady('artifact',current.artifact);
    assert.equal(fixture.previewRequests.filter(id=>id===current.artifact).length,1,'Native file activation must issue one source read');
    await focusIs(focusedKey);await press('ArrowUp');
  }
  await screenshot('sources-tree-native-file-activation');

  // The only catalog item is intentionally excluded from Sources. It must not
  // create a phantom root or a stale Tab stop; the truly empty catalog follows.
  const canvas=await fixture.addSource('4000','data:image/png;base64,');
  Object.assign(canvas,{kind:'canvas_data_url',capture_origin:'canvas_to_data_url',execution_context_id:'0',sensitive:true,mime_type:'text/plain',url:'https://canvas.tree.invalid/filtered'});
  fixture.artifacts.splice(0,fixture.artifacts.length,canvas);
  await until("state.artifacts.length===1&&state.artifacts[0].artifact_id==='4000'",'Canvas-only filtered catalog was not admitted');
  assert.equal((await invariant()).length,0);assert.match(await evaluate('elements.sourceTree.textContent'),/No source artifacts captured/);
  assert.equal(await evaluate('document.activeElement===elements.sourceTree'),true,'An empty filtered tree must retain native focus on its container');
  await screenshot('sources-tree-filtered-empty');
  fixture.artifacts.splice(0);await until('state.artifacts.length===0','Empty live HTTP catalog did not clear retained rows');
  assert.equal((await invariant()).length,0);assert.match(await evaluate('elements.sourceTree.textContent'),/No source artifacts captured/);
  fixture.debuggerState.scripts=[];fixture.debuggerState.generation++;
  await until('state.debuggerSession.scripts.length===0','Empty Page catalog was not admitted');await collection('page');
  assert.equal((await invariant()).length,0);assert.match(await evaluate('elements.sourceTree.textContent'),/No live scripts|Waiting for/);
  await press('Tab');assert.equal(await evaluate('document.activeElement===elements.sourceTree'),true,'The empty Page tree must remain keyboard reachable');
  await screenshot('sources-tree-page-empty');
  assert.equal(fixture.rejectedWrites.length,0,'Tree navigation must never execute debugger mutations');
  assert.equal(fixture.requests.length,0,'Tree navigation must not request Facts analysis');
  assert.equal(fixture.analysisRequests.length,0,'Tree navigation must not request deobfuscation');
  assert(await evaluate("elements.sourceTree.querySelectorAll('img,script,iframe,svg').length===0&&globalThis.__sourceTreeExecuted===undefined"));
  return {status:'passed',path:'existing installed-Chrome strict native pointer/key/wheel driver; production catalog refresh, renderer and selection',viewports:[[1440,900],[760,560],[360,740]],receipts,inputs,
    checks:['Chrome accessibility-tree hierarchy, owned groups and collapsed descendants','default expanded scoped origin/path branches','native pointer/Enter/Space single branch toggles and file activations','arrows/Home/End/modified arrows and one roving Tab stop','hidden selected descendant preserves editor, Find, logical view and fetch counts','Page/Captured and same-name origin isolation','refresh/add/reorder focus and scroll retention; removed focus ancestor fallback','Find focus is not stolen and does not filter the navigator','hostile/long/deep labels and bounded narrow layout','canvas-only filtered and truly empty catalogs']};
}
