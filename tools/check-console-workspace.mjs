// Original scripted native replies. These fixtures never execute page JavaScript.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

export function createConsoleFixture() {
  const fixture = {session:null, sequence:10, target:'101', calls:[], messages:[], pending:[], inspectMode:'ok', stateMode:'ok', pollMode:'ok', propertyCount:48, request:0, receipts:[], receiptSequence:0, errors:[]};
  const value = (type,text,handle) => ({type,text,truncated:false,...(handle?{handle}:{})});
  const state = () => ({contract_version:2,state:fixture.session?'ready':'idle',session_id:fixture.session,available:true});
  const targets = () => [{id:fixture.target,origin:'https://fixture.invalid',label:'Console workbench fixture',url:'https://fixture.invalid/console',main_frame:true,truncated:false}];
  fixture.respond = async (path, action) => {
    if (path === '/api/native-console') return fixture.stateMode === 'error' ? {status:503,body:{error:'Synthetic unavailable backend'}} : {status:200,body:state()};
    fixture.calls.push(structuredClone(action));if(fixture.calls.length>512)throw new Error('Synthetic action limit exceeded');
    if (action.action === 'start') {fixture.session=String(++fixture.sequence);fixture.request=0;return {status:200,body:{...state(),targets:targets(),truncated:false}};}
    if (action.action === 'stop') {fixture.session=null;return {status:200,body:state()};}
    if (action.action === 'targets') {fixture.target=String(Number(fixture.target)+1);return {status:200,body:{...state(),targets:targets(),truncated:false}};}
    assert.equal(action.session_id,fixture.session);
    assert.equal(action.target_id,fixture.target);
    const command=action.command, requestId=String(++fixture.request);
    let runtime={status:'ok',text:'Complete'};
    if (command.operation === 'evaluate') {
      if (command.source === 'fixture.slow') await new Promise(resolve=>fixture.pending.push(resolve));
      if (command.source === 'fixture.fail') return {status:503,body:{error:'Synthetic transport failure'}};
      if (command.source === 'fixture.stale') return {status:200,body:{...state(),status:'stale_target',text:'Synthetic document replaced',request_id:requestId}};
      runtime={status:'ok',value:command.source==='fixture.object'?value('object','Object {alpha, guarded, nested}', '1'):command.source==='fixture.malformed'?{type:'invented',text:'bad',truncated:false}:command.source==='fixture.throw'?null:value('number','42')};
      if(command.source==='fixture.throw') runtime={status:'exception',text:'Synthetic exception: inert <script>text</script>'};
    }
    if (command.operation === 'inspect') {
      if(fixture.inspectMode==='pending') await new Promise(resolve=>fixture.pending.push(resolve));
      const end=Math.min(fixture.propertyCount,command.offset+16);
      runtime=fixture.inspectMode==='error'?{status:'error',text:'Synthetic expired handle'}:{status:'ok',properties:Array.from({length:Math.max(0,end-command.offset)},(_,i)=>({name:`property${command.offset+i}`,value:i===1?value('accessor','[Getter]'):value('string',`inert <script>${command.offset+i}</script>`)})),offset:end,more:end<fixture.propertyCount};
    }
    if(command.operation==='poll'&&fixture.pollMode==='error')return {status:503,body:{error:'Synthetic poll failure'}};
    if(command.operation==='poll'){
      runtime={status:'ok',messages:fixture.messages.splice(0,32),dropped:0};
      if(fixture.pollMode==='pending')await new Promise(resolve=>fixture.pending.push(resolve));
    }
    if(command.operation==='complete') runtime={status:'ok',items:[]};
    return {status:200,body:{...state(),request_id:requestId,runtime}};
  };
  const respond=fixture.respond;
  fixture.respond=async(path,action)=>{
    const receipt={sequence:++fixture.receiptSequence,phase:'pending',action:action?.action||'state',session_id:action?.session_id||null,target_id:action?.target_id||null,operation:action?.command?.operation||null,source:action?.command?.source?.slice(0,128)||null,offset:action?.command?.offset??null};
    fixture.receipts.push(receipt);if(fixture.receipts.length>512)fixture.receipts.shift();
    try {
      const reply=await respond(path,action);
      Object.assign(receipt,{phase:'complete',session_id:action?.session_id||reply.body.session_id,request_id:reply.body.request_id||null,http_status:reply.status,status:reply.body.runtime?.status||reply.body.status||reply.body.state,value:reply.body.runtime?.value?.text?.slice(0,256)||null,property_offset:reply.body.runtime?.offset??null,message_count:reply.body.runtime?.messages?.length??null});
      return reply;
    } catch(error) {receipt.phase='failed';receipt.error=String(error.message).slice(0,2048);throw error;}
  };
  fixture.release=()=>{for(const resolve of fixture.pending.splice(0)) resolve();};
  fixture.handle=async (request,response)=>{
    try {
      const path=new URL(request.url,'http://127.0.0.1').pathname;
      if(!['/api/native-console','/api/native-console/actions'].includes(path))return false;
      let text='';for await(const chunk of request){text+=chunk;if(text.length>65536)throw new Error('Synthetic request exceeds fixture bound');}
      const reply=await fixture.respond(path,text?JSON.parse(text):null);
      if(!response.destroyed){response.writeHead(reply.status,{'Content-Type':'application/json'});response.end(JSON.stringify(reply.body));}return true;
    } catch(error) {
      fixture.errors.push(String(error.stack||error).slice(0,8192));if(fixture.errors.length>8)fixture.errors.shift();
      if(!response.destroyed){response.writeHead(500,{'Content-Type':'application/json'});response.end(JSON.stringify({error:'Synthetic fixture failure; see fixture receipts'}));}
      return true;
    }
  };
  return fixture;
}

// Input coordinates must be measured after the shared pane refresh and the
// disclosure's asynchronous toggle/ResizeObserver positioning have painted.
// This observes rendering only; strict hit testing and real input stay in click.

// Deterministically model the browser's scroll clamping when the shared
// divider temporarily expands a scrollport during restore/measure/reapply.
async function checkConsolePaneScroll(root) {
  let total=620, mainSize=360, trackWrites=0, serial=0, visible=true;const mutations=[],extraOwners=[];
  const queue=new Map(), documentEvents={}, windowEvents={}, parents=new Map();
  const scrollOwner=(contentHeight,extent)=>{let top=0,left=0;return {isConnected:true,contentHeight,
    get scrollTop(){return top;},set scrollTop(value){top=Math.max(0,Math.min(value,this.contentHeight-extent()));},
    get scrollLeft(){return left;},set scrollLeft(value){left=Math.max(0,Math.min(value,400));}};};
  const reading=scrollOwner(300,()=>mainSize),innerReading=scrollOwner(200,()=>mainSize-160),consoleReading=scrollOwner(800,()=>total-mainSize);
  const plainStyle=()=>({setProperty(){},removeProperty(){}});
  const node=()=>({id:'',hidden:false,dataset:{},style:plainStyle(),parentElement:null,attributes:{},classList:{add(){},remove(){}},listeners:{},setAttribute(k,v){this.attributes[k]=v;},addEventListener(k,v){this.listeners[k]=v;},getClientRects(){return [];},getBoundingClientRect(){return {left:0,right:360,top:0,bottom:total,width:360,height:total};},querySelector(){return node();}});
  const body=node();body.children=[];body.append=n=>body.children.push(n);
  const workspace=node();workspace.parentElement=body;
  workspace.style={setProperty(name,value){if(name==='grid-template-rows'){trackWrites++;mainSize=Number.parseFloat(value);}},removeProperty(name){if(name==='grid-template-rows'){trackWrites++;mainSize=360;reading.scrollTop=Math.max(0,Math.min(reading.scrollTop,reading.contentHeight-mainSize));innerReading.scrollTop=Math.max(0,Math.min(innerReading.scrollTop,innerReading.contentHeight-(mainSize-160)));for(const owner of extraOwners)owner.scrollTop=0;}}};
  const main=node(),panel=node();main.id='main';panel.id='native-console-panel';
  main.getClientRects=panel.getClientRects=()=>visible?[{}]:[];main.parentElement=panel.parentElement=workspace;
  main.getBoundingClientRect=()=>({left:0,right:360,top:0,bottom:mainSize,width:360,height:mainSize});
  panel.getBoundingClientRect=()=>({left:0,right:360,top:mainSize,bottom:total,width:360,height:total-mainSize});
  workspace.querySelector=selector=>selector==='.main'?main:panel;
  parents.set('#workspace',workspace);parents.set('main',main);parents.set('#native-console-panel',panel);
  const document={body,querySelector:selector=>{if(!parents.has(selector))parents.set(selector,node());return parents.get(selector);},createElement:()=>node(),addEventListener:(name,fn)=>documentEvents[name]=fn};
  const enqueue=fn=>{queue.set(++serial,fn);return serial;},cancel=id=>queue.delete(id);
  const flush=()=>{let count=0;while(queue.size){assert(++count<20,'Pane scheduling must settle');const [id,fn]=queue.entries().next().value;queue.delete(id);fn();}};
  const context={document,window:{addEventListener:(name,fn)=>windowEvents[name]=fn},innerWidth:360,innerHeight:740,
    localStorage:{getItem:()=>JSON.stringify({'native-console':.33}),setItem(){}},isPlainObject:value=>!!value&&typeof value==='object',
    requestAnimationFrame:enqueue,cancelAnimationFrame:cancel,setTimeout:enqueue,clearTimeout:cancel,
    MutationObserver:class{constructor(fn){mutations.push(fn);}observe(){}},ResizeObserver:class{observe(){}},
    getComputedStyle:element=>({display:element===workspace?'grid':'block',overflowX:'visible',overflowY:'visible',getPropertyValue:()=>`${mainSize}px ${total-mainSize}px`})};
  runInNewContext(await readFile(join(root,'apps/research-ui/pane_layout.js'),'utf8')+';initializePaneLayout();',context);flush();
  assert(mainSize<reading.contentHeight,'Saved dock must create the short scrollable upper pane');
  const initialWrites=trackWrites;reading.scrollTop=60;innerReading.scrollTop=40;consoleReading.scrollTop=50;
  for(const owner of [reading,innerReading,consoleReading]){documentEvents.scroll({target:owner});flush();
    assert.equal(reading.scrollTop,60,'A pure scroll must not expand the pane and clamp its reading position');
    assert.equal(innerReading.scrollTop,40,'A nested list scroll must keep its own reading position');
    assert.equal(consoleReading.scrollTop,50,'Console scrolling must keep the upper pane independent');
    assert.equal(trackWrites,initialWrites,'A pure scroll must reposition dividers without rewriting layout tracks');
  }
  // The ordinary broker refresh mutates observed hidden attributes even while
  // the same pane remains on screen. Its full measurement must be transactional.
  for(let i=0;i<3;i++){mutations[0]([{attributeName:'hidden'}]);flush();
    assert.equal(reading.scrollTop,60,'A full mutation refresh must preserve the outer reading offset');
    assert.equal(innerReading.scrollTop,40,'A full mutation refresh must preserve nested reading offsets');
    assert.equal(consoleReading.scrollTop,50,'A full mutation refresh must preserve Console reading offset');
  }
  reading.scrollTop=17;innerReading.scrollLeft=90;mutations[0]([{attributeName:'hidden'}]);flush();
  assert.equal(reading.scrollTop,17,'Current selection-driven offsets win over the last scroll-event value');assert.equal(innerReading.scrollLeft,90,'Horizontal reading offset is retained');
  reading.scrollTop=60;reading.contentHeight=245;total=700;windowEvents.resize({type:'resize'});flush();
  assert.equal(reading.scrollTop,14,'A real resize must clamp to the final extent, not the temporary default extent');
  reading.contentHeight=300;reading.scrollTop=0;mutations[0]([{attributeName:'hidden'}]);flush();assert.equal(reading.scrollTop,0,'An explicit move to the top must not resurrect a prior offset');
  innerReading.isConnected=false;mutations[0]([{attributeName:'hidden'}]);flush();innerReading.isConnected=true;innerReading.scrollTop=20;
  mutations[0]([{attributeName:'hidden'}]);flush();assert.equal(innerReading.scrollTop,0,'Detached owners are pruned rather than retained across reinsertion');
  total=700;windowEvents.resize({type:'resize'});documentEvents.scroll({target:reading});flush();assert(trackWrites>initialWrites,'A coalesced resize still requires full layout');
  const resizedWrites=trackWrites;documentEvents.scroll({target:reading});windowEvents.resize({type:'resize'});flush();assert(trackWrites>resizedWrites,'A resize after scroll must upgrade the pending refresh');
  const handle=body.children.find(child=>child.id==='pane-divider-native-console'),beforeKey=mainSize;
  handle.listeners.keydown({key:'ArrowDown',preventDefault(){},stopPropagation(){}});assert.equal(mainSize,beforeKey+10,'Divider keyboard resize must remain active');assert.equal(handle.style.top,`${mainSize-4}px`,'Divider hit target follows its split');
  visible=false;mutations[0]([{attributeName:'hidden'}]);flush();assert.equal(handle.hidden,true,'Visibility changes must retire the divider');visible=true;mutations[0]([{attributeName:'hidden'}]);flush();assert.equal(handle.hidden,false,'Reopening must restore full layout measurement');
  // Counterexample for the old reopen -> immediate summary click sequence:
  // the strict pre-input hit test can pass, then the scheduled real pane refresh
  // moves the summary before pointer delivery. No toggle-positioning or scroll
  // callback is required for that miss. Outside dismissal is checked separately
  // in the controller fixture. This models a possible ordering; the old CI
  // screenshot does not establish its input coordinates or disclosure state.
  const closeDock=()=>{visible=false;mutations[0]([{attributeName:'hidden'}]);flush();};
  const reopenDock=()=>{visible=true;mutations[0]([{attributeName:'hidden'}]);};
  const summaryBox=()=>({top:panel.getBoundingClientRect().top+4,bottom:panel.getBoundingClientRect().top+30});
  const pointerClick=()=>{
    const before=summaryBox(),y=(before.top+before.bottom)/2;
    assert(y>=before.top&&y<=before.bottom,'The baseline pre-input hit test passes');
    flush();const after=summaryBox();
    assert(y>=after.top&&y<=after.bottom,'Pane refresh moved the summary before pointer delivery');
  };
  closeDock();reopenDock();
  assert.throws(pointerClick,/Pane refresh moved the summary/,'The original immediate click must expose the scheduling counterexample');
  closeDock();reopenDock();
  {
    const queued=queue.size,result=runInNewContext('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))',context);
    assert(result&&typeof result.then==='function'&&queue.size>queued,'Readiness must observe a future render frame');
    flush();await result;
  }
  assert.doesNotThrow(pointerClick,'Read-only paint readiness must precede strict measurement and pointer delivery');
  console.log('PASS Console immediate-reopen pointer counterexample and read-only paint readiness (production pane scheduler; not rendered QA)');
  for(let i=0;i<65;i++){const owner=scrollOwner(800,()=>100);owner.scrollTop=10;extraOwners.push(owner);documentEvents.scroll({target:owner});}flush();mutations[0]([{attributeName:'hidden'}]);flush();
  assert.equal(extraOwners[0].scrollTop,0,'The oldest of 65 registered owners must be dropped');assert(extraOwners.slice(1).every(owner=>owner.scrollTop===10),'The 64 most recent owners remain preserved');
  extraOwners[1].scrollTop=0;documentEvents.scroll({target:extraOwners[1]});flush();extraOwners[1].scrollTop=10;mutations[0]([{attributeName:'hidden'}]);flush();assert.equal(extraOwners[1].scrollTop,0,'Returning to the origin removes an owner from tracking');
  console.log('PASS Console pane-scroll and mutation-refresh clamp regressions, nested/current offsets, final resize clamping, bounded/dropped/detached owners, resize/visibility scheduling and divider keyboard geometry (geometry model; not rendered QA)');
}

export async function checkConsoleCompletion(root) {
  const syntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
  const completion = await readFile(join(root, 'apps/research-ui/native_console_completion.js'), 'utf8');
  const {suggest, query} = runInNewContext(syntax + completion +
    ';({suggest:nativeConsoleSuggestions,query:nativeConsoleCompletionQuery})');
  const plain = value => JSON.parse(JSON.stringify(value));
  for (const [source, caret, prefix, start, end, path, names] of [
    ['document.que', 12, 'que', 9, 12, ['document'], ['querySelector', 'querySelectorAll']],
    ['document?.que', 13, 'que', 10, 13, ['document'], ['querySelector', 'querySelectorAll']],
    ['document.  que', 14, 'que', 11, 14, ['document'], ['querySelector', 'querySelectorAll']],
    ['/* inert */ Math.ra', 19, 'ra', 17, 19, ['Math'], ['random']],
    ['// inert\nMath.ra', 16, 'ra', 14, 16, ['Math'], ['random']],
    ['"😀"; document.querySelectorAll', 20, 'query', 15, 31, ['document'], ['querySelector']],
  ]) {
    const expected = {prefix, start, end, source, caret};
    const local = suggest(source, caret);
    assert.deepEqual(plain({...local, items:undefined}), expected, source);
    assert.deepEqual(Array.from(local.items, item => item.name), names, source);
    assert.deepEqual(plain(query(source, caret)), {path, ...expected}, source);
  }
  for (const source of ['"document.que', "'document.que", '`document.que',
    '// document.que', '/* document.que', '/document.que',
    'const pattern = /document.que', 'document.que' + '\u0001' + '// unfinished']) {
    for (const explicit of [false, true]) {
      assert.equal(suggest(source, source.length, explicit), null, source);
      assert.equal(query(source, source.length, explicit), null, source);
    }
  }
  // Catalog-only inference may inspect syntax for a known return type. Native
  // queries must still reject calls, computed keys, and literal receivers.
  for (const source of ['document.querySelector("a").sty', 'new Map().ge',
    '[1, 2].ma', '"snow".toU', 'Promise.resolve(1).th']) {
    assert(suggest(source, source.length), source);
    assert.equal(query(source, source.length), null, source);
  }
  for (const source of ['window[pageGetter()].', 'customPageObject.']) {
    assert.equal(suggest(source, source.length), null, source);
  }
  assert.equal(query('window[pageGetter()].', 'window[pageGetter()].'.length), null);
  assert.deepEqual(Array.from(query('customPageObject.', 17).path), ['customPageObject']);
  assert.equal(suggest('Math.log', 8), null, 'An exact name must remain ready to run');
  assert.equal(suggest('Math.log', 8, true).items[0].name, 'log');
  for (const complete of [suggest, query]) {
    assert.equal(complete('', 0), null);
    assert(complete('', 0, true));
    assert.equal(complete('document.', -1), null);
    assert.equal(complete('document.', 10), null);
    assert(complete(' '.repeat(8180) + 'document.que', 8192));
    assert.equal(complete(' '.repeat(8181) + 'document.que', 8193), null);
  }
  const chain = Array(8).fill('owner').join('.') + '.pr';
  assert.equal(query(chain, chain.length).path.length, 8);
  assert.equal(query('owner.' + chain, chain.length + 6), null);
  for (const source of ['a'.repeat(128) + '.', 'a'.repeat(128)]) {
    assert(query(source, source.length), '128-unit identifiers remain accepted');
  }
  for (const source of ['a'.repeat(129) + '.', 'a'.repeat(129)]) {
    assert.equal(query(source, source.length), null, '129-unit identifiers remain rejected');
  }
  console.log('PASS Console completion shared lexical boundaries, UTF-16 ranges, catalog/native separation and exact input/path/identifier limits (not rendered QA)');
}

// Behavioral DOM fixture only. Pixel, hit testing and keyboard coverage use the
// same browser driver as Requests, through --console-ui-browser.
export async function checkConsoleDOM(root) {
  await checkConsoleCompletion(root);
  await checkConsolePaneScroll(root);
  let document;
  class Node {
    constructor(tag='div') {this.tagName=tag;this.children=[];this.parentNode=null;this.dataset={};this.style={};this.attributes={};this.listeners={};this._text='';this.className='';this.value='';this.hidden=false;this.disabled=false;this.scrollTop=0;this.clientHeight=100;this.clientWidth=600;this.scrollHeight=100;this.selectionStart=0;this.selectionEnd=0;}
    get isConnected(){return this===document.body||!!this.parentNode?.isConnected;}
    get firstElementChild(){return this.children[0];}
    get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
    set textContent(text){this.replaceChildren();this._text=String(text);}
    get options(){return this.children;}
    get selectedOptions(){return this.children.filter(child=>child.value===this.value);}
    append(...children){for(let child of children){if(typeof child==='string'){const text=new Node('text');text.textContent=child;child=text;}if(child.tagName==='fragment'){this.append(...[...child.children]);continue;}child.remove();child.parentNode=this;this.children.push(child);}}
    replaceChildren(...children){for(const child of this.children)child.parentNode=null;this.children=[];this._text='';this.append(...children);if(this.tagName==='select'&&!this.children.some(child=>child.value===this.value))this.value=this.children[0]?.value||'';}
    remove(){if(this.parentNode){this.parentNode.children.splice(this.parentNode.children.indexOf(this),1);this.parentNode=null;}}
    setAttribute(name,value){this.attributes[name]=String(value);}
    getAttribute(name){return this.attributes[name]??null;}
    removeAttribute(name){delete this.attributes[name];}
    matches(selector){return selector==='*'&&this.tagName!=='text'||selector[0]==='.'?selector==='*'||this.className.split(' ').includes(selector.slice(1)):selector[0]==='#'?this.id===selector.slice(1):this.tagName===selector;}
    querySelectorAll(selector){return this.children.flatMap(child=>[...(child.matches(selector)?[child]:[]),...child.querySelectorAll(selector)]);}
    querySelector(selector){return this.querySelectorAll(selector)[0]??null;}
    closest(selector){return this.matches(selector)?this:this.parentNode?.closest(selector)??null;}
    contains(node){return node===this||this.children.some(child=>child.contains(node));}
    addEventListener(name,callback){(this.listeners[name]??=[]).push(callback);}
    async emit(name,fields={}){for(const callback of this.listeners[name]??[])await callback({target:this,currentTarget:this,preventDefault(){},stopPropagation(){},...fields});}
    click(){return this.disabled?Promise.resolve():this.emit('click');}
    focus(){document.activeElement=this;}
    select(){} reportValidity(){return true;} setSelectionRange(start,end){this.selectionStart=start;this.selectionEnd=end;}
    getBoundingClientRect(){return {top:0,bottom:100,left:0,right:600,width:600,height:100};}
  }
  const body=new Node('body'),documentEvents={};
  document={body,activeElement:null,querySelector:selector=>body.querySelector(selector),createElement:tag=>new Node(tag),createTextNode:text=>{const node=new Node('text');node.textContent=text;return node;},createDocumentFragment:()=>new Node('fragment'),addEventListener:(name,fn)=>documentEvents[name]=fn,dispatchEvent(){}};
  const html=await readFile(join(root,'apps/research-ui/index.html'),'utf8');
  const ids=[...html.matchAll(/<(\w+)[^>]*\bid="(native-console-[\w-]+)"[^>]*>/g)];
  const panel=new Node('section');panel.id='native-console-panel';body.append(panel);
  for(const [,tag,id]of ids){if(id===panel.id)continue;const node=new Node(tag);node.id=id;panel.append(node);}
  const get=id=>document.querySelector('#native-console-'+id);
  const workspace=new Node();workspace.id='workspace';body.append(workspace);
  const summary=new Node('summary'),menu=new Node();menu.className='native-console-connection-body';get('connection').append(summary,menu);menu.append(get('start'),get('stop'),get('refresh'));get('target').append(new Node('option'));
  get('level').value='all';get('scroll').append(get('output'));get('output').clientHeight=100;get('source').value='';
  const fixture=createConsoleFixture();let copies=0;
  const source=await readFile(join(root,'apps/research-ui/native_console.js'),'utf8');
  const context={document,TextEncoder,console,setTimeout,clearTimeout,setInterval(){},ResizeObserver:class{observe(){}},MutationObserver:class{observe(){}},CustomEvent:class{},navigator:{clipboard:{writeText:async()=>{copies++;}}},createNativeConsoleCompletion:()=>({close(){},keydown(){return false;}}),createSourceTokenizer:()=>({}),SOURCE_HIGHLIGHT_TOKEN_LIMIT:8192,sourceSyntaxTokens:text=>[{type:'plain',text}],sourcePrettyTokens:()=>[],fetch:async(path,options)=>{const reply=await fixture.respond(path,options?.body?JSON.parse(options.body):null);return {ok:reply.status===200,status:reply.status,json:async()=>reply.body};}};
  runInNewContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.testConsole = {initialize, logs, poll, renderControls, state:()=>({session,pending,submitting,generation,outputGeneration,outputBytes,outputNodes})};})();'),context);
  // Exercise production disclosure listeners separately from the scheduling
  // counterexample: positioning and inside pointers must never close the menu.
  get('connection').open=true;await get('connection').emit('toggle');
  assert.equal(get('connection').open,true);assert.equal(menu.style.width,'350px');
  for(const target of [summary,get('stop')]){documentEvents.pointerdown({target});assert.equal(get('connection').open,true);}
  documentEvents.pointerdown({target:body});assert.equal(get('connection').open,false);
  const api=context.testConsole;fixture.stateMode='error';await api.initialize();assert.match(get('notice').textContent,/Check availability/);assert.equal(get('start').disabled,true);fixture.stateMode='ok';await get('check').click();get('url').value='https://fixture.invalid/console';await get('start').click();
  // Event listener returns void for start; drain the serialized request.
  const settle=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};await settle();
  get('target').value=fixture.target;await get('target').emit('change');await settle();
  const submit=async text=>{get('source').value=text;await get('source').emit('input');return get('form').emit('submit');};
  await submit('fixture.object');assert.equal(copies,0);assert.equal(fixture.calls.filter(call=>call.command?.operation==='inspect').length,0);
  const object=get('output').querySelector('.native-console-object');object.open=true;await object.emit('toggle');await settle();
  assert.equal(object.querySelectorAll('.native-console-property').length,16);assert.match(object.textContent,/\[Getter\]/);assert.equal(copies,0);
  const pager=object.querySelector('.native-console-property-pager');fixture.inspectMode='pending';pager.children[1].focus();const heldInspection=pager.children[1].click();await settle();assert.equal(pager.children[1].getAttribute('aria-disabled'),'true');assert.equal(document.activeElement,pager.children[1]);get('source').focus();fixture.inspectMode='ok';fixture.release();await heldInspection;await settle();assert.equal(document.activeElement,get('source'));
  assert.equal(object.querySelectorAll('.native-console-property').length,16);assert.match(object.textContent,/property16/);
  fixture.inspectMode='error';await pager.children[1].click();await settle();assert.match(object.textContent,/Previous page preserved/);assert.match(object.textContent,/property16/);
  fixture.inspectMode='ok';await pager.children[2].click();await settle();assert.match(object.textContent,/property32/);assert.equal(object.querySelectorAll('.native-console-property').length,16);
  // Live shrink is a valid empty terminal page, not malformed transport.
  await pager.children[0].click();await settle();assert.match(object.textContent,/property16/);
  fixture.propertyCount=4;pager.children[1].focus();await pager.children[1].click();await settle();
  assert.match(object.textContent,/4 properties remain/);assert.equal(pager.children[0].disabled,false);assert.equal(pager.children[0].textContent,'First properties');assert.equal(document.activeElement,pager.children[0]);assert.equal(object.querySelectorAll('.native-console-property').length,0);
  await pager.children[0].click();await settle();assert.equal(object.querySelectorAll('.native-console-property').length,4);assert.match(object.textContent,/property0/);
  // Repeated empty-page reload and later regrowth remain explicit and bounded.
  fixture.propertyCount=48;const response=fixture.respond;await submit('fixture.object');
  const growing=get('output').querySelectorAll('.native-console-object').at(-1);growing.open=true;await growing.emit('toggle');await settle();
  const growthPager=growing.querySelector('.native-console-property-pager');await growthPager.children[1].click();await settle();fixture.propertyCount=0;growthPager.children[1].focus();await growthPager.children[1].click();await settle();
  assert.match(growing.textContent,/0 properties remain/);assert.equal(document.activeElement,growthPager.children[0]);
  await growthPager.children[2].click();await settle();assert.match(growing.textContent,/0 properties remain/);
  fixture.propertyCount=48;growthPager.children[2].focus();await growthPager.children[2].click();await settle();assert.match(growing.textContent,/property32/);assert.equal(growing.querySelectorAll('.native-console-property').length,16);assert.equal(document.activeElement,growthPager.children[0]);
  // A populated lower offset or non-progressing more=true remains malformed.
  for(const malformed of [{properties:[],offset:-1,more:false},{properties:[{name:'bad',value:{type:'number',text:'1',truncated:false}}],offset:4,more:false},{properties:[],offset:16,more:true},{properties:[],offset:65537,more:false}]){
    fixture.respond=async(path,action)=>{const reply=await response(path,action);if(action?.command?.operation==='inspect')reply.body.runtime={status:'ok',...malformed};return reply;};
    await growthPager.children[0].click();await settle();assert.match(growing.textContent,/Malformed property page/);assert.match(growing.textContent,/property32/);assert.equal(growthPager.children[0].disabled,false);
  }
  fixture.respond=response;
  const pending=submit('fixture.slow');await settle();assert.equal(get('source').disabled,false);get('source').value='next draft';await get('source').emit('input');await get('form').emit('submit');assert.equal(fixture.calls.filter(call=>call.command?.source==='next draft').length,0);
  fixture.release();await pending;assert.equal(get('source').value,'next draft');assert.equal(api.state().submitting,false);
  await submit('fixture.fail');assert.match(get('output').textContent,/Outcome unavailable/);assert.match(get('notice').textContent,/never retried/);assert.equal(get('source').disabled,true);
  const retained=get('output').textContent;await get('refresh').click();await settle();assert.equal(get('output').textContent.startsWith(retained),true);get('target').value=fixture.target;await get('target').emit('change');await settle();
  // An old object cannot silently bind to the replacement document.
  const calls=fixture.calls.length;await growthPager.children[0].click();await settle();assert.equal(fixture.calls.slice(calls).filter(call=>call.command?.operation==='inspect').length,0);assert.match(growing.textContent,/earlier document selection/);
  await submit('fixture.stale');assert.equal(get('target').value,'');assert.equal(get('source').disabled,true);
  await get('refresh').click();await settle();get('target').value=fixture.target;await get('target').emit('change');await settle();
  fixture.pollMode='error';await api.poll();assert.equal(get('source').disabled,true);assert.equal(get('badge').textContent,'Connection lost');fixture.pollMode='ok';await get('refresh').click();await settle();get('target').value=fixture.target;await get('target').emit('change');await settle();
  // A quiet poll owns its old transcript epoch. Clear does not cancel the
  // native context or discard a command explicitly submitted after it.
  const contextGeneration=api.state().generation;
  fixture.messages.push({level:'info',text:'before-clear poll message',time:0});fixture.pollMode='pending';const oldPoll=api.poll();await settle();assert(fixture.pending.length);assert.equal(get('clear').disabled,false);
  const clear=get('clear').click();assert.equal(get('output').children.length,0);assert.equal(api.state().generation,contextGeneration);
  const afterClear=submit('fixture.afterClear');await settle();fixture.pollMode='ok';fixture.release();await oldPoll;await clear;await afterClear;await settle();
  assert.doesNotMatch(get('output').textContent,/before-clear poll message/);assert.match(get('output').textContent,/fixture.afterClear/);assert.match(get('output').textContent,/42/);assert.equal(document.activeElement,get('source'));
  const currentCommand=get('output').querySelector('.native-console-command');const currentResult=get('output').querySelectorAll('.native-console-result').at(-1);
  for(const row of [currentCommand,currentResult]){assert.equal(row.dataset.consoleSession,fixture.session);assert.equal(row.dataset.consoleDocument,fixture.target);assert.equal(row.dataset.commandNumber,currentCommand.dataset.commandNumber);assert.equal(row.dataset.requestId,currentCommand.dataset.requestId);}
  assert.equal(fixture.calls.filter(call=>call.command?.source==='fixture.afterClear').length,1);
  // A malformed quiet poll is owned and fails closed without partial output.
  const retainedBeforeMalformed=get('output').textContent;fixture.messages.push({level:'info',text:'must not partially append',time:0},{level:'invented',text:'bad',time:0});await api.poll();assert.equal(get('output').textContent,retainedBeforeMalformed);assert.equal(get('source').disabled,true);assert.match(get('notice').textContent,/Malformed page message/);
  await get('refresh').click();await settle();get('target').value=fixture.target;await get('target').emit('change');await settle();
  // Native Message emits finite numeric Unix milliseconds. Validate the
  // entire batch before any Date conversion, dropped marker or row insertion.
  for(const time of [-8640000000000000,-0.5,0,0.5,1700000000000.125,8640000000000000]){
    api.logs({messages:[{level:'info',text:'valid timestamp boundary',time}],dropped:0});
    assert.equal(get('output').children.at(-1).querySelector('.native-console-time').textContent,new Date(time).toLocaleTimeString());
  }
  let timestampCoercions=0;const coercibleTime={valueOf(){timestampCoercions++;return 0;},toString(){timestampCoercions++;return '0';}};
  const invalidTimes=[undefined,null,false,'0','2026-10-07T00:00:00Z',[],{}, {valueOf:0,toString:0},coercibleTime,NaN,Infinity,-Infinity,-8640000000000001,8640000000000001];
  const retainedBeforeTime=get('output').textContent,countsBeforeTime=get('output-count').textContent,bytesBeforeTime=api.state().outputBytes,nodesBeforeTime=api.state().outputNodes;
  for(const time of invalidTimes){
    assert.throws(()=>api.logs({messages:[{level:'info',text:'must remain atomic',time:0},{level:'info',text:'invalid timestamp',time}],dropped:1}),/Malformed page message/);
    assert.equal(get('output').textContent,retainedBeforeTime);assert.equal(get('output-count').textContent,countsBeforeTime);assert.equal(api.state().outputBytes,bytesBeforeTime);assert.equal(api.state().outputNodes,nodesBeforeTime);
  }
  assert.equal(timestampCoercions,0,'Timestamp validation must not coerce objects');
  fixture.messages.push({level:'info',text:'must remain atomic',time:0},{level:'info',text:'bad time',time:{valueOf:0,toString:0}});await api.poll();
  assert.equal(get('output').textContent,retainedBeforeTime);assert.equal(get('badge').textContent,'Connection lost');assert.equal(get('source').disabled,true);assert.match(get('notice').textContent,/Malformed page message/);
  await get('refresh').click();await settle();get('target').value=fixture.target;await get('target').emit('change');await settle();
  await submit('fixture.malformed');assert.match(get('notice').textContent,/Malformed runtime value/);assert.equal(api.state().submitting,false);
  await submit('fixture.throw');assert.match(get('output').textContent,/inert <script>text<\/script>/);assert.equal(get('output').querySelector('script'),null);
  for(let i=0;i<140;i++)api.logs({messages:[{level:'info',text:`fixture message ${i}`,time:0}],dropped:0});
  assert(get('output').children.length<=128);assert(api.state().outputBytes<=262144);assert(api.state().outputNodes<=8192);assert.match(get('output-count').textContent,/older removed/);
  get('filter').value='no-such-value';await get('filter').emit('input');assert.equal(get('no-matches').hidden,false);await get('filter-close').click();assert.equal(get('no-matches').hidden,true);
  await get('clear').click();assert.equal(get('output').children.length,0);assert.equal(get('empty').hidden,false);assert.equal(copies,0);
  get('source').value='reconnect draft';const oldSession=fixture.session;await get('stop').click();await settle();await get('start').click();await settle();assert.notEqual(fixture.session,oldSession);assert.equal(get('source').value,'reconnect draft');assert.equal(get('target').value,'');
  const broken=createConsoleFixture();const request={url:'/api/native-console/actions',async *[Symbol.asyncIterator](){yield '{malformed';}},reply={destroyed:false,writeHead(status){this.status=status;},end(text){this.text=text;}};assert.equal(await broken.handle(request,reply),true);assert.equal(reply.status,500);assert.equal(broken.errors.length,1);
  const wrong={url:'/api/native-console/actions',async *[Symbol.asyncIterator](){yield JSON.stringify({action:'runtime',session_id:'wrong',target_id:'101',command:{operation:'poll'}});}};await broken.handle(wrong,reply);assert.equal(reply.status,500);assert.equal(broken.receipts.at(-1).phase,'failed');assert.equal(broken.errors.length,2);
  console.log('PASS Console serialized command/result identity, editable drafts, bounded property paging, shrink/regrowth and focus, held-poll Clear epochs, atomic malformed-poll/timestamp recovery without coercion, inert rendering, retry/reconnect, fixture error receipts, and transcript/filter/history bounds (DOM fixture; not rendered QA)');
}
