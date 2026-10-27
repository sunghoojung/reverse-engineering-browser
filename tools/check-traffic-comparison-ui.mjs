import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Plan only native scrolling; the existing pointer helper remains the final
// visibility/hit-test gate. The row may be clipped by either scroll owner.
export function comparisonRequestRevealPlan({row, ledger, clip}) {
  assert(row.height > 0 && ledger.bottom-ledger.top >= row.height && clip.bottom-clip.top >= row.height,
    'Comparison request row must fit its ledger and visible outer pane');
  const inner = row.top < ledger.top ? row.top-ledger.top : row.bottom > ledger.bottom ? row.bottom-ledger.bottom : 0;
  const outer = row.top < clip.top ? row.top-clip.top : row.bottom > clip.bottom ? row.bottom-clip.bottom : 0;
  if (Math.min(ledger.bottom,clip.bottom) <= Math.max(ledger.top,clip.top)) {
    // A row's unpainted rect can lie inside the outer pane while its own
    // scrollport is entirely offscreen. Reveal that scrollport before wheeling it.
    return {owner:'.request-pane',delta:ledger.top>=clip.bottom?Math.min(ledger.bottom-clip.bottom,ledger.top-clip.top):Math.max(ledger.top-clip.top,ledger.bottom-clip.bottom)};
  }
  if (inner) return {owner:'#request-rows',delta:inner};
  if (outer) return {owner:'.request-pane',delta:outer};
  return null;
}

export async function checkTrafficComparisonController(root) {
  const reveal={row:{top:361,bottom:389,height:28},ledger:{top:333,bottom:389},clip:{top:170,bottom:357}};
  assert.deepEqual(comparisonRequestRevealPlan(reveal),{owner:'.request-pane',delta:32},'The CI-clipped second row needs outer-pane scrolling');
  assert.equal(comparisonRequestRevealPlan({...reveal,row:{top:329,bottom:357,height:28},ledger:{top:301,bottom:357}}),null);
  assert.deepEqual(comparisonRequestRevealPlan({row:{top:228,bottom:256,height:28},ledger:{top:200,bottom:228},clip:{top:100,bottom:400}}),{owner:'#request-rows',delta:28});
  assert.deepEqual(comparisonRequestRevealPlan({row:{top:230,bottom:258,height:28},ledger:{top:500,bottom:556},clip:{top:170,bottom:357}}),{owner:'.request-pane',delta:199},'Reveal the fully offscreen ledger before wheeling its unpainted row');
  assert.deepEqual(comparisonRequestRevealPlan({row:{top:230,bottom:258,height:28},ledger:{top:0,bottom:56},clip:{top:170,bottom:357}}),{owner:'.request-pane',delta:-170});
  assert.deepEqual(comparisonRequestRevealPlan({row:{top:329,bottom:357,height:28},ledger:{top:357,bottom:385},clip:{top:170,bottom:357}}),{owner:'.request-pane',delta:28});
  assert.deepEqual(comparisonRequestRevealPlan({row:{top:301,bottom:329,height:28},ledger:{top:329,bottom:357},clip:{top:170,bottom:357}}),{owner:'#request-rows',delta:-28});
  assert.equal(comparisonRequestRevealPlan({row:{top:329,bottom:357,height:28},ledger:{top:329,bottom:357},clip:{top:170,bottom:357}}),null);
  assert.throws(()=>comparisonRequestRevealPlan({...reveal,clip:{top:350,bottom:357}}),/must fit/,'Scrolling cannot excuse an impossibly clipped control');
  const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const source = await readFile(join(root,'apps/research-ui/traffic_view.js'),'utf8');
  const navigation = await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const algorithms = await readFile(join(root,'apps/research-ui/traffic_comparison.js'),'utf8');
  const requestRoot = app.slice(app.indexOf('      function requestTraceRoot('),app.indexOf('      function requestSignalProfileSelection('));
  const state = {sessionMode:'live',requests:[],selectedRequestId:null};
  const document = {activeElement:null};
  class Node {
    constructor(tag) {this.tagName=tag;this.children=[];this.dataset={};this.events={};this.attributes={};this.text='';}
    set textContent(value){this.text=String(value);this.children=[];}
    get textContent(){return this.text+this.children.map(child=>child.textContent).join('');}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;this.text='';}
    setAttribute(key,value){this.attributes[key]=String(value);}
    addEventListener(name,handler){this.events[name]=handler;}
    focus(){document.activeElement=this;}
    click(){if(!this.disabled)this.events.click?.();}
  }
  document.createElement=tag=>new Node(tag);
  const container=new Node('section'); let ui;
  const redraw=()=>ui.renderTrafficComparison(container,state.requests.find(value=>value.id===state.selectedRequestId),true);
  ui=runInNewContext(`${requestRoot}\n${navigation}\n${algorithms}\n${source}\n;({createTrafficComparisonController,investigationRequestIdentity,investigationSame,renderTrafficComparison,syncTrafficComparison,identity:()=>trafficComparisonController?.identity})`,
    {state,document,TextEncoder,TextDecoder,Uint8Array,URL,integerText:(event,key)=>String(event[key]),renderInspector:redraw});
  const owner={mode:'live'};
  const body=text=>({state:'available',mime:'application/json',text,headers:[['content-type','application/json']]});
  // Native Traffic rows: the exact identity is the row's unique request_started event.
  const started=(sequence,requestId)=>({session_id:'5',process_id:3,sequence_number:String(sequence),request_id:String(requestId),type:'request_started'});
  const request=(id,patch={})=>({id,origin:'live',operation:'request_completed',tabId:'1',events:[started(id==='a'?11:12,id==='a'?101:102)],firstTimestamp:1n,method:'POST',path:'https://fixture.invalid/test',status:200,
    exchange:{request:body('{"request":1}'),response:body('{"response":1}')},...patch});
  const otherProcess=value=>({...value,events:[{...value.events[0],process_id:4}]});
  const a=request('a'),b=request('b');
  const controller=ui.createTrafficComparisonController(ui.investigationRequestIdentity,ui.investigationSame);
  assert(controller.pin(a,[a,b],owner));
  assert.equal(controller.sync([a,b],owner),a);
  assert.deepEqual(Object.keys(controller.identity).sort(),['process','request','sequence','session','type']);
  assert.equal(controller.sync([b],owner),null);assert.match(controller.notice,/expired/);
  assert.equal(controller.sync([a,b],owner),null,'An expired baseline must never silently rebind');
  for(const change of [{mode:'demo'},{mode:'idle'}]){
    assert(controller.pin(a,[a,b],owner));assert.equal(controller.sync([a,b],{...owner,...change}),null);assert.equal(controller.sync([a,b],owner),null);
  }
  assert.equal(controller.pin(a,[a,{...a}],owner),false);
  assert.equal(controller.pin({...a,origin:'sample'},[{...a,origin:'sample'}],owner),false);
  const event={session_id:'9007199254740993',process_id:17,sequence_number:'18446744073709551615',request_id:'91',type:'request_started'};
  const native={id:'native',origin:'live',operation:'request_started',events:[event]};
  assert(controller.pin(native,[native],owner));assert.equal(controller.identity.session,event.session_id);
  assert.equal(controller.sync([{...native,events:[{...event,session_id:'9007199254740994'}]}],owner),null);
  assert(controller.pin(a,[a,b],owner));controller.clear();assert.equal(controller.identity,null);

  state.requests=[a,b];state.selectedRequestId='a';redraw();
  assert.equal(container.rebComparison.pin.disabled,false);container.rebComparison.pin.click();assert(ui.identity());
  const pin=container.rebComparison.pin;
  state.selectedRequestId='b';b.exchange.response=body('{"response":2,"html":"<img src=x onerror=alert(1)>"}');redraw();
  assert.match(container.textContent,/response.*changed/s);assert.match(container.textContent,/<img/);
  assert.equal(container.children.flatMap(child=>child.children).some(node=>node.tagName==='img'),false);
  const view=container.rebComparison;
  const identityDisclosure=container.children[2],identitySummary=view.identitySummary;
  identityDisclosure.open=true;identitySummary.focus();
  b.status=201;redraw();assert.equal(container.children[2],identityDisclosure);assert.equal(identityDisclosure.open,true);assert.equal(document.activeElement,identitySummary);
  b.status=200;redraw();

  const result=view.result.children;view.result.scrollTop=120;view.result.focus();redraw();
  assert.equal(container.rebComparison.pin,pin);assert.equal(view.result.children,result);assert.equal(view.result.scrollTop,120);assert.equal(document.activeElement,view.result);
  const responseSection=view.result.children.find(value=>value.dataset.label==='Response body');
  responseSection.open=false;responseSection.children[0].focus();
  b.exchange.response=body('{"response":3}');redraw();assert.match(container.textContent,/Selected: 3/);
  const changedResponseSection=view.result.children.find(value=>value.dataset.label==='Response body');
  assert.equal(changedResponseSection.open,false);assert.equal(document.activeElement,changedResponseSection.children[0]);

  for(const [field,value] of [['methodTruncated',true],['urlTruncated',true],['hostOnly',true],['targetKind','unknown']]){
    b[field]=value;redraw();assert.match(container.textContent,/General · incomplete/);delete b[field];redraw();assert.match(container.textContent,/General · equal/);
  }
  for(const field of ['headersTruncated','headers_truncated']){
    b.exchange.request[field]=true;redraw();assert.match(container.textContent,/Request headers · incomplete/);delete b.exchange.request[field];redraw();assert.match(container.textContent,/Request headers · equal/);
  }
  assert.equal(controller.pin(a,[a,otherProcess(a)],owner),false,'Same visible request ID with different exact identities cannot be pinned ambiguously');

  b.exchange.response={...body(''),bytes:new TextEncoder().encode('{"response":3}')};delete b.exchange.response.text;redraw();
  b.exchange.response.bytes[12]=52;redraw();assert.match(container.textContent,/Selected: 4/,'In-place byte updates invalidate comparison exactly');
  assert(view.byteSnapshots.reduce((sum,value)=>sum+(value?.bytes.length??0),0)<=4*128*1024);
  state.sessionMode='demo';redraw();assert.equal(ui.identity(),null);assert.match(container.textContent,/Baseline expired/);assert.equal(view.result.children.length,0);assert.equal(document.activeElement,view.pin,'Expiry transfers focused summary to the enabled pin action');
  state.sessionMode='live';redraw();assert.equal(ui.identity(),null);
  state.selectedRequestId='a';redraw();container.rebComparison.pin.click();state.selectedRequestId='b';redraw();
  view.result.children.find(value=>value.dataset.label==='Response body').children[0].focus();
  state.requests=[a,b,otherProcess(b)];redraw();
  assert.equal(document.activeElement,container,'Ambiguous selection transfers focused summary to the comparison panel');
  assert.equal(view.pin.disabled,true);assert.equal(view.result.children.length,0);
  state.requests=[a,b];redraw();
  container.rebComparison.pin.click();assert(ui.identity());container.rebComparison.clear.click();assert.equal(ui.identity(),null);assert.equal(view.byteSnapshots.length,0);assert.equal(document.activeElement,container.rebComparison.pin);
  const aHead={...a,method:'HEAD',status:204},bHead={...b,method:'HEAD',status:204};delete aHead.exchange;delete bHead.exchange;
  state.requests=[aHead,bHead];state.selectedRequestId='a';redraw();view.pin.click();state.selectedRequestId='b';redraw();
  assert.match(container.textContent,/Response body · unavailable/);
  for(const value of state.requests)value.exchange={request:{state:'missing'},response:{state:'empty',reason:'This HTTP response has no body.'}};
  redraw();assert.match(container.textContent,/Response body · equal/,'Capture presence differs from an inspector-only HTTP empty fallback');
  state.requests=[{...native,method:'GET',path:'https://fixture.invalid/native',status:200}];state.selectedRequestId='native';redraw();view.pin.click();
  state.requests=[{...state.requests[0],id:'renamed-native'}];state.selectedRequestId='renamed-native';redraw();
  assert.match(view.identitySummary.textContent,/Baseline:.*renamed-native.*selected:.*renamed-native/,'Visible row IDs refresh even when exact native event identity is unchanged');
  ui.renderTrafficComparison(container,b,false);assert.equal(container.children.length,0,'Leaving comparison erases its copied result DOM');
  console.log('PASS captured comparison: production identity/evidence-mode expiry, ambiguity, explicit repin/clear, inert DOM and unchanged refresh ownership');
}
