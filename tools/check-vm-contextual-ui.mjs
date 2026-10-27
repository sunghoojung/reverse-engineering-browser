#!/usr/bin/env node
// Authored inputs only: offline controller/CLI checks; no browser driver.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {pathToFileURL} from 'node:url';
import model from '../apps/research-ui/vm_contextual.js';
import evidenceModel from '../apps/research-ui/vm_contextual_evidence.js';
import {execute,capabilities} from './vm-agent.mjs';
const sha=hex=>createHash('sha256').update(Buffer.from(hex,'hex')).digest('hex');
export async function contextualFixture() {
  const definition={format:'reb-vm-contextual-definition-v1',build_id:'authored-ui-build',definition_id:'authored-ui-definition',image_sha256:sha('1003ff10'),architecture:'stack',opcode_bytes:1,operand_endianness:'little',register_count:0,
    instructions:[{instruction_id:'MACRO',mnemonic:'MACRO',operands:[{name:'target',width:1,signed:false,kind:'address'}],operations:[{operation:'nop',args:[]},{operation:'jump',args:[]}],flow:{kind:'jump',target:{operand:'target',base:'absolute'}}},{instruction_id:'HALT',mnemonic:'HALT',operands:[],operations:[{operation:'halt',args:[]}],flow:{kind:'halt'}}],
    mappings:[{pc:0,decoder_state:'start',raw_opcode:'10',instruction_id:'MACRO',next_decoder_state:'done'},{pc:0,decoder_state:'alternate',raw_opcode:'10',instruction_id:'HALT',next_decoder_state:null},{pc:3,decoder_state:'done',raw_opcode:'10',instruction_id:'HALT',next_decoder_state:null}]};
  const image={format:'reb-vm-contextual-image-v1',build_id:definition.build_id,definition_id:definition.definition_id,image_id:'authored-ui-image',bytes_hex:'1003ff10',entry_contexts:[{offset:0,decoder_state:'start'},{offset:0,decoder_state:'alternate'},{offset:2,decoder_state:null}]};
  const analysis=await model.analyze(definition,image);
  const evidence={format:'reb-vm-contextual-evidence-v1',identity:analysis.identity,capture_id:'authored-not-captured',run_id:'authored-run',context_id:'authored-context',mapping_provenance:{kind:'supplied',reference:'authored-ui-fixture'},events:[{event_id:'authored-jump',sequence:0,kind:'jump',pc:0,decoder_state:'start',raw_opcode:'10',to:{pc:3,decoder_state:'done'}}],gaps:[]};
  return {definition,image,evidence};
}
const source=await readFile(new URL('../apps/research-ui/vm_contextual_view.js',import.meta.url),'utf8');
const descendants=e=>[e,...e.children.flatMap(descendants)];
function harness(selectedModel=model) {
  const document={activeElement:null};
  class Element {
    constructor(tag){this.tagName=tag;this.children=[];this.events={};this.attributes={};this.text='';this.value='';}
    set textContent(value){this.text=String(value);this.children=[];} get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
    append(...children){this.children.push(...children);} replaceChildren(...children){this.text='';this.children=children;}
    setAttribute(key,value){this.attributes[key]=String(value);} getAttribute(key){return this.attributes[key]??null;}
    addEventListener(key,action){this.events[key]=action;} focus(){document.activeElement=this;}
    querySelector(selector){const [,key,value]=selector.match(/^\[([^=]+)="([^"]+)"\]$/);return descendants(this).find(e=>e.getAttribute(key)===value)??null;}
  }
  document.createElement=tag=>new Element(tag);
  const api=runInNewContext(source+';({mountVmContextual})',{document,TextEncoder,TextDecoder,vmContextual:selectedModel,vmContextualEvidence:evidenceModel});
  const root=new Element('section');return {root,document,ui:api.mountVmContextual(root)};
}
const file=(value,name='authored.json')=>{const bytes=new TextEncoder().encode(typeof value==='string'?value:JSON.stringify(value));return {name,size:bytes.byteLength,arrayBuffer:async()=>bytes.buffer};};
const button=(root,label)=>descendants(root).find(e=>e.tagName==='button'&&e.textContent===label);
async function load(ui,fixture){for(const kind of ['definition','image','evidence'])if(fixture[kind])await ui.importFile(kind,file(fixture[kind]));await ui.analyzeInputs();}
export async function checkContextualController() {
  const fixture=await contextualFixture(),{root,ui,document}=harness();
  assert(ui.analyze.disabled);await ui.importFile('definition',file(fixture.definition));assert(ui.analyze.disabled);await ui.importFile('image',file(fixture.image));assert(!ui.analyze.disabled);assert.equal(ui.getReport(),null);
  await ui.analyzeInputs();assert.equal(ui.getReport().instructions.length,3);assert.equal(ui.getLinked(),null);
  assert.match(ui.diagnostics.textContent,/unknown_state/);ui.select('context:0:alternate');assert.equal(ui.getSelected(),'context:0:alternate');assert.match(ui.detail.textContent,/HALT/);
  await ui.importFile('evidence',file(fixture.evidence));assert.equal(ui.getReport(),null);await ui.analyzeInputs();assert.match(ui.detail.textContent,/matches_declared/);assert.match(ui.detail.textContent,/authored-not-captured/);assert.match(ui.detail.textContent,/nop\(\)jump\(\)/);
  ui.filter.value='alternate';ui.filter.events.input();assert.equal(descendants(ui.listing).filter(e=>e.getAttribute('data-vm-contextual-id')).length,1);assert.equal(ui.getSelected(),'context:0:start');assert.match(ui.listing.textContent,/selection hidden by filter/);
  const hiddenAvailability={detail:{}};root.events['vm-workspace-query'](hiddenAvailability);assert.equal(hiddenAvailability.detail.previous,true);root.events['vm-workspace-previous']();assert.equal(ui.getSelected(),'context:0:alternate');ui.select('context:0:start');
  ui.reveal.events.click();assert.equal(ui.filter.value,'');assert.equal(ui.getSelected(),'context:0:start');
  ui.showTab('edges');const destination=descendants(ui.detail).find(e=>e.getAttribute('data-contextual-destination')==='context:3:done');assert(destination);destination.events.click();assert.equal(ui.getSelected(),'context:3:done');
  const availability={detail:{}};root.events['vm-workspace-query'](availability);assert.equal(availability.detail.next,false);assert.equal(availability.detail.previous,true);root.events['vm-workspace-previous']();assert.notEqual(ui.getSelected(),'context:3:done');root.events['vm-workspace-search']();assert.equal(document.activeElement,ui.filter);
  ui.select('context:0:start');ui.showTab('instruction');
  const prior=ui.getReport();for(const bad of ['{}','{"format":1,"format":2}','<img src=x onerror=alert(1)>']){await ui.importFile('definition',file(bad));assert.equal(ui.getReport(),prior);assert.match(ui.notice.textContent,/Import refused/);}
  let read=false;await ui.importFile('definition',{size:1048577,arrayBuffer:async()=>{read=true;}});assert.equal(read,false);
  await ui.importFile('image',{size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer});assert.equal(ui.getReport(),prior);
  await ui.importFile('definition',file(fixture.definition,'<img src=x onerror=alert(1)>.json'));await ui.analyzeInputs();assert(ui.detail.textContent.includes('<img'));assert(!descendants(root).some(e=>e.tagName==='img'));
  const many=structuredClone(fixture);many.evidence.events=Array.from({length:65},(_,n)=>({...fixture.evidence.events[0],event_id:'jump-'+n,sequence:n}));await load(ui,many);
  assert.equal(descendants(ui.detail).filter(e=>e.tagName==='p'&&e.textContent.includes('matches_declared')).length,32);
  button(root,'Next linked jumps').events.click();assert.equal(document.activeElement.textContent,'Next linked jumps');button(root,'Next linked jumps').events.click();assert.equal(document.activeElement.textContent,'Previous linked jumps');
  ui.removeEvidence.events.click();assert.equal(ui.getReport(),null);await ui.analyzeInputs();assert.equal(ui.getLinked(),null);
  let finish;const pending=ui.importFile('image',{size:4,arrayBuffer:()=>new Promise(resolve=>{finish=resolve;})});ui.clear.events.click();finish(new TextEncoder().encode('{}').buffer);await pending;assert.equal(ui.getReport(),null);assert(ui.analyze.disabled);
  let finishAnalysis;const delayed=harness({...model,analyze:()=>new Promise(resolve=>{finishAnalysis=resolve;})}).ui;await delayed.importFile('definition',file(fixture.definition));await delayed.importFile('image',file(fixture.image));const working=delayed.analyzeInputs();delayed.clear.events.click();finishAnalysis(prior);await working;assert.equal(delayed.getReport(),null);
  const largeReport={...prior,instructions:Array.from({length:70},(_,n)=>({...prior.instructions[0],id:'paged-'+n,offset:n}))};
  const paged=harness({...model,analyze:async()=>largeReport});await load(paged.ui,{definition:fixture.definition,image:fixture.image});
  assert.equal(descendants(paged.ui.listing).filter(e=>e.getAttribute('data-vm-contextual-id')).length,32);button(paged.root,'Next contexts').events.click();assert(descendants(paged.ui.listing).some(e=>e.getAttribute('data-vm-contextual-id')==='paged-32'));button(paged.root,'Next contexts').events.click();assert.equal(descendants(paged.ui.listing).filter(e=>e.getAttribute('data-vm-contextual-id')).length,6);
  const firstVisible=descendants(paged.ui.listing).find(e=>e.getAttribute('data-vm-contextual-id')==='paged-64');firstVisible.events.keydown({key:'Home',preventDefault(){}});assert.equal(paged.ui.getSelected(),'paged-0');assert.equal(paged.document.activeElement.getAttribute('data-vm-contextual-id'),'paged-0');
  const firstRow=descendants(paged.ui.listing).find(e=>e.getAttribute('data-vm-contextual-id')==='paged-0');for(const modifier of ['isComposing','altKey','ctrlKey','metaKey'])firstRow.events.keydown({key:'ArrowDown',[modifier]:true,preventDefault(){throw Error('Modified event consumed');}});assert.equal(paged.ui.getSelected(),'paged-0');
  paged.ui.select('paged-69',true,true);paged.ui.filter.value='paged-0';paged.ui.filter.events.input();assert.equal(paged.ui.getSelected(),'paged-69');paged.ui.reveal.events.click();assert(descendants(paged.ui.listing).some(e=>e.getAttribute('data-vm-contextual-id')==='paged-69'));
  const dir=await mkdtemp(join(tmpdir(),'reb-contextual-cli-'));try {
    for(const kind of ['definition','image','evidence'])await writeFile(join(dir,kind+'.json'),JSON.stringify(fixture[kind]));
    const args=['--definition',join(dir,'definition.json'),'--input',join(dir,'image.json')];
    assert.equal((await execute(['analyze-contextual',...args])).result.instructions.length,3);
    assert.equal((await execute(['link-contextual',...args,'--evidence',join(dir,'evidence.json')])).result.observed_edges.length,1);
    assert(capabilities().contextual.commands.includes('link-contextual'));assert(capabilities().opcode_evidence.commands.includes('opcode-ledger'));
    await assert.rejects(execute(['analyze-contextual',...args,'--url','https://example.com']));
    const mismatch={...fixture.image,build_id:'other'};await writeFile(join(dir,'image.json'),JSON.stringify(mismatch));await assert.rejects(execute(['analyze-contextual',...args]));
  } finally {await rm(dir,{recursive:true,force:true});}
  console.log('PASS contextual controller and CLI: state identity, ordered macros, jumps, bounds, inert text, focus, cancellation, fixed-workflow discovery');
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await checkContextualController();
