import assert from 'node:assert/strict';
import {selectRenderedOption} from './rendered-keyboard.mjs';
import {recordCompatibilityDemo} from './generate-vm-compatibility-demo.mjs';
export async function checkVmSemanticsInteractions({evaluate,viewport,click,key,screenshot}) {
 const before={pc:0,halted:false,registers:[0],stack:[],memory:[]},after={...before,pc:1,registers:[7]},halted={...after,halted:true};
 const trace={format:'reb-vm-trace-v1',identity:{trace_id:'owned-ui',investigation_id:'1',finding_id:'2',artifact_id:'3',artifact_sha256:'a'.repeat(64),scope_id:'owned-ui',backend:'native'},architecture:'register',coverage:{complete:true,dropped_steps:0,limitations:['<img src=x onerror=alert(1)> inert fixture']},steps:[{sequence:0,opcode:'03',operands:[0,7],instruction_size:1,before,after,evidence_refs:['fixture:0']},{sequence:1,opcode:'09',operands:[],instruction_size:1,before:after,after:halted,evidence_refs:['fixture:1']}]};
 const root='#vm-semantics-workflow';
 await viewport(1440,900);await evaluate("showScreen('vm');");await click('#vm-show-execution');
 // All providers remain in native tab order. Opening Live is deliberate and
 // returning to Imported must still reach its original file input by keyboard.
 await key('Tab','Tab',{windowsVirtualKeyCode:9});assert.equal(await evaluate('document.activeElement.id'),'vm-show-owned');
 assert.equal(await evaluate(`(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&getComputedStyle(e).outlineStyle!=='none'})()`),true,'Live provider keyboard focus must be visible');
 await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
 assert.equal(await evaluate("document.querySelector('#vm-show-owned').getAttribute('aria-pressed')"),'true');
 assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').hidden"),false);
 assert.equal(await evaluate(`document.querySelector('${root}').hidden`),true);
 assert.deepEqual(await evaluate(`(()=>{const model=vmExecutionWorkspace.owned.controller.model();return {session:model.view?.session??null,pending:model.pending.map(command=>command.action)}})()`),{session:null,pending:[]},'Provider activation must not create or request a live fixture');
 await key('Tab','Tab',{windowsVirtualKeyCode:9,modifiers:8});assert.equal(await evaluate('document.activeElement.id'),'vm-show-execution');
 await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
 assert.equal(await evaluate("document.querySelector('#vm-show-execution').getAttribute('aria-pressed')"),'true');
 assert.equal(await evaluate("document.querySelector('#vm-show-owned').getAttribute('aria-pressed')"),'false');
 assert.equal(await evaluate(`document.querySelector('${root}').hidden`),false);
 assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').hidden"),true);
 await key('Tab','Tab',{windowsVirtualKeyCode:9});assert.equal(await evaluate('document.activeElement.id'),'vm-show-owned');
 await key('Tab','Tab',{windowsVirtualKeyCode:9});assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Import VM execution trace');
 const ensureVisible=async selector=>{
  const owner=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw Error('Missing VM control');const p=e.closest('.vm-context-panel');return {layout:document.querySelector('${root}').dataset.layout,context:p?.id.replace('vm-context-panel-',''),state:!!e.closest('.vm-step-inspector'),listing:!!e.closest('.vm-execution-listing'),navigation:!!e.closest('.vm-execution-navigation'),navigationOpen:document.querySelector('${root}').dataset.navigationOpen==='true'};})()`);
  if(owner.navigation&&owner.layout!=='wide'&&!owner.navigationOpen)await click(root+' .vm-navigation-toggle');
  if(owner.context){
   if(owner.layout==='narrow')await click(root+' [data-vm-panel="evidence"]');
   else if(await evaluate(`document.querySelector('${root} .vm-execution-context').hidden`))await click(root+' .vm-context-launchers button:nth-child('+({occurrences:1,validation:2,comparison:3,audit:4}[owner.context])+')');
   await click('#vm-context-tab-'+owner.context);
  }else if(owner.layout==='narrow'&&(owner.state||owner.listing))await click(root+' [data-vm-panel="'+(owner.state?'state':'listing')+'"]');
 };
 const importFile=async(value,label)=>{const selector='[aria-label="'+label+'"]';await ensureVisible(selector);await evaluate(`(async()=>{const input=document.querySelector(${JSON.stringify(selector)});const data=new DataTransfer();data.items.add(new File([${JSON.stringify(JSON.stringify(value))}],'owned.json',{type:'application/json'}));input.files=data.files;input.dispatchEvent(new Event('change',{bubbles:true}));const deadline=performance.now()+5000;while(input.value){if(performance.now()>deadline)throw Error('Import did not settle');await new Promise(r=>setTimeout(r,10));}})()`);};
 const visibleClick=async selector=>{await ensureVisible(selector);await evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'nearest'})`);await click(selector);};
 const keyboardActivate=async selector=>{await ensureVisible(selector);await key('Tab','Tab',{windowsVirtualKeyCode:9});await evaluate(`document.querySelector(${JSON.stringify(selector)}).focus()`);await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});};
 const text=()=>evaluate(`document.querySelector('${root}').textContent`);
 await viewport(360,740);await click(root+' [data-vm-panel="evidence"]');await click(root+' .vm-context-header > button');assert.equal(await evaluate('document.activeElement.getAttribute("data-vm-panel")'),'listing');await click(root+' [data-vm-panel="evidence"]');await viewport(1440,900);await click(root+' .vm-context-header > button');assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Filter retained execution rows');
 await click(root+' .vm-context-launchers button:last-child');await viewport(360,740);await click(root+' .vm-context-header > button');assert.equal(await evaluate('document.activeElement.getAttribute("data-vm-panel")'),'listing');await viewport(1440,900);
 await importFile(trace,'Import VM execution trace');assert((await text()).includes('Exact input-file SHA-256:'));assert((await text()).includes('backend claim: native (not authenticated)'));assert.equal(await evaluate(`document.querySelectorAll('${root} img').length`),0);
 await visibleClick(root+' .vm-execution-navigation details summary');await visibleClick(root+' [data-vm-step="0"]');
 await visibleClick(root+' [data-vm-location="registers:0"] button');assert((await text()).includes('Observed snapshots for registers:0'));
 await ensureVisible('[aria-label="Execution step"]');await selectRenderedOption({evaluate,click,key,selector:'[aria-label="Execution step"]',index:1,keyboardFocus:true});assert((await text()).includes('Step 1 · opcode 09'));assert((await text()).includes('"sequence": 1'));
 await importFile({format:'reb-vm-hypothesis-v1',trace_id:'owned-ui',mappings:[{opcode:'03',operation:'register_const'},{opcode:'09',operation:'halt'}]},'Validate opcode hypothesis file');assert((await text()).includes('matched: step 0'));assert((await text()).includes('matched: step 1'));assert((await text()).includes('"status": "matched"'));
 await importFile({bad:true},'Import VM execution trace');assert((await text()).includes('Previous valid trace remains visible'));assert.equal(await evaluate("document.querySelector('[aria-label=\"Execution step\"]').value"),'1');assert((await text()).includes('Supplied trace: owned-ui'));
 await ensureVisible('[aria-label="Execution step"]');await selectRenderedOption({evaluate,click,key,selector:'[aria-label="Execution step"]',index:0,keyboardFocus:true});
 await importFile(trace,'Import comparison VM trace');
 await ensureVisible('[aria-label="Comparison execution step"]');await selectRenderedOption({evaluate,click,key,selector:'[aria-label="Comparison execution step"]',index:1,keyboardFocus:true});
 const byText=async (label,keyboard=false)=>{const selector=await evaluate(`(()=>{const b=[...document.querySelectorAll('${root} button')].find(b=>b.textContent===${JSON.stringify(label)});b.setAttribute('data-vm-test-action','active');return '${root} [data-vm-test-action="active"]';})()`);if(keyboard){
  await ensureVisible(selector);
  await evaluate(`(()=>{const button=document.querySelector(${JSON.stringify(selector)});if(button.disabled)throw Error('Keyboard page control is disabled');button.focus();if(document.activeElement!==button)throw Error('Keyboard page control did not receive focus');})()`);
  if(keyboard==='Space')await key(' ','Space',{windowsVirtualKeyCode:32,text:' ',unmodifiedText:' '});
  else await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
  // Page controls are replaced only after their real keyboard activation rerenders.
  // Await that transition before asserting rows; never substitute a DOM click.
  await evaluate(`(async()=>{const deadline=performance.now()+3000;while(document.querySelector(${JSON.stringify(selector)})){if(performance.now()>deadline)throw Error('Keyboard page activation did not rerender');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
 }else await visibleClick(selector);await evaluate(`document.querySelector('${root} [data-vm-test-action="active"]')?.removeAttribute('data-vm-test-action')`);};
 await byText('Compare selected steps');assert((await text()).includes('Manual pair: primary step 0 ↔ comparison step 1'));
 await importFile({bad:true},'Import comparison VM trace');assert((await text()).includes('Both previous valid traces'));assert((await text()).includes('Manual pair:'));
 const wrong=JSON.parse(JSON.stringify(trace));wrong.steps=[wrong.steps[0]];wrong.steps[0].after.registers[0]=8;await importFile(wrong,'Import VM execution trace');
 await importFile({format:'reb-vm-hypothesis-v1',trace_id:'owned-ui',mappings:[{opcode:'03',operation:'register_const'}]},'Validate opcode hypothesis file');
 await byText('contradicted: step 0');assert((await text()).includes('registers:0: expected 7; observed 8'));
 for(const [width,height] of [[1440,900],[600,800],[360,740]]){
  await viewport(width,height);await visibleClick('[aria-label="Show changed locations only"]');await key('Tab');
  assert.equal(await evaluate(`(()=>{const e=document.querySelector('${root}');return e.scrollWidth<=e.clientWidth+1&&document.querySelector('.vm-grid').getBoundingClientRect().bottom<=innerHeight+1})()`),true);
  assert.equal(await evaluate(`(()=>{const e=document.activeElement,r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&s.outlineStyle!=='none'})()`),true,'Keyboard focus must be visible');
  assert.equal(await evaluate(`(()=>{const rows=[...document.querySelectorAll('${root} .vm-state-row')];return rows.length>0&&rows.every(row=>[...row.children].every(e=>e.scrollWidth<=e.clientWidth+1))})()`),true,'State cells must remain readable');
  {
   const theme=await evaluate("document.documentElement.getAttribute('data-theme')");
   for(const palette of ['dark','light']){
    await evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(palette)})`);
    const colors=await evaluate(`(()=>{const rgb=s=>s.match(/[0-9.]+/g).slice(0,3).map(Number),lum=s=>{const a=rgb(s).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return a[0]*.2126+a[1]*.7152+a[2]*.0722;},ratio=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);return ['.vm-file-control','.vm-clear-traces','.vm-listing-row[aria-selected="true"]','.vm-state-row[data-changed="true"]'].map(selector=>{const n=document.querySelector('#vm-semantics-workflow '+selector);if(!n)throw Error('Missing color role '+selector);const c=getComputedStyle(n);return {selector,contrast:ratio(c.color,c.backgroundColor),pseudoContrast:selector.includes('vm-listing-row')?ratio(getComputedStyle(n.querySelector('span'),'::before').color,c.backgroundColor):99,background:c.backgroundColor};});})()`);
    assert(colors.every(role=>role.contrast>=4.5&&(width===1440||role.pseudoContrast>=4.5)),`${palette} rendered VM text contrast must be at least4.5`);
    assert.equal(new Set(colors.map(role=>role.background)).size,4,'Action, clear, selection and changed roles must remain visually distinct');
    await screenshot(`vm-semantic-colors-${palette}-${width}.png`);
   }
   await evaluate(theme===null?"document.documentElement.removeAttribute('data-theme')":`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)})`);
  }
  await screenshot(`vm-semantics-${width}.png`);
 }
 const sparse=JSON.parse(JSON.stringify(trace));sparse.coverage={complete:false,dropped_steps:3,limitations:['synthetic gaps']};sparse.steps[1].sequence=4;sparse.steps[0].before.memory=[[0,0],[9,null]];sparse.steps[0].after.memory=[[9,null],[20,0]];sparse.steps[0].before.stack=[0];sparse.steps[0].after.stack=[];
 await importFile(sparse,'Import VM execution trace');assert((await text()).includes('Gap after selected step: next retained sequence 4'));assert((await text()).includes('absent (not recorded)'));await byText('Next retained step');assert((await text()).includes('Gap before selected step: previous retained sequence 0'));
 const maximal=(offset=0)=>{const t=JSON.parse(JSON.stringify(trace));t.identity.trace_id='maximal:'+offset;t.steps=[{sequence:0,opcode:'03',operands:[63,7],instruction_size:1,before:{pc:0,halted:false,registers:Array(64).fill(0),stack:Array(128).fill(0),memory:Array.from({length:256},(_,i)=>[offset+i,0])},after:{pc:1,halted:false,registers:[...Array(63).fill(0),8],stack:Array(128).fill(0),memory:Array.from({length:256},(_,i)=>[offset+256+i,0])},evidence_refs:['maximal:0']}];return t;};
 await importFile(maximal(),'Import VM execution trace');if(await evaluate("document.querySelector('[aria-label=\"Show changed locations only\"]').checked"))await visibleClick('[aria-label="Show changed locations only"]');
 await byText('Next state locations page');assert((await text()).includes('65–128 of 706; page 2 of 12'));assert.equal(await evaluate('document.activeElement.textContent'),'Next state locations page');
 await importFile({format:'reb-vm-hypothesis-v1',trace_id:'maximal:0',mappings:[{opcode:'03',operation:'register_const'}]},'Validate opcode hypothesis file');await byText('contradicted: step 0');assert.equal(await evaluate('document.activeElement.textContent'),'registers:63');assert.equal(await evaluate(`document.querySelectorAll('${root} .vm-mismatch').length`),64);await byText('Next hypothesis mismatches page',true);assert.equal(await evaluate('document.activeElement.textContent'),'Next hypothesis mismatches page');
 await importFile(maximal(512),'Import comparison VM trace');await byText('Compare selected steps');
 for(let page=1;page<20;page++)await byText('Next comparison locations page');assert((await text()).includes('1217–1218 of 1218; page 20 of 20'));assert.equal(await evaluate('document.activeElement.textContent'),'Previous comparison locations page');
 for(const [width,height] of [[1440,900],[600,800],[360,740]]){await viewport(width,height);await byText('Previous comparison locations page',width===600?'Space':'Enter');assert.equal(await evaluate(`document.querySelectorAll('${root} [data-vm-comparison-location]').length`),64);assert.equal(await evaluate(`document.querySelectorAll('${root} [data-vm-location]').length`),64);assert.equal(await evaluate(`(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return e.textContent==='Previous comparison locations page'&&r.left>=0&&r.right<=innerWidth&&getComputedStyle(e).outlineStyle!=='none'})()`),true);await screenshot(`vm-semantics-max-pages-${width}.png`);}
 // Exercise the new hierarchy without weakening any pre-existing VM or Traffic assertions.
 await viewport(1440,900);
 const listingTrace=JSON.parse(JSON.stringify(trace));listingTrace.identity.trace_id='listing:owned';listingTrace.steps=Array.from({length:256},(_,sequence)=>({sequence,opcode:'03',operands:[0,7],instruction_size:3,before:{pc:7,halted:false,registers:[7],stack:[0],memory:[[0,0],[9,null]]},after:{pc:7,halted:false,registers:[7],stack:[0],memory:[[0,0],[9,null]]},evidence_refs:['listing:'+sequence]}));
 await importFile(listingTrace,'Import VM execution trace');
 await byText('Close evidence');
 assert.equal(await evaluate(`document.querySelector('${root}').dataset.layout`),'wide');
 assert.equal(await evaluate(`getComputedStyle(document.querySelector('${root} .vm-execution-body')).gridRowStart`),'3');
 assert.equal(await evaluate(`document.querySelector('.vm-findings-workspace').hidden`),true);
 assert.deepEqual(await evaluate(`Array.from(document.querySelectorAll('${root} .vm-pane-heading > span'),e=>e.textContent)`),['Navigation','Execution','State']);
 assert.equal(await evaluate(`document.querySelectorAll('${root} .vm-execution-toolbar').length`),1);
 assert.equal(await evaluate(`document.querySelectorAll('${root} .vm-evidence-strip, ${root} .vm-mobile-toolbar').length`),0);
 assert.equal(await evaluate(`document.querySelector('${root} .vm-listing-pager').parentElement.className`),'vm-listing-footer');
 assert.equal(await evaluate(`(()=>{const body=document.querySelector('${root} .vm-listing-body'),box=body.getBoundingClientRect();return [...body.querySelectorAll('[data-vm-sequence]')].filter(row=>{const r=row.getBoundingClientRect();return r.top>=box.top&&r.bottom<=box.bottom;}).length>=12;})()`),true,'Wide listing must show at least12 complete rows');
 assert.equal(await evaluate(`document.querySelectorAll('${root} [data-vm-sequence]').length`),64);
 await byText('Next retained steps page');assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'0');
 await evaluate(`document.querySelector('${root} [data-vm-sequence="64"]').focus()`);await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
 assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'64','Enter on an off-page tab stop must inspect that exact row');
 await byText('Back to selected row');await key('ArrowUp','ArrowUp',{windowsVirtualKeyCode:38});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'63');
 await key('ArrowDown','ArrowDown',{windowsVirtualKeyCode:40});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'64');
 await key('End','End',{windowsVirtualKeyCode:35});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'255');
 await key('Home','Home',{windowsVirtualKeyCode:36});await key('PageDown','PageDown',{windowsVirtualKeyCode:34});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'64');
 await key('PageUp','PageUp',{windowsVirtualKeyCode:33});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'0');
 assert((await text()).includes('3 adapter-defined PC units'));assert((await text()).includes('Full instruction bytes unavailable'));
 const focusedVisible=()=>evaluate(`(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&getComputedStyle(e).outlineStyle!=='none';})()`);
 for(const [width,height] of [[1440,900],[1024,768],[760,560],[600,800],[360,740]]){
  await viewport(width,height);await visibleClick('#vm-state-tab-registers');
  assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'0');
  assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth&&document.querySelector('${root}').scrollWidth<=document.querySelector('${root}').clientWidth+1`),true);
  await screenshot(`vm-execution-listing-${width}.png`);
 }
 for(const width of [1024,1440]){await viewport(360,740);await click(root+' [data-vm-panel="listing"]');await evaluate(`document.querySelector('${root} [data-vm-panel="listing"]').focus()`);await viewport(width,900);await evaluate(`(async()=>{const deadline=performance.now()+3000;while(document.activeElement!==document.querySelector('[aria-label="Filter retained execution rows"]')){if(performance.now()>deadline)throw Error('Resize left focus on hidden mobile panel control');await new Promise(resolve=>setTimeout(resolve,10));}})()`);assert(await focusedVisible());}
 await viewport(1024,768);await visibleClick(root+' .vm-navigation-toggle');await key('Tab','Tab',{windowsVirtualKeyCode:9});await evaluate(`document.querySelector('${root} .vm-navigation-close').focus()`);await viewport(1440,900);await evaluate(`(async()=>{const deadline=performance.now()+3000;while(document.activeElement!==document.querySelector('${root} .vm-execution-navigation')){if(performance.now()>deadline)throw Error('Resize left focus on hidden navigation control');await new Promise(resolve=>setTimeout(resolve,10));}})()`);assert(await focusedVisible());await viewport(1024,768);await click(root+' .vm-navigation-close');
 for(const width of [1024,360]){
  await viewport(width,740);await click(root+' .vm-navigation-toggle');
  await click(root+' .vm-execution-navigation > button:not(.vm-navigation-close)');
  assert.equal(await evaluate(`document.querySelector('${root}').dataset.navigationOpen`),'false');
  assert.equal(await evaluate('document.activeElement.id'),'vm-context-tab-audit');
  assert(await focusedVisible());await click(root+' .vm-context-header > button');
  assert.equal(await evaluate(`document.querySelector('${root}').dataset.navigationOpen`),'true');
  assert.equal(await evaluate('document.activeElement.textContent'),'Provenance and limits');
  assert(await focusedVisible());await click(root+' .vm-navigation-close');
 }
 await viewport(1024,740);await click(root+' .vm-navigation-toggle');
 await click(root+' .vm-execution-navigation > button:not(.vm-navigation-close)');
 await viewport(360,740);
 await evaluate(`(async()=>{const deadline=performance.now()+3000;while(document.activeElement?.getAttribute('data-vm-panel')!=='evidence'){if(performance.now()>deadline)throw Error('Resize did not restore visible Evidence panel focus');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
 assert(await focusedVisible(),'Resized-open provenance must retain a visible focus outline');
 await click(root+' .vm-context-header > button');
 assert.equal(await evaluate('document.activeElement.textContent'),'Provenance and limits');
 assert(await focusedVisible());await click(root+' .vm-navigation-close');
 await viewport(360,740);await visibleClick('#vm-state-tab-instruction');
 if(await evaluate(`document.querySelector('[aria-label="Show changed locations only"]').checked`))await visibleClick('[aria-label="Show changed locations only"]');
 await keyboardActivate(root+' [data-vm-location="registers:0"] button');assert.equal(await evaluate(`document.querySelector('${root}').dataset.panel`),'evidence');assert.equal(await evaluate('document.activeElement.id'),'vm-context-tab-occurrences');
 await keyboardActivate(root+' .vm-context-header > button');assert.equal(await evaluate(`document.querySelector('${root}').dataset.panel`),'state');assert.equal(await evaluate('document.activeElement.textContent'),'registers:0');assert(await focusedVisible());
 await keyboardActivate(root+' [data-vm-location="registers:0"] button');await keyboardActivate(root+' .vm-occurrence [data-vm-step="1"]');assert.equal(await evaluate(`document.querySelector('${root}').dataset.panel`),'state');assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'1');assert(await focusedVisible());
 await visibleClick(root+' .vm-execution-navigation details summary');await keyboardActivate(root+' .vm-execution-navigation [data-vm-step="0"]');assert.equal(await evaluate(`document.querySelector('${root}').dataset.navigationOpen`),'false');assert.equal(await evaluate(`document.querySelector('${root}').dataset.panel`),'state');assert(await focusedVisible());
 await viewport(1440,900);await visibleClick('#vm-state-tab-instruction');
 // A normalized owned finding uses the unchanged real finding/source render path.
 await click('#vm-show-findings');
 await evaluate(`(async()=>{const content='// Owned VM finding source fixture\\n',bytes=new TextEncoder().encode(content),digest=await crypto.subtle.digest('SHA-256',bytes);state.artifacts=[{protocol_version:1,artifact_id:'9876',session_id:'11',navigation_id:'13',frame_id:'17',parent_artifact_id:'0',creator_event_id:'19',execution_context_id:'23',capture_origin:'dynamic_javascript',kind:'javascript',url:'https://fixture.invalid/vm-owned.js',mime_type:'text/javascript',byte_size:bytes.length,sha256:Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join(''),sensitive:false,content}];state.vmFindings=[{findingId:'owned-finding',investigationId:'owned-investigation',sourceArtifactId:'9876',hostRuntime:'javascript',confidence:'candidate',analysis:{vm_score:20,anti_bot_score:0,status:'partial',evidence_families:['owned fixture'],observations:Array.from({length:40},(_,i)=>({rule_id:'owned:'+i,detail:'Owned deterministic observation '+i,weight:1})),coverage:{residual_unknowns:['Synthetic fixture only']}}}];state.selectedVmFindingId='owned-finding';renderVmLab();})()`);
 await visibleClick('#vm-detail button');assert.equal(await evaluate('state.selectedArtifactId'),'9876');assert.equal(await evaluate(`document.querySelector('#screen-sources').hidden`),false);
 await evaluate(`showScreen('vm',elements.requestVmCandidates)`);assert.equal(await evaluate(`document.querySelector('#vm-findings-workspace').hidden`),false);
 await evaluate(`window.vmFindingNodes={list:document.querySelector('#vm-list').firstChild,detail:document.querySelector('#vm-detail').firstChild};document.querySelector('#vm-detail').scrollTop=150;window.vmFindingScroll=document.querySelector('#vm-detail').scrollTop;`);
 await click('#vm-show-execution');await click('#vm-show-findings');
 assert.equal(await evaluate(`vmFindingNodes.list===document.querySelector('#vm-list').firstChild&&vmFindingNodes.detail===document.querySelector('#vm-detail').firstChild&&document.querySelector('#vm-detail').scrollTop===vmFindingScroll&&state.selectedVmFindingId==='owned-finding'`),true,'Findings mode switch preserves DOM, exact identity and scroll');
 await click('#vm-show-execution');assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'0');
 // A short CSS viewport reproduces the available layout at 200% desktop zoom.
 // This is a layout regression; the separate actual browser-zoom gate remains.
 await viewport(720,450);await evaluate(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);await visibleClick(root+' [data-vm-panel="listing"]');
 await evaluate(`document.querySelector('${root} .vm-listing-row').scrollIntoView({block:'start'})`);
 const shortLayout=await evaluate(`(()=>{const workspace=document.querySelector('${root}'),body=workspace.querySelector('.vm-listing-body'),w=workspace.getBoundingClientRect(),b=body.getBoundingClientRect(),screen=document.querySelector('#screen-vm').getBoundingClientRect();const top=Math.max(0,w.top,b.top,screen.top),bottom=Math.min(innerHeight,w.bottom,b.bottom,screen.bottom);return{bodyHeight:body.clientHeight,scrollable:workspace.scrollHeight>workspace.clientHeight,rows:[...body.querySelectorAll('.vm-listing-row')].filter(row=>{const r=row.getBoundingClientRect();return r.top>=top-1&&r.bottom<=bottom+1;}).length,horizontal:document.documentElement.scrollWidth>innerWidth};})()`);
 assert(shortLayout.bodyHeight>=240,'Short viewport retains a usable listing body');assert(shortLayout.scrollable,'Short viewport has intentional VM-local vertical scrolling');assert(shortLayout.rows>=2,'At least two complete execution rows are visible after scrolling at 720×450');assert.equal(shortLayout.horizontal,false);
 await screenshot('vm-execution-short-height-720x450.png');
 await key('Tab','Tab',{windowsVirtualKeyCode:9});await evaluate(`document.querySelector('${root} .vm-listing-row[data-vm-sequence="0"]').focus()`);await key('ArrowDown','ArrowDown',{windowsVirtualKeyCode:40});assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'1');assert(await focusedVisible());
 assert.equal(await evaluate(`(()=>{const r=document.activeElement.getBoundingClientRect(),w=document.querySelector('${root}').getBoundingClientRect(),screen=document.querySelector('#screen-vm').getBoundingClientRect(),body=document.querySelector('${root} .vm-listing-body').getBoundingClientRect();return r.top>=Math.max(0,w.top,screen.top,body.top)-1&&r.bottom<=Math.min(innerHeight,w.bottom,screen.bottom,body.bottom)+1;})()`),true,'Focused row is inside every short-height scroll viewport');
 await visibleClick(root+' [data-vm-panel="state"]');await visibleClick('#vm-state-tab-registers');assert(await evaluate(`document.querySelector('${root} .vm-inspector-body').clientHeight>=200`));
 await key('Tab','Tab',{windowsVirtualKeyCode:9});await evaluate(`(()=>{const cell=document.querySelector('${root} [data-vm-location="registers:0"]');cell.scrollIntoView({block:'center'});cell.querySelector('button').focus({preventScroll:true});})()`);
 assert(await focusedVisible());assert.equal(await evaluate(`(()=>{const cell=document.querySelector('${root} [data-vm-location="registers:0"]'),r=cell.getBoundingClientRect(),w=document.querySelector('${root}').getBoundingClientRect(),screen=document.querySelector('#screen-vm').getBoundingClientRect(),body=document.querySelector('${root} .vm-inspector-body').getBoundingClientRect();return cell.textContent.includes('registers:0')&&r.top>=Math.max(0,w.top,screen.top,body.top)-1&&r.bottom<=Math.min(innerHeight,w.bottom,screen.bottom,body.bottom)+1;})()`),true,'A complete exact state cell is readable inside the short viewport');await screenshot('vm-execution-short-height-state-720x450.png');
 await viewport(1440,900);await evaluate(`document.querySelector('${root}').scrollTop=0`);
 const consoleWasOpen=await evaluate(`document.querySelector('#native-console-toggle').getAttribute('aria-expanded')==='true'`);
 if(!consoleWasOpen)await click('#native-console-toggle');
 assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth&&document.querySelector('${root}').getBoundingClientRect().bottom<=innerHeight`),true);await screenshot('vm-execution-console-open.png');
 if(!consoleWasOpen)await click('#native-console-toggle');
 // Record the reviewed owned compatibility fixture, then use the ordinary file
 // import path. This is real fixture execution, never upstream or site capture.
 await importFile(recordCompatibilityDemo(),'Import VM execution trace');
 await ensureVisible('[aria-label="Execution step"]');await selectRenderedOption({evaluate,click,key,selector:'[aria-label="Execution step"]',index:6,keyboardFocus:true});
 await visibleClick('#vm-state-tab-memory');
 assert.equal(await evaluate(`document.querySelector('${root} [data-vm-location="memory:64"]').getAttribute('data-changed')`),'true');
 assert.match(await evaluate(`document.querySelector('${root} [data-vm-location="memory:64"]').textContent`),/42/);
 assert.equal(await evaluate(`document.querySelectorAll('${root} .vm-listing-row').length`),14);
 assert.match(await evaluate(`document.querySelector('${root} .vm-context-summary').textContent`),/owned-16bit-compatibility-demo/);
 await screenshot('vm-compatibility-demo-memory-store-desktop.png');
 await ensureVisible('[aria-label="Execution step"]');await selectRenderedOption({evaluate,click,key,selector:'[aria-label="Execution step"]',index:13,keyboardFocus:true});
 await visibleClick('#vm-state-tab-instruction');assert.match(await text(),/halted/);
 await screenshot('vm-compatibility-demo-halted-desktop.png');
 await byText('Clear imported traces');assert.equal(await evaluate("document.querySelector('[aria-label=\"Execution step\"]').disabled"),true);assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Import VM execution trace');
 return {status:'passed',checks:['real file digest import','opcode support → exact step → cell','manually paired comparison','invalid comparison retains both traces','counterexample → exact step → mismatch','inert payload','clear and focus','readable cells and visible keyboard focus at three viewports','full-height retained listing and64-row keyboard paging','exact Instruction/Registers/Stack/Memory tabs','360px cell/occurrence/support focus restoration','Findings DOM/source/scroll round trip','1440/1024/760/600/360 layouts and Console geometry','720×450 short-height vertical scroll and keyboard inspection']};
}
