/* Per-build declarations and supplied runtime evidence stay inert and local. */
function mountVmContextual(root, model = vmContextual, evidenceModel = vmContextualEvidence) {
  const node = (tag, text = '') => { const element = document.createElement(tag); element.textContent = text; return element; };
  const button = (text, action) => { const element = node('button', text); element.type = 'button'; element.className = 'secondary-button'; element.addEventListener('click', action); return element; };
  const inputs = {}, fileInputs = {}, inputStates = {}, reads = {definition:0,image:0,evidence:0}, pending = new Set();
  let generation = 0, busy = false, report = null, linked = null, selected = null, page = 0, diagnosticPage = 0, referencePage = 0, jumpPage = 0, auditPage = 0, activeTab = 'instruction';
  const size = 32, toolbar = node('div'), notice = node('p'), summary = node('p'), listing = node('div'), detail = node('div'), diagnostics = node('div');
  toolbar.className = 'vm-contextual-toolbar vm-contextual-imports'; notice.setAttribute('role','status'); notice.setAttribute('aria-live','polite');
  listing.className = 'vm-contextual-list'; diagnostics.className = 'vm-contextual-diagnostics'; detail.className = 'vm-contextual-detail'; detail.tabIndex = 0; detail.setAttribute('aria-label','Selected decoder context');
  const label = (offset,state) => `${offset === null ? '?' : '0x'+offset.toString(16)} / state ${state ?? 'unknown'}`;
  const update = () => { analyze.disabled = !inputs.definition || !inputs.image || pending.size > 0 || busy; analyze.textContent = busy ? 'Analyzing…' : 'Analyze build'; };
  let detailBody = detail, detailPanels = {};
  const field = (name,value) => { detailBody.append(node('p',`${name}: ${value}`)); };
  const filter = node('input'); filter.type = 'search'; filter.className = 'vm-review-filter'; filter.placeholder = 'Find PC, state or instruction'; filter.setAttribute('aria-label', 'Filter decoder contexts');
  const filtered = () => (report?.instructions ?? []).filter(instruction => !filter.value.trim() || [label(instruction.offset,instruction.decoder_state), instruction.mnemonic, instruction.raw_opcode, instruction.id].join(' ').toLowerCase().includes(filter.value.trim().toLowerCase()));
  function select(id, focus = false, reveal = false) {
    if (!report?.instructions.some(instruction => instruction.id === id)) return;
    selected = id; referencePage = jumpPage = 0;
    if (reveal) { filter.value = ''; page = Math.floor(filtered().findIndex(instruction => instruction.id === id) / size); }
    draw(); if (focus) detail.focus();
  }
  filter.addEventListener('input', () => { page = 0; draw(); });
  const reveal = button('Reveal selected context', () => select(selected, true, true));
  root.addEventListener('vm-workspace-query', event => { const rows=filtered(),index=rows.findIndex(item=>item.id===selected); Object.assign(event.detail,{search:true,previous:rows.length>0&&(index<0||index>0),next:rows.length>0&&(index<0||index<rows.length-1)}); });
  root.addEventListener('vm-workspace-search', () => filter.focus());
  for (const [event, direction] of [['vm-workspace-next',1],['vm-workspace-previous',-1]]) root.addEventListener(event, () => {
    const rows = filtered(), index = rows.findIndex(instruction => instruction.id === selected), next = index < 0 ? (direction > 0 ? 0 : rows.length - 1) : index + direction;
    if (rows[next]) { page = Math.floor(next / size); select(rows[next].id, true); }
  });
  const tabs = [['instruction','Instruction'],['pseudocode','Pseudocode'],['edges','Edges'],['evidence','Evidence'],['inputs','Inputs and limits']];
  function section(key) {
    if (detailPanels[key]) { detailBody = detailPanels[key]; return; }
    const panel = node('section'); detailPanels[key] = panel; panel.hidden = activeTab !== key; panel.setAttribute('role','tabpanel'); panel.id = 'vm-contextual-panel-' + key; panel.setAttribute('aria-labelledby','vm-contextual-tab-' + key); detail.append(panel); detailBody = panel;
  }
  function showTab(key, focus = false) { activeTab = key; draw(); if (focus) root.querySelector(`[data-contextual-tab="${key}"]`)?.focus(); }

  function paginate(target, count, current, action, noun) {
    const pages = Math.max(1,Math.ceil(count/size)), bar = node('div'); bar.className = 'vm-contextual-toolbar';
    const move = direction => {
      action(current+direction);
      const preferred=root.querySelector(`[data-vm-contextual-page="${noun}:${direction}"]`);
      const fallback=root.querySelector(`[data-vm-contextual-page="${noun}:${-direction}"]`);
      (preferred&&!preferred.disabled?preferred:fallback)?.focus();
    };
    const previous = button(`Previous ${noun}`,()=>move(-1)), next = button(`Next ${noun}`,()=>move(1));
    previous.setAttribute('data-vm-contextual-page',`${noun}:-1`); next.setAttribute('data-vm-contextual-page',`${noun}:1`);
    previous.disabled = current === 0; next.disabled = current+1 >= pages;
    bar.append(previous,node('span',`Page ${current+1} of ${pages} · ${count} ${noun}`),next); target.append(bar);
  }
  function draw() {
    listing.replaceChildren(); detail.replaceChildren(); diagnostics.replaceChildren(); detailPanels = {};
    summary.textContent = report ? `${report.identity.build_id} · ${report.coverage.instruction_count} decoded contexts · ${report.coverage.undecoded_bytes} undecoded bytes · ${report.diagnostics.length} stopped contexts` : 'Import a build definition and hash-bound image. Evidence is optional. No imported code runs here.';
    reveal.disabled = !selected;
    if (!report) { listing.append(node('h2','PC + decoder state'),node('p','Analyze a definition and image to list decoder contexts.')); detail.append(node('h2','Selected context'),node('p','Select a decoded context to inspect its declared operations and supplied evidence.')); return; }
    listing.append(node('h2','PC + decoder state'));
    const contexts = filtered();
    page = Math.min(page,Math.max(0,Math.ceil(contexts.length/size)-1));
    listing.append(node('p',`${contexts.length}/${report.instructions.length} contexts${selected && !contexts.some(item=>item.id===selected) ? ' · selection hidden by filter' : ''}`));
    paginate(listing,contexts.length,page,next=>{page=next;draw();},'contexts');
    if (!contexts.length) listing.append(node('p','No matching contexts. Clear the filter or reveal the selected context.'));
    for (const instruction of contexts.slice(page*size,(page+1)*size)) {
      const row = button(`${label(instruction.offset,instruction.decoder_state)} · ${instruction.mnemonic} · ${instruction.raw_opcode}`,()=>select(instruction.id,true));
      row.setAttribute('data-vm-contextual-id',instruction.id); row.setAttribute('aria-pressed',String(selected===instruction.id));
      const visible=contexts.slice(page*size,(page+1)*size); row.tabIndex=selected===instruction.id || !visible.some(item=>item.id===selected)&&instruction===visible[0] ? 0 : -1;
      row.addEventListener('keydown', event => {
        if(event.isComposing||event.altKey||event.ctrlKey||event.metaKey)return;
        if(!['ArrowDown','ArrowUp','Home','End'].includes(event.key))return;
        event.preventDefault(); const index=contexts.findIndex(item=>item.id===instruction.id), next=event.key==='Home'?0:event.key==='End'?contexts.length-1:index+(event.key==='ArrowDown'?1:-1);
        if(!contexts[next])return; page=Math.floor(next/size);select(contexts[next].id);root.querySelector(`[data-vm-contextual-id="${contexts[next].id}"]`)?.focus();
      }); listing.append(row);
    }
    const instruction = report.instructions.find(item=>item.id===selected);
    detail.append(node('h2',instruction ? label(instruction.offset,instruction.decoder_state) : 'No decoded context selected'));
    const tabBar = node('div'); tabBar.className = 'vm-review-tabs'; tabBar.setAttribute('role','tablist'); tabBar.setAttribute('aria-label','Contextual detail');
    for (const [key, title] of tabs) {
      const control = button(title, () => showTab(key,true)); control.id = 'vm-contextual-tab-' + key; control.setAttribute('data-contextual-tab',key); control.setAttribute('role','tab'); control.setAttribute('aria-controls','vm-contextual-panel-' + key); control.setAttribute('aria-selected',String(activeTab === key)); control.tabIndex = activeTab === key ? 0 : -1;
      control.addEventListener('keydown', event => { if(event.isComposing||event.altKey||event.ctrlKey||event.metaKey)return; const index = tabs.findIndex(item=>item[0]===key); let next; if(event.key==='ArrowRight')next=(index+1)%tabs.length; else if(event.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length; else if(event.key==='Home')next=0; else if(event.key==='End')next=tabs.length-1; if(next!==undefined){event.preventDefault();showTab(tabs[next][0],true);} });
      tabBar.append(control);
    }
    detail.append(tabBar); for (const [key] of tabs) section(key); section('instruction');
    if (instruction) {
      field('Instruction',`${instruction.mnemonic} · ${instruction.bytes_hex} · ${instruction.size} bytes`);
      field('Next declared decoder state',instruction.next_decoder_state ?? 'unknown');
      field('Semantics',`${instruction.semantics_status}; supplied declaration, unverified`);
      detailBody.append(node('h3','Ordered macro operations'));
      const operations = node('ol'); for (const op of instruction.operations) operations.append(node('li',`${op.operation}(${op.args.join(', ')})`)); detailBody.append(operations);
      section('pseudocode');
      detailBody.append(node('h3','Instruction-linked abstract pseudocode'));
      detailBody.append(node('p','Declared abstract operations, not a decompiler or proof of runtime equivalence.'));
      for (const line of instruction.pseudocode) detailBody.append(node('pre',line.text ?? 'Unknown semantics'));
      section('edges');
      detailBody.append(node('h3','Declared outgoing edges'));
      const declared = report.cfg.edges.filter(edge=>edge.from_instruction_id===selected);
      if (!declared.length) detailBody.append(node('p','No declared outgoing edge.'));
      for (const edge of declared) {
        const destination = report.instructions.find(item=>item.offset === edge.to_offset && item.decoder_state === edge.to_decoder_state);
        const text = `${edge.kind} → ${label(edge.to_offset,edge.to_decoder_state)} · ${edge.status} · declared_static`;
        if (destination) { const link = button(text, () => select(destination.id,true,true)); link.setAttribute('data-contextual-destination',destination.id); detailBody.append(link); }
        else detailBody.append(node('p',text));
      }
      detailBody.append(node('h3','Supplied observed jumps'));
      const observed = linked?.observed_edges.filter(edge=>edge.from_instruction_id===selected) ?? [];
      if (!observed.length) detailBody.append(node('p','No linked explicit jump evidence. Absence does not establish absence of execution.'));
      jumpPage = Math.min(jumpPage, Math.max(0, Math.ceil(observed.length/size)-1));
      paginate(detailBody,observed.length,jumpPage,next=>{jumpPage=next;draw();},'linked jumps');
      for (const edge of observed.slice(jumpPage*size,(jumpPage+1)*size)) detailBody.append(node('p',`${edge.event_id} #${edge.sequence} → ${label(edge.to_offset,edge.to_decoder_state)} · source ${edge.from_status}, destination ${edge.to_status} · ${edge.status} · ${edge.declared_relation}`));
      section('evidence');
      detailBody.append(node('h3','Runtime evidence references'));
      const refs = linked?.links.filter(link=>link.instruction_id===selected) ?? [];
      referencePage = Math.min(referencePage, Math.max(0, Math.ceil(refs.length/size)-1));
      paginate(detailBody,refs.length,referencePage,next=>{referencePage=next;draw();},'event references');
      for (const ref of refs.slice(referencePage*size,(referencePage+1)*size)) detailBody.append(node('p',`${ref.event_id} · sequence ${ref.sequence} · ${ref.status}`));
    }
    section('inputs');
    detailBody.append(node('h3','Input identity and limits'));
    for (const [key,value] of Object.entries(report.identity)) field(key,value);
    for (const [key,value] of Object.entries(report.provenance)) field(key,value ?? 'Unavailable: no exact source text');
    for (const kind of ['definition','image','evidence']) if (inputs[kind]) field(`${kind} input`,inputs[kind].name);
    if (linked) {
      field('Evidence reference',`${linked.evidence.capture_id} / ${linked.evidence.run_id} / ${linked.evidence.context_id}`);
      field('Mapping provenance',JSON.stringify(linked.evidence.mapping_provenance));
      field('Evidence gaps',JSON.stringify(linked.evidence.gaps));
      field('Unlinked events',linked.links.filter(item=>item.instruction_id===null).length);
      section('evidence');
      detailBody.append(node('h3','All supplied event links, including unresolved'));
      auditPage = Math.min(auditPage, Math.max(0, Math.ceil(linked.links.length/size)-1));
      paginate(detailBody,linked.links.length,auditPage,next=>{auditPage=next;draw();},'all evidence links');
      for (const link of linked.links.slice(auditPage*size,(auditPage+1)*size)) {
        const edge=linked.observed_edges.find(item=>item.event_id===link.event_id);
        detailBody.append(node('pre',JSON.stringify({link,observed_edge:edge??null})));
      }
    }
    section('inputs');
    for (const warning of [...report.warnings,...(linked?.warnings ?? [])]) detailBody.append(node('p',warning));
    const issues = [...report.diagnostics,...(linked?.diagnostics ?? [])];
    diagnostics.append(node('h2','Unknowns and evidence diagnostics'));
    diagnosticPage = Math.min(diagnosticPage,Math.max(0,Math.ceil(issues.length/size)-1));
    paginate(diagnostics,issues.length,diagnosticPage,next=>{diagnosticPage=next;draw();},'diagnostics');
    for (const issue of issues.slice(diagnosticPage*size,(diagnosticPage+1)*size)) diagnostics.append(node('pre',JSON.stringify(issue)));
  }
  function invalidate() { generation++; busy=false; report=null; linked=null; selected=null; page=diagnosticPage=referencePage=jumpPage=auditPage=0; filter.value=''; draw(); }
  async function importFile(kind,file) {
    if (!file || !Object.hasOwn(reads,kind)) return;
    const owner=++reads[kind]; generation++; busy=false; pending.add(kind); update();
    try {
      if (!Number.isSafeInteger(file.size) || file.size<1 || file.size>1048576) throw Error('Choose a JSON file from 1 byte to 1 MiB');
      const bytes=await file.arrayBuffer(); if (!bytes.byteLength || bytes.byteLength>1048576) throw Error('File exceeds the 1 MiB bound or is empty');
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
      if(owner!==reads[kind])return;
      (kind==='definition'?model.parseDefinition:kind==='image'?model.parseImage:evidenceModel.parseEvidence)(text);
      inputs[kind]={text,name:String(file.name||kind+'.json').slice(0,256)}; inputStates[kind].textContent=inputs[kind].name; invalidate(); notice.textContent=`${kind} loaded. Choose Analyze build.`;
    } catch(error) { if(owner===reads[kind])notice.textContent=`Import refused: ${error.message}. Previous valid inputs and analysis retained.`; }
    finally { if(owner===reads[kind]){pending.delete(kind);fileInputs[kind].value='';update();} }
  }
  async function analyzeInputs() {
    if(analyze.disabled)return;
    const owner=++generation; busy=true;update();notice.textContent='Checking input hashes and contextual declarations…';
    try {
      const result=inputs.evidence ? await evidenceModel.link(inputs.definition.text,inputs.image.text,inputs.evidence.text) : await model.analyze(inputs.definition.text,inputs.image.text);
      if(owner!==generation)return;
      linked=inputs.evidence?result:null;report=linked?linked.analysis:result;selected=report.instructions[0]?.id??null;page=diagnosticPage=referencePage=jumpPage=auditPage=0;draw();
      imports.open=false; filter.focus(); notice.textContent='Contextual analysis ready. Declared semantics and supplied observations remain unverified; vendor compatibility is not established.';
    } catch(error) { if(owner===generation)notice.textContent=`Analysis refused: ${error.message}. No code executed.`; }
    finally { if(owner===generation){busy=false;update();} }
  }
  for(const kind of ['definition','image','evidence']) {
    const control=node('label',`${kind==='evidence'?'Optional runtime evidence':kind==='definition'?'Definition':'Image'} JSON `),input=node('input');input.type='file';input.accept='.json,application/json';input.setAttribute('aria-label',`Import contextual ${kind} JSON`);
    input.addEventListener('change',()=>importFile(kind,input.files?.[0]));fileInputs[kind]=input;inputStates[kind]=node('span','No file selected');control.append(input,inputStates[kind]);toolbar.append(control);
  }
  const analyze=button('Analyze build',analyzeInputs); analyze.className = 'secondary-button vm-tool-primary';
  const clear=button('Clear',()=>{for(const kind of Object.keys(reads)){reads[kind]++;delete inputs[kind];fileInputs[kind].value='';inputStates[kind].textContent='No file selected';}pending.clear();invalidate();update();notice.textContent='Contextual inputs cleared.';imports.open=true;fileInputs.definition.focus();});
  const removeEvidence=button('Remove evidence',()=>{reads.evidence++;pending.delete('evidence');delete inputs.evidence;fileInputs.evidence.value='';inputStates.evidence.textContent='No file selected';invalidate();update();notice.textContent='Evidence removed. Analyze declarations again.';});
  const actions=node('div'); actions.className='vm-contextual-actions'; actions.append(analyze,removeEvidence,clear);
  const intro=node('p','Supported: hash-bound per-build declarative decoding, explicit decoder contexts and ordered macro operations. Runtime links use supplied evidence only. Vendor recovery, encrypted images, seed/key extraction and anti-debug bypass are unsupported.');
  const heading=node('h2','Contextual decoding'); heading.className='vm-tool-title';
  const limits=node('details'); limits.className='vm-tool-editor'; limits.append(node('summary','Supported inputs and limits'),intro);
  const panes=node('div');panes.className='vm-contextual-panes vm-review-workbench'; const navigation=node('section'); navigation.className='vm-review-listing'; navigation.append(filter,reveal,listing); detail.className += ' vm-review-inspector'; panes.append(navigation,detail); const imports=node('details'); imports.className='vm-review-imports'; imports.open=true; imports.append(node('summary','Definition, image and optional evidence inputs'),toolbar,actions); root.append(heading,summary,imports,notice,panes,diagnostics,limits);draw();update();
  return {importFile,analyzeInputs,fileInputs,analyze,clear,removeEvidence,notice,summary,listing,detail,diagnostics,select,getReport:()=>report,getLinked:()=>linked,getSelected:()=>selected,filter,reveal,showTab};
}
if(typeof module==='object'&&module?.exports)module.exports={mountVmContextual};
