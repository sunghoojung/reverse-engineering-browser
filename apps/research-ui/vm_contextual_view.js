/* Per-build declarations and supplied runtime evidence stay inert and local. */
function mountVmContextual(root, model = vmContextual, evidenceModel = vmContextualEvidence) {
  const node = (tag, text = '') => { const element = document.createElement(tag); element.textContent = text; return element; };
  const button = (text, action) => { const element = node('button', text); element.type = 'button'; element.className = 'secondary-button'; element.addEventListener('click', action); return element; };
  const inputs = {}, fileInputs = {}, reads = {definition:0,image:0,evidence:0}, pending = new Set();
  let generation = 0, busy = false, report = null, linked = null, selected = null, page = 0, diagnosticPage = 0, referencePage = 0, jumpPage = 0, auditPage = 0;
  const size = 32, toolbar = node('div'), notice = node('p'), summary = node('p'), listing = node('div'), detail = node('div'), diagnostics = node('div');
  toolbar.className = 'vm-contextual-toolbar'; notice.setAttribute('role','status'); notice.setAttribute('aria-live','polite');
  listing.className = 'vm-contextual-list'; detail.className = 'vm-contextual-detail'; detail.tabIndex = 0; detail.setAttribute('aria-label','Selected decoder context');
  const label = (offset,state) => `${offset === null ? '?' : '0x'+offset.toString(16)} / state ${state ?? 'unknown'}`;
  const update = () => { analyze.disabled = !inputs.definition || !inputs.image || pending.size > 0 || busy; analyze.textContent = busy ? 'Analyzing…' : 'Analyze build'; };
  const field = (name,value) => { detail.append(node('p',`${name}: ${value}`)); };
  function select(id, focus = false) { selected = id; referencePage = jumpPage = 0; draw(); if (focus) detail.focus(); }
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
    listing.replaceChildren(); detail.replaceChildren(); diagnostics.replaceChildren();
    summary.textContent = report ? `${report.identity.build_id} · ${report.coverage.instruction_count} decoded contexts · ${report.coverage.undecoded_bytes} undecoded bytes · ${report.diagnostics.length} stopped contexts` : 'Import a build definition and hash-bound image. Evidence is optional. No imported code runs here.';
    if (!report) return;
    listing.append(node('h2','PC + decoder state'));
    page = Math.min(page,Math.max(0,Math.ceil(report.instructions.length/size)-1));
    paginate(listing,report.instructions.length,page,next=>{page=next;draw();},'contexts');
    for (const instruction of report.instructions.slice(page*size,(page+1)*size)) {
      const row = button(`${label(instruction.offset,instruction.decoder_state)} · ${instruction.mnemonic} · ${instruction.raw_opcode}`,()=>select(instruction.id,true));
      row.setAttribute('data-vm-contextual-id',instruction.id); row.setAttribute('aria-pressed',String(selected===instruction.id)); listing.append(row);
    }
    const instruction = report.instructions.find(item=>item.id===selected);
    detail.append(node('h2',instruction ? label(instruction.offset,instruction.decoder_state) : 'No decoded context selected'));
    if (instruction) {
      field('Instruction',`${instruction.mnemonic} · ${instruction.bytes_hex} · ${instruction.size} bytes`);
      field('Next declared decoder state',instruction.next_decoder_state ?? 'unknown');
      field('Semantics',`${instruction.semantics_status}; supplied declaration, unverified`);
      detail.append(node('h3','Ordered macro operations'));
      const operations = node('ol'); for (const op of instruction.operations) operations.append(node('li',`${op.operation}(${op.args.join(', ')})`)); detail.append(operations);
      detail.append(node('h3','Instruction-linked abstract pseudocode'));
      for (const line of instruction.pseudocode) detail.append(node('pre',line.text ?? 'Unknown semantics'));
      detail.append(node('h3','Declared outgoing edges'));
      const declared = report.cfg.edges.filter(edge=>edge.from_instruction_id===selected);
      if (!declared.length) detail.append(node('p','No declared outgoing edge.'));
      for (const edge of declared) detail.append(node('p',`${edge.kind} → ${label(edge.to_offset,edge.to_decoder_state)} · ${edge.status} · declared_static`));
      detail.append(node('h3','Supplied observed jumps'));
      const observed = linked?.observed_edges.filter(edge=>edge.from_instruction_id===selected) ?? [];
      if (!observed.length) detail.append(node('p','No linked explicit jump evidence. Absence does not establish absence of execution.'));
      jumpPage = Math.min(jumpPage, Math.max(0, Math.ceil(observed.length/size)-1));
      paginate(detail,observed.length,jumpPage,next=>{jumpPage=next;draw();},'linked jumps');
      for (const edge of observed.slice(jumpPage*size,(jumpPage+1)*size)) detail.append(node('p',`${edge.event_id} #${edge.sequence} → ${label(edge.to_offset,edge.to_decoder_state)} · source ${edge.from_status}, destination ${edge.to_status} · ${edge.status} · ${edge.declared_relation}`));
      detail.append(node('h3','Runtime evidence references'));
      const refs = linked?.links.filter(link=>link.instruction_id===selected) ?? [];
      referencePage = Math.min(referencePage, Math.max(0, Math.ceil(refs.length/size)-1));
      paginate(detail,refs.length,referencePage,next=>{referencePage=next;draw();},'event references');
      for (const ref of refs.slice(referencePage*size,(referencePage+1)*size)) detail.append(node('p',`${ref.event_id} · sequence ${ref.sequence} · ${ref.status}`));
    }
    detail.append(node('h3','Input identity and limits'));
    for (const [key,value] of Object.entries(report.identity)) field(key,value);
    for (const [key,value] of Object.entries(report.provenance)) field(key,value ?? 'Unavailable: no exact source text');
    for (const kind of ['definition','image','evidence']) if (inputs[kind]) field(`${kind} input`,inputs[kind].name);
    if (linked) {
      field('Evidence reference',`${linked.evidence.capture_id} / ${linked.evidence.run_id} / ${linked.evidence.context_id}`);
      field('Mapping provenance',JSON.stringify(linked.evidence.mapping_provenance));
      field('Evidence gaps',JSON.stringify(linked.evidence.gaps));
      field('Unlinked events',linked.links.filter(item=>item.instruction_id===null).length);
      detail.append(node('h3','All supplied event links, including unresolved'));
      auditPage = Math.min(auditPage, Math.max(0, Math.ceil(linked.links.length/size)-1));
      paginate(detail,linked.links.length,auditPage,next=>{auditPage=next;draw();},'all evidence links');
      for (const link of linked.links.slice(auditPage*size,(auditPage+1)*size)) {
        const edge=linked.observed_edges.find(item=>item.event_id===link.event_id);
        detail.append(node('pre',JSON.stringify({link,observed_edge:edge??null})));
      }
    }
    for (const warning of [...report.warnings,...(linked?.warnings ?? [])]) detail.append(node('p',warning));
    const issues = [...report.diagnostics,...(linked?.diagnostics ?? [])];
    diagnostics.append(node('h2','Unknowns and evidence diagnostics'));
    diagnosticPage = Math.min(diagnosticPage,Math.max(0,Math.ceil(issues.length/size)-1));
    paginate(diagnostics,issues.length,diagnosticPage,next=>{diagnosticPage=next;draw();},'diagnostics');
    for (const issue of issues.slice(diagnosticPage*size,(diagnosticPage+1)*size)) diagnostics.append(node('pre',JSON.stringify(issue)));
  }
  function invalidate() { generation++; busy=false; report=null; linked=null; selected=null; page=diagnosticPage=referencePage=jumpPage=auditPage=0; draw(); }
  async function importFile(kind,file) {
    if (!file || !Object.hasOwn(reads,kind)) return;
    const owner=++reads[kind]; generation++; busy=false; pending.add(kind); update();
    try {
      if (!Number.isSafeInteger(file.size) || file.size<1 || file.size>1048576) throw Error('Choose a JSON file from 1 byte to 1 MiB');
      const bytes=await file.arrayBuffer(); if (!bytes.byteLength || bytes.byteLength>1048576) throw Error('File exceeds the 1 MiB bound or is empty');
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
      if(owner!==reads[kind])return;
      (kind==='definition'?model.parseDefinition:kind==='image'?model.parseImage:evidenceModel.parseEvidence)(text);
      inputs[kind]={text,name:String(file.name||kind+'.json').slice(0,256)}; invalidate(); notice.textContent=`${kind} loaded. Choose Analyze build.`;
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
      notice.textContent='Contextual analysis ready. Declared semantics and supplied observations remain unverified; vendor compatibility is not established.';
    } catch(error) { if(owner===generation)notice.textContent=`Analysis refused: ${error.message}. No code executed.`; }
    finally { if(owner===generation){busy=false;update();} }
  }
  for(const kind of ['definition','image','evidence']) {
    const control=node('label',`${kind==='evidence'?'Optional runtime evidence':kind} JSON `),input=node('input');input.type='file';input.accept='.json,application/json';input.setAttribute('aria-label',`Import contextual ${kind} JSON`);
    input.addEventListener('change',()=>importFile(kind,input.files?.[0]));fileInputs[kind]=input;control.append(input);toolbar.append(control);
  }
  const analyze=button('Analyze build',analyzeInputs);
  const clear=button('Clear',()=>{for(const kind of Object.keys(reads)){reads[kind]++;delete inputs[kind];fileInputs[kind].value='';}pending.clear();invalidate();update();notice.textContent='Contextual inputs cleared.';fileInputs.definition.focus();});
  const removeEvidence=button('Remove evidence',()=>{reads.evidence++;pending.delete('evidence');delete inputs.evidence;fileInputs.evidence.value='';invalidate();update();notice.textContent='Evidence removed. Analyze declarations again.';});
  toolbar.append(analyze,removeEvidence,clear);
  const intro=node('p','Supported: hash-bound per-build declarative decoding, explicit decoder contexts and ordered macro operations. Runtime links use supplied evidence only. Vendor recovery, encrypted images, seed/key extraction and anti-debug bypass are unsupported.');
  const panes=node('div');panes.className='vm-contextual-panes';panes.append(listing,detail);root.append(toolbar,notice,intro,summary,panes,diagnostics);draw();update();
  return {importFile,analyzeInputs,fileInputs,analyze,clear,removeEvidence,notice,summary,listing,detail,diagnostics,select,getReport:()=>report,getLinked:()=>linked,getSelected:()=>selected};
}
if(typeof module==='object'&&module?.exports)module.exports={mountVmContextual};
