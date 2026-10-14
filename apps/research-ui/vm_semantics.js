/* Bounded supplied VM traces and declarative hypotheses. Never execute captured code. */
const vmParseJSON = typeof module==='object'&&module?.exports&&typeof require==='function' ? require('./captured_client.js').capturedClientJSON : (...args)=>capturedClientJSON(...args);
const vmSemantics = (() => {
  const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const exact = (v, keys) => object(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
  const fail = message => { throw Error(message); };
  const integer = v => Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
  const count = v => Number.isSafeInteger(v) && v >= 0;
  const value = v => v === null || integer(v);
  const label = v => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v);
  const canonical = v => Array.isArray(v) ? v.map(canonical) : object(v) ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])) : v;
  const equal = (a,b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
  const clone = v => JSON.parse(JSON.stringify(v));
  const operations = ['stack_const','stack_add','register_const','register_add','load','store','jump','branch_zero','halt'];
  function state(v) {
    if (!exact(v,['pc','halted','registers','stack','memory']) || !count(v.pc) || v.pc > 65535 || typeof v.halted !== 'boolean' ||
        !Array.isArray(v.registers) || v.registers.length > 64 || !v.registers.every(value) ||
        !Array.isArray(v.stack) || v.stack.length > 128 || !v.stack.every(value) ||
        !Array.isArray(v.memory) || v.memory.length > 256) fail('Invalid bounded VM state');
    let previous = -1;
    for (const cell of v.memory) {
      if (!Array.isArray(cell) || cell.length !== 2 || !count(cell[0]) || cell[0] > 65535 || cell[0] <= previous || !value(cell[1])) fail('Memory must contain sorted unique bounded addresses');
      previous = cell[0];
    }
    return v;
  }
  function parse(text) {
    if(typeof text!=='string'||new TextEncoder().encode(text).length>1048576)fail('JSON exceeds 1 MiB');
    const numbers=new Map(),document=vmParseJSON(text,numbers);
    for(const token of numbers.values())if(!/^(0|-?[1-9][0-9]*)$/.test(token)||!Number.isSafeInteger(Number(token)))fail('VM numeric fields require exact canonical safe integers');
    return document;
  }
  function trace(input) {
    let nodes=0;
    const check=(v,depth)=>{if(++nodes>600000||depth>64)fail('Trace structure exceeds bounds');if(typeof v==='number'){if(!Number.isSafeInteger(v)||Object.is(v,-0))fail('Trace numbers must be exact safe integers');}else if(Array.isArray(v)){for(const item of v)check(item,depth+1);}else if(object(v)){for(const item of Object.values(v))check(item,depth+1);}else if(v!==null&&!['string','boolean'].includes(typeof v))fail('Trace must contain JSON values only');};
    check(input,0);
    const serialized=JSON.stringify(input);
    if(typeof serialized!=='string'||new TextEncoder().encode(serialized).length>1048576)fail('Trace exceeds 1 MiB');
    const v = JSON.parse(serialized);
    if (!exact(v,['format','identity','architecture','coverage','steps']) || v.format !== 'reb-vm-trace-v1' || !['stack','register'].includes(v.architecture) ||
        !exact(v.identity,['trace_id','investigation_id','finding_id','artifact_id','artifact_sha256','scope_id','backend']) ||
        !['fixture','native','cdp','external'].includes(v.identity.backend) || typeof v.identity.artifact_sha256!=='string' || !/^[a-f0-9]{64}$/.test(v.identity.artifact_sha256) ||
        !['trace_id','investigation_id','finding_id','artifact_id','scope_id'].every(k=>label(v.identity[k])) ||
        !exact(v.coverage,['complete','dropped_steps','limitations']) || typeof v.coverage.complete !== 'boolean' || !count(v.coverage.dropped_steps) ||
        !Array.isArray(v.coverage.limitations) || v.coverage.limitations.length > 16 || !v.coverage.limitations.every(x=>typeof x==='string'&&x.length<=256) ||
        !Array.isArray(v.steps) || v.steps.length > 256 || !v.steps.length) fail('Invalid reb-vm-trace-v1 identity, coverage or bounds');
    if (v.coverage.complete && v.coverage.dropped_steps) fail('Complete coverage cannot include dropped steps');
    let previous;
    for (const step of v.steps) {
      if (!exact(step,['sequence','opcode','operands','instruction_size','before','after','evidence_refs']) || !count(step.sequence) ||
          typeof step.opcode!=='string' || !/^[a-f0-9]{2}(?:[a-f0-9]{2}){0,7}$/.test(step.opcode) || !Array.isArray(step.operands) || step.operands.length>8 || !step.operands.every(integer) ||
          !Number.isInteger(step.instruction_size) || step.instruction_size<1 || step.instruction_size>64 ||
          !Array.isArray(step.evidence_refs) || step.evidence_refs.length<1 || step.evidence_refs.length>8 || !step.evidence_refs.every(label)) fail('Invalid bounded VM step');
      state(step.before);state(step.after);
      if (previous && step.sequence <= previous.sequence) fail('Steps must have increasing unique sequence IDs');
      if (previous && step.sequence === previous.sequence+1 && !equal(previous.after,step.before)) fail('Adjacent supplied states disagree');
      if (previous && step.sequence !== previous.sequence+1 && v.coverage.complete) fail('Complete coverage cannot contain sequence gaps');
      if (step.before.halted) fail('A halted state cannot execute a step');
      previous=step;
    }
    return v;
  }
  function predict(step,operation,architecture) {
    const next=clone(step.before), operands=step.operands;
    const unsupported=()=>fail('Unsupported or unknown operand/state');
    const arity=n=>{if(operands.length!==n)unsupported();};
    const register=i=>{if(!count(i)||i>=next.registers.length||next.registers[i]===null)unsupported();return next.registers[i];};
    const destination=i=>{if(!count(i)||i>=next.registers.length)unsupported();return i;};
    const address=i=>{if(!count(i)||i>65535)unsupported();return i;};
    const stack=()=>{if(!next.stack.length||next.stack.at(-1)===null)unsupported();return next.stack.pop();};
    next.pc+=step.instruction_size;
    if (operation.startsWith('stack_')&&architecture!=='stack'||operation.startsWith('register_')&&architecture!=='register')unsupported();
    switch(operation) {
      case 'stack_const':arity(1);if(next.stack.length>=128)unsupported();next.stack.push(operands[0]);break;
      case 'stack_add':arity(0);{const right=stack(),left=stack();next.stack.push((left+right)|0);}break;
      case 'register_const':arity(2);next.registers[destination(operands[0])]=operands[1];break;
      case 'register_add':arity(3);{const left=register(operands[1]),right=register(operands[2]);next.registers[destination(operands[0])]=(left+right)|0;}break;
      case 'load':arity(2);{const cell=next.memory.find(x=>x[0]===address(operands[1]));if(!cell||cell[1]===null)unsupported();next.registers[destination(operands[0])]=cell[1];}break;
      case 'store':arity(2);{const a=address(operands[0]),v=register(operands[1]),cell=next.memory.find(x=>x[0]===a);if(cell)cell[1]=v;else{if(next.memory.length>=256)unsupported();next.memory.push([a,v]);next.memory.sort((a,b)=>a[0]-b[0]);}}break;
      case 'jump':arity(1);next.pc=address(operands[0]);break;
      case 'branch_zero':arity(2);if(register(operands[0])===0)next.pc=address(operands[1]);else address(operands[1]);break;
      case 'halt':arity(0);next.pc=step.before.pc;next.halted=true;break;
      default:unsupported();
    }
    if(next.pc>65535)unsupported();
    return next;
  }
  function effects(step) {
    const changes=[];
    for(const key of ['pc','halted'])if(step.before[key]!==step.after[key])changes.push({location:key,before:step.before[key],after:step.after[key]});
    for(const key of ['registers','stack'])for(let i=0;i<Math.max(step.before[key].length,step.after[key].length);i++)if(step.before[key][i]!==step.after[key][i])changes.push({location:key+':'+i,before:step.before[key][i]??null,after:step.after[key][i]??null,before_present:i<step.before[key].length,after_present:i<step.after[key].length});
    const a=new Map(step.before.memory),b=new Map(step.after.memory);
    for(const i of [...new Set([...a.keys(),...b.keys()])].sort((x,y)=>x-y))if(a.has(i)!==b.has(i)||a.get(i)!==b.get(i))changes.push({location:'memory:'+i,before:a.get(i)??null,after:b.get(i)??null,before_present:a.has(i),after_present:b.has(i)});
    return changes;
  }
  const namespaces=['pc','halted','registers','stack','memory'];
  function location(input) {
    if(input==='pc'||input==='halted')return input;
    if(typeof input!=='string'||input.length>12)fail('Expected an exact VM location');
    const match=/^(registers|stack|memory):(0|[1-9][0-9]*)$/.exec(input);
    if(!match)fail('Expected pc, halted, registers:N, stack:N or memory:N');
    const index=Number(match[2]),maximum={registers:63,stack:127,memory:65535}[match[1]];
    if(!count(index)||index>maximum)fail('VM location index exceeds its namespace bounds');
    return input;
  }
  const locationOrder=(a,b)=>{const [as,ai]=a.split(':'),[bs,bi]=b.split(':');return namespaces.indexOf(as)-namespaces.indexOf(bs)||(Number(ai??0)-Number(bi??0));};
  function snapshotCells(snapshot) {
    const cells=new Map(['pc','halted'].map(key=>[key,{present:true,value:snapshot[key]}]));
    for(const key of ['registers','stack'])snapshot[key].forEach((value,index)=>cells.set(key+':'+index,{present:true,value}));
    for(const [address,value] of snapshot.memory)cells.set('memory:'+address,{present:true,value});
    return cells;
  }
  const cellAt=(cells,key)=>cells.get(key)??{present:false,value:null};
  const changed=(a,b)=>a.present!==b.present||a.value!==b.value;
  function observationStatus(a,b) {
    // Availability differs observably, but matched absence/unknown is never value equality.
    if(a.present!==b.present)return 'different';
    if(!a.present||a.value===null||b.value===null)return 'unknown';
    return a.value===b.value?'observed_equal':'different';
  }
  function reportWarnings(v) {
    const warnings=['Supplied identity and origin are not authenticated.',
      'Snapshots establish differences only, not reads, intermediate writes or causal dependence.',
      'A different status can mean supplied observation availability differs, not that runtime values are known to differ.',
      'Unknown or absent cells do not establish equal values; observed equality is not semantic equivalence.'];
    if(!v.coverage.complete)warnings.push('Trace coverage is incomplete; omitted execution is unknown.');
    if(v.coverage.dropped_steps)warnings.push('Reported dropped steps: '+v.coverage.dropped_steps+'.');
    if(v.steps.some((s,i)=>i>0&&s.sequence!==v.steps[i-1].sequence+1))warnings.push('Retained sequence gaps exist; neighboring retained steps are not necessarily consecutive execution.');
    if(v.coverage.limitations.length)warnings.push('Supplied coverage limitations apply; see coverage.limitations.');
    return warnings;
  }
  function selectedStep(v,sequence) {
    if(!count(sequence)||Object.is(sequence,-0))fail('Expected an exact nonnegative safe-integer sequence');
    const index=v.steps.findIndex(s=>s.sequence===sequence);
    if(index<0)fail('Step not retained');
    const retained=v.steps[index],before=snapshotCells(retained.before),after=snapshotCells(retained.after);
    const cells=[...new Set([...before.keys(),...after.keys()])].sort(locationOrder).map(location=>{
      const a=cellAt(before,location),b=cellAt(after,location);
      return {location,before:a,after:b,changed:changed(a,b),status:observationStatus(a,b)};
    });
    return {format:'reb-vm-step-v1',identity:v.identity,architecture:v.architecture,coverage:v.coverage,
      step:retained,cells,changes:effects(retained),previous_sequence:v.steps[index-1]?.sequence??null,
      next_sequence:v.steps[index+1]?.sequence??null,evidence_refs:retained.evidence_refs,reads:'unknown',
      warnings:reportWarnings(v),equivalence_proven:false};
  }
  function step(input,sequence) {return selectedStep(trace(input),sequence);}
  function compareSteps(leftInput,leftSequence,rightInput,rightSequence) {
    const left=step(leftInput,leftSequence),right=step(rightInput,rightSequence);
    const a=new Map(left.cells.map(cell=>[cell.location,cell])),b=new Map(right.cells.map(cell=>[cell.location,cell]));
    const absent=()=>({present:false,value:null});
    const cells=[...new Set([...a.keys(),...b.keys()])].sort(locationOrder).map(location=>{
      const l=a.get(location),r=b.get(location),left_before=l?.before??absent(),left_after=l?.after??absent(),
        right_before=r?.before??absent(),right_after=r?.after??absent();
      const before_status=observationStatus(left_before,right_before),after_status=observationStatus(left_after,right_after);
      const status=[before_status,after_status].includes('different')?'different':
        [before_status,after_status].includes('unknown')?'unknown':'observed_equal';
      return {location,left_before,left_after,right_before,right_after,before_status,after_status,status};
    });
    const warnings=[...new Set([...left.warnings,...right.warnings]),
      'Only the two explicitly selected sequence IDs are compared; no instruction, location or trace alignment is inferred.',
      'Matching location names compare supplied namespaces and indices, not proven corresponding runtime storage.',
      'PC values and instruction sizes use capture-adapter-defined units; units may differ between traces.',
      'Matching supplied identities, artifact hashes or exact input-file hashes do not establish trace alignment or corresponding execution.'];
    const differingIdentity=['investigation_id','finding_id','artifact_id','artifact_sha256','scope_id'].filter(key=>left.identity[key]!==right.identity[key]);
    if(differingIdentity.length)warnings.push('Supplied evidence identities differ: '+differingIdentity.join(', ')+'. Cross-source correspondence is unproven.');
    if(left.architecture!==right.architecture)warnings.push('Selected traces use different architectures; location names do not establish corresponding semantics.');
    return {format:'reb-vm-step-comparison-v1',left,right,cells,warnings,equivalence_proven:false};
  }
  function occurrences(input,selectedLocation,page=0,pageSize=16) {
    const v=trace(input),key=location(selectedLocation);
    if(!count(page)||Object.is(page,-0)||!Number.isInteger(pageSize)||pageSize<1||pageSize>64||!Number.isSafeInteger(page*pageSize))fail('Expected a nonnegative safe page and page size 1–64');
    const observations=[];
    for(const retained of v.steps) {
      const before=cellAt(snapshotCells(retained.before),key),after=cellAt(snapshotCells(retained.after),key);
      if(before.present||after.present)observations.push({sequence:retained.sequence,opcode:retained.opcode,before,after,
        changed:changed(before,after),status:observationStatus(before,after),evidence_refs:retained.evidence_refs});
    }
    const offset=page*pageSize,items=observations.slice(offset,offset+pageSize);
    return {format:'reb-vm-location-occurrences-v1',identity:v.identity,architecture:v.architecture,coverage:v.coverage,
      location:key,items,total:observations.length,page,page_size:pageSize,
      next_page:offset+items.length<observations.length?page+1:null,
      evidence_refs:[...new Set(items.flatMap(item=>item.evidence_refs))],reads:'unknown',
      warnings:[...reportWarnings(v),'Occurrences are retained snapshot observations, not proven accesses or reads.'],equivalence_proven:false};
  }
  function validate(input,hypotheses) {
    const v=trace(input);
    if(!exact(hypotheses,['format','trace_id','mappings'])||hypotheses.format!=='reb-vm-hypothesis-v1'||hypotheses.trace_id!==v.identity.trace_id||!Array.isArray(hypotheses.mappings)||hypotheses.mappings.length>256)fail('Invalid hypothesis identity or bounds');
    const map=new Map();for(const m of hypotheses.mappings){if(!exact(m,['opcode','operation'])||!operations.includes(m.operation)||!v.steps.some(s=>s.opcode===m.opcode)||map.has(m.opcode))fail('Invalid or duplicate opcode hypothesis');map.set(m.opcode,m.operation);}
    const results=v.steps.map(step=>{const operation=map.get(step.opcode);let expected=null,status='unknown';if(operation){try{expected=predict(step,operation,v.architecture);status=equal(expected,step.after)?'matched':'contradicted';}catch{status='unsupported';}}return {sequence:step.sequence,opcode:step.opcode,operation:operation??null,status,expected,observed:step.after,evidence_refs:step.evidence_refs};});
    return {format:'reb-vm-validation-v1',identity:v.identity,coverage:v.coverage,equivalence_proven:false,results};
  }
  function inspect(input) {
    const v=trace(input),opcodes=[];
    for(const opcode of [...new Set(v.steps.map(x=>x.opcode))]) {
      const steps=v.steps.filter(x=>x.opcode===opcode),candidates=operations.filter(operation=>steps.every(step=>{try{return equal(predict(step,operation,v.architecture),step.after);}catch{return false;}}));
      opcodes.push({opcode,observations:steps.length,sequences:steps.map(x=>x.sequence),candidates,status:candidates.length?'inferred':'unknown'});
    }
    return {format:'reb-vm-inspection-v1',identity:v.identity,architecture:v.architecture,coverage:v.coverage,trust:'supplied trace; origin not authenticated',reads:'unknown; snapshots establish differences only',opcodes,steps:v.steps.map(s=>({sequence:s.sequence,opcode:s.opcode,operands:s.operands,from:s.before.pc,to:s.after.pc,changes:effects(s),evidence_refs:s.evidence_refs})),equivalence_proven:false};
  }
  return {parse,trace,inspect,validate,predict,effects,operations,step,compareSteps,occurrences};
})();
if(typeof module==='object'&&module?.exports)module.exports=vmSemantics;

function mountVmSemantics(root) {
  let current=null,comparison=null,serial=0,comparisonSerial=0,hypothesisSerial=0;
  let statePage=0,comparisonPage=0,validationPage=0,opcodePage=0,mismatchPage=0,alignSelectedLocation=false,selectedCellButton=null;
  const pageSize=64;
  let sourceHash=null,comparisonHash=null,hypothesisHash=null,selectedLocation=null,occurrencePage=0,validationReport=null,pairedReport=null;
  const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
  const button=(text,action)=>{const e=node('button',text);e.type='button';e.className='secondary-button';e.addEventListener('click',action);return e;};
  const fileInput=label=>{const e=node('input');e.type='file';e.accept='.json,application/json';e.setAttribute('aria-label',label);return e;};
  const select=label=>{const e=node('select');e.setAttribute('aria-label',label);e.disabled=true;return e;};
  const pre=()=>{const e=node('pre');e.tabIndex=0;return e;};
  const audit=(label,body)=>{const e=node('details');e.className='vm-audit';e.append(node('summary',label),body);return e;};
  const title=node('h2','Linked execution-state workspace');
  const notice=node('p','Import a local execution trace. Existing detection findings remain below. Supplied traces do not establish native capture or semantic equivalence.');notice.setAttribute('role','status');
  const input=fileInput('Import VM execution trace'),comparisonInput=fileInput('Import comparison VM trace'),hypothesis=fileInput('Validate opcode hypothesis file');hypothesis.disabled=true;
  const selector=select('Execution step'),comparisonSelector=select('Comparison execution step');
  const identity=node('div'),comparisonIdentity=node('div'),map=node('div'),details=pre(),validation=pre(),stateView=node('div'),stepHeading=node('h3'),occurrences=node('div'),validationView=node('div'),comparisonView=node('div');
  stepHeading.tabIndex=-1;stateView.className='vm-state-view';
  const changesOnly=node('input');changesOnly.type='checkbox';changesOnly.checked=true;changesOnly.setAttribute('aria-label','Show changed locations only');
  const changesLabel=node('label');changesLabel.className='vm-inline-control';changesLabel.append(changesOnly,node('span','Changes only'));
  const pager=(target,label,total,page,onPage,focusDirection=null)=>{
    const pages=Math.max(1,Math.ceil(total/pageSize));
    target.append(node('p',`${label}: ${total? page*pageSize+1:0}–${Math.min(total,(page+1)*pageSize)} of ${total}; page ${page+1} of ${pages}.`));
    const previous=button(`Previous ${label.toLowerCase()} page`,()=>onPage(page-1,'previous'));
    const next=button(`Next ${label.toLowerCase()} page`,()=>onPage(page+1,'next'));
    previous.disabled=page===0;next.disabled=page+1>=pages;
    const controls=node('div');controls.className='vm-step-controls';controls.append(previous,next);target.append(controls);
    return ()=>{if(focusDirection)(focusDirection==='previous'?(previous.disabled?next:previous):(next.disabled?previous:next)).focus();};
  };
  const valueText=v=>!v.present?'absent (not recorded)':v.value===null?'unknown (null)':String(v.value);
  const renderIdentity=(target,trace,hash)=>{target.replaceChildren();if(!trace)return;target.append(node('p',`Supplied trace: ${trace.identity.trace_id} · ${trace.architecture} · backend claim: ${trace.identity.backend} (not authenticated)`),node('p',`Exact input-file SHA-256: ${hash}`),node('p',`Supplied artifact SHA-256 claim: ${trace.identity.artifact_sha256}`),node('p',`Coverage: ${trace.coverage.complete?'complete supplied sequence':'incomplete'}; dropped steps: ${trace.coverage.dropped_steps}. ${trace.coverage.limitations.join(' · ')}`));};
  const fillSelector=(target,trace)=>{target.replaceChildren(...trace.steps.map(s=>{const e=node('option',`Step ${s.sequence} · PC ${s.before.pc} · opcode ${s.opcode}`);e.value=String(s.sequence);return e;}));target.value=String(trace.steps[0].sequence);target.disabled=false;};
  const read=async file=>{if(!file||file.size>1048576)throw Error('Select a JSON file up to 1 MiB');const bytes=await file.arrayBuffer();if(bytes.byteLength>1048576)throw Error('File exceeds 1 MiB');const parsed=vmSemantics.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));if(!globalThis.crypto?.subtle)throw Error('SHA-256 requires a secure local workspace');const digest=await crypto.subtle.digest('SHA-256',bytes);return {parsed,hash:Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('')};};
  const invalidatePair=()=>{pairedReport=null;comparisonPage=0;comparisonView.textContent='Choose both exact steps, then Compare selected steps. No automatic alignment is performed.';};
  const go=(sequence,targetLocation=null)=>{selector.value=String(sequence);statePage=0;alignSelectedLocation=true;if(targetLocation){mismatchPage=0;selectedLocation=targetLocation;occurrencePage=0;changesOnly.checked=false;}invalidatePair();display();if(targetLocation&&selectedCellButton)selectedCellButton.focus();else stepHeading.focus();};
  const stepLink=(sequence,label,targetLocation=null)=>{const e=button(label??`Step ${sequence}`,()=>go(sequence,targetLocation));e.setAttribute('data-vm-step',String(sequence));return e;};
  const showOccurrences=(focusDirection=null)=>{
    occurrences.replaceChildren();if(!current||!selectedLocation)return;
    const report=vmSemantics.occurrences(current,selectedLocation,occurrencePage,16);
    occurrences.append(node('h4',`Observed snapshots for ${selectedLocation}`),node('p',`${report.total} retained occurrences; page ${report.page+1}. Presence and snapshot changes do not establish reads or writes.`));
    for(const item of report.items){const row=node('div');row.className='vm-occurrence';row.append(stepLink(item.sequence),node('span',`${valueText(item.before)} → ${valueText(item.after)}${item.changed?' · changed':''}`));occurrences.append(row);}
    const previous=button('Previous occurrences',()=>{occurrencePage--;showOccurrences('previous');}),next=button('Next occurrences',()=>{occurrencePage++;showOccurrences('next');});previous.disabled=occurrencePage===0;next.disabled=(occurrencePage+1)*16>=report.total;occurrences.append(previous,next);if(focusDirection)(focusDirection==='previous'?(previous.disabled?next:previous):(next.disabled?previous:next)).focus();
  };
  const cellRow=(cell)=>{const row=node('div');row.className='vm-state-row';row.setAttribute('data-vm-location',cell.location);const location=button(cell.location,()=>{selectedLocation=cell.location;occurrencePage=0;showOccurrences();});if(selectedLocation===cell.location)selectedCellButton=location;row.append(location,node('span',`Before: ${valueText(cell.before)}`),node('span',`After: ${valueText(cell.after)}`),node('span',cell.changed?'changed':'unchanged snapshot'));return row;};
  const display=(focusDirection=null,focusSection='state')=>{
    if(!current)return;const report=vmSemantics.step(current,Number(selector.value)),step=report.step;
    stepHeading.textContent=`Step ${step.sequence} · opcode ${step.opcode} · PC ${step.before.pc} → ${step.after.pc}`;
    previous.disabled=report.previous_sequence===null;next.disabled=report.next_sequence===null;
    stateView.replaceChildren();selectedCellButton=null;
    for(const warning of report.warnings)stateView.append(node('p',warning));
    if(report.previous_sequence!==null&&report.previous_sequence+1!==step.sequence)stateView.append(node('p',`Gap before selected step: previous retained sequence ${report.previous_sequence}; missing execution is unknown.`));
    if(report.next_sequence!==null&&step.sequence+1!==report.next_sequence)stateView.append(node('p',`Gap after selected step: next retained sequence ${report.next_sequence}; missing execution is unknown.`));
    stateView.append(node('p',`Operands: ${step.operands.length?step.operands.join(', '):'none'}. Reads and intermediate writes: unknown.`));
    const cells=report.cells.filter(c=>!changesOnly.checked||c.changed);
    if(alignSelectedLocation){const index=cells.findIndex(c=>c.location===selectedLocation);if(index>=0)statePage=Math.floor(index/pageSize);alignSelectedLocation=false;}
    statePage=Math.min(statePage,Math.max(0,Math.ceil(cells.length/pageSize)-1));
    stateView.append(node('p',`${cells.length} matching / ${report.cells.length} recorded locations. Availability changes do not necessarily establish different runtime values.`));
    if(selectedLocation&&!cells.some(c=>c.location===selectedLocation))stateView.append(node('p',`Selected location ${selectedLocation} is absent or hidden by Changes only; its retained occurrences remain below.`));
    const restorePageFocus=pager(stateView,'State locations',cells.length,statePage,(page,direction)=>{statePage=page;display(direction);},focusSection==='state'?focusDirection:null);
    let restoreMismatchFocus=()=>{};
    const visibleCells=cells.slice(statePage*pageSize,(statePage+1)*pageSize);
    for(const namespace of ['pc','halted','registers','stack','memory']){const group=visibleCells.filter(c=>c.location.split(':')[0]===namespace);if(group.length){stateView.append(node('h4',namespace));for(const cell of group)stateView.append(cellRow(cell));}}
    if(!cells.length)stateView.append(node('p','No changed locations in these supplied snapshots.'));
    stateView.append(node('p',`Evidence references (unresolved, inert): ${step.evidence_refs.join(', ')}`));
    details.textContent=JSON.stringify({sequence:step.sequence,opcode:step.opcode,operands:step.operands,before:step.before,after:step.after,observed_changes:vmSemantics.effects(step),evidence_refs:step.evidence_refs,warnings:report.warnings},null,2);
    const result=validationReport?.results.find(r=>r.sequence===step.sequence);
    if(result?.status==='contradicted'){
      stateView.append(node('h4','Hypothesis mismatch: expected → observed'));
      const mismatches=vmSemantics.effects({before:result.expected,after:result.observed});mismatchPage=Math.min(mismatchPage,Math.max(0,Math.ceil(mismatches.length/pageSize)-1));restoreMismatchFocus=pager(stateView,'Hypothesis mismatches',mismatches.length,mismatchPage,(page,direction)=>{mismatchPage=page;display(direction,'mismatch');},focusSection==='mismatch'?focusDirection:null);
      for(const cell of mismatches.slice(mismatchPage*pageSize,(mismatchPage+1)*pageSize)){const row=node('p',`${cell.location}: expected ${valueText({present:cell.before_present??true,value:cell.before})}; observed ${valueText({present:cell.after_present??true,value:cell.after})}`);row.className='vm-mismatch';stateView.append(row);}
    }
    showOccurrences();restorePageFocus();restoreMismatchFocus();
  };
  const previous=button('Previous retained step',()=>{if(current){const report=vmSemantics.step(current,Number(selector.value));if(report.previous_sequence!==null)go(report.previous_sequence);}});
  const next=button('Next retained step',()=>{if(current){const report=vmSemantics.step(current,Number(selector.value));if(report.next_sequence!==null)go(report.next_sequence);}});previous.disabled=next.disabled=true;
  const renderMap=(focusDirection=null)=>{
    map.replaceChildren();if(!current)return;const report=vmSemantics.inspect(current);
    map.append(node('p',`Trace ${current.identity.trace_id}: candidate operations are inferred from retained cases only.`));
    const restorePageFocus=pager(map,'Opcodes',report.opcodes.length,opcodePage,(page,direction)=>{opcodePage=page;renderMap(direction);},focusDirection);
    for(const opcode of report.opcodes.slice(opcodePage*pageSize,(opcodePage+1)*pageSize)){
      const group=node('details'),support=node('div');let supportPage=0;
      group.append(node('summary',`Opcode ${opcode.opcode}: ${opcode.candidates.join(', ')||'unknown'} · ${opcode.observations} supporting observations`));
      const renderSupport=(focusDirection=null)=>{
        support.replaceChildren();const restore=pager(support,'Support steps',opcode.sequences.length,supportPage,(page,direction)=>{supportPage=page;renderSupport(direction);},focusDirection);
        for(const sequence of opcode.sequences.slice(supportPage*pageSize,(supportPage+1)*pageSize))support.append(stepLink(sequence,`Support step ${sequence}`));restore();
      };
      renderSupport();group.append(support);map.append(group);
    }
    restorePageFocus();
  };
  const renderValidation=(focusDirection=null)=>{validationView.replaceChildren();if(!validationReport){validationView.textContent='No hypothesis validation has been requested.';return;}validationPage=Math.min(validationPage,Math.max(0,Math.ceil(validationReport.results.length/pageSize)-1));const restorePageFocus=pager(validationView,'Validation steps',validationReport.results.length,validationPage,(page,direction)=>{validationPage=page;renderValidation(direction);},focusDirection);for(const result of validationReport.results.slice(validationPage*pageSize,(validationPage+1)*pageSize)){const row=node('div');row.className='vm-occurrence';row.append(stepLink(result.sequence,`${result.status}: step ${result.sequence}`,result.status==='contradicted'?vmSemantics.effects({before:result.expected,after:result.observed})[0]?.location:null),node('span',`opcode ${result.opcode} · ${result.operation??'no mapping'}`));validationView.append(row);}validation.textContent=JSON.stringify({exact_trace_input_file_sha256:sourceHash,exact_hypothesis_input_file_sha256:hypothesisHash,result:validationReport},null,2);restorePageFocus();};
  input.addEventListener('change',async()=>{const owner=++serial;try{const loaded=await read(input.files[0]),parsed=vmSemantics.trace(loaded.parsed);if(owner!==serial)return;current=parsed;sourceHash=loaded.hash;hypothesisSerial++;validationReport=null;hypothesisHash=null;validation.textContent='';selectedLocation=null;occurrencePage=0;statePage=0;validationPage=0;opcodePage=0;mismatchPage=0;alignSelectedLocation=false;fillSelector(selector,current);hypothesis.disabled=false;renderIdentity(identity,current,sourceHash);renderMap();renderValidation();invalidatePair();notice.textContent=`Loaded supplied trace ${current.identity.trace_id}; ${current.steps.length} steps. Gaps are not inferred transitions. Backend labels do not authenticate origin.`;display();}catch(error){if(owner===serial)notice.textContent=`Import refused: ${error.message}. ${current?'Previous valid trace remains visible.':'No trace loaded.'}`;}finally{if(owner===serial)input.value='';}});
  comparisonInput.addEventListener('change',async()=>{const owner=++comparisonSerial;try{const loaded=await read(comparisonInput.files[0]),parsed=vmSemantics.trace(loaded.parsed);if(owner!==comparisonSerial)return;comparison=parsed;comparisonHash=loaded.hash;fillSelector(comparisonSelector,comparison);renderIdentity(comparisonIdentity,comparison,comparisonHash);invalidatePair();notice.textContent='Comparison trace loaded. Pair two exact retained steps explicitly; matching IDs, PCs or hashes do not align them.';}catch(error){if(owner===comparisonSerial)notice.textContent=`Comparison import refused: ${error.message}. Both previous valid traces remain visible.`;}finally{if(owner===comparisonSerial)comparisonInput.value='';}});
  hypothesis.addEventListener('change',async()=>{const owner=serial,request=++hypothesisSerial,trace=current;try{const loaded=await read(hypothesis.files[0]);if(owner!==serial||request!==hypothesisSerial||trace!==current)return;validationReport=vmSemantics.validate(current,loaded.parsed);hypothesisHash=loaded.hash;validationPage=0;mismatchPage=0;renderValidation();display();}catch(error){if(owner===serial&&request===hypothesisSerial)notice.textContent=`Validation refused: ${error.message}. Previous validation remains visible.`;}finally{if(owner===serial&&request===hypothesisSerial)hypothesis.value='';}});
  selector.addEventListener('change',()=>{statePage=0;alignSelectedLocation=true;invalidatePair();display();});comparisonSelector.addEventListener('change',invalidatePair);changesOnly.addEventListener('change',()=>{statePage=0;display();});
  const renderComparison=(focusDirection=null)=>{
    if(!pairedReport)return;
    comparisonView.replaceChildren(node('p',`Manual pair: primary step ${pairedReport.left.step.sequence} ↔ comparison step ${pairedReport.right.step.sequence}. Observed equality never proves semantic equivalence.`));
    comparisonView.append(node('p',sourceHash===comparisonHash?'Exact input-file digests match; this does not establish semantic equivalence or aligned instructions.':'Exact input-file digests differ; supplied bytes differ, without establishing a semantic execution difference.'));
    comparisonView.append(node('p',`${pairedReport.cells.length} compared location rows. Different can mean different supplied availability; absent cells are not runtime zero.`));
    for(const warning of pairedReport.warnings)comparisonView.append(node('p',warning));
    const restorePageFocus=pager(comparisonView,'Comparison locations',pairedReport.cells.length,comparisonPage,(page,direction)=>{comparisonPage=page;renderComparison(direction);},focusDirection);
    for(const cell of pairedReport.cells.slice(comparisonPage*pageSize,(comparisonPage+1)*pageSize)){
      const row=node('div');row.className='vm-state-row';row.setAttribute('data-vm-comparison-location',cell.location);
      row.append(node('strong',cell.location),node('span',`Primary: ${valueText(cell.left_before)} → ${valueText(cell.left_after)}`),node('span',`Comparison: ${valueText(cell.right_before)} → ${valueText(cell.right_after)}`),node('span',cell.status));comparisonView.append(row);
    }
    const raw=pre();raw.textContent=JSON.stringify({exact_input_file_sha256:{left:sourceHash,right:comparisonHash},report:pairedReport},null,2);comparisonView.append(audit('Raw manual comparison audit',raw));restorePageFocus();
  };
  const compare=button('Compare selected steps',()=>{if(!current||!comparison){notice.textContent='Import a primary and an optional comparison trace first.';return;}pairedReport=vmSemantics.compareSteps(current,Number(selector.value),comparison,Number(comparisonSelector.value));comparisonPage=0;renderComparison();});
  const clearComparison=button('Clear comparison trace',()=>{comparisonSerial++;comparison=null;comparisonHash=null;comparisonInput.value='';comparisonSelector.replaceChildren();comparisonSelector.disabled=true;comparisonIdentity.replaceChildren();invalidatePair();comparisonInput.focus();});
  const clear=button('Clear imported traces',()=>{serial++;comparisonSerial++;hypothesisSerial++;current=comparison=null;sourceHash=comparisonHash=hypothesisHash=null;validationReport=pairedReport=null;selectedLocation=null;occurrencePage=0;statePage=comparisonPage=validationPage=opcodePage=mismatchPage=0;alignSelectedLocation=false;selectedCellButton=null;for(const e of [selector,comparisonSelector]){e.replaceChildren();e.disabled=true;}hypothesis.disabled=true;previous.disabled=next.disabled=true;for(const e of [input,comparisonInput,hypothesis])e.value='';for(const e of [details,map,validation,identity,comparisonIdentity,stateView,stepHeading,occurrences,validationView,comparisonView])e.textContent='';notice.textContent='Imported traces cleared. Existing findings are unchanged.';input.focus();});
  const stepControls=node('div');stepControls.className='vm-step-controls';stepControls.append(selector,previous,next,changesLabel);
  root.append(title,notice,node('label','Primary trace (up to 1 MiB / 256 steps)'),input,clear,identity,node('h3','Opcode evidence and candidates'),map,stepHeading,stepControls,stateView,occurrences,audit('Raw selected-step audit',details),node('h3','Hypothesis counterexamples'),hypothesis,validationView,audit('Raw validation audit',validation),node('h3','Manual two-trace comparison'),node('p','At most two imported traces. Choose each step deliberately. No alignment by PC, sequence, opcode or hash.'),comparisonInput,clearComparison,comparisonIdentity,comparisonSelector,compare,comparisonView);
  invalidatePair();
  return {clear,selector,input,hypothesis,notice,details,map,validation,comparisonInput,comparisonSelector,comparisonView,compare,clearComparison,changesOnly,stateView,occurrences,previous,next,validationView};
}
if(typeof document!=='undefined'){const root=document.querySelector('#vm-semantics-workflow');if(root)mountVmSemantics(root);}
