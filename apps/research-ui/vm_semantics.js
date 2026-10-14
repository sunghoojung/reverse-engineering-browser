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
  return {parse,trace,inspect,validate,predict,effects,operations};
})();
if(typeof module==='object'&&module?.exports)module.exports=vmSemantics;

function mountVmSemantics(root) {
  let current=null,serial=0,hypothesisSerial=0;
  const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
  const title=node('h2','Opcode and state workflow'),notice=node('p','Import a local execution trace. Existing VM detection remains below. Supplied traces do not establish native capture or general semantic equivalence.');
  notice.setAttribute('role','status');
  const input=node('input');input.type='file';input.accept='.json,application/json';input.setAttribute('aria-label','Import VM execution trace');
  const hypothesis=node('input');hypothesis.type='file';hypothesis.accept='.json,application/json';hypothesis.setAttribute('aria-label','Validate opcode hypothesis file');hypothesis.disabled=true;
  const selector=node('select');selector.setAttribute('aria-label','Execution step');selector.disabled=true;
  const details=node('pre'),map=node('pre'),validation=node('pre');for(const e of [details,map,validation]){e.tabIndex=0;e.style.whiteSpace='pre-wrap';e.style.overflowWrap='anywhere';e.style.maxHeight='24rem';e.style.overflow='auto';}
  const clear=node('button','Clear imported trace');clear.type='button';clear.className='secondary-button';
  const read=async file=>{if(!file||file.size>1048576)throw Error('Select a JSON file up to 1 MiB');const bytes=await file.arrayBuffer();if(bytes.byteLength>1048576)throw Error('File exceeds 1 MiB');return vmSemantics.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));};
  const display=()=>{if(!current)return;const step=current.steps[Number(selector.value)];if(!step)return;details.textContent=JSON.stringify({sequence:step.sequence,opcode:step.opcode,operands:step.operands,before:step.before,after:step.after,observed_changes:vmSemantics.effects(step),reads:'unknown',evidence_refs:step.evidence_refs},null,2);};
  input.addEventListener('change',async()=>{const owner=++serial;try{const parsed=vmSemantics.trace(await read(input.files[0]));if(owner!==serial)return;current=parsed;selector.replaceChildren(...current.steps.map((s,i)=>{const e=node('option',`Step ${s.sequence} · PC ${s.before.pc} · opcode ${s.opcode}`);e.value=String(i);return e;}));selector.value='0';selector.disabled=false;hypothesis.disabled=false;validation.textContent='No hypothesis validation has been requested.';const report=vmSemantics.inspect(current);map.textContent=JSON.stringify({identity:report.identity,trust:report.trust,coverage:report.coverage,opcode_candidates:report.opcodes},null,2);notice.textContent=`Loaded supplied trace ${current.identity.trace_id}; ${current.steps.length} steps. Candidate semantics are inferred, never established by a name match.`;display();}catch(error){if(owner===serial)notice.textContent=`Import refused: ${error.message}. ${current?'Previous valid trace remains visible.':'No trace loaded.'}`;}finally{if(owner===serial)input.value='';}});
  hypothesis.addEventListener('change',async()=>{const owner=serial,request=++hypothesisSerial,trace=current;try{const parsed=await read(hypothesis.files[0]);if(owner!==serial||request!==hypothesisSerial||trace!==current)return;validation.textContent=JSON.stringify(vmSemantics.validate(current,parsed),null,2);}catch(error){if(owner===serial&&request===hypothesisSerial)validation.textContent=`Validation refused: ${error.message}`;}finally{if(owner===serial&&request===hypothesisSerial)hypothesis.value='';}});
  selector.addEventListener('change',display);
  clear.addEventListener('click',()=>{serial++;current=null;selector.replaceChildren();selector.disabled=true;hypothesis.disabled=true;input.value='';hypothesis.value='';details.textContent='';map.textContent='';validation.textContent='';notice.textContent='Imported trace cleared. Existing findings are unchanged.';input.focus();});
  root.append(title,notice,input,hypothesis,clear,node('h3','Opcode evidence and candidates'),map,node('h3','State changes'),selector,details,node('h3','Differential validation'),validation);
  return {clear,selector,input,hypothesis,notice,details,map,validation};
}
if(typeof document!=='undefined'){const root=document.querySelector('#vm-semantics-workflow');if(root)mountVmSemantics(root);}
