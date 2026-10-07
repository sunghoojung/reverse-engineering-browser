// Cold-path presentation only. Rust owns classification, comparison and metrics.
const float32Maximum = 65536;
const float32ResponseMaximum = 524288;
const float32Policies = {zero:'numeric_equal_bits_distinct',nonfinite:'excluded_from_delta_ulp_tolerance',nan:'never_numeric_equal_payload_preserved',relative:'absolute_delta_over_maximum_magnitude_zero_is_zero',tolerance:'absolute_or_relative_or_ulp_finite_only',accumulation:'binary64_sequential_index_order',coverage:'complete_supplied_buffers_not_capture_completeness'};
const float32Limits = {samples_per_input:65536,bytes_per_input:262144,detail_rows:256,request_bytes:2097152,response_bytes:524288,manifest_bytes:8388608,manifest_records:8192};
const float32CountKeys = ['positive_zero','negative_zero','subnormal','normal','positive_infinity','negative_infinity','nan','finite_count'];
function float32Keys(value, keys) {return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));}
function float32Integer(n,max=float32Maximum) {return Number.isSafeInteger(n) && n >= 0 && n <= max;}
function float32Same(a,b) {return JSON.stringify(a) === JSON.stringify(b);}
function float32ConstantObject(value, expected) {return float32Keys(value,Object.keys(expected)) && Object.entries(expected).every(([key,v]) => value[key] === v);}
function float32Unavailable(protocol) {return ['http:','https:'].includes(protocol) ? '' : 'Float32 diagnostics need the local live backend or browser development UI. Stored-evidence native mode is unavailable.';}
function float32Bytes(input) {
  let bytes;
  if (input.source.kind === 'bits') {
    const words=input.source.words;
    if (!Array.isArray(words) || words.length>float32Maximum) throw new Error('Use at most 65,536 binary32 words.');
    bytes=new Uint8Array(words.length*4);const view=new DataView(bytes.buffer);
    words.forEach((word,index) => {if(!/^[0-9a-f]{8}$/.test(word))throw new Error('Each raw word must contain eight lowercase hexadecimal digits.');view.setUint32(index*4,Number.parseInt(word,16),input.representation==='float32-le');});
  } else if (input.source.kind === 'bytes') {
    const text=input.source.base64;
    if(text.length>349528)throw new Error('Byte input exceeds 256 KiB.');
    let decoded;try{decoded=atob(text);}catch{throw new Error('Use canonical padded base64 bytes.');}
    if(btoa(decoded)!==text || decoded.length>262144)throw new Error('Use canonical base64 of at most 256 KiB.');
    bytes=Uint8Array.from(decoded,char=>char.charCodeAt(0));
  } else return null;
  if(bytes.length !== input.channels*input.frames*4)throw new Error('Byte length must match the complete declared channels × frames × 4 layout.');
  return bytes;
}
async function float32ExpectedIdentity(input) {
  const bytes=float32Bytes(input), source=input.source;
  const sha256=bytes ? Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte=>byte.toString(16).padStart(2,'0')).join('') : source.sha256;
  return {origin:bytes ? source.kind === 'bits' ? 'supplied_bits':'supplied_bytes':'verified_artifact',sha256,byte_length:bytes?.length ?? source.byte_length,sample_count:input.channels*input.frames,session_id:bytes ? null:source.session_id,artifact_id:bytes ? null:source.artifact_id,representation:input.representation,channels:input.channels,frames:input.frames,layout:'interleaved'};
}
function isFloat32Report(value,request,identities) {
  const count=n=>float32Integer(n), finite=n=>typeof n==='number' && Number.isFinite(n), positive=n=>finite(n)&&n>=0;
  const optional=(v,check)=>v===null||check(v), boolean=v=>typeof v==='boolean';
  if(!float32Keys(value,['protocol_version','profile','input','reference','input_summary','reference_summary','comparison','tolerances','policies','detail','limits','source_ids']) || value.protocol_version!==1 || value.profile!=='binary32-finite-steps-v1' || !float32ConstantObject(value.policies,float32Policies) || !float32ConstantObject(value.limits,float32Limits) || !float32Same(value.source_ids,['rust-f32-representation','oracle-binary32-format']) || !float32ConstantObject(value.tolerances,request.tolerances))return false;
  if(!float32ConstantObject(value.input,identities[0]) || (identities[1] ? !float32ConstantObject(value.reference,identities[1]):value.reference!==null))return false;
  const summary=(v,identity)=>float32Keys(v,[...float32CountKeys,'finite_sum_absolute']) && float32CountKeys.every(k=>count(v[k])) && positive(v.finite_sum_absolute) && float32CountKeys.slice(0,7).reduce((sum,k)=>sum+v[k],0)===identity.sample_count && v.finite_count===v.positive_zero+v.negative_zero+v.subnormal+v.normal;
  if(!summary(value.input_summary,value.input) || (value.reference ? !summary(value.reference_summary,value.reference):value.reference_summary!==null))return false;
  const sample=v=>float32Keys(v,['bits','class','sign_bit','value']) && /^[0-9a-f]{8}$/.test(v.bits) && ['zero','subnormal','normal','infinity','nan'].includes(v.class) && float32Integer(v.sign_bit,1) && (['nan','infinity'].includes(v.class) ? v.value===null:finite(v.value));
  const difference=v=>float32Keys(v,['bit_equal','numeric_equal','absolute_delta','relative_delta','ulp_distance','within_tolerance']) && boolean(v.bit_equal)&&boolean(v.numeric_equal)&&optional(v.absolute_delta,positive)&&optional(v.relative_delta,n=>positive(n)&&n<=2)&&optional(v.ulp_distance,n=>float32Integer(n,4294967295))&&optional(v.within_tolerance,boolean) && [v.relative_delta,v.ulp_distance,v.within_tolerance].every(n=>(n===null)===(v.absolute_delta===null));
  const detail=value.detail,total=Math.max(value.input.sample_count,value.reference?.sample_count??0),end=Math.min(total,request.detail.start+request.detail.limit);
  if(!float32Keys(detail,['start','limit','total','returned','next_start','rows']) || detail.start!==request.detail.start || detail.limit!==request.detail.limit || detail.total!==total || detail.returned!==end-detail.start || detail.next_start!==(end<total?end:null) || !Array.isArray(detail.rows) || detail.rows.length!==detail.returned || detail.rows.length>256)return false;
  if(!detail.rows.every((row,offset)=>float32Keys(row,['index','byte_offset','input','reference','difference']) && row.index===detail.start+offset && row.byte_offset===row.index*4 && (row.index<value.input.sample_count?sample(row.input):row.input===null) && (row.index<(value.reference?.sample_count??0)?sample(row.reference):row.reference===null) && (row.input&&row.reference?difference(row.difference):row.difference===null)))return false;
  const c=value.comparison;
  if(!value.reference)return c===null;
  const counters=['compared_pairs','input_tail','reference_tail','bit_equal_pairs','numeric_equal_pairs','finite_pairs','excluded_nonfinite_pairs','within_tolerance_pairs'];
  const flags=['raw_bytes_equal','representations_match','layouts_match'],nullableFlags=['all_bits_equal','all_numeric_equal','all_within_tolerance'],metrics=['maximum_absolute_delta','maximum_relative_delta','rms_delta'];
  if(!float32Keys(c,['status',...counters,...flags,...nullableFlags,'first_bit_mismatch',...metrics,'maximum_ulp_distance','ulp_histogram']) || !['empty','unequal_length','layout_mismatch','complete'].includes(c.status) || !counters.every(k=>count(c[k])) || !flags.every(k=>boolean(c[k])) || !nullableFlags.every(k=>optional(c[k],boolean)) || !metrics.every(k=>optional(c[k],positive)) || !optional(c.maximum_ulp_distance,n=>float32Integer(n,4294967295)) || !optional(c.first_bit_mismatch,n=>count(n)&&n<c.compared_pairs))return false;
  const pairs=Math.min(value.input.sample_count,value.reference.sample_count),sameLayout=value.input.channels===value.reference.channels&&value.input.frames===value.reference.frames;
  const status=pairs===0?'empty':value.input.sample_count!==value.reference.sample_count?'unequal_length':!sameLayout?'layout_mismatch':'complete';
  if(c.status!==status || c.layouts_match!==sameLayout || c.representations_match!==(value.input.representation===value.reference.representation) || c.compared_pairs!==pairs || c.input_tail!==value.input.sample_count-pairs || c.reference_tail!==value.reference.sample_count-pairs || c.finite_pairs+c.excluded_nonfinite_pairs!==pairs || c.bit_equal_pairs>pairs || c.numeric_equal_pairs>pairs || c.within_tolerance_pairs>c.finite_pairs || (c.first_bit_mismatch===null)!==(c.bit_equal_pairs===pairs))return false;
  if(c.all_bits_equal!==(status==='complete'?c.bit_equal_pairs===pairs:null) || c.all_numeric_equal!==(status==='complete'?c.numeric_equal_pairs===pairs:null) || c.all_within_tolerance!==(status==='complete'&&c.finite_pairs===pairs?c.within_tolerance_pairs===pairs:null) || [...metrics,'maximum_ulp_distance'].some(k=>(c[k]===null)!==(c.finite_pairs===0)))return false;
  const buckets=['zero','one','two_to_four','five_to_sixteen','over_sixteen'];return float32Keys(c.ulp_histogram,buckets)&&buckets.every(k=>count(c.ulp_histogram[k]))&&buckets.reduce((sum,k)=>sum+c.ulp_histogram[k],0)===c.finite_pairs;
}
function createFloat32Controller({changed=()=>{},fetcher=fetch,timeoutMs=15000}={}) {
  let revision=0,pending=null,last=null,status='idle',message='Select exact raw words, bytes or retained artifact identities. Nothing runs automatically.';
  const snapshot=()=>({revision,pending:pending!==null,report:last?.report??null,request:last?.request??null,stale:last!==null&&last.revision!==revision,status,message});
  const notify=()=>changed(snapshot());
  const cancel=(label='Comparison cancelled. Previous results remain visible.')=>{if(!pending)return;revision++;const prior=pending;pending=null;prior.controller.abort();prior.reject(new Error(label));status='cancelled';message=label;notify();};
  const invalidate=()=>{cancel('Input changed. Previous results are stale.');revision++;status='idle';message='Input changed. Run explicitly to replace the previous result.';notify();};
  const clear=()=>{cancel();revision++;last=null;status='idle';message='Results cleared. Inputs stay in this panel only.';notify();};
  const rejectInput=error=>{cancel('Invalid input cancelled the pending comparison.');revision++;status='error';message=error.message;notify();};
  const run=async input=>{
    cancel('Superseded by a new comparison.');
    const request=JSON.parse(JSON.stringify(input)),body=JSON.stringify(request);
    if(new TextEncoder().encode(body).length>2097152)throw new Error('Request exceeds 2 MiB.');
    const owned=++revision,controller=new AbortController();let reject;
    const interrupted=new Promise((_,no)=>{reject=no;});
    pending={controller,reject};status='loading';message='Comparing complete selected buffers locally…';notify();
    const timer=setTimeout(()=>{if(owned===revision)cancel('Comparison deadline exceeded. Previous results remain visible.');},timeoutMs);
    try{
      const report=await Promise.race([(async()=>{
        const identities=await Promise.all([float32ExpectedIdentity(request.input),request.reference?float32ExpectedIdentity(request.reference):null]);
        if(controller.signal.aborted)throw new Error('Cancelled.');
        const response=await fetcher('/api/float32/compare',{method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',body,signal:controller.signal});
        const bytes=await evidencePackageReadBytes(response,float32ResponseMaximum,controller.signal);
        if(!response.ok)throw new Error(({400:'Invalid layout, representation or request.',404:'Selected artifact is unavailable.',408:'The bounded operation timed out.',409:'Artifact identity changed. Review the selection.',413:'The input or complete manifest scan exceeds a resource limit.',422:'Artifact bytes failed complete integrity verification.'})[response.status]||`Local diagnostics returned HTTP ${response.status}.`);
        let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new Error('Malformed float32 response.');}
        if(!isFloat32Report(value,request,identities))throw new Error('Float32 response does not match the exact selected inputs and contract.');
        return value;
      })(),interrupted]);
      if(owned!==revision)return;
      last={report,request,revision:owned};status='ready';message='Complete supplied buffers inspected. Capture completeness and environment identity are not established.';
    }catch(error){if(owned!==revision)return;status='error';message=error.message;}
    finally{clearTimeout(timer);if(owned===revision){pending=null;notify();}}
  };
  return {snapshot,run,cancel,invalidate,clear,rejectInput};
}

function mountFloat32Inspector(root,{getArtifacts=()=>[],protocol=location.protocol}={}) {
  const $=selector=>root.querySelector(selector),element=(tag,text,className='')=>{const node=document.createElement(tag);node.textContent=text;if(className)node.className=className;return node;};
  let lastArtifacts='',renderedReport;
  const controller=createFloat32Controller({changed:render});
  function selected(side) {
    const kind=$(`[data-float32-kind="${side}"]`).value,representation=$(`[data-float32-endian="${side}"]`).value;
    const channels=Number($(`[data-float32-channels="${side}"]`).value),frames=Number($(`[data-float32-frames="${side}"]`).value);
    if(!float32Integer(channels,64)||channels<1||!float32Integer(frames)||channels*frames>65536)throw new Error('Declare 1–64 channels and at most 65,536 total samples.');
    let source;
    if(kind==='artifact') {
      const key=$(`[data-float32-artifact="${side}"]`).value;
      const artifact=getArtifacts().slice(0,2048).find(row=>JSON.stringify([row.session_id,row.artifact_id,row.sha256,row.byte_size])===key);
      if(!artifact)throw new Error('Choose one retained artifact with an exact identity.');
      source={kind,session_id:artifact.session_id,artifact_id:artifact.artifact_id,sha256:artifact.sha256,byte_length:artifact.byte_size};
    } else {
      const text=$(`[data-float32-input="${side}"]`).value.trim();
      source=kind==='bits'?{kind,words:text?text.split(/\s+/):[]}:{kind,base64:text};
    }
    const input={representation,channels,frames,source};float32Bytes(input);return input;
  }
  function request(start=0) {
    const absolute=Number($('#float32-absolute').value),relative=Number($('#float32-relative').value),ulps=Number($('#float32-ulps').value);
    if(!Number.isFinite(absolute)||absolute<0||absolute>1e80||!Number.isFinite(relative)||relative<0||relative>2||!float32Integer(ulps,4294967295))throw new Error('Tolerances must be finite, nonnegative and within the shown bounds.');
    return {protocol_version:1,input:selected('input'),reference:$('#float32-reference-enabled').checked?selected('reference'):null,tolerances:{absolute,relative,ulps},detail:{start,limit:64}};
  }
  function refreshSources() {
    const artifacts=getArtifacts().slice(0,2048).filter(row=>typeof row.session_id==='string'&&typeof row.artifact_id==='string'&&/^[0-9a-f]{64}$/.test(row.sha256)&&float32Integer(row.byte_size,262144)).slice(0,2048);
    const key=JSON.stringify(artifacts.map(row=>[row.session_id,row.artifact_id,row.sha256,row.byte_size]));if(key===lastArtifacts)return;lastArtifacts=key;
    let activeSelectionChanged=false;
    for(const side of ['input','reference']) {
      const select=$(`[data-float32-artifact="${side}"]`),old=select.value;
      select.replaceChildren(new Option('Select retained artifact',''));
      for(const a of artifacts)select.add(new Option(`Session ${a.session_id} · artifact ${a.artifact_id} · ${a.byte_size} B`,JSON.stringify([a.session_id,a.artifact_id,a.sha256,a.byte_size])));
      select.value=old;
      const active=$(`[data-float32-kind="${side}"]`).value==='artifact' && (side==='input'||$('#float32-reference-enabled').checked);
      activeSelectionChanged ||= active && Boolean(old) && select.value!==old;
    }
    // A cached inactive selector must not cancel a newer raw-byte draft/run.
    if(activeSelectionChanged)controller.invalidate();
  }
  function render(view=controller.snapshot()) {
    $('#float32-status').textContent=float32Unavailable(protocol)||view.message;
    $('#float32-status').dataset.kind=view.status;
    $('#float32-run').disabled=Boolean(float32Unavailable(protocol))||view.pending;$('#float32-cancel').disabled=!view.pending;
    const referenceFields=$('#float32-reference-fields'),referenceEnabled=$('#float32-reference-enabled').checked;
    referenceFields.hidden=!referenceEnabled;referenceFields.disabled=!referenceEnabled;
    for(const side of ['input','reference']){const kind=$(`[data-float32-kind="${side}"]`).value,artifact=kind==='artifact';const input=$(`[data-float32-input="${side}"]`);input.closest('label').hidden=artifact;input.placeholder=kind==='bytes'?'Canonical padded base64 bytes':'Eight-digit lowercase hex words, separated by whitespace';$(`[data-float32-artifact="${side}"]`).closest('label').hidden=!artifact;}
    const output=$('#float32-result');
    // Polls, busy-state changes and edits must preserve disclosures, scroll and
    // focused result controls while the immutable report itself is unchanged.
    if(view.report===renderedReport){
      const receipt=output.querySelector('.float32-receipt');if(receipt)receipt.textContent=view.stale?'Previous result · stale selection':'Current result · exact input identities';
      const previous=$('#float32-previous'),next=$('#float32-next');
      if(previous)previous.disabled=view.pending||view.stale||view.report.detail.start===0;
      if(next)next.disabled=view.pending||view.stale||view.report.detail.next_start===null;
      return;
    }
    renderedReport=view.report;output.replaceChildren();if(!view.report){output.append(element('p','No result yet. Raw bits preserve signed zero and NaN payloads.'));return;}
    const report=view.report,c=report.comparison;
    output.append(element('p',view.stale?'Previous result · stale selection':'Current result · exact input identities','float32-receipt'));
    for(const [label,identity,summary] of [['Input',report.input,report.input_summary],['Reference',report.reference,report.reference_summary]])if(identity){
      const details=element('details','');details.className='float32-identity';details.append(element('summary',`${label}: ${identity.sample_count} samples · ${identity.origin.replaceAll('_',' ')} · ${identity.representation}`),element('p',`SHA-256 ${identity.sha256}`),element('p',`${identity.channels} channels × ${identity.frames} frames · interleaved${identity.session_id!==null?` · session ${identity.session_id}, artifact ${identity.artifact_id}`:''}`),element('p',`+0 ${summary.positive_zero} · −0 ${summary.negative_zero} · subnormal ${summary.subnormal} · normal ${summary.normal} · +∞ ${summary.positive_infinity} · −∞ ${summary.negative_infinity} · NaN ${summary.nan}`),element('p',`Finite absolute sum ${summary.finite_sum_absolute} · binary64, sequential sample order; not an equality test`));output.append(details);
    }
    const resultText=v=>v===null?'Unavailable':v?'Equal':'Different';
    if(c){const metrics=element('dl','','float32-metrics');for(const [label,text] of [['Coverage',`${c.status} · ${c.compared_pairs} pairs · tails ${c.input_tail}/${c.reference_tail}`],['Raw bytes',resultText(c.raw_bytes_equal)],['Float32 bits',resultText(c.all_bits_equal)],['Numerical equality',resultText(c.all_numeric_equal)],['Finite tolerance',c.all_within_tolerance===null?'Unavailable':c.all_within_tolerance?'Within caller tolerance':'Outside caller tolerance'],['Maximum |Δ|',c.maximum_absolute_delta??'No finite pairs'],['Maximum relative Δ',c.maximum_relative_delta??'No finite pairs'],['Maximum ULP steps',c.maximum_ulp_distance??'No finite pairs'],['RMS Δ',c.rms_delta??'No finite pairs'],['Finite/excluded pairs',`${c.finite_pairs} / ${c.excluded_nonfinite_pairs}`]]){metrics.append(element('dt',label),element('dd',String(text)));}output.append(metrics);}
    output.append(element('p',`Tolerance: |Δ| ≤ ${report.tolerances.absolute} OR symmetric relative Δ ≤ ${report.tolerances.relative} OR ULP ≤ ${report.tolerances.ulps}. Finite pairs only. +0/−0 are numerically equal; NaN is never numerically equal.`));
    const nav=element('div','','float32-page');const previous=element('button','Previous samples','secondary-button'),next=element('button','Next samples','secondary-button');previous.type=next.type='button';previous.id='float32-previous';next.id='float32-next';previous.disabled=view.pending||view.stale||report.detail.start===0;next.disabled=view.pending||view.stale||report.detail.next_start===null;
    previous.onclick=()=>submit(Math.max(0,report.detail.start-report.detail.limit));next.onclick=()=>submit(report.detail.next_start);nav.append(previous,element('span',`${report.detail.returned?report.detail.start+1:0}–${report.detail.start+report.detail.returned} of ${report.detail.total}`),next);output.append(nav);
    const rows=element('div','','float32-rows');rows.tabIndex=0;rows.setAttribute('aria-label','Float32 sample details');
    const sampleText=v=>v?`0x${v.bits} · ${v.sign_bit?'−':'+'}${v.class} · ${v.value===null?'no finite value':Object.is(v.value,-0)?'−0':v.value}`:'Missing sample';
    for(const row of report.detail.rows){const card=element('article','','float32-row');card.append(element('h4',`Sample ${row.index} · byte ${row.byte_offset}`),element('p',`Input ${sampleText(row.input)}`));if(report.reference)card.append(element('p',`Reference ${sampleText(row.reference)}`));if(row.difference)card.append(element('p',`Bits ${row.difference.bit_equal?'equal':'differ'} · numeric ${row.difference.numeric_equal?'equal':'differ'} · |Δ| ${row.difference.absolute_delta??'unavailable'} · ULP ${row.difference.ulp_distance??'unavailable'}`));rows.append(card);}output.append(rows);
  }
  async function submit(start=0){try{await controller.run(request(start));}catch(error){controller.rejectInput(error);}}
  root.querySelector('form').addEventListener('submit',event=>{event.preventDefault();void submit();});
  root.addEventListener('input',event=>{if(event.target.matches('input,textarea,select'))controller.invalidate();});
  root.addEventListener('change',event=>{if(event.target.matches('select,input'))controller.invalidate();});
  $('#float32-cancel').addEventListener('click',()=>controller.cancel());$('#float32-clear').addEventListener('click',()=>controller.clear());
  $('#float32-example').addEventListener('click',()=>{controller.invalidate();$('#float32-reference-enabled').checked=true;for(const side of ['input','reference']){$(`[data-float32-kind="${side}"]`).value='bits';$(`[data-float32-endian="${side}"]`).value='float32-le';$(`[data-float32-channels="${side}"]`).value='1';$(`[data-float32-frames="${side}"]`).value='5';}$('[data-float32-input="input"]').value='3f800000 80000000 00000001 7f800000 7fc00001';$('[data-float32-input="reference"]').value='3f800001 00000000 00000002 7f800000 7fc00002';render();});
  render();return {cancel:()=>controller.cancel(),refresh:()=>{refreshSources();render();},controller};
}
