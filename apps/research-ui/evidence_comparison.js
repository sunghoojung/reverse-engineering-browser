/* Secondary local metadata tools. No capture, export, execution or automatic request. */
(() => {
  'use strict';
  const profile = 'reb-declared-metadata-v1';
  const facets = ['artifacts', 'coverage', 'events', 'gaps', 'provenance', 'relationships', 'selection'];
  const inputLimit = 4194304;
  const outputLimit = 524288;
  const stableId = (value,prefix) => typeof value==='string' && value.length===prefix.length+64 && value.startsWith(prefix) && /^[a-f0-9]{64}$/.test(value.slice(prefix.length));
  const packageId = value => stableId(value,'reb-package-v1:sha256:');
  const statuses = ['equal_declared_metadata','changed_declared_metadata','left_only','right_only'];
  const limitations = ['untrusted_input','authenticity_not_established','artifact_bytes_not_present_not_reverified','capture_configuration_unknown','observer_regime_unknown','historical_epochs_unknown','behavioral_equivalence_not_established','timing_equivalence_not_established'];
  const integer = (value, maximum) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
  const object = value => value && typeof value === 'object' && !Array.isArray(value);
  const summary = value => object(value) && (value.kind === 'scalar'
    ? value.value === null || typeof value.value === 'boolean' || Number.isSafeInteger(value.value) || typeof value.value === 'string' && value.value.length <= 4096
    : ['object', 'array'].includes(value.kind) && integer(value.count, 4096));
  function validResult(value, offset, leftId, rightId) {
    if (!object(value) || value.protocol_version !== 1 || value.normalization_profile !== profile || !stableId(value.comparison_id,'reb-comparison-v1:sha256:') ||
      value.left_package_id !== leftId || value.right_package_id !== rightId || !packageId(leftId) || !packageId(rightId) ||
      JSON.stringify(value.facets) !== JSON.stringify(facets) || JSON.stringify(value.limitations) !== JSON.stringify(limitations) || value.package_metadata_equal !== (leftId===rightId) || ![true, false, null].includes(value.selected_metadata_equal) ||
      !object(value.comparability) || value.comparability.observer_regime !== 'unknown' || value.comparability.capture_coverage !== 'unknown_or_partial' ||
      value.comparability.behavior !== 'not_established' || value.comparability.timing !== 'not_established' ||
      !object(value.page) || value.page.offset !== offset || value.page.limit !== 50 || !integer(value.page.total, 2181) ||
      !Array.isArray(value.rows) || value.rows.length > 50 || value.rows.length !== Math.min(50, Math.max(0, value.page.total - offset)) ||
      value.page.next_offset !== (offset + value.rows.length < value.page.total ? offset + value.rows.length : null) ||
      !object(value.counts) || !['equal_declared_metadata', 'changed_declared_metadata', 'left_only', 'right_only', 'ambiguous_cross_scope'].every(k => integer(value.counts[k], 2181))) return false;
    const coverage = v => object(v) && ['complete','empty'].includes(v.selection) && ['events','artifacts'].every(section => {
      const c=v[section]; return object(c) && integer(c.selected_count,section==='events'?1024:64) && ['complete','not_requested'].includes(c.selection_state) && ['complete','not_read'].includes(c.source_scan) && ['unknown','partial'].includes(c.capture_state) && Array.isArray(c.limitations) && c.limitations.length<=11 && c.limitations.every(text=>typeof text==='string' && /^[a-z_]{1,64}$/.test(text));
    });
    if (!object(value.coverage) || !coverage(value.coverage.left) || !coverage(value.coverage.right) ||
      value.counts.equal_declared_metadata+value.counts.changed_declared_metadata+value.counts.left_only+value.counts.right_only!==value.page.total ||
      value.selected_metadata_equal !== (value.page.total===0 ? null : value.counts.changed_declared_metadata+value.counts.left_only+value.counts.right_only===0) ||
      value.counts.ambiguous_cross_scope>value.counts.left_only+value.counts.right_only ||
      (value.package_metadata_equal && value.selected_metadata_equal===false) ||
      !value.rows.every(row=>object(row) && stableId(row.row_id,'reb-comparison-row-v1:sha256:')) ||
      new Set(value.rows.map(row=>row.row_id)).size!==value.rows.length) return false;
    const ref = (r,id,facet) => {
      if (r===null) return true;
      if (!object(r) || r.package_id!==id || r.facet!==facet) return false;
      if (!['events','artifacts'].includes(facet)) return r.key===null;
      return object(r.key) && Object.keys(r.key).length===(facet==='events'?3:2) && evidencePackageKey(facet==='events'?'event':'artifact',r.key)!==null;
    };
    const pageCounts = Object.fromEntries([...statuses,'ambiguous_cross_scope'].map(status=>[status,0]));
    if (!value.rows.every(row => {
      if (!object(row) || !stableId(row.row_id,'reb-comparison-row-v1:sha256:') || !facets.includes(row.facet) ||
        !statuses.includes(row.status) || !['declared_scoped_key','selected_facet','ambiguous_cross_scope','unmatched'].includes(row.alignment) ||
        !ref(row.left,leftId,row.facet) || !ref(row.right,rightId,row.facet) || !integer(row.cross_scope_candidates,1024) || !integer(row.differences_omitted,64) ||
        !Array.isArray(row.differences) || row.differences.length>12 || !row.differences.every(d=>object(d) && typeof d.field==='string' && d.field.length<=64 && summary(d.left) && summary(d.right) && !(d.left.kind==='scalar' && d.right.kind==='scalar' && d.left.value===d.right.value)) || new Set(row.differences.map(d=>d.field)).size!==row.differences.length) return false;
      const pair=row.left!==null && row.right!==null, record=['events','artifacts'].includes(row.facet);
      if (pair) {
        if (record && JSON.stringify(evidencePackageKey(row.facet==='events'?'event':'artifact',row.left.key))!==JSON.stringify(evidencePackageKey(row.facet==='events'?'event':'artifact',row.right.key))) return false;
        if (!['equal_declared_metadata','changed_declared_metadata'].includes(row.status) || row.alignment!==(record?'declared_scoped_key':'selected_facet') || row.cross_scope_candidates!==0 ||
          (row.status==='equal_declared_metadata')!==(row.differences.length+row.differences_omitted===0)) return false;
      } else if (!record || (row.status==='left_only' ? row.left===null || row.right!==null : row.status==='right_only' ? row.left!==null || row.right===null : true) || row.alignment!==(row.cross_scope_candidates?'ambiguous_cross_scope':'unmatched') || row.differences.length || row.differences_omitted) return false;
      if (pair && row.facet==='artifacts') {
        if (typeof row.declared_content_hash_match!=='boolean' || row.status==='equal_declared_metadata' && !row.declared_content_hash_match) return false;
        const hashChanged=row.differences.some(d=>['sha256','byte_size'].includes(d.field));
        if (row.declared_content_hash_match && hashChanged || !row.declared_content_hash_match && !hashChanged && row.differences_omitted===0) return false;
      } else if (row.declared_content_hash_match!==null) return false;
      pageCounts[row.status]++;if(row.alignment==='ambiguous_cross_scope')pageCounts.ambiguous_cross_scope++;
      return true;
    })) return false;
    const fullPage=value.page.offset===0 && value.rows.length===value.page.total;
    return Object.keys(pageCounts).every(status=>fullPage ? pageCounts[status]===value.counts[status] : pageCounts[status]<=value.counts[status]);
  }
  class ComparisonFailure extends Error {
    constructor(kind) { super(kind); this.kind=kind; }
  }
  async function readResponse(response,signal) {
    if (!response.ok) throw new ComparisonFailure(response.status===503?'busy':response.status===408?'deadline':'rejected');
    const bytes = await evidencePackageReadBytes(response,outputLimit,signal);
    return JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));
  }
  function createController({fetcher = fetch, onChange = () => {}, deadline = 20000} = {}) {
    let revision = 0, active = null, disposed = false;
    const model = {files:[null,null], result:null, busy:false, message:'Choose two local metadata packages, then compare.'};
    const publish = () => { if (!disposed) onChange(model); };
    const retire = () => { revision++; active?.abort.abort(); active?.cancel(); clearTimeout(active?.timer); active = null; model.busy = false; };
    const select = (side,file) => {
      if (disposed || ![0,1].includes(side)) return;
      retire(); model.result = null; model.files[side] = file ?? null;
      model.message = 'Selection changed. Compare explicitly to inspect these files.'; publish();
    };
    async function compare(offset = 0) {
      if (disposed || model.busy) return false;
      if (!integer(offset,2181) || model.files.some(file => !file || !integer(file.size,inputLimit) || file.size === 0)) {
        model.message = 'Choose two nonempty metadata JSON files, each at most 4 MiB.'; publish(); return false;
      }
      retire(); const owned = revision; const files = [...model.files]; const abort = new AbortController();
      const current=()=>owned===revision && !disposed && !abort.signal.aborted;
      let cancel; const cancellation = new Promise(resolve => { cancel = () => resolve(null); });
      active = {abort,cancel,timer:null};
      model.busy = true; model.message = 'Comparing declared metadata locally…';
      let timer;
      const timeout = new Promise((_,reject) => { timer = setTimeout(() => { abort.abort(); reject(new ComparisonFailure('deadline')); },deadline); active.timer = timer; });
      publish();
      try {
        const work = async () => {
          if (!current()) return null;
          const originals = [];
          for (const file of files) {
            if (!current()) return null;
            const bytes = new Uint8Array(await file.arrayBuffer());
            if (!current()) return null;
            if (bytes.length !== file.size || bytes.length > inputLimit) throw new Error('A selected file changed or exceeded its limit.');
            originals.push(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));
          }
          // Preserve original duplicate keys and numeric tokens for the backend.
          const body = `{"left":${originals[0]},"right":${originals[1]},"normalization_profile":"${profile}","facets":${JSON.stringify(facets)},"offset":${offset},"limit":50}`;
          if (!current()) return null;
          const response = await fetcher('/api/evidence/packages/compare',{method:'POST',cache:'no-store',headers:{'content-type':'application/json'},body,signal:abort.signal});
          const result = await readResponse(response,abort.signal);
          if (!current()) return null;
          // Used only to bind a successful response to these selected originals;
          // this local read never replaces backend strict original-byte validation.
          const ids = originals.map(text => JSON.parse(text).package_id);
          if (!validResult(result,offset,ids[0],ids[1])) throw new Error('The local service returned an incompatible comparison.');
          return result;
        };
        const result = await Promise.race([work(),timeout,cancellation]);
        if (!current() || !result) return false;
        model.result = result; model.message = 'Declared metadata compared. Capture, behavior and timing equivalence remain unknown.'; return true;
      } catch (error) {
        const reason = error instanceof ComparisonFailure ? ({busy:'The local comparison service is busy or unavailable. Retry only when you choose.',deadline:'The bounded comparison timed out. No new result was applied.',rejected:'The comparison request was rejected. Review both metadata packages and their limits.'})[error.kind] : null;
        if (owned === revision && !disposed) model.message = (reason || 'Comparison unavailable or incompatible. Check the selected files and local service.') + ' The previous result is retained.';
        return false;
      } finally {
        clearTimeout(timer); abort.abort();
        if (owned === revision && !disposed) { active = null; model.busy = false; publish(); }
      }
    }
    return {model,select,compare,close(){retire();model.message='Comparison closed. Reopening does not send a request.';publish();},clear(){retire();model.files=[null,null];model.result=null;model.message='Package selection cleared.';publish();},dispose(){retire();disposed=true;}};
  }
  function mount(host,{fetcher = fetch} = {}) {
    if (!host) return null;
    if (host.rebEvidenceComparison) return host.rebEvidenceComparison;
    const doc = host.ownerDocument || document;
    const node = (tag,text,className='') => { const n=doc.createElement(tag);n.textContent=text;n.className=className;return n; };
    const toolbar=node('div','','package-toolbar'); const inputs=[];
    for (const name of ['Left package','Right package']) {
      const label=node('label',name); const input=node('input','');input.type='file';input.accept='.json,application/json';
      input.dataset.comparisonSide = String(inputs.length); label.append(input); toolbar.append(label); inputs.push(input);
    }
    const button = text => {const b=node('button',text,'secondary-button');b.type='button';return b;};
    const compare=button('Compare metadata'),clear=button('Clear files'),cancel=button('Cancel'),previous=button('Previous'),next=button('Next');
    for (const [name,b] of [['compare',compare],['clear',clear],['cancel',cancel],['previous',previous],['next',next]]) b.dataset.comparisonAction=name;
    previous.setAttribute('aria-label','Previous comparison page');next.setAttribute('aria-label','Next comparison page');
    toolbar.append(compare,clear,cancel);
    const notice=node('p','','package-note');notice.setAttribute('role','status');notice.setAttribute('aria-live','polite');
    const results=node('div','','package-comparison-results');const paging=node('div','','package-toolbar');const page=node('span','');paging.append(previous,page,next);
    host.replaceChildren(node('p','Two supplied metadata files are sent only to this local service. No capture or export runs. Matching hashes describe declarations; raw artifact bytes are absent. Observer settings and historical epochs remain unknown.','package-note'),toolbar,notice,results,paging);
    const show = value => value.kind==='scalar' ? JSON.stringify(value.value) : `${value.kind} (${value.count} entries; inspect original for detail)`;
    const reference = r => r ? `${r.package_id} / ${r.facet}${r.key ? ' / '+Object.entries(r.key).map(([k,v])=>`${k}=${v}`).join(', ') : ''}` : 'No matched record';
    const controller=createController({fetcher,onChange:model=>{
      const focused=doc.activeElement;
      compare.disabled=model.busy || model.files.some(f=>!f);cancel.disabled=!model.busy;
      notice.textContent=model.message;
      previous.disabled=model.busy || !model.result || model.result.page.offset===0; next.disabled=model.busy || !model.result || model.result.page.next_offset===null;
      // Disabling the focused trigger otherwise sends native keyboard events to
      // the document body, outside the comparison's scoped Escape handler.
      if ([compare,cancel,previous,next].includes(focused) && focused.disabled) {
        const nextFocus=model.busy ? cancel : compare;
        if (!nextFocus.disabled) nextFocus.focus({preventScroll:true});
      }
      if (results.resultIdentity === model.result) return;
      results.resultIdentity=model.result; results.replaceChildren();page.textContent='';
      if (!model.result) return;
      const result=model.result;
      results.append(node('p',`Declared metadata: ${result.counts.equal_declared_metadata} equal, ${result.counts.changed_declared_metadata} changed, ${result.counts.left_only} left only, ${result.counts.right_only} right only. ${result.counts.ambiguous_cross_scope} cross-scope ambiguities.`, 'package-note'),node('p','Unknown observer regime and unknown or partial capture coverage. Equal metadata does not establish equal behavior, timing, completeness or raw bytes.','package-note'));
      results.append(node('p',`Result ${result.comparison_id}`,'package-note'));
      for (const side of ['left','right']) {
        const c=result.coverage[side];
        results.append(node('p',`${side==='left'?'Left':'Right'} package: ${c.events.selected_count} selected events (${c.events.capture_state} capture), ${c.artifacts.selected_count} selected artifact descriptors (${c.artifacts.capture_state} capture). Exporter scan assertions are untrusted.`, 'package-note'));
        const limitations=[...new Set([...c.events.limitations,...c.artifacts.limitations])];
        results.append(node('p',`${side==='left'?'Left':'Right'} limitations: ${limitations.map(v=>v.replaceAll('_',' ')).join(', ')}.`, 'package-note'));
      }

      const list=node('ol','','package-report-rows');
      for (const row of result.rows) {
        const item=node('li','');const detail=node('details','','package-disclosure');detail.append(node('summary',`${row.facet} · ${row.status.replaceAll('_',' ')} · ${row.alignment.replaceAll('_',' ')}`));
        detail.append(node('p',`Left: ${reference(row.left)}`,'package-note'),node('p',`Right: ${reference(row.right)}`,'package-note'));
        if (row.cross_scope_candidates) detail.append(node('p',`${row.cross_scope_candidates} coincident local identifiers in other sessions. No records were paired.`,'package-note'));
        if (row.declared_content_hash_match !== null) detail.append(node('p',`Declared artifact hash and size ${row.declared_content_hash_match?'match':'differ'}. Raw bytes were not reverified.`,'package-note'));
        for (const d of row.differences) detail.append(node('p',`${d.field}: ${show(d.left)} → ${show(d.right)}`,'package-note'));
        if (row.differences_omitted) detail.append(node('p',`${row.differences_omitted} additional changed fields omitted. Inspect the referenced originals.`,'package-note'));
        detail.append(node('p',row.row_id,'package-note'));item.append(detail);list.append(item);
      }
      results.append(list);page.textContent=result.page.total ? `${result.page.offset+1}–${result.page.offset+result.rows.length} of ${result.page.total}` : 'No selected records';
    }});
    const listeners=[];const on=(element,type,fn)=>{element.addEventListener(type,fn);listeners.push(()=>element.removeEventListener(type,fn));};
    inputs.forEach((input,side)=>on(input,'change',()=>controller.select(side,input.files?.[0])));
    const clearFiles=()=>{inputs.forEach(input=>{input.value='';});controller.clear();};
    on(compare,'click',()=>controller.compare());on(clear,'click',clearFiles);on(cancel,'click',()=>controller.close());
    on(previous,'click',()=>controller.compare(Math.max(0,controller.model.result.page.offset-50)));on(next,'click',()=>controller.compare(controller.model.result.page.next_offset));
    const disclosure=host.closest?.('details');if(disclosure) on(disclosure,'toggle',()=>{if(!disclosure.open) controller.close();});
    let mountedDisposed=false;
    const handle={controller,clear:clearFiles,close:()=>controller.close(),dispose(){
      if(mountedDisposed)return;mountedDisposed=true;
      listeners.forEach(fn=>fn());controller.dispose();
      if(host.rebEvidenceComparison===handle){host.replaceChildren();delete host.rebEvidenceComparison;}
    }};
    host.rebEvidenceComparison=handle;controller.clear();return handle;
  }
  globalThis.RebEvidenceComparison = {mount,createController,validResult};
})();
