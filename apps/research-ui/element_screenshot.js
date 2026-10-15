/* Bounded local screenshot markup. Page text/HTML is never inserted into this UI. */
(function (global) {
  'use strict';
  const MAX_IMAGE = 5592408;
  const keys = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
  const integer = (value, max, min = 0) => Number.isSafeInteger(value) && value >= min && value <= max;
  const finite = (value, max, min = 0) => typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max;
  const text = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && new TextEncoder().encode(value).length <= max;
  const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const id = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
  function selection(value) {
    return keys(value, ['instance_id','connection_epoch','session_id','target_id','document_epoch','frame_id','loader_id','document_node_id','revision']) &&
      text(value.instance_id,128) && integer(value.connection_epoch,Number.MAX_SAFE_INTEGER,1) && integer(value.session_id,Number.MAX_SAFE_INTEGER,1) && text(value.target_id,4096) &&
      integer(value.document_epoch,Number.MAX_SAFE_INTEGER) && text(value.frame_id,4096) && text(value.loader_id,4096) && id(value.document_node_id) && hash(value.revision);
  }
  function documentValid(value) {
    if (!keys(value,['selection','viewport','elements','outside_viewport','limitations']) || !selection(value.selection) ||
        !keys(value.viewport,['x','y','width','height']) || !finite(value.viewport.x,10000000) || !finite(value.viewport.y,10000000) ||
        !finite(value.viewport.width,4096,0.000001) || !finite(value.viewport.height,4096,0.000001) || value.viewport.width * value.viewport.height > 8000000 ||
        !integer(value.outside_viewport,4096) || !Array.isArray(value.limitations) || value.limitations.length !== 4 || !value.limitations.every(item => text(item,1024)) ||
        !Array.isArray(value.elements) || value.elements.length > 128) return false;
    const seen = new Set();
    return value.elements.every((box,index) => {
      if (!keys(box,['number','node_id','x','y','width','height','viewport_clipped']) || box.number !== index+1 || !id(box.node_id) || seen.has(box.node_id) ||
          !finite(box.x,4096) || !finite(box.y,4096) || !finite(box.width,4096,0.000001) || !finite(box.height,4096,0.000001) ||
          box.x + box.width > value.viewport.width + 0.000001 || box.y + box.height > value.viewport.height + 0.000001 || typeof box.viewport_clipped !== 'boolean') return false;
      seen.add(box.node_id); return true;
    });
  }
  function captureValid(value) {
    return keys(value,['format','document','image','consistency','occlusion']) && value.format === 'reb-element-screenshot-v1' &&
      value.consistency === 'before-after-observed-stable' && value.occlusion === 'unknown' && documentValid(value.document) &&
      keys(value.image,['mime','base64','width','height','sha256']) && value.image.mime === 'image/png' && hash(value.image.sha256) &&
      integer(value.image.width,4096,1) && integer(value.image.height,4096,1) && value.image.width * value.image.height <= 8000000 &&
      text(value.image.base64,MAX_IMAGE) && value.image.base64.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value.image.base64) &&
      value.image.base64.length/4*3-(value.image.base64.endsWith('==')?2:value.image.base64.endsWith('=')?1:0) <= 4*1024*1024;
  }
  function context(state) {
    const experiment = state?.request_interception;
    if (state?.state !== 'running' || experiment?.isolated !== true || !text(experiment.target_id,4096) || experiment.target_id !== state.target?.id ||
        state.object_experiment?.isolated !== true || state.object_experiment.target_id !== experiment.target_id ||
        !integer(state.object_experiment?.session_id,Number.MAX_SAFE_INTEGER,1) || !integer(state.element_document_epoch,Number.MAX_SAFE_INTEGER) ||
        !text(state.network?.instance_id,128) || !integer(state.network.capture_epoch,Number.MAX_SAFE_INTEGER,1)) return null;
    return {instance_id:state.network.instance_id,connection_epoch:state.network.capture_epoch,session_id:state.object_experiment.session_id,target_id:experiment.target_id,document_epoch:state.element_document_epoch};
  }
  const contextKey = state => JSON.stringify(context(state));
  const matches = (document,state) => {
    const current = context(state);
    return current && Object.entries(current).every(([key,value]) => document.selection[key] === value);
  };
  // Independently testable controller: pending work belongs to an exact local
  // context generation. Clear/close/navigation retire both requests and replies.
  function createController({getState,request,onChange,setTimer = setTimeout,clearTimer = clearTimeout}) {
    let revision = 0, pending = false, inspected = null, captured = null, controller = null, currentKey = contextKey(getState());
    const snapshot = () => ({pending,document:inspected,capture:captured});
    const emit = message => onChange(snapshot(),message);
    function clear(message = 'Local screenshot and selection cleared.') {
      revision++; controller?.abort(); controller = null; pending = false; inspected = null; captured = null; emit(message);
    }
    function refresh() {
      const next = contextKey(getState());
      if (next !== currentKey) { currentKey = next; clear('The selected page changed or disconnected. Inspect the document again.'); } else emit();
    }
    async function run(capture, confirmed) {
      refresh();
      if (pending) return false;
      const selected = context(getState());
      if (!selected) { emit('Open a running isolated page in Objects first.'); return false; }
      if (capture && (!inspected || !matches(inspected,getState()) || !confirmed)) { emit('Inspect this document and confirm sensitive local capture first.'); return false; }
      const expected = inspected, key = currentKey, own = ++revision;
      let timer = null;
      captured = null;
      const activeController = new AbortController(); controller = activeController; pending = true; emit(capture ? 'Capturing the selected document…' : 'Inspecting bounded geometry and privacy exclusions…');
      try {
        const response = await Promise.race([request(capture ? {action:'capture_element_screenshot',selection:expected.selection,confirm_sensitive:true} :
          {action:'inspect_element_document',target_id:selected.target_id},activeController.signal), new Promise((_,reject) => { timer = setTimer(() => { activeController.abort(); reject(new Error('Local capture deadline expired. Inspect again to retry.')); },15000); })]);
        if (own !== revision) return false;
        if (key !== contextKey(getState())) { refresh(); return false; }
        if (capture) {
          if (!keys(response,['ok','capture']) || response.ok !== true || !captureValid(response.capture) || !matches(response.capture.document,getState()) ||
              JSON.stringify(response.capture.document) !== JSON.stringify(expected)) throw new Error('Capture identity or geometry did not match the inspected document.');
          captured = response.capture;
          emit('Captured bytes received. Verifying and decoding the local PNG…');
        } else {
          if (!keys(response,['ok','document']) || response.ok !== true || !documentValid(response.document) || !matches(response.document,getState())) throw new Error('Unsupported or stale document response.');
          inspected = response.document; captured = null;
          emit(`${inspected.elements.length} viewport boxes inspected. Confirm before capturing raw pixels.`);
        }
        return true;
      } catch (error) {
        if (own === revision) { inspected = null; captured = null; emit(error?.name === 'AbortError' ? 'Capture cancelled. Inspect again to retry.' : String(error?.message || 'Capture failed.').slice(0,512)); }
        return false;
      } finally {
        clearTimer(timer);
        if (own === revision) { pending = false; controller = null; emit(); }
        else refresh();
      }
    }
    return {inspect:() => run(false,false),capture:confirmed => run(true,confirmed),clear,refresh,snapshot};
  }
  function install({getState,root = document.querySelector('#element-screenshot-workspace'),fetcher = global.fetch.bind(global)}) {
    if (!root) return {refresh(){},setVisible(){}};
    const query = name => root.querySelector(`[data-element-${name}]`);
    const inspect = query('inspect'), grab = query('capture'), clear = query('clear'), confirm = query('confirm'), notice = query('notice');
    const stage = query('stage'), list = query('list'), metadata = query('metadata'), limits = query('limits');
    let visible = false, lastCapture = null, selected = null, activeUrl = null, renderEpoch = 0;
    const revoke = () => { if (activeUrl) URL.revokeObjectURL(activeUrl); activeUrl = null; };
    function select(number,focus = false) {
      selected = number;
      for (const button of root.querySelectorAll('[data-element-number]')) {
        const yes = Number(button.dataset.elementNumber) === number;
        button.setAttribute('aria-pressed',String(yes));
        if (yes && focus && button.classList.contains('element-screenshot-row')) button.focus();
      }
    }
    function renderCapture(capture) {
      const own = ++renderEpoch; revoke(); stage.replaceChildren(); list.replaceChildren(); selected = null;
      if (!capture) return;
      const image = document.createElement('img'); image.alt = 'Raw local snapshot of the explicitly selected disposable document';
      image.width = capture.image.width; image.height = capture.image.height;
      const bytes = Uint8Array.from(atob(capture.image.base64),character => character.charCodeAt(0));
      const read32 = offset => new DataView(bytes.buffer).getUint32(offset);
      if (bytes.length > 4*1024*1024 || bytes.length < 33 || ![137,80,78,71,13,10,26,10].every((byte,index) => bytes[index] === byte) ||
          read32(8) !== 13 || String.fromCharCode(...bytes.slice(12,16)) !== 'IHDR' || read32(16) !== image.width || read32(20) !== image.height) {
        controller.clear('The PNG dimensions or signature did not match the capture.'); return;
      }
      const sx = image.width/capture.document.viewport.width, sy = image.height/capture.document.viewport.height;
      if (sx < 0.5 || sx > 4 || sy < 0.5 || sy > 4 || Math.abs(sx-sy) > 0.01) { controller.clear('Unsupported image-to-layout scale.'); return; }
      // Header/digest checks are not image-decoder acceptance.
      if (!global.crypto?.subtle) { controller.clear('Local image verification is unavailable.'); return; }
      // Keep the verified PNG in a local blob URL, never in HTML or storage.
      global.crypto.subtle.digest('SHA-256',bytes).then(digest => {
        if (own !== renderEpoch) return;
        if (!matches(capture.document,getState())) { controller.clear('The selected document changed before image verification.'); return; }
        const hash = Array.from(new Uint8Array(digest),byte => byte.toString(16).padStart(2,'0')).join('');
        if (hash !== capture.image.sha256) { controller.clear('PNG content digest mismatch.'); return; }
        activeUrl = URL.createObjectURL(new Blob([bytes],{type:'image/png'}));
        image.onload = () => {
          if (own !== renderEpoch) return;
          if (!matches(capture.document,getState())) { controller.clear('The selected document changed before image decoding.'); return; }
          if (image.naturalWidth !== capture.image.width || image.naturalHeight !== capture.image.height) { controller.clear('Decoded image dimensions did not match the capture.'); return; }
          notice.textContent = 'Local snapshot ready. Numbered boxes describe layout bounds; occlusion is unknown.';
          stage.append(image);
          const {width,height} = capture.document.viewport;
          // Larger boxes first so smaller nested rectangles remain pointer-reachable.
          for (const box of [...capture.document.elements].sort((a,b) => b.width*b.height-a.width*a.height)) {
            const button = document.createElement('button'); button.type = 'button'; button.className = 'element-screenshot-box';
            button.dataset.elementNumber = String(box.number); button.setAttribute('aria-label',`Element ${box.number}, layout bound, occlusion unknown`);
            button.setAttribute('aria-pressed','false'); button.style.left = `${box.x/width*100}%`; button.style.top = `${box.y/height*100}%`;
            button.style.width = `${box.width/width*100}%`; button.style.height = `${box.height/height*100}%`;
            const label = document.createElement('span'); label.textContent = String(box.number); button.append(label);
            button.addEventListener('click',() => select(box.number)); stage.append(button);
          }
          for (const box of capture.document.elements) {
            const button = document.createElement('button'); button.type = 'button'; button.className = 'element-screenshot-row';
            button.dataset.elementNumber = String(box.number); button.setAttribute('aria-pressed','false');
            button.textContent = `${box.number}. Element ${box.node_id} · ${box.width.toFixed(1)} × ${box.height.toFixed(1)} CSS px${box.viewport_clipped ? ' · viewport clipped' : ''}`;
            button.addEventListener('click',() => select(box.number));
            button.addEventListener('keydown',event => {
              const max = capture.document.elements.length;
              const next = {ArrowDown:Math.min(max,box.number+1),ArrowRight:Math.min(max,box.number+1),ArrowUp:Math.max(1,box.number-1),ArrowLeft:Math.max(1,box.number-1),Home:1,End:max}[event.key];
              if (next) { event.preventDefault(); select(next,true); }
            });
            list.append(button);
          }
          if (capture.document.elements.length) select(1);
        };
        image.onerror = () => { if (own === renderEpoch) controller.clear('The captured PNG could not be decoded.'); };
        image.src = activeUrl;
      }).catch(() => { if (own === renderEpoch) controller.clear('Local image verification failed.'); });
    }
    const controller = createController({getState,request:async (body,signal) => {
      const response = await fetcher('/api/debugger/actions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal,cache:'no-store'});
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'The local capture was refused.');
      return data;
    },onChange:(state,message) => {
      if (message) notice.textContent = message;
      inspect.disabled = state.pending || !context(getState()); grab.disabled = state.pending || !state.document || !confirm.checked;
      clear.disabled = !state.pending && !state.document && !state.capture; confirm.disabled = state.pending || !state.document;
      if (!state.document) confirm.checked = false;
      metadata.textContent = state.document ? `Document ${state.document.selection.document_node_id} · revision ${state.document.selection.revision.slice(0,12)} · ${state.document.elements.length} viewport boxes · ${state.document.outside_viewport} outside viewport` : 'No document selected.';
      limits.replaceChildren(...(state.document?.limitations || []).map(text => { const item = document.createElement('li'); item.textContent = text; return item; }));
      if (state.capture !== lastCapture) { lastCapture = state.capture; renderCapture(state.capture); }
    }});
    inspect.addEventListener('click',() => { confirm.checked = false; controller.inspect(); });
    grab.addEventListener('click',() => controller.capture(confirm.checked));
    clear.addEventListener('click',() => controller.clear());
    confirm.addEventListener('change',() => { grab.disabled = controller.snapshot().pending || !controller.snapshot().document || !confirm.checked; });
    global.addEventListener('pagehide',() => controller.clear());
    return {refresh:() => controller.refresh(),setVisible(value) {
      root.hidden = !value;
      if (visible && !value) controller.clear('Screenshot panel closed; local capture cleared.');
      visible = value; controller.refresh();
    }};
  }
  const api = {documentValid,captureValid,context,contextKey,createController,install};
  global.RebElementScreenshot = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
