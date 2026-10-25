/* Attached-page Wasm inspection and paused import maps.
 * Requests stay explicit. guest_position is never invented. */
const CapturedVmLab = (() => {
  const model = {notice: '', importReport: null, listing: null, memory: null};
  const views = [];
  const text = value => value == null ? '' : String(value);
  const integer = (value, max, min = 0) => Number.isSafeInteger(value) && value >= min && value <= max;
  function owner(session) {
    const documentOwner = {
      instance_id: session?.network?.instance_id,
      connection_epoch: session?.network?.capture_epoch,
      document_epoch: session?.target_document_epoch,
      target_id: session?.target?.id
    };
    const complete = typeof documentOwner.instance_id === 'string' && documentOwner.instance_id.length > 0 &&
      integer(documentOwner.connection_epoch, Number.MAX_SAFE_INTEGER) &&
      integer(documentOwner.document_epoch, Number.MAX_SAFE_INTEGER) &&
      typeof documentOwner.target_id === 'string' && documentOwner.target_id.length > 0;
    return complete ? documentOwner : null;
  }
  function objectLab(session) {
    const experiment = session?.object_experiment;
    return experiment?.isolated === true && experiment.target_id === session?.target?.id &&
      integer(experiment.navigation_id, Number.MAX_SAFE_INTEGER, 1) &&
      typeof experiment.url === 'string' && experiment.url.length > 0;
  }
  function attachedPage(session) {
    return ['running', 'paused'].includes(session?.state) && typeof session?.target?.id === 'string' &&
      session.target.id.length > 0 && (session.target.type == null || session.target.type === 'page');
  }
  function listRequest(session, confirmed) {
    if (!attachedPage(session)) {
      return {ok: false, message: 'Attach one page in the debugger. Workers and other pages are refused. Effects: code-execution and browser-control, hidden from MCP until --allow-effects.'};
    }
    if (objectLab(session)) return {ok: true, request: {action: 'list_live_wasm_objects', target_id: session.target.id}};
    if (session.target?.type && session.target.type !== 'page') {
      return {ok: false, message: 'Captured Wasm inspection accepts only the attached page. Workers and other pages are refused.'};
    }
    if (confirmed !== true) {
      return {ok: false, message: 'Captured Wasm inspection requires confirmed true. Missing fields: confirmed, captured_owner.instance_id, captured_owner.connection_epoch, captured_owner.document_epoch, captured_owner.target_id.'};
    }
    const captured = owner(session);
    if (!captured) return {ok: false, message: 'The attached document owner is incomplete. Required fields: instance_id, connection_epoch, document_epoch, target_id.'};
    return {ok: true, request: {action: 'list_live_wasm_objects', target_id: session.target.id, confirmed: true, captured_owner: captured}};
  }
  function readRequest(session, input) {
    const listing = input?.listing;
    const length = Number(input?.length);
    const offset = Number(input?.offset);
    if (!listing || !integer(listing.listing_id, Number.MAX_SAFE_INTEGER, 1) || typeof input?.objectId !== 'string') {
      return {ok: false, message: 'List live Wasm objects before reading memory.'};
    }
    if (input?.confirmed !== true) return {ok: false, message: 'Memory reads require confirmed true. Length must be 1 through 4096 bytes.'};
    if (!integer(offset, Number.MAX_SAFE_INTEGER) || !integer(length, 4096, 1)) {
      return {ok: false, message: 'Memory offset must be a safe integer and length must be 1 through 4096 bytes.'};
    }
    const request = {
      action: 'read_live_wasm_memory', target_id: listing.target_id, listing_id: listing.listing_id,
      object_id: input.objectId, offset, length, confirmed: true
    };
    if (listing.owner_scope === 'captured_document') {
      const captured = owner(session);
      if (!captured) return {ok: false, message: 'Repeat the attached captured_owner. Required fields: instance_id, connection_epoch, document_epoch, target_id.'};
      request.captured_owner = captured;
    }
    if (typeof input.exportName === 'string' && input.exportName.length > 0) request.export_name = input.exportName;
    return {ok: true, request};
  }
  function importRequest(session, input) {
    const captured = owner(session);
    if (session?.state !== 'paused' || !captured || !integer(session.generation, Number.MAX_SAFE_INTEGER)) {
      return {ok: false, message: 'Pause the attached page and select one local, closure, or block binding. Missing fields: expected_generation, owner, call_frame_id, scope_index, binding_name.'};
    }
    if (!['local', 'closure', 'block'].includes(input?.scopeType)) {
      return {ok: false, message: 'Map imports only from a local, closure, or block scope. Globals and other pages are refused.'};
    }
    if (typeof input.callFrameId !== 'string' || !input.callFrameId || typeof input.bindingName !== 'string' || !input.bindingName ||
        !integer(input.scopeIndex, 11)) {
      return {ok: false, message: 'Missing fields: call_frame_id, scope_index, binding_name.'};
    }
    return {ok: true, request: {
      action: 'inspect_paused_import_object', expected_generation: session.generation, owner: captured,
      call_frame_id: input.callFrameId, scope_index: input.scopeIndex, binding_name: input.bindingName
    }};
  }
  function reportText(report) {
    if (!report) return 'No import map yet. Pause in the glue function, then Map imports on one local, closure, or block binding.';
    const lines = [
      `provenance ${report.provenance || 'unknown'}`,
      `invocation ${report.invocation || 'unproven'}`,
      `guest_position ${report.guest_position == null ? 'null' : text(report.guest_position)}`,
      'Effects: analysis. getProperties only. No guest program counter is invented.'
    ];
    for (const module of report.modules || []) {
      lines.push(`namespace ${module.module_name} · ${module.state}`);
      for (const row of module.imports || []) {
        const place = row.host_location ? ` script ${row.host_location.script_id} line ${Number(row.host_location.line) + 1}` : '';
        lines.push(`  ${row.import_name} · ${row.state} · ${row.host_function_name || 'unnamed'}${place} · guest_position ${row.guest_position == null ? 'null' : text(row.guest_position)}`);
      }
    }
    if ((report.omissions || []).length) lines.push(`omissions ${report.omissions.join(', ')}`);
    return lines.join('\n');
  }
  function memoryText(memory) {
    if (!memory) return 'No memory slice. Reads copy 1–4096 bytes and are not atomic.';
    const bytes = Array.isArray(memory.bytes) ? memory.bytes : [];
    const hex = bytes.map(value => Number(value).toString(16).padStart(2, '0')).join(' ');
    return [`owner_scope ${memory.owner_scope}`, `offset ${memory.offset} length ${memory.length} shared ${memory.shared} atomic ${memory.atomic}`, hex || 'empty'].join('\n');
  }
  function element(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content != null) node.textContent = content;
    return node;
  }
  function mount(root, api) {
    if (!root || root.dataset.ready === '1') return;
    root.dataset.ready = '1';
    root.replaceChildren();
    const effects = element('p', 'vm-lab-note', 'Lists and reads run WebAssembly built-ins in the selected page (code-execution, browser-control). MCP hides them until --allow-effects. Captured pages need confirmed true and captured_owner: instance_id, connection_epoch, document_epoch, target_id. Other pages are refused. linkage_reason stays explicit when no artifact join exists. Caller dispatch reports are not a live sampler.');
    const notice = element('p', 'vm-lab-notice', '');
    notice.setAttribute('role', 'status');
    const confirmLabel = element('label', 'vm-lab-check');
    const confirm = document.createElement('input');
    confirm.type = 'checkbox';
    confirm.setAttribute('aria-label', 'Confirm live Wasm inspection of this attached page');
    confirmLabel.append(confirm, document.createTextNode(' Confirm inspection of this attached page'));
    const list = element('button', 'secondary-button', 'List Wasm objects');
    list.type = 'button';
    const objectLabel = element('label', null, 'Object');
    const objects = document.createElement('select');
    objects.setAttribute('aria-label', 'Live Wasm object');
    objectLabel.append(objects);
    const exportLabel = element('label', null, 'Memory export');
    const exportName = document.createElement('input');
    exportName.type = 'text';
    exportName.maxLength = 512;
    exportName.placeholder = 'Instance export name';
    exportName.setAttribute('aria-label', 'Wasm memory export name');
    exportLabel.append(exportName);
    const offsetLabel = element('label', null, 'Offset');
    const offset = document.createElement('input');
    offset.type = 'number'; offset.min = '0'; offset.value = '0';
    offset.setAttribute('aria-label', 'Wasm memory offset');
    offsetLabel.append(offset);
    const lengthLabel = element('label', null, 'Length');
    const length = document.createElement('input');
    length.type = 'number'; length.min = '1'; length.max = '4096'; length.value = '16';
    length.setAttribute('aria-label', 'Wasm memory length, 1 through 4096 bytes');
    lengthLabel.append(length);
    const read = element('button', 'secondary-button', 'Read memory slice');
    read.type = 'button';
    const row = element('div', 'vm-lab-row');
    row.append(objectLabel, exportLabel, offsetLabel, lengthLabel);
    const memory = element('pre', 'vm-lab-report');
    const imports = element('pre', 'vm-lab-report');
    const heap = element('p', 'vm-lab-note', 'Heap snapshots use the reordered V8 ingest in Memory Explorer. This lab does not sample guest program counters. Map imports from a paused local, closure, or block binding; invocation stays unproven.');
    root.append(effects, notice, confirmLabel, list, row, read, memory, imports, heap);
    const view = {root, api, confirm, list, read, objects, exportName, offset, length, notice, memory, imports};
    views.push(view);
    const paint = () => render(view);
    confirm.addEventListener('change', paint);
    list.addEventListener('click', async () => {
      const built = listRequest(api.session(), confirm.checked);
      if (!built.ok) { model.notice = built.message; refresh(); return; }
      model.notice = 'Listing live Wasm objects.';
      refresh();
      const result = await api.run(built.request);
      if (result?.wasm) {
        model.listing = result.wasm;
        model.notice = `${result.wasm.owner_scope}. ${result.wasm.linkage_reason}`;
      } else if (!result) model.notice = 'Listing was not accepted. Check the debugger status for the missing field.';
      refresh();
    });
    read.addEventListener('click', async () => {
      const built = readRequest(api.session(), {
        confirmed: confirm.checked, listing: model.listing, objectId: objects.value,
        exportName: exportName.value.trim(), offset: Number(offset.value), length: Number(length.value)
      });
      if (!built.ok) { model.notice = built.message; refresh(); return; }
      model.notice = 'Reading a bounded Wasm memory slice.';
      refresh();
      const result = await api.run(built.request);
      if (result?.memory) {
        model.memory = result.memory;
        model.notice = `Read ${result.memory.length} bytes. atomic is false. Not an artifact join.`;
      } else if (!result) model.notice = 'The memory read was not accepted.';
      refresh();
    });
    paint();
  }
  function render(view) {
    const session = view.api.session();
    const busy = view.api.busy();
    const lab = objectLab(session);
    view.notice.textContent = model.notice || (lab ? 'Object Lab is the attached disposable page. Listing does not need captured_owner. Reads still require confirmation.' : 'Captured inspection needs the confirmation above. Other pages are refused.');
    view.list.disabled = busy || !attachedPage(session) || (!lab && !view.confirm.checked);
    view.read.disabled = busy || !model.listing || !view.confirm.checked;
    const selected = view.objects.value;
    const rows = model.listing?.objects || [];
    if (view.objects.dataset.listing !== text(model.listing?.listing_id)) {
      view.objects.replaceChildren();
      for (const row of rows) {
        const option = document.createElement('option');
        option.value = row.id;
        option.textContent = `${row.kind} ${row.id}`;
        view.objects.append(option);
      }
      if (!rows.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'No listing';
        view.objects.append(option);
      }
      view.objects.dataset.listing = text(model.listing?.listing_id);
      if ([...view.objects.options].some(option => option.value === selected)) view.objects.value = selected;
    }
    view.memory.textContent = memoryText(model.memory);
    view.imports.textContent = reportText(model.importReport);
  }
  function refresh() { for (const view of views) render(view); }
  function showImport(report, notice) {
    model.importReport = report || null;
    if (notice) model.notice = notice;
    refresh();
  }
  return {owner, objectLab, listRequest, readRequest, importRequest, mount, refresh, showImport, reportText};
})();
