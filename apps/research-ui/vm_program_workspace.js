/* One VM investigation. The guest program is the Findings canvas.
   This is the owned register fixture, paused after the add.
   A loaded opcode workspace attaches only when its source digest matches. */
(function () {
  const root = document.querySelector('#vm-program-workspace');
  if (!root) return;
  const U = null;
  const steps = [
    {pc:0, next:1, op:1, name:'const', line:'r0, 7', operands:[['immediate','7']], effects:[['write','r0','7']], before:[U,U,U], after:['7',U,U], mem:[], flow:'next → PC 1', note:'Declared flow and the after-PC agree.'},
    {pc:1, next:2, op:1, name:'const', line:'r1, 5', operands:[['immediate','5']], effects:[['write','r1','5']], before:['7',U,U], after:['7','5',U], mem:[], flow:'next → PC 2', note:'Declared flow and the after-PC agree.'},
    {pc:2, next:3, op:2, name:'add', line:'r0, r0, r1', operands:[['r0','7'],['r1','5']], effects:[['read','r0','7'],['read','r1','5'],['write','r0','12']], before:['7','5',U], after:['12','5',U], mem:[], flow:'next → PC 3', note:'Addition is modulo 2^64, from the declaration. The sample records the values.'},
    {pc:3, next:4, op:3, name:'store', line:'r0', operands:[['r0','12']], effects:[['write','mem[16]','12']], before:['12','5',U], after:['12','5',U], mem:[['16','12']], flow:'next → PC 4', note:'The address operand is not in the sample. Memory 16 is the declared write target.'},
    {pc:4, next:5, op:4, name:'load', line:'r2', operands:[['mem[16]','12']], effects:[['read','mem[16]','12'],['write','r2','12']], before:['12','5',U], after:['12','5','12'], mem:[['16','12']], flow:'next → PC 5', note:'r2 becomes observed here. Before this step it was unknown.'},
    {pc:5, next:6, op:5, name:'bz', line:'r2', operands:[['r2','12'],['immediate','10']], effects:[], before:['12','5','12'], after:['12','5','12'], mem:[['16','12']], flow:'fell through → PC 6', note:'Not taken. The declaration still names target 10. This run did not take that edge.'},
    {pc:6, next:8, op:6, name:'jump', line:'→ 8', operands:[['immediate','8']], effects:[], before:['12','5','12'], after:['12','5','12'], mem:[['16','12']], flow:'jump → PC 8', note:'Index 7 is not in the program. The jump lands on 8.'},
    {pc:8, next:10, op:7, name:'bnz', line:'r2', operands:[['r2','12'],['immediate','10']], effects:[], before:['12','5','12'], after:['12','5','12'], mem:[['16','12']], flow:'taken → PC 10', note:'Taken. Target 10 matches the after-PC.'},
    {pc:10, next:10, op:8, name:'halt', line:'', operands:[], effects:[], before:['12','5','12'], after:['12','5','12'], mem:[['16','12']], flow:'halt at PC 10', note:'The fixture stops. Effects on every opcode stay inferred.', halt:true}
  ];
  const declared = [
    {pc:0, op:1, name:'const'}, {pc:1, op:1, name:'const'}, {pc:2, op:2, name:'add'},
    {pc:3, op:3, name:'store'}, {pc:4, op:4, name:'load'}, {pc:5, op:5, name:'bz'},
    {pc:6, op:6, name:'jump'}, {pc:8, op:7, name:'bnz'}, {pc:10, op:8, name:'halt'}
  ];
  const gaps = new Set([7, 9]);
  const opcodes = [[1,'const'],[2,'add'],[3,'store'],[4,'load'],[5,'bz'],[6,'jump'],[7,'bnz'],[8,'halt']];
  const GOLDEN_SOURCE = '32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e';
  let executed = 3, pin = 2, filter = null, view = 'run', detailTab = 'state';
  const history = [2];
  let historyIndex = 0;
  function shortDigest(value) {
    const hex = String(value || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) return 'unrecognized';
    return hex.slice(0, 8) + '...' + hex.slice(-4);
  }
  function workspaceAttachment() {
    let doc = null;
    try { doc = state.vmOpcodeWorkspace; } catch (error) { doc = null; }
    const workspaces = doc && Array.isArray(doc.workspaces) ? doc.workspaces : null;
    if (!workspaces) return {kind: 'absent'};
    const match = workspaces.find(item => item && item.source_artifact_sha256 === GOLDEN_SOURCE);
    if (match) return {kind: 'attached', workspace: match};
    const other = workspaces.find(item => item && item.source_artifact_sha256);
    return {kind: 'refused', digest: other ? other.source_artifact_sha256 : ''};
  }
  function quietLine(attachment) {
    const base = 'No effect on this run is contradicted. Nothing is confirmed. ';
    if (attachment.kind === 'refused') return base + 'The loaded opcode workspace was refused because its source digest is not owned-register-v1. Its handlers, bytes, and traversal stay in the findings record.';
    if (attachment.kind === 'attached') return base + 'Handler source from the matching digest is a property of the selected instruction. An instruction index still cannot characterize a guest byte.';
    return base + 'No opcode workspace is attached, so handler source, guest bytes, and traversal stay unknown.';
  }
  root.innerHTML = [
    '<div class="vmp-top"><div class="vmp-title"><div class="vmp-kicker">Owned fixture · deterministic example</div><h2>owned-register-v1</h2>',
    '<p class="vmp-meta"><b>fixture finding</b> 105 · <b>interpreter</b> 107 · <b>bytecode</b> 108 · <b>source</b> <span title="32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e">32f42d24…a52e</span></p></div>',
    '<div class="vmp-mode" role="group" aria-label="Evidence shown"><button type="button" id="vmp-run" aria-pressed="true">Fixture replay</button><button type="button" id="vmp-declared" aria-pressed="false">Declarations</button></div></div>',
    '<div class="vmp-session"><span class="vmp-pill" id="vmp-pill"><i class="vmp-dot"></i><span id="vmp-state">Paused</span></span><span class="vmp-facts" id="vmp-facts"></span><span class="vmp-spacer"></span>',
    '<button class="vmp-btn" type="button" id="vmp-follow">Current replay PC</button><button class="vmp-btn primary" type="button" id="vmp-step">Next fixture step</button><button class="vmp-btn" type="button" id="vmp-reset">Reset replay</button></div>',
    '<p class="vmp-provenance">Authored owned-register-v1 example. Replay reveals fixed fixture transitions; it does not execute a VM or represent the active capture.</p>',
    '<p class="vmp-refusal" id="vmp-refusal" hidden></p>',
    '<div class="vmp-ruler"><div class="vmp-kicker">Instruction index</div><div class="vmp-cells" id="vmp-cells"></div>',
    '<div class="vmp-bytes" id="vmp-bytes"><strong>Guest bytes unavailable.</strong> An instruction index cannot characterize a byte. This is not execution coverage.</div>',
    '<div class="vmp-key"><span><i class="obs"></i>observed</span><span><i class="inf"></i>declared only</span><span><i class="pin"></i>pinned</span><span><i class="live"></i>replay PC</span><span><i class="unk"></i>unknown</span></div>',
    '<p class="vmp-quiet" id="vmp-quiet"></p></div>',
    '<div class="vmp-navigation" aria-label="Instruction navigation"><button type="button" class="vmp-btn" id="vmp-back" aria-label="Previous selected instruction">← Back</button><button type="button" class="vmp-btn" id="vmp-forward" aria-label="Next selected instruction">Forward →</button><form id="vmp-goto"><label for="vmp-address">Go to PC</label><input id="vmp-address" inputmode="numeric" placeholder="index" aria-describedby="vmp-navigation-status"><button type="submit" class="vmp-btn">Go</button></form><span id="vmp-navigation-status" role="status" aria-live="polite">Select a row · ↑ ↓ Home End</span></div>',
    '<div class="vmp-body"><aside class="vmp-symbols" aria-label="Opcode browser"><div class="vmp-pane-head">Opcodes <span>observed / declared</span></div><div class="vmp-isa" id="vmp-isa"></div></aside>',
    '<section class="vmp-listing" aria-label="Instruction listing"><div class="vmp-pane-head">Listing <span>PC units: instruction index</span></div><p class="vmp-filter" id="vmp-filter" hidden></p><div class="vmp-columns" aria-hidden="true"><span>PC</span><span>Op</span><span>Instruction</span><span>Dispatch</span></div><div class="vmp-rows" id="vmp-rows"></div></section>',
    '<section class="vmp-inspector" id="vmp-inspector" aria-label="Selected instruction"></section></div>',
    '<div class="vmp-queue"><div class="vmp-kicker" id="vmp-qk">Open</div><div class="vmp-items" id="vmp-queue"></div></div>'
  ].join('');
  const $ = id => document.getElementById(id);
  const stepAt = pc => steps.find(step => step.pc === pc);
  const done = pc => view === 'run' && steps.slice(0, executed).some(step => step.pc === pc);
  const livePc = () => view !== 'run' ? null : executed === 0 ? 0 : steps[executed - 1].next;
  const halted = () => view === 'run' && executed === steps.length;
  function regText(before, after, i) {
    const b = before[i], a = after[i];
    if (b === U && a === U) return ['unknown', 'vmp-unk'];
    if (b === U) return ['unknown → ' + a, 'vmp-chg'];
    if (a === U) return [b + ' → unknown', 'vmp-chg'];
    if (b === a) return [a + '  unchanged', 'vmp-same'];
    return [b + ' → ' + a, 'vmp-chg'];
  }
  function queueItems(attachment) {
    const items = [
      {id:'bytes', kind:'static', title:'Guest bytes unavailable', detail:'Instruction-index PCs. No retained byte is characterized.'},
      {id:'layout', kind:'static', title:'Operand byte layout unknown', detail:'All eight declarations leave offset and size null.'},
      {id:'entry', kind:'static', title:'Traversal entry unavailable', detail:'No byte entry, so reachability stays incomplete.'}
    ];
    if (attachment.kind === 'refused') items.unshift({id:'refuse', kind:'static', title:'Opcode workspace refused', detail:'Source digest does not match owned-register-v1, so that document is not drawn here.'});
    if (view === 'declared') {
      items.push({id:'sampler', kind:'static', title:'Sampler unavailable', detail:'Handlers are declared. No dispatch sample is a confirmation.'});
      return items;
    }
    if (executed < 5) items.push({id:'r2', kind:'run', title:'r2 unknown', detail:'Stored bits are 0. That is not an observed value.'});
    const ahead = steps.length - executed;
    if (ahead) items.push({id:'ahead', kind:'run', title:ahead + (ahead === 1 ? ' instruction not sampled' : ' instructions not sampled'), detail:'Declared handlers ahead of the live PC.'});
    else items.push({id:'confirm', kind:'static', title:'Nothing confirmed', detail:'Halt was observed. Every effect is still inferred.'});
    return items;
  }
  function evidenceMarkup(d, step, attachment) {
    const reads = step ? step.effects.filter(item => item[0] === 'read') : [];
    const writes = step ? step.effects.filter(item => item[0] === 'write') : [];
    const flow = step ? step.flow : 'Unknown until a sample records this instruction.';
    const readText = reads.length ? reads.map(item => item[1] + ' = ' + item[2]).join(', ') : 'unknown';
    const writeText = writes.length ? writes.map(item => item[1] + ' = ' + item[2]).join(', ') : 'unknown';
    let source = 'Unknown. No opcode workspace is attached.';
    let reach = 'Traversal entry unavailable. No retained byte can be an entry.';
    if (attachment.kind === 'refused') {
      source = 'Refused. Loaded source ' + shortDigest(attachment.digest) + ' is not ' + shortDigest(GOLDEN_SOURCE) + '.';
      reach = 'Not drawn. Reachability from the refused document stays in the findings record.';
    } else if (attachment.kind === 'attached') {
      const handler = (attachment.workspace.handlers || []).find(item => item && item.opcode === d.op);
      const coordinate = handler && handler.source;
      const offset = coordinate && Number.isSafeInteger(coordinate.byte_offset) && coordinate.byte_offset >= 0 ? coordinate.byte_offset : null;
      const size = coordinate && Number.isSafeInteger(coordinate.byte_size) && coordinate.byte_size > 0 ? coordinate.byte_size : null;
      source = offset === null ? 'Matching source is attached. This opcode has no handler coordinate.' : 'Matching source, byte ' + offset + ', size ' + (size === null ? 'unknown' : size) + '.';
      reach = 'Entry still unavailable. A matching source does not invent a byte entry for an instruction index.';
    }
    return '<div class="vmp-sec"><div class="vmp-kicker">Declared effect</div><div class="vmp-kv"><span>layout</span><b class="vmp-unk">offset and size unknown</b><span>width</span><b class="vmp-unk">unknown</b><span>reads</span><b>' + readText + '</b><span>writes</span><b>' + writeText + '</b><span>flow</span><b>' + flow + '</b></div></div>'
      + '<div class="vmp-sec"><div class="vmp-kicker">Handler source</div><p>' + source + '</p></div>'
      + '<div class="vmp-sec"><div class="vmp-kicker">Reachability</div><p>' + reach + '</p></div>'
      + '<div class="vmp-sec"><div class="vmp-kicker">Bytes of this instruction</div><p>An instruction index cannot characterize a byte in the retained snapshot.</p></div>'
      + '<div class="vmp-sec"><div class="vmp-kicker">Isolated experiment</div><p>Unavailable. Confirmation needs an isolated experiment for opcode ' + d.op + ' and these inputs. It does not generalize.</p></div>';
  }
  function paintInspector(attachment) {
    const live = livePc();
    const d = declared.find(item => item.pc === pin);
    const exec = d && done(pin);
    const step = exec ? stepAt(pin) : null;
    if (!d) { $('vmp-inspector').innerHTML = ''; return; }
    const claims = [
      exec ? '<span class="vmp-chip obs">dispatch observed</span>' : '<span class="vmp-chip inf">declared only</span>',
      '<span class="vmp-chip inf">effect inferred</span>',
      '<span class="vmp-chip no">not confirmed</span>'
    ];
    if (view === 'run' && pin === live && !exec) claims.push('<span class="vmp-chip">replay cursor</span>');
    let body = '<div class="vmp-sec"><div class="vmp-kicker">Identity</div><div class="vmp-kv"><span>PC</span><b>' + pin + '</b><span>units</span><b>instruction index</b><span>opcode</span><b>' + d.op + '</b><span>handler</span><b>' + d.op + '</b><span>binding</span><b>declared reference</b></div></div>';
    if (step) {
      body += '<div class="vmp-sec"><div class="vmp-kicker">Operands · observed</div><div class="vmp-kv">';
      if (!step.operands.length) body += '<span>operands</span><b class="vmp-unk">none</b>';
      for (const [name, value] of step.operands) body += '<span>' + name + '</span><b>' + value + '</b>';
      body += '<span>bytes</span><b class="vmp-unk">unavailable</b></div>';
      if (step.effects.length) {
        body += '<div class="vmp-kicker" style="margin-top:8px">Accesses</div><div class="vmp-kv">';
        for (const [access, loc, value] of step.effects) body += '<span>' + access + '</span><b>' + loc + ' = ' + value + '</b>';
        body += '</div>';
      }
      body += '<div class="vmp-kicker" style="margin-top:8px">Flow</div><p>' + step.flow + '</p><p class="vmp-note">' + step.note + '</p></div>';
      body += '<div class="vmp-sec"><div class="vmp-kicker">Registers</div><div class="vmp-kv">';
      for (let i = 0; i < 3; i++) {
        const [text, kind] = regText(step.before, step.after, i);
        body += '<span>r' + i + '</span><b class="' + kind + '">' + text + '</b>';
      }
      body += '</div>';
      if (step.after.includes(U)) body += '<p class="vmp-note">Unknown is not zero. A stored 0 with unknown evidence is not shown as a value.</p>';
      body += '</div><div class="vmp-sec"><div class="vmp-kicker">Memory · guest address</div><div class="vmp-kv">';
      if (!step.mem.length) body += '<span>access</span><b class="vmp-unk">none this step</b>';
      for (const [addr, value] of step.mem) body += '<span>[' + addr + ']</span><b>' + value + ' observed</b>';
      body += '</div></div>';
    } else {
      body += '<div class="vmp-sec"><div class="vmp-kicker">Snapshot</div><p>No retained transition at this PC. Operands stay unknown until a sample records them.</p><p class="vmp-note">The mnemonic is the declared name. It is not a lifted program.</p></div>';
    }
    body = '<div class="vmp-detail-panel"' + (detailTab === 'state' ? '' : ' hidden') + '>' + body + '</div><div class="vmp-detail-panel"' + (detailTab === 'evidence' ? '' : ' hidden') + '>' + evidenceMarkup(d, step, attachment) + '</div>';
    body += '<p class="vmp-host">Host events · none linked to this instruction.</p>';
    $('vmp-inspector').innerHTML = '<div class="vmp-kicker">' + (exec ? 'Pinned step' : 'Pinned declaration') + '</div><h3>' + d.name + '</h3>' + (step && step.line ? '<p class="vmp-line">' + step.line + '</p>' : '') + '<div class="vmp-claims">' + claims.join('') + '</div>' + '<div class="vmp-detail-tabs" role="group" aria-label="Instruction details"><button type="button" data-act="tab" data-tab="state" aria-pressed="' + (detailTab === 'state') + '">State</button><button type="button" data-act="tab" data-tab="evidence" aria-pressed="' + (detailTab === 'evidence') + '">Evidence & source</button></div><div class="vmp-detail-scroll">' + body + '</div>';
  }
  function render() {
    const active = document.activeElement;
    const focusKey = root.contains(active) ? ['act', 'pc', 'op', 'tab'].map(key => [key, active.dataset[key]]).filter(([, value]) => value !== undefined) : [];
    const scroll = ['vmp-rows', 'vmp-isa'].map(id => [id, $(id).scrollTop]);
    const detailScroll = root.querySelector('.vmp-detail-scroll')?.scrollTop || 0;
    const attachment = workspaceAttachment();
    const refusal = $('vmp-refusal');
    if (attachment.kind === 'refused') {
      refusal.hidden = false;
      refusal.textContent = 'Refused to attach the loaded opcode workspace (' + shortDigest(attachment.digest) + '). It is a different program, so it stays in the findings record.';
    } else {
      refusal.hidden = true;
      refusal.textContent = '';
    }
    $('vmp-quiet').textContent = quietLine(attachment);

    const live = livePc();
    const run = view === 'run';
    $('vmp-run').setAttribute('aria-pressed', String(run));
    $('vmp-declared').setAttribute('aria-pressed', String(!run));
    const pill = $('vmp-pill');
    pill.dataset.kind = !run ? 'static' : halted() ? 'halted' : 'paused';
    $('vmp-state').textContent = !run ? 'Static' : halted() ? 'Replay complete' : 'Replay paused';
    $('vmp-facts').textContent = !run ? 'declarations only · no live cursor' : halted() ? '9 of 9 revealed · halted at PC 10' : executed + ' of 9 revealed · replay PC ' + live + ' · pinned PC ' + pin;
    $('vmp-step').disabled = !run || halted();
    $('vmp-follow').disabled = !run || pin === live;
    $('vmp-follow').textContent = run && pin === live ? 'At replay PC' : 'Current replay PC';
    const cells = [];
    for (let pc = 0; pc <= 10; pc++) {
      const gap = gaps.has(pc);
      const exec = !gap && done(pc);
      const cls = ['vmp-cell', gap ? 'gap' : exec ? 'exec' : 'ahead', pc === live ? 'live' : '', pc === pin ? 'pin' : ''].filter(Boolean).join(' ');
      cells.push('<button type="button" class="' + cls + '" data-act="cell" data-pc="' + pc + '" aria-label="Instruction index ' + pc + (gap ? ' absent' : '') + '" aria-pressed="' + (pc === pin) + '"' + (gap ? ' disabled' : '') + '>' + pc + '</button>');
    }
    $('vmp-cells').innerHTML = cells.join('');
    const counts = {};
    for (const [op] of opcodes) counts[op] = {n:0, seen:0};
    for (const item of declared) { counts[item.op].n += 1; if (done(item.pc)) counts[item.op].seen += 1; }
    $('vmp-isa').innerHTML = opcodes.map(([op, name]) => {
      const count = counts[op];
      return '<button type="button" class="vmp-op" data-act="op" data-op="' + op + '" aria-pressed="' + (filter === op) + '"><span>' + String(op).padStart(2, '0') + '</span><span class="nm">' + name + '</span><span class="ct' + (count.seen ? ' has' : '') + '">' + (run ? count.seen + '/' + count.n : '0/' + count.n) + '</span></button>';
    }).join('');
    const show = [];
    for (let pc = 0; pc <= 10; pc++) {
      if (gaps.has(pc)) { if (filter === null && run) show.push({pc, gap:true}); continue; }
      const item = declared.find(entry => entry.pc === pc);
      if (filter !== null && item.op !== filter) continue;
      show.push({pc, gap:false, item, step: done(pc) ? stepAt(pc) : null});
    }
    $('vmp-filter').hidden = filter === null;
    if (filter !== null) {
      const name = opcodes.find(entry => entry[0] === filter)[1];
      $('vmp-filter').innerHTML = 'Opcode ' + String(filter).padStart(2, '0') + ' ' + name + ' <button type="button" data-act="clear">Show the program</button>';
    }
    $('vmp-rows').innerHTML = show.map(row => {
      if (row.gap) return '<div class="vmp-row gaprow"><span>' + row.pc + '</span><span></span><span class="mn">index absent</span><span class="ev">gap</span></div>';
      const exec = !!row.step;
      const cls = ['vmp-row', exec ? 'observed' : 'inferred', row.pc === pin ? 'pin' : '', row.pc === live ? 'live' : ''].filter(Boolean).join(' ');
      const line = exec && row.step.line ? row.step.name + ' ' + row.step.line : row.item.name;
      const evidence = (exec ? 'observed' : 'inferred') + (row.pc === live ? ' · current' : '');
      return '<button type="button" class="' + cls + '" data-act="row" data-pc="' + row.pc + '" aria-pressed="' + (row.pc === pin) + '"><span class="pc">' + row.pc + '</span><span>' + String(row.item.op).padStart(2, '0') + '</span><span class="mn">' + line + '</span><span class="ev">' + evidence + '</span></button>';
    }).join('');
    paintInspector(attachment);
    const items = queueItems(attachment);
    $('vmp-qk').textContent = 'Open · ' + items.length;
    $('vmp-queue').innerHTML = items.map(item => '<div class="vmp-item ' + item.kind + '"><i></i><span><strong>' + item.title + '</strong><em>' + item.detail + '</em></span></div>').join('');
    $('vmp-back').disabled = historyIndex === 0;
    $('vmp-forward').disabled = historyIndex === history.length - 1;
    for (const [id, top] of scroll) $(id).scrollTop = top;
    root.querySelector('.vmp-detail-scroll').scrollTop = detailScroll;
    if (focusKey.length) root.querySelector(focusKey.map(([key, value]) => '[data-' + key + '="' + value + '"]').join(''))?.focus({preventScroll: true});
  }
  function select(pc, remember = true) {
    if (!declared.some(item => item.pc === pc)) return;
    if (remember && pc !== pin) { history.splice(historyIndex + 1); history.push(pc); if (history.length > 24) history.shift(); historyIndex = history.length - 1; }
    pin = pc; render();
  }
  function reveal() {
    const row = root.querySelector('[data-act="row"][data-pc="' + pin + '"]');
    row?.focus({preventScroll: true}); row?.scrollIntoView({block: 'nearest'});
  }
  root.addEventListener('click', event => {
    const node = event.target.closest('[data-act]');
    if (!node || !root.contains(node)) return;
    const act = node.dataset.act;
    if (act === 'tab') { detailTab = node.dataset.tab; render(); }
    if (act === 'row' || act === 'cell') { if (act === 'cell') filter = null; select(Number(node.dataset.pc)); }
    if (act === 'op') {
      const op = Number(node.dataset.op);
      if (filter === op) { filter = null; render(); return; }
      filter = op;
      const match = declared.find(item => item.op === op && done(item.pc)) || declared.find(item => item.op === op);
      select(match.pc);
    }
    if (act === 'clear') { filter = null; render(); reveal(); }
  });
  $('vmp-step').addEventListener('click', () => { if (view === 'run' && executed < steps.length) { executed += 1; render(); } });
  $('vmp-follow').addEventListener('click', () => { if (view === 'run') { filter = null; select(livePc()); reveal(); } });
  $('vmp-reset').addEventListener('click', () => { executed = 3; pin = 2; filter = null; view = 'run'; history.splice(0, history.length, 2); historyIndex = 0; render(); });
  $('vmp-run').addEventListener('click', () => { view = 'run'; render(); });
  $('vmp-declared').addEventListener('click', () => { view = 'declared'; filter = null; render(); });
  root.addEventListener('keydown', event => {
    const row = event.target.closest('[data-act="row"]');
    if (!row || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const rows = [...root.querySelectorAll('[data-act="row"]')];
    const index = rows.indexOf(row);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1 : Math.max(0, Math.min(rows.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
    event.preventDefault(); select(Number(rows[next].dataset.pc)); reveal();
  });
  $('vmp-back').addEventListener('click', () => { if (historyIndex > 0) { filter = null; select(history[--historyIndex], false); } });
  $('vmp-forward').addEventListener('click', () => { if (historyIndex < history.length - 1) { filter = null; select(history[++historyIndex], false); } });
  $('vmp-goto').addEventListener('submit', event => {
    event.preventDefault(); const text = $('vmp-address').value.trim(); const pc = /^\d+$/.test(text) ? Number(text) : NaN;
    if (!declared.some(item => item.pc === pc)) { $('vmp-navigation-status').textContent = 'No instruction at that index. Available: 0–6, 8, 10.'; return; }
    filter = null; select(pc); reveal(); $('vmp-navigation-status').textContent = 'Selected PC ' + pc;
  });
  render();
  const detail = document.querySelector('#vm-detail');
  if (detail) new MutationObserver(() => render()).observe(detail, {childList: true});
}());
