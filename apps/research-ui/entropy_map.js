/* Sources Map: one fixed-size picture of a whole captured artifact, from
 * protocol/artifact-map-v1.md. The backend reads the bytes; this view holds only
 * the two cell arrays of the artifact currently shown, paints one canvas with
 * one ImageData, and uses no DOM per cell. Everything is released when the map
 * closes, the selection changes or the session changes. Captured-derived text
 * is inserted as text only. */
const ENTROPY_MAP_TIMEOUT_MS = 90000;
const ENTROPY_MAP_MAX_SIDE = 128;
const ENTROPY_MAP_GROUPS = ['code', 'data', 'string', 'structure', 'custom', 'undecoded', 'unknown'];
const ENTROPY_MAP_GROUP_LABELS = {code: 'code', data: 'data', string: 'string', structure: 'structure', custom: 'custom', undecoded: 'undecoded', unknown: 'unknown'};

// Hilbert curve index to cell, so adjacent bytes stay adjacent on the square.
function entropyMapHilbertPoint(side, index) {
  let x = 0, y = 0, remaining = index;
  for (let span = 1; span < side; span *= 2) {
    const rx = 1 & Math.floor(remaining / 2);
    const ry = 1 & (remaining ^ rx);
    if (ry === 0) {
      if (rx === 1) { x = span - 1 - x; y = span - 1 - y; }
      const swap = x; x = y; y = swap;
    }
    x += span * rx;
    y += span * ry;
    remaining = Math.floor(remaining / 4);
  }
  return [x, y];
}

function entropyMapHilbertIndex(side, column, row) {
  let x = column, y = row, index = 0;
  for (let span = side / 2; span >= 1; span = Math.floor(span / 2)) {
    const rx = (x & span) > 0 ? 1 : 0;
    const ry = (y & span) > 0 ? 1 : 0;
    index += span * span * ((3 * rx) ^ ry);
    if (ry === 0) {
      if (rx === 1) { x = side - 1 - x; y = side - 1 - y; }
      const swap = x; x = y; y = swap;
    }
  }
  return index;
}

function entropyMapDecode(text, expected) {
  if (typeof text !== 'string') return null;
  let binary;
  try { binary = atob(text); } catch { return null; }
  if (binary.length !== expected) return null;
  const cells = new Uint8Array(expected);
  for (let index = 0; index < expected; index += 1) cells[index] = binary.charCodeAt(index);
  return cells;
}

function isEntropyMapDocument(value, source) {
  const grid = value?.grid, entropy = value?.entropy, high = value?.high_entropy, kinds = value?.kind_map;
  return Boolean(value) && value.version === 1 && value.schema === 'artifact-map-v1' &&
    value.artifact_id === source?.artifact_id && value.sha256 === source?.sha256 &&
    Number.isSafeInteger(value.byte_length) && value.byte_length === source?.byte_size &&
    Number.isSafeInteger(grid?.side) && grid.side >= 0 && grid.side <= ENTROPY_MAP_MAX_SIDE &&
    (grid.side === 0 || (grid.side & (grid.side - 1)) === 0) && grid.order === 'hilbert' &&
    grid.cell_count === grid.side * grid.side && Number.isSafeInteger(grid.window_bytes) &&
    entropy?.units_per_bit === 30 && typeof entropy.cells === 'string' &&
    typeof entropy.mean_bits === 'number' && typeof entropy.max_bits === 'number' &&
    typeof high?.threshold_bits === 'number' && Number.isSafeInteger(high.threshold_units) &&
    Number.isSafeInteger(high.windows) && Number.isSafeInteger(high.bytes) &&
    typeof kinds?.cells === 'string' && Number.isSafeInteger(kinds.mixed_flag) && Array.isArray(kinds.kinds) &&
    kinds.kinds.length > 0 && kinds.kinds.length <= 32 &&
    kinds.kinds.every(row => typeof row?.label === 'string' && ENTROPY_MAP_GROUPS.includes(row.group)) &&
    Array.isArray(value.highest_ranges) && value.highest_ranges.length <= 8 &&
    value.highest_ranges.every(row => Number.isSafeInteger(row?.start) && Number.isSafeInteger(row?.end) &&
      row.start >= 0 && row.end > row.start && row.end <= value.byte_length && typeof row.peak_bits === 'number') &&
    typeof value.facts?.source === 'string' && Array.isArray(value.facts.notes);
}

function entropyMapHex(value) { return `0x${value.toString(16)}`; }

function entropyMapBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Line and column of a UTF-8 byte offset in decoded text, or null past its end.
function entropyMapTextPosition(text, byteOffset) {
  let bytes = 0, line = 0, column = 0;
  for (let index = 0; index < text.length; index += 1) {
    if (bytes >= byteOffset) return {line, column};
    const code = text.charCodeAt(index);
    if (code === 10) { line += 1; column = 0; bytes += 1; continue; }
    column += 1;
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) { bytes += 4; index += 1; column += 1; }
    else bytes += 3;
  }
  return bytes >= byteOffset && text.length > 0 ? {line, column} : null;
}

function entropyMapHexColor(value) {
  const match = /^#([0-9a-f]{6})$/i.exec(String(value).trim());
  if (!match) return [0, 0, 0];
  const number = Number.parseInt(match[1], 16);
  return [number >> 16, (number >> 8) & 255, number & 255];
}

// Moves Sources to one original byte and reports why it could not, without
// leaving the map. Hex and disassembly use their own row layouts.
function revealSourceByteOffset(source, offset, leaveMap) {
  if (!source || sourceIdentity(selectedSource()) !== sourceIdentity(source)) return 'This artifact is no longer selected.';
  const label = `Byte ${entropyMapHex(offset)}`;
  if (source.content === undefined) return `${label} cannot be shown yet: the artifact view has not loaded.`;
  if (sourceHexArtifact(source)) {
    if (state.sourceWasm && source.kind === 'wasm' && state.wasmCache.has(wasmKey(source))) {
      const rows = sourceDisplayView(source).wasmRows ?? [];
      let line = -1;
      rows.forEach((row, index) => { if (row.byte_offset !== null && row.byte_offset <= offset) line = index; });
      if (line < 0) return `${label} comes before the first inspection row.`;
      leaveMap();
      renderSources();
      moveSourceWindow(line);
      return '';
    }
    const limit = source.wasmHexBytes ?? 0;
    if (offset >= limit) return `${label} is past the first ${entropyMapBytes(limit)} the hex view holds. The map covers the whole artifact.`;
    state.sourceWasm = false;
    leaveMap();
    renderSources();
    const line = Math.floor(offset / 16);
    moveSourceWindow(line);
    const row = elements.sourceCode.querySelector(`[data-local-line="${line}"]`);
    if (row) { row.tabIndex = -1; row.focus({preventScroll: true}); row.scrollIntoView({block: 'center'}); }
    elements.sourcePosition.textContent = `${label} · hex row ${entropyMapHex(line * 16)}`;
    return '';
  }
  if (source.contentLossy) return `${label} cannot be placed: the text view replaced invalid UTF-8.`;
  const text = source.content.slice(0, source.sourceTextLength ?? source.content.length);
  const position = entropyMapTextPosition(text, offset);
  if (!position) return `${label} is past the ${entropyMapBytes(Math.min(source.byte_size, 2097152))} of text Sources holds. The map covers the whole artifact.`;
  leaveMap();
  renderSources();
  revealOriginalLine(source, position.line, position.column);
  return '';
}

const ENTROPY_MAP_VIEW_KIND = 'Whole-artifact map · original bytes';

function createEntropyMap({button, root, codeWrap, viewKind, toolbar, getSource, identityOf, reveal}) {
  let open = false, built = null, generation = 0, controller = null, timer = 0, mode = 'entropy';
  let openIdentity = null, map = null, status = 'idle', message = '', themeObserver = null;
  let hover = -1, cursor = -1, lut = null, focusWhenReady = false, codeViewKind = null;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  function build() {
    if (built) return built;
    const head = element('header', 'map-head');
    const title = element('h2', 'map-title', 'Map');
    const stats = element('span', 'map-stats');
    const modes = element('div', 'map-modes');
    modes.setAttribute('role', 'group');
    modes.setAttribute('aria-label', 'Map coloring');
    const modeButtons = ['entropy', 'kind'].map(value => {
      const control = element('button', '', value === 'entropy' ? 'Entropy' : 'Kind');
      control.type = 'button';
      control.dataset.mapMode = value;
      control.addEventListener('click', () => setMode(value));
      modes.append(control);
      return control;
    });
    head.append(title, stats, modes);

    const statePanel = element('div', 'map-state');
    statePanel.setAttribute('role', 'status');
    statePanel.setAttribute('aria-live', 'polite');
    const stateText = element('p', 'map-state-text');
    const retry = element('button', 'map-retry', 'Retry');
    retry.type = 'button';
    retry.addEventListener('click', load);
    statePanel.append(stateText, retry);

    const body = element('div', 'map-body');
    const main = element('div', 'map-main');
    const frame = element('div', 'map-frame');
    const area = element('div', 'map-area');
    const canvas = element('canvas', 'map-canvas');
    canvas.tabIndex = 0;
    canvas.setAttribute('role', 'application');
    canvas.setAttribute('aria-label', 'Artifact map. Arrow keys move between windows, Enter opens the bytes.');
    const hoverCell = element('div', 'map-cell');
    const focusCell = element('div', 'map-cell map-cell-focus');
    hoverCell.hidden = true;
    focusCell.hidden = true;
    const popover = element('div', 'map-popover');
    popover.hidden = true;
    area.append(canvas, hoverCell, focusCell, popover);
    frame.append(area);

    const legend = element('div', 'map-legend');
    const ramp = element('div', 'map-ramp');
    const low = element('span', 'map-ramp-end', '0');
    const track = element('div', 'map-ramp-track');
    const tick = element('span', 'map-ramp-tick');
    const marker = element('span', 'map-ramp-marker');
    marker.hidden = true;
    track.append(tick, marker);
    const highEnd = element('span', 'map-ramp-end', '8 bits');
    const threshold = element('span', 'map-threshold');
    const statusDot = element('span', 'map-status-dot');
    const statusWord = element('span', 'map-status');
    ramp.append(low, track, highEnd, threshold, statusDot, statusWord);
    const kindLegend = element('ul', 'map-kind-legend');
    kindLegend.hidden = true;
    legend.append(ramp, kindLegend);
    main.append(frame, legend);

    const summary = element('aside', 'map-summary');
    summary.setAttribute('aria-label', 'Artifact summary');
    const facts = element('dl', 'map-facts');
    const noticeLine = element('p', 'map-notice');
    noticeLine.setAttribute('role', 'status');
    noticeLine.hidden = true;
    const rangesHead = element('h3', 'map-section', 'Highest entropy');
    const ranges = element('ul', 'map-ranges');
    const notes = element('ul', 'map-notes');
    summary.append(facts, noticeLine, rangesHead, ranges, notes);

    body.append(main, summary);
    const announce = element('p', 'map-announce');
    announce.setAttribute('aria-live', 'polite');
    root.replaceChildren(head, statePanel, body, announce);

    canvas.addEventListener('pointermove', event => setHover(cellAt(event)));
    canvas.addEventListener('pointerleave', () => setHover(-1));
    canvas.addEventListener('click', event => { const cell = cellAt(event); if (cell >= 0) { setCursor(cell); activate(cell); } });
    // The focused cell appears on the first key press, so opening the map with
    // a pointer does not leave a stray cursor and popover over the first window.
    canvas.addEventListener('blur', () => { focusCell.hidden = true; showPopover(hover); });
    canvas.addEventListener('keydown', keydown);

    built = {stats, modeButtons, statePanel, stateText, retry, body, canvas, hoverCell, focusCell, popover, area, marker, tick, threshold,
      statusDot, statusWord, kindLegend, ramp, facts, noticeLine, rangesHead, ranges, notes, announce};
    return built;
  }

  function cellRange(index) {
    const start = Math.floor(index * map.byteLength / map.cellCount);
    const end = Math.floor((index + 1) * map.byteLength / map.cellCount);
    return [start, end];
  }

  function cellAt(event) {
    if (!map || !built) return -1;
    const box = built.canvas.getBoundingClientRect();
    if (!box.width || !box.height) return -1;
    const column = Math.max(0, Math.min(map.side - 1, Math.floor((event.clientX - box.left) / box.width * map.side)));
    const row = Math.max(0, Math.min(map.side - 1, Math.floor((event.clientY - box.top) / box.height * map.side)));
    return entropyMapHilbertIndex(map.side, column, row);
  }

  function cellBits(index) { return map.entropy[index] / map.doc.entropy.units_per_bit; }
  function cellKind(index) { return map.doc.kind_map.kinds[map.kinds[index] & ~map.doc.kind_map.mixed_flag]; }
  function cellMixed(index) { return (map.kinds[index] & map.doc.kind_map.mixed_flag) !== 0; }
  function cellHigh(index) { return map.entropy[index] >= map.doc.high_entropy.threshold_units; }

  function renderCell(index, node) {
    if (index < 0 || !map) { node.hidden = true; return; }
    const [x, y] = entropyMapHilbertPoint(map.side, index);
    const size = 100 / map.side;
    node.style.left = `${x * size}%`;
    node.style.top = `${y * size}%`;
    node.style.width = `${size}%`;
    node.style.height = `${size}%`;
    node.hidden = false;
  }

  function describe(index) {
    const [start, end] = cellRange(index);
    const kind = cellKind(index);
    return `${entropyMapHex(start)} to ${entropyMapHex(end - 1)}, ${kind.label}${cellMixed(index) ? ' mixed' : ''}, entropy ${cellBits(index).toFixed(2)} bits per byte`;
  }

  function showPopover(index) {
    const {popover, area, marker, statusWord} = built;
    if (index < 0 || !map) {
      popover.hidden = true;
      marker.hidden = true;
      statusWord.textContent = legendStatus();
      built.statusDot.hidden = mode !== 'entropy' || (map?.doc.high_entropy.windows ?? 0) === 0;
      return;
    }
    const [start, end] = cellRange(index);
    const kind = cellKind(index);
    const bits = cellBits(index);
    const rows = [['range', `${entropyMapHex(start)} - ${entropyMapHex(end - 1)}`], ['kind', `${kind.label}${cellMixed(index) ? ' (mixed)' : ''}`], ['entropy', `${bits.toFixed(2)} bits/byte`]];
    popover.replaceChildren(...rows.flatMap(([key, value]) => [element('span', 'map-popover-key', key), element('span', 'map-popover-value', value)]));
    popover.hidden = false;
    const [x, y] = entropyMapHilbertPoint(map.side, index);
    const cell = area.clientWidth / map.side;
    const left = (x + 1) * cell + 12;
    const top = y * cell;
    const width = popover.offsetWidth, height = popover.offsetHeight;
    popover.style.left = `${left + width > area.clientWidth ? Math.max(4, x * cell - width - 12) : left}px`;
    popover.style.top = `${Math.max(4, Math.min(area.clientHeight - height - 4, top))}px`;
    marker.style.left = `${bits / 8 * 100}%`;
    marker.hidden = mode !== 'entropy';
    if (mode === 'entropy') {
      statusWord.textContent = cellHigh(index) ? 'high-entropy' : 'under threshold';
      built.statusDot.hidden = !cellHigh(index);
    }
  }

  function setHover(index) {
    if (index === hover) return;
    hover = index;
    renderCell(index, built.hoverCell);
    if (index >= 0) showPopover(index);
    else if (document.activeElement === built.canvas && cursor >= 0) showPopover(cursor);
    else showPopover(-1);
  }

  function setCursor(index) {
    cursor = index;
    renderCell(index, built.focusCell);
    if (index >= 0) built.announce.textContent = describe(index);
  }

  function keydown(event) {
    if (!map) return;
    if (event.key === 'Escape') { event.preventDefault(); close(true); return; }
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); if (cursor >= 0) activate(cursor); return; }
    if (cursor < 0 && ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) {
      event.preventDefault();
      setCursor(0);
      showPopover(0);
      return;
    }
    let next = cursor < 0 ? 0 : cursor;
    if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = map.cellCount - 1;
    else {
      const delta = {ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1]}[event.key];
      if (!delta) return;
      const [x, y] = entropyMapHilbertPoint(map.side, next);
      const column = Math.max(0, Math.min(map.side - 1, x + delta[0]));
      const row = Math.max(0, Math.min(map.side - 1, y + delta[1]));
      next = entropyMapHilbertIndex(map.side, column, row);
    }
    event.preventDefault();
    setCursor(next);
    showPopover(next);
  }

  function activate(index) {
    goToByte(cellRange(index)[0]);
  }

  function goToByte(offset) {
    const source = getSource();
    const problem = reveal(source, offset, () => close(false));
    if (problem && built) {
      built.noticeLine.textContent = problem;
      built.noticeLine.hidden = false;
    }
  }

  // Tokens are the only colors. They are read once per paint so a theme change
  // repaints from the same stylesheet, and the LUT costs about 1 KB.
  function readLut() {
    const styles = getComputedStyle(document.documentElement);
    const color = name => entropyMapHexColor(styles.getPropertyValue(name));
    const stops = [[0, color('--map-entropy-0')], [60, color('--map-entropy-1')], [120, color('--map-entropy-2')], [180, color('--map-entropy-3')], [209, color('--map-entropy-4')]];
    const highLow = color('--map-high-low'), highTop = color('--map-high-top');
    const table = new Uint8Array(241 * 3);
    const mix = (a, b, t, channel) => Math.round(a[channel] + (b[channel] - a[channel]) * t);
    for (let unit = 0; unit <= 240; unit += 1) {
      let rgb;
      if (unit >= 210) {
        const t = (unit - 210) / 30;
        rgb = [0, 1, 2].map(channel => mix(highLow, highTop, t, channel));
      } else {
        let lower = stops[0], upper = stops[stops.length - 1];
        for (let index = 0; index + 1 < stops.length; index += 1) {
          if (unit >= stops[index][0] && unit <= stops[index + 1][0]) { lower = stops[index]; upper = stops[index + 1]; break; }
        }
        const span = upper[0] - lower[0] || 1;
        rgb = [0, 1, 2].map(channel => mix(lower[1], upper[1], (unit - lower[0]) / span, channel));
      }
      table.set(rgb, unit * 3);
    }
    const groups = Object.fromEntries(ENTROPY_MAP_GROUPS.map(group => [group, color(`--map-kind-${group}`)]));
    return {table, groups};
  }

  function paint() {
    if (!map || !built) return;
    lut = readLut();
    const {canvas} = built;
    if (canvas.width !== map.side || canvas.height !== map.side) {
      canvas.width = map.side;
      canvas.height = map.side;
      map.image = null;
    }
    const context = canvas.getContext('2d', {alpha: false});
    if (!context) return;
    map.image ??= context.createImageData(map.side, map.side);
    const pixels = map.image.data;
    const groupColors = map.doc.kind_map.kinds.map(row => lut.groups[row.group]);
    for (let index = 0; index < map.cellCount; index += 1) {
      const [x, y] = entropyMapHilbertPoint(map.side, index);
      const offset = (y * map.side + x) * 4;
      if (mode === 'entropy') {
        const unit = Math.min(240, map.entropy[index]) * 3;
        pixels[offset] = lut.table[unit]; pixels[offset + 1] = lut.table[unit + 1]; pixels[offset + 2] = lut.table[unit + 2];
      } else {
        const rgb = groupColors[map.kinds[index] & ~map.doc.kind_map.mixed_flag] ?? [0, 0, 0];
        pixels[offset] = rgb[0]; pixels[offset + 1] = rgb[1]; pixels[offset + 2] = rgb[2];
      }
      pixels[offset + 3] = 255;
    }
    context.putImageData(map.image, 0, 0);
  }

  function legendStatus() {
    const windows = map?.doc.high_entropy.windows ?? 0;
    return mode === 'kind' ? '' : windows ? `${windows.toLocaleString()} ${windows === 1 ? 'window' : 'windows'} high` : 'no windows high';
  }

  function renderLegend() {
    const {ramp, kindLegend, statusDot, statusWord, threshold, tick} = built;
    const doc = map?.doc;
    const entropy = mode === 'entropy';
    ramp.hidden = !entropy;
    kindLegend.hidden = entropy;
    if (!doc) return;
    threshold.textContent = `≥ ${doc.high_entropy.threshold_bits.toFixed(1)}`;
    threshold.title = `A window at or above ${doc.high_entropy.threshold_bits.toFixed(1)} bits per byte is marked high-entropy. The mark states this test only.`;
    tick.style.left = `${doc.high_entropy.threshold_bits / 8 * 100}%`;
    statusDot.hidden = !entropy || doc.high_entropy.windows === 0;
    statusWord.textContent = legendStatus();
    const present = new Map();
    for (const row of doc.kind_map.kinds) {
      if (row.windows > 0 || row.bytes > 0) present.set(row.group, (present.get(row.group) ?? 0) + row.bytes);
    }
    kindLegend.replaceChildren(...[...present].map(([group, bytes]) => {
      const item = element('li', 'map-kind-item');
      item.dataset.group = group;
      item.title = entropyMapBytes(bytes);
      const swatch = element('span', 'map-kind-swatch');
      swatch.style.background = `var(--map-kind-${group})`;
      item.append(swatch, element('span', '', ENTROPY_MAP_GROUP_LABELS[group]));
      return item;
    }));
  }

  function renderSummary() {
    const doc = map.doc;
    const {facts, ranges, notes, rangesHead} = built;
    const rows = [
      ['Length', `${doc.byte_length.toLocaleString()} bytes`],
      ['Integrity', 'SHA-256 verified'],
      ['Mean', `${doc.entropy.mean_bits.toFixed(2)} bits/byte`],
      ['Max', `${doc.entropy.max_bits.toFixed(2)} bits/byte`],
      ['High', `${doc.high_entropy.windows.toLocaleString()} windows at ≥ ${doc.high_entropy.threshold_bits.toFixed(1)} bits/byte`],
    ];
    if (doc.facts.source === 'wasm_section_frames') {
      rows.push(['Sections', String(doc.facts.sections)], ['Segments', String(doc.facts.data_segments)]);
    } else if (doc.facts.source === 'javascript_lexer') {
      rows.push(['Strings', `${doc.facts.string_literals.toLocaleString()} · ${entropyMapBytes(doc.facts.string_bytes)}`]);
    } else if (doc.facts.source === 'vm_byte_coverage') {
      rows.push(['Coverage', `${doc.facts.characterized_bytes.toLocaleString()} of ${doc.facts.analyzed_bytes.toLocaleString()} analyzed bytes`]);
    }
    facts.replaceChildren(...rows.flatMap(([key, value]) => [element('dt', '', key), element('dd', '', value)]));
    rangesHead.hidden = doc.highest_ranges.length === 0;
    ranges.replaceChildren(...doc.highest_ranges.map(range => {
      const item = element('li');
      const control = element('button', 'map-range');
      control.type = 'button';
      control.title = `Open byte ${entropyMapHex(range.start)}`;
      control.append(element('span', 'map-range-offset', `${entropyMapHex(range.start)} - ${entropyMapHex(range.end - 1)}`),
        element('span', 'map-range-bits', range.peak_bits.toFixed(2)));
      if (range.high) control.dataset.high = 'true';
      control.addEventListener('click', () => goToByte(range.start));
      item.append(control);
      return item;
    }));
    const lines = [...doc.facts.notes];
    if (doc.grid.below_min_window) lines.unshift(`Shorter than the ${doc.grid.min_window_bytes}-byte minimum window, so the entropy scale cannot be reached and this cell is never marked.`);
    notes.replaceChildren(...lines.map(text => element('li', '', text)));
    notes.hidden = lines.length === 0;
  }

  function setMode(value) {
    mode = value;
    if (!built) return;
    built.modeButtons.forEach(control => control.setAttribute('aria-pressed', String(control.dataset.mapMode === mode)));
    if (status === 'ready') { renderLegend(); paint(); if (hover >= 0) showPopover(hover); else if (document.activeElement === built.canvas && cursor >= 0) showPopover(cursor); }
  }

  function renderStatus() {
    const {statePanel: panel, stateText, retry, body, stats, modeButtons} = built;
    const ready = status === 'ready';
    panel.hidden = ready;
    body.hidden = !ready;
    stateText.textContent = message;
    retry.hidden = status !== 'error' && status !== 'disconnected';
    panel.dataset.kind = status;
    modeButtons.forEach(control => { control.disabled = !ready; });
    stats.textContent = ready ? `Hilbert ${map.side}×${map.side} · ${entropyMapBytes(map.doc.grid.window_bytes)} per cell · ${entropyMapBytes(map.byteLength)}` : '';
  }

  function cancelPending() {
    controller?.abort();
    controller = null;
    if (timer) clearTimeout(timer);
    timer = 0;
  }

  function releaseMap() {
    cancelPending();
    themeObserver?.disconnect();
    themeObserver = null;
    map = null;
    lut = null;
    hover = -1;
    cursor = -1;
    if (built) {
      // Zero-sized backing store: the bitmap is released with the map.
      built.canvas.width = 0;
      built.canvas.height = 0;
      built.hoverCell.hidden = true;
      built.focusCell.hidden = true;
      built.popover.hidden = true;
      built.marker.hidden = true;
      built.noticeLine.hidden = true;
      built.noticeLine.textContent = '';
      built.facts.replaceChildren();
      built.ranges.replaceChildren();
      built.notes.replaceChildren();
      built.kindLegend.replaceChildren();
    }
  }

  async function load() {
    const source = getSource();
    if (!open || !source) return;
    const current = generation += 1;
    releaseMap();
    status = 'loading';
    message = 'Reading the whole artifact and verifying its hash.';
    renderStatus();
    const abort = new AbortController();
    controller = abort;
    timer = setTimeout(() => abort.abort(), ENTROPY_MAP_TIMEOUT_MS);
    try {
      const response = await fetch(`/api/artifact-map?artifact_id=${encodeURIComponent(source.artifact_id)}`, {cache: 'no-store', signal: abort.signal});
      const report = await response.json().catch(() => null);
      if (current !== generation) return;
      if (!response.ok) throw new Error(report?.error ? String(report.error).slice(0, 400) : `The artifact map returned ${response.status}.`);
      if (!isEntropyMapDocument(report, source)) throw new Error('The backend returned an invalid artifact map.');
      if (report.grid.cell_count === 0) {
        status = 'empty';
        message = 'This artifact has no bytes, so there is nothing to map.';
        renderStatus();
        return;
      }
      const entropy = entropyMapDecode(report.entropy.cells, report.grid.cell_count);
      const kinds = entropyMapDecode(report.kind_map.cells, report.grid.cell_count);
      if (!entropy || !kinds || kinds.some(cell => (cell & ~report.kind_map.mixed_flag) >= report.kind_map.kinds.length)) {
        throw new Error('The backend returned an invalid artifact map.');
      }
      // The base64 strings are redundant once decoded.
      report.entropy.cells = '';
      report.kind_map.cells = '';
      map = {doc: report, entropy, kinds, side: report.grid.side, cellCount: report.grid.cell_count, byteLength: report.byte_length, image: null};
      status = 'ready';
      message = '';
      renderStatus();
      renderSummary();
      renderLegend();
      paint();
      themeObserver = new MutationObserver(() => { paint(); });
      themeObserver.observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
      // The canvas cannot take focus while the loading state hides it.
      if (focusWhenReady) built.canvas.focus({preventScroll: true});
    } catch (error) {
      if (current !== generation) return;
      const aborted = error?.name === 'AbortError';
      status = aborted || error instanceof TypeError ? 'disconnected' : 'error';
      message = aborted ? 'The map did not finish in time. The stored artifact is unchanged.'
        : error instanceof TypeError ? 'The evidence store is unavailable. The stored artifact is unchanged.' : String(error?.message ?? error).slice(0, 400);
      renderStatus();
    } finally {
      if (current === generation) { controller = null; if (timer) clearTimeout(timer); timer = 0; }
    }
  }

  // The status bar names the map as the evidence state while it shows. Closing
  // it restores the state the last Sources render wrote, unless a render for
  // another selection has already replaced the map's label.
  function showViewKind() {
    if (viewKind.textContent !== ENTROPY_MAP_VIEW_KIND) codeViewKind = viewKind.textContent;
    viewKind.textContent = ENTROPY_MAP_VIEW_KIND;
  }

  function showView() {
    build();
    root.hidden = false;
    codeWrap.hidden = true;
    setMode(mode);
    button.setAttribute('aria-pressed', 'true');
    button.setAttribute('aria-label', 'Hide artifact map');
    showViewKind();
  }

  function close(returnFocus) {
    if (!open) return;
    open = false;
    generation += 1;
    releaseMap();
    status = 'idle';
    openIdentity = null;
    root.hidden = true;
    codeWrap.hidden = false;
    if (viewKind.textContent === ENTROPY_MAP_VIEW_KIND && codeViewKind !== null) viewKind.textContent = codeViewKind;
    codeViewKind = null;
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', 'Show artifact map');
    if (returnFocus) button.focus?.();
  }

  function show() {
    const source = getSource();
    if (!source || source.source_type !== 'artifact') return false;
    open = true;
    openIdentity = identityOf(source);
    focusWhenReady = true;
    showView();
    load();
    return true;
  }

  // Runs after each Sources render. A different artifact, a closed tab or a new
  // session retires this map rather than repainting it.
  function sync() {
    const source = getSource();
    const eligible = source?.source_type === 'artifact';
    button.hidden = !source;
    button.disabled = !eligible;
    button.title = eligible ? 'Map the whole artifact by entropy and kind' : 'Open one captured artifact to map it.';
    button.setAttribute('aria-pressed', String(open));
    if (open && (!eligible || identityOf(source) !== openIdentity)) close(false);
    if (open) showViewKind();
  }

  button.addEventListener('click', () => { if (open) close(true); else show(); });
  // Another view of the artifact replaces the map rather than sitting under it.
  toolbar.addEventListener('click', event => {
    const control = event.target.closest?.('.source-tool');
    if (open && control && control !== button && !control.closest('.source-window') && control.id !== 'source-sidebar-toggle' && control.id !== 'source-quick-open') close(false);
  });

  return {sync, open: show, close: () => close(false), isOpen: () => open, setVisible: visible => { if (!visible) close(false); }};
}
