// The code view Payload, Response, Native Console and Analyst share with Sources; captured text only ever becomes text nodes.
const CODE_VIEW_ROW_UNITS = 4096;
const CODE_VIEW_BLOCK_ROWS = 200;
// A block, and what one frame mounts, is also bounded by characters: 200 rows of
// a one-line body are 800 Ki characters, which WebKit took over half a second
// to style and lay out in one task.
const CODE_VIEW_BLOCK_CHARACTERS = 64 * 1024;
const CODE_VIEW_ROW_HEIGHT = 18;
const CODE_VIEW_LAYOUT_CHARACTERS = 32 * 1024 * 1024;

function codeViewNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Splits syntax tokens at find marks ({column, length, match}); every piece is a text node.
function codeViewPaint(node, tokens, marks = [], current = -1) {
  let offset = 0, index = 0;
  for (const token of tokens) {
    const end = offset + token.text.length;
    for (let at = offset; at < end;) {
      while (index < marks.length && marks[index].column + marks[index].length <= at) index += 1;
      const mark = marks[index];
      const inside = Boolean(mark) && mark.column <= at;
      const stop = Math.min(end, mark ? (inside ? mark.column + mark.length : mark.column) : end);
      const piece = token.text.slice(at - offset, stop - offset);
      let leaf = token.type === 'plain' ? document.createTextNode(piece) : codeViewNode('span', `syntax-${token.type}`, piece);
      if (inside) {
        const wrapper = codeViewNode('mark', mark.match === current ? 'code-view-mark is-current' : 'code-view-mark');
        wrapper.append(leaf);
        leaf = wrapper;
      }
      node.append(leaf);
      at = stop;
    }
    offset = end;
  }
  return node;
}

// One lexer across a short text; past `limit` units or `tokens` colored tokens the rest stays plain.
function codeViewColor(node, text, syntax, {limit = 8192, tokens = 1024} = {}) {
  const tokenizer = createSourceTokenizer(syntax);
  tokenizer.coloredTokens = Math.max(0, SOURCE_HIGHLIGHT_TOKEN_LIMIT - tokens);
  let plain = '';
  const flush = () => {if (plain) node.append(document.createTextNode(plain)); plain = '';};
  text.slice(0, limit).split('\n').forEach((line, index) => {
    if (index) plain += '\n';
    if (!line) return;
    for (const token of sourceSyntaxTokens(line, tokenizer)) {
      if (token.type === 'plain') plain += token.text;
      else {flush(); node.append(codeViewNode('span', `syntax-${token.type}`, token.text));}
    }
  });
  plain += text.slice(limit);
  flush();
  return node;
}

function codeViewSyntax(language) {
  return {javascript: {kind: 'javascript'}, json: {kind: 'json', mime_type: 'application/json'}}[language] ?? {kind: 'plain', mime_type: 'text/plain'};
}

// Layouts of retained bodies; `request` and `layouts` replace the backend read and the layout worker.
function createCodeLayouts({onChange = () => {}, request, layouts} = {}) {
  const entries = new Map();
  let client = null;
  const formats = () => client ??= createSourceFormatClient({request, layouts, onChange: () => onChange()});
  const bound = keep => {
    let characters = [...entries.values()].reduce((sum, entry) => sum + (entry.text?.length ?? 0), 0);
    for (const [name, entry] of entries) {
      if (entries.size <= 8 && characters <= CODE_VIEW_LAYOUT_CHARACTERS) break;
      if (name === keep || entry.status === 'pending') continue;
      characters -= entry.text?.length ?? 0;
      entries.delete(name);
    }
  };
  return {
    layout(artifact, text, syntax, language = null) {
      const source = artifact && {source_type: 'artifact', kind: artifact.kind, mime_type: artifact.mime_type, url: artifact.url,
        session_id: artifact.session_id, artifact_id: artifact.artifact_id, sha256: artifact.sha256, byte_size: artifact.byte_size,
        content: text, language};
      const backend = source ? formats().view(source, text) : null;
      if (backend?.pending) return {status: 'pending', engine: 'oxc'};
      if (backend && !backend.fallback) return {status: 'ready', text: backend.text, map: backend.map, input: text, engine: 'oxc', notice: null};
      const notice = backend?.notice ?? null;
      const name = JSON.stringify([artifact?.session_id, artifact?.artifact_id, artifact?.sha256, syntax.kind, syntax.mime_type, notice]);
      let entry = entries.get(name);
      if (entry?.input !== text) {
        entry = {status: 'pending', input: text, engine: 'in-page', notice};
        entries.set(name, entry);
        formats().layout(syntax, text).then(result => {
          if (entries.get(name) !== entry) return;
          if (typeof result?.text === 'string' && result.map) Object.assign(entry, {status: 'ready', text: result.text, map: result.map});
          else Object.assign(entry, {status: 'error', error: String(result?.error ?? 'Pretty print failed').replace(/\.$/, '')});
          bound(name);
          onChange();
        });
      }
      return entry;
    }
  };
}

function codeLayoutNote(layout) {
  if (!layout || layout.status === 'pending') return layout ? 'Formatting…' : null;
  if (layout.status === 'error') return `${layout.error}; shown as sent.`;
  return layout.engine === 'oxc' ? null : layout.notice ? `Whitespace layout: ${layout.notice.replace(/\.$/, '')}.` : null;
}

// Lines without a final CR; a line over 4 Ki units continues on further rows.
function codeViewRows(text) {
  const rows = [];
  for (let start = 0, line = 0; start <= text.length; line += 1) {
    const newline = text.indexOf('\n', start), end = newline < 0 ? text.length : newline;
    const length = end - start, shown = text.charCodeAt(end - 1) === 13 ? length - 1 : length;
    let at = 0;
    do {
      let stop = Math.min(shown, at + CODE_VIEW_ROW_UNITS);
      const code = text.charCodeAt(start + stop - 1);
      if (stop < shown && code >= 0xd800 && code <= 0xdbff) stop -= 1;
      rows.push({line, offset: start, columnStart: at, columnEnd: stop, fullLength: length, text: text.slice(start + at, start + stop)});
      at = stop;
    } while (at < shown);
    if (newline < 0) break;
    start = newline + 1;
  }
  return rows;
}

// A lazily mounted code block; with `layout` ({map, input}) a clicked token reports its raw range.
function createCodeView({text, rows = codeViewRows(text), syntax, label, className = '', rowClass = '', wrap = false, marks = new Map(),
  current = -1, layout = null, onRaw = null}) {
  const index = sourceDocumentIndex(text);
  const highlighter = createSourceHighlighter(syntax, index);
  const box = codeViewNode('div', `code-view ${className}${wrap ? ' is-wrapped' : ''}`);
  box.setAttribute('role', 'region');
  box.setAttribute('aria-label', label);
  box.tabIndex = 0;
  const blocks = [], mounted = [], plain = new Set();
  // Each block's first row and character count; a block ends at 200 rows or 64 Ki characters.
  const starts = [], sizes = [];
  for (let row = 0, count = 0; row < rows.length; row += 1, count += 1) {
    const length = rows[row].text.length;
    if (!count || count === CODE_VIEW_BLOCK_ROWS || sizes.at(-1) + length > CODE_VIEW_BLOCK_CHARACTERS) {
      starts.push(row);
      sizes.push(0);
      count = 0;
    }
    sizes[sizes.length - 1] += length;
  }
  const excerptsOf = block => rows.slice(starts[block], starts[block + 1] ?? rows.length);
  const blockOf = row => {
    let low = 0, high = starts.length - 1;
    while (low < high) {const middle = (low + high + 1) >> 1; if (starts[middle] <= row) low = middle; else high = middle - 1;}
    return low;
  };
  let pumping = false, disposed = false;
  const paint = (block, node) => {
    const from = starts[block], excerpts = excerptsOf(block);
    if (!highlighter.ready(excerpts)) highlighter.advance(SOURCE_COLOR_SYNC_UNITS);
    const colors = highlighter.rows(excerpts);
    if (!colors) plain.add(block); else plain.delete(block);
    node.replaceChildren(...excerpts.map((row, offset) => {
      const tokens = colors?.rows[offset];
      const exact = tokens && tokens.map(token => token.text).join('') === row.text;
      const element = codeViewNode('div', `code-view-row${rowClass ? ` ${rowClass}` : ''}${row.columnStart ? ' is-continued' : ''}`);
      element.dataset.row = String(from + offset);
      codeViewPaint(element, exact ? tokens : [{type: 'plain', text: row.text || ' '}], marks.get(from + offset) ?? [], current);
      return mounted[from + offset] = element;
    }));
    if (plain.size && !pumping) pump();
  };
  // Lexer checkpoints extend between tasks; blocks shown plain recolor once they
  // are reached, at most 64 Ki characters of them a task.
  const pump = () => {
    pumping = true;
    setTimeout(() => {
      if (disposed) return;
      highlighter.advance(SOURCE_COLOR_SLICE_UNITS);
      let budget = CODE_VIEW_BLOCK_CHARACTERS;
      for (const block of [...plain]) {
        if (budget <= 0) break;
        if (!highlighter.ready(excerptsOf(block))) continue;
        budget -= sizes[block];
        paint(block, blocks[block]);
      }
      if (plain.size && (budget <= 0 || !highlighter.done())) pump(); else pumping = false;
    }, 0);
  };
  const fill = block => {
    const node = blocks[block];
    if (!node || node.dataset.filled) return false;
    node.dataset.filled = 'true';
    observer?.unobserve(node);
    node.style.removeProperty('height');
    paint(block, node);
    return true;
  };
  // Blocks that come near the view mount in order, at most 64 Ki characters a
  // frame, so a view of long unwrapped rows never lays out several blocks at once.
  const near = new Set();
  let framed = false;
  const mountNear = () => {
    framed = false;
    if (disposed) return;
    let budget = CODE_VIEW_BLOCK_CHARACTERS;
    for (const block of [...near].sort((a, b) => a - b)) {
      if (budget <= 0) break;
      near.delete(block);
      if (fill(block)) budget -= sizes[block];
    }
    if (near.size) nextFrame();
  };
  const nextFrame = () => {
    if (framed) return;
    framed = true;
    (typeof requestAnimationFrame === 'function' ? requestAnimationFrame : setTimeout)(mountNear);
  };
  const observer = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      const block = Number(entry.target.dataset.block);
      if (entry.isIntersecting) near.add(block); else near.delete(block);
    }
    if (near.size) nextFrame();
  }, {root: box, rootMargin: '600px 0px'}) : null;
  starts.forEach((from, block) => {
    const node = codeViewNode('div', 'code-view-block');
    node.dataset.block = String(block);
    node.style.height = `${((starts[block + 1] ?? rows.length) - from) * CODE_VIEW_ROW_HEIGHT}px`;
    box.append(node);
    blocks.push(node);
    observer?.observe(node);
  });
  fill(0);
  let rawIndex = null;
  box.addEventListener('click', event => {
    const token = event.target?.closest?.('[data-row] span, [data-row] mark');
    const element = token?.closest('[data-row]');
    if (!layout?.map || !onRaw || !token || !element) return;
    const row = rows[Number(element.dataset.row)];
    let column = row.columnStart;
    for (let node = token; node && node !== element; node = node.parentNode) {
      for (let sibling = node.previousSibling; sibling; sibling = sibling.previousSibling) column += sibling.textContent.length;
    }
    const start = row.offset + column, range = sourceWhitespaceRange(layout.map, layout.input, text, start, start + token.textContent.length);
    if (!range) return;
    codeViewSelectToken(token);
    rawIndex ??= sourceDocumentIndex(layout.input);
    onRaw({...range, line: row.line, column, from: sourceDocumentPosition(rawIndex, range.start), to: sourceDocumentPosition(rawIndex, range.end)});
  });
  return {
    box,
    reveal(row) {
      fill(blockOf(row));
      return mounted[row] ?? null;
    },
    dispose() {
      disposed = true;
      observer?.disconnect();
    }
  };
}

// Selects a clicked token on the page. Its characters are the raw range's, so copying it copies the evidence.
function codeViewSelectToken(node) {
  const selection = globalThis.getSelection?.();
  if (!selection) return;
  // A drag inside this token keeps the researcher's own selection.
  if (!selection.isCollapsed && selection.containsNode(node, true) && selection.toString() !== node.textContent) return;
  selection.selectAllChildren(node);
}

function codeViewRawText(raw) {
  return `Line ${raw.line + 1}, Column ${raw.column + 1} · raw ${raw.from.line + 1}:${raw.from.column + 1}–${raw.to.line + 1}:${raw.to.column + 1} (offsets ${raw.start}–${raw.end})`;
}

// Colors a textarea through a mirror behind it; the textarea keeps editing, and its owner calls refresh.
function mountCodeEditor(textarea, mirror, syntaxOf) {
  const sync = () => {mirror.scrollTop = textarea.scrollTop; mirror.scrollLeft = textarea.scrollLeft;};
  const refresh = () => {
    mirror.replaceChildren();
    codeViewColor(mirror, textarea.value, syntaxOf(), {limit: 65536, tokens: 16384});
    // The mirror keeps the geometry of a final empty line.
    mirror.append(document.createTextNode('\n'));
    sync();
  };
  textarea.addEventListener('scroll', sync);
  return {refresh};
}
