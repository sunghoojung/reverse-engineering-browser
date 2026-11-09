/* Traffic table columns: widths, hidden columns and the header menu. The
 * layout is saved locally. Narrow tables drop low-priority columns first so
 * no column clips or collides; rows always carry every cell. */
const TRAFFIC_COLUMN_STORAGE = 'reb.traffic.columns.v1';
// Lower priority numbers stay longest when the table narrows.
const TRAFFIC_COLUMNS = Object.freeze([
  {id: 'name', label: 'Name', width: 0, min: 120, priority: 0},
  {id: 'status', label: 'Status', width: 84, min: 48, priority: 1},
  {id: 'type', label: 'Type', width: 52, min: 40, priority: 5},
  {id: 'method', label: 'Method', width: 58, min: 44, priority: 6},
  {id: 'protocol', label: 'Protocol', width: 64, min: 48, priority: 8, hidden: true},
  {id: 'initiator', label: 'Initiator', width: 96, min: 52, priority: 7},
  {id: 'size', label: 'Size', width: 132, min: 52, priority: 3},
  {id: 'time', label: 'Time', width: 88, min: 48, priority: 2},
  {id: 'waterfall', label: 'Waterfall', width: 132, min: 64, priority: 4}
]);

function trafficColumnLayout(saved) {
  const hidden = new Set(TRAFFIC_COLUMNS.filter(column => column.hidden).map(column => column.id));
  const widths = {};
  if (saved && typeof saved === 'object') {
    if (Array.isArray(saved.hidden)) {
      hidden.clear();
      for (const id of saved.hidden) if (id !== 'name' && TRAFFIC_COLUMNS.some(column => column.id === id)) hidden.add(id);
    }
    for (const column of TRAFFIC_COLUMNS) {
      const width = saved.widths?.[column.id];
      if (column.width && Number.isFinite(width)) widths[column.id] = Math.max(column.min, Math.min(480, Math.round(width)));
    }
  }
  return {hidden, widths};
}

// The columns that fit `available` pixels, dropping the highest priority numbers first.
function trafficFittedColumns(layout, available) {
  const shown = TRAFFIC_COLUMNS.filter(column => !layout.hidden.has(column.id));
  const width = column => column.width ? layout.widths[column.id] ?? column.width : column.min;
  let total = shown.reduce((sum, column) => sum + width(column), 0);
  const dropped = new Set();
  for (const column of [...shown].sort((a, b) => b.priority - a.priority)) {
    if (!(available > 0) || total <= available || column.id === 'name') break;
    dropped.add(column.id);
    total -= width(column);
  }
  const visible = shown.filter(column => !dropped.has(column.id));
  return {visible: visible.map(column => column.id), dropped: [...dropped],
    template: visible.map(column => column.width ? `${width(column)}px` : `minmax(${column.min}px, 1fr)`).join(' ')};
}

function mountTrafficColumns(table, {storage = globalThis.localStorage} = {}) {
  const head = table.querySelector('.request-head');
  const rows = table.querySelector('.request-rows');
  let layout = trafficColumnLayout(read());
  let menu = null;

  function read() {
    try { return JSON.parse(storage?.getItem(TRAFFIC_COLUMN_STORAGE) ?? 'null'); } catch { return null; }
  }
  function save() {
    try {
      storage?.setItem(TRAFFIC_COLUMN_STORAGE, JSON.stringify({version: 1, hidden: [...layout.hidden], widths: layout.widths}));
    } catch { /* Private or file: storage keeps the layout for this window only. */ }
  }
  // The rows' scrollbar gutter is the only width the header does not share.
  function fittedColumns() {
    return trafficFittedColumns(layout, (rows?.clientWidth || head.clientWidth || 0) - 2);
  }
  function apply() {
    const fitted = fittedColumns();
    const hidden = TRAFFIC_COLUMNS.map(column => column.id).filter(id => !fitted.visible.includes(id)).join(' ');
    if (table.dataset.hiddenColumns !== hidden) table.dataset.hiddenColumns = hidden;
    table.style.setProperty('--request-columns', fitted.template);
    for (const button of head.querySelectorAll('[data-column]')) {
      const narrowed = fitted.dropped.includes(button.dataset.column);
      button.title = `${button.dataset.columnLabel}. Click to sort; Shift+Left or Shift+Right resizes; the context menu or Shift+F10 shows or hides columns.${narrowed ? ' Some columns are hidden until the table is wider.' : ''}`;
    }
  }
  function resize(id, delta) {
    const column = TRAFFIC_COLUMNS.find(candidate => candidate.id === id);
    if (!column?.width) return;
    layout.widths[id] = Math.max(column.min, Math.min(480, (layout.widths[id] ?? column.width) + delta));
    apply();
  }

  // Removing the focused menu fires focusout, which must find it already closed.
  function closeMenu(focus = true) {
    const closing = menu;
    if (!closing) return;
    menu = null;
    closing.remove();
    if (focus) closing.opener?.focus({preventScroll: true});
  }
  function openMenu(opener, x, y) {
    closeMenu(false);
    menu = document.createElement('div');
    menu.className = 'column-menu';
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', 'Columns');
    menu.opener = opener;
    // A column the width dropped is on but not shown, so it never reads as simply checked.
    const sync = (item, column) => {
      const dropped = fittedColumns().dropped.includes(column.id);
      item.setAttribute('aria-checked', dropped ? 'mixed' : String(!layout.hidden.has(column.id)));
      item.textContent = dropped ? `${column.label} (no room)` : column.label;
      item.title = dropped ? `${column.label} is on, but this table is too narrow to show it.` : '';
    };
    const items = TRAFFIC_COLUMNS.map(column => {
      const item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('role', 'menuitemcheckbox');
      item.dataset.columnId = column.id;
      sync(item, column);
      item.disabled = column.id === 'name';
      item.addEventListener('click', () => {
        if (layout.hidden.has(column.id)) layout.hidden.delete(column.id); else layout.hidden.add(column.id);
        save();
        apply();
        for (const other of items) sync(other, TRAFFIC_COLUMNS.find(entry => entry.id === other.dataset.columnId));
      });
      return item;
    });
    const reset = document.createElement('button');
    reset.type = 'button';
    reset.setAttribute('role', 'menuitem');
    reset.textContent = 'Reset columns';
    reset.addEventListener('click', () => {
      layout = trafficColumnLayout(null);
      save();
      apply();
      closeMenu();
    });
    menu.append(...items, reset);
    menu.addEventListener('keydown', event => {
      const enabled = [...menu.querySelectorAll('button:not(:disabled)')];
      const at = enabled.indexOf(document.activeElement);
      if (event.key === 'Escape' || event.key === 'Tab') {
        event.preventDefault();
        event.stopPropagation();
        closeMenu();
      } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? enabled.length - 1
          : (at + (event.key === 'ArrowDown' ? 1 : -1) + enabled.length) % enabled.length;
        enabled[next].focus();
      }
    });
    menu.addEventListener('focusout', event => {
      if (menu && !menu.contains(event.relatedTarget)) closeMenu(false);
    });
    // Fixed to the viewport so a short table cannot clip it.
    document.body.append(menu);
    menu.style.left = `${Math.max(4, Math.min(x, innerWidth - menu.offsetWidth - 4))}px`;
    menu.style.top = `${Math.max(4, Math.min(y, innerHeight - menu.offsetHeight - 4))}px`;
    menu.querySelector('button:not(:disabled)')?.focus();
  }

  for (const button of head.querySelectorAll('[data-column]')) {
    button.dataset.columnLabel = button.firstChild?.textContent?.trim() || button.dataset.column;
    const handle = document.createElement('span');
    handle.className = 'column-resizer';
    handle.setAttribute('aria-hidden', 'true');
    if (button.dataset.column !== 'name') button.append(handle);
    let drag = null;
    handle.addEventListener('pointerdown', event => {
      event.preventDefault();
      handle.setPointerCapture?.(event.pointerId);
      drag = {x: event.clientX, width: button.getBoundingClientRect().width};
    });
    handle.addEventListener('pointermove', event => {
      if (!drag) return;
      const column = TRAFFIC_COLUMNS.find(candidate => candidate.id === button.dataset.column);
      layout.widths[column.id] = Math.max(column.min, Math.min(480, Math.round(drag.width + event.clientX - drag.x)));
      apply();
    });
    const end = () => { if (drag) { drag = null; save(); } };
    handle.addEventListener('pointerup', end);
    handle.addEventListener('pointercancel', end);
    // A drag on the handle is not a sort.
    handle.addEventListener('click', event => event.stopPropagation());
    button.addEventListener('keydown', event => {
      if (event.shiftKey && (event.key === 'ArrowLeft' || event.key === 'ArrowRight')) {
        event.preventDefault();
        resize(button.dataset.column, event.key === 'ArrowRight' ? 16 : -16);
        save();
      } else if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
        event.preventDefault();
        const box = button.getBoundingClientRect();
        openMenu(button, box.left, box.bottom);
      }
    });
  }
  head.addEventListener('contextmenu', event => {
    event.preventDefault();
    openMenu(event.target.closest?.('[data-column]') ?? head.querySelector('[data-column]'), event.clientX, event.clientY);
  });
  document.addEventListener('pointerdown', event => {
    if (menu && !menu.contains(event.target)) closeMenu(false);
  });
  if (typeof ResizeObserver === 'function') new ResizeObserver(apply).observe(table);
  apply();
}
