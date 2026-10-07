// Shared pane geometry is a local UI preference, independent of captured evidence.
function initializePaneLayout() {
  const storageKey = 'origin-trace.layout.v1';
  const configurations = [
    { id: 'native-console', parent: '#workspace', panes: ['.main', '#native-console-panel'], axis: 'y', minimum: [180, 190], label: 'workspace and console' },
    { id: 'traffic', parent: '.traffic-grid', panes: ['.request-pane', '.detail-pane'], axis: 'y', minimum: [220, 220], label: 'Traffic list and inspector' },
    { id: 'traffic-columns', parent: '.traffic-grid', panes: ['.request-pane', '.detail-pane'], axis: 'x', minimum: [380, 360], label: 'Traffic list and inspector' },
    { id: 'repeater', parent: '.repeater-split', panes: ['.repeater-request-pane', '.repeater-response-pane'], axis: 'x', minimum: [320, 260], label: 'Repeater request and response' },
    { id: 'sources', parent: '#screen-sources', panes: ['.sources-navigator', '.sources-editor'], axis: 'x', minimum: [140, 320], label: 'Source navigator and editor' },
    { id: 'memory', parent: '.memory-grid', panes: ['.memory-search-pane', '.memory-results-pane'], axis: 'x', minimum: [220, 460], label: 'Memory criteria and results' },
    { id: 'memory-detail', parent: '.memory-results-pane', panes: ['.memory-results-list', '.memory-detail'], axis: 'x', minimum: [210, 220], label: 'Memory matches and details' },
    { id: 'decoder', parent: '.decoder-grid', panes: ['.decoder-column:first-child', '.decoder-column:last-child'], axis: 'x', minimum: [340, 300], label: 'Decoder pipeline and output' }
  ];
  let saved = {};
  try {
    const value = JSON.parse(localStorage.getItem(storageKey));
    if (isPlainObject(value)) {
      for (const configuration of configurations) {
        const ratio = value[configuration.id];
        if (typeof ratio === 'number' && Number.isFinite(ratio) && ratio > 0 && ratio < 1) saved[configuration.id] = ratio;
      }
    }
  } catch { /* Preferences are optional, including in private native sessions. */ }
  const persist = () => {
    try { localStorage.setItem(storageKey, JSON.stringify(saved)); } catch { /* Keep the current layout. */ }
  };
  let scheduled = false, dragging = null;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    let frame, timeout;
    const refresh = () => {
      cancelAnimationFrame(frame);
      clearTimeout(timeout);
      scheduled = false;
      layouts.forEach(layout => layout.refresh());
    };
    frame = requestAnimationFrame(refresh);
    // WebKit can suspend animation frames for an inactive native window while
    // continuing input and DOM updates. Hidden-screen dividers must still retire.
    timeout = setTimeout(refresh, 50);
  };
  const layouts = configurations.map(configuration => {
    const parent = document.querySelector(configuration.parent);
    const handle = document.createElement('div');
    handle.id = `pane-divider-${configuration.id}`;
    handle.className = 'pane-divider'; handle.dataset.axis = configuration.axis;
    handle.setAttribute('role', 'separator'); handle.tabIndex = 0;
    handle.setAttribute('aria-label', `Resize ${configuration.label}`);
    handle.setAttribute('aria-orientation', configuration.axis === 'x' ? 'vertical' : 'horizontal');
    handle.title = 'Drag to resize. Arrow keys: resize; Shift: larger step; Home or double-click: reset.';
    handle.hidden = true;
    // Overlay handles cannot become extra grid tracks or alter pane selectors.
    document.body.append(handle);
    const property = configuration.axis === 'x' ? 'grid-template-columns' : 'grid-template-rows';
    let geometry = null;
    const restore = () => parent.style.removeProperty(property);
    const measure = () => {
      const panes = configuration.panes.map(selector => parent.querySelector(selector));
      if (panes.some(pane => !pane || !pane.getClientRects().length)) return null;
      const style = getComputedStyle(parent);
      const tracks = style.getPropertyValue(property).trim().split(/\s+/);
      if (style.display !== 'grid' || tracks.length < 2 || tracks.length > 3 ||
          !tracks.every(track => /^\d+(?:\.\d+)?px$/.test(track))) return null;
      const [a, b] = panes.map(pane => pane.getBoundingClientRect());
      const horizontal = configuration.axis === 'x';
      if (horizontal ? Math.abs(a.right - b.left) > 2 || Math.abs(a.top - b.top) > 2
        : Math.abs(a.bottom - b.top) > 2 || Math.abs(a.left - b.left) > 2) return null;
      const total = horizontal ? a.width + b.width : a.height + b.height;
      const minimum = [...configuration.minimum];
      if (configuration.id === 'traffic') {
        if (total > parent.getBoundingClientRect().height + 2) return null;
        const controls = [...panes[0].children].filter(child => !child.matches('.request-table'))
          .reduce((height, child) => height + child.getBoundingClientRect().height, 0);
        const emptyHeight = panes[0].querySelector('.request-empty')?.getBoundingClientRect().height ?? 0;
        minimum[0] = Math.max(minimum[0], Math.ceil(controls + panes[0].querySelector('.request-head').getBoundingClientRect().height + Math.max(56, emptyHeight) + panes[0].querySelector('.request-window').getBoundingClientRect().height + 2));
        if (panes[1].querySelector('.exchange-html-preview')) minimum[1] = 320;
      }
      if (total < minimum[0] + minimum[1]) return null;
      // Clip to scrolling ancestors so a divider never floats over another screen.
      let clip = { left: 0, top: 0, right: innerWidth, bottom: innerHeight };
      for (let ancestor = parent; ancestor; ancestor = ancestor.parentElement) {
        const overflow = getComputedStyle(ancestor);
        const rect = ancestor.getBoundingClientRect();
        if (overflow.overflowX !== 'visible') { clip.left = Math.max(clip.left, rect.left); clip.right = Math.min(clip.right, rect.right); }
        if (overflow.overflowY !== 'visible') { clip.top = Math.max(clip.top, rect.top); clip.bottom = Math.min(clip.bottom, rect.bottom); }
      }
      const position = horizontal ? a.right : a.bottom;
      const start = horizontal ? Math.max(a.top, b.top, clip.top) : Math.max(a.left, b.left, clip.left);
      const end = horizontal ? Math.min(a.bottom, b.bottom, clip.bottom) : Math.min(a.right, b.right, clip.right);
      if (end - start < 24 || position < (horizontal ? clip.left : clip.top) || position > (horizontal ? clip.right : clip.bottom)) return null;
      return { panes, tracks, total, minimum, size: horizontal ? a.width : a.height, position, start, end };
    };
    const apply = ratio => {
      if (!geometry) return;
      const size = Math.max(geometry.minimum[0], Math.min(geometry.total - geometry.minimum[1], geometry.total * ratio));
      const tracks = [`${size}px`, 'minmax(0, 1fr)', ...geometry.tracks.slice(2)];
      parent.style.setProperty(property, tracks.join(' '));
    };
    const refresh = () => {
      // Remove our tracks before testing the responsive layout's geometry.
      restore(); geometry = measure();
      if (geometry && (saved[configuration.id] !== undefined ||
          geometry.size < geometry.minimum[0] || geometry.size > geometry.total - geometry.minimum[1])) {
        apply(saved[configuration.id] ?? geometry.size / geometry.total); geometry = measure();
      }
      if (configuration.id === 'sources') {
        const toolbar = parent.querySelector('.source-editor-toolbar');
        if (toolbar.getClientRects().length) {
          parent.style.setProperty('--source-toolbar-bottom', `${Math.max(0,
            toolbar.getBoundingClientRect().bottom - parent.getBoundingClientRect().top)}px`);
        }
      }
      handle.hidden = !geometry;
      if (!geometry) {
        if (dragging?.layout === layout) finish(false);
        return;
      }
      geometry.panes.forEach((pane, index) => { if (!pane.id) pane.id = `pane-${configuration.id}-${index}`; });
      handle.setAttribute('aria-controls', geometry.panes[0].id);
      handle.setAttribute('aria-valuemin', String(geometry.minimum[0]));
      handle.setAttribute('aria-valuemax', String(Math.floor(geometry.total - geometry.minimum[1])));
      handle.setAttribute('aria-valuenow', String(Math.round(geometry.size)));
      handle.setAttribute('aria-valuetext', `${Math.round(geometry.size)} pixels`);
      const horizontal = configuration.axis === 'x';
      Object.assign(handle.style, {
        left: `${horizontal ? geometry.position - 4 : geometry.start}px`,
        top: `${horizontal ? geometry.start : geometry.position - 4}px`,
        width: `${horizontal ? 8 : geometry.end - geometry.start}px`,
        height: `${horizontal ? geometry.end - geometry.start : 8}px`
      });
    };
    const setSize = size => {
      if (!geometry) return;
      saved[configuration.id] = Math.max(geometry.minimum[0], Math.min(geometry.total - geometry.minimum[1], size)) / geometry.total;
      refresh();
    };
    const reset = () => { delete saved[configuration.id]; persist(); refresh(); };
    const finish = commit => {
      if (dragging?.layout !== layout) return;
      const previous = dragging.previous;
      const pointerId = dragging.pointerId;
      dragging = null;
      if (handle.hasPointerCapture(pointerId)) handle.releasePointerCapture(pointerId);
      document.body.classList.remove('resizing-panes-x', 'resizing-panes-y');
      if (commit) persist();
      else {
        if (previous === undefined) delete saved[configuration.id];
        else saved[configuration.id] = previous;
        refresh();
      }
    };
    const layout = { refresh, finish };
    handle.addEventListener('pointerdown', event => {
      if (!geometry || event.button !== 0 || dragging) return;
      event.preventDefault(); handle.focus(); handle.setPointerCapture(event.pointerId);
      dragging = { layout, pointerId: event.pointerId, previous: saved[configuration.id],
        start: configuration.axis === 'x' ? event.clientX : event.clientY, size: geometry.size };
      document.body.classList.add(`resizing-panes-${configuration.axis}`);
    });
    handle.addEventListener('pointermove', event => {
      if (dragging?.layout !== layout || dragging.pointerId !== event.pointerId) return;
      setSize(dragging.size + (configuration.axis === 'x' ? event.clientX : event.clientY) - dragging.start);
    });
    handle.addEventListener('pointerup', event => { if (dragging?.pointerId === event.pointerId) finish(true); });
    handle.addEventListener('pointercancel', () => finish(false));
    handle.addEventListener('lostpointercapture', () => finish(false));
    handle.addEventListener('dblclick', reset);
    handle.addEventListener('keydown', event => {
      if (event.key === 'Escape' && dragging?.layout === layout) { event.preventDefault(); event.stopPropagation(); finish(false); return; }
      if (event.key === 'Home') { event.preventDefault(); reset(); return; }
      const arrows = configuration.axis === 'x' ? ['ArrowLeft', 'ArrowRight'] : ['ArrowUp', 'ArrowDown'];
      const direction = arrows.indexOf(event.key);
      if (direction === -1 || !geometry) return;
      event.preventDefault(); setSize(geometry.size + (direction ? 1 : -1) * (event.shiftKey ? 50 : 10)); persist();
    });
    const sizeObserver = new ResizeObserver(schedule);
    sizeObserver.observe(parent);
    if (configuration.id === 'sources') sizeObserver.observe(parent.querySelector('.source-editor-toolbar'));
    return layout;
  });
  const observer = new MutationObserver(schedule);
  observer.observe(document.querySelector('main'), { subtree: true, attributes: true,
    attributeFilter: ['hidden', 'data-empty', 'data-sidebar-open', 'data-hooks-open'] });
  observer.observe(document.querySelector('#exchange-inspector'), { childList: true });
  observer.observe(document.querySelector('#native-console-panel'), { attributes: true, attributeFilter: ['hidden'] });
  window.addEventListener('resize', schedule);
  document.addEventListener('scroll', schedule, true);
  window.addEventListener('blur', () => dragging?.layout.finish(false));
  schedule();
}
