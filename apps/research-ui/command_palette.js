/* Command palette (Cmd/Ctrl + K): reach any workspace, action or retained
 * evidence by name. It only calls each owner's existing navigation; it never
 * fetches, captures or runs page code, and every result is inserted as text.
 * The registry loads before every other module so any of them can add a
 * result group at load time, before or after app.js mounts the dialog. */
(function () {
  'use strict';
  // Each group lists at most 50 results and states how many more matched.
  // Providers are synchronous; scanning stops after 10,000 candidates so one
  // large catalog cannot stall typing, and the group says so.
  const GROUP_LIMIT = 50, CANDIDATE_LIMIT = 10000, QUERY_LIMIT = 256, TEXT_LIMIT = 1024;
  const external = new Map();
  let builtin = [];
  let view = null;

  const label = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
  function admit(provider, empty = false) {
    if (!provider || typeof provider !== 'object' || !label(provider.id, 64) || !label(provider.group, 64) || typeof provider.search !== 'function') {
      throw new TypeError('A palette provider needs {id, group, search(query)}: a non-empty id and group of at most 64 characters and a function.');
    }
    return Object.freeze({id: provider.id, group: provider.group, search: provider.search, empty});
  }

  // Registering an existing id replaces that provider in place. The returned
  // function removes exactly this registration.
  function addProvider(provider) {
    const entry = admit(provider);
    external.set(entry.id, entry);
    return () => { if (external.get(entry.id) === entry) external.delete(entry.id); };
  }

  // Lower ranks sort first: a title prefix, a later word in the title, any
  // title substring, a detail prefix or word, then any detail substring.
  function textRank(text, needle) {
    const lower = text.toLowerCase();
    let index = lower.indexOf(needle);
    if (index < 0) return -1;
    if (index === 0) return 0;
    for (; index >= 0; index = lower.indexOf(needle, index + 1)) {
      if (!/[\p{L}\p{N}_$]/u.test(lower[index - 1])) return 1;
    }
    return 2;
  }
  function matchRank(needle, title, detail) {
    const inTitle = textRank(title, needle);
    if (inTitle >= 0) return inTitle;
    const inDetail = detail ? textRank(detail, needle) : -1;
    return inDetail < 0 ? -1 : inDetail === 2 ? 4 : 3;
  }

  // Pure result model: groups in provider order, each ranked and capped. An
  // empty query lists only the built-in groups marked for it (workspaces and
  // actions); providers are not asked. A provider that throws or returns
  // something other than a list becomes a note in its own group.
  function results(rawQuery) {
    const query = String(rawQuery ?? '').slice(0, QUERY_LIMIT).trim();
    const needle = query.toLowerCase();
    const groups = [];
    for (const provider of [...builtin, ...external.values()]) {
      if (!needle && !provider.empty) continue;
      const group = {id: provider.id, label: provider.group, items: [], more: 0, notes: []};
      try {
        const candidates = provider.search(query);
        if (!Array.isArray(candidates)) throw new TypeError('The provider did not return a list.');
        const scanned = Math.min(candidates.length, CANDIDATE_LIMIT), ranked = [];
        let malformed = 0;
        for (let index = 0; index < scanned; index++) {
          const item = candidates[index];
          if (!item || typeof item !== 'object' || typeof item.title !== 'string' || !item.title.trim() || typeof item.run !== 'function' ||
              (item.detail !== undefined && item.detail !== null && typeof item.detail !== 'string')) {malformed++; continue;}
          const title = item.title.slice(0, TEXT_LIMIT), detail = (item.detail ?? '').slice(0, TEXT_LIMIT);
          const rank = needle ? matchRank(needle, title, detail) : 0;
          if (rank >= 0) ranked.push({rank, index, title, detail, run: item.run});
        }
        ranked.sort((a, b) => a.rank - b.rank || a.index - b.index);
        group.items = ranked.slice(0, GROUP_LIMIT).map(({title, detail, run}) => ({title, detail, run}));
        group.more = ranked.length - group.items.length;
        if (candidates.length > scanned) group.notes.push(`Only the first ${CANDIDATE_LIMIT.toLocaleString('en-US')} of ${candidates.length.toLocaleString('en-US')} candidates were matched; refine the query.`);
        if (malformed) group.notes.push(`${malformed} malformed ${malformed === 1 ? 'result was' : 'results were'} ignored.`);
      } catch {
        group.items = []; group.more = 0;
        group.notes = ['This group is unavailable: its search failed. Other results are unaffected.'];
      }
      if (group.items.length || group.notes.length) groups.push(group);
    }
    return groups;
  }

  function mount({trigger = null, providers = []} = {}) {
    if (view) return view.api;
    const dialog = document.getElementById('command-palette');
    const input = document.getElementById('command-palette-input');
    const list = document.getElementById('command-palette-results');
    const status = document.getElementById('command-palette-status');
    if (!dialog || !input || !list || !status) return null;
    builtin = providers.map(provider => admit(provider, provider.empty === true));
    let rows = [], active = -1, opener = null;
    const element = (tag, className, text) => {
      const node = document.createElement(tag); node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    };
    function activate(index, scroll = true) {
      rows[active]?.option.setAttribute('aria-selected', 'false');
      active = rows.length ? (index + rows.length) % rows.length : -1;
      const row = rows[active];
      if (!row) {input.removeAttribute('aria-activedescendant'); return;}
      row.option.setAttribute('aria-selected', 'true');
      input.setAttribute('aria-activedescendant', row.option.id);
      if (scroll) row.option.scrollIntoView?.({block: 'nearest'});
    }
    function render() {
      const groups = results(input.value);
      rows = []; active = -1;
      const sections = groups.map((group, groupIndex) => {
        const section = element('div', 'command-palette-group');
        const heading = element('div', 'command-palette-heading', group.label);
        heading.id = `command-palette-group-${groupIndex}`;
        section.setAttribute('role', 'group'); section.setAttribute('aria-labelledby', heading.id);
        section.append(heading);
        for (const item of group.items) {
          const index = rows.length, option = element('div', 'command-palette-option');
          option.id = `command-palette-option-${index}`;
          option.setAttribute('role', 'option'); option.setAttribute('aria-selected', 'false');
          option.append(element('span', 'command-palette-title', item.title));
          if (item.detail) option.append(element('span', 'command-palette-detail', item.detail));
          option.addEventListener('click', () => execute(index));
          option.addEventListener('pointermove', () => { if (active !== index) activate(index, false); });
          section.append(option); rows.push({option, item});
        }
        const notes = [...(group.more ? [`${group.more} more, refine the query`] : []), ...group.notes];
        for (const note of notes) {
          const line = element('p', 'command-palette-note', note); line.setAttribute('role', 'none'); section.append(line);
        }
        return section;
      });
      const query = input.value.trim();
      if (!sections.length) sections.push(element('p', 'command-palette-empty', `Nothing matches “${query}”. Workspaces, actions, retained requests, files and VM findings were searched.`));
      list.replaceChildren(...sections);
      activate(0);
      const capped = groups.filter(group => group.more).map(group => `${group.label} shows ${group.items.length} of ${group.items.length + group.more}`);
      status.textContent = !query ? 'Type to search retained requests, files and findings.'
        : `${rows.length} ${rows.length === 1 ? 'result' : 'results'}${capped.length ? ` · ${capped.join(', ')}; refine the query` : ''}`;
    }
    function open(initialQuery) {
      if (!dialog.open) {
        // Another modal dialog owns the keyboard; never stack over it.
        if (document.querySelector('dialog:modal')) return false;
        opener = document.activeElement;
        input.value = typeof initialQuery === 'string' ? initialQuery.slice(0, QUERY_LIMIT) : '';
        dialog.showModal();
        trigger?.setAttribute('aria-expanded', 'true');
      } else if (typeof initialQuery === 'string') input.value = initialQuery.slice(0, QUERY_LIMIT);
      render();
      input.focus();
      input.select?.();
      return true;
    }
    function close() {
      if (!dialog.open) return;
      dialog.close();
      trigger?.setAttribute('aria-expanded', 'false');
      // Results hold run() closures over evidence identities; drop them.
      list.replaceChildren(); rows = []; active = -1;
      input.removeAttribute('aria-activedescendant');
      const target = opener; opener = null;
      if (target?.isConnected && typeof target.focus === 'function') target.focus({preventScroll: true});
    }
    // Close first so focus returns to where it was; the owner's navigation
    // then moves it (to a request row, a source, a finding) exactly as a
    // direct click would.
    function execute(index) {
      const row = rows[index];
      if (!row) return;
      close();
      try { row.item.run(); } catch (error) { console.error('Command palette result failed', error); }
    }
    input.addEventListener('input', render);
    dialog.addEventListener('keydown', event => {
      // Workspace, Console and sidebar shortcuts stay out while it is open.
      event.stopPropagation();
      if (event.key === 'Escape' && !event.isComposing) {event.preventDefault(); close(); return;}
      if (event.code === 'KeyK' && event.metaKey && !event.altKey && !event.shiftKey && !event.repeat) {event.preventDefault(); close(); return;}
      if (event.key === 'Tab') {event.preventDefault(); return;}
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      const move = {ArrowDown: active + 1, ArrowUp: active - 1, Home: 0, End: rows.length - 1}[event.key];
      if (move !== undefined) {event.preventDefault(); if (rows.length) activate(move); return;}
      if (event.key === 'Enter' && !event.isComposing) {event.preventDefault(); execute(active);}
    });
    dialog.addEventListener('cancel', event => {event.preventDefault(); close();});
    // A click inside the dialog but outside the panel (its backdrop) closes it.
    dialog.addEventListener('click', event => { if (event.target === dialog) close(); });
    // Keep the caret in the field while a result is clicked.
    list.addEventListener('mousedown', event => event.preventDefault());
    trigger?.addEventListener('click', () => open());
    document.addEventListener('keydown', event => {
      if (event.code !== 'KeyK' || !(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey || event.repeat) return;
      // Ctrl+K deletes to the end of the line in macOS text fields; leave it there.
      if (!event.metaKey && event.target?.closest?.('input, textarea, select, [contenteditable="true"]')) return;
      if (document.querySelector('dialog:modal')) return;
      event.preventDefault();
      open();
    });
    view = {api: Object.freeze({open, close, dialog})};
    return view.api;
  }

  globalThis.RebCommandPalette = Object.freeze({
    addProvider,
    open: initialQuery => view ? view.api.open(initialQuery) : false,
    close: () => view?.api.close(),
    results,
    mount
  });
}());
