/* Evidence chips: the building blocks every Origin Trace pane uses in place
 * of explanatory sentences. Each block shows the one fact a researcher acts
 * on and keeps the rest one click or one focus away, so nothing a reader
 * needs is lost:
 *
 *   chip / renderChips   a count or label, and a breakdown or fact panel it opens
 *   reasonChip           a raw reason token with its label and one-line meaning
 *   evidenceClassChip    observed, declared, inferred, correlated or unknown
 *   limitsDisclosure     a pane's caveats as one-sentence bullets
 *   emptyState           a title, one reason, an action and "Why is this empty?"
 *   formatEvidenceTime   session-relative time; the exact monotonic ns stays
 *                        in the tooltip and the copy
 *   formatCount          a count in the reader's locale grouping
 *
 * Captured values are always inserted as text. A chip whose meaning is in a
 * tooltip is a focusable button that names its tooltip with
 * aria-describedby, and a chip that opens a panel carries aria-expanded, so
 * the keyboard and a screen reader reach everything a pointer does. Panels
 * float (position: fixed) next to their chip but stay after it in the DOM,
 * so Tab moves from a chip into its panel. The README documents the API. */
(function () {
  'use strict';

  const NS_PER_US = 1000n, NS_PER_MS = 1000000n, NS_PER_S = 1000000000n;
  let sequence = 0;
  const nextId = prefix => `${prefix}-${++sequence}`;
  const node = (tag, className = '', text = null) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== null) element.textContent = String(text);
    return element;
  };
  const svgIcon = path => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 12 12');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('class', 'ev-icon');
    const shape = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    shape.setAttribute('d', path);
    svg.append(shape);
    return svg;
  };
  const CHEVRON = 'M3 4.5 6 7.5 9 4.5';

  // ---- Time ---------------------------------------------------------------

  // Canonical decimal, bigint or safe integer nanoseconds; anything else is
  // not a recorded time.
  function nanoseconds(value) {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === 'string' && /^-?(?:0|[1-9][0-9]{0,19})$/.test(value)) return BigInt(value);
    return null;
  }

  // The zero of session-relative time. `store` is the first record of the
  // store (the session summary's first_time_ns, over the whole store);
  // `records` is the earliest record the UI has read, used until the store
  // answers. Monotonic time is one clock per machine, so every process of a
  // session shares this origin.
  let timeOrigin = null;
  function setTimeOrigin(value, basis = 'store') {
    const ns = value === null || value === undefined ? null : nanoseconds(value);
    if (ns === null || ns < 0n) { timeOrigin = null; return null; }
    if (!['store', 'records'].includes(basis)) throw new TypeError('A time origin basis is store or records.');
    timeOrigin = Object.freeze({ns, basis});
    return timeOrigin;
  }
  const originLabel = basis => basis === 'records' ? 'the first record read' : 'the first stored record';

  // `whole.fraction` with the fraction padded to `places` digits, truncated
  // so a value never rounds up into the next unit.
  function decimal(ns, unit, places) {
    const whole = ns / unit;
    if (!places) return whole.toLocaleString('en-US');
    const scale = 10n ** BigInt(places);
    const fraction = (ns % unit) * scale / unit;
    return `${whole.toLocaleString('en-US')}.${fraction.toString().padStart(places, '0')}`;
  }

  // A span of time in three significant digits: 850 ns, 3.21 µs, 32.1 ms,
  // 321 ms, 4.56 s, 2 min 05 s, 1 h 02 min. For durations and offsets that
  // are read, not compared to the nanosecond; the exact value stays with
  // the record.
  function formatEvidenceDuration(value) {
    const ns = nanoseconds(value);
    if (ns === null) return 'not recorded';
    const sign = ns < 0n ? '-' : '';
    const span = ns < 0n ? -ns : ns;
    if (span < NS_PER_US) return `${sign}${span} ns`;
    const significant = (unit, name) => {
      const digits = (span / unit).toString().length;
      return `${sign}${decimal(span, unit, Math.max(0, 3 - digits))} ${name}`;
    };
    if (span < NS_PER_MS) return significant(NS_PER_US, 'µs');
    if (span < NS_PER_S) return significant(NS_PER_MS, 'ms');
    if (span < 60n * NS_PER_S) return significant(NS_PER_S, 's');
    const seconds = span / NS_PER_S;
    if (seconds < 3600n) return `${sign}${seconds / 60n} min ${String(seconds % 60n).padStart(2, '0')} s`;
    return `${sign}${(seconds / 3600n).toLocaleString('en-US')} h ${String(seconds / 60n % 60n).padStart(2, '0')} min`;
  }

  // +12.345 s, +2:05.345 or +1:02:05.345: a clock reading with millisecond
  // precision, the same width for neighbouring rows.
  function clock(ns) {
    const sign = ns < 0n ? '-' : '+';
    const span = ns < 0n ? -ns : ns;
    const millis = String(span % NS_PER_S / NS_PER_MS).padStart(3, '0');
    const seconds = span / NS_PER_S;
    if (seconds < 60n) return `${sign}${seconds}.${millis} s`;
    const minutes = seconds / 60n, ss = String(seconds % 60n).padStart(2, '0');
    if (minutes < 60n) return `${sign}${minutes}:${ss}.${millis}`;
    return `${sign}${minutes / 60n}:${String(minutes % 60n).padStart(2, '0')}:${ss}.${millis}`;
  }

  // One evidence time. `text` is what a row shows; `title` says what it is
  // relative to and gives the exact monotonic value; `exact` is the raw ns,
  // for copying. Options:
  //   relativeTo: {ns, label}  an offset from another record, such as
  //                            {ns: start, label: 'request start'}
  //   origin: ns               a session zero other than the registered one
  function formatEvidenceTime(value, options = {}) {
    const ns = nanoseconds(value);
    if (ns === null) return {text: 'time not recorded', title: 'This record has no monotonic time.', exact: null};
    const exact = ns.toString();
    const raw = `${exact} ns monotonic`;
    const relative = options.relativeTo ? nanoseconds(options.relativeTo.ns) : null;
    if (relative !== null) {
      const delta = ns - relative;
      const label = typeof options.relativeTo.label === 'string' && options.relativeTo.label ? options.relativeTo.label : 'the reference record';
      const direction = delta < 0n ? 'before' : 'after';
      return {text: `${delta < 0n ? '' : '+'}${formatEvidenceDuration(delta)}`,
        title: `${decimal(delta < 0n ? -delta : delta, NS_PER_S, 9)} s ${direction} ${label} · ${raw}`, exact};
    }
    const explicit = options.origin === undefined ? null : nanoseconds(options.origin);
    const origin = explicit !== null ? {ns: explicit, basis: 'store'} : timeOrigin;
    if (!origin) {
      // Before any record is read there is no session zero; the clock itself
      // is still a readable unit.
      return {text: `${decimal(ns, NS_PER_S, 3)} s`, title: `${raw}, since this Mac started; the session start is not known yet`, exact};
    }
    const delta = ns - origin.ns;
    return {text: clock(delta),
      title: `${decimal(delta < 0n ? -delta : delta, NS_PER_S, 9)} s ${delta < 0n ? 'before' : 'after'} ${originLabel(origin.basis)} · ${raw}`, exact};
  }

  // A <time> for a row or list cell: the relative text, the full title on
  // hover and the exact ns in data-monotonic-ns. Rows are themselves
  // focusable, so the exact value is read in the selected record's details.
  function timeElement(value, options = {}) {
    const time = formatEvidenceTime(value, options);
    const element = node('time', 'ev-time', time.text);
    element.title = time.title;
    if (time.exact !== null) element.dataset.monotonicNs = time.exact;
    return element;
  }

  // A focusable time for a details pane: its tooltip is the title, and a
  // click copies the exact monotonic ns.
  function timeButton(value, options = {}) {
    const time = formatEvidenceTime(value, options);
    const holder = node('span', 'ev-time-wrap');
    const element = node('button', 'ev-time ev-time-button', time.text);
    element.type = 'button';
    holder.append(element);
    if (time.exact === null) { element.disabled = true; return holder; }
    element.dataset.monotonicNs = time.exact;
    describe(element, `${time.title}. Click to copy ${time.exact}.`, holder);
    element.addEventListener('click', () => copyText(time.exact, element, `Copied ${time.exact} ns`));
    return holder;
  }

  // ---- Tooltip --------------------------------------------------------------

  // One floating tooltip serves every chip. Its text is a copy of the chip's
  // own description element, which aria-describedby names, so a screen
  // reader hears the description once and the floating copy stays
  // aria-hidden. It shows after a short hover or at once on keyboard focus,
  // stays while the pointer moves onto it, and Escape hides it.
  let tip = null, tipOwner = null, tipTimer = 0, tipHideTimer = 0;
  function tipElement() {
    if (tip?.isConnected) return tip;
    tip = node('div', 'ev-tip');
    tip.setAttribute('aria-hidden', 'true');
    tip.hidden = true;
    tip.addEventListener('pointerenter', () => clearTimeout(tipHideTimer));
    tip.addEventListener('pointerleave', () => scheduleHide());
    document.body.append(tip);
    return tip;
  }
  // Gives `trigger` a tooltip: a hidden description inside `holder` (the
  // wrapper the caller places), named by aria-describedby. Calling it again
  // replaces the text.
  const descriptions = new WeakMap();
  function describe(trigger, text, holder) {
    let description = descriptions.get(trigger);
    if (!description) {
      description = node('span', 'ev-description');
      description.id = nextId('ev-description');
      description.hidden = true;
      holder.append(description);
      trigger.setAttribute('aria-describedby', description.id);
      trigger.dataset.evTip = '';
      trigger.addEventListener('pointerenter', () => { clearTimeout(tipHideTimer); clearTimeout(tipTimer); tipTimer = setTimeout(() => showTip(trigger), 350); });
      trigger.addEventListener('pointerleave', () => { clearTimeout(tipTimer); scheduleHide(); });
      trigger.addEventListener('focus', () => { if (focusVisible(trigger)) showTip(trigger, true); });
      trigger.addEventListener('blur', () => hideTip(trigger));
      descriptions.set(trigger, description);
    }
    if (description.textContent !== text) description.textContent = text;
    if (tipOwner === trigger) showTip(trigger, tipFromFocus);
    return description;
  }
  const focusVisible = element => { try { return element.matches(':focus-visible'); } catch { return false; } };
  // A tip shown for keyboard focus also takes the next Escape; one shown on
  // hover lets Escape reach whatever else is open.
  let tipFromFocus = false;
  function showTip(element, fromFocus = false) {
    const description = descriptions.get(element);
    if (!description?.textContent || !element.isConnected) return;
    const box = tipElement();
    clearTimeout(tipHideTimer);
    tipOwner = element;
    tipFromFocus = fromFocus;
    box.textContent = description.textContent;
    box.hidden = false;
    place(box, element, 'above', 6);
  }
  function scheduleHide() {
    clearTimeout(tipHideTimer);
    tipHideTimer = setTimeout(() => hideTip(), 120);
  }
  function hideTip(owner = null) {
    if (owner && tipOwner !== owner) return;
    clearTimeout(tipTimer);
    tipOwner = null;
    tipFromFocus = false;
    if (tip) tip.hidden = true;
  }

  // Places a fixed box beside an anchor: on the preferred side when it fits,
  // otherwise the side with more room, clamped inside the window with an
  // 8 px margin and scrolling inside when taller than the room.
  function place(box, anchor, prefer = 'below', gap = 4) {
    const margin = 8;
    const rect = anchor.getBoundingClientRect();
    const width = window.innerWidth || document.documentElement.clientWidth || 0;
    const height = window.innerHeight || document.documentElement.clientHeight || 0;
    box.style.maxHeight = '';
    box.style.left = '0px';
    box.style.top = '0px';
    const own = box.getBoundingClientRect();
    const below = height - rect.bottom - gap - margin, above = rect.top - gap - margin;
    const side = prefer === 'above' ? (own.height <= above || above >= below ? 'above' : 'below')
      : (own.height <= below || below >= above ? 'below' : 'above');
    const room = Math.max(48, side === 'above' ? above : below);
    if (own.height > room) box.style.maxHeight = `${Math.floor(room)}px`;
    const boxHeight = Math.min(own.height, room);
    const top = side === 'above' ? rect.top - gap - boxHeight : rect.bottom + gap;
    const left = Math.min(Math.max(margin, rect.left), Math.max(margin, width - margin - own.width));
    box.style.left = `${Math.round(left)}px`;
    box.style.top = `${Math.round(Math.max(margin, top))}px`;
    box.dataset.side = side;
  }

  async function copyText(text, element, confirmation) {
    try {
      await navigator.clipboard.writeText(text);
      if (tipOwner === element || focusVisible(element)) {
        showTip(element, tipFromFocus || focusVisible(element));
        if (tip) tip.textContent = confirmation;
      }
    } catch {
      if (tip && tipOwner === element) tip.textContent = 'Copy is unavailable here; select the text instead.';
    }
  }

  // ---- Disclosures ----------------------------------------------------------

  // At most one floating panel is open. Escape inside it, or on its chip,
  // closes it and returns focus to the chip; Escape elsewhere, a press
  // outside or focus moving elsewhere closes it where focus is. An in-place
  // disclosure (an empty state's causes) only toggles.
  let openDisclosure = null;
  function setOpen(control, open, {focus = false} = {}) {
    const {button, panel} = control;
    if (open && control.floating && openDisclosure && openDisclosure !== control) setOpen(openDisclosure, false);
    button.setAttribute('aria-expanded', String(open));
    panel.hidden = !open;
    if (open) {
      if (control.floating) openDisclosure = control;
      control.render?.();
      if (control.floating) place(panel, button, control.prefer ?? 'below');
    } else if (openDisclosure === control) {
      openDisclosure = null;
    }
    if (focus) button.focus({preventScroll: true});
  }
  function reposition() {
    if (openDisclosure?.floating && openDisclosure.button.isConnected) place(openDisclosure.panel, openDisclosure.button, openDisclosure.prefer ?? 'below');
    else if (openDisclosure && !openDisclosure.button.isConnected) openDisclosure = null;
    if (tipOwner?.isConnected && tip && !tip.hidden) place(tip, tipOwner, 'above', 6);
  }
  let listening = false;
  function listen() {
    if (listening || typeof document === 'undefined') return;
    listening = true;
    document.addEventListener('pointerdown', event => {
      if (!openDisclosure) return;
      const {button, panel} = openDisclosure;
      if (!button.contains(event.target) && !panel.contains(event.target)) setOpen(openDisclosure, false);
    }, true);
    document.addEventListener('keydown', event => {
      if (event.key !== 'Escape') return;
      if (tip && !tip.hidden) {
        const fromFocus = tipFromFocus;
        hideTip();
        if (fromFocus) { event.stopPropagation(); event.preventDefault(); return; }
      }
      if (!openDisclosure) return;
      const {button, panel} = openDisclosure;
      event.stopPropagation(); event.preventDefault();
      setOpen(openDisclosure, false, {focus: button.contains(event.target) || panel.contains(event.target)});
    }, true);
    document.addEventListener('focusin', event => {
      if (!openDisclosure) return;
      const {button, panel} = openDisclosure;
      if (!button.contains(event.target) && !panel.contains(event.target)) setOpen(openDisclosure, false);
    });
    window.addEventListener('resize', reposition);
    document.addEventListener('scroll', reposition, true);
  }

  // A button that opens a panel placed right after it. `floating` panels
  // are fixed beside the button; others open in place.
  function disclosure(button, panel, {floating = true, prefer = 'below', render = null} = {}) {
    listen();
    panel.id ||= nextId('ev-panel');
    panel.hidden = true;
    button.setAttribute('aria-expanded', 'false');
    button.setAttribute('aria-controls', panel.id);
    const control = {button, panel, floating, prefer, render};
    button.addEventListener('click', () => setOpen(control, button.getAttribute('aria-expanded') !== 'true'));
    return control;
  }

  // ---- Reasons and evidence classes ------------------------------------------

  // The glossary: one entry per raw reason token. Owners define their tokens
  // (evidence_models.js defines the named capture gaps); an undefined token
  // still renders, as its words with no meaning line.
  const reasons = new Map();
  const TOKEN = /^[a-z][a-z0-9_-]{0,127}$/;
  const kinds = new Set(['loss', 'limit', 'policy', 'state']);
  function defineReasons(entries) {
    for (const [token, entry] of Object.entries(entries ?? {})) {
      if (!TOKEN.test(token) || typeof entry?.label !== 'string' || !entry.label || entry.label.length > 80 ||
          (entry.meaning !== undefined && typeof entry.meaning !== 'string') || (entry.kind !== undefined && !kinds.has(entry.kind))) {
        throw new TypeError(`Reason ${token} needs a token of lowercase letters, digits, _ or -, a label of at most 80 characters, and an optional meaning and kind (${[...kinds].join(', ')}).`);
      }
      reasons.set(token, Object.freeze({label: entry.label, meaning: entry.meaning ?? '', kind: entry.kind ?? null}));
    }
  }
  const WORDS = {wasm: 'Wasm', js: 'JS', vm: 'VM', csp: 'CSP', url: 'URL', dom: 'DOM', id: 'ID', sw: 'service worker', http: 'HTTP'};
  function reason(token) {
    const known = reasons.get(token);
    if (known) return known;
    const words = String(token).replace(/^native_/, '').split(/[_-]+/).filter(Boolean).map(word => WORDS[word] ?? word).join(' ');
    return {label: words ? words.charAt(0).toUpperCase() + words.slice(1) : String(token), meaning: '', kind: null};
  }

  // A raw reason as a chip: its label and the monospace token. The tooltip
  // is the glossary meaning; a click copies the token.
  function reasonChip(token, options = {}) {
    const info = reason(token);
    const label = options.label ?? info.label;
    const meaning = options.meaning ?? info.meaning;
    const holder = node('span', 'ev-reason-wrap');
    const element = node('button', 'ev-reason');
    element.type = 'button';
    element.dataset.reason = token;
    if (options.kind ?? info.kind) element.dataset.kind = options.kind ?? info.kind;
    element.append(node('span', 'ev-reason-label', label), node('code', 'ev-reason-token', token));
    holder.append(element);
    describe(element, `${meaning ? `${meaning} ` : ''}Click to copy ${token}.`, holder);
    element.addEventListener('click', () => copyText(token, element, `Copied ${token}`));
    return holder;
  }

  const EVIDENCE_CLASSES = {
    observed: 'Recorded by a native probe while the page ran.',
    declared: 'Read from retained source or bytes: what the code declares, not what ran.',
    inferred: 'Derived by an analyzer from recorded evidence; not itself observed.',
    correlated: 'Matched by shared session, navigation or frame identifiers; no recorded link.',
    unknown: 'Not established by the evidence in view.'
  };
  function evidenceClassChip(kind, options = {}) {
    if (!Object.hasOwn(EVIDENCE_CLASSES, kind)) throw new TypeError(`An evidence class is one of ${Object.keys(EVIDENCE_CLASSES).join(', ')}.`);
    const holder = node('span', 'ev-class-wrap');
    const element = node('button', 'ev-class', options.label ?? kind);
    element.type = 'button';
    element.dataset.class = kind;
    element.setAttribute('aria-label', `Evidence class: ${options.label ?? kind}`);
    holder.append(element);
    describe(element, options.meaning ?? EVIDENCE_CLASSES[kind], holder);
    return holder;
  }

  // ---- Counts ----------------------------------------------------------------

  // A count in the reader's locale grouping (75,511 in English), as the Flow
  // graph heading reads. Wire totals are decimal strings so that a uint64
  // stays exact; a number, a bigint or such a string is grouped, and
  // anything else is shown as given.
  const countFormat = new Intl.NumberFormat();
  function formatCount(value) {
    if (typeof value === 'string' && /^-?[0-9]+$/.test(value)) return countFormat.format(BigInt(value));
    if (typeof value === 'bigint' || Number.isFinite(value)) return countFormat.format(value);
    return String(value);
  }

  // ---- Chips with panels --------------------------------------------------

  const tones = new Set(['loss', 'limit', 'neutral', 'ok']);
  const countText = (count, atLeast) => `${atLeast ? '≥' : ''}${formatCount(count)}`;
  function nounFor(count, noun) {
    const [singular, plural] = Array.isArray(noun) ? noun : [noun, `${noun}s`];
    return count === 1 || count === 1n ? singular : plural;
  }
  // The text a chip shows: "3 gaps", "≥3 gaps", or its own text.
  function chipText(spec) {
    if (spec.text) return spec.text;
    return `${countText(spec.count, spec.atLeast)} ${nounFor(spec.count, spec.noun)}${spec.suffix ? ` ${spec.suffix}` : ''}`;
  }
  function validate(spec) {
    if (!spec || typeof spec.key !== 'string' || !spec.key) throw new TypeError('A chip needs a key.');
    if (!spec.text && !(typeof spec.count === 'bigint' || Number.isSafeInteger(spec.count))) throw new TypeError(`Chip ${spec.key} needs text or a count.`);
    if (spec.tone !== undefined && !tones.has(spec.tone)) throw new TypeError(`Chip ${spec.key} tone is one of ${[...tones].join(', ')}.`);
    if ([spec.breakdown, spec.facts, spec.run].filter(Boolean).length > 1) throw new TypeError(`Chip ${spec.key} opens a breakdown, lists facts or runs an action, not more than one.`);
  }

  // One breakdown: a head (title and scope), an optional one-sentence
  // detail and reason chips, one row per cause with its count, detail and
  // reasons, a note and actions. Facts panels list label and value pairs
  // instead. `current` returns the chip's latest spec: an update whose panel
  // reads the same keeps these nodes, so an action runs the newest callback.
  function renderPanel(panel, spec, current = () => spec) {
    const parts = [];
    const content = spec.breakdown ?? spec.facts;
    if (content.title || content.scope) {
      const head = node('div', 'ev-panel-head');
      if (content.title) head.append(node('strong', 'ev-panel-title', content.title));
      if (content.scope) head.append(node('span', 'ev-panel-scope', content.scope));
      parts.push(head);
    }
    const reasonList = entries => {
      const list = node('ul', 'ev-panel-reasons');
      for (const entry of entries) {
        const item = node('li', 'ev-panel-reason');
        item.append(reasonChip(entry.token, {label: entry.label, meaning: entry.meaning, kind: entry.kind}));
        if (entry.count !== undefined) item.append(node('span', 'ev-panel-count', `×${countText(entry.count, entry.atLeast)}`));
        list.append(item);
      }
      return list;
    };
    if (spec.breakdown) {
      if (spec.breakdown.detail) parts.push(node('p', 'ev-panel-lede', spec.breakdown.detail));
      if (spec.breakdown.reasons?.length) parts.push(reasonList(spec.breakdown.reasons));
      if (spec.breakdown.rows?.length) {
        const list = node('ul', 'ev-panel-rows');
        for (const row of spec.breakdown.rows) {
          const item = node('li', 'ev-panel-row');
          if (row.tone) item.dataset.tone = row.tone;
          const line = node('div', 'ev-panel-line');
          line.append(node('span', 'ev-panel-label', row.label));
          if (row.count !== undefined) line.append(node('span', 'ev-panel-count', countText(row.count, row.atLeast)));
          item.append(line);
          if (row.detail) item.append(node('p', 'ev-panel-detail', row.detail));
          if (row.reasons?.length) item.append(reasonList(row.reasons));
          list.append(item);
        }
        parts.push(list);
      }
    } else {
      const list = node('dl', 'ev-panel-facts');
      for (const [label, value] of spec.facts.rows ?? []) list.append(node('dt', '', label), node('dd', '', value));
      parts.push(list);
    }
    if (content.note) parts.push(node('p', 'ev-panel-note', content.note));
    if (content.actions?.length) {
      const actions = node('div', 'ev-panel-actions');
      content.actions.forEach((action, index) => {
        const button = node('button', 'secondary-button ev-panel-action', action.label);
        button.type = 'button';
        if (action.key) button.dataset.action = action.key;
        button.addEventListener('click', () => {
          if (openDisclosure?.panel === panel) setOpen(openDisclosure, false);
          const latest = current();
          (latest.breakdown ?? latest.facts)?.actions?.[index]?.run();
        });
        actions.append(button);
      });
      parts.push(actions);
    }
    panel.replaceChildren(...parts);
  }

  // Serializes what a panel shows, so an unchanged update keeps the panel's
  // nodes and the focus inside it.
  const panelKey = spec => JSON.stringify(spec.breakdown ?? spec.facts, (key, value) =>
    typeof value === 'bigint' ? value.toString() : typeof value === 'function' ? true : value);

  // A chip: a counted noun ("3 gaps") or its own text, in a tone. It opens a
  // breakdown, lists facts, runs an action (with an optional pressed state),
  // or only shows its tooltip. Returns a controller: element (the wrapper to
  // place), button, update(spec), and close().
  function chip(initial) {
    validate(initial);
    const element = node('span', 'ev-chip-wrap');
    const button = node('button', 'ev-chip');
    button.type = 'button';
    const dot = node('span', 'ev-chip-dot');
    dot.setAttribute('aria-hidden', 'true');
    const label = node('span', 'ev-chip-text');
    button.append(dot, label);
    element.append(button);
    let spec = null, panel = null, control = null, renderedKey = '';
    const controller = {element, button, update, close: () => control && setOpen(control, false), spec: () => spec};
    function update(next) {
      validate(next);
      if (spec && Boolean(spec.breakdown || spec.facts) !== Boolean(next.breakdown || next.facts)) throw new TypeError(`Chip ${next.key} cannot change between a panel and no panel; render a new key.`);
      spec = next;
      const text = chipText(spec);
      if (label.textContent !== text) label.textContent = text;
      button.dataset.tone = spec.tone ?? 'neutral';
      button.dataset.key = spec.key;
      if (spec.variant) button.dataset.variant = spec.variant;
      else delete button.dataset.variant;
      dot.hidden = !spec.dot;
      if (spec.name) button.setAttribute('aria-label', spec.name);
      else button.removeAttribute('aria-label');
      if (spec.run) {
        if (spec.pressed === undefined) button.removeAttribute('aria-pressed');
        else button.setAttribute('aria-pressed', String(Boolean(spec.pressed)));
      }
      if (spec.description) describe(button, spec.description, element);
      if ((spec.breakdown || spec.facts) && !panel) {
        // A chevron after the text says the chip opens a panel.
        const chevron = svgIcon(CHEVRON);
        chevron.classList.add('ev-chip-chevron');
        button.append(chevron);
        panel = node('div', 'ev-panel');
        panel.setAttribute('role', 'group');
        element.append(panel);
        control = disclosure(button, panel, {prefer: spec.prefer ?? 'below', render: renderOpen});
      }
      if (panel) {
        panel.setAttribute('aria-label', spec.panelName ?? (spec.breakdown ?? spec.facts).title ?? text);
        control.prefer = spec.prefer ?? 'below';
        if (!panel.hidden) renderOpen();
      }
    }
    function renderOpen() {
      const key = panelKey(spec);
      if (key === renderedKey) return;
      const focused = panel.contains(document.activeElement) ? [...panel.querySelectorAll('button')].indexOf(document.activeElement) : -1;
      renderedKey = key;
      renderPanel(panel, spec, () => spec);
      if (focused >= 0) (panel.querySelectorAll('button')[focused] ?? button).focus({preventScroll: true});
      if (control?.floating) place(panel, button, control.prefer);
    }
    button.addEventListener('click', () => { if (spec.run) spec.run(); });
    update(initial);
    return controller;
  }

  // Draws `specs` into `container` by key: a chip whose key stays is updated
  // in place, so an open panel and focus survive every refresh; new keys
  // are created and gone keys removed. Returns the controllers in order.
  const rendered = new WeakMap();
  function renderChips(container, specs) {
    const previous = rendered.get(container) ?? new Map();
    const next = new Map();
    const controllers = [];
    for (const spec of specs.filter(Boolean)) {
      if (next.has(spec.key)) throw new TypeError(`Two chips share the key ${spec.key}.`);
      let controller = previous.get(spec.key);
      const kind = Boolean(spec.breakdown || spec.facts);
      if (controller && Boolean(controller.spec().breakdown || controller.spec().facts) === kind) controller.update(spec);
      else controller = chip(spec);
      next.set(spec.key, controller);
      controllers.push(controller);
    }
    const focusLost = [...previous.entries()].some(([key, controller]) => !next.has(key) && controller.element.contains(document.activeElement));
    for (const [key, controller] of previous) if (!next.has(key) || next.get(key) !== controller) controller.close();
    const current = [...container.children];
    const wanted = controllers.map(controller => controller.element);
    if (current.length !== wanted.length || current.some((child, index) => child !== wanted[index])) container.replaceChildren(...wanted);
    rendered.set(container, next);
    if (focusLost) (wanted[0]?.querySelector('button') ?? container.closest('[tabindex]'))?.focus({preventScroll: true});
    return controllers;
  }

  // ---- Limits and empty states ---------------------------------------------

  // One "Limits" button per pane header. Its panel lists the pane's caveats,
  // one sentence each, and stays closed until asked for.
  function limitsDisclosure(items, options = {}) {
    const element = node('span', 'ev-limits');
    const button = node('button', 'ev-limits-button');
    button.type = 'button';
    button.append(node('span', '', options.label ?? 'Limits'), svgIcon('M6 1.5a4.5 4.5 0 1 1 0 9 4.5 4.5 0 0 1 0-9ZM6 5.5v3M6 3.6v.1'));
    button.setAttribute('aria-label', options.name ?? `${options.label ?? 'Limits'} of this pane`);
    const panel = node('div', 'ev-panel ev-limits-panel');
    panel.setAttribute('role', 'group');
    panel.setAttribute('aria-label', options.label ?? 'Limits');
    const list = node('ul', 'ev-limits-list');
    for (const item of items) list.append(node('li', '', item));
    panel.append(list);
    element.append(button, panel);
    disclosure(button, panel, {prefer: options.prefer ?? 'below'});
    return element;
  }

  // An empty pane: a one-line title, at most one one-line reason, an
  // optional primary action, and the other causes under "Why is this
  // empty?". A cause marked `applies` is listed first and marked as this
  // session's, so the reader never weighs causes that do not apply.
  function emptyState({title, reason: line = '', action = null, causes = [], label = 'Why is this empty?'}) {
    const element = node('div', 'ev-empty');
    element.append(node('p', 'ev-empty-title', title));
    if (line) element.append(node('p', 'ev-empty-reason', line));
    if (action) {
      const button = node('button', 'primary-button ev-empty-action', action.label);
      button.type = 'button';
      button.addEventListener('click', () => action.run());
      element.append(button);
    }
    if (causes.length) {
      const button = node('button', 'ev-empty-why');
      button.type = 'button';
      button.append(node('span', '', label), svgIcon(CHEVRON));
      const list = node('ul', 'ev-empty-causes');
      const ordered = [...causes].sort((left, right) => Number(Boolean(right.applies)) - Number(Boolean(left.applies)));
      for (const cause of ordered) {
        const item = node('li', '', cause.text);
        if (cause.applies) {
          item.dataset.applies = 'true';
          item.prepend(node('span', 'ev-empty-applies', 'This session'));
        }
        list.append(item);
      }
      element.append(button, list);
      disclosure(button, list, {floating: false});
    }
    return element;
  }

  // ---- Notices ---------------------------------------------------------------

  // A one-line notice made of chips: a lead ("Incomplete capture"), the
  // chips, optional actions and an optional dismiss. Plain-text notices
  // (loading, disconnected, malformed) keep their own text instead.
  const noticeParts = new WeakMap();
  function renderNotice(element, {lead = '', text = '', chips: specs = [], actions = [], dismiss = null}) {
    let body = element.querySelector(':scope > .ev-notice');
    if (!body) {
      body = node('div', 'ev-notice');
      element.replaceChildren(body);
    }
    const parts = noticeParts.get(body) ?? {};
    if (!parts.lead) {
      parts.lead = node('span', 'ev-notice-lead');
      parts.text = node('span', 'ev-notice-text');
      parts.chips = node('span', 'ev-notice-chips');
      parts.actions = node('span', 'ev-notice-actions');
      body.append(parts.lead, parts.text, parts.chips, parts.actions);
      noticeParts.set(body, parts);
    }
    parts.lead.textContent = lead;
    parts.lead.hidden = !lead;
    parts.text.textContent = text;
    parts.text.hidden = !text;
    renderChips(parts.chips, specs);
    parts.chips.hidden = !specs.filter(Boolean).length;
    const key = JSON.stringify([actions.map(action => [action.key, action.label]), Boolean(dismiss), dismiss?.name]);
    if (parts.actionsKey !== key) {
      parts.actionsKey = key;
      const buttons = actions.map(action => {
        const button = node('button', 'ev-notice-action', action.label);
        button.type = 'button';
        if (action.key) button.dataset.action = action.key;
        button.addEventListener('click', () => parts.handlers.get(action.key ?? action.label)?.());
        return button;
      });
      if (dismiss) {
        const button = node('button', 'ev-notice-dismiss');
        button.type = 'button';
        button.dataset.action = 'dismiss';
        button.setAttribute('aria-label', dismiss.name ?? 'Dismiss');
        button.append(svgIcon('M3 3l6 6M9 3 3 9'));
        button.addEventListener('click', () => parts.dismiss?.());
        buttons.push(button);
      }
      parts.actions.replaceChildren(...buttons);
    }
    parts.handlers = new Map(actions.map(action => [action.key ?? action.label, action.run]));
    parts.dismiss = dismiss?.run ?? null;
    parts.actions.hidden = !actions.length && !dismiss;
  }

  const api = Object.freeze({
    chip, renderChips, reasonChip, evidenceClassChip, limitsDisclosure, emptyState, renderNotice,
    defineReasons, reason, evidenceClasses: Object.freeze({...EVIDENCE_CLASSES}),
    formatEvidenceTime, formatEvidenceDuration, formatCount, timeElement, timeButton, setTimeOrigin,
    timeOrigin: () => timeOrigin,
    close: () => { if (openDisclosure) setOpen(openDisclosure, false); hideTip(); }
  });
  globalThis.RebEvidenceChips = api;
  if (typeof module === 'object' && module?.exports) module.exports = api;
})();
