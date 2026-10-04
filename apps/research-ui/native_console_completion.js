// Local API hints only. Never inspect Origin Trace's window, evaluate an
// expression, or invoke a page getter to obtain completions.
const nativeConsoleCatalog = (() => {
  const groups = new Map();
  const group = (name, properties = '', methods = '') => {
    const entries = new Map();
    for (const [words, kind] of [[properties, 'property'], [methods, 'function']]) {
      for (const word of words.split(' ').filter(Boolean)) {
        const [label, type, returns] = word.split(':');
        entries.set(label, {name: label, kind, type: type || (kind === 'function' ? 'function' : ''), returns});
      }
    }
    groups.set(name, entries);
    return entries;
  };
  group('global', 'window:window self:window globalThis:window document:document navigator:navigator location:location history:history console:console localStorage:storage sessionStorage:storage performance:performance Math:math JSON:json Object:object Array:arrayConstructor String:stringConstructor Number:numberConstructor Promise:promiseConstructor Date:dateConstructor Map:mapConstructor Set:setConstructor URL:urlConstructor URLSearchParams:paramsConstructor Reflect:reflect undefined NaN Infinity',
    'fetch:function:promise setTimeout setInterval clearTimeout clearInterval requestAnimationFrame cancelAnimationFrame queueMicrotask structuredClone atob:function:string btoa:function:string parseInt parseFloat isNaN isFinite encodeURI encodeURIComponent decodeURI decodeURIComponent addEventListener removeEventListener dispatchEvent');
  for (const [name, type] of [['Boolean', 'function'], ['BigInt', 'function'], ['Symbol', 'function'], ['RegExp', 'function'], ['Error', 'function'], ['TypeError', 'function'], ['TextEncoder', 'function'], ['TextDecoder', 'function'], ['AbortController', 'function'], ['Headers', 'function'], ['Request', 'function'], ['Response', 'function'], ['Uint8Array', 'arrayConstructor'], ['ArrayBuffer', 'function'], ['WebSocket', 'function']]) {
    groups.get('global').set(name, {name, kind: 'function', type});
  }
  for (const name of ['Object', 'Array', 'String', 'Number', 'Promise', 'Date', 'Map', 'Set', 'URL', 'URLSearchParams']) groups.get('global').get(name).kind = 'function';
  group('window', 'innerWidth innerHeight outerWidth outerHeight scrollX scrollY screen devicePixelRatio frames length parent:window top:window opener:window closed name origin', 'getComputedStyle:function:style scroll scrollTo scrollBy matchMedia focus blur postMessage');
  for (const [name, entry] of groups.get('global')) groups.get('window').set(name, entry);
  group('document', 'body:element head:element documentElement:element activeElement:element scrollingElement:element title URL documentURI readyState referrer cookie domain visibilityState hidden forms:collection images:collection links:collection scripts:collection',
    'querySelector:function:element querySelectorAll:function:collection getElementById:function:element getElementsByClassName:function:collection getElementsByTagName:function:collection createElement:function:element createTextNode addEventListener removeEventListener dispatchEvent hasFocus');
  group('element', 'id className classList:classList style:style dataset textContent innerHTML outerHTML tagName localName attributes children:collection childNodes:collection parentElement:element parentNode:element firstElementChild:element lastElementChild:element nextElementSibling:element previousElementSibling:element value checked disabled clientWidth clientHeight scrollWidth scrollHeight scrollTop scrollLeft',
    'querySelector:function:element querySelectorAll:function:collection getAttribute setAttribute removeAttribute hasAttribute toggleAttribute getBoundingClientRect getClientRects matches closest:function:element append prepend appendChild removeChild replaceChildren insertAdjacentHTML remove focus blur click scrollIntoView addEventListener removeEventListener dispatchEvent');
  group('collection', 'length', 'item:function:element forEach entries keys values');
  group('classList', 'length value', 'add remove toggle contains replace item supports entries keys values forEach');
  group('style', 'cssText length display visibility color background backgroundColor opacity width height position top right bottom left margin padding border fontSize fontFamily transform overflow zIndex', 'getPropertyValue getPropertyPriority setProperty removeProperty item');
  group('navigator', 'userAgent platform language languages:array onLine cookieEnabled hardwareConcurrency maxTouchPoints vendor clipboard:clipboard geolocation permissions serviceWorker', 'sendBeacon');
  group('clipboard', '', 'read:function:promise readText:function:promise write:function:promise writeText:function:promise');
  group('location', 'href origin protocol host hostname port pathname search hash', 'assign replace reload toString:function:string');
  group('history', 'length state scrollRestoration', 'back forward go pushState replaceState');
  group('console', '', 'log info warn error debug table dir dirxml trace assert clear count countReset group groupCollapsed groupEnd time timeLog timeEnd');
  group('storage', 'length', 'getItem setItem removeItem clear key');
  group('performance', 'timeOrigin timing navigation', 'now getEntries:function:array getEntriesByName:function:array getEntriesByType:function:array mark measure clearMarks clearMeasures');
  group('math', 'E PI LN2 LN10 LOG2E LOG10E SQRT1_2 SQRT2', 'abs acos acosh asin asinh atan atanh atan2 ceil cbrt cos cosh exp expm1 floor fround hypot imul log log1p log2 log10 max min pow random round sign sin sinh sqrt tan tanh trunc');
  group('json', '', 'parse stringify:function:string');
  group('object', 'prototype:object', 'assign create defineProperty defineProperties entries:function:array fromEntries freeze getOwnPropertyDescriptor getOwnPropertyDescriptors getOwnPropertyNames:function:array getOwnPropertySymbols:function:array getPrototypeOf hasOwn is isExtensible isFrozen isSealed keys:function:array preventExtensions seal setPrototypeOf values:function:array');
  group('arrayConstructor', 'prototype:array', 'from:function:array isArray of:function:array');
  group('array', 'length', 'at concat:function:array copyWithin:function:array entries every fill:function:array filter:function:array find findIndex findLast findLastIndex flat:function:array flatMap:function:array forEach includes indexOf join:function:string keys lastIndexOf map:function:array pop push reduce reduceRight reverse:function:array shift slice:function:array some sort:function:array splice:function:array toReversed:function:array toSorted:function:array toSpliced:function:array toString:function:string unshift values with:function:array');
  group('stringConstructor', 'prototype:string', 'fromCharCode:function:string fromCodePoint:function:string raw:function:string');
  group('string', 'length', 'at charAt:function:string charCodeAt codePointAt concat:function:string endsWith includes indexOf lastIndexOf match matchAll normalize:function:string padEnd:function:string padStart:function:string repeat:function:string replace:function:string replaceAll:function:string search slice:function:string split:function:array startsWith substring:function:string toLowerCase:function:string toUpperCase:function:string trim:function:string trimEnd:function:string trimStart:function:string');
  group('numberConstructor', 'MAX_VALUE MIN_VALUE MAX_SAFE_INTEGER MIN_SAFE_INTEGER NaN NEGATIVE_INFINITY POSITIVE_INFINITY EPSILON', 'isFinite isInteger isNaN isSafeInteger parseFloat parseInt');
  group('promiseConstructor', 'prototype:promise', 'all:function:promise allSettled:function:promise any:function:promise race:function:promise reject:function:promise resolve:function:promise withResolvers');
  group('promise', '', 'then:function:promise catch:function:promise finally:function:promise');
  group('dateConstructor', 'prototype:date', 'now parse UTC');
  group('date', '', 'getTime getDate getDay getFullYear getHours getMilliseconds getMinutes getMonth getSeconds getTimezoneOffset toISOString:function:string toJSON:function:string toLocaleString:function:string toString:function:string setTime setDate setFullYear setHours setMinutes setMonth setSeconds');
  group('mapConstructor', 'prototype:map');
  group('map', 'size', 'clear delete entries forEach get has keys set:function:map values');
  group('setConstructor', 'prototype:set');
  group('set', 'size', 'add:function:set clear delete entries forEach has keys values');
  group('urlConstructor', 'prototype:url', 'canParse parse:function:url createObjectURL revokeObjectURL');
  group('url', 'href origin protocol username password host hostname port pathname search hash searchParams:params', 'toString:function:string toJSON:function:string');
  group('paramsConstructor', 'prototype:params');
  group('params', 'size', 'append delete entries forEach get getAll:function:array has keys set sort toString:function:string values');
  group('reflect', '', 'apply construct defineProperty deleteProperty get getOwnPropertyDescriptor getPrototypeOf has isExtensible ownKeys preventExtensions set setPrototypeOf');
  group('function', 'length name', 'apply bind:function:function call toString:function:string');
  return groups;
})();

function nativeConsoleSuggestions(source, caret, explicit = false) {
  if (source.length > 8192 || caret < 0 || caret > source.length) return null;
  // The sentinel makes an unfinished string, regex or comment consume the
  // caret. Reuse the source lexer rather than mistaking dots inside data for JS.
  const lexed = sourcePrettyTokens(source.slice(0, caret) + '\u0001', 'javascript');
  const last = lexed.at(-1);
  if (!last || last.kind !== 'operator' || last.text !== '\u0001') return null;
  let previous = null;
  for (const token of lexed) {
    if (['whitespace', 'comment', 'line-comment'].includes(token.kind)) continue;
    if (token.text === '/' && sourcePrettyMayStartRegex(previous) && sourcePrettyRegexEnd(source.slice(0, caret), token.start) === token.start + 1) return null;
    previous = token;
  }
  const tokens = lexed.slice(0, -1).filter(token => !['whitespace', 'comment', 'line-comment'].includes(token.kind));
  let index = tokens.length - 1;
  const word = tokens[index]?.kind === 'word' && tokens[index].end === caret ? tokens[index--] : null;
  const start = word?.start ?? caret;
  const prefix = word?.text ?? '';
  const member = ['.', '?.'].includes(tokens[index]?.text);
  if (!member && !prefix && !explicit) return null;
  if (member && tokens[index].end !== start && source.slice(tokens[index].end, start).trim()) return null;
  const resolve = (position, depth = 0) => {
    if (depth > 16 || position < 0) return null;
    const token = tokens[position];
    if (token.kind === 'literal' && ['"', "'", '`'].includes(token.text[0]) && token.text.at(-1) === token.text[0]) return {type: 'string'};
    if (token.text === ']') {
      let nesting = 1;
      let open = position;
      while (--open >= 0) {
        if (tokens[open].text === ']') ++nesting;
        if (tokens[open].text === '[' && --nesting === 0) break;
      }
      // Recognize array literals, but never guess the type of a computed lookup.
      if (open >= 0 && (!tokens[open - 1] || ['=', '(', ',', ':', ';', 'return'].includes(tokens[open - 1].text))) return {type: 'array'};
      return null;
    }
    if (token.text === ')') {
      let nesting = 1;
      let open = position;
      while (--open >= 0) {
        if (tokens[open].text === ')') ++nesting;
        if (tokens[open].text === '(' && --nesting === 0) break;
      }
      if (open < 0) return null;
      const callable = resolve(open - 1, depth + 1);
      return callable?.returns ? {type: callable.returns} : null;
    }
    if (token.kind !== 'word') return null;
    if (['.', '?.'].includes(tokens[position - 1]?.text)) {
      const owner = resolve(position - 2, depth + 1);
      return nativeConsoleCatalog.get(owner?.type)?.get(token.text) ?? null;
    }
    if (tokens[position - 1]?.text === 'new') {
      const type = nativeConsoleCatalog.get('global').get(token.text)?.type;
      return {returns: nativeConsoleCatalog.get(type)?.get('prototype')?.type};
    }
    return nativeConsoleCatalog.get('global').get(token.text) ?? null;
  };
  const group = member ? nativeConsoleCatalog.get(resolve(index - 1)?.type) : nativeConsoleCatalog.get('global');
  if (!group) return null;
  // Replace the entire identifier when completing in its middle. All offsets
  // are UTF-16, matching the textarea, source lexer and native selection API.
  let end = caret;
  while (end < source.length && /[\w$]/.test(source[end])) ++end;
  const items = [...group.values()].filter(entry => entry.name.startsWith(prefix) &&
    (explicit || entry.name !== source.slice(start, end))).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0).slice(0, 24);
  return items.length ? {items, start, end, prefix, source, caret} : null;
}

function createNativeConsoleCompletion(source, mirror, root) {
  const list = document.createElement('div');
  list.id = 'native-console-completions'; list.className = 'native-console-completions';
  list.hidden = true; list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', 'Built-in JavaScript API suggestions');
  document.body.append(list);
  source.setAttribute('role', 'combobox'); source.setAttribute('aria-autocomplete', 'list');
  source.setAttribute('aria-controls', list.id); source.setAttribute('aria-expanded', 'false');
  const measure = document.createElement('pre'); measure.className = 'native-console-caret-measure'; measure.setAttribute('aria-hidden', 'true');
  const before = document.createTextNode(''); const caret = document.createElement('span'); caret.textContent = '\u200b';
  measure.append(before, caret); mirror.parentElement.append(measure);
  let current = null;
  let selected = 0;
  let scheduled = false;
  let composing = false;
  let dismissed = false;
  function close() {
    current = null; list.hidden = true; list.replaceChildren(); before.data = '';
    source.setAttribute('aria-expanded', 'false'); source.removeAttribute('aria-activedescendant');
  }
  function position() {
    if (!current) return;
    const input = source.getBoundingClientRect();
    const clip = document.querySelector('#native-console-scroll').getBoundingClientRect();
    before.data = source.value.slice(0, source.selectionStart);
    measure.style.width = `${source.clientWidth}px`; measure.style.height = `${source.clientHeight}px`;
    const marker = caret.getBoundingClientRect();
    const top = marker.top - source.scrollTop; const left = marker.left - source.scrollLeft;
    if (top < Math.max(clip.top, input.top) || top + 18 > Math.min(clip.bottom, input.bottom) + 1) { close(); return; }
    const viewport = window.visualViewport;
    const width = viewport?.width ?? window.innerWidth; const height = viewport?.height ?? window.innerHeight;
    const x = viewport?.offsetLeft ?? 0; const y = viewport?.offsetTop ?? 0;
    list.style.width = `${Math.min(300, width - 16)}px`;
    list.style.left = `${Math.max(x + 8, Math.min(left, x + width - list.offsetWidth - 8))}px`;
    const below = y + height - top - 22 - 8; const above = top - y - 8;
    const upward = below < Math.min(198, list.scrollHeight) && above > below;
    list.style.maxHeight = `${Math.max(0, Math.min(198, upward ? above : below))}px`;
    list.style.top = `${upward ? top - list.offsetHeight - 3 : top + 21}px`;
  }
  function select(index) {
    selected = index;
    [...list.querySelectorAll('[role="option"]')].forEach((row, i) => row.setAttribute('aria-selected', String(i === index)));
    const row = list.children[index]; source.setAttribute('aria-activedescendant', row.id);
    row.scrollIntoView({block: 'nearest'});
  }
  function show(explicit = false) {
    if (composing || source.disabled || root.hidden || document.activeElement !== source ||
        source.selectionStart !== source.selectionEnd || dismissed && !explicit) { close(); return; }
    const suggestion = nativeConsoleSuggestions(source.value, source.selectionStart, explicit);
    if (!suggestion) { close(); return; }
    const previous = current?.items[selected]?.name;
    current = suggestion;
    const rows = current.items.map((item, index) => {
      const row = document.createElement('div'); row.id = `${list.id}-${index}`;
      row.className = 'native-console-completion'; row.dataset.kind = item.kind; row.setAttribute('role', 'option');
      const icon = document.createElement('span'); icon.className = 'native-console-completion-icon'; icon.setAttribute('aria-hidden', 'true');
      icon.textContent = item.kind === 'function' ? 'ƒ' : 'p';
      const label = document.createElement('span'); label.className = 'native-console-completion-name';
      const match = document.createElement('strong'); match.textContent = current.prefix;
      label.append(match, document.createTextNode(item.name.slice(current.prefix.length)));
      const kind = document.createElement('span'); kind.className = 'native-console-completion-kind'; kind.textContent = item.kind;
      row.append(icon, label, kind);
      row.addEventListener('pointerdown', event => { event.preventDefault(); select(index); accept(); });
      return row;
    });
    list.replaceChildren(...rows); list.hidden = false; source.setAttribute('aria-expanded', 'true');
    position();
    if (current) select(Math.max(0, current.items.findIndex(item => item.name === previous)));
  }
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    // Native WebKit may suspend animation frames in an inactive window.
    // Complete after the input/mirror handlers even before the next paint.
    queueMicrotask(() => { scheduled = false; show(); });
  }
  function accept() {
    if (!current || current.source !== source.value || current.caret !== source.selectionStart || source.selectionStart !== source.selectionEnd) { close(); return; }
    const item = current.items[selected];
    const next = source.value.slice(0, current.start) + item.name + source.value.slice(current.end);
    if (next.length > 8192 || new TextEncoder().encode(next).length > 8192) { close(); return; }
    source.setRangeText(item.name, current.start, current.end, 'end');
    close(); source.dispatchEvent(new Event('input', {bubbles: true})); dismissed = true;
  }
  source.addEventListener('input', () => { dismissed = false; schedule(); });
  source.addEventListener('click', () => { dismissed = false; schedule(); });
  source.addEventListener('selectionchange', schedule);
  source.addEventListener('blur', close);
  source.addEventListener('compositionstart', () => { composing = true; close(); });
  source.addEventListener('compositionend', () => { composing = false; dismissed = false; schedule(); });
  source.addEventListener('scroll', position);
  document.querySelector('#native-console-scroll').addEventListener('scroll', position);
  new ResizeObserver(position).observe(source);
  new MutationObserver(() => { if (root.hidden || source.disabled) close(); }).observe(root, {attributes: true, subtree: true, attributeFilter: ['hidden', 'disabled']});
  document.addEventListener('pointerdown', event => { if (event.target !== source && !list.contains(event.target)) close(); });
  window.addEventListener('resize', position);
  window.visualViewport?.addEventListener('resize', position);
  return {
    close,
    keydown(event) {
      if (event.isComposing || composing) return false;
      if (event.ctrlKey && !event.metaKey && !event.altKey && event.code === 'Space') {
        event.preventDefault(); dismissed = false; show(true); return true;
      }
      if (current && !event.shiftKey && !event.ctrlKey && !event.metaKey && !event.altKey) {
        if (['ArrowDown', 'ArrowUp'].includes(event.key)) {
          event.preventDefault(); select((selected + (event.key === 'ArrowDown' ? 1 : -1) + current.items.length) % current.items.length); return true;
        }
        if (event.key === 'Tab' || event.key === 'Enter') { event.preventDefault(); accept(); return true; }
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); dismissed = true; close(); return true; }
      }
      if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) { dismissed = false; schedule(); }
      else if (event.key === 'Tab' || event.key === 'Enter' || event.key === 'Escape') close();
      return false;
    }
  };
}
