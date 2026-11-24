#!/usr/bin/env node
// The evidence chip blocks (apps/research-ui/evidence_chips.js): formatters,
// chips and their panels, keyed reconciliation, reason and evidence-class
// chips, limits, empty states and notices. The shipped script runs in a
// LinkeDOM document with a small focus model (LinkeDOM keeps no active
// element). Not rendered QA: placement, hover and WebKit focus are covered
// by make rendered-ui-check.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {runInNewContext} from 'node:vm';

const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
const source = await readFile(new URL('../apps/research-ui/evidence_chips.js', import.meta.url), 'utf8');
const n = value => new Intl.NumberFormat().format(value);
const passed = [];
const pass = name => passed.push(name);

// Loading installs nothing: no listener, no node, no document needed.
{
  const context = {};
  runInNewContext(source, context);
  assert.equal(typeof context.RebEvidenceChips.formatCount, 'function');
  assert(Object.isFrozen(context.RebEvidenceChips));
  pass('loads without a document and freezes its API');
}

function mount() {
  const {window, document} = parseHTML('<!doctype html><html><body><main id="root"></main><input id="outside"></body></html>');
  let active = document.body;
  Object.defineProperty(document, 'activeElement', {get: () => active, configurable: true});
  window.HTMLElement.prototype.focus = function focus() {
    if (active === this) return;
    active = this;
    this.dispatchEvent(new window.Event('focusin', {bubbles: true}));
  };
  const copies = [];
  const context = {window, document, navigator: {clipboard: {writeText: async text => { copies.push(text); }}}, setTimeout, clearTimeout};
  runInNewContext(source, context);
  const event = (target, type, init = {}) => target.dispatchEvent(Object.assign(new window.Event(type, {bubbles: true, cancelable: true}), init));
  return {window, document, chips: context.RebEvidenceChips, root: document.getElementById('root'), copies, event,
    press: (target, key) => event(target, 'keydown', {key}), get active() { return active; }};
}

// ---- Formatters ---------------------------------------------------------------
{
  const {chips} = mount();
  for (const [value, expected] of [[75511, n(75511)], [75511n, n(75511n)], ['75511', n(75511)], ['18446744073709551615', n(18446744073709551615n)],
    [0, '0'], [-1200, n(-1200)], ['n/a', 'n/a'], [Number.NaN, 'NaN'], [null, 'null']]) {
    assert.equal(chips.formatCount(value), expected, String(value));
  }
  if (new Intl.NumberFormat().resolvedOptions().locale.startsWith('en')) assert.equal(chips.formatCount(75511), '75,511');
  pass('formatCount groups numbers, bigints and uint64 decimal strings in the locale and shows anything else as given');

  for (const missing of [null, undefined, '', '01', '1.5', 1.5, '+1', 'x', Number.MAX_SAFE_INTEGER + 1]) {
    assert.deepEqual({...chips.formatEvidenceTime(missing)}, {text: 'time not recorded', title: 'This record has no monotonic time.', exact: null}, String(missing));
  }
  const unanchored = chips.formatEvidenceTime('1993065185052000');
  assert.equal(unanchored.text, '1,993,065.185 s', 'before any origin the clock still reads in seconds');
  assert.equal(unanchored.exact, '1993065185052000');
  assert.match(unanchored.title, /^1993065185052000 ns monotonic, since this Mac started; the session start is not known yet$/);
  assert.equal(chips.timeOrigin(), null);
  assert.throws(() => chips.setTimeOrigin('1', 'session'), /store or records/);
  const origin = 1993065000000000n;
  assert.deepEqual({...chips.setTimeOrigin(String(origin), 'store')}, {ns: origin, basis: 'store'});
  for (const [delta, text] of [[0n, '+0.000 s'], [999999999n, '+0.999 s'], [12345000000n, '+12.345 s'], [125345000000n, '+2:05.345'],
    [3725345000000n, '+1:02:05.345'], [-1500000000n, '-1.500 s']]) {
    assert.equal(chips.formatEvidenceTime(origin + delta).text, text, `${delta} ns`);
  }
  assert.equal(chips.formatEvidenceTime(origin + 12345000000n).title, `12.345000000 s after the first stored record · ${origin + 12345000000n} ns monotonic`);
  assert.equal(chips.formatEvidenceTime(origin - 1500000000n).title, `1.500000000 s before the first stored record · ${origin - 1500000000n} ns monotonic`);
  chips.setTimeOrigin(String(origin), 'records');
  assert.match(chips.formatEvidenceTime(origin).title, /after the first record read/);
  assert.equal(chips.formatEvidenceTime(origin + 5n, {origin: String(origin + 5n)}).text, '+0.000 s', 'an explicit origin wins');
  const relative = chips.formatEvidenceTime(origin + 32100000n, {relativeTo: {ns: origin, label: 'request start'}});
  assert.equal(relative.text, '+32.1 ms');
  assert.equal(relative.title, `0.032100000 s after request start · ${origin + 32100000n} ns monotonic`);
  assert.equal(chips.formatEvidenceTime(origin, {relativeTo: {ns: origin + 850n, label: ''}}).text, '-850 ns');
  assert.match(chips.formatEvidenceTime(origin, {relativeTo: {ns: origin + 850n, label: ''}}).title, /before the reference record/);
  assert.equal(chips.formatEvidenceTime('18446744073709551615').exact, '18446744073709551615', 'a uint64 stays exact');
  assert.equal(chips.setTimeOrigin(null), null);
  assert.equal(chips.setTimeOrigin(-1n), null, 'a negative origin is no origin');
  assert.equal(chips.timeOrigin(), null);
  pass('formatEvidenceTime: session-relative clock, truncation, before and after, relative offsets, exact ns in title and copy');

  for (const [ns, text] of [[850n, '850 ns'], [3210n, '3.21 µs'], [32100000n, '32.1 ms'], [321000000n, '321 ms'], [4560000000n, '4.56 s'],
    [125000000000n, '2 min 05 s'], [3720000000000n, '1 h 02 min'], [-4560000000n, '-4.56 s'], [null, 'not recorded']]) {
    assert.equal(chips.formatEvidenceDuration(ns), text, String(ns));
  }
  pass('formatEvidenceDuration reads three significant digits and never rounds up a unit');
}

// ---- Time elements -----------------------------------------------------------
{
  const {chips, root, copies, document} = mount();
  chips.setTimeOrigin('1000000000');
  const time = chips.timeElement('13345000000');
  assert.equal(time.tagName, 'TIME');
  assert.equal(time.textContent, '+12.345 s');
  assert.equal(time.dataset.monotonicNs, '13345000000');
  assert.match(time.title, /after the first stored record/);
  assert.equal(chips.timeElement(null).dataset.monotonicNs, undefined);
  const holder = chips.timeButton('13345000000');
  root.append(holder);
  const button = holder.querySelector('button');
  assert.equal(button.textContent, '+12.345 s');
  const description = document.getElementById(button.getAttribute('aria-describedby'));
  assert.equal(description.parentNode, holder, 'the description travels with its button');
  assert.equal(description.hidden, true);
  assert.match(description.textContent, /Click to copy 13345000000\.$/);
  button.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(copies, ['13345000000']);
  const unrecorded = chips.timeButton('');
  assert.equal(unrecorded.querySelector('button').disabled, true);
  assert.equal(unrecorded.querySelector('button').getAttribute('aria-describedby'), null);
  pass('timeElement and timeButton: relative text, exact ns in data and copy, a described focusable button');
}

// ---- Chips and panels ---------------------------------------------------------
{
  const {chips, root, document, press, event} = mount();
  const text = spec => chips.chip(spec).button.textContent;
  assert.equal(text({key: 'a', count: 1, noun: 'gap'}), '1 gap');
  assert.equal(text({key: 'a', count: 2n, noun: 'gap'}), '2 gaps');
  assert.equal(text({key: 'a', count: 75511n, noun: ['lost', 'lost'], suffix: '(network)'}), `${n(75511)} lost (network)`);
  assert.equal(text({key: 'a', count: 3n, atLeast: true, noun: 'gap'}), '≥3 gaps');
  assert.equal(text({key: 'a', text: 'newest 64 MiB'}), 'newest 64 MiB');
  for (const [spec, message] of [[{count: 1}, /needs a key/], [{key: 'a'}, /needs text or a count/], [{key: 'a', count: 1.5}, /needs text or a count/],
    [{key: 'a', text: 'x', tone: 'red'}, /tone is one of/], [{key: 'a', text: 'x', facts: {rows: []}, run() {}}, /not more than one/]]) {
    assert.throws(() => chips.chip(spec), message);
  }
  // Captured values are text, never markup.
  const hostile = '<img src=x onerror="globalThis.owned=1">';
  const unsafe = chips.chip({key: 'x', text: hostile, facts: {title: hostile, rows: [['Value', hostile]]}});
  root.append(unsafe.element);
  unsafe.button.click();
  assert.equal(unsafe.element.querySelector('img'), null);
  assert.equal(unsafe.button.textContent, hostile);
  assert.equal(unsafe.element.querySelector('dd').textContent, hostile);
  unsafe.close();
  pass('chip text: counted nouns, plurals, grouped counts, lower bounds, validation, captured values as text');

  const runs = [];
  const spec = run => ({key: 'gaps', tone: 'loss', count: 560n, noun: 'gap', name: '560 gaps in the stored capture', prefer: 'above',
    breakdown: {title: 'Capture gaps', scope: 'stored capture', detail: 'One line.',
      rows: [{label: 'Sequence gaps', count: 280n, tone: 'loss', detail: 'Absent IDs.', reasons: [{token: 'native_wasm_dispatch_transport_unavailable', count: 2n}]},
        {label: 'Queue drops', count: 280n, atLeast: true, tone: 'loss'}],
      note: 'Counts can overlap.', actions: [{key: 'evidence', label: 'Show in Evidence', run}]}});
  const [gaps] = chips.renderChips(root, [spec(() => runs.push('first'))]);
  const {button} = gaps;
  const panel = document.getElementById(button.getAttribute('aria-controls'));
  assert.equal(button.dataset.tone, 'loss');
  assert.equal(button.getAttribute('aria-label'), '560 gaps in the stored capture');
  assert.equal(button.getAttribute('aria-expanded'), 'false');
  assert.equal(panel.previousElementSibling, button, 'the panel follows its chip, so Tab reaches it next');
  assert.equal(panel.getAttribute('role'), 'group');
  assert.equal(panel.getAttribute('aria-label'), 'Capture gaps');
  assert.equal(panel.hidden, true);
  assert(button.querySelector('.ev-chip-chevron'), 'a chip that opens a panel shows a chevron');
  button.click();
  assert.equal(button.getAttribute('aria-expanded'), 'true');
  assert.equal(panel.hidden, false);
  assert.equal(panel.querySelector('.ev-panel-title').textContent, 'Capture gaps');
  assert.equal(panel.querySelector('.ev-panel-scope').textContent, 'stored capture');
  assert.deepEqual([...panel.querySelectorAll('.ev-panel-row .ev-panel-line')].map(line => line.textContent), ['Sequence gaps280', 'Queue drops≥280']);
  const reason = panel.querySelector('.ev-reason');
  assert.equal(reason.querySelector('.ev-reason-label').textContent, 'Wasm dispatch transport unavailable', 'an undefined token reads as its words');
  assert.equal(reason.querySelector('.ev-reason-token').textContent, 'native_wasm_dispatch_transport_unavailable', 'the raw token stays visible');
  assert.equal(panel.querySelector('.ev-panel-reason .ev-panel-count').textContent, '×2');
  assert.equal(panel.querySelector('.ev-panel-note').textContent, 'Counts can overlap.');
  assert.match(panel.dataset.side, /^(above|below)$/, 'an open floating panel is placed');
  // An update that reads the same keeps the open panel's nodes and runs the newest callback.
  const row = panel.querySelector('.ev-panel-row');
  chips.renderChips(root, [spec(() => runs.push('second'))]);
  assert.equal(root.querySelector('.ev-chip'), button, 'the chip is updated in place');
  assert.equal(panel.querySelector('.ev-panel-row'), row, 'an unchanged panel keeps its nodes');
  assert.equal(panel.hidden, false, 'an open panel survives a refresh');
  panel.querySelector('.ev-panel-action').click();
  assert.deepEqual(runs, ['second'], 'a panel action runs the newest callback, never a stale one');
  assert.equal(panel.hidden, true, 'an action closes its panel');
  // Escape inside the panel closes it and returns focus to the chip.
  button.click();
  panel.querySelector('.ev-panel-action').focus();
  press(panel.querySelector('.ev-panel-action'), 'Escape');
  assert.equal(panel.hidden, true);
  assert.equal(document.activeElement, button);
  // A press or focus outside closes it.
  button.click();
  event(document.getElementById('outside'), 'pointerdown');
  assert.equal(panel.hidden, true);
  button.click();
  document.getElementById('outside').focus();
  assert.equal(panel.hidden, true, 'focus moving elsewhere closes the panel');
  // At most one floating panel is open.
  const facts = chips.chip({key: 'connection', text: 'Live', tone: 'ok', dot: true, variant: 'ghost', facts: {title: 'Connection', rows: [['Session', 'Live session']]}});
  root.append(facts.element);
  button.click();
  facts.button.click();
  assert.equal(panel.hidden, true, 'opening a second panel closes the first');
  assert.deepEqual([...facts.element.querySelectorAll('dt, dd')].map(item => item.textContent), ['Session', 'Live session']);
  assert.equal(facts.button.dataset.variant, 'ghost');
  assert.equal(facts.button.querySelector('.ev-chip-dot').hidden, false);
  chips.close();
  assert.equal(facts.element.querySelector('.ev-panel').hidden, true);
  pass('breakdown and facts panels: DOM order, aria-expanded and aria-controls, Escape, outside press, focus-out, one open, refresh-stable nodes and newest callbacks');

  // Keyed reconciliation: kept keys update in place, gone keys go, focus survives.
  const container = document.createElement('div');
  root.append(container);
  const first = chips.renderChips(container, [{key: 'a', text: 'A'}, {key: 'b', text: 'B'}]);
  first[1].button.focus();
  const second = chips.renderChips(container, [{key: 'b', text: 'B2'}, null, {key: 'c', text: 'C'}]);
  assert.equal(second[0], first[1], 'a kept key keeps its controller');
  assert.deepEqual([...container.querySelectorAll('.ev-chip')].map(item => item.textContent), ['B2', 'C']);
  assert.equal(document.activeElement, first[1].button, 'focus on a kept chip stays');
  chips.renderChips(container, [{key: 'c', text: 'C'}]);
  assert.equal(document.activeElement, container.querySelector('.ev-chip'), 'focus on a removed chip moves to the first chip');
  assert.throws(() => chips.renderChips(container, [{key: 'c', text: 'C'}, {key: 'c', text: 'D'}]), /share the key c/);
  const plain = chips.renderChips(container, [{key: 'c', text: 'C'}])[0];
  const withPanel = chips.renderChips(container, [{key: 'c', text: 'C', facts: {rows: []}}])[0];
  assert.notEqual(plain, withPanel, 'a chip that gains a panel is a new chip');
  chips.renderChips(container, []);
  assert.equal(container.children.length, 0);
  pass('renderChips: keyed in-place updates, ordering, removal, focus rescue, duplicate keys refused');

  // An action chip shows the state it toggles.
  let pressed = false;
  const toggle = () => chips.renderChips(container, [{key: 'failed', tone: 'neutral', count: 2, noun: ['failed', 'failed'], pressed,
    name: '2 failed requests: show only failed requests', run: () => { pressed = !pressed; toggle(); }}]);
  toggle();
  const failed = container.querySelector('.ev-chip');
  assert.equal(failed.getAttribute('aria-pressed'), 'false');
  assert.equal(failed.getAttribute('aria-expanded'), null, 'an action chip opens nothing');
  failed.click();
  assert.equal(failed.getAttribute('aria-pressed'), 'true');
  pass('action chips run and show aria-pressed');

  // A described chip names its tooltip; the floating copy is aria-hidden.
  const described = chips.chip({key: 'd', text: 'Degraded', tone: 'limit', description: 'The artifact receiver is offline.'});
  root.append(described.element);
  const tipText = document.getElementById(described.button.getAttribute('aria-describedby'));
  assert.equal(tipText.textContent, 'The artifact receiver is offline.');
  chips.chip({key: 'd', text: 'Degraded', description: 'x'}).update({key: 'd', text: 'Degraded', description: 'Changed.'});
  assert.equal(tipText.textContent, 'The artifact receiver is offline.', 'each chip owns its description');
  pass('described chips: aria-describedby names a hidden description in the chip wrapper');
}

// ---- Reasons, evidence classes, limits, empty states, notices ----------------
{
  const {chips, root, document, copies} = mount();
  chips.defineReasons({native_example_budget: {label: 'Example budget', kind: 'limit', meaning: 'The example budget filled.'}});
  assert.deepEqual({...chips.reason('native_example_budget')}, {label: 'Example budget', meaning: 'The example budget filled.', kind: 'limit'});
  assert.deepEqual({...chips.reason('native_sw_url_lost')}, {label: 'Service worker URL lost', meaning: '', kind: null});
  for (const bad of [{Bad: {label: 'x'}}, {ok: {label: ''}}, {ok: {label: 'x', kind: 'other'}}, {ok: {label: 'x'.repeat(81)}}]) {
    assert.throws(() => chips.defineReasons(bad), /needs a token/);
  }
  const reason = chips.reasonChip('native_example_budget');
  root.append(reason);
  const reasonButton = reason.querySelector('button');
  assert.equal(reasonButton.dataset.kind, 'limit');
  assert.equal(reasonButton.textContent, 'Example budgetnative_example_budget');
  assert.equal(document.getElementById(reasonButton.getAttribute('aria-describedby')).textContent, 'The example budget filled. Click to copy native_example_budget.');
  reasonButton.click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(copies, ['native_example_budget']);
  pass('reasonChip: glossary label, raw token, meaning as its description, click copies the token; defineReasons validates');

  const observed = chips.evidenceClassChip('observed');
  root.append(observed);
  assert.equal(observed.querySelector('button').getAttribute('aria-label'), 'Evidence class: observed');
  assert.equal(document.getElementById(observed.querySelector('button').getAttribute('aria-describedby')).textContent, 'Recorded by a native probe while the page ran.');
  assert.deepEqual(Object.keys(chips.evidenceClasses), ['observed', 'declared', 'inferred', 'correlated', 'unknown']);
  assert.throws(() => chips.evidenceClassChip('guessed'), /one of observed/);
  pass('evidenceClassChip: five classes, each named and described');

  const limits = chips.limitsDisclosure(['Rows come from the newest 5,000 events.', 'Counts cover the newest 64 MiB.']);
  root.append(limits);
  const limitsButton = limits.querySelector('.ev-limits-button');
  assert.equal(limitsButton.getAttribute('aria-label'), 'Limits of this pane');
  limitsButton.click();
  assert.deepEqual([...limits.querySelectorAll('li')].map(item => item.textContent), ['Rows come from the newest 5,000 events.', 'Counts cover the newest 64 MiB.']);
  assert.equal(limits.querySelector('.ev-panel').hidden, false);
  chips.close();
  pass('limitsDisclosure: one button whose panel lists one sentence per limit');

  let reran = 0;
  const empty = chips.emptyState({title: 'No requests yet', reason: 'Capture is running.', action: {label: 'Reload', run: () => { reran += 1; }},
    causes: [{text: 'The page made no requests.'}, {text: 'The capture filter excludes them.', applies: true}]});
  root.append(empty);
  assert.equal(empty.querySelector('.ev-empty-title').textContent, 'No requests yet');
  assert.equal(empty.querySelector('.ev-empty-reason').textContent, 'Capture is running.');
  empty.querySelector('.ev-empty-action').click();
  assert.equal(reran, 1);
  const why = empty.querySelector('.ev-empty-why');
  const causes = empty.querySelector('.ev-empty-causes');
  assert.equal(why.textContent, 'Why is this empty?');
  assert.equal(causes.hidden, true);
  why.click();
  assert.equal(why.getAttribute('aria-expanded'), 'true');
  assert.equal(causes.hidden, false);
  assert.equal(causes.dataset.side, undefined, 'causes open in place, not floating');
  assert.deepEqual([...causes.children].map(item => item.textContent), ['This sessionThe capture filter excludes them.', 'The page made no requests.']);
  why.click();
  assert.equal(causes.hidden, true);
  pass('emptyState: title, one reason, an action, and causes in place with the applying cause first');

  const line = document.createElement('div');
  root.append(line);
  const shown = [];
  let dismissed = 0;
  const draw = label => chips.renderNotice(line, {lead: 'Incomplete capture', chips: [{key: 'drops', tone: 'loss', count: 3n, noun: 'queue drop'}],
    actions: [{key: 'evidence', label: 'Show in Evidence', run: () => shown.push(label)}], dismiss: {name: 'Dismiss this notice', run: () => { dismissed += 1; }}});
  draw('first');
  const action = line.querySelector('.ev-notice-action');
  draw('second');
  assert.equal(line.querySelector('.ev-notice-action'), action, 'unchanged actions keep their buttons');
  action.click();
  assert.deepEqual(shown, ['second'], 'an action runs the newest handler');
  assert.equal(line.querySelector('.ev-notice-lead').textContent, 'Incomplete capture');
  assert.equal(line.querySelector('.ev-notice-text').hidden, true);
  assert.equal(line.querySelector('.ev-notice-chips .ev-chip').textContent, '3 queue drops');
  const dismiss = line.querySelector('.ev-notice-dismiss');
  assert.equal(dismiss.getAttribute('aria-label'), 'Dismiss this notice');
  dismiss.click();
  assert.equal(dismissed, 1);
  chips.renderNotice(line, {text: 'Reading the request index'});
  assert.equal(line.querySelector('.ev-notice-lead').hidden, true);
  assert.equal(line.querySelector('.ev-notice-text').textContent, 'Reading the request index');
  assert.equal(line.querySelector('.ev-notice-chips').hidden, true);
  assert.equal(line.querySelector('.ev-notice-actions').hidden, true);
  assert.equal(line.querySelector('.ev-notice-dismiss'), null);
  pass('renderNotice: lead, text, chips, stable actions with newest handlers, and a named dismiss');
}

console.log(`PASS evidence chips: ${passed.length} block contracts (LinkeDOM model with a focus model; placement and WebKit focus are rendered QA)`);
for (const name of passed) console.log(`  ${name}`);
