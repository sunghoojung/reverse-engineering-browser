#!/usr/bin/env node
// Live session panel against the shipped scripts in an offline DOM model,
// with a fake native bridge: what each state shows, what the page asks
// native, that native values stay text and that a refused choice stays on
// screen. Not rendered QA: layout, focus and the real bridge are covered by
// the start panel tests in tools/origin-trace-rendered-ui/.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
const {window, context, asyncErrors, release} = loadShippedUi();
const document = window.document;
const panel = document.getElementById('session-panel');
assert(panel, 'index.html declares the session panel');
assert.equal(panel.getAttribute('role'), 'dialog');
assert.equal(panel.getAttribute('aria-modal'), 'false', 'the panel is part of the workspace, not a modal');
assert(panel.closest('#workspace'), 'the panel lives inside the workspace');
const push = state => runInContext('__rebSessionPanel', context)(state);
const text = () => panel.textContent.replace(/\s+/g, ' ');
const buttonNamed = name => [...panel.querySelectorAll('button')].find(button => button.textContent === name);
const settle = async () => { for (let turn = 0; turn < 4; turn += 1) await nextTurn(); };

// Without the native app nothing is drawn and nothing is asked.
push({panel: 'hidden'});
assert.equal(panel.hidden, true);
assert.equal(panel.children.length, 0);

const posted = [];
let answer = message => ({ok: true});
context.webkit = {messageHandlers: {rebSession: {postMessage: async message => {
  posted.push(JSON.parse(JSON.stringify(message)));
  const reply = answer(message);
  if (reply instanceof Error) throw reply;
  return reply;
}}}};

const modes = [{id: 'content', title: 'Content (default)'}, {id: 'metadata', title: 'Metadata only'}];
const hostile = '<img src=x onerror="window.__rebInjected=1">';
const choose = (sites, extra = {}) => ({panel: 'choose', mode: 'content', modes, sites, ...extra});
const saved = (generation, items) => ({state: 'saved', generation, limit: 8, items});

// The start choices, with the same wording as the alert they replace.
push(choose(saved(1, [{label: 'window.hsw', sourceURL: 'https://hcaptcha.test/glue.js'}, {label: hostile, sourceURL: null}])));
assert.equal(panel.hidden, false);
assert.equal(panel.dataset.state, 'choose');
for (const phrase of ['Start a live research session', 'Choose the evidence boundary for this session.',
  'You can start another session later from the Origin Trace menu.', 'Capture mode', 'Content (default)', 'Metadata only',
  'Retains request paths, queries and bodies and response bodies up to 16 MiB each, request and response headers, cookies, and Canvas images.',
  'Keeps request hosts and each request body’s length, type and SHA-256, without headers, cookies or Canvas images.',
  'Artifacts keep raw source URLs locally; only an explicitly exported redacted copy is altered.',
  'Tracking 2 functions', 'window.hsw', 'https://hcaptcha.test/glue.js', 'Source URL not recorded',
  'Content mode also records settled-value digests of their string and byte results (sensitive capture)',
  'A Brave without invocation capture starts without them and says so.']) {
  assert(text().includes(phrase), `the start panel says: ${phrase}`);
}
assert(text().includes(hostile), 'a saved label is shown as its own text');
assert.equal(panel.querySelectorAll('img').length, 0, 'a saved label never becomes markup');
assert.equal(window.__rebInjected, undefined);
assert.deepEqual([...panel.querySelectorAll('footer button')].map(button => button.textContent), ['Continue Offline', 'Start Session']);
const radio = id => panel.querySelector(`#session-panel-mode-${id}`);
assert.equal(radio('content').checked, true, 'native preselects the mode');
// Sessions from the panel always use the isolated profile: no Keychain choice.
assert(!/keychain/i.test(text()), 'the start panel offers no Keychain choice');
assert.equal(panel.querySelectorAll('input[type="checkbox"]').length, 0);
assert.equal(posted.length, 0, 'drawing the panel asks native nothing');

// The page selection drives the digest wording and is what Start sends.
radio('metadata').checked = true;
radio('metadata').dispatchEvent(new window.Event('change'));
assert(text().includes('Metadata mode records no settled-value digests.'));
assert(!text().includes('Content mode also records settled-value digests'));
// Native republishing the same decision (a Remove reply) keeps that selection.
push(choose(saved(1, [{label: 'window.hsw', sourceURL: 'https://hcaptcha.test/glue.js'}, {label: hostile, sourceURL: null}])));
assert.equal(radio('metadata').checked, true, 'a redraw keeps the researcher’s mode');

// Remove names the list it saw; native answers with the new state.
answer = message => message.op === 'removeSite'
  ? choose(saved(2, [{label: hostile, sourceURL: null}]), {mode: 'content'}) : {ok: true};
panel.querySelector('[aria-label="Remove window.hsw"]').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'removeSite', index: 0, generation: 1});
assert(text().includes('Tracking 1 function'), text());
assert(!text().includes('window.hsw'));
assert.equal(radio('metadata').checked, true, 'native’s reply does not reset the selection');

// Clear All asks first, in place.
const before = posted.length;
buttonNamed('Clear All').click();
assert.equal(posted.length, before, 'the first Clear All only asks');
assert(buttonNamed('Confirm Clear All'));
answer = message => message.op === 'clearSites' ? choose({state: 'empty', generation: 3, limit: 8, items: []}) : {ok: true};
buttonNamed('Confirm Clear All').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'clearSites', generation: 2});
assert(text().includes('Tracking no functions'));
assert(text().includes('Choose Track calls in Sources during a capture to save a function.'));
assert.equal(buttonNamed('Clear All'), undefined, 'nothing to clear');

// Start sends the page's selection; native validates it.
answer = () => ({ok: true});
buttonNamed('Start Session').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'metadata'}, 'Start sends the capture mode and nothing else');

// A refused choice stays on screen with the reason and working controls.
answer = () => new Error('This start choice is no longer open.');
buttonNamed('Start Session').click();
await settle();
const refusal = panel.querySelector('[role="alert"]');
assert(refusal && refusal.textContent.includes('This start choice is no longer open.'), text());
assert(refusal.textContent.includes('New Live Session…'));
assert.equal(buttonNamed('Start Session').disabled, false, 'controls come back after a refusal');
assert.equal(panel.dataset.state, 'choose');

// An unreadable site file can be cleared.
push({panel: 'hidden'});
push(choose({state: 'unreadable', generation: 4, limit: 8, items: []}));
assert(text().includes('Saved functions unreadable'));
assert(buttonNamed('Clear All'));
assert.equal(radio('content').checked, true, 'a new decision starts from native’s choice');
assert.equal(panel.querySelector('[role="alert"]'), null, 'a new decision clears an old refusal');

// Starting: a status, no actions.
push({panel: 'starting', mode: 'metadata', modes});
assert.equal(panel.dataset.state, 'starting');
assert(text().includes('Starting a live session'));
assert(text().includes('Capture mode: Metadata only.'));
assert.equal(panel.querySelectorAll('button').length, 0);
assert.equal(panel.querySelector('[role="status"]')?.textContent.includes('within a minute'), true);
assert.equal(panel.getAttribute('aria-busy'), 'true');

// A session that never became ready, then one that ended.
const log = `Brave stopped during native startup. ${hostile}\n\nSession log: /tmp/live-session.log`;
push({panel: 'failed', mode: 'content', modes,
  failure: {title: 'Live session unavailable', message: log, afterStartup: false}});
assert.equal(panel.dataset.state, 'failed');
assert(text().includes('Live session unavailable'));
assert.equal(panel.querySelector('#session-panel-failure').textContent, log, 'the launcher cause and log path are shown as text');
assert.equal(panel.querySelectorAll('img').length, 0);
assert(text().includes('Retry starts a new session with the same capture mode: Content (default).'));
assert(!/keychain/i.test(text()), 'Retry names no Keychain choice');
assert(!text().includes('replaces this ended workspace'));
assert.deepEqual([...panel.querySelectorAll('footer button')].map(button => button.textContent), ['Continue Offline', 'Retry']);
answer = () => ({ok: true});
buttonNamed('Retry').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'retry'});
push({panel: 'failed', mode: 'metadata', modes,
  failure: {title: 'Live session ended', message: 'The live capture coordinator stopped unexpectedly.', afterStartup: true}});
assert(text().includes('Live session ended'));
assert(text().includes('the same capture mode: Metadata only.'));
assert(text().includes('Continue Offline replaces this ended workspace'));
buttonNamed('Continue Offline').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'offline'});

push({panel: 'hidden'});
assert.equal(panel.hidden, true);
assert.equal(panel.children.length, 0);
await settle();
assert.deepEqual(asyncErrors, [], 'no unhandled rejection');
release();

// Native owns the decision: every choice the page can send is checked there.
const native = readFileSync(new URL('../apps/research-ui/macos/SessionPanel.swift', import.meta.url), 'utf8');
for (const op of ['state', 'start', 'retry', 'offline', 'removeSite', 'clearSites']) {
  assert(native.includes(`case "${op}"`) || native.includes(`"${op}"`), `native handles ${op}`);
}
assert.match(native, /isSubset\(of: \["op", "mode"\]\)/, 'native refuses a start that names anything but the mode');
assert(!/body\["keychain"\]/.test(native), 'native reads no Keychain value from the page');
assert.match(native, /LiveCaptureMode\(rawValue: raw\)/, 'native accepts only a known capture mode');
console.log('PASS session panel: start choices with the alert’s wording, no Keychain option, saved sites as text, Remove and Clear All by generation, '
  + 'Start with the page selection, a refused choice kept on screen, starting, unavailable and ended states with Retry and Continue Offline '
  + '(offline DOM model; rendered layout, focus and the real bridge are in the rendered harness)');
