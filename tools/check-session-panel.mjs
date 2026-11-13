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

// A Content session's limits: shown only for Content, drawn from native's
// values and bounds, checked here as native checks them, and sent with Start.
const limits = (request = 256, response = 512, media = false) => ({
  request_content_budget_mib: {value: request, min: 1, max: 4096, default: 256},
  response_body_budget_mib: {value: response, min: 1, max: 16384, default: 512},
  response_media: {value: media, default: false}});
const field = id => panel.querySelector(`#session-panel-${id}`);
const type = (id, value) => { field(id).value = value; field(id).dispatchEvent(new window.Event('input')); };
push({panel: 'hidden'});
answer = () => ({ok: true});
push(choose({state: 'empty', generation: 5, limit: 8, items: []}, {limits: limits()}));
for (const phrase of ['Content limits', 'Request content budget', 'Response body budget', 'Capture media and fonts',
  'How much of the request bodies and full URLs this session keeps, counting identical content once.',
  'Past it, later ones are listed but not kept. 1 to 4,096 MiB; default 256 MiB.',
  'Past it, later bodies are listed but not kept. 1 to 16,384 MiB; default 512 MiB.',
  'Also keep the images, audio, video and fonts that pages load. They count against the response body budget.',
  'Both budgets stay on this Mac with the session and can use that much disk.']) {
  assert(text().includes(phrase), `the Content limits say: ${phrase}`);
}
assert.equal(field('request-budget').value, '256', 'native’s default request content budget');
assert.equal(field('response-budget').value, '512', 'native’s default response body budget');
assert.equal(field('media').checked, false, 'media and fonts are skipped by default');
assert.equal(panel.querySelector('label[for="session-panel-request-budget"]').textContent, 'Request content budget');
assert.equal(field('request-budget').getAttribute('aria-describedby'), 'session-panel-request-budget-detail');
assert.deepEqual([...panel.querySelectorAll('input[type="checkbox"]')].map(box => box.id), ['session-panel-media'],
  'the media choice is the only checkbox');
assert(!/keychain/i.test(text()), 'the limits name no Keychain choice');
// Metadata keeps no content, so it shows and sends none of the limits.
radio('metadata').checked = true;
radio('metadata').dispatchEvent(new window.Event('change'));
assert.equal(field('request-budget'), null, 'Metadata shows no request content budget');
assert.equal(field('media'), null, 'Metadata shows no media choice');
assert(!text().includes('Content limits'));
buttonNamed('Start Session').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'metadata'}, 'a Metadata start names no limit');
radio('content').checked = true;
radio('content').dispatchEvent(new window.Event('change'));
assert.equal(field('request-budget').value, '256', 'the limits come back with Content');
buttonNamed('Start Session').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'content', request_content_budget_mib: 256,
  response_body_budget_mib: 512, response_media: false}, 'a Content start sends the default limits as numbers');
// A raised budget and media capture, typed and kept across a native redraw.
type('request-budget', ' 1024 ');
type('response-budget', '16384');
field('media').checked = true;
field('media').dispatchEvent(new window.Event('change'));
push(choose({state: 'empty', generation: 6, limit: 8, items: []}, {limits: limits()}));
assert.equal(field('request-budget').value, ' 1024 ', 'a redraw keeps the typed budget');
assert.equal(field('media').checked, true, 'a redraw keeps the media choice');
buttonNamed('Start Session').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'content', request_content_budget_mib: 1024,
  response_body_budget_mib: 16384, response_media: true}, 'a raised budget and media capture are sent');
// Out of bounds: named at the field, and nothing is sent.
for (const [id, value, rule] of [
  ['request-budget', '4097', 'Request content budget must be a whole number from 1 to 4096 MiB.'],
  ['request-budget', '0', 'Request content budget must be a whole number from 1 to 4096 MiB.'],
  ['request-budget', '12.5', 'Request content budget must be a whole number from 1 to 4096 MiB.'],
  ['request-budget', '', 'Request content budget must be a whole number from 1 to 4096 MiB.'],
  ['request-budget', '-5', 'Request content budget must be a whole number from 1 to 4096 MiB.'],
  ['response-budget', '16385', 'Response body budget must be a whole number from 1 to 16384 MiB.'],
  ['response-budget', '1e3', 'Response body budget must be a whole number from 1 to 16384 MiB.'],
]) {
  type('request-budget', '256');
  type('response-budget', '512');
  type(id, value);
  const sent = posted.length;
  buttonNamed('Start Session').click();
  await settle();
  assert.equal(posted.length, sent, `${id} ${JSON.stringify(value)} starts nothing`);
  const error = panel.querySelector(`#session-panel-${id}-error`);
  assert.equal(error?.textContent, rule, `${id} ${JSON.stringify(value)} names the rule`);
  assert.equal(error.getAttribute('role'), 'alert');
  assert.equal(field(id).getAttribute('aria-invalid'), 'true');
  assert.equal(field(id).getAttribute('aria-describedby'), `session-panel-${id}-error session-panel-${id}-detail`);
  assert.equal(panel.dataset.state, 'choose', 'the decision stays open');
}
// Fixing the value removes the error at once; Return in the field starts.
type('response-budget', '2048');
assert.equal(panel.querySelector('#session-panel-response-budget-error'), null, 'a fixed value clears its error');
assert.equal(field('response-budget').getAttribute('aria-invalid'), null);
const enter = new window.Event('keydown');
enter.key = 'Enter';
field('response-budget').dispatchEvent(enter);
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'content', request_content_budget_mib: 256,
  response_body_budget_mib: 2048, response_media: true}, 'Return in a budget starts with the shown limits');
// Native's own refusal of a value stays on screen with its reason.
answer = () => new Error('Request content budget must be a whole number from 1 to 4096 MiB.');
buttonNamed('Start Session').click();
await settle();
assert(panel.querySelector('[role="alert"]')?.textContent.includes('Request content budget must be a whole number'), text());
assert.equal(panel.dataset.state, 'choose');
answer = () => ({ok: true});
// A new decision starts again from native's values.
push({panel: 'hidden'});
push(choose({state: 'empty', generation: 7, limit: 8, items: []}, {limits: limits(64, 128, true)}));
assert.equal(field('request-budget').value, '64');
assert.equal(field('response-budget').value, '128');
assert.equal(field('media').checked, true);
assert.equal(panel.querySelector('.session-panel-limit-error'), null);
// An inherited opt-out preselects Metadata, and the panel says why beside the mode.
push({panel: 'hidden'});
push(choose({state: 'empty', generation: 8, limit: 8, items: []}, {mode: 'metadata', limits: limits(),
  modeNote: 'Metadata is preselected because REB_CAPTURE_REQUEST_CONTENT=0 is set.'}));
assert.equal(radio('metadata').checked, true, 'the opt-out preselects Metadata');
const modeNote = panel.querySelector('#session-panel-mode-note');
assert.equal(modeNote?.textContent, 'Metadata is preselected because REB_CAPTURE_REQUEST_CONTENT=0 is set.');
assert(modeNote.closest('.session-panel-modes'), 'the note sits with the mode control');
assert.equal(panel.querySelector('.session-panel-modes').getAttribute('aria-describedby'), 'session-panel-mode-note');
buttonNamed('Start Session').click();
await settle();
assert.deepEqual(posted.at(-1), {op: 'start', mode: 'metadata'}, 'Start without touching the mode starts Metadata');
push({panel: 'hidden'});
push(choose({state: 'empty', generation: 9, limit: 8, items: []}, {limits: limits()}));
assert.equal(panel.querySelector('#session-panel-mode-note'), null, 'no note when nothing preselected the mode');
// Starting and failed sessions name the limits they run with.
push({panel: 'starting', mode: 'content', modes, limits: limits(1024, 2048, true)});
assert(text().includes('Capture mode: Content (default). Request content budget 1,024 MiB, response body budget 2,048 MiB, media and fonts kept.'), text());
push({panel: 'failed', mode: 'content', modes, limits: limits(1024, 2048, false),
  failure: {title: 'Live session unavailable', message: 'Brave stopped.', afterStartup: false}});
assert(text().includes('Retry starts a new session with the same capture mode: Content (default). Same limits: request content budget 1,024 MiB, response body budget 2,048 MiB, media and fonts skipped.'), text());
push({panel: 'failed', mode: 'content', modes,
  failure: {title: 'Live session unavailable', message: 'Brave stopped.', afterStartup: false}});
assert(!text().includes('Same limits'), 'a session the panel did not start names no limits');

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
// A start is accepted only through LivePanelStart.parse, whose rules (the mode,
// Content limits checked as the agent path checks them, none on Metadata, no
// other key) tools/check-live-session-failure.swift runs.
assert(!/body\["keychain"\]/.test(native), 'native reads no Keychain value from the page');
assert.match(native, /if let modeNote \{ value\["modeNote"\] = modeNote \}/, 'native publishes why the mode is preselected');
const startCase = native.slice(native.indexOf('case "start":'), native.indexOf('case "retry":'));
assert.match(startCase, /switch LivePanelStart\.parse\(body\)/, 'native parses a start with the shared rules');
assert.match(startCase, /accept\(\.start\(start\.mode, start\.limits\)\)/, 'native starts with the parsed choice only');
assert.doesNotMatch(startCase, /body\[/, 'the start case reads nothing from the page but through the parser');
const coordinator = readFileSync(new URL('../apps/research-ui/macos/LiveSessionCoordinator.swift', import.meta.url), 'utf8');
assert.match(coordinator, /isSubset\(of: \["op", "mode"\] \+ ContentLimits\.keys\)/, 'the parser refuses any other key');
// One set of bounds and defaults: the app, the agent path and the launcher.
const agent = readFileSync(new URL('../apps/origin-trace-backend/src/session_launch.rs', import.meta.url), 'utf8');
const launcher = readFileSync(new URL('../scripts/run-live-session.sh', import.meta.url), 'utf8');
assert.match(coordinator, /requestContentBudgetRange: ClosedRange<UInt32> = 1\.\.\.4096/);
assert.match(coordinator, /responseBodyBudgetRange: ClosedRange<UInt32> = 1\.\.\.16384/);
assert.match(coordinator, /ContentLimits\(requestContentBudgetMiB: 256, responseBodyBudgetMiB: 512, responseMedia: false\)/);
assert.match(coordinator, /static let keys = \["request_content_budget_mib", "response_body_budget_mib", "response_media"\]/);
assert.match(agent, /\(1\.\.=4096\)\.contains\(&budget\)/);
assert.match(agent, /\(1\.\.=16384\)\.contains\(&budget\)/);
assert.match(agent, /request_content_budget_mib\.unwrap_or\(256\)/);
assert.match(agent, /response_body_budget_mib\.unwrap_or\(512\)/);
assert.match(launcher, /REB_REQUEST_CONTENT_BUDGET_MIB:-256\}/);
assert.match(launcher, /REB_RESPONSE_BODY_BUDGET_MIB:-512\}/);
assert.match(launcher, /request_content_budget_mib > 4096/);
assert.match(launcher, /response_body_budget_mib > 16384/);
console.log('PASS session panel: start choices with the alert’s wording, no Keychain option, saved sites as text, Remove and Clear All by generation, '
  + 'Start with the page selection, a refused choice kept on screen, starting, unavailable and ended states with Retry and Continue Offline, '
  + 'Content limits only for Content with defaults, raised values, out-of-bounds refusals that send nothing, and the app, agent and launcher bounds in step '
  + '(offline DOM model; rendered layout, focus and the real bridge are in the rendered harness)');
