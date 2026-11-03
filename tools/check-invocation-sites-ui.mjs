// Track calls to a function: the production invocation_sites.js module with
// only DOM leaves and fetch faked. Byte offsets are checked against the shared
// site fixture the backend and the Python tool read, and the app.js wiring is
// checked for the original-view rule and the shipped asset lists.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {fakeDocument} from './check-command-palette.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const read = path => readFile(join(root, path), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const module = await read('apps/research-ui/invocation_sites.js');

function load(context = {}) {
  return runInNewContext(`${module}\n;({INVOCATION_SITE_LIMIT, invocationSiteByteOffset, invocationSiteHeader, createInvocationSitesPanel})`,
    {TextEncoder, ...context});
}

// The UI's byte offset of a `(` equals the site byte_offset the backend and
// tools/native-js-invocation-site.py compute for the same artifact bytes.
{
  const model = load();
  const fixture = JSON.parse(await read('tools/fixtures/native-js-invocation/site-cases.json'));
  let checked = 0;
  for (const item of fixture.cases.filter(item => item.site && item.source)) {
    // Sources decodes with the BOM kept, so the BOM is a character of the text.
    const text = item.source;
    const offset = [...Array(text.length).keys()].find(index =>
      new TextEncoder().encode(text.slice(0, index)).length === item.byte_offset);
    assert.equal(model.invocationSiteByteOffset(text, offset), item.site.byte_offset, item.name);
    checked++;
  }
  assert(checked >= 6);
  const astral = 'a=\u{1F600}(b)';
  assert.equal(model.invocationSiteByteOffset(astral, 3), null, 'Never between the halves of a surrogate pair');
  assert.equal(model.invocationSiteByteOffset(astral, astral.length), null);
  assert.equal(model.invocationSiteByteOffset(astral, 1, 1), null, 'Never past the retained text');
  assert.equal(model.invocationSiteByteOffset(astral, -1), null);
  console.log(`PASS invocation site positions: UTF-16 Sources positions convert to the shared fixture's UTF-8 byte offsets (${checked} cases), surrogate halves and positions past the text refused`);
}

const site = (label, extra = {}) => ({site: {anchor_offset: label.length, artifact_id: '7', artifact_sha256: 'a'.repeat(64), byte_offset: label.length,
  shape: 'function-entry', source_length: 99, source_sha256: 'b'.repeat(64)}, label, source_url: 'https://example.test/glue.js', session_id: '11',
  retained: {state: 'not_retained', matching_artifact_id: null, other_version_artifact_id: null}, ...extra});
const set = (sites, session = {state: 'not_armed', count: 0, digests: false, sites: []}) =>
  ({format: 'reb-js-invocation-site-set-v1', limit: 8, count: sites.length, sites, next_capture: 'x', session});

{
  const {invocationSiteHeader} = load();
  assert.equal(invocationSiteHeader(set([])), null, 'Nothing to say without sites');
  const armed = invocationSiteHeader(set([site('window.hsw')], {state: 'armed', count: 2, digests: true, sites: [{label: 'window.hsw'}, {label: 'f'}]}));
  assert.equal(armed.text, 'Tracking 2 functions · value digests');
  assert.match(armed.title, /window\.hsw, f/);
  assert.match(armed.title, /sensitive capture/);
  const one = invocationSiteHeader(set([], {state: 'armed', count: 1, digests: false, sites: [{label: 'hsw'}]}));
  assert.equal(one.text, 'Tracking 1 function');
  const old = invocationSiteHeader(set([site('hsw')], {state: 'browser_unsupported', count: 1, digests: false, sites: [{label: 'hsw'}]}));
  assert.equal(old.text, 'Not tracking 1 saved function');
  assert.equal(old.kind, 'warning');
  assert.match(old.title, /does not define invocation capture/);
  const saved = invocationSiteHeader(set([site('a'), site('b')]));
  assert.equal(saved.text, '2 functions saved for the next capture');
  const stale = invocationSiteHeader(set([site('a', {retained: {state: 'other_version', matching_artifact_id: null, other_version_artifact_id: '9'}})],
    {state: 'armed', count: 1, digests: false, sites: [{label: 'a'}]}));
  assert.equal(stale.text, 'Tracking 1 function · 1 will not match');
  assert.equal(stale.kind, 'warning');
  console.log('PASS invocation site header: armed, digests, unsupported Brave, saved-only and stale script versions');
}

function panel({protocol = 'http:', responses, source = {source_type: 'artifact', kind: 'javascript', session_id: '11', artifact_id: '7'},
  position = {byteOffset: 42, line: 3, column: 4}, positionProblem = () => ''} = {}) {
  const {document, create, fire} = fakeDocument();
  const requests = [];
  const fetcher = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({path, body});
    const reply = responses(path, body);
    if (reply instanceof Error) throw reply;
    return {ok: reply.status < 400, status: reply.status, json: async () => reply.body};
  };
  const container = create('div', 'invocation-sites-panel'), chip = create('button', 'invocation-tracking'), track = create('button', 'source-track-calls');
  const revealed = [], shown = [];
  const context = {document, TextEncoder};
  runInNewContext(module, context);
  const ui = context.createInvocationSitesPanel({root: container, chip, trackButton: track, fetcher, protocol,
    getSource: () => source, positionProblem, getPosition: () => position,
    onReveal: candidate => revealed.push(candidate), onShow: () => shown.push(true)});
  const byAction = name => container.all.find(element => element.dataset?.invocationAction === name);
  const text = () => container.textContent;
  return {ui, document, fire, container, chip, track, requests, revealed, shown, byAction, text};
}

const hostile = '<img src=x onerror=alert(1)>window.hsw=function(';
const candidate = (line, offset, extra = {}) => ({byte_offset: offset, start_byte: offset - 8, line, column: 5, kind: 'function',
  binding: 'o.dup', context: hostile, supported: true, refusal: null, ...extra});
const resolution = extra => ({format: 'reb-js-invocation-site-resolution-v1', status: 'refused', reason: 'ambiguous', message: '2 function definitions bind o.dup. Choose one by its position; nothing was guessed.',
  function: null, candidates: [], candidate_relation: 'matches', candidate_count: 2, candidates_truncated: false, site: null, label: null, saved: false, ...extra});

{
  let current = set([]);
  const view = panel({responses: (path, body) => {
    if (!body) return {status: 200, body: current};
    if (body.action === 'add' && body.name === 'o.dup') return {status: 200, body: {ok: true, added: false, set: current,
      resolution: resolution({candidates: [candidate(2, 10), candidate(4, 30, {supported: false, refusal: 'Generators and async generators are never armed.'})]})}};
    if (body.action === 'add') {
      current = set([site(body.label ?? 'window.hsw')]);
      return {status: 200, body: {ok: true, added: true, set: current, resolution: resolution({status: 'resolved', reason: null, label: body.label ?? 'window.hsw',
        function: candidate(1, body.byte_offset ?? 20), candidates: [], candidate_count: 0, message: 'Resolved.'})}};
    }
    if (body.action === 'remove') { current = set([]); return {status: 200, body: {ok: true, removed: true, set: current}}; }
    if (body.action === 'clear') { current = set([]); return {status: 200, body: {ok: true, cleared: 1, set: current}}; }
    throw new Error('unexpected');
  }});
  await view.ui.refresh();
  assert.equal(view.chip.hidden, true, 'No chip without saved or armed sites');
  assert.match(view.text(), /not the open page/);
  assert.match(view.text(), /Saved for the next capture \(0 of 8\)/);
  // Keyboard: Enter in the name field resolves the name.
  view.ui.input.value = 'o.dup';
  const enter = view.fire(view.ui.input, 'keydown', {key: 'Enter'});
  assert.equal(enter.defaultPrevented, true);
  await settle(); await settle();
  assert.deepEqual(view.requests.at(-1).body, {action: 'add', session_id: '11', artifact_id: '7', name: 'o.dup'});
  assert.match(view.text(), /2 function definitions bind o\.dup/);
  const contexts = view.container.all.filter(element => element.className === 'invocation-site-context');
  assert.equal(contexts.length, 2);
  for (const context of contexts) {
    assert.equal(context.textContent, hostile, 'Captured context is text');
    assert.equal(context.children.length, 0, 'Captured context never becomes elements');
  }
  assert.match(view.text(), /Generators and async generators are never armed/);
  // The supported candidate can be tracked by its exact offset; the other cannot.
  const tracks = view.container.all.filter(element => element.dataset?.invocationAction === 'track-candidate');
  assert.equal(tracks.length, 1);
  view.fire(view.container.all.find(element => element.tagName === 'BUTTON' && element.textContent === 'Show'), 'click');
  assert.equal(view.revealed[0].line, 2);
  view.fire(tracks[0], 'click');
  await settle(); await settle();
  assert.deepEqual(view.requests.at(-1).body, {action: 'add', session_id: '11', artifact_id: '7', byte_offset: 10, label: 'o.dup'});
  assert.match(view.text(), /Saved o\.dup .*not the open page/);
  assert.equal(view.chip.hidden, false);
  assert.equal(view.chip.textContent, '1 function saved for the next capture');
  // The toolbar action sends the current position as an artifact byte offset.
  view.fire(view.track, 'click');
  await settle(); await settle();
  assert.equal(view.shown.length, 1, 'The action opens the tracking pane');
  assert.equal(view.requests.at(-1).body.byte_offset, 42);
  // Remove is labeled per site; clear asks for a second, explicit choice.
  const remove = view.container.all.find(element => element.getAttribute?.('aria-label')?.startsWith('Remove '));
  assert(remove);
  view.fire(remove, 'click');
  await settle(); await settle();
  assert.equal(view.requests.at(-1).body.action, 'remove');
  current = set([site('a')]);
  await view.ui.refresh();
  const clear = view.byAction('clear');
  view.fire(clear, 'click');
  assert.equal(clear.textContent, 'Confirm clear');
  assert.notEqual(view.requests.at(-1).body?.action, 'clear', 'The first click clears nothing');
  view.fire(clear, 'click');
  await settle(); await settle();
  assert.deepEqual(view.requests.at(-1).body, {action: 'clear', confirm: true});
  assert.match(view.text(), /Cleared 1 saved function/);
  assert(!/innerHTML|insertAdjacentHTML|outerHTML/.test(module), 'The module inserts captured text as text only');
  console.log('PASS invocation site pane: Enter resolves a name, refusals list inert candidates, candidates and the toolbar save exact offsets, remove and confirmed clear');
}

{
  // A failed refresh keeps the last understandable set and says so.
  let fail = false;
  const view = panel({responses: path => fail ? new Error('Connection refused') : {status: 200, body: set([site('kept')])}});
  await view.ui.refresh();
  fail = true;
  await view.ui.refresh();
  assert.match(view.text(), /kept/);
  assert.match(view.text(), /Connection refused\. The list below is from the last successful read\./);
  // Errors from the server are shown as given, such as a full set.
  fail = false;
  const full = panel({responses: (path, body) => body ? {status: 409, body: {error: 'The saved set already tracks 8 functions, the most one capture can arm. Remove one first.'}} : {status: 200, body: set([])}});
  await full.ui.refresh();
  full.ui.input.value = 'hsw';
  full.ui.trackName();
  await settle(); await settle();
  assert.match(full.text(), /already tracks 8 functions/);
  // A non-artifact source and a non-original view say why the action is off.
  const derived = panel({responses: () => ({status: 200, body: set([])}), positionProblem: () => 'Switch to the original source view to track a function at a position.'});
  await derived.ui.refresh();
  assert.equal(derived.track.disabled, true);
  assert.match(derived.track.title, /original source view/);
  const lossy = panel({responses: () => ({status: 200, body: set([])}), source: {source_type: 'artifact', kind: 'javascript', session_id: '1', artifact_id: '2', contentLossy: true}});
  await lossy.ui.refresh();
  assert.match(lossy.track.title, /not strict UTF-8/);
  // Stored-evidence native mode has no backend: nothing is fetched or offered.
  const offline = panel({protocol: 'reb:', responses: () => { throw new Error('No request may be sent'); }});
  await offline.ui.refresh();
  assert.equal(offline.requests.length, 0);
  assert.equal(offline.chip.hidden, true);
  assert.equal(offline.ui.input.disabled, true);
  assert.equal(offline.track.disabled, true);
  assert.match(offline.text(), /unavailable in stored-evidence native mode/);
  console.log('PASS invocation site pane: failed refresh keeps the last list, server refusals shown, original-view and strict UTF-8 rules, offline native mode sends nothing');
}

{
  // app.js derives the position only from the original view, and every
  // shipped asset list carries the module before app.js.
  const app = await read('apps/research-ui/app.js');
  const rule = app.slice(app.indexOf('function invocationSitePositionProblem()'), app.indexOf('function invocationSitePosition()'));
  assert.match(rule, /state\.sourceWasm \|\| state\.sourceDeobfuscated \|\| state\.sourceFormatted/);
  const html = await read('apps/research-ui/index.html');
  assert(html.indexOf('src="invocation_sites.js"') > 0 && html.indexOf('src="invocation_sites.js"') < html.indexOf('src="app.js"'));
  for (const id of ['invocation-tracking', 'source-track-calls', 'invocation-sites-details', 'invocation-sites-panel']) assert(html.includes(`id="${id}"`), id);
  for (const path of ['scripts/build-research-app.sh', 'apps/research-ui/macos/OriginTraceApp.swift', 'apps/origin-trace-backend/src/app.rs']) {
    assert((await read(path)).includes('invocation_sites.js'), `${path} ships invocation_sites.js`);
  }
  console.log('PASS invocation site wiring: original-view rule, header chip, toolbar action and pane markup, module shipped by the app, packager and backend');
}
