#!/usr/bin/env node
// In-app agent dock against the shipped scripts in an offline DOM model: the
// safe markdown subset, citation validation, byte budgets and the panel states,
// with a stand-in for the LangGraph runtime. Not rendered QA. The bundled graph
// is tools/check-agent-runtime.mjs, native is tools/check-agent-core.swift and
// the packaged app path is test24 in the rendered harness.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

export async function checkAgentPanel() {
  const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
  const {window, context, asyncErrors, release} = loadShippedUi();
  const model = runInContext('RebAgentModel', context);
  // Values cross the VM realm boundary, so structural checks copy them first.
  const copy = value => JSON.parse(JSON.stringify(value));

  // Captured and model text stays inert: raw HTML is not a block type.
  const hostile = '<img src=x onerror=alert(1)> **bold** `code` [cite session=9 artifact=5 offset=12]';
  const blocks = model.parseMarkdown(hostile);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].inline[0].text, '<img src=x onerror=alert(1)> ');
  assert.deepEqual(copy(blocks[0].inline.map(token => token.type)), ['text', 'strong', 'text', 'code', 'text', 'cite']);
  assert.equal(blocks[0].inline[5].fields.offset, '12');
  const fenced = model.parseMarkdown('Before\n```js\nalert("<b>x</b>")\n```\n- one\n- two');
  assert.deepEqual(copy(fenced.map(block => block.type)), ['paragraph', 'code', 'list']);
  assert.equal(fenced[1].lang, 'js');
  assert.equal(fenced[1].text, 'alert("<b>x</b>")');
  assert.equal(fenced[2].items.length, 2);

  // Only the exact token forms become citations.
  assert.deepEqual({...model.parseCitation('session=9 artifact=5 offset=12')}, {session: '9', artifact: '5', offset: '12'});
  assert.deepEqual({...model.parseCitation('session=9 process=1 sequence=4')}, {session: '9', process: '1', sequence: '4'});
  for (const bad of ['session=9', 'artifact=5', 'session=9 artifact=5 sequence=1', 'session=9 process=1 sequence=4 offset=2',
    'session=x artifact=5', 'session=9 artifact=5 unknown=1', 'session=9 session=9 artifact=5']) {
    assert.equal(model.parseCitation(bad), null, bad);
  }

  const artifact = {session_id: '9', artifact_id: '5', byte_size: 100, sha256: 'a'.repeat(64), kind: 'javascript'};
  const event = {session_id: '9', process_id: '1', sequence_number: '4', type: 'request_started'};
  const noFetch = {artifacts: [artifact], events: [event], fetchArtifact: async () => [], fetchEvents: async () => []};
  assert.equal((await model.verifyCitation({session: '9', artifact: '5', offset: '100'}, noFetch)).status, 'verified');
  assert.equal((await model.verifyCitation({session: '9', artifact: '5', offset: '101'}, noFetch)).reason, 'offset out of range');
  assert.equal((await model.verifyCitation({session: '9', artifact: '6'}, noFetch)).status, 'unverified', 'an invented artifact stays unverified');
  assert.equal((await model.verifyCitation({session: '8', artifact: '5'}, noFetch)).status, 'unverified', 'the wrong session is not a match');
  assert.equal((await model.verifyCitation({session: '9', process: '1', sequence: '4'}, noFetch)).kind, 'event');
  assert.equal((await model.verifyCitation({session: '9', process: '1', sequence: '5'}, noFetch)).status, 'unverified');
  const fetched = await model.verifyCitation({session: '9', artifact: '7'}, {...noFetch, fetchArtifact: async () => [{...artifact, artifact_id: '7'}]});
  assert.equal(fetched.status, 'verified', 'a retained artifact outside the window is found through the API');

  // Pins are cut on a character boundary and say so.
  const clipped = model.clipPin('é'.repeat(100), 21);
  assert.equal(clipped.text, 'é'.repeat(10));
  assert.equal(clipped.truncated, true);
  assert.equal(clipped.totalBytes, 200);
  assert.equal(model.clipPin('short', 21).truncated, false);

  // The web view keeps a byte budget and always keeps the row being streamed.
  const log = model.createTranscriptModel(4096);
  log.add({id: 'old', role: 'tool', result: 'x'.repeat(4000)});
  log.add({id: 'next', role: 'notice', text: 'y'.repeat(4000)});
  const stats = log.stats();
  assert.equal(stats.droppedRows, 1, 'the oldest row leaves first');
  assert.equal(log.rows()[0].id, 'next');
  assert.ok(stats.bytes <= 2 * 4096 + 512);
  log.appendText('next', 'z'.repeat(4000));
  assert.equal(log.get('next').text.length, 8000, 'a streaming row is not evicted');

  // Permission levels: never remembered above Ask for actions.
  assert.deepEqual(copy(model.PERMISSIONS.map(level => level.id)), ['read-only', 'ask', 'auto', 'full']);
  for (const [stored, remembered] of [['full', 'ask'], ['auto', 'ask'], ['ask', 'ask'], ['read-only', 'read-only'], [null, 'read-only'], ['everything', 'read-only']]) {
    assert.equal(model.rememberable(stored), remembered, `remembered ${stored}`);
  }

  // Panel states through the shipped controller and a fake native bridge.
  const posted = [];
  // Consent in the dock is the only confirmation. Native checks what enable
  // carries, as AgentPermission.requested does, and this fake refuses the same.
  const levelsNative = ['read-only', 'ask', 'auto', 'full'];
  let engine = {type: 'status', phase: 'off', running: false, childRunning: false, tools: [], provider: null, model: null, effects: false};
  // Later the native side reports subscriptions too, as AgentBridge.status does.
  let subscriptions = false, standIn = true, grokSignedIn = false, chatgptSignedIn = false;
  const status = () => ({available: true, reason: '', standIn,
    providers: [{id: 'claude', label: 'Claude', vendor: 'Anthropic', defaultModel: 'claude-opus-5-5', hasKey: true},
      {id: 'chatgpt', label: 'ChatGPT', vendor: 'OpenAI', defaultModel: 'gpt-6-astra', hasKey: true,
        ...(subscriptions ? {supportsKey: true, subscriptionModel: 'gpt-6-astra', subscription: {kind: 'oauth', available: true, signedIn: chatgptSignedIn}} : {})},
      ...(subscriptions ? [{id: 'grok', label: 'Grok', vendor: 'xAI', defaultModel: 'default', subscriptionModel: 'default', supportsKey: false,
        hasKey: false, subscription: {kind: 'cli', available: true, cli: 'grok'}}] : [])], engine});
  context.__agentPost = message => {
    posted.push(message);
    if (message.op === 'enable') {
      const cli = message.auth === 'subscription' && message.provider !== 'chatgpt';
      const permission = message.permission;
      if (!levelsNative.includes(permission)) return Promise.reject(new Error('Choose a permission level to turn the agent on.'));
      if (typeof message.sensitive !== 'boolean' || (message.sensitive && permission !== 'full')) {
        return Promise.reject(new Error('Sensitive capture options belong to Full access.'));
      }
      engine = {...engine, phase: 'ready', childRunning: !cli, provider: message.provider, model: message.model || 'claude-opus-5-5',
        auth: message.auth, loop: cli ? 'cli' : 'langgraph', cliRunning: false, permission, sensitive: permission === 'full' && message.sensitive === true,
        tools: [{name: 'get_events', readOnly: true, needsApproval: false}]};
      return Promise.resolve({...status(), tools: [{name: 'get_events', description: 'Read', schema: {type: 'object'}, readOnly: true, needsApproval: false}]});
    }
    if (message.op === 'lowerPermission') {
      engine = {...engine, permission: message.permission, sensitive: false};
      return Promise.resolve({...status(), tools: [{name: 'get_events', description: 'Read', schema: {type: 'object'}, readOnly: true, needsApproval: false}]});
    }
    if (message.op === 'subscriptionStatus') {
      return Promise.resolve(grokSignedIn ? {kind: 'cli', available: true, signedIn: true, cli: 'grok'}
        : {kind: 'cli', available: true, signedIn: false, cli: 'grok', reason: 'The Grok CLI is not signed in.'});
    }
    if (message.op === 'subscriptionSignIn') { chatgptSignedIn = true; return Promise.resolve({signedIn: true, sharing: true}); }
    if (message.op === 'cliSend' || message.op === 'cliCancel') return Promise.resolve({ok: true});
    if (message.op === 'cliDecide') return Promise.resolve({waiting: true});
    if (message.op === 'disable') { engine = {...engine, phase: 'off', childRunning: false}; return Promise.resolve(status()); }
    if (message.op === 'turn' || message.op === 'transcriptAppend') return Promise.resolve({ok: true});
    if (message.op === 'transcript') return Promise.resolve({rows: [], before: null});
    if (message.op === 'models') {
      const models = {'claude:key': ['claude-opus-5-5', 'claude-sonnet-5-5'], 'chatgpt:key': ['gpt-6-astra'], 'chatgpt:subscription': ['gpt-6-astra']}[`${message.provider}:${message.auth}`] ?? ['default'];
      return Promise.resolve({models, defaultModel: models[0], fromProvider: true});
    }
    if (message.op === 'clearTranscript') return Promise.resolve({ok: true});
    return Promise.resolve(status());
  };
  // The panel drives the graph through this interface; the real one is bundled.
  const runtimeCalls = [];
  context.__runtimeCalls = runtimeCalls;
  runInContext(`const fakeRuntime = {createAgentRuntime(options) {
      __runtimeCalls.push({op: 'create', provider: options.provider, model: options.model, tools: options.tools.map(tool => tool.name),
        permission: options.permission, sensitive: options.sensitive});
      globalThis.__runtimeEmit = options.emit;
      return {running: false, send(turn) { __runtimeCalls.push({op: 'send', text: turn.text}); return Promise.resolve(); },
        setPermission(next) { __runtimeCalls.push({op: 'setPermission', permission: next.permission, tools: next.tools.length}); },
        decide(callId, allow) { __runtimeCalls.push({op: 'decide', callId, allow}); return true; },
        cancel() { __runtimeCalls.push({op: 'cancel'}); }, dispose() { __runtimeCalls.push({op: 'dispose'}); }};
    }};
    globalThis.RebAgentRuntimes = {claude: fakeRuntime, chatgpt: fakeRuntime};
    globalThis.webkit = {messageHandlers: {rebAgent: {postMessage: message => __agentPost(message)}}};
    globalThis.fetch = async () => new Response(JSON.stringify({instance_id: '100:200'}), {status: 200});
    globalThis.requestAnimationFrame = callback => { callback(0); return 0; };`, context);
  const doc = window.document;
  const byId = id => doc.getElementById(id);
  const settle = async () => { for (let i = 0; i < 6; i++) await nextTurn(); };
  // The DOM model has no KeyboardEvent; a keydown Event with the same fields reaches the same handlers.
  const press = async (node, key, init = {}) => {
    const event = new window.Event('keydown', {bubbles: true, cancelable: true});
    Object.assign(event, {key, shiftKey: false, isComposing: false, ...init});
    node.dispatchEvent(event);
    await settle();
  };
  const dockState = () => byId('agent-dock').dataset.state;
  const turnOn = async () => { byId('agent-turn-on').click(); await settle(); };
  // Off lives in the header menu now, behind the More button.
  const turnOff = async () => {
    byId('agent-more').click();
    await settle();
    assert.equal(byId('agent-menu').hidden, false, 'More opens the menu');
    byId('agent-turn-off').click();
    await settle();
  };
  assert.equal(byId('agent-dock').hidden, true, 'the dock is closed by default');
  assert.equal(posted.length, 0, 'nothing is asked of native while closed');

  byId('agent-toggle').click();
  await settle();
  assert.equal(byId('agent-dock').hidden, false);
  assert.equal(dockState(), 'off');
  assert.match(byId('agent-surface').textContent, /The agent is off/);
  assert.equal(byId('agent-status').textContent, 'Off', 'the header chip says the agent is off');
  assert.equal(byId('agent-composer').hidden, true, 'the composer waits until the agent is on');
  assert.equal(byId('agent-send').disabled, true);
  assert.equal(byId('agent-new').disabled, true, 'there is no conversation to start over while off');
  // Each provider is a card with its own readiness, without asking any CLI.
  const cards = [...doc.querySelectorAll('[data-provider]')].map(node => node.dataset.provider);
  assert.deepEqual(copy(cards), ['claude', 'chatgpt']);
  assert.equal(doc.querySelector('[data-provider="claude"]').getAttribute('aria-pressed'), 'true');
  assert.match(byId('agent-account-text').textContent, /Local stand-in provider/);
  assert.match(doc.querySelector('.agent-leaves').textContent, /Nothing leaves this Mac/, 'the setup state says what leaves, once');

  // The model is chosen in the setup card; the list holds only that provider's models.
  byId('agent-setup-model').click();
  await settle();
  const picker = byId('agent-picker');
  assert.equal(picker.hidden, false, 'the model button opens the picker');
  assert.equal(byId('agent-setup-model').getAttribute('aria-expanded'), 'true');
  assert.deepEqual(copy([...picker.querySelectorAll('[data-model]')].map(node => node.dataset.model)), ['claude-opus-5-5', 'claude-sonnet-5-5']);
  assert.equal(picker.querySelector('[data-model="claude-opus-5-5"]').getAttribute('aria-checked'), 'true');
  assert.equal(picker.querySelector('[data-model="claude-opus-5-5"]').getAttribute('role'), 'menuitemradio');
  assert.match(picker.querySelector('[data-model="claude-sonnet-5-5"]').textContent, /Claude Sonnet 5\.5/, 'model ids read as names');
  picker.querySelector('[data-model="claude-sonnet-5-5"]').click();
  await settle();
  assert.equal(picker.hidden, true, 'choosing a model closes the picker');
  assert.match(byId('agent-setup-model').textContent, /Claude Sonnet 5\.5/);
  byId('agent-setup-model').click();
  await settle();
  await press(picker, 'Escape');
  assert.equal(picker.hidden, true, 'Escape closes the picker');
  assert.equal(byId('agent-setup-model').getAttribute('aria-expanded'), 'false');
  byId('agent-setup-model').click();
  await settle();
  picker.querySelector('[data-model="claude-opus-5-5"]').click();
  await settle();
  assert.equal(posted.some(message => message.op === 'subscriptionStatus'), false, 'no CLI is asked while only key providers are shown');

  // Turning on requires the explicit disclosure step.
  await turnOn();
  assert.equal(dockState(), 'consent');
  assert.match(byId('agent-surface').textContent, /tool result/i);
  assert.match(byId('agent-surface').textContent, /URLs, hosts/);
  assert.equal(posted.some(message => message.op === 'enable'), false, 'consent comes before enabling');
  const levels = [...doc.querySelectorAll('input[name="agent-permission"]')];
  assert.deepEqual(levels.map(radio => radio.value), ['read-only', 'ask', 'auto', 'full'], 'four levels, lowest first');
  assert.equal(levels.find(radio => radio.checked)?.value, 'read-only', 'Read only is the default');
  assert.equal(byId('agent-permission-warning'), null, 'no warning below Auto-approve');
  assert.equal(byId('agent-consent-accept').textContent, 'Turn on Read only', 'the button names the level');
  const choose = async value => {
    const radio = byId(`agent-level-${value}`);
    radio.checked = true;
    radio.dispatchEvent(new window.Event('change'));
    await settle();
  };
  await choose('ask');
  assert.equal(byId('agent-permission-warning'), null, 'Ask for actions needs no warning');
  assert.equal(byId('agent-consent-accept').textContent, 'Turn on Ask for actions');
  await choose('auto');
  assert.match(byId('agent-permission-warning').textContent, /without asking you first/, 'Auto-approve warns in plain words');
  assert.equal(byId('agent-consent-accept').textContent, 'Turn on Auto-approve actions');
  assert.equal(byId('agent-sensitive'), null, 'the sensitive option belongs to Full access');
  await choose('full');
  const warning = byId('agent-permission-warning').textContent;
  for (const item of model.FULL_LEAVES) assert.ok(warning.includes(item), `Full access lists ${item}`);
  assert.match(warning, /runs its own live capture sessions/);
  assert.match(warning, /go to the local stand-in provider, with captured content/, 'the box says content leaves, never that it stays local');
  assert.doesNotMatch(warning, /stay on this Mac/);
  assert.match(warning, /Also allow sensitive capture options/);
  assert.doesNotMatch(byId('agent-surface').textContent, /once more/, 'no second confirmation is promised');
  assert.equal(byId('agent-sensitive').checked, false, 'sensitive capture stays off unless ticked');
  assert.equal(byId('agent-consent-accept').textContent, 'Turn on Full access', 'the button names the level');
  byId('agent-sensitive').checked = true;
  byId('agent-sensitive').dispatchEvent(new window.Event('change'));
  await choose('ask');
  await choose('full');
  assert.equal(byId('agent-sensitive').checked, false, 'leaving Full access clears the sensitive option');
  await choose('read-only');
  // Cancel goes back without starting anything.
  [...byId('agent-surface').querySelectorAll('button')].find(node => node.textContent === 'Cancel').click();
  await settle();
  assert.equal(dockState(), 'off');
  assert.equal(posted.some(message => message.op === 'enable'), false, 'Cancel starts nothing');
  await turnOn();
  byId('agent-consent-accept').click();
  await settle();
  const enable = posted.find(message => message.op === 'enable');
  assert.equal(enable.permission, 'read-only');
  assert.equal(enable.sensitive, false);
  assert.equal(byId('agent-permission').textContent, 'Read only', 'the header names the running level');
  assert.equal(byId('agent-permission').hidden, false);
  assert.equal(enable.sessionKey, '100:200');
  assert.equal(enable.model, 'claude-opus-5-5', 'the model chosen in the setup card is the one enabled');
  assert.equal(dockState(), 'ready');
  assert.equal(byId('agent-status').textContent, 'Claude Opus 5.5 · Stand-in', 'the chip names the model and how it is paid for');
  assert.match(byId('agent-model').textContent, /Claude Opus 5\.5 · Stand-in/);
  assert.equal(byId('agent-composer').hidden, false);

  // The empty state offers suggestions that fill the composer and never send.
  const suggestion = [...doc.querySelectorAll('.agent-suggestion')].find(node => node.textContent === 'Which hosts did it contact?');
  assert.ok(suggestion, 'the empty state offers suggestions');
  suggestion.click();
  await settle();
  const input = byId('agent-input');
  assert.equal(input.value, 'Which hosts did it contact?');
  assert.equal(runtimeCalls.some(call => call.op === 'send'), false, 'a suggestion is not sent by itself');
  assert.equal(byId('agent-send').disabled, false);

  // A turn: streaming text, a tool row with its result, and inert markup.
  input.value = 'What loaded?';
  input.dispatchEvent(new window.Event('input'));
  byId('agent-send').click();
  await settle();
  assert.deepEqual(copy(runtimeCalls.find(call => call.op === 'create')), {op: 'create', provider: 'claude', model: 'claude-opus-5-5', tools: ['get_events'],
    permission: 'read-only', sensitive: false}, 'the graph is built from the native tool list and level');
  assert.ok(runtimeCalls.some(call => call.op === 'send' && call.text === 'What loaded?'), 'the question goes to the graph');
  assert.ok(posted.some(message => message.op === 'turn' && message.running === true), 'native knows a turn is running');
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'user'), 'the question is kept locally');
  assert.equal(dockState(), 'running');
  assert.equal(byId('agent-send').getAttribute('aria-label'), 'Stop', 'Send becomes Stop while a turn runs');
  const sends = runtimeCalls.filter(call => call.op === 'send').length;
  input.value = 'A second question';
  input.dispatchEvent(new window.Event('input'));
  await press(input, 'Enter');
  assert.equal(runtimeCalls.filter(call => call.op === 'send').length, sends, 'Return while a turn runs sends nothing');
  assert.equal(runtimeCalls.some(call => call.op === 'cancel'), false, 'and does not stop the turn');
  input.value = '';
  input.dispatchEvent(new window.Event('input'));
  const emit = event => runInContext(`__runtimeEmit(${JSON.stringify(event)})`, context);
  emit({type: 'text', rowId: 'a1', turnId: 't', delta: 'Answer <img src=x onerror=alert(1)> [cite session=9 artifact=999]'});
  const fencedSource = 'const a = "<b>x</b>"; // <img src=x onerror=alert(2)>';
  emit({type: 'text', rowId: 'a2', turnId: 't', delta: 'Code:\n```js\n' + fencedSource + '\n```\n'});
  emit({type: 'tool', id: 'tool1', turnId: 't', name: 'get_events', arguments: '{"limit":5}', state: 'running', readOnly: true});
  await settle();
  assert.ok(doc.querySelector('.agent-tool-running .agent-spinner'), 'a running call shows a spinner');
  emit({type: 'tool', id: 'tool1', turnId: 't', name: 'get_events', arguments: '{"limit":5}', state: 'done', result: '{"count":1,"marker":"<b>result</b>"}', resultBytes: 34, isError: false});
  await settle();
  const logNode = byId('agent-log');
  assert.match(logNode.textContent, /get_events/);
  assert.equal(logNode.querySelector('img'), null, 'model markup is never instantiated');
  assert.match(logNode.textContent, /<img src=x onerror=alert\(1\)>/);
  // A call is one collapsed line: state, name, arguments and size. The full
  // result is drawn only while open, and a button opens it from the keyboard.
  const summary = logNode.querySelector('.agent-tool-summary');
  assert.equal(summary.tagName, 'BUTTON', 'a tool line is a button, so Return and Space open it');
  assert.equal(summary.getAttribute('aria-expanded'), 'false', 'tool results start collapsed');
  assert.equal(logNode.querySelector('.agent-tool-detail'), null, 'a collapsed result keeps no rendered body');
  assert.match(summary.textContent, /get_events.*limit=5.*34 B/);
  assert.ok(summary.querySelector('.agent-tool-state-done'));
  const toolNode = logNode.querySelector('.agent-tool');
  summary.click();
  await settle();
  assert.equal(summary.getAttribute('aria-expanded'), 'true');
  const detail = logNode.querySelector('.agent-tool-detail');
  assert.equal(summary.getAttribute('aria-controls'), detail.id);
  assert.match(detail.textContent, /Result sent to the provider · 34 B/);
  assert.match(detail.textContent, /"marker":"<b>result<\/b>"/, 'the full result is shown');
  assert.equal(detail.querySelector('b'), null, 'and stays text');
  assert.equal(logNode.querySelector('.agent-tool'), toolNode, 'opening a result keeps the row node');
  summary.click();
  await settle();
  assert.equal(logNode.querySelector('.agent-tool-detail'), null, 'closing a result drops its body');
  // Fenced code takes the shared code view's colors, and its markup stays text.
  const fencedBody = logNode.querySelector('.agent-code-body');
  assert.equal(fencedBody.textContent, fencedSource);
  assert.ok(['keyword', 'string', 'comment'].every(kind => fencedBody.querySelector(`.syntax-${kind}`)), 'fenced code is colored by the shared lexer');
  assert.ok([...fencedBody.querySelectorAll('*')].every(node => node.tagName === 'SPAN'), 'colored code holds only text spans');
  assert.equal(logNode.querySelector('b'), null, 'markup in fenced code is never instantiated');
  // A streamed reply keeps the blocks it drew; in pieces it must draw what the whole reply does.
  const reply = 'Intro <b>x</b>\nmore\n\n# Head\n- one\n- two\n\n```json\n{"a": [1, "<i>"]}\n```\n1. after\n\n```js\nlet open = 1;';
  for (let at = 0; at < reply.length; at += 7) {
    emit({type: 'text', rowId: 'p1', turnId: 't', delta: reply.slice(at, at + 7)});
    await settle();
  }
  emit({type: 'text', rowId: 'p2', turnId: 't', delta: reply});
  await settle();
  const rowMarkup = id => logNode.querySelector(`[data-row-id="${id}"]`).innerHTML;
  assert.equal(rowMarkup('p1'), rowMarkup('p2'), 'a reply streamed in pieces draws as the whole reply does');
  assert.equal(logNode.querySelector('b, i'), null);
  await settle();
  assert.match(logNode.textContent, /not verified/, 'an invented citation stays labeled plain text');
  assert.equal(logNode.querySelector('.agent-cite'), null);
  assert.ok(logNode.querySelector('.agent-row-user .agent-user-bubble'), 'the question is a bubble');

  // An action waits on an explicit per-call decision with no standing grant.
  emit({type: 'approval', turnId: 't', callId: 'c1', name: 'capture_action', arguments: '{"action":"pause"}'});
  await settle();
  const allow = logNode.querySelector('[data-approve="c1"]');
  assert.equal(allow.textContent, 'Allow once');
  const card = allow.closest('.agent-approval');
  assert.equal(card.getAttribute('role'), 'group');
  assert.equal(card.tabIndex, -1, 'the request can take focus when it appears');
  assert.equal(byId(card.getAttribute('aria-labelledby')).textContent, 'Allow capture_action?');
  assert.ok(logNode.querySelector('.agent-approval .agent-tool-pre .syntax-key'), 'tool arguments are colored as JSON');
  assert.ok(![...logNode.querySelectorAll('button')].some(node => /always/i.test(node.textContent)), 'there is no Always allow');
  allow.click();
  await settle();
  assert.deepEqual(copy(runtimeCalls.find(call => call.op === 'decide')), {op: 'decide', callId: 'c1', allow: true}, 'Allow once resumes the graph');
  assert.match(logNode.querySelector('.agent-approval').textContent, /Allowed once/);
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'tool' && message.row.state === 'done'), 'tool rows are kept locally');
  emit({type: 'turnEnd', turnId: 't', inputTokens: 1200, outputTokens: 34});
  await settle();
  assert.ok(posted.some(message => message.op === 'turn' && message.running === false), 'native knows the turn ended');

  // Counts live in the menu and the tooltip, not the header text.
  assert.doesNotMatch(byId('agent-status').textContent, /tool|token/);
  assert.match(byId('agent-status').title, /1 tool · Read only · last turn 1,200 tokens in, 34 tokens out/);
  byId('agent-more').click();
  await settle();
  const menu = byId('agent-menu');
  assert.equal(menu.getAttribute('role'), 'menu');
  assert.equal(byId('agent-more').getAttribute('aria-expanded'), 'true');
  assert.match(menu.textContent, /1,200 tokens in/);
  assert.ok([...menu.querySelectorAll('[role="menuitem"]')].every(node => node.tabIndex === -1), 'menu items move with the arrow keys, not Tab');
  await press(menu, 'Escape');
  assert.equal(menu.hidden, true, 'Escape closes the menu');
  assert.equal(byId('agent-more').getAttribute('aria-expanded'), 'false');
  // What leaves this Mac is one menu item away.
  byId('agent-more').click();
  await settle();
  byId('agent-menu-info').click();
  await settle();
  const sheet = byId('agent-sheet');
  assert.equal(sheet.hidden, false);
  assert.equal(sheet.getAttribute('role'), 'dialog');
  assert.match(sheet.textContent, /local stand-in provider/);
  assert.match(sheet.textContent, /LangGraph in this window/);
  await press(sheet, 'Escape');
  assert.equal(sheet.hidden, true, 'Escape closes Info');

  // While on, the composer picker shows the running choice; another one
  // turns the agent off and asks again.
  byId('agent-model').click();
  await settle();
  assert.equal(picker.hidden, false);
  assert.equal(picker.querySelector('[data-pick="claude:key"]').getAttribute('aria-checked'), 'true');
  assert.ok(picker.querySelector('[data-pick="chatgpt:key"]'), 'every provider is listed');
  assert.match(picker.textContent, /turns the agent off and asks again/);
  await press(picker, 'Tab');
  assert.equal(picker.hidden, true, 'Tab leaves the picker');

  // A new conversation restarts the same consented choice with no history;
  // the earlier rows stay in the local transcript.
  const enables = posted.filter(message => message.op === 'enable').length;
  const disposes = runtimeCalls.filter(call => call.op === 'dispose').length;
  assert.equal(byId('agent-new').disabled, false);
  byId('agent-new').click();
  await settle();
  const restarted = posted.filter(message => message.op === 'enable');
  assert.equal(restarted.length, enables + 1, 'New conversation enables again');
  assert.deepEqual(copy({...restarted.at(-1), op: undefined}), copy({...enable, op: undefined}), 'with the same provider, model, permission and session');
  assert.equal(runtimeCalls.filter(call => call.op === 'dispose').length, disposes + 1, 'the old graph and its history are dropped');
  assert.equal(posted.some(message => message.op === 'clearTranscript'), false, 'the local transcript is kept');
  assert.equal(doc.querySelectorAll('#agent-log .agent-row').length, 0);
  assert.match(byId('agent-surface').textContent, /Ask about this session/);
  assert.ok([...byId('agent-surface').querySelectorAll('button')].some(node => node.textContent === 'Show earlier rows'), 'earlier rows are one click away');
  // Clear transcript asks first, then deletes the local record and starts fresh.
  emit({type: 'text', rowId: 'n1', turnId: 't2', delta: 'Something new'});
  await settle();
  byId('agent-more').click();
  await settle();
  byId('agent-menu-clear').click();
  await settle();
  assert.equal(sheet.getAttribute('role'), 'alertdialog');
  assert.equal(posted.some(message => message.op === 'clearTranscript'), false, 'clearing asks first');
  byId('agent-clear-confirm').click();
  await settle();
  assert.ok(posted.some(message => message.op === 'clearTranscript'), 'confirmed, the local transcript is cleared');
  assert.equal(posted.filter(message => message.op === 'enable').length, enables + 2);
  assert.doesNotMatch(byId('agent-surface').textContent, /Show earlier rows/);

  // Full access: the consent step turns it on, with nothing asked after it.
  await turnOff();
  await turnOn();
  await choose('full');
  const enablesBefore = posted.filter(message => message.op === 'enable').length;
  byId('agent-sensitive').checked = true;
  byId('agent-sensitive').dispatchEvent(new window.Event('change'));
  byId('agent-consent-accept').click();
  await settle();
  assert.equal(posted.filter(message => message.op === 'enable').length, enablesBefore + 1, 'one enable, straight from consent');
  assert.equal(dockState(), 'ready', 'Full access is on with no further step');
  const full = posted.findLast(message => message.op === 'enable');
  assert.equal(full.permission, 'full');
  assert.equal(full.sensitive, true, 'the sensitive option reaches native only when ticked');
  assert.equal(runtimeCalls.findLast(call => call.op === 'create').permission, 'full', 'the graph builds the Full access prompt');
  const badge = byId('agent-permission');
  assert.equal(badge.textContent, 'Full access');
  assert.equal(badge.dataset.level, 'full');
  assert.equal(window.localStorage.getItem('origin-trace.agent.permission'), 'ask', 'Full access is never remembered');
  // Lower from the menu, without restarting the conversation.
  byId('agent-more').click();
  await settle();
  const visible = id => byId(id) && !byId(id).hidden;
  assert.ok(visible('agent-lower-read-only') && visible('agent-lower-ask') && visible('agent-lower-auto'), 'every lower level is offered');
  assert.equal(visible('agent-raise'), false, 'nothing is above Full access');
  const createdBefore = runtimeCalls.filter(call => call.op === 'create').length;
  byId('agent-lower-ask').click();
  await settle();
  assert.deepEqual(copy(posted.findLast(message => message.op === 'lowerPermission')), {op: 'lowerPermission', permission: 'ask'});
  assert.equal(runtimeCalls.findLast(call => call.op === 'setPermission')?.permission, 'ask', 'the running graph takes the lower level');
  assert.equal(runtimeCalls.filter(call => call.op === 'create').length, createdBefore, 'lowering keeps the conversation');
  assert.equal(badge.textContent, 'Ask');
  assert.match(byId('agent-log').textContent, /Permission lowered to Ask for actions/);
  byId('agent-more').click();
  await settle();
  assert.equal(visible('agent-lower-ask') || visible('agent-lower-auto'), false, 'only lower levels stay offered');
  assert.ok(visible('agent-lower-read-only') && visible('agent-raise'));
  // Raising goes back through consent, one level up.
  byId('agent-raise').click();
  await settle();
  assert.equal(dockState(), 'consent', 'raising asks again');
  assert.equal([...doc.querySelectorAll('input[name="agent-permission"]')].find(radio => radio.checked)?.value, 'auto');
  [...byId('agent-surface').querySelectorAll('button')].find(node => node.textContent === 'Cancel').click();
  await settle();

  // Off is a full stop and clears the view.
  await turnOn();
  await choose('read-only');
  byId('agent-consent-accept').click();
  await settle();
  await turnOff();
  assert.ok(posted.some(message => message.op === 'disable'));
  assert.ok(runtimeCalls.some(call => call.op === 'dispose'), 'off disposes the graph');
  assert.match(byId('agent-surface').textContent, /The agent is off/);
  assert.equal(byId('agent-send').disabled, true);

  // No listeners or timers while closed.
  byId('agent-toggle').click();
  await settle();
  const before = posted.length;
  byId('workspace').dispatchEvent(new window.Event('pointerup'));
  doc.dispatchEvent(new window.Event('selectionchange'));
  byId('workspace').dispatchEvent(new window.Event('pointerdown', {bubbles: true}));
  await settle();
  assert.equal(posted.length, before, 'a closed panel does no work');
  assert.ok(posted.some(message => message.op === 'panel' && message.visible === false), 'native is told the panel closed');
  // One right-side dock at a time, in either order, without stealing focus.
  const agentDock = byId('agent-dock'), xrefsDock = byId('xrefs-dock');
  byId('agent-toggle').click();
  await settle();
  assert.equal(agentDock.hidden, false);
  byId('xrefs-toggle').click();
  await settle();
  assert.equal(agentDock.hidden, true, 'opening Cross-references closes the agent dock');
  assert.equal(xrefsDock.hidden, false);
  assert.equal(byId('workspace').dataset.agentDock, undefined, 'the agent gives up the dock column');
  byId('agent-toggle').click();
  await settle();
  assert.equal(xrefsDock.hidden, true, 'opening the agent closes Cross-references');
  assert.equal(agentDock.hidden, false);
  assert.equal(byId('workspace').dataset.xrefsOpen, undefined, 'Cross-references gives up the dock column');
  byId('agent-toggle').click();
  await settle();

  // The Swift CLI drivers and the graph send the same system prompt.
  const runtimeSource = readFileSync(new URL('../apps/research-ui/agent-runtime/src/runtime.mjs', import.meta.url), 'utf8');
  const swiftSource = readFileSync(new URL('../apps/research-ui/macos/AgentCore.swift', import.meta.url), 'utf8');
  const swiftText = name => new RegExp(`let ${name} = """\\n([\\s\\S]*?)\\n  """`).exec(swiftSource)?.[1]?.split('\n').map(line => line.replace(/^  /, '')).join('\n');
  const jsText = name => new RegExp(`export const ${name} = \`([^\`]*)\`;`).exec(runtimeSource)?.[1];
  for (const [js, swift] of [['SYSTEM_PROMPT', 'agentSystemPrompt'], ['PERMISSION_PROMPT_READ_ONLY', 'agentPermissionPromptReadOnly'],
    ['PERMISSION_PROMPT_ASK', 'agentPermissionPromptAsk'], ['PERMISSION_PROMPT_AUTO', 'agentPermissionPromptAuto'],
    ['PERMISSION_PROMPT_FULL', 'agentPermissionPromptFull'], ['PERMISSION_PROMPT_FULL_SENSITIVE', 'agentPermissionPromptFullSensitive']]) {
    assert.ok(jsText(js) && jsText(js) === swiftText(swift), `the CLI loops get the same ${js} as the graph`);
  }
  assert.ok(jsText('SYSTEM_PROMPT').includes('{permission}'));
  assert.doesNotMatch(jsText('PERMISSION_PROMPT_FULL'), /stay on this Mac|stay local/, 'Full access never claims content stays local');
  for (const name of ['PERMISSION_PROMPT_READ_ONLY', 'PERMISSION_PROMPT_ASK', 'PERMISSION_PROMPT_AUTO']) assert.match(jsText(name), /stay on this Mac/);

  // Subscriptions: Grok is subscription only and asks its CLI whether it is signed in.
  // A provider stand-in stays configured: it never applies to a CLI loop.
  subscriptions = true;
  byId('agent-toggle').click();
  await settle();
  const grok = doc.querySelector('[data-provider="grok"]');
  assert.ok(grok, 'Grok has a provider card');
  assert.match(grok.closest('.agent-provider').textContent, /Not checked/, 'an unchosen CLI is not asked yet');
  assert.equal(posted.some(message => message.op === 'subscriptionStatus'), false);
  grok.click();
  await settle();
  assert.ok(posted.some(message => message.op === 'subscriptionStatus' && message.provider === 'grok'), 'the Grok CLI is asked about its sign-in');
  assert.equal(doc.querySelector('[data-auth="key"]'), null, 'Grok has no API key path');
  assert.match(byId('agent-account').textContent, /Subscription only/);
  assert.match(byId('agent-account-text').textContent, /Run grok login in Terminal/, 'a signed-out CLI says how to sign in');
  assert.match(byId('agent-account').textContent, /Signed out/);
  assert.equal(byId('agent-account-action').textContent, 'Check again');
  assert.equal(byId('agent-turn-on').disabled, true, 'a signed-out CLI cannot be turned on');
  await turnOn();
  assert.equal(posted.some(message => message.op === 'enable' && message.provider === 'grok'), false, 'even when asked');
  assert.match(byId('agent-surface').textContent, /Run grok login in Terminal/);
  grokSignedIn = true;
  byId('agent-account-action').click();
  await settle();
  assert.match(byId('agent-account-text').textContent, /through your Grok CLI/);
  assert.ok(posted.some(message => message.op === 'models' && message.provider === 'grok' && message.auth === 'subscription'), 'its models come from the CLI');
  assert.doesNotMatch(doc.querySelector('.agent-leaves').textContent, /stand-in/, 'a provider stand-in does not redirect a CLI');
  assert.match(doc.querySelector('.agent-leaves').textContent, /xAI through your Grok CLI/);
  await turnOn();
  const grokConsent = byId('agent-surface').textContent;
  assert.match(grokConsent, /through the Grok CLI installed and signed in on this Mac/, 'the disclosure names the CLI');
  assert.match(grokConsent, /own local use/, 'and that this is the researcher\'s own login');
  assert.match(grokConsent, /~\/\.grok\/sessions/, 'and that Grok keeps its own record');
  assert.match(grokConsent, /tool result/);
  assert.match(grokConsent, /URLs, hosts/);
  assert.doesNotMatch(grokConsent, /stand-in/, 'a provider stand-in does not redirect a CLI, so the disclosure never says so');
  const creates = runtimeCalls.filter(entry => entry.op === 'create').length;
  byId('agent-consent-accept').click();
  await settle();
  const grokEnable = posted.findLast(message => message.op === 'enable');
  assert.equal(grokEnable.provider, 'grok');
  assert.equal(grokEnable.auth, 'subscription');
  assert.equal(runtimeCalls.filter(entry => entry.op === 'create').length, creates, 'the CLI loop loads no LangGraph bundle');

  // The CLI's rows render like the graph's, and decisions go to native.
  input.value = 'What did the CLI see?';
  input.dispatchEvent(new window.Event('input'));
  await press(input, 'Enter');
  const sent = posted.findLast(message => message.op === 'cliSend');
  assert.equal(sent?.text, 'What did the CLI see?', 'Return sends the question to the native CLI driver');
  const cli = event => runInContext(`__rebAgentEvent(${JSON.stringify({...event, cli: true})})`, context);
  cli({type: 'text', rowId: 'g1', turnId: sent.turnId, delta: 'From Grok <b>bold</b>'});
  cli({type: 'tool', id: 'tool-g', turnId: sent.turnId, name: 'get_session_summary', arguments: '{}', state: 'running', readOnly: true});
  cli({type: 'tool', id: 'tool-g', turnId: sent.turnId, name: 'get_session_summary', arguments: '{}', state: 'done', result: '{"events":3}', resultBytes: 12, isError: false});
  cli({type: 'approval', turnId: sent.turnId, callId: 'gc1', name: 'capture_action', arguments: '{"action":"pause"}'});
  await settle();
  assert.match(logNode.textContent, /From Grok <b>bold<\/b>/);
  assert.equal(logNode.querySelector('b'), null, 'CLI text stays inert');
  assert.equal(logNode.querySelector('[data-row-id="tool-g"] .agent-tool-summary').getAttribute('aria-expanded'), 'false');
  logNode.querySelector('[data-approve="gc1"]').click();
  await settle();
  assert.deepEqual(copy(posted.findLast(message => message.op === 'cliDecide')), {op: 'cliDecide', callId: 'gc1', allow: true}, 'Allow once reaches the driver');
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'tool' && message.row.id === 'tool-g'), 'CLI tool rows are kept locally');
  cli({type: 'assistantDone', turnId: sent.turnId, rowId: 'g1', text: 'From Grok <b>bold</b>'});
  cli({type: 'turnEnd', turnId: sent.turnId, stopped: false, inputTokens: 3, outputTokens: 2});
  await settle();
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'assistant' && message.row.rowId === 'g1'));
  assert.equal(byId('agent-send').getAttribute('aria-label'), 'Send', 'the turn ended');
  input.value = 'Stop this one';
  input.dispatchEvent(new window.Event('input'));
  byId('agent-send').click();
  await settle();
  byId('agent-send').click();
  await settle();
  assert.ok(posted.some(message => message.op === 'cliCancel'), 'Stop ends the CLI turn natively');
  cli({type: 'turnEnd', turnId: posted.findLast(message => message.op === 'cliSend').turnId, stopped: true});
  await turnOff();

  // ChatGPT: the subscription signs in through the browser and keeps the graph.
  standIn = false;
  byId('agent-toggle').click();
  await settle();
  byId('agent-toggle').click();
  await settle();
  doc.querySelector('[data-provider="chatgpt"]').click();
  await settle();
  doc.querySelector('[data-auth="subscription"]').click();
  await settle();
  const signIn = byId('agent-account-action');
  assert.equal(signIn.textContent, 'Sign in');
  signIn.click();
  await settle();
  assert.ok(posted.some(message => message.op === 'subscriptionSignIn' && message.provider === 'chatgpt'), 'Sign in starts the native flow');
  assert.match(byId('agent-account-text').textContent, /token sharing allowed/);
  await turnOn();
  assert.match(byId('agent-surface').textContent, /under your ChatGPT plan, through token sharing/);
  byId('agent-consent-accept').click();
  await settle();
  assert.equal(posted.findLast(message => message.op === 'enable').auth, 'subscription');
  assert.equal(runtimeCalls.findLast(entry => entry.op === 'create').provider, 'chatgpt', 'the ChatGPT subscription runs the LangGraph graph');
  assert.equal(byId('agent-status').textContent, 'GPT-6 Astra · ChatGPT plan');
  byId('agent-more').click();
  await settle();
  byId('agent-menu-info').click();
  await settle();
  assert.match(sheet.textContent, /Sign out of ChatGPT/);
  assert.match(sheet.textContent, /LangGraph in this window/);
  await press(sheet, 'Escape');
  // Choosing Claude in the picker while on turns ChatGPT off and asks for Claude's disclosure.
  const disables = posted.filter(message => message.op === 'disable').length;
  byId('agent-model').click();
  await settle();
  picker.querySelector('[data-pick="claude:key"]').click();
  await settle();
  assert.equal(posted.filter(message => message.op === 'disable').length, disables + 1, 'switching turns the agent off first');
  assert.equal(dockState(), 'consent', 'and asks again for the new choice');
  assert.match(byId('agent-surface').textContent, /go to Anthropic/);
  [...byId('agent-surface').querySelectorAll('button')].find(node => node.textContent === 'Cancel').click();
  await settle();
  assert.equal(dockState(), 'off');
  byId('agent-toggle').click();
  await settle();
  assert.deepEqual(asyncErrors, [], 'no asynchronous errors');
  release();
  console.log('PASS agent panel: safe markdown, verified citations, byte budget, consent as the only confirmation for the four permission levels (warning, named button, badge, lowering and raising), collapsed tool results, approvals, menus and picker, new conversation, closed-panel behavior, and subscription states with the CLI and ChatGPT paths (not rendered QA)');
}

if (import.meta.url === `file://${process.argv[1]}`) await checkAgentPanel();
