#!/usr/bin/env node
// In-app agent dock against the shipped scripts in an offline DOM model: the
// safe markdown subset, citation validation, byte budgets and the panel states,
// with a stand-in for the LangGraph runtime. Not rendered QA. The bundled graph
// is tools/check-agent-runtime.mjs, native is tools/check-agent-core.swift and
// the packaged app path is test24 in the rendered harness.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
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

  // Panel states through the shipped controller and a fake native bridge.
  const posted = [];
  let engine = {type: 'status', phase: 'off', running: false, childRunning: false, tools: [], provider: null, model: null, effects: false};
  const status = () => ({available: true, reason: '', standIn: true,
    providers: [{id: 'claude', label: 'Claude', vendor: 'Anthropic', defaultModel: 'claude-opus-5-5', hasKey: true},
      {id: 'chatgpt', label: 'ChatGPT', vendor: 'OpenAI', defaultModel: 'gpt-6-astra', hasKey: true}], engine});
  context.__agentPost = message => {
    posted.push(message);
    if (message.op === 'enable') {
      engine = {...engine, phase: 'ready', childRunning: true, provider: message.provider, model: 'claude-opus-5-5', tools: [{name: 'get_events', readOnly: true}]};
      return Promise.resolve({...status(), tools: [{name: 'get_events', description: 'Read', schema: {type: 'object'}, readOnly: true}]});
    }
    if (message.op === 'disable') { engine = {...engine, phase: 'off', childRunning: false}; return Promise.resolve(status()); }
    if (message.op === 'turn' || message.op === 'transcriptAppend') return Promise.resolve({ok: true});
    if (message.op === 'transcript') return Promise.resolve({rows: [], before: null});
    if (message.op === 'models') return Promise.resolve({models: ['claude-opus-5-5'], defaultModel: 'claude-opus-5-5', fromProvider: true});
    return Promise.resolve(status());
  };
  // The panel drives the graph through this interface; the real one is bundled.
  const runtimeCalls = [];
  context.__runtimeCalls = runtimeCalls;
  runInContext(`globalThis.RebAgentRuntimes = {claude: {createAgentRuntime(options) {
      __runtimeCalls.push({op: 'create', provider: options.provider, model: options.model, tools: options.tools.map(tool => tool.name)});
      globalThis.__runtimeEmit = options.emit;
      return {running: false, send(turn) { __runtimeCalls.push({op: 'send', text: turn.text}); return Promise.resolve(); },
        decide(callId, allow) { __runtimeCalls.push({op: 'decide', callId, allow}); return true; },
        cancel() { __runtimeCalls.push({op: 'cancel'}); }, dispose() { __runtimeCalls.push({op: 'dispose'}); }};
    }}};
    globalThis.webkit = {messageHandlers: {rebAgent: {postMessage: message => __agentPost(message)}}};
    globalThis.fetch = async () => new Response(JSON.stringify({instance_id: '100:200'}), {status: 200});
    globalThis.requestAnimationFrame = callback => { callback(0); return 0; };`, context);
  const doc = window.document;
  const settle = async () => { for (let i = 0; i < 6; i++) await nextTurn(); };
  assert.equal(doc.getElementById('agent-dock').hidden, true, 'the dock is closed by default');
  assert.equal(posted.length, 0, 'nothing is asked of native while closed');

  doc.getElementById('agent-toggle').click();
  await settle();
  assert.equal(doc.getElementById('agent-dock').hidden, false);
  assert.match(doc.getElementById('agent-surface').textContent, /The agent is off/);
  assert.equal(doc.getElementById('agent-send').disabled, true);

  // Turning on requires the explicit disclosure step.
  const switchInput = doc.getElementById('agent-switch');
  switchInput.checked = true;
  switchInput.dispatchEvent(new window.Event('change'));
  await settle();
  assert.match(doc.getElementById('agent-surface').textContent, /tool result/i);
  assert.match(doc.getElementById('agent-surface').textContent, /URLs, hosts/);
  assert.equal(posted.some(message => message.op === 'enable'), false, 'consent comes before enabling');
  assert.equal(doc.getElementById('agent-effects').checked, false, 'actions stay off by default');
  doc.getElementById('agent-consent-accept').click();
  await settle();
  const enable = posted.find(message => message.op === 'enable');
  assert.equal(enable.effects, false);
  assert.equal(enable.sessionKey, '100:200');

  // A turn: streaming text, a tool row with its result, and inert markup.
  const input = doc.getElementById('agent-input');
  input.value = 'What loaded?';
  input.dispatchEvent(new window.Event('input'));
  doc.getElementById('agent-send').click();
  await settle();
  assert.deepEqual(copy(runtimeCalls.find(call => call.op === 'create')), {op: 'create', provider: 'claude', model: 'claude-opus-5-5', tools: ['get_events']},
    'the graph is built from the native tool list');
  assert.ok(runtimeCalls.some(call => call.op === 'send' && call.text === 'What loaded?'), 'the question goes to the graph');
  assert.ok(posted.some(message => message.op === 'turn' && message.running === true), 'native knows a turn is running');
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'user'), 'the question is kept locally');
  const emit = event => runInContext(`__runtimeEmit(${JSON.stringify(event)})`, context);
  emit({type: 'text', rowId: 'a1', turnId: 't', delta: 'Answer <img src=x onerror=alert(1)> [cite session=9 artifact=999]'});
  const fencedSource = 'const a = "<b>x</b>"; // <img src=x onerror=alert(2)>';
  emit({type: 'text', rowId: 'a2', turnId: 't', delta: 'Code:\n```js\n' + fencedSource + '\n```\n'});
  emit({type: 'tool', id: 'tool1', turnId: 't', name: 'get_events', arguments: '{"limit":5}', state: 'running', readOnly: true});
  emit({type: 'tool', id: 'tool1', turnId: 't', name: 'get_events', arguments: '{"limit":5}', state: 'done', result: '{"count":1}', resultBytes: 11, isError: false});
  await settle();
  const logNode = doc.getElementById('agent-log');
  assert.match(logNode.textContent, /get_events/);
  assert.equal(logNode.querySelector('img'), null, 'model markup is never instantiated');
  assert.match(logNode.textContent, /<img src=x onerror=alert\(1\)>/);
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

  // An action waits on an explicit per-call decision with no standing grant.
  emit({type: 'approval', turnId: 't', callId: 'c1', name: 'capture_action', arguments: '{"action":"pause"}'});
  await settle();
  const allow = logNode.querySelector('[data-approve="c1"]');
  assert.equal(allow.textContent, 'Allow once');
  assert.ok(logNode.querySelector('.agent-approval .agent-tool-pre .syntax-key'), 'tool arguments are colored as JSON');
  assert.ok(![...logNode.querySelectorAll('button')].some(node => /always/i.test(node.textContent)), 'there is no Always allow');
  allow.click();
  await settle();
  assert.deepEqual(copy(runtimeCalls.find(call => call.op === 'decide')), {op: 'decide', callId: 'c1', allow: true}, 'Allow once resumes the graph');
  assert.ok(posted.some(message => message.op === 'transcriptAppend' && message.row.role === 'tool' && message.row.state === 'done'), 'tool rows are kept locally');
  emit({type: 'turnEnd', turnId: 't'});
  await settle();
  assert.ok(posted.some(message => message.op === 'turn' && message.running === false), 'native knows the turn ended');

  // Off is a full stop and clears the view.
  switchInput.checked = false;
  switchInput.dispatchEvent(new window.Event('change'));
  await settle();
  assert.ok(posted.some(message => message.op === 'disable'));
  assert.ok(runtimeCalls.some(call => call.op === 'dispose'), 'off disposes the graph');
  assert.match(doc.getElementById('agent-surface').textContent, /The agent is off/);
  assert.equal(doc.getElementById('agent-send').disabled, true);

  // No listeners or timers while closed.
  doc.getElementById('agent-toggle').click();
  await settle();
  const before = posted.length;
  doc.getElementById('workspace').dispatchEvent(new window.Event('pointerup'));
  doc.dispatchEvent(new window.Event('selectionchange'));
  await settle();
  assert.equal(posted.length, before, 'a closed panel does no work');
  assert.ok(posted.some(message => message.op === 'panel' && message.visible === false), 'native is told the panel closed');
  // One right-side dock at a time, in either order, without stealing focus.
  const agentDock = doc.getElementById('agent-dock'), xrefsDock = doc.getElementById('xrefs-dock');
  doc.getElementById('agent-toggle').click();
  await settle();
  assert.equal(agentDock.hidden, false);
  doc.getElementById('xrefs-toggle').click();
  await settle();
  assert.equal(agentDock.hidden, true, 'opening Cross-references closes the agent dock');
  assert.equal(xrefsDock.hidden, false);
  assert.equal(doc.getElementById('workspace').dataset.agentDock, undefined, 'the agent gives up the dock column');
  doc.getElementById('agent-toggle').click();
  await settle();
  assert.equal(xrefsDock.hidden, true, 'opening the agent closes Cross-references');
  assert.equal(agentDock.hidden, false);
  assert.equal(doc.getElementById('workspace').dataset.xrefsOpen, undefined, 'Cross-references gives up the dock column');
  doc.getElementById('agent-toggle').click();
  await settle();
  assert.deepEqual(asyncErrors, [], 'no asynchronous errors');
  release();
  console.log('PASS agent panel: safe markdown, verified citations, byte budget, consent, approvals and closed-panel behavior (not rendered QA)');
}

if (import.meta.url === `file://${process.argv[1]}`) await checkAgentPanel();
