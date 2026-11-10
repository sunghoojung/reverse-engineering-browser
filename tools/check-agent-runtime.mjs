#!/usr/bin/env node
// Runs the bundled LangGraph agent loop exactly as the app ships it, in a VM
// context with only web globals (no require, process, Buffer or async_hooks),
// against a local stand-in provider. A fake bridge plays the native side with
// the same rules: one endpoint per provider, page credentials dropped, bodies
// streamed back as base64 chunks, and actions refused without Allow once.
// Usage: node tools/check-agent-runtime.mjs <agent_runtime_claude.js> <agent_runtime_chatgpt.js>
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const [claudeBundle, chatgptBundle] = process.argv.slice(2);
assert(claudeBundle && chatgptBundle, 'usage: node tools/check-agent-runtime.mjs <agent_runtime_claude.js> <agent_runtime_chatgpt.js>');

// Values cross the VM realm, so structural checks compare plain copies.
const copy = value => JSON.parse(JSON.stringify(value));
const requests = [];
const script = [];
const sse = events => events.map(event => `event: ${event.type ?? 'message'}\ndata: ${JSON.stringify(event)}\n\n`).join('');
let counter = 0;
const id = prefix => `${prefix}_${++counter}`;
const claudeStart = () => ({type: 'message_start', message: {id: id('msg'), type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], stop_reason: null, usage: {input_tokens: 9, output_tokens: 0}}});
const claudeTool = (name, input) => sse([claudeStart(),
  {type: 'content_block_start', index: 0, content_block: {type: 'thinking', thinking: '', signature: ''}},
  {type: 'content_block_delta', index: 0, delta: {type: 'signature_delta', signature: 'signed-reasoning'}},
  {type: 'content_block_stop', index: 0},
  {type: 'content_block_start', index: 1, content_block: {type: 'tool_use', id: id('toolu'), name, input: {}}},
  {type: 'content_block_delta', index: 1, delta: {type: 'input_json_delta', partial_json: JSON.stringify(input)}},
  {type: 'content_block_stop', index: 1},
  {type: 'message_delta', delta: {stop_reason: 'tool_use'}, usage: {output_tokens: 4}}, {type: 'message_stop'}]);
const claudeText = text => sse([claudeStart(),
  {type: 'content_block_start', index: 0, content_block: {type: 'text', text: ''}},
  ...text.match(/.{1,12}/gs).map(piece => ({type: 'content_block_delta', index: 0, delta: {type: 'text_delta', text: piece}})),
  {type: 'content_block_stop', index: 0},
  {type: 'message_delta', delta: {stop_reason: 'end_turn'}, usage: {output_tokens: 6}}, {type: 'message_stop'}]);
// The Responses stream as the API sends it: each output item is added, filled
// by its deltas, then done.
const openAIEvents = output => {
  const events = [{type: 'response.created', response: {id: id('resp'), object: 'response', status: 'in_progress', output: []}}];
  output.forEach((item, index) => {
    if (item.type === 'function_call') {
      events.push({type: 'response.output_item.added', output_index: index, item: {...item, arguments: '', status: 'in_progress'}},
        {type: 'response.function_call_arguments.delta', item_id: item.id, output_index: index, delta: item.arguments},
        {type: 'response.function_call_arguments.done', item_id: item.id, output_index: index, arguments: item.arguments});
    } else if (item.type === 'message') {
      const text = item.content[0].text;
      events.push({type: 'response.output_item.added', output_index: index, item: {...item, content: [], status: 'in_progress'}},
        {type: 'response.content_part.added', item_id: item.id, output_index: index, content_index: 0, part: {type: 'output_text', text: '', annotations: []}},
        {type: 'response.output_text.delta', item_id: item.id, output_index: index, content_index: 0, delta: text},
        {type: 'response.output_text.done', item_id: item.id, output_index: index, content_index: 0, text},
        {type: 'response.content_part.done', item_id: item.id, output_index: index, content_index: 0, part: item.content[0]});
    } else {
      events.push({type: 'response.output_item.added', output_index: index, item: {type: item.type, id: item.id, summary: []}});
    }
    events.push({type: 'response.output_item.done', output_index: index, item});
  });
  events.push({type: 'response.completed', response: {id: id('resp'), object: 'response', status: 'completed', model: 'gpt-6-astra', output, usage: {input_tokens: 9, output_tokens: 3, total_tokens: 12}}});
  return sse(events);
};
const server = createServer((request, response) => {
  let body = '';
  request.on('data', chunk => { body += chunk; });
  request.on('end', () => {
    requests.push({url: request.url, headers: request.headers, body});
    const next = script.shift() ?? claudeText('Unscripted.');
    response.writeHead(200, {'content-type': 'text/event-stream'});
    if (next === 'hold') { response.write(sse([claudeStart()])); return; }
    response.end(next);
  });
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const standIn = `http://127.0.0.1:${server.address().port}`;

// The native rules, in miniature. tools/check-agent-core.swift checks the real ones.
const endpoints = {claude: 'https://api.anthropic.com/v1/messages', chatgpt: 'https://api.openai.com/v1/responses'};
const forwarded = new Set(['content-type', 'accept', 'anthropic-version', 'anthropic-beta', 'idempotency-key', 'openai-beta']);
const toolDefinitions = [
  {name: 'get_events', description: 'Read events', readOnly: true, schema: {type: 'object', properties: {limit: {type: 'integer'}}, additionalProperties: false}},
  {name: 'capture_action', description: 'Pause or resume capture', readOnly: false, schema: {type: 'object', properties: {action: {type: 'string'}}, required: ['action']}},
];
const toolCalls = [];
const fetchCancels = [];
const pageHeaders = [];
let fetchListener = null;
let provider = 'claude';
const bridge = {
  onFetchEvent: listener => { fetchListener = listener; },
  async call(op, fields) {
    if (op === 'providerFetch') {
      const url = new URL(fields.url);
      assert.equal(`${url.origin}${url.pathname}`, endpoints[provider], 'the page asks only for the fixed endpoint');
      pageHeaders.push(fields.headers);
      const headers = Object.fromEntries(Object.entries(fields.headers).filter(([name]) => forwarded.has(name.toLowerCase())));
      const response = await fetch(standIn + url.pathname + url.search, {method: fields.method, headers, body: fields.body});
      (async () => {
        const reader = response.body.getReader();
        let buffered = '';
        for (;;) {
          const {done, value} = await reader.read();
          if (done) break;
          buffered += Buffer.from(value).toString('latin1');
          let boundary;
          while ((boundary = buffered.indexOf('\n\n')) >= 0) {
            fetchListener({type: 'fetchChunk', id: fields.id, data: Buffer.from(buffered.slice(0, boundary + 2), 'latin1').toString('base64')});
            buffered = buffered.slice(boundary + 2);
          }
        }
        if (buffered) fetchListener({type: 'fetchChunk', id: fields.id, data: Buffer.from(buffered, 'latin1').toString('base64')});
        fetchListener({type: 'fetchEnd', id: fields.id});
      })().catch(error => fetchListener({type: 'fetchError', id: fields.id, message: String(error)}));
      return {status: response.status, headers: {'content-type': response.headers.get('content-type')}};
    }
    if (op === 'fetchCancel') { fetchCancels.push(fields.id); return {ok: true}; }
    if (op === 'toolCall') {
      const definition = toolDefinitions.find(item => item.name === fields.name);
      if (!definition.readOnly && !fields.approved) return {text: 'This action needs Allow once. It did not run.', isError: true};
      toolCalls.push({name: fields.name, arguments: fields.arguments, approved: fields.approved});
      return {text: JSON.stringify({events: [{session_id: '9', process_id: '1', sequence_number: '4'}]}), isError: false};
    }
    throw new Error(`unexpected op ${op}`);
  },
};

// Each bundle runs in its own web-only context, as each loads alone in the app.
async function loadBundle(path, provider) {
const globals = {console, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, AbortSignal, Headers, Request, Response,
  ReadableStream, TransformStream, WritableStream, TextDecoderStream, Blob, FormData, crypto: globalThis.crypto, setTimeout, clearTimeout,
  setInterval, clearInterval, queueMicrotask, structuredClone, atob, btoa, Event, EventTarget, DOMException, performance};
globals.globalThis = globals; globals.window = globals; globals.self = globals;
const context = vm.createContext(globals);
const source = await readFile(path, 'utf8');
vm.runInContext(source, context, {filename: path});
assert.equal(vm.runInContext('typeof require + typeof process + typeof Buffer + typeof fetch', context), 'undefinedundefinedundefinedundefined',
  'no Node globals, and no global fetch: every request goes through the bridge');
const api = globals.RebAgentRuntimes?.[provider];
assert(api?.createAgentRuntime, `the ${provider} bundle exposes its runtime`);
const otherSdk = provider === 'claude' ? 'api.openai.com' : 'api.anthropic.com';
assert(!source.includes(otherSdk), `the ${provider} bundle carries no other provider SDK`);
return api;
}
const runtimes = {claude: await loadBundle(claudeBundle, 'claude'), chatgpt: await loadBundle(chatgptBundle, 'chatgpt')};
const runtimeApi = runtimes.claude;

function harness(kind) {
  provider = kind;
  const events = [];
  const runtime = runtimes[kind].createAgentRuntime({bridge, provider: kind, model: kind === 'claude' ? 'claude-opus-5-5' : 'gpt-6-astra', tools: toolDefinitions, emit: event => events.push(event)});
  const waitFor = async (predicate, label) => {
    const deadline = Date.now() + 15000;
    while (!predicate()) { assert(Date.now() < deadline, `timed out: ${label}: ${JSON.stringify(events.slice(-4))}`); await new Promise(done => setTimeout(done, 10)); }
  };
  return {runtime, events, waitFor};
}

// A read tool call through the graph, with thinking replayed unchanged.
const claude = harness('claude');
script.push(claudeTool('get_events', {limit: 5}), claudeText('One request [cite session=9 process=1 sequence=4].'));
await claude.runtime.send({turnId: 't1', text: 'What loaded?', context: 'kind=request session=9', pins: []});
const text = claude.events.filter(event => event.type === 'text').map(event => event.delta).join('');
assert.equal(text, 'One request [cite session=9 process=1 sequence=4].', 'model text streams to the panel');
assert.deepEqual(copy(claude.events.filter(event => event.type === 'tool').map(event => event.state)), ['running', 'done'], 'the tool call is visible');
assert.deepEqual(copy(toolCalls.at(-1)), {name: 'get_events', arguments: {limit: 5}, approved: false});
assert(claude.events.some(event => event.type === 'assistantDone' && event.text === text), 'the finished answer is reported once for the transcript');
assert(claude.events.some(event => event.type === 'turnEnd' && event.turnId === 't1' && !event.stopped));
const second = JSON.parse(requests.at(-1).body);
assert.equal(second.model, 'claude-opus-5-5');
assert.equal(second.fallbacks, 'default', 'refusal fallback is requested');
assert(requests.at(-1).url.endsWith('/v1/messages?beta=true'), 'fallback uses the beta messages path');
assert.equal(requests.at(-1).headers['anthropic-beta'], 'server-side-fallback-2026-07-01');
assert(JSON.stringify(second.messages).includes('signed-reasoning'), 'signed thinking is replayed unchanged');
assert(JSON.stringify(second.messages).includes('tool_result'), 'the tool result is sent back');
assert(JSON.stringify(second.system).includes('untrusted data'), 'the model is told tool results are data');
assert(JSON.stringify(second.messages).includes('<current_selection>kind=request session=9</current_selection>'), 'selection identifiers are in the turn');
for (const headers of pageHeaders) {
  const credential = Object.entries(headers).find(([name]) => ['x-api-key', 'authorization'].includes(name.toLowerCase()));
  assert(!credential || credential[1] === 'origin-trace-native-key' || credential[1] === 'Bearer origin-trace-native-key', 'the page holds only a placeholder');
}
assert(requests.every(request => !request.headers['x-api-key'] && !request.headers.authorization), 'native never forwards the page credential');

// Deny: the graph pauses before the action and resumes without running it.
script.push(claudeTool('capture_action', {action: 'pause'}), claudeText('Denied, noted.'));
const before = toolCalls.length;
const denied = claude.runtime.send({turnId: 't2', text: 'Pause capture', pins: []});
await claude.waitFor(() => claude.events.some(event => event.type === 'approval' && event.turnId === 't2'), 'approval');
assert(claude.runtime.running, 'the turn waits for the decision');
const approval = claude.events.find(event => event.type === 'approval' && event.turnId === 't2');
assert.equal(approval.name, 'capture_action');
assert.equal(claude.runtime.decide(approval.callId, false), true);
await denied;
assert.equal(toolCalls.length, before, 'a denied action does not run');
assert(claude.events.some(event => event.type === 'tool' && event.turnId === 't2' && event.state === 'denied'));
assert(requests.at(-1).body.includes('denied this call'), 'the model is told the call was denied');

// Allow once runs that one call, approved, and nothing else.
script.push(claudeTool('capture_action', {action: 'pause'}), claudeText('Paused.'));
const allowed = claude.runtime.send({turnId: 't3', text: 'Pause it now', pins: []});
await claude.waitFor(() => claude.events.some(event => event.type === 'approval' && event.turnId === 't3'), 'second approval');
const second_approval = claude.events.find(event => event.type === 'approval' && event.turnId === 't3');
assert.equal(claude.runtime.decide('not-a-call', true), false, 'an unknown decision is ignored');
claude.runtime.decide(second_approval.callId, true);
await allowed;
assert.deepEqual(copy(toolCalls.at(-1)), {name: 'capture_action', arguments: {action: 'pause'}, approved: true});

// The approval does not carry over: the next action asks again.
script.push(claudeTool('capture_action', {action: 'resume'}), claudeText('Asked.'));
const again = claude.runtime.send({turnId: 't4', text: 'Resume', pins: []});
await claude.waitFor(() => claude.events.some(event => event.type === 'approval' && event.turnId === 't4'), 'third approval');
claude.runtime.cancel();
await again;
assert(claude.events.some(event => event.type === 'turnEnd' && event.turnId === 't4' && event.stopped), 'stop while paused ends the turn');
assert.equal(toolCalls.at(-1).arguments.action, 'pause', 'the cancelled action never ran');

// Cancel mid-stream aborts the provider request; the next turn still works.
script.length = 0;
script.push('hold');
const held = claude.runtime.send({turnId: 't5', text: 'Long answer', pins: []});
await claude.waitFor(() => requests.length && script.length === 0, 'held request');
await new Promise(done => setTimeout(done, 100));
claude.runtime.cancel();
await held;
assert(claude.events.some(event => event.type === 'turnEnd' && event.turnId === 't5' && event.stopped), 'stop ends a streaming turn');
assert(fetchCancels.length > 0, 'stop cancels the native request');
script.push(claudeText('Still here.'));
await claude.runtime.send({turnId: 't6', text: 'Hello again', pins: []});
assert(claude.events.some(event => event.type === 'text' && event.turnId === 't6'), 'the conversation continues after a stop');
const resent = JSON.parse(requests.at(-1).body).messages;
assert(resent.every((message, index) => message.role !== 'assistant' || !JSON.stringify(message.content).includes('tool_use') ||
  JSON.stringify(resent[index + 1]?.content ?? '').includes('tool_result')), 'no tool call is resent without its result');

// History keeps a byte budget by whole turns, and Claude thinking leaves with them.
const budget = harness('claude');
const excerpt = 'x'.repeat(120 * 1024);
for (let turn = 0; turn < 18; turn += 1) {
  script.push(claudeTool('get_events', {limit: 1}), claudeText(`Turn ${turn}.`));
  await budget.runtime.send({turnId: `b${turn}`, text: `Question ${turn}`, pins: [{label: 'excerpt', text: excerpt, truncated: false}]});
}
assert(budget.events.some(event => event.type === 'notice' && /Older context left this conversation/.test(event.text)), 'the trim is labeled');
assert(budget.runtime.historyBytes() <= runtimeApi.HISTORY_BYTES, 'retained history stays within its budget');
const trimmed = JSON.parse(requests.at(-1).body).messages;
assert(!JSON.stringify(trimmed).includes('Question 0'), 'the oldest turn left the conversation');
assert(JSON.stringify(trimmed[0]).includes('Question'), 'history restarts on a whole turn');
assert(!JSON.stringify(trimmed.slice(0, -2)).includes('signed-reasoning'), 'signed thinking left with the trim');

// ChatGPT: the Responses API, nothing stored by the provider, reasoning replayed.
const chat = harness('chatgpt');
script.push(openAIEvents([
  {type: 'reasoning', id: 'rs_1', summary: [], encrypted_content: 'ENCRYPTED_REASONING'},
  {type: 'function_call', id: 'fc_1', call_id: 'call_1', name: 'get_events', arguments: '{"limit":2}', status: 'completed'},
]), openAIEvents([{type: 'message', id: 'msg_1', role: 'assistant', status: 'completed', content: [{type: 'output_text', text: 'Two events.', annotations: []}]}]));
const openAIStart = requests.length;
await chat.runtime.send({turnId: 'c1', text: 'Summarize', pins: []});
assert(chat.events.some(event => event.type === 'turnEnd' && event.turnId === 'c1'));
const firstOpenAI = JSON.parse(requests[openAIStart].body);
assert(requests[openAIStart].url.endsWith('/v1/responses'), 'ChatGPT uses the Responses API');
assert.equal(firstOpenAI.store, false, 'the provider stores nothing');
assert.equal(firstOpenAI.tools?.[0]?.type, 'function');
const replay = requests[openAIStart + 1].body;
assert(replay.includes('ENCRYPTED_REASONING') && replay.includes('function_call_output'), 'reasoning and results are replayed');

server.close();
server.closeAllConnections?.();
console.log(`PASS agent runtime (bundled LangGraph StateGraph in a web-only context): tool call, Deny and Allow once breakpoints, stop while paused and while streaming, Claude and ChatGPT requests, placeholder-only key`);
