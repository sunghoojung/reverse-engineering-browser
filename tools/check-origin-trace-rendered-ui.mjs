#!/usr/bin/env node
// Rendered UI acceptance on the native macOS product path. A hosted XCTest
// bundle runs inside a relocated copy of the packaged Origin Trace app and
// drives its production WKWebView with native AppKit pointer and key events.
// The UI is served by the packaged backend from a bounded synthetic session
// that includes events emitted by the real C++ native Wasm encoders.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync, spawn} from 'node:child_process';
import {chmod, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildEvidence, HOSTILE_BYTECODE_MARKUP, HOSTILE_SOURCE_MARKER, HOSTILE_SOURCE_URL, HOSTILE_URL, HOSTILE_URL_MARKER, NAMED_GAP_REASONS, SOURCE_LINE_COUNT,
  SYNTHETIC_REQUEST_COUNT, REQUEST_BODY_HOST, REQUEST_BODY_TARGET, REQUEST_BODY_MARKER, METADATA_BODY_HOST, RESPONSE_BODY_HOST, RESPONSE_BODY_MARKER, HEADER_VALUE_MARKER, COOKIE_VALUE_MARKER, INVOCATION_ARTIFACT_ID, MINIFIED_ARTIFACT_ID} from './origin-trace-rendered-ui/evidence-fixture.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const harness = join(root, 'tools/origin-trace-rendered-ui');
const report = join(root, 'build/rendered-ui-qa');
const usage = 'usage: node tools/check-origin-trace-rendered-ui.mjs [--only <testName>]';
const argv = process.argv.slice(2);
const maximumHeight = process.env.REB_RENDERED_UI_MAX_HEIGHT;
if (maximumHeight !== undefined) {
  assert(/^\d+$/.test(maximumHeight) && Number.isSafeInteger(Number(maximumHeight)) && Number(maximumHeight) >= 560,
    'REB_RENDERED_UI_MAX_HEIGHT must be an integer of at least 560 CSS pixels');
}
let only = null;
for (let index = 0; index < argv.length; index += 1) {
  if (argv[index] === '--only' && argv[index + 1]) only = argv[++index];
  else throw new Error(`Unknown argument ${argv[index]}\n${usage}`);
}

assert.equal(process.platform, 'darwin', 'Rendered UI acceptance runs in the packaged macOS app');
const app = join(root, 'build/Origin Trace.app');
const goldenStores = {guestStore: join(root, 'build/native-golden/guest-evidence'), dispatchStore: join(root, 'build/native-golden/wasm-evidence'),
  observedStore: join(root, 'build/vm-observed-evidence')};
for (const required of [app, join(root, 'build/sessions/demo.jsonl'), ...Object.values(goldenStores).map(store => join(store, 'manifest.jsonl'))]) {
  assert(existsSync(required), `Missing ${required}; run make app-build e2e native-wasm-golden-check vm-observed-evidence`);
}

// Full Xcode provides XCTest. Respect an explicit DEVELOPER_DIR, otherwise use
// the selected developer directory or the standard Xcode location without
// changing the global selection.
function developerDirectory() {
  const candidates = [process.env.DEVELOPER_DIR, process.env.DEVELOPER_DIR ? null : execFileSync('xcode-select', ['-p'], {encoding: 'utf8'}).trim(),
    '/Applications/Xcode.app/Contents/Developer'].filter(Boolean);
  const found = candidates.find(path => existsSync(join(path, 'usr/bin/xcodebuild')));
  assert(found, 'Rendered UI acceptance requires full Xcode (XCTest); Command Line Tools alone are insufficient');
  return found;
}
const environment = {...process.env, DEVELOPER_DIR: developerDirectory()};
const arch = execFileSync('uname', ['-m'], {encoding: 'utf8'}).trim();
const destination = `platform=macOS,arch=${arch}`;

function summary(output) {
  const lines = output.split('\n').filter(line =>
    /error|failed|Test Case|Executed |TEST (EXECUTE )?(FAILED|SUCCEEDED)|RENDERED_UI_|HarnessError/i.test(line));
  return (lines.length ? lines.slice(-60).join('\n') : output.slice(-6000)).slice(-16000);
}

function run(command, args, {timeout, label}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {env: environment, detached: true});
    let output = '';
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { output = (output + chunk).slice(-1024 * 1024); });
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') output += `\n${error}`; }
      reject(new Error(`${label} timed out\n${summary(output)}`));
    }, timeout);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve(output);
      else {
        const error = new Error(`${label} exited ${code}\n${summary(output)}`);
        Object.defineProperty(error, 'output', {value: output, enumerable: false});
        reject(error);
      }
    });
  });
}

async function waitForFile(path, child, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error('Packaged backend stopped during startup');
    try { const text = (await readFile(path, 'utf8')).trim(); if (text) return text; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await new Promise(done => setTimeout(done, 50));
  }
  throw new Error('Packaged backend endpoint did not become ready');
}

const temporary = await mkdtemp(join(tmpdir(), 'reb-rendered-ui-'));
let backend;
let failingBackend;
let agentStandIn;
const agentRequests = [];
let log = '';
try {
  await rm(report, {recursive: true, force: true});
  await mkdir(join(report, 'screenshots'), {recursive: true});
  // A relocated copy proves the bundle does not depend on source-tree paths.
  const host = join(temporary, 'Origin Trace.app');
  await cp(app, host, {recursive: true});
  execFileSync('codesign', ['--verify', '--deep', '--strict', host], {stdio: 'pipe'});
  const stores = await buildEvidence({root: join(temporary, 'evidence'), sessions: join(root, 'build/sessions'), ...goldenStores});

  const endpointFile = join(temporary, 'endpoint');
  backend = spawn(join(host, 'Contents/MacOS/OriginTraceBackend'), ['--host', '127.0.0.1', '--port', '0',
    '--endpoint-file', endpointFile, '--store', stores.store, '--trace-store', stores.traceStore,
    '--signal-store', stores.signalStore, '--artifacts', stores.artifacts, '--api-collection', stores.apiCollection,
    '--local-analyst', stores.localAnalyst, '--decoder', join(host, 'Contents/MacOS/OriginTraceDecoder'),
    // Sources and the app's start panel share one saved site set here, as
    // they share Application Support in a real app run.
    '--js-invocation-site-store', stores.invocationSites],
  {cwd: temporary, stdio: ['ignore', 'pipe', 'pipe']});
  let backendLog = '';
  for (const stream of [backend.stdout, backend.stderr]) stream.on('data', chunk => { backendLog = (backendLog + chunk).slice(-256 * 1024); });
  const endpoint = await waitForFile(endpointFile, backend);
  assert.match(endpoint, /^http:\/\/127\.0\.0\.1:\d+$/, 'The packaged backend must bind loopback only');
  // The packaged app's default content mode retains request content, so the
  // titlebar carries its session label in every screenshot.
  const uiURL = `${endpoint}/?native=1&canvas_images=0&request_content=1`;

  // A local stand-in for the provider, so the agent's whole loop runs through
  // the packaged app with no key and no network. The real tool server answers.
  const citedArtifact = (await (await fetch(`${endpoint}/api/artifacts?kind=javascript&limit=1`)).json()).artifacts[0];
  const sse = lines => lines.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('');
  const toolTurn = () => sse([{type: 'message_start', message: {id: `msg_${Math.random().toString(36).slice(2)}`, type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], stop_reason: null, usage: {input_tokens: 40, output_tokens: 0}}},
    {type: 'content_block_start', index: 0, content_block: {type: 'tool_use', id: `toolu_${Math.random().toString(36).slice(2)}`, name: 'get_artifacts', input: {}}},
    {type: 'content_block_delta', index: 0, delta: {type: 'input_json_delta', partial_json: '{"limit":3}'}},
    {type: 'content_block_stop', index: 0}, {type: 'message_delta', delta: {stop_reason: 'tool_use'}, usage: {output_tokens: 8}}, {type: 'message_stop'}]);
  const answer = `The session loaded **one** script. <img src=x onerror="window.__rebInjected=1"> See [cite session=${citedArtifact.session_id} artifact=${citedArtifact.artifact_id}] and an invented [cite session=${citedArtifact.session_id} artifact=999999].

\`\`\`js
fetch("/getcaptcha");
\`\`\`

- first observation
- second observation`;
  const textTurn = () => sse([{type: 'message_start', message: {id: `msg_${Math.random().toString(36).slice(2)}`, type: 'message', role: 'assistant', model: 'claude-opus-5-5', content: [], stop_reason: null, usage: {input_tokens: 64, output_tokens: 0}}},
    {type: 'content_block_start', index: 0, content_block: {type: 'text', text: ''}},
    {type: 'content_block_delta', index: 0, delta: {type: 'text_delta', text: answer}},
    {type: 'content_block_stop', index: 0}, {type: 'message_delta', delta: {stop_reason: 'end_turn'}, usage: {output_tokens: 32}}, {type: 'message_stop'}]);
  agentStandIn = createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      agentRequests.push({path: request.url, headers: request.headers, body});
      if (request.url.endsWith('/v1/models')) {
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify({data: [{id: 'claude-opus-5-5'}, {id: 'claude-sonnet-5-5'}]}));
        return;
      }
      response.setHeader('Content-Type', 'text/event-stream');
      // A turn's first request asks for a tool; the request carrying its result
      // gets the answer. Earlier turns' results are history, not this signal.
      const last = JSON.stringify(JSON.parse(body || '{}').messages?.at(-1) ?? '');
      response.end(last.includes('tool_result') ? textTurn() : toolTurn());
    });
  });
  await new Promise(done => agentStandIn.listen(0, '127.0.0.1', done));
  const agentProviderURL = `http://127.0.0.1:${agentStandIn.address().port}`;

  // A separate, real backend has no cached analysis. Removing execution
  // permission from its copied binary makes self-reexecution fail at spawn.
  const failureRoot = join(temporary, 'worker-failure');
  await mkdir(join(failureRoot, 'blobs'), {recursive: true});
  const source = await readFile(join(root, 'tools/fixtures/dispatch-shapes/handler-array-interpreter.js'));
  const sha = createHash('sha256').update(source).digest('hex');
  await writeFile(join(failureRoot, 'blobs', `${sha}.bin`), source);
  await writeFile(join(failureRoot, 'manifest.jsonl'), JSON.stringify({protocol_version: 1,
    artifact_id: '1', session_id: '1', navigation_id: '1', frame_id: '1', parent_artifact_id: '0', creator_event_id: '0',
    execution_context_id: '1', capture_origin: 'dynamic_javascript', kind: 'javascript', url: 'fixture://worker-failure.js',
    mime_type: 'text/javascript', byte_size: source.length, sha256: sha, sensitive: false, content_path: `blobs/${sha}.bin`}) + '\n');
  await writeFile(join(failureRoot, 'events.jsonl'), '');
  const failureBinary = join(temporary, 'FailureBackend');
  await cp(join(host, 'Contents/MacOS/OriginTraceBackend'), failureBinary);
  const failureEndpoint = join(failureRoot, 'endpoint');
  failingBackend = spawn(failureBinary, ['--port', '0', '--endpoint-file', failureEndpoint,
    '--store', join(failureRoot, 'events.jsonl'), '--artifacts', failureRoot,
    '--ui-directory', join(host, 'Contents/Resources/research-ui'),
    '--trace-store', join(failureRoot, 'traces.jsonl'), '--signal-store', join(failureRoot, 'signals.jsonl'),
    '--api-collection', join(failureRoot, 'collection.json'), '--local-analyst', join(failureRoot, 'analyst.json')],
  {cwd: temporary, stdio: 'ignore'});
  const failureURL = await waitForFile(failureEndpoint, failingBackend);
  await chmod(failureBinary, 0o644);
  const failure = await fetch(`${failureURL}/api/analysis/vm`);
  assert.equal(failure.status, 503);
  assert.match((await failure.json()).error, /analysis-worker-failed: spawn \(1 omitted artifacts\)/);

  const missingBrave = join(temporary, 'no-brave', 'Brave Browser Development.app', 'Contents', 'MacOS', 'Brave Browser Development');
  const derived = join(root, 'build/rendered-ui-derived');
  log += await run('xcodebuild', ['build-for-testing', '-project', join(harness, 'OriginTraceRenderedUITests.xcodeproj'),
    '-scheme', 'OriginTraceRenderedUITests', '-destination', destination, '-derivedDataPath', derived],
  {timeout: 600000, label: 'XCTest bundle build'});
  const products = join(derived, 'Build/Products');
  const generated = (await readdir(products)).find(name => name.endsWith('.xctestrun') && !name.startsWith('hosted'));
  assert(generated, 'xcodebuild did not produce an xctestrun description');
  // Host the bundle in the packaged app. This is the documented xctestrun
  // format; it replaces only the host, arguments and environment.
  const plist = join(products, generated);
  const description = JSON.parse(execFileSync('plutil', ['-convert', 'json', '-o', '-', plist], {encoding: 'utf8'}));
  const target = description.OriginTraceRenderedUITests;
  assert(target, 'Unexpected xctestrun target name');
  const executable = join(host, 'Contents/MacOS/OriginTrace');
  Object.assign(target, {
    TestHostPath: host,
    IsAppHostedTestBundle: true,
    // The bundled reb:// workspace reads and writes the same synthetic stores
    // as the harness backend, never the user's Application Support files.
    CommandLineArguments: ['--ui-url', uiURL, '--api-collection', stores.apiCollection, '--local-analyst', stores.localAnalyst],
    EnvironmentVariables: {
      ...(maximumHeight === undefined ? {} : {REB_RENDERED_UI_MAX_HEIGHT: maximumHeight}),
      REB_DISABLE_AUTOMATIC_LIVE_SESSION: '1',
      // An explicit Brave that does not exist: Start in the start panel fails
      // at once and nothing launches, whatever Brave this machine has.
      REB_BRAVE_BINARY: missingBrave,
      REB_JS_INVOCATION_SITE_STORE: stores.invocationSites,
      REB_AGENT_PROVIDER_BASE_URL: agentProviderURL,
      REB_AGENT_TRANSCRIPT_DIR: join(temporary, 'agent-transcripts'),
      // None of the researcher's CLIs runs. Claude is the stand-in CLI that
      // make app-build builds (tools/agent-cli-stand-in.swift); no Grok CLI is
      // found, so its account line reads the same on every machine.
      REB_AGENT_CLAUDE_CLI: join(root, 'build/check-agent-core'),
      REB_AGENT_GROK_CLI: join(temporary, 'no-grok-cli'),
      REB_AGENT_CLI_DIR: join(temporary, 'agent-cli'),
      REB_RENDERED_UI_BACKEND_PID: String(backend.pid),
      REB_RENDERED_UI_FAILURE_URL: failureURL,
      REB_RENDERED_UI_FAILURE_BINARY: failureBinary,
      REB_RENDERED_UI_OUTPUT: join(report, 'screenshots'),
      REB_RENDERED_UI_PROBES: join(harness, 'probes.js'),
      REB_RENDERED_UI_EXPECT: JSON.stringify({hostileUrl: HOSTILE_URL, hostileUrlMarker: HOSTILE_URL_MARKER, hostileSourceUrl: HOSTILE_SOURCE_URL,
        hostileSourceMarker: HOSTILE_SOURCE_MARKER, hostileBytecodeMarkup: HOSTILE_BYTECODE_MARKUP,
        requestCount: SYNTHETIC_REQUEST_COUNT, sourceLines: SOURCE_LINE_COUNT, namedGapReasons: NAMED_GAP_REASONS,
        requestBodyHost: REQUEST_BODY_HOST, requestBodyTarget: REQUEST_BODY_TARGET, requestBodyMarker: REQUEST_BODY_MARKER,
        metadataBodyHost: METADATA_BODY_HOST, responseBodyHost: RESPONSE_BODY_HOST, responseBodyMarker: RESPONSE_BODY_MARKER,
        headerValueMarker: HEADER_VALUE_MARKER, cookieValueMarker: COOKIE_VALUE_MARKER,
        invocationArtifactId: INVOCATION_ARTIFACT_ID, minifiedArtifactId: MINIFIED_ARTIFACT_ID,
        invocationSiteStore: stores.invocationSites}),
    },
  });
  target.TestingEnvironmentVariables = {...target.TestingEnvironmentVariables,
    DYLD_INSERT_LIBRARIES: '__PLATFORMS__/MacOSX.platform/Developer/usr/lib/libXCTestBundleInject.dylib',
    XCInjectBundleInto: executable};
  // The launch pass opens the app as a researcher does, which the harness
  // page's --ui-url would prevent, so it runs alone in its own host launch.
  const launchTest = 'testLaunchStartsWithoutStartPanel';
  const launchDescription = JSON.parse(JSON.stringify(description));
  if (only) target.OnlyTestIdentifiers = [`OriginTraceRenderedUITests/${only}`];
  else target.SkipTestIdentifiers = [`OriginTraceRenderedUITests/${launchTest}`];
  const hosted = join(products, 'hosted-origin-trace.xctestrun');
  await writeFile(hosted, '');
  execFileSync('plutil', ['-convert', 'xml1', '-o', hosted, '-'], {input: JSON.stringify(description)});
  const launchTarget = launchDescription.OriginTraceRenderedUITests;
  // No --ui-url and no explicit evidence-store argument, so the app takes its
  // automatic live-session path. Its stores come from the environment, as a
  // researcher's overrides would, and do not exist yet, as on a first launch:
  // the bundled workspace reports an existing event store as live capture, so
  // only an absent one shows the idle offline workspace beside the panel.
  const launchStores = join(temporary, 'launch-stores');
  await mkdir(launchStores, {recursive: true});
  launchTarget.CommandLineArguments = ['--api-collection', join(launchStores, 'api-collection.json'),
    '--local-analyst', join(launchStores, 'local-analyst.json')];
  launchTarget.EnvironmentVariables = {...launchTarget.EnvironmentVariables,
    REB_DISABLE_AUTOMATIC_LIVE_SESSION: '0', REB_RENDERED_UI_LAUNCH: '1',
    REB_EVENT_STORE: join(launchStores, 'events.jsonl'), REB_ORIGIN_TRACE_STORE: join(launchStores, 'origin-trace.jsonl'),
    REB_REQUEST_SIGNAL_STORE: join(launchStores, 'request-signals.jsonl'), REB_ARTIFACT_STORE: join(launchStores, 'artifacts'),
    REB_JS_INVOCATION_SITE_STORE: join(launchStores, 'js-invocation-sites-v1.json')};
  launchTarget.OnlyTestIdentifiers = [`OriginTraceRenderedUITests/${launchTest}`];
  const hostedLaunch = join(products, 'hosted-origin-trace-launch.xctestrun');
  await writeFile(hostedLaunch, '');
  execFileSync('plutil', ['-convert', 'xml1', '-o', hostedLaunch, '-'], {input: JSON.stringify(launchDescription)});

  const passes = [
    ...(only === launchTest ? [] : [{xctestrun: hosted, result: join(report, 'rendered-ui.xcresult'), label: 'Rendered UI acceptance'}]),
    ...(!only || only === launchTest ? [{xctestrun: hostedLaunch, result: join(report, 'rendered-ui-launch.xcresult'), label: 'Rendered UI launch'}] : []),
  ];
  try {
    for (const [index, pass] of passes.entries()) {
      // Each pass starts its own host; never let one still running take the
      // launch pass's reopen. Only the app executable: the harness backend
      // runs from the same bundle and serves both passes.
      if (index > 0) {
        try { execFileSync('pkill', ['-f', `${join(temporary, 'Origin Trace.app/Contents/MacOS/OriginTrace').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}( |$)`]); } catch {}
      }
      log += await run('xcodebuild', ['test-without-building', '-xctestrun', pass.xctestrun, '-destination', destination,
        '-resultBundlePath', pass.result, '-parallel-testing-enabled', 'NO'], {timeout: 900000, label: pass.label});
    }
  } catch (error) {
    log += error.output ?? '';
    throw error;
  } finally {
    await writeFile(join(report, 'backend.log'), backendLog);
  }
  if (!only || only === 'test0AgentPanel') {
    // The Claude model asks with the refusal-fallback beta, as `/v1/messages?beta=true`.
    const asked = agentRequests.filter(entry => new URL(entry.path, 'http://stand-in').pathname === '/v1/messages');
    assert(asked.length >= 4, `The agent must reach the local stand-in provider for each turn: ${asked.length}`);
    assert(asked.every(entry => !entry.headers['x-api-key'] && !entry.headers.authorization), 'A stand-in provider receives no key');
    assert(!asked.some(entry => entry.body.includes(HOSTILE_SOURCE_MARKER)), 'Captured source must not reach the provider');
    const transcripts = await readdir(join(temporary, 'agent-transcripts'));
    assert(transcripts.length > 0, 'The agent writes a local transcript');
    for (const name of transcripts) assert.equal((await stat(join(temporary, 'agent-transcripts', name))).mode & 0o777, 0o600, 'The transcript is user-only');
    assert.equal((await stat(join(temporary, 'agent-transcripts'))).mode & 0o777, 0o700, 'The transcript directory is user-only');
    log += '\nRENDERED_UI_AGENT_CHECK transcript and provider assertions passed\n';
  }
  const executed = [...log.matchAll(/Test Case '-\[OriginTraceRenderedUITests\.OriginTraceRenderedUITests (\w+)\]' passed/g)].map(match => match[1]);
  assert(executed.length > 0, 'No rendered UI test executed');
  const screenshots = (await readdir(join(report, 'screenshots'))).filter(name => name.endsWith('.png')).sort();
  for (const name of screenshots) {
    const bytes = await readFile(join(report, 'screenshots', name));
    assert(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), `Invalid PNG ${name}`);
  }
  await writeFile(join(report, 'result.json'), JSON.stringify({packagedApp: true, hostedXCTest: true, cdp: false,
    tests: executed, screenshots}, null, 2) + '\n');
  console.log(`PASS rendered packaged-app UI: ${executed.join(', ')} (${screenshots.length} screenshots in build/rendered-ui-qa/screenshots)`);
} finally {
  await writeFile(join(report, 'xcodebuild.log'), log).catch(() => {});
  if (failingBackend && failingBackend.exitCode === null) failingBackend.kill('SIGTERM');
  agentStandIn?.close();
  if (backend && backend.exitCode === null) backend.kill('SIGTERM');
  // Stop any app instance still running from this relocated copy.
  try { execFileSync('pkill', ['-f', join(temporary, 'Origin Trace.app/Contents/MacOS/')]); } catch {}
  await rm(temporary, {recursive: true, force: true});
}
