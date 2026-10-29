#!/usr/bin/env node
// Rendered UI acceptance on the native macOS product path. A hosted XCTest
// bundle runs inside a relocated copy of the packaged Origin Trace app and
// drives its production WKWebView with native AppKit pointer and key events.
// The UI is served by the packaged backend from a bounded synthetic session
// that includes events emitted by the real C++ native Wasm encoders.
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildEvidence, HOSTILE_BYTECODE_MARKUP, HOSTILE_SOURCE_MARKER, HOSTILE_SOURCE_URL, HOSTILE_URL, HOSTILE_URL_MARKER, SOURCE_LINE_COUNT,
  SYNTHETIC_REQUEST_COUNT} from './origin-trace-rendered-ui/evidence-fixture.mjs';

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
const goldenStores = {guestStore: join(root, 'build/native-golden/guest-evidence'), dispatchStore: join(root, 'build/native-golden/wasm-evidence')};
for (const required of [app, join(root, 'build/sessions/demo.jsonl'), ...Object.values(goldenStores).map(store => join(store, 'manifest.jsonl'))]) {
  assert(existsSync(required), `Missing ${required}; run make app-build e2e native-wasm-golden-check`);
}

// Full Xcode provides XCTest. Respect an explicit DEVELOPER_DIR, otherwise use
// the selected developer directory or the standard Xcode location without
// changing the global selection.
function developerDirectory() {
  const candidates = [process.env.DEVELOPER_DIR, execFileSync('xcode-select', ['-p'], {encoding: 'utf8'}).trim(),
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
    '--local-analyst', stores.localAnalyst, '--decoder', join(host, 'Contents/MacOS/OriginTraceDecoder')],
  {cwd: temporary, stdio: ['ignore', 'pipe', 'pipe']});
  let backendLog = '';
  for (const stream of [backend.stdout, backend.stderr]) stream.on('data', chunk => { backendLog = (backendLog + chunk).slice(-256 * 1024); });
  const endpoint = await waitForFile(endpointFile, backend);
  assert.match(endpoint, /^http:\/\/127\.0\.0\.1:\d+$/, 'The packaged backend must bind loopback only');
  const uiURL = `${endpoint}/?native=1&canvas_images=0`;

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
    CommandLineArguments: ['--ui-url', uiURL],
    EnvironmentVariables: {
      ...(maximumHeight === undefined ? {} : {REB_RENDERED_UI_MAX_HEIGHT: maximumHeight}),
      REB_DISABLE_AUTOMATIC_LIVE_SESSION: '1',
      REB_RENDERED_UI_OUTPUT: join(report, 'screenshots'),
      REB_RENDERED_UI_PROBES: join(harness, 'probes.js'),
      REB_RENDERED_UI_EXPECT: JSON.stringify({hostileUrl: HOSTILE_URL, hostileUrlMarker: HOSTILE_URL_MARKER, hostileSourceUrl: HOSTILE_SOURCE_URL,
        hostileSourceMarker: HOSTILE_SOURCE_MARKER, hostileBytecodeMarkup: HOSTILE_BYTECODE_MARKUP,
        requestCount: SYNTHETIC_REQUEST_COUNT, sourceLines: SOURCE_LINE_COUNT}),
    },
  });
  target.TestingEnvironmentVariables = {...target.TestingEnvironmentVariables,
    DYLD_INSERT_LIBRARIES: '__PLATFORMS__/MacOSX.platform/Developer/usr/lib/libXCTestBundleInject.dylib',
    XCInjectBundleInto: executable};
  if (only) target.OnlyTestIdentifiers = [`OriginTraceRenderedUITests/${only}`];
  const hosted = join(products, 'hosted-origin-trace.xctestrun');
  await writeFile(hosted, '');
  execFileSync('plutil', ['-convert', 'xml1', '-o', hosted, '-'], {input: JSON.stringify(description)});

  const result = join(report, 'rendered-ui.xcresult');
  try {
    log += await run('xcodebuild', ['test-without-building', '-xctestrun', hosted, '-destination', destination,
      '-resultBundlePath', result, '-parallel-testing-enabled', 'NO'], {timeout: 900000, label: 'Rendered UI acceptance'});
  } catch (error) {
    log += error.output ?? '';
    throw error;
  } finally {
    await writeFile(join(report, 'backend.log'), backendLog);
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
  if (backend && backend.exitCode === null) backend.kill('SIGTERM');
  // Stop any app instance still running from this relocated copy.
  try { execFileSync('pkill', ['-f', join(temporary, 'Origin Trace.app/Contents/MacOS/')]); } catch {}
  await rm(temporary, {recursive: true, force: true});
}
