import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {cp, mkdir, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {analystFixtureLibrary} from './check-analyst-editor.mjs';
import {notebookModels} from './check-investigation-notebook.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const scenarios = ['clean-close', 'clean-quit', 'file-return-close', 'folder-escape-quit',
  'saving-quit', 'pending-close', 'missing-close', 'throwing-quit', 'malformed-close',
  'repeated-close-quit', 'navigation-close', 'untrusted-close', 'late-callback', 'timeout-close'];

const repeatedCloseTrace = [
  'close-request 1', 'close-request 2', 'quit-queued 1', 'quit-observed 1',
  'decision-ready 1', 'stay-click', 'stay-dismissed', 'draft-preserved queries=1',
  'close-request 1', 'close-request 2', 'quit-queued 2', 'quit-observed 2',
  'decision-ready 2', 'close-anyway-click',
];

function checkRepeatedCloseTrace(output) {
  const prefix = 'NATIVE_CLOSE_TRACE repeated-close-quit ';
  const actual = output.split(/\r?\n/).filter(line => line.startsWith(prefix))
    .map(line => line.slice(prefix.length));
  assert.deepEqual(actual, repeatedCloseTrace,
    'Both queued Quits must reach AppKit before their decision; Stay must preserve the draft');
}

// This is an acceptance gate, not a source-pattern substitute for AppKit.
export async function checkNativeCloseContract() {
  const build = await readFile(join(root, 'scripts/build-research-app.sh'), 'utf8');
  for (const name of ['NativeCloseGuard.swift', 'NativeCloseGuardSmoke.swift']) assert(build.includes(name));
  const app = await readFile(join(root, 'apps/research-ui/macos/OriginTraceApp.swift'), 'utf8');
  assert(app.includes('window.delegate = closeGuard'));
  assert(app.includes('closeGuard?.applicationShouldTerminate()'));
  assert(app.includes('closeSmoke?.didCheckTermination(reply)'));
  const smoke = await readFile(join(root, 'apps/research-ui/macos/NativeCloseGuardSmoke.swift'), 'utf8');
  assert(smoke.includes('NSApp.postEvent(event, atStart: false)'));
  assert(/perform\(#selector\(dispatchDeferredQuit\(_:\)\), with: nil,\s*afterDelay: 0, inModes: \[\.default\]\)/.test(smoke),
    'Repeated Quit must wait for default mode, outside the previous termination modal loop');
  const dispatcher = smoke.slice(smoke.indexOf('@objc private func dispatchDeferredQuit'),
    smoke.indexOf('private func chooseStay()'));
  assert(dispatcher.includes('NSApp.terminate(nil)'));
  assert(!/NSApp\.terminate\s*\(/.test(smoke.replace(dispatcher, '')),
    'Smoke Quit must not enter termination synchronously from the WebKit completion');
  const trace = events => events.map(event => `NATIVE_CLOSE_TRACE repeated-close-quit ${event}`).join('\n');
  checkRepeatedCloseTrace(trace(repeatedCloseTrace));
  for (const event of repeatedCloseTrace) {
    assert.throws(() => checkRepeatedCloseTrace(trace(repeatedCloseTrace.filter(item => item !== event))));
  }
  const earlyStay = [...repeatedCloseTrace];
  [earlyStay[3], earlyStay[5]] = [earlyStay[5], earlyStay[3]];
  assert.throws(() => checkRepeatedCloseTrace(trace(earlyStay)), 'Reject Stay before Quit delivery');
  console.log('PASS native close trace validator rejects missing and reordered lifecycle evidence');
  const guard = await readFile(join(root, 'apps/research-ui/macos/NativeCloseGuard.swift'), 'utf8');
  assert(guard.includes('alert.window.preventsApplicationTerminationWhenModal = false'),
    'The guard-owned sheet must route Quit through the coalesced decision');
  const plist = await readFile(join(root, 'apps/research-ui/macos/Info.plist'), 'utf8');
  assert(/<key>NSSupportsSuddenTermination<\/key>\s*<false\/>/.test(plist),
    'Sudden termination must not bypass the native close delegate');
  assert(!/enableSuddenTermination\s*\(/.test(app + guard));
  const frontend = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  assert(frontend.includes('function analystHasUnsavedWork()'));
  console.log('PASS native close guard build wiring and frontend dependency (not lifecycle acceptance)');
}

async function runScenario(app, directory, name, attempt = 1) {
  const label = `${name}-${attempt}`;
  const stores = join(directory, label);
  const diagnostics = join(root, 'build/native-close-qa', label);
  await mkdir(diagnostics, {recursive: true});
  await mkdir(stores);
  const {empty, validateLibrary} = await notebookModels(root);
  const library = analystFixtureLibrary(empty);
  assert(validateLibrary(library));
  await writeFile(join(stores, 'analyst.json'), JSON.stringify(library));
  const args = ['--store', join(stores, 'events.jsonl'), '--trace-store', join(stores, 'traces.jsonl'),
    '--signal-store', join(stores, 'signals.jsonl'), '--artifacts', join(stores, 'artifacts'),
    '--api-collection', join(stores, 'collection.json'), '--local-analyst', join(stores, 'analyst.json')];
  const child = spawn(join(app, 'Contents/MacOS/OriginTrace'), args, {
    cwd: directory,
    env: {...process.env, REB_APP_SMOKE_TEST: '1', REB_APP_SMOKE_NATIVE_CLOSE: name,
      REB_APP_SMOKE_NATIVE_CLOSE_OUTPUT: diagnostics,
      REB_APP_SMOKE_LIVE_FAILURE: '0', REB_DISABLE_AUTOMATIC_LIVE_SESSION: '1'},
  });
  let output = '';
  let timer;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
    output = (output + chunk).slice(-128 * 1024);
  });
  try {
    await new Promise((resolveExit, reject) => {
      timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`${label}: native lifecycle timed out\n${output}`));
      }, 30000);
      child.once('error', reject);
      child.once('close', (code, signal) => code === 0 ? resolveExit()
        : reject(new Error(`${label}: app exited ${code}/${signal}\n${output}`)));
    });
  } finally {
    clearTimeout(timer);
    await writeFile(join(diagnostics, 'lifecycle.log'), output);
  }
  assert(!output.includes('SMOKE_ERROR'), output);
  assert.deepEqual([...output.matchAll(/^NATIVE_CLOSE_OK (.+)$/gm)].map(match => match[1]), [name], output);
  if (name === 'repeated-close-quit') checkRepeatedCloseTrace(output);
  console.log(`PASS packaged WKWebView/AppKit lifecycle: ${label}`);
}

await checkNativeCloseContract();
if (!process.argv.includes('--contract-only')) {
  assert.equal(process.platform, 'darwin', 'Native close lifecycle acceptance requires macOS/AppKit');
  const temporary = await mkdtemp(join(tmpdir(), 'reb-native-close-'));
  await mkdir(join(root, 'build/native-close-qa'), {recursive: true});
  try {
    const app = join(temporary, 'Origin Trace.app');
    await cp(join(root, 'build/Origin Trace.app'), app, {recursive: true});
    const failures = [];
    for (const scenario of scenarios) {
      // Fresh processes exercise the race repeatedly; no failed attempt is retried or hidden.
      const attempts = scenario === 'repeated-close-quit' ? 5 : 1;
      for (let attempt = 1; attempt <= attempts; attempt++) {
        try { await runScenario(app, temporary, scenario, attempt); }
        catch (error) { failures.push(error); console.error(`FAIL packaged native lifecycle: ${scenario}-${attempt}`); }
      }
    }
    if (failures.length) throw new AggregateError(failures, `${failures.length} native lifecycle scenarios failed`);
  } finally {
    await rm(temporary, {recursive: true, force: true});
  }
}
