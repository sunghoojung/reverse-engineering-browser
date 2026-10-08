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

// This is an acceptance gate, not a source-pattern substitute for AppKit.
export async function checkNativeCloseContract() {
  const build = await readFile(join(root, 'scripts/build-research-app.sh'), 'utf8');
  for (const name of ['NativeCloseGuard.swift', 'NativeCloseGuardSmoke.swift']) assert(build.includes(name));
  const app = await readFile(join(root, 'apps/research-ui/macos/OriginTraceApp.swift'), 'utf8');
  assert(app.includes('window.delegate = closeGuard'));
  assert(app.includes('closeGuard?.applicationShouldTerminate()'));
  const frontend = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  assert(frontend.includes('function analystHasUnsavedWork()'));
  console.log('PASS native close guard build wiring and frontend dependency (not lifecycle acceptance)');
}

async function runScenario(app, directory, name) {
  const stores = join(directory, name);
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
        reject(new Error(`${name}: native lifecycle timed out\n${output}`));
      }, 30000);
      child.once('error', reject);
      child.once('close', (code, signal) => code === 0 ? resolveExit()
        : reject(new Error(`${name}: app exited ${code}/${signal}\n${output}`)));
    });
  } finally {
    clearTimeout(timer);
    await writeFile(join(root, 'build/native-close-qa', `${name}.log`), output);
  }
  assert(!output.includes('SMOKE_ERROR'), output);
  assert.deepEqual([...output.matchAll(/^NATIVE_CLOSE_OK (.+)$/gm)].map(match => match[1]), [name], output);
  console.log(`PASS packaged WKWebView/AppKit lifecycle: ${name}`);
}

await checkNativeCloseContract();
if (!process.argv.includes('--contract-only')) {
  assert.equal(process.platform, 'darwin', 'Native close lifecycle acceptance requires macOS/AppKit');
  const temporary = await mkdtemp(join(tmpdir(), 'reb-native-close-'));
  await mkdir(join(root, 'build/native-close-qa'), {recursive: true});
  try {
    const app = join(temporary, 'Origin Trace.app');
    await cp(join(root, 'build/Origin Trace.app'), app, {recursive: true});
    for (const scenario of scenarios) await runScenario(app, temporary, scenario);
  } finally {
    await rm(temporary, {recursive: true, force: true});
  }
}
