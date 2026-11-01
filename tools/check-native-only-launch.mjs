import assert from 'node:assert/strict';
import {readFile, access, mkdir, mkdtemp, writeFile, rm, symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {execFileSync, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
const root = fileURLToPath(new URL('..', import.meta.url));
const read = name => readFile(join(root, name), 'utf8');
const launch = await read('scripts/run-live-session.sh');
assert.doesNotMatch(launch, /--remote-debugging-(?:port|pipe)|--devtools-active-port|--debugger-transport|--capture-network-content/);
assert.match(launch, /vm_capture_mode="native-stealth"/);
assert.match(launch, /--native-console-live-directory/);
for (const env of [{REB_CDP_NETWORK_CAPTURE:'1'}, {REB_DEBUGGER_TRANSPORT_BINARY:'/tmp/retired-cdp'}]) {
  const result = spawnSync('bash', [join(root, 'scripts/run-live-session.sh')], {env:{...process.env,...env}, encoding:'utf8'});
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /CDP capture and debugger transport were removed/);
}
for (const file of ['apps/reb-debugger-transport/main.cpp','src/transport/debugger_transport.cpp','include/reb/debugger_transport.hpp']) {
  await assert.rejects(access(join(root, file)), {code:'ENOENT'});
}
for (const file of ['Makefile','mk/native.mk','mk/workflows.mk']) {
  assert.doesNotMatch(await read(file), /reb-debugger-transport|DEBUGGER_TRANSPORT_BINARY|debugger-transport:/);
}
const pack = await read('scripts/build-research-app.sh');
assert.doesNotMatch(pack, /cp[^\n]*OriginTraceDebuggerTransport/);
assert.match(pack, /rm -f "\$\{macos_path\}\/OriginTraceDebuggerTransport"/);
assert.match(pack, /OriginTraceNativeConsole/);
console.log('PASS native-only launch: no CDP flags, retired options rejected, transport absent, native console preserved');

const section = (start, end) => {
  const from = launch.indexOf(start);
  const to = launch.indexOf(end, from + start.length);
  assert(from >= 0 && to > from, `Missing live launcher boundary: ${start}`);
  return launch.slice(from, to);
};
// The V8 flag list is assembled before any helper starts and joined into the
// Brave arguments at launch; run both pieces together.
const flagsCode = section('native_js_flags=()', 'require_brave_v8_flags() {') +
  section('if [[ ${#native_js_flags[@]} -gt 0 ]]; then\n  brave_arguments+=', 'if [[ "${capture_canvas_images}"');
for (const quiet of [0, 1]) for (const dispatch of [0, 1]) for (const indirect of [0, 1]) {
  const result = spawnSync('bash', ['-c', `set -eu; brave_arguments=(); native_quiet_mode=${quiet}; native_wasm_dispatch=${dispatch}; native_wasm_call_indirect=${indirect}; native_guest_adapter=""; ${flagsCode}
printf '%s' "${'${brave_arguments[*]-}'}"`], {encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const expected = [quiet ? '--reb-ignore-debugger-statements' : '', dispatch ? '--reb-wasm-br-table-dispatch' : '',
    indirect ? '--reb-wasm-call-indirect-dispatch' : ''].filter(Boolean);
  assert.equal(result.stdout, expected.length ? '--js-flags=' + expected.join(' ') : '');
}
for (const [variable, options] of [['REB_NATIVE_WASM_DISPATCH', {REB_NATIVE_WASM_DISPATCH:'invalid'}],
  ['REB_NATIVE_WASM_DISPATCH', {REB_NATIVE_WASM_DISPATCH:'1',REB_CAPTURE_CATEGORY_MASK:'1'}],
  ['REB_NATIVE_WASM_CALL_INDIRECT', {REB_NATIVE_WASM_CALL_INDIRECT:'invalid'}],
  ['REB_NATIVE_WASM_CALL_INDIRECT', {REB_NATIVE_WASM_CALL_INDIRECT:'1',REB_CAPTURE_CATEGORY_MASK:'1'}]]) {
  const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,...options},encoding:'utf8'});
  assert.equal(result.status,2,result.stderr);
  assert.match(result.stderr,new RegExp(variable));
}
console.log('PASS native Wasm launch is explicit opt-in, category-gated, and composes with quiet mode');

const adapterDirectory = await mkdtemp(join(tmpdir(), 'reb-native-adapter-'));
try {
  const adapterPath = join(adapterDirectory, 'adapter with spaces.json');
  await writeFile(adapterPath, '{}');
  for (const extra of [
    {REB_NATIVE_WASM_GUEST_ADAPTER:adapterPath},
    {REB_NATIVE_WASM_GUEST_ADAPTER:'relative.json', REB_NATIVE_WASM_DISPATCH:'1'},
    {REB_NATIVE_WASM_GUEST_ADAPTER:join(adapterDirectory,'missing.json'), REB_NATIVE_WASM_DISPATCH:'1'},
    {REB_NATIVE_WASM_GUEST_ADAPTER:adapterDirectory, REB_NATIVE_WASM_DISPATCH:'1'},
  ]) {
    const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',...extra}, encoding:'utf8'});
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /REB_NATIVE_WASM_GUEST_ADAPTER/);
  }
  for (const size of [0,8193]) {
    await writeFile(adapterPath, Buffer.alloc(size,32));
    const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'1',REB_NATIVE_WASM_GUEST_ADAPTER:adapterPath},encoding:'utf8'});
    assert.equal(result.status,2,result.stderr);
    assert.match(result.stderr,/between 1 and 8192/);
  }
  // Native browser code owns strict recipe validation; the shell only gates
  // opt-in, file bounds and propagation as a single argument.
  await writeFile(adapterPath,'{}');
  const result = spawnSync('bash',['-c',`set -eu; brave_arguments=(); native_quiet_mode=1; native_wasm_dispatch=1; native_wasm_call_indirect=0; native_guest_adapter="$TEST_ADAPTER"; ${flagsCode}
    printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_ADAPTER:adapterPath},encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split('\n'), ['--js-flags=--reb-ignore-debugger-statements --reb-wasm-br-table-dispatch --reb-wasm-guest-capture','--reb-wasm-guest-adapter='+adapterPath]);
} finally {await rm(adapterDirectory,{recursive:true,force:true});}
console.log('PASS native guest adapter opt-in, bounded file preflight and quoted path propagation');

const sitesDirectory = await mkdtemp(join(tmpdir(), 'reb-native-js-sites-'));
try {
  const sitesPath = join(sitesDirectory, 'js sites.json');
  await writeFile(sitesPath, '{}');
  for (const extra of [
    {REB_NATIVE_JS_DISPATCH_SITES:sitesPath, REB_CAPTURE_CATEGORY_MASK:'1'},
    {REB_NATIVE_JS_DISPATCH_SITES:'relative.json'},
    {REB_NATIVE_JS_DISPATCH_SITES:join(sitesDirectory,'missing.json')},
    {REB_NATIVE_JS_DISPATCH_SITES:sitesDirectory},
  ]) {
    const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',...extra}, encoding:'utf8'});
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /REB_NATIVE_JS_DISPATCH_SITES/);
  }
  for (const size of [0,4097]) {
    await writeFile(sitesPath, Buffer.alloc(size,32));
    const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',REB_NATIVE_JS_DISPATCH_SITES:sitesPath},encoding:'utf8'});
    assert.equal(result.status,2,result.stderr);
    assert.match(result.stderr,/between 1 and 4096/);
  }
  // Native browser code owns canonical site-file validation; the shell gates
  // the opt-in and file bounds and passes the path as one argument.
  await writeFile(sitesPath,'{}');
  for (const [quiet, expected] of [[0, '--js-flags=--reb-js-dispatch-capture'],
                                   [1, '--js-flags=--reb-ignore-debugger-statements --reb-js-dispatch-capture']]) {
    const result = spawnSync('bash',['-c',`set -eu; brave_arguments=(); native_quiet_mode=${quiet}; native_wasm_dispatch=0; native_wasm_call_indirect=0; native_guest_adapter=""; native_js_dispatch_sites="$TEST_SITES"; ${flagsCode}
      printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_SITES:sitesPath},encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    assert.deepEqual(result.stdout.trimEnd().split('\n'), [expected,'--reb-js-dispatch-sites='+sitesPath]);
  }
  const combined = spawnSync('bash',['-c',`set -eu; brave_arguments=(); native_quiet_mode=1; native_wasm_dispatch=1; native_wasm_call_indirect=0; native_guest_adapter="$TEST_SITES"; native_js_dispatch_sites="$TEST_SITES"; ${flagsCode}
    printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_SITES:sitesPath},encoding:'utf8'});
  assert.equal(combined.status,0,combined.stderr);
  assert.deepEqual(combined.stdout.trimEnd().split('\n'), [
    '--js-flags=--reb-ignore-debugger-statements --reb-wasm-br-table-dispatch --reb-wasm-guest-capture --reb-js-dispatch-capture',
    '--reb-wasm-guest-adapter='+sitesPath, '--reb-js-dispatch-sites='+sitesPath]);
} finally {await rm(sitesDirectory,{recursive:true,force:true});}
console.log('PASS native JS dispatch sites opt-in, VM-category gate, bounded file preflight and single js-flags merge');

// V8 ignores an unknown --js-flags entry and every later one, so the real
// launcher must refuse a Brave build that lacks a requested flag before any
// helper or browser starts. Synthetic bundles and recording helpers only.
const preflight = await mkdtemp(join(tmpdir(), 'reb-v8-flag-preflight-'));
try {
  const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
  const receipts = join(preflight, 'receipts');
  const scans = join(preflight, 'scans');
  const bin = join(preflight, 'bin');
  await mkdir(bin);
  // Record every scan the launcher runs, then run the system grep unchanged.
  const systemGrep = execFileSync('sh', ['-c', 'command -v grep'], {encoding:'utf8'}).trim();
  await writeFile(join(bin, 'grep'), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${quote(scans)}\nexec ${quote(systemGrep)} "$@"\n`, {mode:0o755});
  const recorder = role => `#!/bin/sh\nprintf '%s\\n' ${quote(role)} >> ${quote(receipts)}\nexit 3\n`;
  const helpers = {};
  for (const [variable, role] of [['REB_BROKER_BINARY','broker'], ['REB_ARTIFACT_RECEIVER_BINARY','receiver'],
    ['REB_HEAP_SNAPSHOT_BINARY','heap-snapshot'], ['REB_DECODER_BINARY','decoder'],
    ['REB_ORIGIN_TRACE_BACKEND','backend'], ['REB_VM_ANALYZER','analyzer']]) {
    helpers[variable] = join(bin, role);
    await writeFile(helpers[variable], recorder(role), {mode:0o755});
  }
  const allFlags = ['reb_ignore_debugger_statements', 'reb_wasm_br_table_dispatch',
    'reb_wasm_call_indirect_dispatch', 'reb_wasm_guest_capture', 'reb_js_dispatch_capture'];
  // V8's flag table keeps each name as a NUL-terminated string among unrelated bytes.
  const v8Image = names => Buffer.concat([Buffer.alloc(4096, 0xcf),
    ...names.map(name => Buffer.from(`\0${name}\0`)), Buffer.alloc(4096, 0xfa)]);
  let fixtures = 0;
  const braveApp = async ({framework = [], libv8 = null, frameworks = true} = {}) => {
    const output = join(preflight, `output ${fixtures++}`);
    const bundle = join(output, 'Brave Browser Development.app');
    const executable = join(bundle, 'Contents/MacOS/Brave Browser Development');
    await mkdir(dirname(executable), {recursive:true});
    await writeFile(executable, recorder('brave'), {mode:0o755});
    if (frameworks) {
      // Mirror the real versioned framework, reached through its symlinks.
      const directory = join(bundle, 'Contents/Frameworks/Brave Browser Development Framework.framework');
      await mkdir(join(directory, 'Versions/151.1.95.0'), {recursive:true});
      await writeFile(join(directory, 'Versions/151.1.95.0/Brave Browser Development Framework'), v8Image(framework));
      await symlink('151.1.95.0', join(directory, 'Versions/Current'));
      await symlink('Versions/Current/Brave Browser Development Framework', join(directory, 'Brave Browser Development Framework'));
    }
    // Component builds keep libv8.dylib in the output directory beside the app.
    if (libv8) await writeFile(join(output, 'libv8.dylib'), v8Image(libv8));
    return {executable, output};
  };
  const adapterPath = join(preflight, 'adapter.json');
  const sitesPath = join(preflight, 'sites.json');
  await writeFile(adapterPath, '{}');
  await writeFile(sitesPath, '{}');
  const switches = {
    none: {},
    packaged: {REB_NATIVE_QUIET_MODE:'1', REB_NATIVE_WASM_DISPATCH:'1', REB_NATIVE_WASM_CALL_INDIRECT:'1'},
    every: {REB_NATIVE_QUIET_MODE:'1', REB_NATIVE_WASM_DISPATCH:'1', REB_NATIVE_WASM_CALL_INDIRECT:'1',
      REB_NATIVE_WASM_GUEST_ADAPTER:adapterPath, REB_NATIVE_JS_DISPATCH_SITES:sitesPath},
  };
  const lines = async file => {
    try { return (await readFile(file, 'utf8')).trimEnd().split('\n'); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  const launchWith = async (executable, requested) => {
    await rm(receipts, {force:true});
    await rm(scans, {force:true});
    const result = spawnSync('bash', [join(root, 'scripts/run-live-session.sh')], {encoding:'utf8', env:{...process.env, ...helpers,
      PATH:`${bin}:${process.env.PATH}`, REB_BRAVE_BINARY:executable, REB_EMBEDDED_SESSION:'0', REB_ORIGIN_TRACE_APP:preflight,
      REB_LIVE_SESSION_ROOT:join(preflight, 'sessions'), REB_API_COLLECTION_STORE:join(preflight, 'collection.json'),
      REB_LOCAL_ANALYST_STORE:join(preflight, 'analyst.json'), REB_ACTIVE_ENDPOINT_FILE:join(preflight, 'active.endpoint'),
      REB_CAPTURE_CATEGORY_MASK:'4095', REB_NATIVE_QUIET_MODE:'0', REB_NATIVE_WASM_DISPATCH:'0',
      REB_NATIVE_WASM_CALL_INDIRECT:'0', REB_NATIVE_WASM_GUEST_ADAPTER:'', REB_NATIVE_JS_DISPATCH_SITES:'', ...requested}});
    return {...result, receipts: await lines(receipts), scans: await lines(scans)};
  };
  const refused = (result, executable, flag) => {
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [`REB_LIVE_SESSION_FAILURE: Brave at ${executable} ` +
      `does not define the V8 flag ${flag}, so it would ignore that flag and every later --js-flags entry and ` +
      'record none of their evidence. Rebuild Brave from this checkout, or use the Brave release that matches ' +
      'this Origin Trace build.'], 'A refusal names its cause and leaves nothing to clean up');
    assert.deepEqual(result.receipts, [], 'A refused build must start no helper and no browser');
  };
  // Passing the preflight reaches the first helper, which exits at once.
  const accepted = (result, requestedCount, scanned) => {
    assert.equal(result.status, 1, result.stderr);
    assert.doesNotMatch(result.stderr, /does not define the V8 flag/);
    assert.match(result.stderr, /REB_LIVE_SESSION_FAILURE: Event broker (?:stopped during startup|socket did not become ready)/);
    assert.deepEqual(result.receipts, ['broker']);
    assert.equal(result.scans.length, requestedCount, result.scans.join('\n'));
    for (const scan of result.scans) for (const file of scanned) assert(scan.includes(file), `${file} was not scanned: ${scan}`);
  };

  // A build from before the dispatch patch: quiet mode exists, dispatch does not.
  const stale = await braveApp({framework: ['reb_ignore_debugger_statements']});
  refused(await launchWith(stale.executable, switches.packaged), stale.executable, '--reb-wasm-br-table-dispatch');
  // The first missing flag in launch order is named, even late in the list.
  const noJs = await braveApp({framework: allFlags.filter(name => name !== 'reb_js_dispatch_capture')});
  refused(await launchWith(noJs.executable, switches.every), noJs.executable, '--reb-js-dispatch-capture');
  refused(await launchWith(noJs.executable, {...switches.every, REB_NATIVE_QUIET_MODE:'0'}), noJs.executable, '--reb-js-dispatch-capture');
  // No V8-bearing file at all is a refusal, not an unchecked launch.
  const bare = await braveApp({frameworks: false});
  const bareResult = await launchWith(bare.executable, switches.packaged);
  refused(bareResult, bare.executable, '--reb-ignore-debugger-statements');
  assert.deepEqual(bareResult.scans, []);
  console.log('PASS stale Brave refused before any helper or browser starts, naming the first undefined V8 flag');

  const frameworkPath = 'Contents/Frameworks/Brave Browser Development Framework.framework/Brave Browser Development Framework';
  const release = await braveApp({framework: allFlags});
  accepted(await launchWith(release.executable, switches.every), 5, [frameworkPath]);
  accepted(await launchWith(release.executable, switches.packaged), 3, [frameworkPath]);
  const component = await braveApp({libv8: allFlags});
  accepted(await launchWith(component.executable, switches.every), 5, [frameworkPath, join(component.output, 'libv8.dylib')]);
  // An executable outside an app bundle is searched itself.
  const standalone = join(preflight, 'standalone-brave');
  await writeFile(standalone, `${recorder('brave')}# ${allFlags.join(' ')}\n`, {mode:0o755});
  accepted(await launchWith(standalone, switches.packaged), 3, [standalone]);
  console.log('PASS release framework, component libv8.dylib and standalone builds that define every flag pass the preflight');

  for (const fixture of [stale, bare]) accepted(await launchWith(fixture.executable, switches.none), 0, []);
  console.log('PASS no V8 flag preflight runs when no native V8 flag is requested');
} finally {await rm(preflight,{recursive:true,force:true});}
