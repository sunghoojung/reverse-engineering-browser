import assert from 'node:assert/strict';
import {readFile, access, mkdir, mkdtemp, realpath, writeFile, rm, symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {execFileSync, spawn, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';
const root = fileURLToPath(new URL('..', import.meta.url));
// The packaged app always runs the launcher with macOS /bin/bash 3.2.
const shell = process.platform === 'darwin' ? '/bin/bash' : 'bash';
const read = name => readFile(join(root, name), 'utf8');
const launch = await read('scripts/run-live-session.sh');
assert.doesNotMatch(launch, /--remote-debugging-(?:port|pipe)|--devtools-active-port|--debugger-transport|--capture-network-content/);
assert.match(launch, /vm_capture_mode="native-stealth"/);
assert.match(launch, /--native-console-live-directory/);
for (const env of [{REB_CDP_NETWORK_CAPTURE:'1'}, {REB_DEBUGGER_TRANSPORT_BINARY:'/tmp/retired-cdp'}]) {
  const result = spawnSync(shell, [join(root, 'scripts/run-live-session.sh')], {env:{...process.env,...env}, encoding:'utf8'});
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
const flagsCode = section('native_js_flags=()', 'locate_brave_v8_image() {') +
  section('if [[ ${#native_js_flags[@]} -gt 0 ]]; then\n  brave_arguments+=', 'if [[ "${capture_canvas_images}"');
for (const quiet of [0, 1]) for (const dispatch of [0, 1]) for (const indirect of [0, 1]) {
  const result = spawnSync(shell, ['-c', `set -eu; brave_arguments=(); native_quiet_mode=${quiet}; native_wasm_dispatch=${dispatch}; native_wasm_call_indirect=${indirect}; native_guest_adapter=""; ${flagsCode}
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
  const result = spawnSync(shell, [join(root,'scripts/run-live-session.sh')], {env:{...process.env,...options},encoding:'utf8'});
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
    const result = spawnSync(shell, [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',...extra}, encoding:'utf8'});
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /REB_NATIVE_WASM_GUEST_ADAPTER/);
  }
  for (const size of [0,8193]) {
    await writeFile(adapterPath, Buffer.alloc(size,32));
    const result = spawnSync(shell, [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'1',REB_NATIVE_WASM_GUEST_ADAPTER:adapterPath},encoding:'utf8'});
    assert.equal(result.status,2,result.stderr);
    assert.match(result.stderr,/between 1 and 8192/);
  }
  // Native browser code owns strict recipe validation; the shell only gates
  // opt-in, file bounds and propagation as a single argument.
  await writeFile(adapterPath,'{}');
  const result = spawnSync(shell,['-c',`set -eu; brave_arguments=(); native_quiet_mode=1; native_wasm_dispatch=1; native_wasm_call_indirect=0; native_guest_adapter="$TEST_ADAPTER"; ${flagsCode}
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
    const result = spawnSync(shell, [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',...extra}, encoding:'utf8'});
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /REB_NATIVE_JS_DISPATCH_SITES/);
  }
  for (const size of [0,4097]) {
    await writeFile(sitesPath, Buffer.alloc(size,32));
    const result = spawnSync(shell, [join(root,'scripts/run-live-session.sh')], {env:{...process.env,REB_NATIVE_WASM_DISPATCH:'0',REB_NATIVE_JS_DISPATCH_SITES:sitesPath},encoding:'utf8'});
    assert.equal(result.status,2,result.stderr);
    assert.match(result.stderr,/between 1 and 4096/);
  }
  // Native browser code owns canonical site-file validation; the shell gates
  // the opt-in and file bounds and passes the path as one argument.
  await writeFile(sitesPath,'{}');
  for (const [quiet, expected] of [[0, '--js-flags=--reb-js-dispatch-capture'],
                                   [1, '--js-flags=--reb-ignore-debugger-statements --reb-js-dispatch-capture']]) {
    const result = spawnSync(shell,['-c',`set -eu; brave_arguments=(); native_quiet_mode=${quiet}; native_wasm_dispatch=0; native_wasm_call_indirect=0; native_guest_adapter=""; native_js_dispatch_sites="$TEST_SITES"; ${flagsCode}
      printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_SITES:sitesPath},encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    assert.deepEqual(result.stdout.trimEnd().split('\n'), [expected,'--reb-js-dispatch-sites='+sitesPath]);
  }
  const combined = spawnSync(shell,['-c',`set -eu; brave_arguments=(); native_quiet_mode=1; native_wasm_dispatch=1; native_wasm_call_indirect=0; native_guest_adapter="$TEST_SITES"; native_js_dispatch_sites="$TEST_SITES"; ${flagsCode}
    printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_SITES:sitesPath},encoding:'utf8'});
  assert.equal(combined.status,0,combined.stderr);
  assert.deepEqual(combined.stdout.trimEnd().split('\n'), [
    '--js-flags=--reb-ignore-debugger-statements --reb-wasm-br-table-dispatch --reb-wasm-guest-capture --reb-js-dispatch-capture',
    '--reb-wasm-guest-adapter='+sitesPath, '--reb-js-dispatch-sites='+sitesPath]);
} finally {await rm(sitesDirectory,{recursive:true,force:true});}
console.log('PASS native JS dispatch sites opt-in, VM-category gate, bounded file preflight and single js-flags merge');

// V8 ignores an unknown --js-flags entry and every later one, so the real
// launcher must refuse a Brave build whose loaded V8 lacks a requested flag
// before any helper or browser starts. Synthetic bundles and recording helpers
// only; every path below is physical so it matches the launcher's resolution.
const preflight = await realpath(await mkdtemp(join(tmpdir(), 'reb-v8-flag-preflight-')));
try {
  const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
  const at = name => join(preflight, name);
  const receipts = at('receipts');
  const scans = at('scans');
  const started = at('started');
  const finished = at('finished');
  const mode = {fail: at('mode-fail'), hold: at('mode-hold'), slow: at('mode-slow')};
  const bin = at('bin');
  await mkdir(bin);
  // Record every grep the launcher runs. A flag scan can be forced to fail with
  // status 2, park until it is stopped, or finish late. Scans drop the
  // launcher's pipes so a leaked reader cannot hold this check's output open.
  const systemGrep = execFileSync('sh', ['-c', 'command -v grep'], {encoding:'utf8'}).trim();
  await writeFile(join(bin, 'grep'), `#!/bin/sh
printf '%s\\n' "$*" >> ${quote(scans)}
case "$*" in
  *' -e reb_'*)
    exec >/dev/null 2>&1
    if [ -f ${quote(mode.fail)} ]; then exit 2; fi
    if [ -f ${quote(mode.hold)} ]; then printf '%s\\n' "$$" >> ${quote(started)}; exec sleep 30; fi
    if [ -f ${quote(mode.slow)} ]; then case "$*" in *reb_ignore_debugger_statements*) ;; *) sleep 1 ;; esac; fi
    ${quote(systemGrep)} "$@"
    status=$?
    printf '%s\\n' "$*" >> ${quote(finished)}
    exit $status ;;
esac
exec ${quote(systemGrep)} "$@"
`, {mode:0o755});
  const recorder = role => `#!/bin/sh\nprintf '%s\\n' ${quote(role)} >> ${quote(receipts)}\nexit 3\n`;
  const helpers = {};
  for (const [variable, role] of [['REB_BROKER_BINARY','broker'], ['REB_ARTIFACT_RECEIVER_BINARY','receiver'],
    ['REB_HEAP_SNAPSHOT_BINARY','heap-snapshot'], ['REB_DECODER_BINARY','decoder'],
    ['REB_ORIGIN_TRACE_BACKEND','backend'], ['REB_VM_ANALYZER','analyzer']]) {
    helpers[variable] = join(bin, role);
    await writeFile(helpers[variable], recorder(role), {mode:0o755});
  }
  const allNames = ['reb_ignore_debugger_statements', 'reb_wasm_br_table_dispatch',
    'reb_wasm_call_indirect_dispatch', 'reb_wasm_guest_capture', 'reb_js_dispatch_capture'];
  // V8's flag table keeps each name as a NUL-terminated string among unrelated
  // bytes. A component framework names its re-exported library near the start.
  const image = ({names = [], marker = null} = {}) => Buffer.concat([Buffer.alloc(64, 0xcf),
    Buffer.from(marker ? `\0${marker}\0` : ''), Buffer.alloc(4096, 0xfa),
    ...names.map(name => Buffer.from(`\0${name}\0`)), Buffer.alloc(4096, 0xfa)]);
  const appName = 'Brave Browser Development';
  let fixtures = 0;
  const braveApp = async ({framework = [], marker = null, libv8 = null, other = null, frameworks = true} = {}) => {
    const output = at(`output ${fixtures++}`);
    const bundle = join(output, `${appName}.app`);
    const executable = join(bundle, 'Contents/MacOS', appName);
    const frameworkDirectory = join(bundle, 'Contents/Frameworks', `${appName} Framework.framework`);
    await mkdir(dirname(executable), {recursive:true});
    await writeFile(executable, recorder('brave'), {mode:0o755});
    if (frameworks) {
      // Mirror the real versioned framework and its symlinks.
      await mkdir(join(frameworkDirectory, 'Versions/151.1.95.0'), {recursive:true});
      await writeFile(join(frameworkDirectory, 'Versions/151.1.95.0', `${appName} Framework`), image({names:framework, marker}));
      await symlink('151.1.95.0', join(frameworkDirectory, 'Versions/Current'));
      await symlink(`Versions/Current/${appName} Framework`, join(frameworkDirectory, `${appName} Framework`));
    }
    if (other) {
      // A framework the Chromium loader never opens.
      await mkdir(join(bundle, 'Contents/Frameworks/Other.framework'), {recursive:true});
      await writeFile(join(bundle, 'Contents/Frameworks/Other.framework/Other'), image({names:other}));
    }
    if (libv8) await writeFile(join(output, 'libv8.dylib'), image({names:libv8}));
    return {executable, output, bundle, libv8: join(output, 'libv8.dylib'),
      framework: join(frameworkDirectory, 'Versions/Current', `${appName} Framework`)};
  };
  const adapterPath = at('adapter.json');
  const sitesPath = at('sites.json');
  await writeFile(adapterPath, '{}');
  await writeFile(sitesPath, '{}');
  const packaged = ['--reb-ignore-debugger-statements', '--reb-wasm-br-table-dispatch', '--reb-wasm-call-indirect-dispatch'];
  const every = [...packaged, '--reb-wasm-guest-capture', '--reb-js-dispatch-capture'];
  const switches = {
    none: {},
    packaged: {REB_NATIVE_QUIET_MODE:'1', REB_NATIVE_WASM_DISPATCH:'1', REB_NATIVE_WASM_CALL_INDIRECT:'1'},
    every: {REB_NATIVE_QUIET_MODE:'1', REB_NATIVE_WASM_DISPATCH:'1', REB_NATIVE_WASM_CALL_INDIRECT:'1',
      REB_NATIVE_WASM_GUEST_ADAPTER:adapterPath, REB_NATIVE_JS_DISPATCH_SITES:sitesPath},
  };
  const settings = {
    '--reb-ignore-debugger-statements': ['REB_NATIVE_QUIET_MODE=1', 'REB_NATIVE_QUIET_MODE=0'],
    '--reb-wasm-br-table-dispatch': ['REB_NATIVE_WASM_DISPATCH=1', 'REB_NATIVE_WASM_DISPATCH=0'],
    '--reb-wasm-call-indirect-dispatch': ['REB_NATIVE_WASM_CALL_INDIRECT=1', 'REB_NATIVE_WASM_CALL_INDIRECT=0'],
    '--reb-wasm-guest-capture': ['REB_NATIVE_WASM_GUEST_ADAPTER', 'unset REB_NATIVE_WASM_GUEST_ADAPTER'],
    '--reb-js-dispatch-capture': ['REB_NATIVE_JS_DISPATCH_SITES', 'unset REB_NATIVE_JS_DISPATCH_SITES'],
  };
  const prefix = 'REB_LIVE_SESSION_FAILURE: ';
  const undefinedCause = (executable, file, flags) => `${prefix}Brave at ${executable} does not define the requested ` +
    `V8 flags ${flags.map(flag => `${flag} (from ${settings[flag][0]})`).join(', ')} in ${file}. V8 would stop at the ` +
    'first of them and ignore every later --js-flags entry, so that evidence would be silently missing. Use the Brave ' +
    'Browser Development build released with this Origin Trace, or rebuild Brave from this checkout, or turn that ' +
    `capture off with ${flags.map(flag => settings[flag][1]).join(', ')}.`;
  const locateCause = executable => `${prefix}Cannot locate the V8 library of Brave at ${executable}, so its native ` +
    'V8 flags cannot be checked. Set REB_BRAVE_BINARY to <App>.app/Contents/MacOS/<executable> inside a complete ' +
    'Brave build, not a wrapper script or an app copied away from its build output.';
  const inspectCause = (executable, file) => `${prefix}Could not inspect ${file}, the V8 library of Brave at ` +
    `${executable}, for the requested native V8 flags. Check that the file is readable.`;
  const lines = async file => {
    try { return (await readFile(file, 'utf8')).trimEnd().split('\n').filter(Boolean); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  const launchEnvironment = (executable, requested) => ({...process.env, ...helpers,
    PATH:`${bin}:${process.env.PATH}`, REB_BRAVE_BINARY:executable, REB_EMBEDDED_SESSION:'0', REB_ORIGIN_TRACE_APP:preflight,
    REB_LIVE_SESSION_ROOT:at('sessions'), REB_API_COLLECTION_STORE:at('collection.json'),
    REB_LOCAL_ANALYST_STORE:at('analyst.json'), REB_ACTIVE_ENDPOINT_FILE:at('active.endpoint'),
    REB_CAPTURE_CATEGORY_MASK:'4095', REB_NATIVE_QUIET_MODE:'0', REB_NATIVE_WASM_DISPATCH:'0',
    REB_NATIVE_WASM_CALL_INDIRECT:'0', REB_NATIVE_WASM_GUEST_ADAPTER:'', REB_NATIVE_JS_DISPATCH_SITES:'', ...requested});
  const clearReceipts = () => Promise.all([receipts, scans, started, finished].map(file => rm(file, {force:true})));
  const launchWith = async (executable, requested) => {
    await clearReceipts();
    const result = spawnSync(shell, [join(root, 'scripts/run-live-session.sh')],
      {encoding:'utf8', env:launchEnvironment(executable, requested)});
    const allScans = await lines(scans);
    return {...result, receipts: await lines(receipts), finished: await lines(finished), allScans,
      scans: allScans.filter(line => line.includes(' -e reb_'))};
  };
  const refused = (result, cause) => {
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [cause], 'A refusal names its cause and leaves nothing to clean up');
    assert.deepEqual(result.receipts, [], 'A refused build must start no helper and no browser');
  };
  // Passing the preflight reaches the first helper, which exits at once. Each
  // requested flag is scanned in exactly one file: the V8 image Brave loads.
  const scanOf = (flag, file) => `-a -q -F -e ${flag.slice(2).replaceAll('-', '_')} ${file}`;
  const accepted = (result, flags, file) => {
    assert.equal(result.status, 1, result.stderr);
    assert.doesNotMatch(result.stderr, /V8 flags|V8 library/);
    assert.match(result.stderr, /REB_LIVE_SESSION_FAILURE: Event broker (?:stopped during startup|socket did not become ready)/);
    assert.deepEqual(result.receipts, ['broker']);
    assert.deepEqual([...result.scans].sort(), flags.map(flag => scanOf(flag, file)).sort());
  };

  // A build from before the dispatch patch: quiet mode exists, dispatch does not.
  // Every missing flag is listed with the setting that requested it.
  const stale = await braveApp({framework: ['reb_ignore_debugger_statements']});
  const staleResult = await launchWith(stale.executable, switches.packaged);
  refused(staleResult, undefinedCause(stale.executable, stale.framework,
    ['--reb-wasm-br-table-dispatch', '--reb-wasm-call-indirect-dispatch']));
  assert.deepEqual([...staleResult.scans].sort(), packaged.map(flag => scanOf(flag, stale.framework)).sort());
  const none = await braveApp();
  refused(await launchWith(none.executable, switches.every), undefinedCause(none.executable, none.framework, every));
  const noJs = await braveApp({framework: allNames.filter(name => name !== 'reb_js_dispatch_capture')});
  refused(await launchWith(noJs.executable, switches.every),
    undefinedCause(noJs.executable, noJs.framework, ['--reb-js-dispatch-capture']));
  // Names elsewhere in or beside the bundle are not what Brave loads.
  const decoyFramework = await braveApp({framework: ['reb_ignore_debugger_statements'], other: allNames});
  refused(await launchWith(decoyFramework.executable, switches.packaged), undefinedCause(decoyFramework.executable,
    decoyFramework.framework, ['--reb-wasm-br-table-dispatch', '--reb-wasm-call-indirect-dispatch']));
  const strayLibrary = await braveApp({framework: ['reb_ignore_debugger_statements'], libv8: allNames});
  refused(await launchWith(strayLibrary.executable, switches.packaged), undefinedCause(strayLibrary.executable,
    strayLibrary.framework, ['--reb-wasm-br-table-dispatch', '--reb-wasm-call-indirect-dispatch']));
  console.log('PASS a Brave whose loaded V8 lacks requested flags is refused before any helper or browser, listing each flag and its setting');

  // A wrapper's own text is not capability evidence, and an app away from its
  // framework or component libraries cannot be checked.
  const wrapper = at('wrapper brave');
  await writeFile(wrapper, `${recorder('brave')}# ${allNames.join(' ')}\n`, {mode:0o755});
  for (const executable of [wrapper, (await braveApp({frameworks: false})).executable,
    (await braveApp({marker: '@rpath/libchrome_dll.dylib'})).executable]) {
    const result = await launchWith(executable, switches.packaged);
    refused(result, locateCause(executable));
    assert.deepEqual(result.scans, []);
  }
  // A read failure is not evidence that a flag is absent.
  const release = await braveApp({framework: allNames});
  await writeFile(mode.fail, '');
  refused(await launchWith(release.executable, switches.packaged), inspectCause(release.executable, release.framework));
  await rm(mode.fail);
  console.log('PASS wrapper and incomplete builds report an unlocatable V8 library; read errors report an uninspectable one');

  accepted(await launchWith(release.executable, switches.every), every, release.framework);
  accepted(await launchWith(release.executable, switches.packaged), packaged, release.framework);
  const componentDll = await braveApp({marker: '@rpath/libchrome_dll.dylib', libv8: allNames});
  accepted(await launchWith(componentDll.executable, switches.every), every, componentDll.libv8);
  const componentV8 = await braveApp({marker: '@rpath/libv8.dylib', libv8: allNames});
  accepted(await launchWith(componentV8.executable, switches.packaged), packaged, componentV8.libv8);
  // Symlinks resolve before anything is derived: a two-hop executable link with
  // a relative hop, and a linked app whose directory holds a decoy libv8.dylib.
  await symlink(release.executable, at('brave link'));
  await symlink('brave link', at('brave relative link'));
  accepted(await launchWith(at('brave relative link'), switches.packaged), packaged, release.framework);
  await mkdir(at('links'));
  await symlink(componentDll.bundle, join(at('links'), `${appName}.app`));
  await writeFile(join(at('links'), 'libv8.dylib'), image());
  accepted(await launchWith(join(at('links'), `${appName}.app/Contents/MacOS`, appName), switches.packaged),
    packaged, componentDll.libv8);
  console.log('PASS release framework, component libv8.dylib and symlinked builds that define every flag pass the preflight');

  for (const fixture of [stale, none]) {
    const result = await launchWith(fixture.executable, switches.none);
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(result.receipts, ['broker']);
    assert.deepEqual(result.allScans, []);
  }
  console.log('PASS no V8 flag preflight runs when no native V8 flag is requested');

  // A refusal decided by the first scan still waits for every other reader.
  await writeFile(mode.slow, '');
  const slow = await launchWith(none.executable, switches.packaged);
  refused(slow, undefinedCause(none.executable, none.framework, packaged));
  assert.deepEqual([...slow.finished].sort(), packaged.map(flag => scanOf(flag, none.framework)).sort());
  await rm(mode.slow);
  // Stopping the launcher mid-scan stops and reaps every reader.
  await writeFile(mode.hold, '');
  const alive = pid => {
    try { process.kill(pid, 0); return true; }
    catch (error) { if (error.code === 'ESRCH') return false; throw error; }
  };
  for (const [signal, code] of [['SIGTERM', 143], ['SIGINT', 130]]) {
    await clearReceipts();
    const child = spawn(shell, [join(root, 'scripts/run-live-session.sh')], {env:launchEnvironment(release.executable, switches.packaged)});
    let output = '';
    for (const pipe of [child.stdout, child.stderr]) pipe.on('data', chunk => { output += chunk; });
    const exited = new Promise(resolveExit => child.once('exit', (exitCode, exitSignal) => resolveExit({exitCode, exitSignal})));
    let readers = [];
    for (const deadline = Date.now() + 10000; readers.length < packaged.length;) {
      assert(Date.now() < deadline && child.exitCode === null, `Readers did not start: ${output}`);
      await new Promise(resolvePause => setTimeout(resolvePause, 20));
      readers = (await lines(started)).map(Number);
    }
    child.kill(signal);
    let timer;
    const result = await Promise.race([exited, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Launcher survived ${signal}: ${output}`)), 8000);
    })]);
    clearTimeout(timer);
    assert.deepEqual(result, {exitCode: code, exitSignal: null}, output);
    for (const pid of readers) assert.equal(alive(pid), false, `${signal} left reader ${pid} running`);
    assert.deepEqual(await lines(receipts), []);
  }
  await rm(mode.hold);
  console.log('PASS refusal waits for every scan, and SIGTERM or SIGINT mid-scan stops and reaps every reader');
} finally {await rm(preflight,{recursive:true,force:true});}
