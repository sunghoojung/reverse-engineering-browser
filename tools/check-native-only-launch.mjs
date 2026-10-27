import assert from 'node:assert/strict';
import {readFile, access, mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
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

const flagsStart = launch.indexOf('native_js_flags=()');
const flagsEnd = launch.indexOf('if [[ "${capture_canvas_images}"', flagsStart);
assert(flagsStart >= 0 && flagsEnd > flagsStart);
const flagsCode = launch.slice(flagsStart, flagsEnd);
for (const quiet of [0, 1]) for (const dispatch of [0, 1]) {
  const result = spawnSync('bash', ['-c', `set -eu; brave_arguments=(); native_quiet_mode=${quiet}; native_wasm_dispatch=${dispatch}; native_guest_adapter=""; ${flagsCode}
printf '%s' "${'${brave_arguments[*]-}'}"`], {encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const expected = [quiet ? '--reb-ignore-debugger-statements' : '', dispatch ? '--reb-wasm-br-table-dispatch' : ''].filter(Boolean);
  assert.equal(result.stdout, expected.length ? '--js-flags=' + expected.join(' ') : '');
}
for (const options of [{REB_NATIVE_WASM_DISPATCH:'invalid'}, {REB_NATIVE_WASM_DISPATCH:'1',REB_CAPTURE_CATEGORY_MASK:'1'}]) {
  const result = spawnSync('bash', [join(root,'scripts/run-live-session.sh')], {env:{...process.env,...options},encoding:'utf8'});
  assert.equal(result.status,2,result.stderr);
  assert.match(result.stderr,/REB_NATIVE_WASM_DISPATCH/);
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
  const result = spawnSync('bash',['-c',`set -eu; brave_arguments=(); native_quiet_mode=1; native_wasm_dispatch=1; native_guest_adapter="$TEST_ADAPTER"; ${flagsCode}
    printf '%s\\n' "${'${brave_arguments[@]-}'}"`],{env:{...process.env,TEST_ADAPTER:adapterPath},encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.deepEqual(result.stdout.trimEnd().split('\n'), ['--js-flags=--reb-ignore-debugger-statements --reb-wasm-br-table-dispatch','--reb-wasm-guest-adapter='+adapterPath]);
} finally {await rm(adapterDirectory,{recursive:true,force:true});}
console.log('PASS native guest adapter opt-in, bounded file preflight and quoted path propagation');
