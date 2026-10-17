// Deterministic backend/CDP-boundary regression. No browser or external network.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {appendFileSync, existsSync, writeFileSync} from 'node:fs';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const script = fileURLToPath(import.meta.url);
const delay = ms => new Promise(resolveDelay => setTimeout(resolveDelay, ms));
if (process.argv[2] === '--transport') {
  const directory = process.env.REB_INIT_FIXTURE_DIRECTORY;
  const log = value => appendFileSync(join(directory, 'commands.jsonl'), JSON.stringify(value) + '\n');
  const emit = value => {
    const body = value === null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(value));
    const header = Buffer.from([82,69,66,1,0,0,0,0]);
    header.writeUInt32BE(body.length, 4);
    process.stdout.write(Buffer.concat([header, body]));
  };
  log({event: 'open', pid: process.pid});
  emit(null);
  let pending = Buffer.alloc(0);
  let firstMethod;
  process.stdin.on('data', chunk => {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 8 && pending.length >= 8 + pending.readUInt32BE(4)) {
      const size = pending.readUInt32BE(4);
      const message = JSON.parse(pending.subarray(8, 8 + size));
      pending = pending.subarray(8 + size);
      firstMethod ??= message.method;
      log({event: 'command', pid: process.pid, method: message.method});
      const failed = join(directory, 'failed-once');
      if (firstMethod === 'Inspector.enable' && message.method === process.env.REB_INIT_FIXTURE_METHOD && !existsSync(failed)) {
        writeFileSync(failed, 'failed', {mode: 0o600});
        if (process.env.REB_INIT_FIXTURE_MODE !== 'timeout') {
          emit({id: message.id, error: {code: -32000, message: 'Synthetic initialization failure'}});
        }
        continue;
      }
      emit({id: message.id, result: {}});
      if (message.method === 'Network.enable') {
        emit({method: 'Network.requestWillBeSent', params: {
          requestId: 'synthetic-request', timestamp: 1, wallTime: 1,
          type: 'Fetch', request: {url: 'http://localhost/synthetic', method: 'GET', headers: {}},
        }});
      }
    }
  });
} else {
  const root = resolve(process.argv[2] ?? '.');
  const binary = resolve(process.env.ORIGIN_TRACE_BACKEND || join(root, 'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  async function check({name, method = '', mode = 'error', capture = true}) {
    const directory = await mkdtemp(join(tmpdir(), 'reb-cdp-initialization-'));
    let discoveries = 0;
    const server = createServer((_request, response) => {
      discoveries++;
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify([{id: 'fixture-page', type: 'page', title: 'Synthetic page',
        url: 'http://localhost/fixture', webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/devtools/page/fixture-page`} ]));
    });
    await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
    let backend;
    let exited;
    let diagnostics = '';
    try {
      const activePort = join(directory, 'DevToolsActivePort');
      await writeFile(activePort, `${server.address().port}\n/devtools/browser/fixture\n`, {mode: 0o600});
      const transport = join(directory, 'transport');
      await writeFile(transport, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --transport "$@"\n`, {mode: 0o700});
      const endpoint = join(directory, 'endpoint');
      backend = spawn(binary, ['--port', '0', '--endpoint-file', endpoint,
        '--devtools-active-port', activePort, '--debugger-transport', transport,
        ...(capture ? ['--capture-network-content'] : [])], {
        cwd: directory,
        env: {...process.env, REB_INIT_FIXTURE_DIRECTORY: directory,
          REB_INIT_FIXTURE_METHOD: method, REB_INIT_FIXTURE_MODE: mode},
      });
      exited = new Promise(resolveExit => {
        backend.once('exit', resolveExit);
        backend.once('error', error => {diagnostics += error.message; resolveExit();});
      });
      for (const stream of [backend.stdout, backend.stderr]) stream.on('data', chunk => {
        diagnostics = (diagnostics + chunk).slice(-16384);
      });
      let state;
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        assert.equal(backend.exitCode, null, `${name}: backend exited: ${diagnostics}`);
        try {
          const address = (await readFile(endpoint, 'utf8')).trim();
          const response = await fetch(new URL('/api/debugger', address), {signal: AbortSignal.timeout(2000)});
          state = await response.json();
          if (state.state === 'running') break;
        } catch {}
        await delay(50);
      }
      assert.equal(state?.state, 'running', `${name}: initialization did not recover: ${JSON.stringify(state)} ${diagnostics}`);
      assert.equal(state.error, null, `${name}: successful recovery clears error`);
      assert.equal(state.network.capture_enabled, capture);
      assert.equal(state.network.requests.length, capture ? 1 : 0);
      const before = discoveries;
      while (discoveries < before + 2 && Date.now() < deadline) await delay(50);
      assert(discoveries >= before + 2, `${name}: refresh must remain live`);
      const commands = (await readFile(join(directory, 'commands.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
      const owners = commands.filter(command => command.method === 'Inspector.enable');
      const focused = new Set(owners.map(owner => owner.pid));
      const focusedCommands = commands.filter(command => focused.has(command.pid));
      assert.equal(owners.length, method ? 2 : 1, `${name}: exactly one retry, no reconnect loop`);
      if (method) {
        assert.equal(focusedCommands.filter(command => command.method === method).length, 2, `${name}: failed domain is retried`);
        assert.throws(() => process.kill(owners[0].pid, 0), {code: 'ESRCH'}, `${name}: failed transport must be reaped`);
        assert.equal(state.network.capture_epoch, 2);
      }
      if (!capture) assert(!commands.some(command => command.method === 'Network.enable'), 'Disabled content capture must never enable Network');
      console.log(`PASS debugger initialization: ${name}`);
    } finally {
      if (backend && backend.exitCode === null) {
        backend.kill('SIGTERM');
        await Promise.race([exited, delay(5000)]);
        if (backend.exitCode === null && backend.signalCode === null) {backend.kill('SIGKILL'); await exited;}
      }
      await new Promise(resolveClose => server.close(resolveClose));
      await rm(directory, {recursive: true, force: true});
    }
  }
  await check({name: 'successful initialization'});
  await check({name: 'Network.enable error retry', method: 'Network.enable'});
  await check({name: 'early domain error retry', method: 'Runtime.enable'});
  await check({name: 'Network.enable timeout retry', method: 'Network.enable', mode: 'timeout'});
  await check({name: 'restore settings error retry', method: 'Debugger.setPauseOnExceptions'});
  await check({name: 'disabled content capture', capture: false});
}
