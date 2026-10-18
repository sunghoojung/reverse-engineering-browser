// Independent owned-site oracle. No REB or CDP imports: receipts prove only
// requests reaching this server; browser completion checks cover synthetic work.
import {createServer} from 'node:http';
import {createHash, randomUUID} from 'node:crypto';

export async function createCaptureFixture({runId = randomUUID(), limits = {}} = {}) {
  if (typeof runId !== 'string' || runId.length > 80 || !/^[a-zA-Z0-9_-]+$/.test(runId))
    throw new Error('Invalid fixture run ID');
  const bounds = {
    maxReceipts: 512,
    maxReceiptBytes: 262144,
    maxSockets: 64,
    maxBodyBytes: 8192,
    maxFrameBufferBytes: 4096,
    ...limits,
  };
  for (const [key, value] of Object.entries(bounds))
    if (!Number.isSafeInteger(value) || value < 1 || value > 1048576)
      throw Error(`Invalid fixture limit: ${key}`);
  let boundFailure = '',
    receiptBytes = 0;
  const overflow = (message) => {
    boundFailure ||= message;
  };
  const receipts = [],
    completions = new Map(),
    sockets = new Set();
  const operations = [],
    routes = new Map();
  let sequence = 0,
    origin,
    crossOrigin;
  const cases = [
    'document',
    'repeat-redirect',
    'failure-cancel',
    'iframe',
    'dedicated-worker',
    'shared-worker',
    'service-worker',
    'popup',
    'cache',
    'websocket',
    'preflight',
  ];
  function operation(caseId, name, {expectedReceipts = 1, kind = 'http', ...extra} = {}) {
    const operationId = `${runId}:${caseId}:${name}`;
    const path = `/reb-fixture/${runId}/${caseId}/${name}`;
    const op = {operationId, caseId, path, method: 'GET', expectedReceipts, kind, ...extra};
    operations.push(op);
    return `${path}?op=${encodeURIComponent(operationId)}`;
  }
  const doc = operation('document', 'index');
  const css = operation('document', 'style');
  const js = operation('document', 'script');
  const repeat = operation('repeat-redirect', 'repeat', {
    expectedReceipts: 2,
    expectedBody: 'fixture-ok',
  });
  const hop0 = operation('repeat-redirect', 'hop-0');
  const hop1 = operation('repeat-redirect', 'hop-1');
  const failed = operation('failure-cancel', 'reset');
  const cancel = operation('failure-cancel', 'cancel');
  const frame = operation('iframe', 'document');
  const frameFetch = operation('iframe', 'immediate');
  const dedicated = operation('dedicated-worker', 'script');
  const dedicatedFetch = operation('dedicated-worker', 'immediate');
  const shared = operation('shared-worker', 'script');
  const sharedFetch = operation('shared-worker', 'immediate');
  const service = operation('service-worker', 'script');
  const serviceFetch = operation('service-worker', 'install-fetch');
  const synthetic = operation('service-worker', 'synthetic', {
    expectedReceipts: 0,
    expectedClientCompletions: 1,
    expectedBody: 'fixture-synthetic',
  });
  const popup = operation('popup', 'document');
  const popupFetch = operation('popup', 'immediate');
  const cache = operation('cache', 'resource', {
    expectedReceipts: 1,
    expectedClientCompletions: 2,
    expectedBody: 'fixture-cache',
  });
  const preflight = operation('preflight', 'request', {method: 'OPTIONS'});
  operation('preflight', 'request', {method: 'POST'});
  const websocket = operation('websocket', 'socket', {kind: 'websocket-handshake'});
  // Frame expectations are a different evidence class, never HTTP hop counts.
  const websocketFrames = {
    operationId: operations.at(-1).operationId,
    sent: ['fixture-ping'],
    received: ['fixture-ping'],
  };
  const control = `/reb-fixture/${runId}/control`;
  const quote = JSON.stringify;
  const html = (body) =>
    `<!doctype html><meta charset="utf-8"><title>Owned capture fixture</title><link rel="icon" href="data:,">${body}`;
  const finish = `async function finish(caseId,ok=true,detail=''){await fetch('${control}/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({caseId,ok,detail})});}`;
  const workerBody = (fetchPath, send) =>
    `fetch(${quote(fetchPath)}).then(r=>r.text()).then(()=>${send}).catch(e=>${send.replace('true', 'false')});`;
  routes.set(css, {type: 'text/css', body: 'body { color: rgb(1, 2, 3); }'});
  routes.set(js, {type: 'text/javascript', body: 'window.fixtureSubresourceLoaded=true;'});
  routes.set(hop0, {redirect: hop1});
  routes.set(failed, {reset: true});
  routes.set(cancel, {cancel: true});
  routes.set(cache, {cache: true, body: 'fixture-cache'});
  routes.set(frame, {
    type: 'text/html',
    body: html(
      `<script>${finish}fetch(${quote(frameFetch)}).then(r=>r.text()).then(()=>finish('iframe')).catch(e=>finish('iframe',false,e.message));</script>`,
    ),
  });
  routes.set(dedicated, {
    type: 'text/javascript',
    body: workerBody(dedicatedFetch, 'postMessage(true)'),
  });
  routes.set(shared, {
    type: 'text/javascript',
    body: `const work=fetch(${quote(sharedFetch)}).then(r=>r.text());onconnect=e=>{const p=e.ports[0];p.start();work.then(()=>p.postMessage(true),()=>p.postMessage(false));};`,
  });
  routes.set(service, {
    type: 'text/javascript',
    body: `self.addEventListener('install',e=>e.waitUntil(fetch(${quote(serviceFetch)}).then(r=>r.text()).then(()=>self.skipWaiting())));self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));self.addEventListener('fetch',e=>{if(new URL(e.request.url).pathname===${quote(synthetic.split('?')[0])})e.respondWith(new Response('fixture-synthetic'));});`,
  });
  routes.set(popup, {
    type: 'text/html',
    body: html(
      `<script>${finish}fetch(${quote(popupFetch)},{keepalive:true}).then(r=>r.text()).then(()=>finish('popup')).then(()=>window.close()).catch(e=>finish('popup',false,e.message));</script>`,
    ),
  });
  function entry() {
    return html(`<link rel="stylesheet" href="${css}"><script src="${js}"></script><script>
${finish}
const checked=(value,message)=>{if(!value)throw Error(message);};
const run=(id,fn)=>Promise.resolve().then(fn).then(()=>finish(id),e=>finish(id,false,e.message));
window.addEventListener('load',()=>run('document',()=>checked(window.fixtureSubresourceLoaded,'script missing')));
run('repeat-redirect',async()=>{await fetch(${quote(repeat)}).then(r=>r.text());await fetch(${quote(repeat)}).then(r=>r.text());await fetch(${quote(hop0)}).then(r=>r.text());});
run('failure-cancel',async()=>{let rejected=false;try{await fetch(${quote(failed)}).then(r=>r.text());}catch{rejected=true;}checked(rejected,'reset did not fail');const c=new AbortController();const r=await fetch(${quote(cancel)},{signal:c.signal});c.abort();let aborted=false;try{await r.text();}catch{aborted=true;}checked(aborted,'body did not abort');});
const f=document.createElement('iframe');f.src=${quote(crossOrigin + frame)};document.documentElement.append(f);
run('dedicated-worker',()=>new Promise((resolve,reject)=>{const w=new Worker(${quote(dedicated)});w.onmessage=e=>{w.terminate();e.data?resolve():reject(Error('worker fetch failed'));};w.onerror=()=>reject(Error('worker startup failed'));}));
run('shared-worker',()=>new Promise((resolve,reject)=>{const w=new SharedWorker(${quote(shared)});window.fixtureShared=w;w.port.onmessage=e=>{w.port.close();e.data?resolve():reject(Error('shared fetch failed'));};w.onerror=()=>reject(Error('shared startup failed'));w.port.start();}));
run('service-worker',async()=>{await navigator.serviceWorker.register(${quote(service)},{scope:'/'});await navigator.serviceWorker.ready;if(!navigator.serviceWorker.controller)await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));checked(await fetch(${quote(synthetic)}).then(r=>r.text())==='fixture-synthetic','synthetic response missing');});
const p=window.open(${quote(popup)});if(!p)finish('popup',false,'popup blocked');
run('preflight',async()=>{checked(await fetch(${quote(crossOrigin + preflight)},{method:'POST',headers:{'X-Fixture-Probe':'owned'},body:'fixture-preflight'}).then(r=>r.text())==='fixture-ok','preflight POST failed');});
run('cache',async()=>{for(let i=0;i<2;i++)checked(await fetch(${quote(cache)}).then(r=>r.text())==='fixture-cache','cache body missing');});
run('websocket',()=>new Promise((resolve,reject)=>{const w=new WebSocket(${quote(origin.replace('http:', 'ws:') + websocket)});w.onopen=()=>w.send('fixture-ping');w.onmessage=e=>{if(e.data!=='fixture-ping')return reject(Error('echo mismatch'));w.close();};w.onclose=e=>e.wasClean?resolve():reject(Error('unclean websocket close'));w.onerror=()=>reject(Error('websocket failed'));}));
</script>`);
  }
  function record(request, kind = 'http', extra = {}) {
    const url = new URL(request.url, origin);
    const op = operations.find(
      (item) => item.path === url.pathname && item.method === request.method,
    );
    if (!op) return false;
    const receipt = {
      sequence: sequence + 1,
      operationId: op.operationId,
      caseId: op.caseId,
      method: request.method,
      path: url.pathname,
      url: `http://${request.headers.host}${request.url}`,
      kind,
      ...extra,
    };
    const bytes = Buffer.byteLength(JSON.stringify(receipt));
    if (receipts.length >= bounds.maxReceipts || receiptBytes + bytes > bounds.maxReceiptBytes) {
      overflow('receipt limit exceeded');
      request.socket.destroy();
      return false;
    }
    sequence++;
    receiptBytes += bytes;
    receipts.push(receipt);
    return true;
  }
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, origin);
    if (url.pathname === `${control}/complete` && request.method === 'POST') {
      let body = '';
      let bytes = 0;
      try {
        for await (const chunk of request) {
          bytes += chunk.length;
          if (bytes > bounds.maxBodyBytes) {
            overflow('completion body limit exceeded');
            response.writeHead(413).end();
            return;
          }
          body += chunk;
        }
      } catch {
        overflow('completion body interrupted');
        return;
      }
      try {
        const result = JSON.parse(body);
        if (
          !cases.includes(result.caseId) ||
          typeof result.ok !== 'boolean' ||
          completions.has(result.caseId)
        )
          throw Error('invalid or duplicate completion');
        if (typeof result.detail !== 'undefined' && typeof result.detail !== 'string')
          throw Error('invalid detail');
        completions.set(result.caseId, {
          caseId: result.caseId,
          ok: result.ok,
          detail: result.detail ?? '',
          at: Date.now(),
        });
        response.writeHead(204).end();
      } catch {
        response.writeHead(400).end();
      }
      return;
    }
    const expected = operations.find(
      (item) => item.path === url.pathname && item.method === request.method,
    );
    if (!expected || url.searchParams.get('op') !== expected.operationId) {
      response.writeHead(404).end();
      return;
    }
    if (!record(request)) return;
    if (request.method === 'POST') {
      let bytes = 0;
      try {
        for await (const chunk of request) {
          bytes += chunk.length;
          if (bytes > bounds.maxBodyBytes) {
            overflow('request body limit exceeded');
            response.writeHead(413).end();
            return;
          }
        }
      } catch {
        overflow('request body interrupted');
        return;
      }
    }
    const route = routes.get(request.url) ?? {};
    response.setHeader('Access-Control-Allow-Origin', '*');
    response.setHeader('Cache-Control', route.cache ? 'public, max-age=3600' : 'no-store');
    response.setHeader('Service-Worker-Allowed', '/');
    if (request.method === 'OPTIONS') {
      response.setHeader('Access-Control-Allow-Methods', 'POST');
      response.setHeader('Access-Control-Allow-Headers', 'X-Fixture-Probe');
      response.setHeader('Access-Control-Max-Age', '0');
      response.writeHead(204).end();
      return;
    }
    if (route.reset) {
      response.writeHead(200, {'Content-Length': '1000'});
      response.write('partial');
      setTimeout(() => request.socket.destroy(), 20);
      return;
    }
    if (route.cancel) {
      response.writeHead(200, {'Content-Type': 'text/plain'});
      response.write('partial');
      return;
    }
    if (route.redirect) {
      response.writeHead(302, {Location: route.redirect}).end();
      return;
    }
    const isEntry = request.url === doc;
    response.setHeader('Content-Type', isEntry ? 'text/html' : (route.type ?? 'text/plain'));
    response.end(isEntry ? entry() : (route.body ?? 'fixture-ok'));
  });
  server.headersTimeout = 5000;
  server.requestTimeout = 15000;
  server.setTimeout(15000, (socket) => socket.destroy());
  server.on('connection', (socket) => {
    if (sockets.size >= bounds.maxSockets) {
      overflow('socket limit exceeded');
      socket.destroy();
      return;
    }
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.on('upgrade', (request, socket, head) => {
    if (request.url !== websocket || !request.headers['sec-websocket-key']) {
      socket.destroy();
      return;
    }
    if (!record(request, 'websocket-handshake')) return;
    const accept = createHash('sha1')
      .update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    let buffered = head;
    const consume = (chunk) => {
      if (buffered.length + chunk.length > bounds.maxFrameBufferBytes) {
        overflow('frame buffer limit exceeded');
        socket.destroy();
        return;
      }
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 2) {
        const opcode = buffered[0] & 15,
          length = buffered[1] & 127,
          masked = !!(buffered[1] & 128);
        if (length > 125 || !masked) {
          socket.destroy();
          return;
        }
        if (buffered.length < 6 + length) return;
        const payload = Buffer.from(buffered.subarray(6, 6 + length));
        for (let i = 0; i < length; i++) payload[i] ^= buffered[2 + (i % 4)];
        buffered = buffered.subarray(6 + length);
        if (opcode === 8) {
          socket.end(Buffer.concat([Buffer.from([0x88, payload.length]), payload]));
          return;
        }
        if (opcode !== 1) {
          socket.destroy();
          return;
        }
        if (!record(request, 'websocket-frame', {direction: 'sent', payload: payload.toString()}))
          return;
        socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
        if (
          !record(request, 'websocket-frame', {direction: 'received', payload: payload.toString()})
        )
          return;
      }
    };
    socket.on('data', consume);
    socket.on('error', () => {});
    if (head.length) consume(Buffer.alloc(0));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  crossOrigin = `http://localhost:${server.address().port}`;
  const manifest = {
    version: 1,
    runId,
    origins: [origin, crossOrigin],
    bounds,
    cases,
    operations,
    websocketFrames,
    limitations: [
      'Server receipts establish on-wire arrival only.',
      'Cache and service-worker synthetic requests require client and collector evidence.',
      'Cross-site frame is authored; OOPIF isolation requires browser target evidence.',
    ],
  };
  function assertComplete() {
    const errors = boundFailure ? [boundFailure] : [];
    for (const caseId of cases) {
      const result = completions.get(caseId);
      if (!result) errors.push(`${caseId}: incomplete`);
      else if (!result.ok) errors.push(`${caseId}: ${result.detail || 'failed'}`);
    }
    for (const op of operations) {
      const actual = receipts.filter(
        (r) => r.operationId === op.operationId && r.method === op.method && r.kind === op.kind,
      ).length;
      if (actual !== op.expectedReceipts)
        errors.push(
          `${op.operationId} ${op.method}: expected ${op.expectedReceipts} receipts, got ${actual}`,
        );
    }
    for (const direction of ['sent', 'received']) {
      const actual = receipts
        .filter((r) => r.kind === 'websocket-frame' && r.direction === direction)
        .map((r) => r.payload);
      if (JSON.stringify(actual) !== JSON.stringify(websocketFrames[direction]))
        errors.push(`websocket ${direction}: frame mismatch`);
    }
    if (errors.length) throw Error(`Fixture oracle failed:\n${errors.join('\n')}`);
    return {complete: true, caseCount: cases.length, receiptCount: receipts.length};
  }
  async function waitForCompletion({timeoutMs = 15000, drainMs = 250} = {}) {
    if (
      !Number.isFinite(timeoutMs) ||
      timeoutMs < 0 ||
      timeoutMs > 120000 ||
      !Number.isFinite(drainMs) ||
      drainMs < 0 ||
      drainMs > 10000
    )
      throw Error('Invalid fixture timeout');
    const deadline = Date.now() + timeoutMs;
    while (!boundFailure && completions.size < cases.length && Date.now() < deadline)
      await new Promise((resolve) => setTimeout(resolve, 20));
    if (boundFailure) throw Error(`Fixture oracle failed: ${boundFailure}`);
    if (completions.size < cases.length)
      throw Error(
        `Fixture completion timeout: ${cases.filter((id) => !completions.has(id)).join(', ')}`,
      );
    // Fixed bounded drain after explicit completion, not quiet-network inference.
    await new Promise((resolve) => setTimeout(resolve, drainMs));
    return assertComplete();
  }
  return {
    origin,
    crossOrigin,
    entryUrl: origin + doc,
    manifest,
    receipts,
    completions,
    assertComplete,
    waitForCompletion,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
export const startFixture = createCaptureFixture;
