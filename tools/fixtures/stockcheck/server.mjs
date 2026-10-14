#!/usr/bin/env node
// Owned loopback target only. No accounts, credentials, third-party requests,
// persistence, or remotely selectable failure scenarios.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';

export const catalogVersion = 'fixture-v1';
export const scenarios = ['normal', 'login-required', 'schema-change', 'malformed', 'duplicate-key', 'rate-limit', 'slow'];
const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Owned stock-check fixture</title><main><h1>Owned stock-check fixture</h1>
<p>Credential-free test inventory. Check stock sends one request to this loopback server.</p>
<label>SKU <select id="sku"><option>TEA-01</option><option>COFFEE-02</option></select></label>
<label>Variant <select id="variant"><option>small</option><option>large</option></select></label>
<label>Store <select id="store"><option>NORTH</option><option>SOUTH</option><option>UNKNOWN</option></select></label>
<input id="catalog-version" type="hidden" value="fixture-v1">
<button id="check-stock" type="button">Check stock</button><pre id="stock-result" aria-live="polite"></pre>
</main><script type="module" src="/browser.mjs"></script></html>`;
const inventory = new Map([
  ['TEA-01|small|NORTH', 7], ['TEA-01|small|SOUTH', 0], ['TEA-01|large|NORTH', 2],
  ['COFFEE-02|small|NORTH', 4],
]);

export async function startStockcheck({scenario = 'normal'} = {}) {
  if (!scenarios.includes(scenario)) throw new TypeError('Unknown owned fixture scenario');
  const source = await readFile(new URL('browser.mjs', import.meta.url), 'utf8');
  const log = [], timers = new Set();
  let origin;
  const server = createServer(async (request, response) => {
    const send = (status, value) => {
      response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
      response.end(typeof value === 'string' ? value : JSON.stringify(value));
    };
    if (request.headers.host !== new URL(origin).host ||
        (request.headers.origin && request.headers.origin !== origin) || request.headers['sec-fetch-site'] === 'cross-site') {
      send(403, {code: 'outside_owned_fixture'}); return;
    }
    if (request.method === 'GET' && ['/', '/browser.mjs'].includes(request.url)) {
      response.writeHead(200, {'Content-Type': request.url === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8',
        'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"});
      response.end(request.url === '/' ? html : source); return;
    }
    if (request.method !== 'POST' || request.url !== '/api/stock') {send(404, {code: 'not_found'}); return;}
    let bytes = 0, body = '';
    try {
      for await (const part of request) {
        bytes += part.length;
        if (bytes > 4096) {send(413, {code: 'body_limit'}); return;}
        body += part.toString('utf8');
      }
    } catch {return;}
    const entry = {id: `owned-http-${log.length + 1}`, method: request.method, path: request.url,
      headers: Object.entries(request.headers), body, scenario};
    log.push(entry);
    const reply = (status, value) => {entry.status = status; entry.response = typeof value === 'string' ? value : JSON.stringify(value); send(status, value);};
    if (request.headers.authorization || request.headers.cookie) {reply(400, {code: 'credentials_forbidden'}); return;}
    if (scenario === 'login-required') {reply(401, {code: 'login_required'}); return;}
    if (scenario === 'rate-limit') {reply(429, {code: 'rate_limited'}); return;}
    let input;
    try {input = JSON.parse(body);} catch {reply(400, {code: 'bad_json'}); return;}
    if (!input || typeof input !== 'object' || Array.isArray(input) ||
        Object.keys(input).sort().join(',') !== 'catalog_version,lookup_key,sku,store,variant' ||
        ['sku', 'variant', 'store', 'catalog_version', 'lookup_key'].some(key => typeof input[key] !== 'string')) {
      reply(400, {code: 'bad_input'}); return;
    }
    if (input.catalog_version !== catalogVersion) {reply(409, {code: 'catalog_expired'}); return;}
    // Independent server oracle: do not import browser or agent-client derivation.
    const expected = Buffer.from(`${catalogVersion}|${input.store}|${input.variant}|${input.sku}`, 'ascii').toString('base64url');
    if (input.lookup_key !== expected) {reply(422, {code: 'lookup_key_mismatch'}); return;}
    const quantity = inventory.get(`${input.sku}|${input.variant}|${input.store}`);
    const result = {sku: input.sku, variant: input.variant, store: input.store,
      availability: quantity === undefined ? 'unknown' : quantity > 0 ? 'in_stock' : 'out_of_stock',
      ...(quantity === undefined ? {} : {quantity}), catalog_version: catalogVersion, observation: entry.id};
    if (scenario === 'schema-change') {reply(200, {inventory: result}); return;}
    if (scenario === 'malformed') {reply(200, '{"availability":'); return;}
    if (scenario === 'duplicate-key') {reply(200, JSON.stringify(result).replace('"availability":', '"availability":"out_of_stock","availability":')); return;}
    if (scenario === 'slow') {
      const timer = setTimeout(() => {timers.delete(timer); reply(200, result);}, 500);
      timers.add(timer); return;
    }
    reply(200, result);
  });
  server.requestTimeout = 2000;
  server.headersTimeout = 2000;
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  origin = `http://127.0.0.1:${server.address().port}`;
  return {origin, log, source, async close() {
    for (const timer of timers) clearTimeout(timer);
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.length > 1 || args.length && !scenarios.includes(args[0])) throw new Error(`Usage: node server.mjs [${scenarios.join('|')}]`);
  const fixture = await startStockcheck({scenario: args[0]});
  console.log(JSON.stringify({fixture: 'owned-stockcheck-v1', origin: fixture.origin, scenario: args[0] ?? 'normal'}));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, async () => {await fixture.close(); process.exit(0);});
}
