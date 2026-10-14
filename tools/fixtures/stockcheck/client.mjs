// A deliberately narrow, reviewed domain adapter over REB's exported sender.
// Copy beside src/client.mjs in an exported project; never execute captured JS.
export class StockcheckError extends Error {
  constructor(code) {super(code); this.name = 'StockcheckError'; this.code = code;}
}
const fail = code => {throw new StockcheckError(code);};

function validateSelection(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'catalog_version,sku,store,variant' ||
      ['sku', 'variant', 'store', 'catalog_version'].some(key => typeof value[key] !== 'string') ||
      !/^[A-Z0-9-]{1,32}$/.test(value.sku) || !/^[a-z]{1,16}$/.test(value.variant) ||
      !/^[A-Z]{1,16}$/.test(value.store) || !/^fixture-v[0-9]{1,6}$/.test(value.catalog_version)) fail('INVALID_INPUT');
}

export function stockRequest(selection, origin, timeoutMs = 1000) {
  validateSelection(selection);
  let url;
  try {url = new URL(origin);} catch {fail('INVALID_ORIGIN');}
  if (url.origin !== origin || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password) fail('INVALID_ORIGIN');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail('INVALID_INPUT');
  // Authored from the reviewed fixture algorithm, not source evaluation/import.
  const text = `${selection.catalog_version}|${selection.store}|${selection.variant}|${selection.sku}`;
  const lookup_key = Buffer.from(text, 'ascii').toString('base64url');
  return {method: 'POST', url: `${origin}/api/stock`, headers: [['Content-Type', 'application/json']],
    body: JSON.stringify({...selection, lookup_key}), timeout_ms: timeoutMs};
}

function flatResponse(body) {
  // The fixture contract is a flat primitive object. Reject duplicate keys,
  // including escaped spellings, rather than accepting JSON.parse's last value.
  let parsed;
  try {parsed = JSON.parse(body);} catch {fail('MALFORMED_RESPONSE');}
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail('SCHEMA_CHANGED');
  const stringToken = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
  const primitive = /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;
  let index = 0;
  const skip = () => {while (/\s/.test(body[index] ?? '') && index < body.length) index++;};
  const token = expression => {expression.lastIndex = index; const result = expression.exec(body); if (!result) fail('SCHEMA_CHANGED'); index = expression.lastIndex; return result[0];};
  skip(); if (body[index++] !== '{') fail('SCHEMA_CHANGED'); skip();
  const seen = new Set();
  while (body[index] !== '}') {
    const key = JSON.parse(token(stringToken));
    if (seen.has(key)) fail('MALFORMED_RESPONSE');
    seen.add(key); skip(); if (body[index++] !== ':') fail('SCHEMA_CHANGED'); skip();
    token(body[index] === '"' ? stringToken : primitive); skip();
    if (body[index] !== ',') break;
    index++; skip();
  }
  if (body[index++] !== '}') fail('SCHEMA_CHANGED'); skip();
  if (index !== body.length) fail('SCHEMA_CHANGED');
  return parsed;
}

export function stockResult(response, selection) {
  if (response.body_truncated) fail('INCOMPLETE_RESPONSE');
  if (response.status === 401 || response.status === 403) fail('LOGIN_REQUIRED');
  if (response.status === 429) fail('RATE_LIMITED');
  if (response.status === 409) fail('CATALOG_EXPIRED');
  if (response.status >= 300 && response.status < 400) fail('REDIRECT_REFUSED');
  if (response.status !== 200) fail('TARGET_ERROR');
  const contentType = response.headers.find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? '';
  if (contentType.split(';')[0].trim().toLowerCase() !== 'application/json') fail('SCHEMA_CHANGED');
  const value = flatResponse(response.body);
  const allowed = ['sku', 'variant', 'store', 'catalog_version', 'availability', 'quantity', 'observation'];
  if (Object.keys(value).some(key => !allowed.includes(key)) ||
      ['sku', 'variant', 'store', 'catalog_version'].some(key => value[key] !== selection[key]) ||
      !['in_stock', 'out_of_stock', 'unknown'].includes(value.availability) ||
      typeof value.observation !== 'string' || !/^owned-http-[1-9][0-9]*$/.test(value.observation)) fail('SCHEMA_CHANGED');
  const hasQuantity = Object.hasOwn(value, 'quantity');
  if (value.availability === 'unknown' ? hasQuantity : !hasQuantity || !Number.isSafeInteger(value.quantity) || value.quantity < 0 ||
      (value.availability === 'in_stock' ? value.quantity === 0 : value.quantity !== 0)) fail('SCHEMA_CHANGED');
  return {ok: true, ...value};
}

export async function checkStock(selection, {sendRequest, allowedOrigin, send = false, timeoutMs = 1000} = {}) {
  const request = stockRequest(selection, allowedOrigin, timeoutMs);
  if (!send) return {dry_run: true, network_requests: 0, request};
  if (typeof sendRequest !== 'function') fail('MISSING_EXPORTED_TRANSPORT');
  let response;
  try {
    response = await sendRequest(request, {send: true, config: {allowedOrigin, request}});
  } catch (error) {
    fail(error.name === 'AbortError' || error.name === 'TimeoutError' ? 'TIMEOUT_OUTCOME_UNKNOWN' : 'NETWORK_OUTCOME_UNKNOWN');
  }
  return stockResult(response, selection);
}
