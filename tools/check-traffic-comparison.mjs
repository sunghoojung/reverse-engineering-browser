import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

export async function checkTrafficComparisonModel(root) {
  const source = await readFile(join(root, 'apps/research-ui/traffic_comparison.js'), 'utf8');
  const compare = runInNewContext(`${source}\ntrafficCompareRequests`, {
    TextEncoder, TextDecoder, Uint8Array,
    JSON: {stringify: JSON.stringify, parse: text => {
      assert.equal(text[0], '"', 'The lossless parser may decode string tokens only');
      return JSON.parse(text);
    }}
  });
  const body = (text, overrides = {}) => ({state: 'available', mime: 'application/json', text, headers: [], ...overrides});
  const request = (record, overrides = {}) => ({method: 'POST', path: 'https://example.test/data', status: 200,
    exchange: {request: record, response: record}, ...overrides});
  const result = (a, b) => compare(request(a), request(b));
  const part = (report, label = 'Request body') => report.sections.find(item => item.label === label);
  const json = (a, b) => part(result(body(a), body(b)));
  const plain = (a, b) => part(result(body(a, {mime: 'text/plain'}), body(b, {mime: 'text/plain'})));
  const headers = (a, b) => part(result({state: 'available', headers: a}, {state: 'available', headers: b}), 'Request headers');
  const limits = result(body('null'), body('null')).limits;

  assert.equal(json('{"a":1,"b":2}', '{ "b":2, "a":1 }').status, 'equal');
  assert.equal(json('{"a":1,"b":2}', '{ "b":2, "a":1 }').structuralStatus, 'equal');
  assert.equal(json('{"a":1,"b":2}', '{ "b":2, "a":1 }').rawStatus, 'different');
  assert.match(json('{"a":1,"b":2}', '{ "b":2, "a":1 }').message, /exact retained UTF-8 bytes differ/);
  assert.equal(json('"a"', '"\\u0061"').status, 'equal');
  assert.equal(json('"a"', '"\\u0061"').rawStatus, 'different');
  for (const [a, b] of [['9007199254740992', '9007199254740993'], ['1e9999', '1e9998'], ['1', '1.0'], ['0', '-0'], ['1e0', '1']]) {
    const value = json(a, b);
    assert.equal(value.status, 'different'); assert.equal(value.rows[0].before, a); assert.equal(value.rows[0].after, b);
    assert.equal(value.rows[0].path, '', 'Root JSON pointer is the empty string');
  }
  assert.equal(json('{"n":9007199254740993}', '{"n":9007199254740993}').status, 'equal');
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"/":1,"\\/":2}', '{"__proto__":1,"__proto__":2}']) {
    const value = json(text, text);
    assert.equal(value.status, 'unsupported'); assert.equal(value.structuralStatus, 'unsupported');
    assert.equal(value.rawStatus, 'equal'); assert.match(value.message, /Duplicate/);
  }
  assert.equal(json('{"__proto__":1}', '{"__proto__":2}').rows[0].path, '/__proto__');
  const missing = json('{"n":null}', '{}');
  assert.equal(missing.rows[0].path, '/n'); assert.equal(missing.rows[0].kind, 'removed');
  assert.equal(missing.rows[0].before, 'null'); assert.equal(missing.rows[0].after, '(missing)');
  assert.equal(json('{}', '{"n":null}').rows[0].kind, 'added');
  assert.equal(json('null', '{}').rows[0].kind, 'changed');
  assert.equal(json('{"a~/b":{"":1}}', '{"a~/b":{"":2}}').rows[0].path, '/a~0~1b/');
  assert.equal(json('[1,2]', '[2,1]').rows.length, 2);
  assert.equal(json('[1,2]', '[1,2,3]').rows[0].path, '/2');
  assert.equal(json('[1,2]', '[1,2,3]').rows[0].kind, 'added');
  assert.equal(json('[1,2]', '[1]').rows[0].kind, 'removed');
  for (const text of ['{', '{"a":1,}', '[1,]', '01', '1.', '-.1', '1e', 'true false', 'NaN', '"\\x00"', '"raw\nline"', '"unfinished', '\ufeff{}']) {
    const value = json(text, text);
    assert.equal(value.status, 'unsupported', `Reject malformed JSON: ${JSON.stringify(text)}`);
    assert.equal(value.rawStatus, 'equal'); assert.equal(value.structuralStatus, 'unsupported');
  }
  for (const text of ['true', 'false', 'null', '0', '-12.5E-100', '"\\u0000"', '{}', '[]', ' [ true , null ] ']) assert.equal(json(text, text).status, 'equal');
  const deep = '['.repeat(limits.jsonDepth + 2) + '0' + ']'.repeat(limits.jsonDepth + 2);
  assert.equal(json(deep, deep).status, 'incomplete'); assert.match(json(deep, deep).limitReason, /depth/);
  const many = JSON.stringify(Array.from({length: limits.jsonNodes + 1}, () => 1));
  assert.equal(json(many, many).status, 'incomplete'); assert.match(json(many, many).limitReason, /node/);
  const changedMany = json(JSON.stringify(Array.from({length: 100}, () => 1)), JSON.stringify(Array.from({length: 100}, () => 2)));
  assert.equal(changedMany.status, 'different'); assert.equal(changedMany.rows.length, limits.rowsPerSection);
  assert.equal(changedMany.omitted, 100 - limits.rowsPerSection); assert.match(changedMany.message, /36 comparison rows omitted/);
  const longKey = 'a'.repeat(limits.pathCharacters + 1);
  const longPath = json(JSON.stringify({[longKey]: 1}), JSON.stringify({[longKey]: 2}));
  assert.equal(longPath.status, 'different'); assert.equal(longPath.rows.length, 0); assert.equal(longPath.omitted, 1);
  assert.match(longPath.limitReason, /path/);
  const longValue = json(JSON.stringify('a'.repeat(800)), JSON.stringify('b'.repeat(800)));
  assert(longValue.rows[0].before.length <= limits.previewCharacters); assert.match(longValue.rows[0].before, /characters omitted/);
  assert.equal(longValue.rows[0].before[0], '"', 'A clipped preview preserves the original raw lexical prefix');
  const markup = json('{"x":"<img src=x onerror=alert(1)>"}', '{"x":"<script>alert(2)</script>"}');
  assert.equal(markup.rows[0].before, '"<img src=x onerror=alert(1)>"');
  assert.equal(markup.rows[0].after, '"<script>alert(2)</script>"');
  assert.equal(plain('x', 'x').status, 'equal'); assert.equal(plain('x', 'y').status, 'different');
  assert.equal(plain('x', 'y').structuralStatus, null);
  assert.equal(plain('a'.repeat(limits.bodyBytes), 'a'.repeat(limits.bodyBytes)).status, 'equal');
  assert.equal(plain('a'.repeat(limits.bodyBytes + 1), 'a'.repeat(limits.bodyBytes + 1)).status, 'incomplete');
  assert.equal(plain('é'.repeat(limits.bodyBytes / 2 + 1), 'x').status, 'incomplete', 'The byte budget is UTF-8, not UTF-16 length');
  assert.equal(plain('\ud800', '\ud800').status, 'unsupported');
  assert.equal(plain('\udc00', '\udc00').status, 'unsupported');
  assert.equal(plain('😀', '😀').status, 'equal');
  const empty = {state: 'empty'};
  assert.equal(part(result(empty, empty)).status, 'equal');
  assert.equal(part(result(body(''), body(''))).status, 'equal');
  assert.equal(part(result(empty, body('', {mime: 'text/plain'}))).status, 'equal');
  for (const state of ['missing', 'redacted', 'loading', 'error', 'unknown']) {
    assert.equal(part(result({state}, {state})).status, 'unavailable');
    assert.equal(part(result({state}, empty)).status, 'unavailable');
  }
  assert.equal(part(result(undefined, undefined)).status, 'unavailable');
  assert.equal(part(result({state: 'available'}, {state: 'available'})).status, 'unavailable');
  assert.equal(part(result({state: 'empty', text: 'not empty'}, empty)).status, 'unsupported');
  for (const rightText of ['same', 'different']) {
    const value = part(result(body('same', {truncated: true}), body(rightText, {truncated: true})));
    assert.equal(value.status, 'incomplete'); assert.equal(value.rawStatus, 'incomplete');
  }
  const utf8 = new TextEncoder().encode('{"x":9007199254740993}');
  assert.equal(part(result(body('', {bytes: utf8}), body('{"x":9007199254740993}'))).status, 'equal');
  const invalidUtf8 = body('', {bytes: new Uint8Array([0xc0, 0xaf]), mime: 'text/plain'});
  assert.equal(part(result(invalidUtf8, invalidUtf8)).status, 'unsupported');
  assert.equal(part(result(invalidUtf8, invalidUtf8)).rawStatus, 'unsupported');
  const binary = body('', {bytes: new Uint8Array([1, 2, 3]), mime: 'application/octet-stream'});
  assert.equal(part(result(binary, binary)).status, 'unsupported');
  const overBytes = body('', {bytes: new Uint8Array(limits.bodyBytes + 1), mime: 'text/plain'});
  assert.equal(part(result(overBytes, overBytes)).status, 'incomplete');

  const grouped = headers([['X-A', 'one'], ['x-a', 'two'], ['B', '3']], [['b', '3'], ['x-A', 'one'], ['X-a', 'two']]);
  assert.equal(grouped.status, 'equal'); assert.match(grouped.message, /Capture completeness is unverified/);
  const duplicateOrder = headers([['X-A', 'one'], ['x-a', 'two']], [['x-a', 'two'], ['X-A', 'one']]);
  assert.equal(duplicateOrder.status, 'different'); assert.equal(duplicateOrder.rows.length, 1);
  assert.equal(duplicateOrder.rows[0].path, 'x-a'); assert.equal(duplicateOrder.rows[0].before, '["one","two"]');
  assert.equal(headers([], []).status, 'equal');
  assert.equal(headers(undefined, undefined).status, 'unavailable');
  assert.equal(headers(undefined, []).status, 'unavailable');
  assert.equal(headers([['a', 'x']], []).rows[0].kind, 'removed');
  assert.equal(headers([], [['a', 'x']]).rows[0].kind, 'added');
  for (const name of ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-custom']) {
    const value = headers([[name, '<redacted>']], [[name, '<redacted>']]);
    assert.equal(value.status, 'incomplete'); assert.equal(value.rows[0].kind, 'unknown');
    assert.match(value.message, /never establish original equality/);
  }
  assert.equal(headers([['a', '[REDACTED]']], [['a', '[REDACTED]']]).status, 'incomplete');
  assert.equal(headers([['a', 'ok']], [['a', '<redacted>']]).status, 'incomplete');
  assert.equal(headers([['bad name', 'x']], []).status, 'unsupported');
  assert.equal(headers([['a', 3]], []).status, 'unsupported');
  assert.equal(headers(Array.from({length: limits.headerPairs + 1}, () => ['a', 'b']), []).status, 'incomplete');
  assert.equal(headers([['a', 'x'.repeat(limits.headerBytes + 1)]], []).status, 'incomplete');
  assert.equal(part(result({state: 'empty', headers: [], headersTruncated: true}, {state: 'empty', headers: []}), 'Request headers').status, 'incomplete');
  for (const state of [undefined, 'loading', 'missing', 'redacted', 'error']) {
    assert.equal(part(result({state, headers: []}, {state, headers: []}), 'Request headers').status, 'unavailable');
    assert.equal(part(result({state, headers: []}, {state: 'empty', headers: []}), 'Request headers').status, 'unavailable');
    assert.equal(part(result({state, headers: [['x-a', 'known']]}, {state, headers: [['X-A', 'known']]}), 'Request headers').status, 'equal');
  }

  const base = request(body('null'));
  assert.equal(part(compare(base, base), 'General').status, 'equal');
  for (const update of [{method: 'GET'}, {path: 'https://example.test/other'}, {status: 404}]) assert.equal(part(compare(base, {...base, ...update}), 'General').status, 'different');
  for (const update of [{hostOnly: true}, {targetKind: 'unknown'}, {urlTruncated: true}, {status: 'pending'}, {method: 'EVENT'}, {path: undefined}]) {
    assert.equal(part(compare({...base, ...update}, {...base, ...update}), 'General').status, 'incomplete');
  }
  assert.equal(part(compare(null, null), 'General').status, 'incomplete');
  assert.equal(part(compare({...base, path: 'a'.repeat(limits.bodyBytes + 1)}, base), 'General').status, 'incomplete');

  const hugeChanges = n => JSON.stringify(Object.fromEntries(Array.from({length: 70}, (_, index) => ['path-' + index + 'x'.repeat(300), n.repeat(600)])));
  const budget = result(body(hugeChanges('a')), body(hugeChanges('b')));
  let output = 0;
  for (const item of budget.sections) {
    output += item.label.length + item.status.length + item.message.length + item.limitReason.length;
    for (const row of item.rows) output += row.path.length + row.kind.length + row.before.length + row.after.length;
  }
  assert(output <= limits.outputCharacters); assert(budget.sections.some(item => item.limitReason.includes('report limit')));
  const freeze = value => {
    if (!value || typeof value !== 'object') return value;
    for (const child of Object.values(value)) freeze(child);
    return Object.freeze(value);
  };
  const frozen = freeze(request(body('{"a":1}', {headers: [['a', 'b']]})));
  const snapshot = JSON.stringify(frozen);
  assert.equal(part(compare(frozen, frozen)).status, 'equal'); assert.equal(JSON.stringify(frozen), snapshot);
  assert.equal(JSON.stringify(compare(frozen, frozen)), JSON.stringify(compare(frozen, frozen)), 'Comparison is deterministic');
  assert(!/\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|document|window)\b/.test(source), 'Model has no browser, network, or persistence dependencies');
  console.log('PASS bounded Traffic comparison: retained metadata/headers, explicit unknowns, strict UTF-8, lossless JSON lexemes, duplicate rejection, RFC6901 paths, limits and inert previews (not rendered QA)');
}
