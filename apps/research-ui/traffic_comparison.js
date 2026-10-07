/* Pure, read-only comparisons of bounded retained Traffic evidence. No wire replay. */
const TRAFFIC_COMPARISON_LIMITS = Object.freeze({
  bodyBytes: 128 * 1024, headerBytes: 128 * 1024, headerPairs: 256,
  jsonDepth: 24, jsonNodes: 4096, rowsPerSection: 64,
  outputCharacters: 64 * 1024, previewCharacters: 512, pathCharacters: 2048
});

function trafficCompareRequests(left, right) {
  const limits = TRAFFIC_COMPARISON_LIMITS;
  // Reserve bounded space for section explanations as well as row previews.
  let remaining = limits.outputCharacters - 8192;
  const section = label => ({label, status: 'unavailable', message: '', rows: [], omitted: 0, limitReason: ''});
  const noteLimit = (result, reason) => {
    if (!result.limitReason.includes(reason)) result.limitReason += (result.limitReason ? '; ' : '') + reason;
  };
  const clip = value => {
    if (value.length <= limits.previewCharacters) return value;
    const keep = limits.previewCharacters - 40;
    return value.slice(0, keep) + `… (${value.length - keep} characters omitted)`;
  };
  const row = (result, path, kind, before, after) => {
    if (path === null || path.length > limits.pathCharacters) {
      result.omitted++; noteLimit(result, `${limits.pathCharacters}-character path limit`); return;
    }
    before = clip(before); after = clip(after);
    const size = path.length + kind.length + before.length + after.length;
    if (result.rows.length >= limits.rowsPerSection || size > remaining) {
      result.omitted++;
      noteLimit(result, result.rows.length >= limits.rowsPerSection
        ? `${limits.rowsPerSection} rows per section` : `${limits.outputCharacters}-character report limit`);
      return;
    }
    remaining -= size;
    result.rows.push({path, kind, before, after});
  };
  const finish = result => {
    if (result.omitted) result.message += ` ${result.omitted} comparison rows omitted.`;
    if (result.limitReason) result.message += ` Limit: ${result.limitReason}.`;
    return result;
  };
  const scalar = value => typeof value === 'string' || typeof value === 'number' && Number.isFinite(value)
    ? String(value) : null;
  const redacted = value => /<redacted>|\[redacted\]|\(redacted\)|^redacted$/i.test(value);

  function general() {
    const result = section('General');
    let changed = false, unknown = false;
    const fields = [
      {path: 'Method', value: item => item?.method, unknown: item => item?.methodTruncated === true || item?.method === 'EVENT'},
      {path: 'URL', value: item => item?.path, unknown: item => item?.hostOnly === true || item?.targetKind === 'unknown' || item?.urlTruncated === true},
      {path: 'Status', value: item => item?.status, unknown: item => item?.status === 'pending'}
    ];
    for (const field of fields) {
      const a = scalar(field.value(left)), b = scalar(field.value(right));
      const unavailable = a === null || b === null || a === '' || b === '' || field.unknown(left) || field.unknown(right);
      // Reject an oversized field before scanning or comparing it.
      const bounded = a !== null && b !== null && a.length <= limits.bodyBytes && b.length <= limits.bodyBytes;
      if (unavailable || !bounded) {
        unknown = true;
        if (!bounded && a !== null && b !== null) noteLimit(result, '128 KiB metadata field limit');
        row(result, field.path, 'unknown', a ?? '(not captured)', b ?? '(not captured)');
      } else if (a !== b) {
        changed = true; row(result, field.path, 'changed', a, b);
      }
    }
    result.status = unknown ? 'incomplete' : changed ? 'different' : 'equal';
    result.message = unknown
      ? 'Some method, URL, or status metadata is unavailable, pending, host-only, or truncated. Unknown rows cannot establish equality.'
      : changed ? 'Retained method, URL, or status metadata differs.' : 'Retained method, URL, and status metadata match.';
    return finish(result);
  }

  function headerModel(record) {
    if (!Array.isArray(record?.headers)) return {status: 'unavailable', reason: 'Headers were not captured.'};
    if (!record.headers.length && !['available', 'empty'].includes(record.state)) {
      return {status: 'unavailable', reason: 'No retained headers and no completed body capture; header equality is unknown.'};
    }
    const groups = new Map();
    let used = 0, hidden = false;
    if (record.headers.length > limits.headerPairs) return {status: 'incomplete', reason: `${limits.headerPairs}-header-pair limit; ${record.headers.length - limits.headerPairs} additional pairs not inspected.`};
    for (const entry of record.headers) {
      if (!Array.isArray(entry) || entry.length !== 2 || entry.some(value => typeof value !== 'string')) {
        return {status: 'unsupported', reason: 'Malformed retained header pair.'};
      }
      const [name, value] = entry;
      if (used + name.length + value.length > limits.headerBytes) return {status: 'incomplete', reason: '128 KiB header byte limit.'};
      // Encode only after bounding UTF-16 length; UTF-8 allocations remain bounded.
      used += new TextEncoder().encode(name).length + new TextEncoder().encode(value).length;
      if (used > limits.headerBytes) return {status: 'incomplete', reason: '128 KiB header byte limit.'};
      if (!name || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) return {status: 'unsupported', reason: 'Invalid retained header name.'};
      const key = name.toLowerCase();
      const group = groups.get(key) ?? {values: [], redacted: false};
      group.values.push(value);
      group.redacted ||= redacted(value) || ['authorization', 'proxy-authorization', 'cookie', 'set-cookie'].includes(key);
      hidden ||= group.redacted;
      groups.set(key, group);
    }
    return {status: record.headersTruncated === true || record.headers_truncated === true ? 'incomplete' : 'available', groups, hidden,
      reason: record.headersTruncated === true || record.headers_truncated === true ? 'Retained headers are marked truncated.' : ''};
  }

  function headers(label, aRecord, bRecord) {
    const result = section(label), a = headerModel(aRecord), b = headerModel(bRecord);
    if (!a.groups || !b.groups) {
      result.status = [a.status, b.status].includes('incomplete') ? 'incomplete'
        : [a.status, b.status].includes('unsupported') ? 'unsupported' : 'unavailable';
      result.message = `Before: ${a.reason || 'Retained headers available.'} After: ${b.reason || 'Retained headers available.'}`;
      if (result.status === 'incomplete') noteLimit(result, a.reason || b.reason);
      return finish(result);
    }
    let changes = 0;
    const names = [...new Set([...a.groups.keys(), ...b.groups.keys()])].sort();
    for (const name of names) {
      const before = a.groups.get(name), after = b.groups.get(name);
      const unknown = before?.redacted || after?.redacted;
      const equal = before && after && before.values.length === after.values.length && before.values.every((value, index) => value === after.values[index]);
      if (equal && !unknown) continue;
      changes++;
      row(result, name, unknown ? 'unknown' : !before ? 'added' : !after ? 'removed' : 'changed',
        before ? JSON.stringify(before.values) : '(missing)', after ? JSON.stringify(after.values) : '(missing)');
    }
    const incomplete = a.status === 'incomplete' || b.status === 'incomplete' || a.hidden || b.hidden;
    result.status = incomplete ? 'incomplete' : changes ? 'different' : 'equal';
    result.message = incomplete ? 'Retained header comparison is incomplete. Redacted values never establish original equality.'
      : changes ? 'Retained header groups differ.' : 'Retained header groups match.';
    result.message += ' Names are case-insensitive; duplicate values keep their captured order. Capture completeness is unverified.';
    if (a.reason || b.reason) result.message += ` ${a.reason} ${b.reason}`.trimEnd();
    return finish(result);
  }

  function bodyModel(record) {
    if (!record) return {status: 'unavailable', reason: 'Body was not captured.'};
    const reason = typeof record.reason === 'string' && record.reason ? ` ${clip(record.reason)}` : '';
    if (record.state !== 'available' && record.state !== 'empty') {
      const messages = {missing: 'Body was not captured.', redacted: 'Body was redacted.', loading: 'Body is still loading.', error: 'Body could not be loaded.'};
      return {status: 'unavailable', reason: (messages[record.state] || 'Body capture state is unavailable.') + reason};
    }
    if (record.truncated === true) return {status: 'incomplete', reason: 'Body is a retained prefix (capture truncated); full equality is unknown.'};
    let bytes;
    if (record.bytes instanceof Uint8Array) {
      if (record.bytes.byteLength > limits.bodyBytes) return {status: 'incomplete', reason: '128 KiB body byte limit.'};
      bytes = record.bytes;
    } else if (typeof record.text === 'string') {
      if (record.text.length > limits.bodyBytes) return {status: 'incomplete', reason: '128 KiB body byte limit.'};
      // TextEncoder replaces unpaired UTF-16 surrogates, so reject them first.
      for (let index = 0; index < record.text.length; index++) {
        const code = record.text.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = record.text.charCodeAt(++index);
          if (!(next >= 0xdc00 && next <= 0xdfff)) return {status: 'unsupported', reason: 'Body contains invalid UTF-16; lossless UTF-8 comparison is unavailable.'};
        } else if (code >= 0xdc00 && code <= 0xdfff) return {status: 'unsupported', reason: 'Body contains invalid UTF-16; lossless UTF-8 comparison is unavailable.'};
      }
      bytes = new TextEncoder().encode(record.text);
      if (bytes.byteLength > limits.bodyBytes) return {status: 'incomplete', reason: '128 KiB body byte limit.'};
    } else if (record.state === 'empty') bytes = new Uint8Array();
    else return {status: 'unavailable', reason: 'Available body state has no retained text or bytes.'};
    if (record.state === 'empty' && bytes.length) return {status: 'unsupported', reason: 'Empty body state conflicts with retained bytes.'};
    const mime = typeof record.mime === 'string' && record.mime.length <= 512 ? record.mime.split(';')[0].trim().toLowerCase() : '';
    const json = /^(?:application|text)\/(?:[a-z0-9!#$&^_.+-]+\+)?json$/.test(mime);
    const textual = !mime || /^text\//.test(mime) || json || /^(?:application\/(?:[a-z0-9!#$&^_.+-]+\+)?xml|application\/(?:javascript|x-javascript|x-www-form-urlencoded))$/.test(mime);
    if (!textual && bytes.length) return {status: 'unsupported', reason: 'Binary or unsupported MIME body; no text or structural equality is claimed.'};
    try {
      // Keep a BOM rather than silently normalizing retained bytes.
      const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);
      return {status: 'available', text, bytes, json};
    } catch {
      return {status: 'unsupported', reason: 'Body contains invalid UTF-8; no text or structural equality is claimed.'};
    }
  }

  function bodies(label, aRecord, bRecord) {
    const result = section(label), a = bodyModel(aRecord), b = bodyModel(bRecord);
    result.rawStatus = 'unavailable'; result.structuralStatus = null;
    if (a.status !== 'available' || b.status !== 'available') {
      result.status = [a.status, b.status].includes('incomplete') ? 'incomplete'
        : [a.status, b.status].includes('unsupported') ? 'unsupported' : 'unavailable';
      result.rawStatus = result.status;
      result.message = `Before: ${a.reason || 'Complete retained body available.'} After: ${b.reason || 'Complete retained body available.'}`;
      if (result.status === 'incomplete') noteLimit(result, a.reason || b.reason);
      return finish(result);
    }
    const rawEqual = a.bytes.length === b.bytes.length && a.bytes.every((byte, index) => byte === b.bytes[index]);
    result.rawStatus = rawEqual ? 'equal' : 'different';
    // Explicitly empty retained bodies are comparable even with a JSON MIME type.
    if (!a.text.length && !b.text.length) {
      result.status = 'equal'; result.message = 'Both retained bodies are explicitly empty. Exact retained UTF-8 bytes match.';
      return finish(result);
    }
    if (!a.json || !b.json) {
      result.status = rawEqual ? 'equal' : 'different';
      result.message = rawEqual ? 'Exact retained UTF-8 bytes match.' : 'Exact retained UTF-8 bytes differ.';
      result.message += a.json !== b.json ? ' Structural JSON comparison requires JSON MIME types on both sides.' : ' Structural JSON comparison does not apply to this MIME type.';
      if (!rawEqual) row(result, '', 'changed', a.text, b.text);
      return finish(result);
    }
    let before, after;
    try {
      before = trafficComparisonParseJson(a.text, limits);
      after = trafficComparisonParseJson(b.text, limits);
    } catch (error) {
      result.status = error.comparisonLimit ? 'incomplete' : 'unsupported';
      result.structuralStatus = result.status;
      result.message = `Exact retained UTF-8 bytes ${rawEqual ? 'match' : 'differ'}. Structural JSON comparison unavailable: ${error.message}`;
      if (error.comparisonLimit) noteLimit(result, error.message);
      return finish(result);
    }
    let changes = 0;
    const pathFor = (path, key) => path === null || key.length > limits.pathCharacters ? null
      : path + '/' + key.replace(/~/g, '~0').replace(/\//g, '~1');
    const preview = (node, text) => node ? text.slice(node.start, node.end) : '(missing)';
    const compare = (one, two, path) => {
      if (!one || !two || one.type !== two.type) {
        changes++; row(result, path, !one ? 'added' : !two ? 'removed' : 'changed', preview(one, a.text), preview(two, b.text)); return;
      }
      if (one.type === 'object') {
        const keys = [...new Set([...one.value.keys(), ...two.value.keys()])].sort();
        for (const key of keys) compare(one.value.get(key), two.value.get(key), pathFor(path, key));
      } else if (one.type === 'array') {
        for (let index = 0; index < Math.max(one.value.length, two.value.length); index++) compare(one.value[index], two.value[index], pathFor(path, String(index)));
      } else if (one.value !== two.value) {
        changes++; row(result, path, 'changed', preview(one, a.text), preview(two, b.text));
      }
    };
    compare(before, after, '');
    result.status = changes ? 'different' : 'equal';
    result.structuralStatus = result.status;
    result.message = `JSON structure ${changes ? 'differs' : 'matches'}; exact retained UTF-8 bytes ${rawEqual ? 'match' : 'differ'}. Object key order is ignored; arrays match by index; number lexemes are compared exactly. Previews preserve raw lexemes and clip at ${limits.previewCharacters} characters.`;
    return finish(result);
  }

  return {sections: [general(), headers('Request headers', left?.exchange?.request, right?.exchange?.request),
    bodies('Request body', left?.exchange?.request, right?.exchange?.request),
    headers('Response headers', left?.exchange?.response, right?.exchange?.response),
    bodies('Response body', left?.exchange?.response, right?.exchange?.response)], limits: {...limits}};
}

// Span-based lexical parser. Only individual string tokens use JSON.parse; numeric
// tokens are never converted to Number and object members never overwrite a key.
function trafficComparisonParseJson(text, limits) {
  let position = 0, nodes = 0;
  const fail = (message, comparisonLimit = false) => {
    const error = new Error(message); error.comparisonLimit = comparisonLimit; throw error;
  };
  const space = () => { while (position < text.length && /[ \t\r\n]/.test(text[position])) position++; };
  const count = () => { if (++nodes > limits.jsonNodes) fail(`${limits.jsonNodes}-node JSON limit.`, true); };
  function string() {
    const start = position++;
    while (position < text.length) {
      const character = text[position++];
      if (character === '"') return JSON.parse(text.slice(start, position));
      if (character.charCodeAt(0) < 32) fail('Malformed JSON string.');
      if (character === '\\') {
        const escape = text[position++];
        if (escape === 'u') {
          for (let index = 0; index < 4; index++) if (!/^[0-9a-f]$/i.test(text[position++] ?? '')) fail('Malformed JSON escape.');
        } else if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) fail('Malformed JSON escape.');
      }
    }
    fail('Unterminated JSON string.');
  }
  const digit = () => position < text.length && text.charCodeAt(position) >= 48 && text.charCodeAt(position) <= 57;
  function number() {
    const start = position;
    if (text[position] === '-') position++;
    if (text[position] === '0') position++;
    else { if (!digit()) fail('Malformed JSON number.'); while (digit()) position++; }
    if (text[position] === '.') { position++; if (!digit()) fail('Malformed JSON number.'); while (digit()) position++; }
    if (text[position] === 'e' || text[position] === 'E') {
      position++; if (text[position] === '+' || text[position] === '-') position++;
      if (!digit()) fail('Malformed JSON number.'); while (digit()) position++;
    }
    return text.slice(start, position);
  }
  function value(depth) {
    count(); if (depth > limits.jsonDepth) fail(`${limits.jsonDepth}-level JSON depth limit.`, true);
    space(); const start = position, token = text[position];
    let type, parsed;
    if (token === '{') {
      type = 'object'; parsed = new Map(); position++; space();
      if (text[position] !== '}') {
        while (true) {
          space(); if (text[position] !== '"') fail('Malformed JSON object key.');
          count(); const key = string();
          if (parsed.has(key)) fail('Duplicate JSON object keys are ambiguous (including equivalent escaped keys).');
          space(); if (text[position++] !== ':') fail('Malformed JSON object separator.');
          parsed.set(key, value(depth + 1)); space();
          if (text[position] !== ',') break; position++;
        }
      }
      if (text[position++] !== '}') fail('Malformed JSON object.');
    } else if (token === '[') {
      type = 'array'; parsed = []; position++; space();
      if (text[position] !== ']') {
        while (true) {
          parsed.push(value(depth + 1)); space();
          if (text[position] !== ',') break; position++;
        }
      }
      if (text[position++] !== ']') fail('Malformed JSON array.');
    } else if (token === '"') { type = 'string'; parsed = string(); }
    else if (token === '-' || digit()) { type = 'number'; parsed = number(); }
    else {
      const literal = ['true', 'false', 'null'].find(item => text.startsWith(item, position));
      if (!literal) fail('Malformed JSON value.');
      type = literal === 'null' ? 'null' : 'boolean'; parsed = literal; position += literal.length;
    }
    return {type, value: parsed, start, end: position};
  }
  const root = value(0); space();
  if (position !== text.length) fail('Unexpected text after the JSON value.');
  return root;
}
