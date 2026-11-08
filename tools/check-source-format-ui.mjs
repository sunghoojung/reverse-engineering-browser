// Shipped source_syntax.js, source_format.js and app.css against the Rosé Pine theme and the layout mapping.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {runInNewContext} from 'node:vm';

export async function checkSourceFormatUI(root) {
  const read = path => readFile(join(root, path), 'utf8');
  const fixture = name => read(`tools/fixtures/source-format/${name}`);
  const timers = [];
  const model = runInNewContext(`${await read('apps/research-ui/source_syntax.js')}\n${await read('apps/research-ui/source_format.js')}
    ;({createSourceTokenizer, sourceSyntaxTokens, sourceWhitespaceSegments, sourceFormatRawRange, createSourceFormatClient, SOURCE_HIGHLIGHT_TOKEN_LIMIT})`,
  {URL, AbortController, setTimeout: (callback, delay) => {timers.push({callback, delay}); return timers.length;}, clearTimeout() {}});

  const kinds = (source, text) => {
    const tokenizer = model.createSourceTokenizer(source);
    return text.split('\n').flatMap(line => model.sourceSyntaxTokens(line, tokenizer)).filter(token => token.type !== 'plain' || token.text.trim());
  };
  const expectKinds = (tokens, expected, label) => {
    for (const [text, type] of expected) {
      assert(tokens.some(token => token.text === text && token.type === type), `${label}: ${JSON.stringify(text)} is ${type}; got ${JSON.stringify(tokens.filter(token => token.text === text).map(token => token.type))}`);
    }
  };

  // JavaScript: the issue's scope table on the formatted sample.
  const formatted = await fixture('minified.prettier.js');
  const javascript = kinds({kind: 'javascript'}, formatted);
  expectKinds(javascript, [
    ['var', 'keyword'], ['function', 'keyword'], ['return', 'keyword'], ['if', 'keyword'], ['async', 'keyword'], ['await', 'keyword'],
    ['=', 'operator'], ['+', 'operator'], ['??', 'operator'], ['=>', 'operator'], ['?.', 'operator'], ['.', 'operator'], ['!', 'operator'], ['++', 'operator'],
    [',', 'punctuation'], [';', 'punctuation'], [':', 'punctuation'],
    ['a', 'function'], ['t', 'function'], ['fetch', 'function'], ['fn', 'function'],
    ['e', 'parameter'], ['JSON', 'constant'], ['stringify', 'builtin-function'], ['length', 'builtin'],
    ['null', 'number'], ['0', 'number'], ['"POST"', 'string'], ['ok', 'property'], ['n', 'property']
  ], 'JavaScript');
  assert.deepEqual(javascript.filter(token => /^bracket-/.test(token.type)).slice(0, 4).map(token => [token.text, token.type]),
    [['(', 'bracket-0'], [')', 'bracket-0'], ['{', 'bracket-0'], ['(', 'bracket-1']], 'Bracket pairs take depth colors');
  expectKinds(kinds({kind: 'javascript'}, 'class A extends B.C { m(p, q = 1) { console.log(`x${this.y}\\n`, /re+/g); window.addEventListener("x", f) } } // note'), [
    ['class', 'keyword'], ['A', 'type'], ['B', 'inherited'], ['C', 'inherited'], ['m', 'function'], ['p', 'parameter'], ['q', 'parameter'],
    ['console', 'builtin'], ['log', 'builtin-function'], ['this', 'keyword'], ['${', 'bracket-0'], ['\\n', 'escape'], ['/re+/g', 'regexp'],
    ['window', 'builtin'], ['addEventListener', 'builtin-function'], ['//', 'comment-mark'], [' note', 'comment']
  ], 'JavaScript scopes');
  expectKinds(kinds({kind: 'source_map'}, await fixture('sample.json')), [
    ['name', 'key'], ['"', 'punctuation'], ['"fixture"', 'string'], ['-2.5', 'number'], ['true', 'number'], ['null', 'number'], ['\\n', 'escape'], [',', 'punctuation'], ['":', 'punctuation']
  ], 'JSON');
  expectKinds(kinds({kind: 'style', mime_type: 'text/css'}, await fixture('sample.css')), [
    ['@media', 'keyword'], ['max-width', 'key'], ['a', 'tag'], [':hover', 'attribute'], ['.note', 'attribute'], ['color', 'key'], ['#fff', 'keyword'],
    ['4', 'number'], ['px', 'unit'], ['!important', 'keyword'], ['--gap', 'variable'], ['calc', 'builtin-function'], ['/*', 'comment-mark']
  ], 'CSS');
  expectKinds(kinds({kind: 'document', mime_type: 'text/html'}, await fixture('sample.html')), [
    ['<!', 'tag-mark'], ['DOCTYPE', 'tag'], ['div', 'tag'], ['class', 'attribute'], ['"note"', 'string'], ['main', 'string'], ['&amp;', 'escape'], ['<!--', 'comment-mark']
  ], 'HTML');
  const limited = model.createSourceTokenizer({kind: 'javascript'});
  limited.coloredTokens = model.SOURCE_HIGHLIGHT_TOKEN_LIMIT;
  assert.deepEqual(Array.from(model.sourceSyntaxTokens('a + b', limited), token => token.type), ['plain'], 'The colored-token bound still applies');

  // app.css: every kind resolves to the theme's published color and style.
  const css = await read('apps/research-ui/app.css');
  const block = selector => css.slice(css.indexOf(`${selector} {`), css.indexOf('}', css.indexOf(`${selector} {`)));
  const value = (text, name) => text.match(new RegExp(`${name}:\\s*(#[0-9a-f]+)`, 'i'))?.[1];
  const palettes = {
    ':root': {comment: '#6e6a86', punctuation: '#908caa', keyword: '#3e8fb0', string: '#f6c177', number: '#ea9a97', type: '#9ccfd8', 'support-function': '#eb6f92', parameter: '#c4a7e7',
      'bracket-1': '#eb6f9280', 'bracket-2': '#3e8fb080', 'bracket-3': '#f6c17780', bg: '#232136', text: '#e0def4', 'line-number': '#908caa', 'line-highlight': '#817c9c14', selection: '#817c9c26', 'indent-guide': '#817c9c4d'},
    ':root[data-theme="light"]': {comment: '#9893a5', punctuation: '#797593', keyword: '#286983', string: '#ea9d34', number: '#d7827e', type: '#56949f', 'support-function': '#b4637a', parameter: '#907aa9',
      'bracket-1': '#b4637a80', 'bracket-2': '#28698380', 'bracket-3': '#ea9d3480', bg: '#faf4ed', text: '#575279', 'line-number': '#797593', 'line-highlight': '#6e6a860d', selection: '#6e6a8614', 'indent-guide': '#6e6a8626'}
  };
  for (const [selector, palette] of Object.entries(palettes)) {
    const text = block(`      ${selector}`);
    for (const [name, color] of Object.entries(palette)) {
      const variable = ['bg', 'text', 'line-number', 'line-highlight', 'selection', 'indent-guide'].includes(name) ? `--code-${name}` : `--syntax-${name}`;
      assert.equal(value(text, variable), color, `${selector} ${variable}`);
    }
  }
  const rule = kind => css.match(new RegExp(`[^}]*\\.syntax-${kind}\\b[^{]*\\{([^}]*)\\}`))?.[1] ?? '';
  for (const [kind, variable, italic] of [
    ['comment', '--syntax-comment', true], ['keyword', '--syntax-keyword'], ['operator', '--syntax-keyword'], ['punctuation', '--syntax-punctuation'],
    ['string', '--syntax-string'], ['regexp', '--syntax-string'], ['number', '--syntax-number'], ['function', '--syntax-number'],
    ['type', '--syntax-type'], ['builtin', '--syntax-type'], ['key', '--syntax-type'], ['tag', '--syntax-type'], ['builtin-function', '--syntax-support-function', true],
    ['parameter', '--syntax-parameter'], ['attribute', '--syntax-parameter', true], ['inherited', '--syntax-parameter', true], ['property', '--code-text'],
    ['bracket-0', '--syntax-bracket-1'], ['bracket-1', '--syntax-bracket-2'], ['bracket-2', '--syntax-bracket-3']
  ]) {
    assert(rule(kind).includes(`var(${variable})`), `.syntax-${kind} uses ${variable}`);
    assert.equal(rule(kind).includes('italic'), Boolean(italic), `.syntax-${kind} font style`);
  }
  const contrast = css.slice(css.indexOf('@media (prefers-contrast: more)'));
  assert(/--syntax-comment: #908caa; --syntax-keyword: #4fa0c1/.test(contrast), 'Increase Contrast brightens Moon comments and keywords');
  assert(/font: 12px\/18px var\(--code-font\)/.test(block('      .source-code')) && css.includes('--code-font: Menlo, Monaco, "Courier New", monospace;'), 'VS Code macOS editor font');

  // Mapping: whitespace-only, exact by construction, refused otherwise.
  const original = (await fixture('minified.js')).trimEnd();
  const segments = model.sourceWhitespaceSegments(original, formatted);
  assert(segments?.length > 0);
  for (const segment of segments) assert.equal(formatted.slice(segment.derived_start, segment.derived_end), original.slice(segment.original_start, segment.original_end));
  const at = formatted.indexOf('stringify');
  assert.deepEqual({...model.sourceFormatRawRange(segments, at, at + 9)}, {start: original.indexOf('stringify'), end: original.indexOf('stringify') + 9});
  assert.equal(model.sourceWhitespaceSegments('a=1', 'a = 2'), null, 'Any non-whitespace difference is refused');
  assert.equal(model.sourceWhitespaceSegments('a\u0085b', 'ab'), null, 'NEL is not JavaScript whitespace');
  assert(model.sourceWhitespaceSegments('﻿a=1; b', 'a = 1;\n  b'), 'BOM and line separators are layout whitespace');

  // Client: pending, formatted, unavailable and failed layouts.
  const source = {source_type: 'artifact', kind: 'javascript', session_id: '1', artifact_id: '7', sha256: 'f'.repeat(64), byte_size: original.length, content: original};
  const replies = [];
  const changes = [];
  const client = model.createSourceFormatClient({request: async url => replies.shift()(url), onChange: changed => changes.push(changed.artifact_id)});
  const reply = (status, body) => url => ({ok: status === 200, status, json: async () => ({...body, url})});
  const document = (extra, sha256 = source.sha256) => ({schema: 'source-format-v1', mapping: 'whitespace-only', source: {artifact_id: '7', sha256}, ...extra});
  const settle = () => new Promise(resolve => setImmediate(resolve));
  replies.push(reply(200, document({status: 'formatted', text: formatted})));
  assert.equal(client.view(source, original).pending, true);
  await settle();
  const view = client.view(source, original);
  assert.equal(view.text, formatted); assert.equal(view.engine, 'oxc'); assert.equal(view.offset_unit, 'utf-16-code-unit'); assert.deepEqual(changes, ['7']);
  assert.equal(client.view({...source, contentTruncated: true}, original), null, 'A truncated preview keeps the in-page formatter');
  assert.equal(client.view(source, `${original};`), null, 'Derived text keeps the in-page formatter');
  for (const [index, [body, notice]] of [
    [sha256 => document({status: 'unavailable', reason: 'parse-failed', detail: 'The source does not parse.'}, sha256), /could not parse/],
    [() => ({error: 'The Oxc layout needs a live workspace'}), /live workspace/],
    [sha256 => document({status: 'formatted', text: 'var b = 1;'}, sha256), /beyond whitespace/],
    [sha256 => ({...document({status: 'formatted', text: formatted}, sha256), source: {artifact_id: '8', sha256}}), /does not match/]
  ].entries()) {
    const other = {...source, sha256: String(index).repeat(64)};
    replies.push(reply(index === 1 ? 503 : 200, body(other.sha256)));
    assert.equal(client.view(other, original).pending, true);
    await settle();
    const fallback = client.view(other, original);
    assert.equal(fallback.fallback, true); assert.match(fallback.notice, notice);
    replies.push(reply(200, document({status: 'formatted', text: formatted}, other.sha256)));
    client.forget(other);
    assert.equal(client.view(other, original).pending, true, 'A failed layout retries when asked again');
    await settle();
    assert.equal(client.view(other, original).text, formatted);
  }
  assert(timers.every(timer => timer.delay === 180000), 'Each request has a deadline');
  console.log('PASS source format UI: TextMate-scope token kinds for JavaScript, JSON, CSS and HTML fixtures, Rosé Pine Moon/Dawn values and Increase Contrast in app.css, exact whitespace-only mapping and raw ranges, client pending/formatted/fallback/retry (shipped modules, not rendered QA)');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await checkSourceFormatUI(fileURLToPath(new URL('..', import.meta.url)));
