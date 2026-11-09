// Shipped source_syntax.js, source_format.js, code_view.js and app.css against the Rosé Pine theme, the layout mapping and paged layouts.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createContext, runInContext, runInNewContext} from 'node:vm';

export async function checkSourceFormatUI(root) {
  const read = path => readFile(join(root, path), 'utf8');
  const fixture = name => read(`tools/fixtures/source-format/${name}`);
  const timers = [];
  const syntax = await read('apps/research-ui/source_syntax.js'), format = await read('apps/research-ui/source_format.js');
  const codeView = await read('apps/research-ui/code_view.js');
  const model = runInNewContext(`${syntax}\n${format}\n${codeView}
    ;({createSourceTokenizer, sourceSyntaxTokens, sourceWhitespaceMap, sourceWhitespaceWalker, sourceWhitespaceRange, sourceWhitespaceInverse, sourceLayoutTask, createSourceLayoutWorker,
      createSourceFormatClient, sourceFormatLanguage, sourceFormatBlock, prettyPrintSource, SOURCE_HIGHLIGHT_TOKEN_LIMIT, sourceDocumentIndex, sourcePageIndex,
      sourceDocumentWindow, sourceDocumentOffset, sourceDocumentPosition, sourceDocumentMatches, sourceWindowMapping, createSourceHighlighter, codeViewRows})`,
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

  // JavaScript: the kinds rendered VS Code gives the formatted sample.
  const formatted = await fixture('minified.prettier.js');
  const javascript = kinds({kind: 'javascript'}, formatted);
  expectKinds(javascript, [
    ['var', 'keyword'], ['function', 'keyword'], ['return', 'keyword'], ['if', 'keyword'], ['async', 'keyword'], ['await', 'keyword'],
    ['=', 'operator'], ['+', 'operator'], ['??', 'operator'], ['=>', 'operator'], ['?.', 'operator'], ['.', 'operator'], ['!', 'operator'], ['++', 'operator'],
    [',', 'punctuation'], [';', 'punctuation'], [':', 'punctuation'],
    ['a', 'function'], ['t', 'function'], ['fetch', 'function'], ['fn', 'function'],
    ['e', 'parameter'], ['JSON', 'variable-other'], ['stringify', 'function'], ['length', 'builtin'],
    ['null', 'number'], ['0', 'number'], ['"POST"', 'string'], ['ok', 'property'], ['n', 'variable-other']
  ], 'JavaScript');
  assert.deepEqual(javascript.filter(token => /^bracket-/.test(token.type)).slice(0, 4).map(token => [token.text, token.type]),
    [['(', 'bracket-0'], [')', 'bracket-0'], ['{', 'bracket-0'], ['(', 'bracket-1']], 'Bracket pairs take depth colors');
  assert.deepEqual(kinds({kind: 'javascript'}, '((((((((').map(token => token.type),
    ['bracket-0', 'bracket-1', 'bracket-2', 'bracket-3', 'bracket-4', 'bracket-5', 'bracket-0', 'bracket-1'], 'Bracket depth cycles through six colors');
  expectKinds(kinds({kind: 'javascript'}, 'class A extends B.C { m(p, q = 1) { console.log(`x${this.y}\\n`, /re+/g); window.addEventListener("x", f) } } // note'), [
    ['class', 'keyword'], ['A', 'type'], ['B', 'type'], ['C', 'inherited'], ['m', 'function'], ['p', 'parameter'], ['q', 'parameter'],
    ['console', 'variable-other'], ['log', 'function'], ['this', 'this'], ['${', 'bracket-3'], ['\\n', 'escape'], ['/re', 'regexp'], ['+', 'keyword'], ['/', 'regexp'], ['g', 'keyword'],
    ['window', 'variable-other'], ['addEventListener', 'function'], ['//', 'comment-mark'], [' note', 'comment']
  ], 'JavaScript scopes');
  // Constructs the grammar scopes apart from plain variables and calls.
  expectKinds(kinds({kind: 'javascript'}, `import { x as y } from "./m.js"; import * as ns from "m";
class Foo { static count = 0; #priv = 1; #run() {} f = () => 1; constructor(a) { super(a); this.#priv = 2; } }
const arrow = (m) => m, one = z => z; let plain = () => 1;
var big = 10n, re = /a(?:b)[c-d]{1,2}\\.$/gi, ok = s instanceof Object, d = new Date(), p = new Promise(r => r());
var {key: value} = o, e = Foo.prototype, m = module.exports; o = {x: 1}; label: for (;;) { break label; }`), [
    ['as', 'keyword'], ['y', 'variable-other'], ['*', 'number'], ['count', 'variable'], ['#priv', 'variable'], ['#priv', 'variable-other'], ['#', 'text'], ['run', 'function'], ['f', 'function'],
    ['constructor', 'keyword'], ['super', 'variable-other'], ['arrow', 'variable'], ['one', 'variable'], ['plain', 'function'], ['10', 'number'], ['n', 'keyword'],
    ['(?:', 'punctuation'], [')[', 'punctuation'], ['c-d', 'keyword'], ['{1,2}\\.$', 'keyword'], ['gi', 'keyword'],
    ['Object', 'type'], ['Date', 'function'], ['Promise', 'builtin'], ['key', 'variable'], ['Foo', 'builtin'], ['prototype', 'builtin'], ['module', 'builtin'], ['exports', 'builtin'],
    ['x', 'property'], ['label', 'function']
  ], 'JavaScript constructs');
  expectKinds(kinds({kind: 'source_map'}, await fixture('sample.json')), [
    ['name', 'key'], ['"', 'punctuation'], ['"fixture"', 'string'], ['-2.5', 'number'], ['true', 'number'], ['null', 'number'], ['\\n', 'escape'], [',', 'punctuation'], ['":', 'punctuation']
  ], 'JSON');
  expectKinds(kinds({kind: 'style', mime_type: 'text/css'}, await fixture('sample.css')), [
    ['@', 'punctuation'], ['media', 'keyword'], ['max-width', 'key'], ['a', 'tag'], [':', 'attribute-mark'], ['hover', 'attribute'], ['.', 'attribute-mark'], ['note', 'attribute'], ['::', 'attribute-mark'], ['before', 'attribute'],
    ['color', 'key'], ['#', 'punctuation'], ['fff', 'keyword'], ['4', 'number'], ['px', 'unit'], ['!important', 'keyword'], ['--gap', 'variable'], ['--gap', 'variable-other'], ['calc', 'builtin-function'], ['/*', 'comment-mark']
  ], 'CSS');
  expectKinds(kinds({kind: 'style', mime_type: 'text/css'}, '@keyframes k { from { top: 0 } } a[b^="c" i] { d: url(e.png); f: 1px/2; } .g { &:hover { h: i; } }'), [
    ['k', 'parameter'], ['from', 'text'], ['b', 'attribute'], ['^=', 'keyword'], ['i', 'keyword'], ['url', 'builtin-function'], ['e.png', 'parameter'], ['/', 'constant'], ['&', 'tag'], ['hover', 'attribute']
  ], 'CSS constructs');
  expectKinds(kinds({kind: 'document', mime_type: 'text/html'}, await fixture('sample.html')), [
    ['<!', 'tag-mark'], ['DOCTYPE', 'tag'], ['div', 'tag'], ['class', 'attribute'], ['"note"', 'string'], ['main', 'string'], ['&', 'punctuation'], ['amp', 'escape'], [';', 'punctuation'], ['Tom', 'text'], ['Jerry', 'text'], ['<!--', 'comment-mark']
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
      'bracket-1': '#eb6f9280', 'bracket-2': '#3e8fb080', 'bracket-3': '#f6c17780', 'bracket-4': '#9ccfd880', 'bracket-5': '#ea9a9780', 'bracket-6': '#c4a7e780', bg: '#232136', text: '#e0def4', 'line-number': '#908caa', 'line-highlight': '#817c9c14', selection: '#817c9c26', 'indent-guide': '#817c9c4d'},
    ':root[data-theme="light"]': {comment: '#9893a5', punctuation: '#797593', keyword: '#286983', string: '#ea9d34', number: '#d7827e', type: '#56949f', 'support-function': '#b4637a', parameter: '#907aa9',
      'bracket-1': '#b4637a80', 'bracket-2': '#28698380', 'bracket-3': '#ea9d3480', 'bracket-4': '#56949f80', 'bracket-5': '#d7827e80', 'bracket-6': '#907aa980', bg: '#faf4ed', text: '#575279', 'line-number': '#797593', 'line-highlight': '#6e6a860d', selection: '#6e6a8614', 'indent-guide': '#6e6a8626'}
  };
  for (const [selector, palette] of Object.entries(palettes)) {
    const text = block(`      ${selector}`);
    for (const [name, color] of Object.entries(palette)) {
      const variable = ['bg', 'text', 'line-number', 'line-highlight', 'selection', 'indent-guide'].includes(name) ? `--code-${name}` : `--syntax-${name}`;
      assert.equal(value(text, variable), color, `${selector} ${variable}`);
    }
  }
  const rule = kind => css.match(new RegExp(`[^}]*\\.syntax-${kind}(?![\\w-])[^{]*\\{([^}]*)\\}`))?.[1] ?? '';
  for (const [kind, variable, italic] of [
    ['comment', '--syntax-comment', true], ['keyword', '--syntax-keyword'], ['operator', '--syntax-keyword'], ['punctuation', '--syntax-punctuation'],
    ['string', '--syntax-string'], ['regexp', '--syntax-string'], ['number', '--syntax-number'], ['function', '--syntax-number'],
    ['type', '--syntax-type'], ['builtin', '--syntax-type'], ['key', '--syntax-type'], ['tag', '--syntax-type'], ['builtin-function', '--syntax-support-function', true],
    ['parameter', '--syntax-parameter', true], ['attribute', '--syntax-parameter', true], ['inherited', '--syntax-parameter', true], ['property', '--code-text'], ['text', '--code-text'],
    ['variable-other', '--code-text', true], ['this', '--syntax-keyword', true], ['attribute-mark', '--syntax-punctuation', true],
    ['bracket-0', '--syntax-bracket-1'], ['bracket-1', '--syntax-bracket-2'], ['bracket-2', '--syntax-bracket-3'], ['bracket-3', '--syntax-bracket-4'], ['bracket-4', '--syntax-bracket-5'], ['bracket-5', '--syntax-bracket-6']
  ]) {
    assert(rule(kind).includes(`var(${variable})`), `.syntax-${kind} uses ${variable}`);
    assert.equal(rule(kind).includes('italic'), Boolean(italic), `.syntax-${kind} font style`);
  }
  const contrast = css.slice(css.indexOf('@media (prefers-contrast: more)'));
  assert(/--syntax-comment: #908caa; --syntax-keyword: #4fa0c1/.test(contrast), 'Increase Contrast brightens Moon comments and keywords');
  assert(/font: 12px\/18px var\(--code-font\)/.test(block('      .source-code')) && css.includes('--code-font: Menlo, Monaco, "Courier New", monospace;'), 'VS Code macOS editor font');
  // The textarea stays transparent over its color mirror. The form-control rule sets an opaque
  // background and another font at (1,2,1), so this selector must outrank it.
  const editorRule = css.match(/#screen-analyst \.analyst-form \.code-edit > textarea#analyst-content \{([^}]*)\}/)?.[1] ?? '';
  assert(/background: transparent/.test(editorRule) && /-webkit-text-fill-color: transparent/.test(editorRule) && /font: 12px\/18px var\(--code-font\)/.test(editorRule), 'The Analyst textarea stays transparent in the code font');

  // Mapping: whitespace-only, exact by construction, refused otherwise. Every
  // non-whitespace character maps to the same-rank one in the evidence, in
  // any lookup order and across the 4 Ki-unit sync points.
  const original = (await fixture('minified.js')).trimEnd();
  const visible = text => [...text].flatMap((character, at) => /\s/u.test(character) ? [] : [at]);
  const exact = (input, output, label) => {
    const map = model.sourceWhitespaceMap(input, output), walk = model.sourceWhitespaceWalker(map, input, output);
    const from = visible(input), to = visible(output);
    assert.equal(from.length, to.length);
    to.forEach((at, rank) => assert.equal(walk(at), from[rank], `${label}: ascending ${at}`));
    for (let rank = to.length - 1; rank >= 0; rank -= 97) assert.equal(walk(to[rank]), from[rank], `${label}: descending ${to[rank]}`);
    assert.equal(walk(output.search(/\s/)), null, `${label}: layout whitespace has no original character`);
    return map;
  };
  assert.equal(exact(original, formatted, 'Oxc fixture').anchors.length, 2);
  const repeated = Array.from({length: 60}, (_, at) => original.replaceAll('list', `list${at}`)).join(';');
  const layout = model.prettyPrintSource({kind: 'javascript'}, repeated);
  assert(exact(repeated, layout.text, 'in-page layout').anchors.length > 6, 'The layout crosses several sync points');
  const at = formatted.indexOf('stringify');
  assert.deepEqual({...model.sourceWhitespaceRange(model.sourceWhitespaceMap(original, formatted), original, formatted, at, at + 9)},
    {start: original.indexOf('stringify'), end: original.indexOf('stringify') + 9});
  // A token that starts with a space (a comment body) maps exactly; a run of only layout whitespace has no range.
  const bodyInput = '/* keep */a=1;', bodyLayout = '/* keep */\na = 1;', bodyMap = model.sourceWhitespaceMap(bodyInput, bodyLayout);
  assert.deepEqual({...model.sourceWhitespaceRange(bodyMap, bodyInput, bodyLayout, 2, 8)}, {start: 2, end: 8}, 'A comment body keeps its edge spaces');
  assert.deepEqual({...model.sourceWhitespaceRange(bodyMap, bodyInput, bodyLayout, 10, 12)}, {start: 10, end: 11}, 'Layout whitespace is not part of a token');
  assert.equal(model.sourceWhitespaceRange(bodyMap, bodyInput, bodyLayout, 10, 11), null, 'A whitespace run has no raw range');
  assert.equal(model.sourceWhitespaceMap('a=1', 'a = 2'), null, 'Any non-whitespace difference is refused');
  assert.equal(model.sourceWhitespaceMap('a\u0085b', 'ab'), null, 'NEL is not JavaScript whitespace');
  assert(model.sourceWhitespaceMap('\ufeffa=1; b', 'a = 1;\n  b'), 'BOM and line separators are layout whitespace');

  // Layout runner: a worker reply, a worker that fails to load, and the shipped worker entry.
  const replies = [];
  const runner = model.createSourceLayoutWorker({defer: callback => callback(), spawn: () => ({
    postMessage(message) {queueMicrotask(() => this.onmessage({data: {id: message.id, result: model.sourceLayoutTask(message.task)}}));}, terminate() {}
  })});
  assert.equal((await runner.run({op: 'layout', source: {kind: 'javascript'}, value: repeated})).text, layout.text);
  let broken;
  const fallback = model.createSourceLayoutWorker({defer: callback => callback(), spawn: () => (broken = {
    postMessage() {queueMicrotask(() => broken.onerror({preventDefault() {}}));}, terminate() {broken.terminated = true;}
  })});
  assert((await fallback.run({op: 'map', original, formatted})).map, 'A failed worker falls back to the page');
  assert(broken.terminated && (await fallback.run({op: 'map', original, formatted: 'x'})).error);
  class WorkerGlobalScope {}
  const scope = new WorkerGlobalScope(), posted = [], imported = [];
  const worker = createContext({WorkerGlobalScope, self: scope, URL, setTimeout, clearTimeout, AbortController});
  worker.importScripts = name => {imported.push(name); runInContext(syntax, worker);};
  scope.postMessage = (message, transfer) => posted.push({message, transfer});
  runInContext(format, worker);
  scope.onmessage({data: {id: 7, task: {op: 'layout', source: {kind: 'javascript'}, value: repeated}}});
  assert.deepEqual(imported, ['source_syntax.js']);
  assert.equal(posted[0].message.id, 7); assert.equal(posted[0].message.result.text, layout.text);
  assert.equal(posted[0].transfer[0], posted[0].message.result.map.anchors.buffer, 'The map is transferred, not copied');

  // Client: pending, formatted, unavailable and failed layouts.
  const source = {source_type: 'artifact', kind: 'javascript', session_id: '1', artifact_id: '7', sha256: 'f'.repeat(64), byte_size: original.length, content: original};
  const changes = [];
  const client = model.createSourceFormatClient({request: async url => replies.shift()(url), onChange: changed => changes.push(changed.artifact_id),
    layouts: model.createSourceLayoutWorker({spawn: null, defer: callback => callback()})});
  const reply = (status, body) => url => ({ok: status === 200, status, json: async () => ({...body, url})});
  const document = (extra, sha256 = source.sha256) => ({schema: 'source-format-v1', mapping: 'whitespace-only', source: {artifact_id: '7', sha256}, ...extra});
  const settle = () => new Promise(resolve => setImmediate(resolve));
  replies.push(reply(200, document({status: 'formatted', text: formatted})));
  assert.equal(client.view(source, original).pending, true);
  await settle();
  const view = client.view(source, original);
  assert.equal(view.text, formatted); assert.equal(view.engine, 'oxc'); assert.equal(view.offset_unit, 'utf-16-code-unit'); assert.deepEqual(changes, ['7']);
  assert.equal(model.sourceWhitespaceWalker(view.map, original, formatted)(formatted.indexOf('POST')), original.indexOf('POST'));
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
  // Bodies: a request or response body is laid out as its type, or as the language the caller parsed.
  assert.equal(model.sourceFormatLanguage({kind: 'response_body', mime_type: 'application/problem+json; charset=utf-8'}), 'json');
  assert.equal(model.sourceFormatLanguage({kind: 'request_body', mime_type: 'text/plain', language: 'json'}), 'json');
  assert.equal(model.sourceFormatLanguage({kind: 'response_body', mime_type: 'application/x-javascript'}), 'javascript');
  assert.equal(model.sourceFormatLanguage({kind: 'response_body', mime_type: 'text/css'}), null);
  assert.equal(model.sourceFormatLanguage({kind: 'request_target', mime_type: 'application/json'}), null);
  const body = {...source, kind: 'request_body', mime_type: 'text/plain', language: 'json', content: '[1,2]', byte_size: 5, sha256: 'b'.repeat(64)};
  replies.push(url => ({ok: true, status: 200, json: async () => ({...document({status: 'formatted', text: '[1, 2]'}, body.sha256), url})}));
  client.view(body, '[1,2]');
  await settle();
  assert.equal(client.view(body, '[1,2]').text, '[1, 2]');
  assert.equal(client.view({...body, byte_size: 5 * 1024 * 1024, sha256: 'c'.repeat(64)}, '[1,2]').notice, 'Oxc lays out bodies up to 4 MiB here');

  // Paged layouts: whole 1,000-line pages, each checked against its slice of the original between two anchors.
  const unit = 'var a=[1,2],b=function(){return 3};';
  const big = unit.repeat(900), bigLaid = 'var a = [1, 2],\n  b = function () {\n    return 3\n  };\n'.repeat(900).slice(0, -1);
  const lines = bigLaid.split('\n'), anchors = [];
  for (let block = 0; block * 1000 < lines.length; block++) {
    const before = lines.slice(0, block * 1000).join('\n').replace(/\s/g, '').length;
    let at = 0, seen = 0;
    while (seen < before) if (!/\s/.test(big[at++])) seen++;
    while (at < big.length && /\s/.test(big[at])) at++;
    anchors.push(at);
  }
  const bigSource = {...source, artifact_id: '9', sha256: 'd'.repeat(64), byte_size: big.length, content: big};
  const pageReply = (block, extra = {}) => url => ({ok: true, status: 200, json: async () => ({schema: 'source-format-v1', mapping: 'whitespace-only',
    source: {artifact_id: '9', sha256: bigSource.sha256}, status: 'formatted', language: 'javascript', line_count: lines.length,
    anchors: {lines: 1000, source_utf16: anchors}, window: {start_line: block * 1000 + 1, line_count: Math.min(1000, lines.length - block * 1000)},
    text: lines.slice(block * 1000, block * 1000 + 1000).join('\n'), url, ...extra})});
  const paged = model.createSourceFormatClient({request: async url => replies.shift()(url), onChange: () => {},
    layouts: model.createSourceLayoutWorker({spawn: null, defer: callback => callback()})});
  replies.push(pageReply(0));
  assert.equal(paged.page(bigSource, big, 1500).pending, true, 'the first page names the layout before a later one is asked for');
  await settle();
  replies.push(pageReply(1));
  assert.equal(paged.page(bigSource, big, 1500).pending, true);
  await settle();
  const second = paged.page(bigSource, big, 1500);
  assert.deepEqual([second.paged, second.lineBase, second.lineCount, second.base], [true, 1000, lines.length, anchors[1]]);
  replies.push(pageReply(2));
  const loading = paged.page(bigSource, big, 2000);
  assert.equal(loading.pending, true);
  assert.equal(loading.previous, second, 'the page shown last stays while another loads');
  await settle();
  assert.equal(paged.page(bigSource, big, 2999).lineBase, 2000);
  assert.equal(paged.page(bigSource, big, 999).lineBase, 0, 'a page read before is kept');
  replies.push(pageReply(3));
  paged.page(bigSource, big, 99999);
  await settle();
  assert.equal(paged.page(bigSource, big, 99999).lineBase, 3000, 'a line past the end shows the last page');
  assert.equal(model.sourceFormatBlock(anchors, anchors[2] + 5), 2);
  const wrong = {...bigSource, sha256: 'e'.repeat(64)};
  replies.push(url => ({...pageReply(0)(url), json: async () => ({...(await pageReply(0)(url).json()), source: {artifact_id: '9', sha256: wrong.sha256},
    anchors: {lines: 1000, source_utf16: anchors.slice(1)}})}));
  paged.page(wrong, big, 0);
  await settle();
  assert.match(paged.page(wrong, big, 0).notice, /window does not match its layout/);

  // The editor's page index keeps absolute lines and maps every row through the page's anchor.
  const index = model.sourcePageIndex(second.text, second.lineBase, second.lineCount);
  const window = model.sourceDocumentWindow(index, 1500, 4);
  assert.deepEqual([window.start, window.end, window.line, window.rows[0].line], [1000, 2000, 1500, 1000]);
  assert.equal(model.sourceDocumentOffset(index, 999), null, 'a line of another page is not in this one');
  assert.equal(model.sourceDocumentPosition(index, model.sourceDocumentOffset(index, 1500)).line, 1500);
  assert.equal(model.sourceDocumentMatches(index, 'return', 1).matches[0].line, 1002);
  const mapping = model.sourceWindowMapping(big, big, null, second);
  const visibleAt = second.text.indexOf('function');
  const mapped = mapping.position(visibleAt, visibleAt + 1);
  const originalIndex = model.sourceDocumentIndex(big);
  assert.deepEqual(mapped, model.sourceDocumentPosition(originalIndex, anchors[1] + second.sourceInput.indexOf('function')));
  const inverse = model.sourceWhitespaceInverse(second.sourceInput, second.text);
  const returnAt = second.sourceInput.indexOf('return');
  assert.equal(inverse(returnAt), second.text.indexOf('return'));
  assert.equal(inverse(second.sourceInput.indexOf('return', returnAt + 1)), second.text.indexOf('return', second.text.indexOf('return') + 1));
  assert.equal(inverse(0), second.text.search(/\S/));

  // A page that starts inside a block comment takes the original's lexer state there.
  const commented = 'var x=1;/*\n' + 'note\n'.repeat(3) + '*/var y=2;';
  const before = model.createSourceHighlighter({kind: 'javascript'}, model.sourceDocumentIndex(commented));
  const pageText = 'note\nnote\n*/var y = 2;';
  const seeded = model.createSourceHighlighter({kind: 'javascript'}, model.sourcePageIndex(pageText, 1000, 1003),
    {highlighter: before, offset: commented.indexOf('note', commented.indexOf('note') + 1)});
  const rows = model.sourceDocumentWindow(model.sourcePageIndex(pageText, 1000, 1003), 1000, 0).rows;
  assert.equal(seeded.ready(rows), false, 'a seeded page waits for the original lexer');
  while (!seeded.ready(rows)) seeded.advance(1024);
  assert.equal(seeded.rows(rows).rows[0][0].type, 'comment', 'the page continues the comment');
  assert.equal(seeded.rows(rows).rows[2].find(token => token.text === 'var').type, 'keyword');

  // Shared code view rows: CR dropped at line ends, long lines continue, no split surrogate.
  const longLine = 'x'.repeat(4095) + '\u{1f600}' + 'y';
  const viewRows = model.codeViewRows(`a\r\n${longLine}\n`);
  assert.equal(JSON.stringify(viewRows.map(row => [row.line, row.columnStart, row.text.length])), '[[0,0,1],[1,0,4095],[1,4095,3],[2,0,0]]');

  assert(timers.every(timer => timer.delay === 180000), 'Each request has a deadline');
  console.log('PASS source format UI: TextMate-scope token kinds for JavaScript, JSON, CSS and HTML fixtures, Rosé Pine Moon/Dawn values and Increase Contrast in app.css, exact whitespace-only map in any lookup order and raw ranges, layout worker reply/fallback/entry, client pending/formatted/fallback/retry, body languages and the 4 MiB whole-body bound, paged layouts checked per page against their anchors with the last page kept while another loads, absolute page lines, page-to-original mapping and inverse walk, a page seeded with the original lexer state, shared code view rows (shipped modules, not rendered QA)');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await checkSourceFormatUI(fileURLToPath(new URL('..', import.meta.url)));
