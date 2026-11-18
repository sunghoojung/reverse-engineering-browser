import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {performance} from 'node:perf_hooks';

export async function checkSourceWindowModel(root) {
  const script=await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8');
  // Without TextDecoder the hex rows are built from character codes instead.
  const plain=runInNewContext(script+';({formatWasmHex})', {URL});
  const model=runInNewContext(script+
    ';({sourceDocumentIndex,sourceDocumentOffset,sourceDocumentPosition,sourceDocumentLine,sourceDocumentMatches,sourceDocumentWindow,sourceWindowMapping,prettyPrintSource,sourceName,formatWasmHex,'+
    'sourceHexText,sourceHexLayout,sourceHexPage,sourceHexRows,sourceHexColumnByte,SOURCE_HEX_PAGE_ROWS,startSourceFind,cancelSourceFind,sourceFindMatch,sourceFindBetween,sourceFindMarks,sourceFindTextDocument,sourceFindHexDocument,SOURCE_FIND_CHUNK_UNITS,'+
    'createSourceHighlighter,createSourceTokenizer,sourceSyntaxTokens,sourceHasLongLine,sourcePrettyByDefault,SOURCE_COLOR_SLICE_UNITS,SOURCE_HIGHLIGHT_TOKEN_LIMIT})', {URL, TextDecoder});
  assert.equal(model.formatWasmHex(new Uint8Array(32)).split('\n')[0].length, 77);
  const hexCosts = checkHexPages(model, plain);
  assert.equal(model.sourceName({kind:'wasm', url:'https://accounts.hcaptcha.com/hcaptcha.html', capture_origin:'webassembly_instantiate', artifact_id:'5', source_type:'artifact'}), 'wasm webassembly instantiate');
  assert.equal(model.sourceName({kind:'wasm', url:'https://cdn.invalid/path/module.wasm?x=1', capture_origin:'webassembly_instantiate', artifact_id:'6', source_type:'artifact'}), 'module.wasm');
  assert.equal(model.sourceName({kind:'javascript', url:'https://accounts.hcaptcha.com/hcaptcha.html', artifact_id:'7', source_type:'artifact'}), 'hcaptcha.html');
  assert.equal(model.sourceName({source_type:'artifact', artifact_id:'9'}), 'artifact-9');
  for(const text of ['', '\n', 'a\r\nb\n', '\ufeffconst 雪="😀";\r\nK İ k\n', '\n'.repeat(385)+'last']) {
    const index=model.sourceDocumentIndex(text),lines=text.split('\n');
    assert.equal(index.lineCount,lines.length);
    for(let at=0;at<=text.length;at++) {
      const prefix=text.slice(0,at),position=model.sourceDocumentPosition(index,at);
      assert.deepEqual({...position},{line:prefix.split('\n').length-1,column:prefix.length-prefix.lastIndexOf('\n')-1});
    }
    let offset=0;
    for(let line=0;line<lines.length;line++){assert.equal(model.sourceDocumentOffset(index,line),offset);assert.equal(model.sourceDocumentLine(index,line).length,lines[line].length);offset+=lines[line].length+1;}
  }
  const text='\ufeff'+Array.from({length:20001},(_,line)=>line===20000?'const lateNeedle="😀";':`// row ${line}`).join('\r\n');
  const index=model.sourceDocumentIndex(text);
  const matches=model.sourceDocumentMatches(index,'lateNeedle');
  assert.equal(matches.matches.length,1);assert.equal(matches.matches[0].line,20000);assert.equal(matches.matches[0].column,6);
  assert.equal(index.length,text.length);assert.equal(index.anchors.length,157);
  for(const line of [0,998,999,1000,1001,19999,20000]) {
    const window=model.sourceDocumentWindow(index,line,6);
    assert(window.rows.some(row=>row.line===line));assert(window.rows.length<=1000);
    for(const row of window.rows){assert.equal(row.text,text.slice(row.offset+row.columnStart,row.offset+row.columnEnd));}
  }
  const unicode=model.sourceDocumentIndex('\ufeffİ K k K 😀 needle\r\n');
  assert.deepEqual(Array.from(model.sourceDocumentMatches(unicode,'k').matches,match=>match.column),[3,5,7]);
  assert.equal(model.sourceDocumentMatches(unicode,'😀').matches[0].length,2);
  assert.equal(model.sourceDocumentMatches(unicode,' ').matches.length,5);
  for(const query of ['x'.repeat(513),'x\ny','x\ry','x\u2028y'])assert(model.sourceDocumentMatches(unicode,query).error);
  assert.equal(model.sourceDocumentMatches(model.sourceDocumentIndex('x'.repeat(512)),'x'.repeat(512)).matches.length,1);
  assert.equal(model.sourceDocumentMatches(model.sourceDocumentIndex('a '.repeat(1000)),'a').truncated,false);
  assert.equal(model.sourceDocumentMatches(model.sourceDocumentIndex('a '.repeat(1001)),'a').truncated,true);
  assert.equal(model.sourceDocumentMatches(model.sourceDocumentIndex('\n'.repeat(3000)),' ').matches.length,0,'Empty display rows must not become searchable spaces');
  const huge='/*'+'😀'.repeat(600000)+'lateColumnNeedle'+'*/';
  const hugeIndex=model.sourceDocumentIndex(huge),late=model.sourceDocumentMatches(hugeIndex,'lateColumnNeedle').matches[0];
  const hugeWindow=model.sourceDocumentWindow(hugeIndex,late.line,late.column);
  assert.equal(late.column,1200002);assert(hugeWindow.rows[0].text.includes('lateColumnNeedle'));
  assert(hugeWindow.rows[0].text.length<=16385);assert(hugeWindow.rows[0].columnStart>1000000);
  assert(!/^[\udc00-\udfff]/u.test(hugeWindow.rows[0].text));assert(!/[\ud800-\udbff]$/u.test(hugeWindow.rows[0].text));
  const costs=[];
  for(const [name,source] of [['newlines','\n'.repeat(8*1024*1024)],['minified',('find '.repeat(1700000)).slice(0,8*1024*1024)]]) {
    const before=performance.now(),indexed=model.sourceDocumentIndex(source),indexedAt=performance.now();
    const result=model.sourceDocumentMatches(indexed,name==='newlines'?'absent':'find');const searchedAt=performance.now();
    const window=model.sourceDocumentWindow(indexed,indexed.lineCount-1,source.length);
    assert(indexed.anchors.length<=65537);assert(window.rows.length<=1000);
    assert(window.rows.reduce((sum,row)=>sum+row.text.length,0)<=528384);
    costs.push({name,codeUnits:source.length,indexMs:Math.round(indexedAt-before),searchMs:Math.round(searchedAt-indexedAt),windowMs:Math.round(performance.now()-searchedAt),anchors:indexed.anchors.length,rows:window.rows.length,matches:result.matches.length});
  }
  costs.push(...hexCosts, ...checkDocumentFind(model));
  costs.push(...checkCheckpointedColors(model));
  console.log('PASS sparse retained-source index, complete 20,001-line Find, Unicode/CRLF/BOM, bounds, minified late-column excerpts, an exact any-size Find in slices (chunk-spanning matches, ranks, row marks) over a 72 Mi-unit text and a 20 MiB hex view, paged hex rows, checkpointed colors and formatted-line mapping on a 12 MiB one-line bundle; measured model costs '+JSON.stringify(costs));
  return costs;
}

// A deterministic one-line minified bundle: strings, templates, regular
// expressions, comments, classes and arrows in every 4 Ki checkpoint span.
export function minifiedBundle(units) {
  const parts = [];
  for (let n = 0, size = 0; size < units; n++) {
    const id = n.toString(36);
    const block = `var a${id}=function(e,t){if(!e)return null;for(var n=0,r=e.length;n<r;n++){t(e[n],n)}return{ok:!0,list:[1,2,3],re:/a${id}[\\]/]+/g,` +
      `s:\`k\${e}-${id}\`,fn:async()=>{await fetch("/x?y=${id}"+n,{method:"POST",body:JSON.stringify({a:${n % 97}})})}}},b${id}=a${id}?.c??(d,e=>e*2);` +
      `/*c${id}*/class C${id} extends B{m(p,q=1){return console.log(this.y,'\\'${id}')}};`;
    parts.push(block); size += block.length;
  }
  return parts.join('').slice(0, units);
}

// Checkpointed windows must color exactly as one tokenizer run from the start.
// The hex rows of the old whole-buffer formatter, for comparison.
function referenceHex(bytes, base = 0) {
  const rows = [], digits = Math.max(8, Math.max(0, base + bytes.length - 1).toString(16).length);
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = [...bytes.subarray(offset, offset + 16)];
    rows.push(`${(base + offset).toString(16).padStart(digits, '0')}  ${chunk.map(byte => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ')}  |${chunk.map(byte => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('')}|`);
  }
  return rows.join('\n');
}

function seeded(length, seed = 7) {
  const bytes = new Uint8Array(length);
  for (let index = 0, value = seed; index < length; index++) {value = (Math.imul(value, 1103515245) + 12345) >>> 0; bytes[index] = value >>> 24;}
  return bytes;
}

function checkHexPages(model, plain) {
  for (const [length, base] of [[0, 0], [1, 0], [15, 0], [16, 0], [17, 0], [1000, 0], [4096 + 7, 0], [40, 0xfffffff0], [33, 2 ** 40]]) {
    const bytes = seeded(length, length + 1);
    assert.equal(model.formatWasmHex(bytes, base), referenceHex(bytes, base), `hex rows of ${length} bytes at ${base}`);
    assert.equal(plain.formatWasmHex(bytes, base), referenceHex(bytes, base), `hex rows of ${length} bytes at ${base} without TextDecoder`);
  }
  // Pages are slices of the whole view, every row the same width.
  const bytes = seeded(16 * 2500 + 9), whole = referenceHex(bytes), rows = whole.split('\n');
  assert.equal(model.sourceHexRows(bytes), 2501);
  for (const line of [0, 999, 1000, 2499, 2500, 99999]) {
    const page = model.sourceHexPage(bytes, line), block = Math.min(2, Math.floor(line / 1000));
    assert.equal(page.lineBase, block * 1000);assert.equal(page.lineCount, 2501);assert.equal(page.rowUnits, 78);
    assert.equal(page.text, rows.slice(block * 1000, block * 1000 + 1000).join('\n'));
    assert.equal(page.row(page.lineBase), page.lineBase * 16);assert.equal(page.row(page.lineBase - 1), null);
  }
  const empty = model.sourceHexPage(new Uint8Array(0));
  assert.deepEqual([empty.text, empty.lineCount], ['', 1]);
  // Every column of a row names its byte: two digits, then its printable character.
  const page = model.sourceHexPage(bytes, 2500), last = rows[2500];
  const named = Array.from({length: last.length}, (_, column) => model.sourceHexColumnByte(page, 2500, column));
  assert.deepEqual(named.map((byte, column) => byte === null ? null : `${column}:${byte - 2500 * 16}`).filter(Boolean),
    [...Array.from({length: 9}, (_, index) => [`${10 + 3 * index}:${index}`, `${11 + 3 * index}:${index}`]).flat(), ...Array.from({length: 9}, (_, index) => `${60 + index}:${index}`)]);
  const large = seeded(20 * 1024 * 1024), started = performance.now();
  let units = 0;
  for (let line = 0; line < model.sourceHexRows(large); line += model.SOURCE_HEX_PAGE_ROWS) units += model.sourceHexPage(large, line).text.length;
  return [{name: 'hex pages of 20 MiB', pages: Math.ceil(model.sourceHexRows(large) / 1000), units, ms: Math.round(performance.now() - started)}];
}

// Runs a search to its end in slices of at most one chunk each.
function finish(model, document, query) {
  const queue = [];
  const search = model.startSourceFind(document, query, {schedule: step => queue.push(step), sliceMs: 0, now: () => 0});
  let slices = 1;
  while (queue.length) {queue.shift()(); slices++;}
  return {search, slices};
}

function reference(text, query) {
  const pattern = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'giu'), found = [];
  for (let match = pattern.exec(text); match; match = pattern.exec(text)) found.push({offset: match.index, length: match[0].length});
  return found;
}

function checkDocumentFind(model) {
  const units = model.SOURCE_FIND_CHUNK_UNITS;
  // Runs that cross chunk boundaries, so a match runs into the next chunk and
  // that chunk's rescan starts after it; folded and astral characters too.
  const pieces = [];
  for (let at = 0; at < 6; at++) pieces.push('x'.repeat(units - 3 - at), 'a'.repeat(5 + 2 * at), 'KKkİi😀🌍');
  const text = pieces.join('');
  for (const query of ['aa', 'aaa', 'a', 'k', 'KK', 'i', '😀', 'x😀', 'absent', 'xa']) {
    const expected = reference(text, query), {search, slices} = finish(model, model.sourceFindTextDocument(text), query);
    assert.equal(search.status, 'done');assert.equal(search.total, expected.length, `count of ${query}`);assert(slices > 1);
    expected.forEach((match, rank) => assert.deepEqual({...model.sourceFindMatch(search, rank)}, match, `${query} match ${rank}`));
    assert.equal(model.sourceFindMatch(search, expected.length), null);
    const from = units - 10, to = 3 * units + 40;
    assert.deepEqual(Array.from(model.sourceFindBetween(search, from, to), match => ({...match})), expected.filter(match => match.offset >= from && match.offset < to));
    const ranges = [[0, 10], [units - 6, units + 4], [units, 2 * units + 1], [2 * units + 5, 6 * units], [6 * units, text.length]];
    assert.deepEqual(Array.from(model.sourceFindMarks(search, ranges)), ranges.map(([start, end]) => expected.some(match => match.offset >= start && match.offset < end)));
  }
  for (const query of ['x'.repeat(513), 'x\ny', 'x y']) assert(model.startSourceFind(model.sourceFindTextDocument(text), query).error);
  assert.equal(model.startSourceFind(model.sourceFindTextDocument(text), '').status, 'done');
  // Cancel stops the remaining slices.
  const queue = [], cancelled = model.startSourceFind(model.sourceFindTextDocument(text), 'a', {schedule: step => queue.push(step), sliceMs: 0, now: () => 0});
  model.cancelSourceFind(cancelled);
  while (queue.length) queue.shift()();
  assert.equal(cancelled.status, 'running');assert(cancelled.scanned < cancelled.document.chunks);
  const costs = [];
  // Past the former 64 Mi-unit document bound, every match is counted.
  const big = 'f'.repeat(72 * 1024 * 1024 - 32) + 'lateNeedle lateneedle LATENEEDLE', started = performance.now();
  const late = model.startSourceFind(model.sourceFindTextDocument(big), 'lateNeedle', {schedule: step => step(), sliceMs: 1e9});
  assert.equal(late.status, 'done');assert.equal(late.total, 3);
  assert.equal(model.sourceFindMatch(late, 2).offset, big.length - 10);
  costs.push({name: 'Find in 72 Mi units', matches: late.total, ms: Math.round(performance.now() - started)});
  const frequent = performance.now(), every = model.startSourceFind(model.sourceFindTextDocument(big), 'f', {schedule: step => step(), sliceMs: 1e9});
  assert.equal(every.total, big.length - 32);
  costs.push({name: 'count 75,497,440 matches', ms: Math.round(performance.now() - frequent), chunks: every.counts.length});
  // Hex: the rows of every page, laid end to end, are the searched text.
  const bytes = seeded(4 * 1024 * 1024 + 5), whole = referenceHex(bytes);
  for (const query of ['00 0', 'ff  |', '|..', '0001000']) {
    const expected = reference(whole, query).map(match => ({offset: match.offset, length: match.length}));
    assert(expected.length > 1, `the fixture holds ${query}`);
    const {search} = finish(model, model.sourceFindHexDocument(bytes), query);
    assert.equal(search.total, expected.length, `hex count of ${query}`);
    for (const rank of [0, 1, Math.floor(expected.length / 2), expected.length - 1]) assert.deepEqual({...model.sourceFindMatch(search, rank)}, expected[rank]);
  }
  const hex = seeded(20 * 1024 * 1024), hexStarted = performance.now();
  const counted = model.startSourceFind(model.sourceFindHexDocument(hex), '00 00', {schedule: step => step(), sliceMs: 1e9});
  costs.push({name: 'Find over 20 MiB of hex rows', matches: counted.total, ms: Math.round(performance.now() - hexStarted)});
  return costs;
}

function checkCheckpointedColors(model) {
  const javascript = {kind: 'javascript'};
  const types = text => {
    const tokenizer = model.createSourceTokenizer(javascript), result = new Array(text.length);
    tokenizer.coloredTokens = -Infinity;
    let offset = 0;
    for (const line of text.split('\n')) {
      let at = offset;
      if (line) for (const token of model.sourceSyntaxTokens(line, tokenizer)) {result.fill(token.type, at, at + token.text.length); at += token.text.length;}
      offset += line.length + 1;
    }
    return result;
  };
  const build = index => {
    const highlighter = model.createSourceHighlighter(javascript, index);
    let steps = 0, slowest = 0;
    for (let done = false; !done; steps++) {const before = performance.now(); done = highlighter.advance(model.SOURCE_COLOR_SLICE_UNITS); slowest = Math.max(slowest, performance.now() - before);}
    return {highlighter, steps, slowestStepMs: Math.round(slowest)};
  };
  const exact = (text, label) => {
    const expected = types(text), index = model.sourceDocumentIndex(text), {highlighter} = build(index);
    for (const [line, column] of [[0, 0], [0, 100000], [0, 250000], [Math.floor(index.lineCount / 2), 0], [Math.min(1500, index.lineCount - 1), 3], [index.lineCount - 1, 0]]) {
      const window = model.sourceDocumentWindow(index, line, column), colors = highlighter.rows(window.rows);
      window.rows.forEach((row, at) => {
        assert.equal(colors.rows[at].map(token => token.text).join(''), row.text, `${label}: tokens cover the excerpt`);
        let offset = row.offset + row.columnStart;
        for (const token of colors.rows[at]) {
          for (let unit = 0; unit < token.text.length; unit++) {
            const want = expected[offset + unit];
            assert(want === token.type || (token.type === 'plain' && /\s/.test(token.text[unit])), `${label}: ${token.type} at ${offset + unit}, expected ${want}`);
          }
          offset += token.text.length;
        }
      });
    }
  };
  const sample = minifiedBundle(300000);
  exact(sample, 'one-line excerpt');
  exact(model.prettyPrintSource(javascript, sample).text, 'formatted');
  assert(!model.createSourceHighlighter(javascript, model.sourceDocumentIndex(sample)).ready([{offset: 0, columnStart: 200000, fullLength: sample.length}]),
    'A window beyond the checkpoints waits instead of coloring from a guessed state');

  const bundle = minifiedBundle(12 * 1024 * 1024);
  assert(model.sourceHasLongLine(bundle) && model.sourcePrettyByDefault(javascript) && !model.sourceHasLongLine('a\n'.repeat(1000)), 'A minified bundle opens pretty-printed');
  let started = performance.now();
  const original = model.sourceDocumentIndex(bundle), originalColors = build(original);
  const originalMs = Math.round(performance.now() - started);
  const id = /^var a([0-9a-z]+)=/.exec(bundle.slice(bundle.lastIndexOf('var a', bundle.lastIndexOf('var a') - 1)))[1], needle = `C${id} extends`;
  const late = model.sourceDocumentMatches(original, needle).matches;
  assert.equal(late.length, 1);
  const lateWindow = model.sourceDocumentWindow(original, late[0].line, late[0].column), lateColors = originalColors.highlighter.rows(lateWindow.rows);
  assert(lateWindow.rows[0].columnStart > 12000000 && ['regexp', 'type', 'inherited', 'function'].every(type => lateColors.rows[0].some(token => token.type === type)),
    'A clipped late column keeps its colors');
  started = performance.now();
  const formatted = model.prettyPrintSource(javascript, bundle);
  const formatMs = Math.round(performance.now() - started);
  assert(!formatted.error && formatted.map, formatted.error);
  started = performance.now();
  const index = model.sourceDocumentIndex(formatted.text), {highlighter, steps, slowestStepMs} = build(index);
  const formattedMs = Math.round(performance.now() - started);
  const mapping = model.sourceWindowMapping(bundle, bundle, null, formatted);
  let windowMs = 0, previousColumn = -1;
  for (const line of [0, 1000, 2500, Math.floor(index.lineCount / 2), index.lineCount - 1]) {
    started = performance.now();
    const window = model.sourceDocumentWindow(index, line), colors = highlighter.rows(window.rows), mapped = mapping(window.rows);
    windowMs = Math.max(windowMs, performance.now() - started);
    assert(!colors.truncated && colors.rows.every((tokens, at) => !window.rows[at].text.trim() || tokens.some(token => token.type !== 'plain')), `Every row after line ${line + 1} is colored`);
    const first = mapped.find(row => row.originalLine !== null);
    assert.equal(first.originalLine, 0, 'Formatted rows map into the one original line');
    assert(first.originalColumn > previousColumn, 'Formatted lines advance through the original');
    previousColumn = first.originalColumn;
    const row = window.rows.find(candidate => candidate.text.trim()), visible = row.offset + row.text.search(/\S/);
    assert.equal(bundle[mapping.position(visible).column], formatted.text[visible], 'A formatted character names its original column');
  }
  started = performance.now();
  const find = model.sourceDocumentMatches(index, needle);
  const findMs = Math.round(performance.now() - started);
  assert.equal(find.matches.length, 1);
  return [{name: '12 MiB one-line bundle', codeUnits: bundle.length, originalCheckpointMs: originalMs, formatMs, formattedLines: index.lineCount,
    formattedCheckpointMs: formattedMs, checkpointSteps: steps, slowestStepMs, windowMs: Math.round(windowMs), findMs}];
}
