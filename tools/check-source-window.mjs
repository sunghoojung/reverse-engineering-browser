import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {performance} from 'node:perf_hooks';

export async function checkSourceWindowModel(root) {
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8'))+
    ';({sourceDocumentIndex,sourceDocumentOffset,sourceDocumentPosition,sourceDocumentLine,sourceDocumentMatches,sourceDocumentWindow,sourceWindowMapping,prettyPrintSource,sourceName,formatWasmHex,wasmHexByteLimit,'+
    'createSourceHighlighter,createSourceTokenizer,sourceSyntaxTokens,sourceHasLongLine,sourcePrettyByDefault,SOURCE_COLOR_SLICE_UNITS,SOURCE_DOCUMENT_LIMIT,SOURCE_PRETTY_INPUT_LIMIT,SOURCE_HIGHLIGHT_TOKEN_LIMIT})', {URL});
  const wasmLimit=model.wasmHexByteLimit();
  assert.equal(wasmLimit % 16, 0);
  assert(wasmLimit >= 990157, 'A retained ~990 KB module must format in full');
  assert.equal(model.formatWasmHex(new Uint8Array(32)).split('\n')[0].length, 77);
  const formattedLimit=model.formatWasmHex(new Uint8Array(wasmLimit));
  const hexNotice=`\n\n[Hex preview limited to the first ${wasmLimit} bytes; original bytes are unchanged]`;
  assert.equal(formattedLimit.length, (wasmLimit / 16) * 78 - 1);
  assert(formattedLimit.length + hexNotice.length <= 8 * 1024 * 1024, 'The labeled prefix must stay inside the editor index');
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
  assert.equal(index.complete,true);assert.equal(index.anchors.length,157);
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
  const bounded=model.sourceDocumentIndex('a'.repeat(model.SOURCE_DOCUMENT_LIMIT)+'outside');assert.equal(bounded.complete,false);assert.equal(model.sourceDocumentMatches(bounded,'outside').matches.length,0);
  costs.push(...checkCheckpointedColors(model));
  console.log('PASS sparse retained-source index, complete 20,001-line Find, Unicode/CRLF/BOM, bounds, minified late-column excerpts, checkpointed colors and formatted-line mapping on a 12 MiB one-line bundle; measured model costs '+JSON.stringify(costs));
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
