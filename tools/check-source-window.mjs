import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {performance} from 'node:perf_hooks';

export async function checkSourceWindowModel(root) {
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8'))+
    ';({sourceDocumentIndex,sourceDocumentOffset,sourceDocumentPosition,sourceDocumentLine,sourceDocumentMatches,sourceDocumentWindow,sourceWindowMapping,sourceRepresentationLineMap,prettyPrintSource,sourceName,formatWasmHex,wasmHexByteLimit})', {URL});
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
  const bounded=model.sourceDocumentIndex('a'.repeat(8*1024*1024)+'outside');assert.equal(bounded.complete,false);assert.equal(model.sourceDocumentMatches(bounded,'outside').matches.length,0);
  const original='\ufeffconst 雪="😀";\r\n'+'\n'.repeat(20000)+'const late=1;';
  const formatted=model.prettyPrintSource({kind:'javascript'},original);
  if(!formatted.error) {
    const complete=model.sourceRepresentationLineMap(original,original,null,formatted),formattedIndex=model.sourceDocumentIndex(formatted.text);
    const mapping=model.sourceWindowMapping(original,original,null,formatted);
    for(const line of [0,Math.min(1000,formattedIndex.lineCount-1),formattedIndex.lineCount-1]) {
      const window=model.sourceDocumentWindow(formattedIndex,line),mapped=mapping(window.rows);
      mapped.forEach((row,i)=>{assert.equal(row.originalLine,complete[window.rows[i].line].originalLine);assert.equal(row.originalColumn,complete[window.rows[i].line].originalColumn);});
    }
  }
  console.log('PASS sparse retained-source index, complete 20,001-line Find, Unicode/CRLF/BOM, bounds, original mapping and minified late-column excerpts; measured model costs '+JSON.stringify(costs));
  return costs;
}
