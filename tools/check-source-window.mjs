import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {performance} from 'node:perf_hooks';

export async function checkSourceWindowModel(root) {
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/source_syntax.js'),'utf8'))+
    ';({sourceDocumentIndex,sourceDocumentOffset,sourceDocumentPosition,sourceDocumentLine,sourceDocumentMatches,sourceDocumentWindow,sourceWindowMapping,sourceRepresentationLineMap,prettyPrintSource})');
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

export async function checkSourceWindowInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture}) {
  const until=async(expression,message)=>{const end=Date.now()+10000;while(Date.now()<end){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail(message);};
  const press=value=>key(value,value,{windowsVirtualKeyCode:{Enter:13,Escape:27,Tab:9,Backspace:8}[value],...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  const type=async(selector,value)=>{
    await click(selector);await key('a','KeyA',{modifiers:process.platform==='darwin'?4:2,windowsVirtualKeyCode:65,...(process.platform==='darwin'?{commands:['selectAll']}:{})});
    await press('Backspace');
    for(const letter of value)await key(letter,`Key${letter.toUpperCase()}`,{text:letter,unmodifiedText:letter});
  };
  const paneClick=async selector=>{
    // Scroll the sidebar's actual owner, then hit-test a native pointer click.
    // Never scroll an offscreen workspace to conceal a layout problem.
    const delta=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(selector)});if(!node)throw new Error('Missing Facts control');const pane=node.closest('#source-sidebar .debug-panes');if(!pane)return 0;const r=node.getBoundingClientRect(),p=pane.getBoundingClientRect();return r.top<p.top?r.top-p.top:r.bottom>p.bottom?r.bottom-p.bottom:0;})()`);
    if(delta)await wheel('#source-sidebar .debug-panes',delta);
    await click(selector);
  };
  const pick=async id=>{
    await click('#source-quick-open');await type('#quick-open-input',`facts-${id}.js`);await press('Enter');
    await until(`selectedSource()?.artifact_id==='${id}' && !selectedSource()?.loading && state.sourceEditorView?.index`,'Owned source did not render');
  };
  const text='\ufeff'+Array.from({length:20001},(_,line)=>line===999?'// boundaryNeedle A':line===1000?'// boundaryNeedle B':line===20000?'const lateNeedle="😀";':`// retained row ${line}`).join('\r\n');
  const minified='/*'+'a'.repeat(1700000)+'lateColumnNeedle'+'*/';
  const many=await fixture.addSource('40001',text),long=await fixture.addSource('40002',minified);
  const start=Buffer.byteLength(text.slice(0,text.indexOf('lateNeedle'))),end=start+Buffer.byteLength('lateNeedle');
  fixture.factsReports.set('40001',{schema:'reb-javascript-source-facts-v1',profile:'lexical-effects-v1',offset_unit:'utf-8-byte',source_bytes:many.byte_size,ok:true,
    scopes:[{id:0,parent_id:null,range:{start:0,end:many.byte_size},kind:'program'}],regions:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:many.byte_size},kind:'program',entry_order:0}],
    bindings:[{id:0,scope_id:0,name:'lateNeedle',range:{start,end},kind:'const'}],callables:[],operations:[{id:0,region_id:0,order:0,range:{start,end},kind:'read',detail:{target:{kind:'binding',binding_ids:[0],resolution:'lexical-only',name:'lateNeedle'}}}],
    coverage:{status:'complete',truncated:false,diagnostics:[],frontiers:[]},limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}});
  fixture.mode='complete';fixture.previewMode='ready';fixture.deobMode='ready';fixture.liveMode='ready';
  await evaluate('refreshArtifacts()');await viewport(1440,900);
  if(await evaluate('!document.querySelector("#source-sidebar").hidden'))await click('#source-sidebar-toggle');
  if(await evaluate('state.sourceHooksOpen'))await click('#source-hooks-close');
  if(await evaluate('document.querySelector("#screen-sources").hidden'))await click('[data-screen="sources"]');
  const costs=[];
  for(const [width,height] of [[1440,900],[760,560],[360,740]]) {
    await viewport(width,height);await pick('40001');
    await type('#source-search','lateNeedle');
    await until("elements.sourcePosition.textContent.includes('1 of 1') && state.sourceEditorView.window.line===20000",'Find missed the complete retained line after 20,000');
    const result=await evaluate(`(()=>{const row=document.querySelector('#source-code [data-local-line="20000"]'),r=row.getBoundingClientRect(),p=elements.sourceCodeWrap.getBoundingClientRect();return{position:elements.sourcePosition.textContent,coverage:elements.sourceSearchStatus.textContent,rowText:row.querySelector('.source-text').textContent,rows:elements.sourceCode.children.length,visible:r.bottom>p.top&&r.top<p.bottom,focus:document.activeElement.id};})()`);
    assert.match(result.position,/Line 20001, Column 7/);assert.equal(result.rowText,'const lateNeedle="😀";');assert(result.visible);assert(result.rows<=1000);assert.match(result.coverage,/Complete/);assert.equal(result.focus,'source-search');
    await screenshot(`source-window-${width}-late-line`);
    await type('#source-search','boundaryNeedle');await until('state.sourceEditorView.window.line===999','First boundary match not selected');
    await press('Enter');await until('state.sourceEditorView.window.line===1000','Next match did not cross window boundary');
    await key('Enter','Enter',{modifiers:8,windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});await until('state.sourceEditorView.window.line===999','Previous match did not cross window boundary');
    await type('#source-search','');await type('#source-window-line','20001');await type('#source-window-column','7');await press('Enter');
    await until("document.activeElement.dataset.localLine==='20000'",'Go did not focus the late retained line');
    // A linked workspace transition and Back/Forward must restore the logical
    // source window before restoring geometry. No source payload goes in history.
    await click('[data-screen="traffic"]');await click('#investigation-back');
    await until('state.sourceEditorView?.window.line===20000 && !document.querySelector("#screen-sources").hidden','Back lost logical late-line window');
    await click('#investigation-forward');await click('#investigation-back');
    await until('state.sourceEditorView?.window.line===20000','Repeated history lost logical source window');
    await pick('40002');await type('#source-search','lateColumnNeedle');
    await until('state.sourceEditorView.window.column===1700002','Find missed the late minified column');
    const clipped=await evaluate(`(()=>{const row=elements.sourceCode.querySelector('[data-local-line="0"]'),text=row.querySelector('.source-text'),r=text.getBoundingClientRect(),g=row.querySelector('.source-gutter').getBoundingClientRect();return{position:elements.sourcePosition.textContent,length:text.textContent.length,start:Number(row.dataset.columnStart),text:text.textContent,rows:elements.sourceCode.children.length,sameRow:Math.abs(r.top-g.top)<5,notice:row.textContent.includes('omitted')};})()`);
    assert.match(clipped.position,/Line 1, Column 1700003/);assert(clipped.length<=16385);assert(clipped.start>1600000);assert(clipped.text.includes('lateColumnNeedle'));assert(clipped.sameRow);assert(clipped.notice);
    await screenshot(`source-window-${width}-late-column`);
    await type('#source-search','');await pick('40001');await pick('40002');
    assert.equal(await evaluate('state.sourceEditorView.window.column'),0);
    assert.equal(await evaluate("elements.sourceCode.querySelector('.source-text').textContent.includes('lateColumnNeedle')"),false,'Go starts with the late-column target outside the mounted excerpt');
    await type('#source-window-line','1');await type('#source-window-column','1700003');await press('Enter');
    const goVisible=await evaluate(`(()=>{const row=elements.sourceCode.querySelector('[data-local-line="0"]'),text=row.querySelector('.source-text'),range=sourceOccurrenceRange(text,{column:1700002-Number(row.dataset.columnStart),length:16}),r=range.getBoundingClientRect(),p=elements.sourceCodeWrap.getBoundingClientRect();return {visible:r.left>=p.left&&r.right<=p.right&&r.top>=p.top&&r.bottom<=p.bottom,focused:document.activeElement===row,position:elements.sourcePosition.textContent};})()`);
    assert(goVisible.visible,'Go must reveal the actual late-column glyph, not merely the wide source row');assert(goVisible.focused);
    await screenshot(`source-window-${width}-go-late-column`);

    costs.push({width,rows:clipped.rows,mountedCodeUnits:clipped.length,documentBytes:long.byte_size});
  }
  await viewport(1440,900);await pick('40001');await type('#source-search','not-retained');
  assert.match(await evaluate('elements.sourcePosition.textContent'),/0 matches in complete retained text/);
  // Coverage-only mutations are authored fixture metadata, never production
  // captures. They prove that equivalent text cannot retain a complete-negative label.
  await evaluate(`(()=>{const source=state.artifacts.find(value=>value.artifact_id==='40001');source.contentTruncated=true;renderSources();applySourceSearch();})()`);
  assert.match(await evaluate('elements.sourcePosition.textContent'),/coverage is incomplete/);
  await evaluate(`(()=>{const source=state.artifacts.find(value=>value.artifact_id==='40001');source.contentTruncated=false;source.contentLossy=true;renderSources();applySourceSearch();})()`);
  assert.match(await evaluate('elements.sourceSearchStatus.textContent'),/Lossy/);
  await evaluate(`(()=>{const source=state.artifacts.find(value=>value.artifact_id==='40001');source.contentLossy=false;renderSources();})()`);
  await type('#source-search','');
  await click('#source-facts-toggle');
  await until("sourceFactsPanel.model.report?.source.artifact_id==='40001'",'Late-line Facts did not arrive');
  await paneClick('#source-facts-report select');await key('b','KeyB',{windowsVirtualKeyCode:66,text:'b',unmodifiedText:'b'});if(process.platform!=='darwin')await press('Enter');
  await until("document.querySelector('#source-facts-report select').value==='bindings'",'Facts bindings did not become visible');
  await paneClick('.source-fact > button');
  await until("elements.sourcePosition.textContent.includes('Original UTF-8 bytes') && state.sourceEditorView.window.line===20000",'Verified original-byte link still refused line 20001');
  assert((await evaluate('elements.sourcePosition.textContent')).includes(`[${start}, ${end})`));
  await screenshot('source-window-facts-original-late-line');
  if(await evaluate('!document.querySelector("#source-sidebar").hidden'))await click('#source-sidebar-toggle');
  await click('[data-screen="traffic"]');await click('#investigation-back');
  await until("elements.sourcePosition.textContent.includes('Original UTF-8 bytes') && state.sourceEditorView.window.line===20000",'Original-byte range history lost its location or provenance status');
  // Programmatic paste dispatch supplements the native keyboard tests: search
  // inputs normalize pasted newlines before input, so refusal must precede it.
  await type('#source-search','lateNeedle');
  const paste=await evaluate(`(()=>{const data=new DataTransfer();data.setData('text/plain',${JSON.stringify('late\nNeedle')});const event=new ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true});elements.sourceSearch.dispatchEvent(event);return {prevented:event.defaultPrevented,value:elements.sourceSearch.value,status:elements.sourcePosition.textContent};})()`);
  assert(paste.prevented);assert.equal(paste.value,'lateNeedle');assert.match(paste.status,/Multiline paste refused/);
  assert.equal(fixture.rejectedWrites.length,0);
  return {status:'passed',artifact:many.artifact_id,viewports:costs,sourceBytes:Buffer.byteLength(text),readOnly:true};
}
