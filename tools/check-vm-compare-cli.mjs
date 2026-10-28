#!/usr/bin/env node
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,writeFile,readFile,rm,stat,symlink,mkdir,lstat,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import vm from '../apps/research-ui/vm_semantics.js';

const copy=value=>JSON.parse(JSON.stringify(value));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const state=(pc,registers=[],stack=[],memory=[])=>({pc,halted:false,registers,stack,memory});
const fixture=(id,sequence,before,after)=>({
  format:'reb-vm-trace-v1',
  identity:{trace_id:id,investigation_id:'inv:1',finding_id:'finding:2',artifact_id:'artifact:3',artifact_sha256:'a'.repeat(64),scope_id:'owned-cli-test',backend:'fixture'},
  architecture:'register',coverage:{complete:false,dropped_steps:3,limitations:['Supplied owned fixture; no native capture']},
  steps:[{sequence,opcode:'ff',operands:[],instruction_size:1,before,after,evidence_refs:[id+':evidence']}]
});
const left=fixture('left',7,state(3,[null,1],[null],[[4,null],[5,0]]),state(4,[null,2],[],[[8,0]]));
const right=fixture('right',91,state(3,[null,1,0],[],[[4,null]]),state(9,[null,2,0],[null],[[4,null],[8,0]]));
const directory=await mkdtemp(join(tmpdir(),'reb-vm-compare-'));
const cli=resolve('tools/vm-semantics.mjs');
// No wall-clock timeout: every input is a bounded regular file or a FIFO the
// CLI opens non-blocking, so a correct CLI always exits and the check waits for
// that exit. A timer only turned machine stalls into failures. A regression to a
// blocking FIFO open hangs this check, which the CI job timeout reports.
const run=(...args)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8'});
let serial=0;
const fresh=label=>join(directory,`${serial++}-${label}`);
const input=async(label,value)=>{const path=fresh(label);await writeFile(path,typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value));return path;};
const absent=async path=>{await assert.rejects(lstat(path),{code:'ENOENT'});};
const failure=async(args,output,pattern)=>{
  const result=run(...args);
  assert.equal(result.error,undefined,`CLI did not start: ${result.error?.message}`);
  assert.notEqual(result.status,0,`Unexpected success: ${args.join(' ')}`);
  assert.equal(result.stdout,'');
  if(pattern)assert.match(result.stderr,pattern);
  await absent(output);
};
const success=async(...args)=>{
  const result=run(...args);assert.equal(result.status,0,result.stderr);
  const output=args.at(-1),bytes=await readFile(output),receipt=JSON.parse(result.stdout);
  assert.deepEqual(receipt,{bytes:bytes.length,network_requests:0,temporary_cleanup_pending:false});
  assert.equal((await stat(output)).mode&0o777,0o600);
  assert(bytes.length<=4194304);
  return JSON.parse(bytes.toString('utf8'));
};
try {
  const leftPath=await input('left.json',left),rightPath=await input('right.json',right);
  const output=fresh('compare.json');
  const report=await success('compare',leftPath,'7',rightPath,'91',output);
  assert.deepEqual(Object.keys(report),['left_source_sha256','right_source_sha256','result']);
  assert.equal(report.left_source_sha256,hash(await readFile(leftPath)));
  assert.equal(report.right_source_sha256,hash(await readFile(rightPath)));
  assert.notEqual(report.left_source_sha256,left.identity.artifact_sha256);
  assert.notEqual(report.right_source_sha256,right.identity.artifact_sha256);
  assert.deepEqual(report.result,vm.compareSteps(left,7,right,91));
  assert.equal(report.result.equivalence_proven,false);
  assert.equal(report.result.left.step.sequence,7);assert.equal(report.result.right.step.sequence,91);
  assert.deepEqual(report.result.left.identity,left.identity);assert.deepEqual(report.result.right.identity,right.identity);
  assert.deepEqual(report.result.left.coverage,left.coverage);assert.deepEqual(report.result.right.coverage,right.coverage);
  assert.deepEqual(report.result.left.step.evidence_refs,left.steps[0].evidence_refs);
  assert.deepEqual(report.result.right.step.evidence_refs,right.steps[0].evidence_refs);
  const cell=location=>{const item=report.result.cells.find(item=>item.location===location);assert(item,location);return item;};
  assert.equal(cell('registers:0').status,'unknown');
  assert.equal(cell('registers:1').status,'observed_equal');
  assert.equal(cell('registers:2').status,'different');
  assert.deepEqual(cell('registers:2').left_before,{present:false,value:null});
  assert.deepEqual(cell('registers:2').right_before,{present:true,value:0});
  assert.deepEqual(cell('stack:0').left_before,{present:true,value:null});
  assert.deepEqual(cell('stack:0').right_before,{present:false,value:null});
  assert.equal(cell('stack:0').status,'different');
  assert.equal(cell('memory:4').before_status,'unknown');
  assert.equal(cell('memory:4').after_status,'different');

  // Identical parsed observations may have different exact input-file hashes.
  const spaced=await input('spaced.json',JSON.stringify(left,null,2)+'\n');
  const identical=await success('compare',leftPath,'7',spaced,'7',fresh('same-observations.json'));
  assert.notEqual(identical.left_source_sha256,identical.right_source_sha256);
  assert.deepEqual(identical.result.left.identity,identical.result.right.identity);
  assert.equal(identical.result.cells.find(item=>item.location==='registers:0').status,'unknown');
  assert.equal(identical.result.equivalence_proven,false);

  // No positional fallback, rounding, implicit alignment, or sequence coercion.
  for(const sequence of ['0','8','90','92','00','07','+7','-0','-1','7.0','7e0',' 7','7 ','','9007199254740992','Infinity','NaN','0x7']) {
    for(const side of ['left','right']) {
      const out=fresh('sequence-refused');
      const args=['compare',leftPath,side==='left'?sequence:'7',rightPath,side==='right'?sequence:'91',out];
      await failure(args,out);
    }
  }
  const maximum=copy(left);maximum.steps[0].sequence=Number.MAX_SAFE_INTEGER;
  const maxPath=await input('max-sequence.json',maximum);
  const exact=await success('compare',maxPath,'9007199254740991',rightPath,'91',fresh('max-sequence-report'));
  assert.equal(exact.result.left.step.sequence,Number.MAX_SAFE_INTEGER);

  const malformed=[
    '', '{}', '{"format":1,"format":2}', JSON.stringify(left).replace('"pc":3','"pc":3,"pc":3'),
    JSON.stringify(left).replace('"sequence":7','"sequence":7.0'),
    JSON.stringify(left).replace('"sequence":7','"sequence":7e0'),
    JSON.stringify(left).replace('"sequence":7','"sequence":-0'),
    JSON.stringify(left).replace('"sequence":7','"sequence":9007199254740992'),
    JSON.stringify(left).replace('"sequence":7','"sequence":9007199254740991.1'),
    JSON.stringify(left).replace('"left"','"\\ud800"'),
    Buffer.concat([Buffer.from(JSON.stringify(left)),Buffer.from([0xc0,0xaf])]),
    '\ufeff'+JSON.stringify(left),
    JSON.stringify({...left,unexpected:true}),
    JSON.stringify({...left,steps:[]}),
    JSON.stringify({...left,steps:Array.from({length:257},()=>left.steps[0])}),
    ' '.repeat(1048577)
  ];
  for(const value of malformed) {
    const bad=await input('malformed.json',value);
    for(const side of ['left','right']) {
      const out=fresh('malformed-refused');
      await failure(['compare',side==='left'?bad:leftPath,'7',side==='right'?bad:rightPath,'91',out],out);
    }
  }
  // The byte budget includes harmless whitespace and applies independently.
  const json=JSON.stringify(left),padded=await input('exact-1MiB.json',json+' '.repeat(1048576-Buffer.byteLength(json)));
  const paddedReport=await success('compare',padded,'7',padded,'7',fresh('exact-1MiB-report'));
  assert.equal(paddedReport.left_source_sha256,hash(await readFile(padded)));

  for(const side of ['left','right']) {
    const directoryInput=fresh('input-directory');await mkdir(directoryInput);
    const link=fresh('input-symlink');await symlink(leftPath,link);
    const dangling=fresh('input-dangling-symlink');await symlink(fresh('missing-target'),dangling);
    const fifo=fresh('input-fifo');const made=spawnSync('mkfifo',[fifo],{encoding:'utf8'});assert.equal(made.status,0,made.stderr);
    for(const bad of [directoryInput,link,dangling,fifo,'/dev/null',fresh('missing-input')]) {
      const out=fresh('path-refused');
      await failure(['compare',side==='left'?bad:leftPath,'7',side==='right'?bad:rightPath,'91',out],out);
    }
  }
  // Existing outputs, even either source or a dangling symlink, stay intact.
  for(const target of [output,leftPath,rightPath]) {
    const bytes=await readFile(target);
    const result=run('compare',leftPath,'7',rightPath,'91',target);assert.notEqual(result.status,0);
    assert.deepEqual(await readFile(target),bytes);
  }
  const outputDirectory=fresh('output-directory');await mkdir(outputDirectory);
  assert.notEqual(run('compare',leftPath,'7',rightPath,'91',outputDirectory).status,0);
  assert.deepEqual(await readdir(outputDirectory),[]);
  const sentinel=await input('sentinel','do not replace');
  for(const target of [sentinel,fresh('uncreated-symlink-target')]) {
    const link=fresh('output-symlink');await symlink(target,link);
    assert.notEqual(run('compare',leftPath,'7',rightPath,'91',link).status,0);
    assert((await lstat(link)).isSymbolicLink());
    if(target===sentinel)assert.equal(await readFile(target,'utf8'),'do not replace');else await absent(target);
  }
  const missingDirectoryOutput=join(fresh('missing-directory'),'report.json');
  await failure(['compare',leftPath,'7',rightPath,'91',missingDirectoryOutput],missingDirectoryOutput,/new output path/);
  for(const args of [[],['compare'],['compare',leftPath,'7',rightPath,'91'],['compare',leftPath,'7',rightPath,'91',fresh('unused'),'extra'],['inspect',leftPath,output,'extra'],['__proto__'],['toString']]) {
    const result=run(...args);assert.notEqual(result.status,0);assert.match(result.stderr,/explicit offline commands/);
  }
  assert.match(run('--help').stdout,/compare LEFT.json LEFT_SEQUENCE RIGHT.json RIGHT_SEQUENCE OUTPUT.json/);

  // Dense legal inputs retain the 256-step ceiling; expanded legacy reports
  // must still stop before the 4 MiB publication boundary.
  const dense=copy(left);dense.coverage={complete:true,dropped_steps:0,limitations:[]};
  const denseState=i=>state(i,Array(64).fill(i%2),Array(128).fill(i%2),Array.from({length:128},(_,address)=>[address,i%2]));
  dense.steps=Array.from({length:256},(_,sequence)=>({sequence,opcode:'ff',operands:[],instruction_size:1,before:denseState(sequence),after:denseState(sequence+1),evidence_refs:['dense:'+sequence]}));
  assert(Buffer.byteLength(JSON.stringify(dense))<1048576);
  const densePath=await input('dense.json',dense);
  const denseReport=await success('compare',densePath,'255',densePath,'0',fresh('dense-compare'));
  assert.equal(denseReport.result.left.step.sequence,255);assert.equal(denseReport.result.right.step.sequence,0);
  const tooLargeOutput=fresh('oversized-report');
  await failure(['inspect',densePath,tooLargeOutput],tooLargeOutput,/Report exceeds 4 MiB/);

  // Existing command envelopes and exact single-step report remain unchanged.
  const inspected=await success('inspect',leftPath,fresh('inspect.json'));
  assert.deepEqual(inspected,{source_sha256:hash(await readFile(leftPath)),hypotheses_sha256:null,result:vm.inspect(left)});
  const stepped=await success('step',leftPath,'7',fresh('step.json'));
  assert.deepEqual(stepped,{source_sha256:hash(await readFile(leftPath)),hypotheses_sha256:null,result:{format:'reb-vm-step-v1',identity:left.identity,step:left.steps[0],changes:vm.effects(left.steps[0]),reads:'unknown'}});
  const hypotheses={format:'reb-vm-hypothesis-v1',trace_id:left.identity.trace_id,mappings:[]};
  const hypothesesPath=await input('hypotheses.json',hypotheses);
  const validated=await success('validate',leftPath,hypothesesPath,fresh('validate.json'));
  assert.deepEqual(validated,{source_sha256:hash(await readFile(leftPath)),hypotheses_sha256:hash(await readFile(hypothesesPath)),result:vm.validate(left,hypotheses)});
  assert(!(await readdir(directory)).some(name=>name.startsWith('.reb-client-export-')),'Private publication temporary directory leaked');
} finally { await rm(directory,{recursive:true,force:true}); }
console.log('PASS exact two-trace CLI comparison, independent source hashes, unknown/absence distinctions, canonical sequences, malformed/bounded inputs, private atomic no-overwrite output and unchanged legacy reports');
