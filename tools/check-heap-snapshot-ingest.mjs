// Owned synthetic layouts and a fresh local V8 capture, never saved browser data.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {writeHeapSnapshot} from 'node:v8';
import {join, resolve} from 'node:path';
const binary=resolve(process.argv[2] ?? 'build/reb-heap-snapshot');
const directory=await mkdtemp('/tmp/reb-heap-ingest-');
const fixture={snapshot:{meta:{node_fields:['type','name','id','self_size','edge_count'],node_types:[['synthetic','string'],'string','number','number','number'],edge_fields:['type','name_or_index','to_node'],edge_types:[['property'],'string_or_number','node']},node_count:2,edge_count:1},nodes:[0,0,1,0,1,1,1,3,16,0],edges:[0,2,5],strings:['root','owned-known-needle','value']};
async function run(value, success=true, expected) {
 const file=join(directory,'fixture.heapsnapshot');await writeFile(file,typeof value==='string'?value:JSON.stringify(value));
 const result=spawnSync(binary,['--snapshot',file,'--query','owned-known-needle'],{encoding:'utf8',maxBuffer:1024*1024});
 assert.equal(result.status,success?0:1,result.stderr);
 if(success){const body=JSON.parse(result.stdout);assert(body.results.some(r=>r.name.includes('owned-known-needle')));return body;}
 if(expected)assert.match(result.stderr,expected);
}
try {
 await run(fixture);
 await run({strings:fixture.strings,edges:fixture.edges,nodes:fixture.nodes,snapshot:fixture.snapshot});
 for(const suffix of ['\ud800','\udfff','\ud800a','\ud800\ud800','\ud800\udfff']){
  const altered=structuredClone(fixture);altered.strings[1]+=suffix;const result=await run(altered);
  assert.equal(result.string_limit_reached,!/^\ud800\udfff$/.test(suffix));
 }
 await run(JSON.stringify(fixture).slice(0,-10),false,/near byte/);
 await run({...fixture,snapshot:{...fixture.snapshot,meta:{}}},false,/layout/);
 await run({...fixture,snapshot:{...fixture.snapshot,node_count:3}},false,/counts/);
 await run(JSON.stringify(fixture).replace('"nodes":[','"nodes":[00,'),false,/near byte/);
 await run(JSON.stringify(fixture).replace('"nodes":','"nodes":[],"nodes":'),false,/repeats/);
 const missing=structuredClone(fixture);delete missing.strings;await run(missing,false,/requires/);
 globalThis.rebOwnedHeapNeedle={value:'owned-known-needle',allocation:Array.from({length:10},(_,i)=>({value:`owned-known-needle-${i}`}))};
 const actual=join(directory,'fresh.heapsnapshot');writeHeapSnapshot(actual);
 const result=spawnSync(binary,['--snapshot',actual,'--query','owned-known-needle'],{encoding:'utf8',maxBuffer:1024*1024});
 assert.equal(result.status,0,result.stderr);assert(JSON.parse(result.stdout).results.length>0);
 assert((await readFile(actual)).length>0);
 console.log('PASS heap ingest: fresh owned V8 capture, reordered fields, UTF-16 units, malformed/truncated JSON, missing/duplicate sections, unsupported layout and count mismatch');
} finally { delete globalThis.rebOwnedHeapNeedle;await rm(directory,{recursive:true,force:true}); }
