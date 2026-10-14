#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,stat,symlink,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import {network} from './traffic-capture-qa.mjs';
import {introspectionSDL,constantLiteral} from './graphql-sdl.mjs';
const ref=(kind,name)=>({kind,name,ofType:null});
const string=()=>ref('SCALAR','String'),integer=()=>ref('SCALAR','Int');
const input=(name,type,defaultValue=null)=>({name,type,defaultValue,description:null,isDeprecated:false,deprecationReason:null});
const field=(name,type,args=[])=>({name,type,args,description:null,isDeprecated:false,deprecationReason:null});
function fixture() {return {data:{__schema:{description:'Authored only\n" } type Injected { x: Int }',queryType:{name:'Query'},mutationType:null,subscriptionType:null,types:[
  {kind:'SCALAR',name:'String',description:null},{kind:'SCALAR',name:'Int',description:null},
  {kind:'SCALAR',name:'Date',description:'Date scalar',specifiedByURL:'https://example.test/date'},
  {kind:'OBJECT',name:'Query',description:null,interfaces:[],fields:[field('node',ref('INTERFACE','Node'),[input('limit',integer(),'10'),input('filter',ref('INPUT_OBJECT','Filter'),'{choice: RED, tags: ["x", "y"]}')]),field('items',{kind:'NON_NULL',name:null,ofType:{kind:'LIST',name:null,ofType:{kind:'NON_NULL',name:null,ofType:string()}}})]},
  {kind:'INTERFACE',name:'Node',description:null,interfaces:[],fields:[field('id',string())]},
  {kind:'OBJECT',name:'Item',description:null,interfaces:[ref('INTERFACE','Node')],fields:[field('id',string()),{...field('old',string()),isDeprecated:true,deprecationReason:'Use id "instead"'}]},
  {kind:'UNION',name:'Search',description:null,possibleTypes:[ref('OBJECT','Item')]},
  {kind:'ENUM',name:'Color',description:null,enumValues:[{name:'RED',description:null,isDeprecated:false,deprecationReason:null},{name:'BLUE',description:'Blue',isDeprecated:true,deprecationReason:'No longer supported'}]},
  {kind:'INPUT_OBJECT',name:'Filter',description:null,isOneOf:false,inputFields:[input('choice',ref('ENUM','Color'),'RED'),input('tags',{kind:'LIST',name:null,ofType:string()},'[]')]},
  {kind:'INPUT_OBJECT',name:'Lookup',description:null,isOneOf:true,inputFields:[input('id',string()),input('index',integer())]},
  {kind:'OBJECT',name:'__Schema',fields:null}
],directives:[{name:'custom',description:'Inert @x',isRepeatable:true,locations:['FIELD_DEFINITION','OBJECT'],args:[input('label',string(),'"safe"')]}]}}};}
const value=fixture(),before=JSON.stringify(value),result=introspectionSDL(value);
assert.equal(JSON.stringify(value),before);assert.equal(result.type_count,10);assert.equal(result.warnings.length,0);
for(const snippet of ['schema {\n  query: Query\n}','scalar Date @specifiedBy(url: "https://example.test/date")','type Item implements Node','union Search = Item','input Lookup @oneOf','items: [String!]!','directive @custom','repeatable on FIELD_DEFINITION | OBJECT','@deprecated(reason: "Use id \\"instead\\"")','filter: Filter = {choice: RED, tags: ["x", "y"]}'])assert(result.text.includes(snippet),snippet);
assert(result.text.includes('"Authored only\\n\\" } type Injected { x: Int }"'));
assert(!result.text.includes('type __Schema'));assert(!result.text.includes('scalar String'));
assert.equal(introspectionSDL({__schema:value.data.__schema}).text,result.text);
if(process.env.REB_GRAPHQL_REFERENCE) {
  const require=createRequire(new URL(import.meta.url));
  const graphql=require(process.env.REB_GRAPHQL_REFERENCE);
  assert.equal(graphql.version,'16.11.0');
  const parsed=graphql.buildSchema(result.text);
  assert.deepEqual(graphql.validateSchema(parsed),[]);
  const original=graphql.buildClientSchema(value.data);
  assert.equal(graphql.printSchema(parsed),graphql.printSchema(original));
  console.log('PASS independent graphql-js 16.11.0 parser/schema validation and introspection reconstruction equality');
}
const copy=value=>JSON.parse(JSON.stringify(value));
const invalid=[
 v=>v.errors=[{message:'partial'}],v=>delete v.data.__schema.types,v=>v.data.__schema.queryType=null,
 v=>v.data.__schema.types.push(v.data.__schema.types[0]),v=>v.data.__schema.types[3].name='Query }',
 v=>v.data.__schema.types[3].fields[0].type=ref('OBJECT','Missing'),
 v=>v.data.__schema.types[3].fields[0].type=ref('INPUT_OBJECT','Filter'),
 v=>v.data.__schema.types[3].fields[0].args[0].type=ref('OBJECT','Item'),
 v=>v.data.__schema.types[3].fields[0].args[0].defaultValue='10) { injected: String }',
 v=>delete v.data.__schema.types[3].fields[0].args[0].defaultValue,
 v=>v.data.__schema.types[3].fields.push(v.data.__schema.types[3].fields[0]),
 v=>v.data.__schema.types[6].possibleTypes=[ref('SCALAR','String')],
 v=>v.data.__schema.types[7].enumValues[0].name='true',v=>v.data.__schema.types[7].enumValues[1].deprecationReason=null,
 v=>v.data.__schema.types[9].inputFields[0].defaultValue='"not allowed"',
 v=>v.data.__schema.directives[0].locations=['INVALID'],v=>v.data.__schema.directives[0].args[0].name='x) @evil',
 v=>v.data.__schema.types[0].kind='OBJECT',
 v=>v.data.__schema.types[3].fields[1].type.ofType={kind:'NON_NULL',name:null,ofType:string()},
];
for(const mutate of invalid){const changed=copy(value);mutate(changed);assert.throws(()=>introspectionSDL(changed),/Unsupported or incomplete/);}
for(const literal of ['null','true','-12','1.25e-3','RED','"escaped\\n雪"','[1,2,null]','{x: ["value"], nested: {yes: true}}','"""multi\nline"""'])assert.equal(constantLiteral(literal),literal);
for(const literal of ['$variable','1 type X { a: Int }','{a:1,a:2}','[1','01','1.','"\\uD800"','1\u00a0','"unfinished','[1] @x','['.repeat(33)+'1'+']'.repeat(33)])assert.throws(()=>constantLiteral(literal),/Unsupported/);
const old=copy(value);delete old.data.__schema.types[9].isOneOf;assert.equal(introspectionSDL(old).warnings.length,1);
const directory=await mkdtemp(join(tmpdir(),'reb-graphql-')),path=join(directory,'introspection.json'),output=join(directory,'schema.graphql');
const script=new URL('./export-graphql-sdl.mjs',import.meta.url).pathname;
const run=(...args)=>spawnSync(process.execPath,[script,...args],{encoding:'utf8',timeout:15000});
try {
 await writeFile(path,JSON.stringify(value));assert.equal(run('--help').status,0);
 const runResult=run('--input',path,'--output',output);assert.equal(runResult.status,0,runResult.stderr);assert.equal(JSON.parse(runResult.stdout).network_requests,0);
 assert(!runResult.stdout.includes('Authored'));assert.equal((await stat(output)).mode&0o777,0o600);
 const saved=await readFile(output,'utf8');assert.match(saved,/^# Source SHA-256: [a-f0-9]{64}\n/);assert(saved.endsWith(result.text));
 assert.notEqual(run('--input',path,'--output',output).status,0);assert.equal(await readFile(output,'utf8'),saved);
 const link=join(directory,'link');await symlink(path,link);assert.notEqual(run('--input',link,'--output',join(directory,'new')).status,0);
 const net=network(),row=net.requests[0];row.state='complete';row.status=200;row.response.body={state:'available',mime:'application/json',text:JSON.stringify(value),base64:'',truncated:false,reason:''};
 const savedEnvelope={format:'reb-network-request-v1',source:{instance_id:net.instance_id,capture_epoch:net.capture_epoch,request_id:row.id,target_id:row.target_id,started_monotonic_ms:row.started_monotonic_ms},debugger_generation:42,request:row};
 await writeFile(path,JSON.stringify(savedEnvelope));const capturedOutput=join(directory,'captured.graphql');
 const captured=run('--input',path,'--output',capturedOutput);assert.equal(captured.status,0,captured.stderr);assert((await readFile(capturedOutput,'utf8')).includes('# Saved REB identity: '));assert((await readFile(capturedOutput,'utf8')).endsWith(result.text));
 row.response.body.truncated=true;await writeFile(path,JSON.stringify(savedEnvelope));assert.notEqual(run('--input',path,'--output',join(directory,'truncated.graphql')).status,0);
 await writeFile(path,'{"__schema":{},"__schema":{}}');assert.notEqual(run('--input',path,'--output',join(directory,'new')).status,0);
 await writeFile(path,Buffer.alloc(1048577,32));assert.notEqual(run('--input',path,'--output',join(directory,'new')).status,0);
} finally {await rm(directory,{recursive:true,force:true});}
console.log('PASS offline introspection SDL: all type kinds, roots, wrappers, descriptions, defaults, custom directives, OneOf, deprecation, invalid/partial/injection bounds, exact source hash and private no-overwrite CLI');
