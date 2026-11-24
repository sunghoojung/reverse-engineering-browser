#!/usr/bin/env node
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const executable=resolve(process.argv[2]??'build/reb-decoder');
const strictStderr=process.argv.includes('--strict-stderr');
function run(operation,input) {const result=spawnSync(executable,['transform',operation],{input:Buffer.from(input),encoding:'utf8',timeout:60000,maxBuffer:1<<30});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.ok([0,2].includes(result.status),`Unexpected decoder exit ${result.status}: ${result.stderr}`);assert.doesNotMatch(result.stderr,/AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|runtime error:/i);if(strictStderr||result.status===0)assert.equal(result.stderr,'');return result;}
function decode(operation,input) {const result=run(operation,input);assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);}
function refuse(operation,input,status=2) {const result=run(operation,input);assert.notEqual(result.status,0);assert.equal(result.stdout,'');if(status!==null)assert.equal(result.status,status);}
const varint=value=>{let n=BigInt(value),out=[];do{let byte=Number(n&127n);n>>=7n;if(n)byte|=128;out.push(byte);}while(n);return Buffer.from(out);};
const bytes=(number,payload)=>Buffer.concat([varint((number<<3)|2),varint(payload.length),Buffer.from(payload)]);
const envelope=(flags,payload)=>{const head=Buffer.alloc(5);head[0]=flags;head.writeUInt32BE(payload.length,1);return Buffer.concat([head,Buffer.from(payload)]);};
const raw=Buffer.concat([Buffer.from([8,150,1,8]),varint(18446744073709551615n),Buffer.from([0x15,0x78,0x56,0x34,0x12,0x19,1,2,3,4,5,6,7,8]),bytes(4,Buffer.from([0,255,0xc3,0xa9]))]);
const report=decode('protobuf-inspect',raw);assert.equal(report.format,'reb-protobuf-wire-v1');assert.equal(report.schema_known,false);assert.equal(report.fields.length,5);
assert.deepEqual(report.fields.slice(0,2).map(x=>x.unsigned_decimal),['150','18446744073709551615']);
assert.equal(report.fields[2].unsigned_decimal,'305419896');assert.equal(report.fields[3].unsigned_decimal,'578437695752307201');
assert.equal(report.fields[4].bytes_base64,'AP/DqQ==');assert.equal(report.fields[4].end,raw.length);
assert.deepEqual(decode('protobuf-inspect',[]).fields,[]);
assert.equal(decode('protobuf-inspect',[8,0x80,0]).fields[0].unsigned_decimal,'0','Nonminimal observed varint remains inspectable without canonical rewriting');
for(const bad of [[0],[8],[8,...Array(10).fill(255)],[8,...Array(9).fill(255),2],[0x0e],[0x0b],[0x0c],[0x12,2,1],[0x15,1,2],[0x19,1,2,3],Array(11).fill(0x80)])refuse('protobuf-inspect',bad);
{const payload=Buffer.alloc(1048577,7);const field=decode('protobuf-inspect',Buffer.concat([Buffer.from([10,0x81,0x80,0x40]),payload])).fields[0];assert.equal(field.length,1048577);assert.equal(Buffer.from(field.bytes_base64,'base64').equals(payload),true);}assert.equal(decode('protobuf-inspect',Buffer.from(Array(4097).fill([8,1]).flat())).fields.length,4097);
assert.equal(decode('protobuf-inspect',bytes(1,Buffer.alloc(786432))).fields[0].length,786432);
const trailer=envelope(128,Buffer.from('grpc-status:0\r\ngrpc-message:synthetic%20only\r\nx-test:one\r\nx-test:two\r\n'));
const wire=Buffer.concat([envelope(0,raw),envelope(0,Buffer.from([8,1])),trailer]);
const grpc=decode('grpc-web-inspect',wire);assert.equal(grpc.frames.length,3);assert.equal(grpc.frames[0].offset,0);assert.equal(grpc.frames[0].payload_offset,5);assert.equal(grpc.frames[0].end,raw.length+5);assert.deepEqual(grpc.frames[0].protobuf,report);assert.equal(grpc.trailers_present,true);assert.equal(grpc.rpc_success_verified,false);assert.equal(grpc.frames[2].headers.length,4);
assert.equal(decode('grpc-web-inspect',envelope(0,raw)).trailers_present,false);
assert.equal(decode('grpc-web-inspect',trailer).frames[0].kind,'trailers');
assert.equal(decode('grpc-web-inspect',[]).trailers_present,false);
const everyByte=Array.from(wire,byte=>Buffer.from([byte]).toString('base64')).join('');
for(const text of [wire.toString('base64'),everyByte,wire.subarray(0,2).toString('base64')+wire.subarray(2).toString('base64')])assert.deepEqual(decode('grpc-web-text-inspect',Buffer.from(text)),grpc);
for(const text of ['A','====','AB==','AAAA\n','AA==%'])refuse('grpc-web-text-inspect',Buffer.from(text));
for(const bad of [Buffer.from([0,0,0,0]),Buffer.from([0,255,255,255,255]),envelope(1,[8,1]),envelope(129,[]),envelope(2,[]),Buffer.concat([trailer,envelope(0,[])]),envelope(128,Buffer.from('Status:0\r\n')),envelope(128,Buffer.from('grpc-status:0\n')),envelope(128,Buffer.from('grpc-status:0\r\n\r\n')),envelope(128,Buffer.from('x:\0\r\n'))])refuse('grpc-web-inspect',bad);

assert.equal(decode('grpc-web-inspect',Buffer.concat(Array(10000).fill(envelope(0,[])))).frames.length,10000);
const many=Buffer.from(Array(2048).fill([8,1]).flat());{const report=decode('grpc-web-inspect',Buffer.concat([envelope(0,many),envelope(0,many),envelope(0,[8,1])]));assert.deepEqual(report.frames.map(frame=>frame.protobuf.fields.length),[2048,2048,1]);}const trailerLines=Array.from({length:4096},(_,index)=>`x-test-${index}:${'v'.repeat(16)}\r\n`).join('');{const report=decode('grpc-web-inspect',envelope(128,Buffer.from(trailerLines)));assert.equal(report.frames[0].headers.length,4096);assert.ok(trailerLines.length>16384);}
let seed=0x12345678;
for(let i=0;i<128;i++){const input=Buffer.alloc(i%65);for(let j=0;j<input.length;j++){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;input[j]=seed&255;}for(const operation of ['protobuf-inspect','grpc-web-inspect']){const result=run(operation,input);if(result.status===0)JSON.parse(result.stdout);else assert.equal(result.stdout,'');}}
console.log('PASS native protobuf/gRPC-web wire CLI: exact uint64/offsets/repeated fields, binary payloads, framed messages/trailers, padded base64 chunks, malformed/overflow/compression/truncation refusal, 10,000 frames, 4,097 fields and 4,096 trailer lines whole, and deterministic fuzz corpus');
