#!/usr/bin/env node
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
const executable=resolve(process.argv[2]??'build/reb-decoder');
const strictStderr=process.argv.includes('--strict-stderr');
function run(operation,input) {const result=spawnSync(executable,['transform',operation],{input:Buffer.from(input),encoding:'utf8',timeout:5000,maxBuffer:2*1048576});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.ok([0,2,3].includes(result.status),`Unexpected decoder exit ${result.status}: ${result.stderr}`);assert.doesNotMatch(result.stderr,/AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|runtime error:/i);if(strictStderr||result.status===0)assert.equal(result.stderr,'');return result;}
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
refuse('protobuf-inspect',Buffer.alloc(1048577));refuse('protobuf-inspect',Buffer.from(Array(4097).fill([8,1]).flat()),3);
refuse('protobuf-inspect',bytes(1,Buffer.alloc(786432)),3);
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
refuse('grpc-web-inspect',Buffer.concat(Array(257).fill(envelope(0,[]))),3);
assert.equal(decode('grpc-web-inspect',Buffer.concat(Array(256).fill(envelope(0,[])))).frames.length,256);
const many=Buffer.from(Array(2048).fill([8,1]).flat());refuse('grpc-web-inspect',Buffer.concat([envelope(0,many),envelope(0,many),envelope(0,[8,1])]),3);
let seed=0x12345678;
for(let i=0;i<128;i++){const input=Buffer.alloc(i%65);for(let j=0;j<input.length;j++){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;input[j]=seed&255;}for(const operation of ['protobuf-inspect','grpc-web-inspect']){const result=run(operation,input);if(result.status===0)JSON.parse(result.stdout);else assert.equal(result.stdout,'');}}
console.log('PASS native protobuf/gRPC-web wire CLI: exact uint64/offsets/repeated fields, binary payloads, framed messages/trailers, padded base64 chunks, malformed/overflow/compression/truncation refusal, shared field/output bounds and deterministic fuzz corpus');
