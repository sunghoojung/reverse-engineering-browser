#!/usr/bin/env node
import assert from 'node:assert/strict';
import {checkMagicDecoderUI} from './check-magic-decoder-ui.mjs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {gzipSync,deflateSync} from 'node:zlib';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
const executable=resolve(process.argv[2]??'build/reb-decoder');
const strictStderr=process.argv.includes('--strict-stderr');
const run=(op,input)=>{const r=spawnSync(executable,['transform',op],{input:Buffer.from(input),encoding:'utf8',timeout:5000,maxBuffer:2*1048576});assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.ok([0,2,3].includes(r.status),`Unexpected decoder exit ${r.status}: ${r.stderr}`);assert.doesNotMatch(r.stderr,/AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|runtime error:/i);if(strictStderr||r.status===0)assert.equal(r.stderr,'');return r;};
const magic=input=>{const r=run('magic-inspect',input);assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);};
const has=(report,op)=>report.candidates.some(c=>c.operation===op);
for(const algorithm of ['sha256','sha384','sha512'])for(const input of [Buffer.alloc(0),Buffer.from('abc'),Buffer.from('雪😀\r\n\0'),Buffer.from([0,255,128,1]),Buffer.alloc(55,97),Buffer.alloc(56,97),Buffer.alloc(63,97),Buffer.alloc(64,97),Buffer.alloc(111,97),Buffer.alloc(112,97),Buffer.alloc(127,97),Buffer.alloc(128,97),Buffer.alloc(1048576,97)]){const r=run(algorithm,input);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,createHash(algorithm).update(input).digest('hex'));}
assert.equal(run('sha256',Buffer.from('abc')).stdout,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
for(const op of ['sha256','sha384','sha512','magic-inspect']){const r=run(op,Buffer.alloc(1048577));assert.equal(r.status,2);assert.equal(r.stdout,'');}
assert.deepEqual(magic(Buffer.alloc(0)).candidates,[]);
const ambiguous=magic(Buffer.from('deadbeef'));assert(has(ambiguous,'hex-decode'));assert(has(ambiguous,'base64-decode'));assert(has(ambiguous,'base64url-decode'));assert.equal(ambiguous.automatic_transforms,0);assert.equal(ambiguous.meaning_verified,false);
assert(has(magic(Buffer.from('SGVsbG8=')),'base64-decode'));assert(!has(magic(Buffer.from('AB==')),'base64-decode'));assert(!has(magic(Buffer.from('SGVsbG8=\n')),'base64-decode'));assert(!has(magic(Buffer.from('abc')),'hex-decode'));assert(has(magic(Buffer.from('-_8')),'base64url-decode'));
assert(has(magic(Buffer.from('{"inert":"<script>never run</script>"}')),'json-pretty'));assert(!has(magic(Buffer.from('{bad')),'json-pretty'));
for(const [op,compressed] of [['gzip-decompress',gzipSync(Buffer.from('owned'))],['zlib-decompress',deflateSync(Buffer.from('owned'))]]){const report=magic(compressed);assert(has(report,op));assert.equal(report.candidates.find(c=>c.operation===op).confidence,'signature-only');}
const bomb=gzipSync(Buffer.alloc(16*1048576));assert(has(magic(bomb),'gzip-decompress'),'Magic identifies a signature without inflating oversized content');
assert(has(magic(Buffer.from([0x1f,0x8b,8,0,0,0,0,0,0,0])),'gzip-decompress'),'Header-only candidate explicitly does not validate body');
assert(!has(magic(Buffer.from([0x1f,0x8b,8,0xe0,0,0,0,0,0,0])),'gzip-decompress'));
assert.equal(magic(Buffer.from([0xff,0xc0,0x80])).utf8_valid,false);assert.equal(magic(Buffer.from('雪')).utf8_valid,true);
for(const size of [32,40,64,96,128]){const d=magic(Buffer.from('a'.repeat(size))).digest_shape;assert.equal(d.algorithm,'unknown');assert.equal(d.hex_characters,size);}
assert.equal(magic(Buffer.from('a'.repeat(30))).digest_shape,null);
const rust=await readFile(new URL('../apps/origin-trace-backend/src/decoder.rs',import.meta.url),'utf8'),operations=rust.match(/const OPERATIONS: \[&str; (\d+)\] = \[([\s\S]*?)\];/);assert(operations);assert.equal(Number(operations[1]),[...operations[2].matchAll(/"[^"]+"/g)].length);
for(const name of ['apps/research-ui/app.js','apps/research-ui/index.html','apps/research-ui/macos/DecoderService.swift','protocol/openapi.json']){const source=await readFile(new URL('../'+name,import.meta.url),'utf8');for(const op of ['magic-inspect','sha256','sha384','sha512'])assert(source.includes(op),`${name}: ${op}`);}
console.log('PASS actual native Magic/SHA CLI: independent digest vectors at padding/block/1MiB boundaries, binary bytes, ambiguity/false-positive controls, no inflation, unknown digest identity, bounds and capability wiring');

const limits=process.argv.find(arg=>arg.startsWith('--limits='));
if(limits){const result=spawnSync(resolve(limits.slice('--limits='.length)),[],{encoding:'utf8',timeout:5000,maxBuffer:1048576});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');assert.match(result.stdout,/PASS direct Magic\/SHA API/);console.log(result.stdout.trim());}

await checkMagicDecoderUI(run);
