#!/usr/bin/env node
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import client from '../apps/research-ui/captured_client.js';
import {saveArchive,captureDocument} from './captured-request-export.mjs';
import {introspectionSDL} from './graphql-sdl.mjs';
const usage='Usage: node tools/export-graphql-sdl.mjs --input introspection.json --output schema.graphql';
async function main() {
  const args=process.argv.slice(2);if(args.length===1&&args[0]==='--help'){console.log(usage+'\nOffline only. Reads a complete saved __schema or data.__schema response; never queries its server.');return;}
  if(args.length!==4||args[0]!=='--input'||args[2]!=='--output'||!args[1]||!args[3])throw Error(usage);
  let file,bytes,document;const numbers=new Map();
  try {
    file=await open(args[1],constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const info=await file.stat();if(!info.isFile()||info.size>1048576)throw Error();
    const data=Buffer.alloc(1048577);let length=0;
    while(length<data.length){const {bytesRead}=await file.read(data,length,data.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    if(length>1048576)throw Error();bytes=data.subarray(0,length);
    document=client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes),numbers);
  } catch {throw Error('Read a regular UTF-8 introspection JSON file up to 1 MiB, without symlinks, duplicate keys or excessive nesting.');}
  finally {await file?.close();}
  let sourceIdentity=null;
  if(document?.format==='reb-network-request-v1') {
    const source=captureDocument(document,numbers),record=source.evidence.record,body=record.response.body;
    if(record.state!=='complete'||record.status!==200||body.state!=='available'||body.truncated||body.text&&body.base64)throw Error('Select a complete retained HTTP 200 introspection JSON response body.');
    let text=body.text;
    if(body.base64){const decoded=Buffer.from(body.base64,'base64');if(decoded.toString('base64')!==body.base64)throw Error('Captured response has invalid base64.');text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(decoded);}
    document=client.capturedClientJSON(text,new Map());sourceIdentity=source.identity;
  }
  const result=introspectionSDL(document),hash=createHash('sha256').update(bytes).digest('hex');
  const output=Buffer.from('# Source SHA-256: '+hash+'\n'+(sourceIdentity?'# Saved REB identity: '+JSON.stringify(sourceIdentity)+'\n':'')+result.text);
  const cleanup=await saveArchive(args[3],output);
  console.log(JSON.stringify({format:'reb-graphql-sdl-result-v1',source_sha256:hash,type_count:result.type_count,directive_count:result.directive_count,bytes:output.length,network_requests:0,temporary_cleanup_pending:cleanup}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
