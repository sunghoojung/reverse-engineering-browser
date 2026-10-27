#!/usr/bin/env node
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import client from '../apps/research-ui/captured_client.js';
import passive from './passive-security.cjs';
import {captureDocument,saveArchive} from './captured-request-export.mjs';
const usage='Usage: node tools/report-passive-security.mjs --input selected-request.json --output security-report.json';
async function main() {
  const args=process.argv.slice(2);
  if(args.length===1&&args[0]==='--help'){console.log(usage+'\nOffline passive observations from one saved reb-network-request-v1 response. No target requests or secret values in the report.');return;}
  if(args.length!==4||args[0]!=='--input'||args[2]!=='--output'||!args[1]||!args[3])throw Error(usage);
  let file,text,document;const numbers=new Map();
  try {
    file=await open(args[1],constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const info=await file.stat();if(!info.isFile()||info.size>1048576)throw Error();
    const bytes=Buffer.alloc(1048577);let length=0;
    while(length<bytes.length){const {bytesRead}=await file.read(bytes,length,bytes.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    if(length>1048576)throw Error();
    text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes.subarray(0,length));
    document=client.capturedClientJSON(text,numbers);
  } catch {throw Error('Select one regular UTF-8 JSON file up to 1 MiB, without symlinks, duplicate keys or excessive nesting.');}
  finally {await file?.close();}
  let report;
  try {const source=captureDocument(document,numbers);report=await passive.passiveSecurityReport(source.evidence.record,source.identity,text,'saved-exact-request');}
  catch {throw Error('Select a valid bounded reb-network-request-v1 response with matching exact source identity.');}
  const bytes=Buffer.from(JSON.stringify(report,null,2)+'\n');
  const cleanup=await saveArchive(args[3],bytes);
  console.log(JSON.stringify({format:'reb-passive-security-result-v1',source_sha256:report.source.sha256,header_observations:report.headers.length,
    secret_looking_rows:report.secrets.findings.length,coverage_complete:false,bytes:bytes.length,network_requests:0,temporary_cleanup_pending:cleanup}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
