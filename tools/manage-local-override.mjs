#!/usr/bin/env node
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import client from '../apps/research-ui/captured_client.js';
import {applyOverride} from './local-overrides.mjs';
const usage = 'Usage: node tools/manage-local-override.mjs --arm|--disarm action.json --base-url http://127.0.0.1:PORT';
async function main() {
  const args=process.argv.slice(2);
  if(args.length===1 && args[0]==='--help'){console.log(usage);return;}
  if(args.length!==4 || !['--arm','--disarm'].includes(args[0]) || args[2]!=='--base-url')throw new Error(usage);
  let file, action;
  try {
    const path=resolve(args[1]);if(await realpath(dirname(path))!==dirname(path))throw new Error();
    file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const before=await file.stat({bigint:true});if(!before.isFile()||before.size>524288n)throw new Error();
    const bytes=Buffer.alloc(524289);let length=0;
    while(length<bytes.length){const {bytesRead}=await file.read(bytes,length,bytes.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    const after=await file.stat({bigint:true});
    if(length>524288 || BigInt(length)!==before.size || before.size!==after.size || before.mtimeNs!==after.mtimeNs || before.ctimeNs!==after.ctimeNs)throw new Error();
    action=client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,length)),new Map());
  } catch {throw new Error('Read a bounded regular prepared action file without symlinks, malformed UTF-8 or duplicate JSON keys.');}
  finally {await file?.close();}
  console.log(JSON.stringify(await applyOverride(args[3],action,{disarm:args[0]==='--disarm'})));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
