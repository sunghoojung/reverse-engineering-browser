#!/usr/bin/env node
import {lstat,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {readMarkerFile,runMarkerPlan,saveMarkerFile} from './marker-fuzz.mjs';
const usage='Usage: node tools/run-marker-fuzz.mjs --plan reviewed-plan.json --arm REVIEWED_SHA256 --base-url http://127.0.0.1:PORT [--report new-report.json]';
async function main(){
  const args=process.argv.slice(2);
  if(args.length===1&&args[0]==='--help'){console.log(usage);return;}
  if(![6,8].includes(args.length)||args[0]!=='--plan'||args[2]!=='--arm'||args[4]!=='--base-url'||args.length===8&&args[6]!=='--report')throw new Error(usage);
  if(args.length===8){
    const output=resolve(args[7]);
    if(await realpath(dirname(output))!==dirname(output))throw new Error('Report output requires an existing directory without symlinks.');
    try{await lstat(output);throw new Error('Report output already exists; choose a new path before arming.');}catch(error){if(error.code!=='ENOENT')throw error;}
  }
  const control=new AbortController(),cancel=()=>control.abort();
  process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
  try{
    const report=await runMarkerPlan(await readMarkerFile(args[1]),{arm:args[3],baseUrl:args[5],signal:control.signal});
    console.log(JSON.stringify(report,null,2));
    if(args.length===8)await saveMarkerFile(args[7],report);
    if(report.state!=='complete')process.exitCode=2;
  }finally{process.off('SIGINT',cancel);process.off('SIGTERM',cancel);}
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
