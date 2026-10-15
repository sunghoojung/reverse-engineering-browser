#!/usr/bin/env node
import {markerPlan,readMarkerFile,saveMarkerFile} from './marker-fuzz.mjs';
const usage='Usage: node tools/prepare-marker-fuzz.mjs --input authored.json [--output reviewed-plan.json]';
async function main(){
  const args=process.argv.slice(2);
  if(args.length===1 && args[0]==='--help'){console.log(usage);return;}
  if(![2,4].includes(args.length)||args[0]!=='--input'||args.length===4&&args[2]!=='--output')throw new Error(usage);
  const plan=markerPlan(await readMarkerFile(args[1]));
  if(args.length===4){await saveMarkerFile(args[3],plan);console.log(JSON.stringify({format:plan.format,plan_sha256:plan.plan_sha256,cases:plan.cases.length,total_request_bytes:plan.total_request_bytes,output:args[3]}));}
  else console.log(JSON.stringify(plan,null,2));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
