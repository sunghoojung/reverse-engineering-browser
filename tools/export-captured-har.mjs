#!/usr/bin/env node
// One saved exact-request response. No live network, page evaluation or replay.
import {readCapture,saveArchive} from './captured-request-export.mjs';
import {harProject} from './har-project.mjs';
const usage='Usage: node tools/export-captured-har.mjs --input request.json --output request.har [--mode raw|redacted_copy]';
async function main() {
  const args=process.argv.slice(2),options={};
  if(args.length===1 && args[0]==='--help') {console.log(usage+'\nOffline only. Raw exports may contain secrets; redaction is an explicit best-effort copy. Unsupported timing/body evidence is refused.');return;}
  for(let index=0;index<args.length;index+=2) {
    const key=args[index],value=args[index+1];
    if(!['--input','--output','--mode'].includes(key) || Object.hasOwn(options,key) || !value || value.startsWith('--') || value==='-') throw Error(usage);
    options[key]=value;
  }
  if(!options['--input'] || !options['--output']) throw Error(usage);
  const mode=options['--mode']??'raw',source=await readCapture(options['--input']),project=harProject(source,mode);
  const cleanup=await saveArchive(options['--output'],project.bytes);
  console.log(JSON.stringify({format:'reb-har-export-result-v1',mode,entries:1,bytes:project.bytes.length,network_requests:0,temporary_cleanup_pending:cleanup}));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
