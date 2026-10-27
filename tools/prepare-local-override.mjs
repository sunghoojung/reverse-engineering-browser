#!/usr/bin/env node
import {readOverrideAsset,overrideAction,saveOverrideAction} from './local-overrides.mjs';
const usage = 'Usage: node tools/prepare-local-override.mjs --file asset.js [--output action.json --url URL --target-id ID --experiment-id INTEGER --sha256 REVIEWED_HASH [--content-type TYPE] [--method GET|HEAD] [--ttl-ms 1000..300000]]';
async function main() {
  const args = process.argv.slice(2), options = {};
  if (args.length === 1 && args[0] === '--help') { console.log(usage); return; }
  for (let i = 0; i < args.length; i += 2) {
    if (!['--file','--output','--url','--target-id','--experiment-id','--sha256','--content-type','--method','--ttl-ms'].includes(args[i]) || Object.hasOwn(options,args[i]) || !args[i+1] || args[i+1].startsWith('--')) throw new Error(usage);
    options[args[i]] = args[i+1];
  }
  if (!options['--file']) throw new Error(usage);
  const asset = await readOverrideAsset(options['--file']);
  if (!options['--output']) {
    if (Object.keys(options).length !== 1) throw new Error(usage);
    console.log(JSON.stringify({format:'reb-local-override-preview-v1',bytes:asset.bytes,sha256:asset.sha256,armed:false,network_requests:0,instruction:'Review this file locally. Offline historical preparation requires its reviewed digest and exact target, experiment and URL. Execution was removed; no content was uploaded.'}));
    return;
  }
  for (const field of ['--experiment-id','--ttl-ms']) if (options[field] !== undefined && !/^[1-9][0-9]*$/.test(options[field])) throw new Error(usage);
  const action = overrideAction(asset,{url:options['--url'],targetId:options['--target-id'],experimentId:Number(options['--experiment-id']),sha256:options['--sha256'],
    ...(options['--content-type'] ? {contentType:options['--content-type']} : {}),...(options['--method'] ? {method:options['--method']} : {}),...(options['--ttl-ms'] ? {ttlMs:Number(options['--ttl-ms'])} : {})});
  const cleanupPending = await saveOverrideAction(options['--output'],action);
  console.log(JSON.stringify({format:'reb-local-override-prepared-v1',armed:false,network_requests:0,expires_at_ms:action.local_override.expires_at_ms,temporary_cleanup_pending:cleanupPending,
    instruction:'Private historical action file prepared offline. Execution was removed; this file cannot arm an override. File content may be sensitive; do not share it.'}));
}
main().catch(error => {console.error(error.message);process.exitCode = 1;});
