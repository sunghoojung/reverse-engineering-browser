#!/usr/bin/env node
// Offline only: authored/reviewed saved input becomes data in the existing exporter.
import client from '../apps/research-ui/captured_client.js';
import {readCapture,saveArchive} from './captured-request-export.mjs';
import {pythonProject} from './python-client-project.mjs';

const usage = 'Usage: node tools/export-captured-client.mjs --input request.json --output project.zip [--mode raw|redacted_copy] [--python-client requests|httpx]';
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log(usage+'\nOffline only. Default mode is raw; raw evidence can contain secrets. Redaction is an explicit best-effort copy. No target requests are sent.'); return;
  }
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index+1];
    if (!['--input','--output','--mode','--python-client'].includes(name) || Object.hasOwn(options,name) || !value || value.startsWith('--') || value === '-') throw new Error(usage);
    options[name] = value;
  }
  if (options['--python-client'] && !['requests','httpx'].includes(options['--python-client'])) throw new Error(usage);
  if (!options['--input'] || !options['--output'] || options['--mode'] && !['raw','redacted_copy'].includes(options['--mode'])) throw new Error(usage);
  const mode = options['--mode'] ?? 'raw';
  const source = await readCapture(options['--input']);
  const project = options['--python-client'] ? await pythonProject(source,mode,options['--python-client']) : client.capturedClientProject(source,mode);
  const cleanupPending = await saveArchive(options['--output'],project.bytes);
  console.log(JSON.stringify({format:'reb-client-export-result-v1',mode,archive_bytes:project.bytes.length,network_requests:0,...(options['--python-client'] ? {python_client:options['--python-client']} : {}),
    problems:project.provenance.problems,temporary_cleanup_pending:cleanupPending,instruction:'Review the local evidence and configuration before any explicit send or sharing. This saved snapshot does not establish live capture freshness.'}));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
