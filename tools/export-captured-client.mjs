#!/usr/bin/env node
// Offline only: authored/reviewed saved input becomes data in the existing exporter.
import {constants} from 'node:fs';
import {open, mkdtemp, writeFile, link, rm} from 'node:fs/promises';
import {dirname, join} from 'node:path';
import client from '../apps/research-ui/captured_client.js';
import traffic from '../apps/research-ui/traffic_view.js';

const usage = 'Usage: node tools/export-captured-client.mjs --input request.json --output project.zip [--mode raw|redacted_copy]';
const maxInput = 1048576;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const text = (value, limit, nonempty = false) => typeof value === 'string' && (!nonempty || value.length > 0) && Buffer.byteLength(value) <= limit;
const count = value => Number.isSafeInteger(value) && value >= 0;
const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const invalid = () => { throw new Error('Input must be one complete reb-network-request-v1 response with matching exact identity and valid retained fields.'); };

function selection(document, numbers) {
  if (!exact(document,['format','source','debugger_generation','request']) || document.format !== 'reb-network-request-v1' || !count(document.debugger_generation)) invalid();
  const source = document.source, record = document.request;
  if (!exact(source,['instance_id','capture_epoch','request_id','target_id','started_monotonic_ms']) ||
      !text(source.instance_id,128,true) || !count(source.capture_epoch) || !text(source.request_id,8192,true) ||
      !text(source.target_id,4096,true) || !finite(source.started_monotonic_ms) || !object(record)) invalid();
  for (const path of ['/debugger_generation','/source/capture_epoch','/request/wall_time_ms','/request/encoded_data_length','/request/status']) {
    const token = numbers.get(path);
    if (token !== undefined && !/^-?(0|[1-9][0-9]*)$/.test(token)) invalid();
  }
  // No silent integer rounding in evidence, including unknown future fields.
  // These three fields are explicitly binary64 times in the retained contract.
  const times = new Set(['/source/started_monotonic_ms','/request/started_monotonic_ms','/request/duration_ms']);
  for (const [path,token] of numbers) {
    const value = Number(token);
    if (!Number.isFinite(value) || !times.has(path) && Number.isInteger(value) && !Number.isSafeInteger(value)) invalid();
  }
  for (const [key,limit] of Object.entries({id:8192,protocol_request_id:4096,target_id:4096,target_title:65536,url:65536,method:32,
    resource_type:128,document_url:65536,status_text:512,protocol:128,mime_type:512,error_text:512})) {
    if (!text(record[key],limit,['id','protocol_request_id','target_id'].includes(key))) invalid();
  }
  for (const key of ['url_truncated','method_truncated','document_url_truncated','from_disk_cache','from_service_worker']) if (typeof record[key] !== 'boolean') invalid();
  if (!finite(record.started_monotonic_ms) || !count(record.wall_time_ms) || !count(record.encoded_data_length) ||
      !['pending','complete','failed'].includes(record.state) || !(record.status === null || Number.isSafeInteger(record.status)) ||
      !(record.duration_ms === null || finite(record.duration_ms)) || !object(record.initiator)) invalid();
  if (record.id !== source.request_id || record.target_id !== source.target_id || record.started_monotonic_ms !== source.started_monotonic_ms) invalid();
  for (const side of [record.request,record.response]) {
    if (!exact(side,['headers','headers_truncated','body']) || typeof side.headers_truncated !== 'boolean' || !Array.isArray(side.headers) || side.headers.length > 128) invalid();
    let size = 0;
    for (const pair of side.headers) {
      if (!Array.isArray(pair) || pair.length !== 2 || !text(pair[0],128) || !text(pair[1],8192)) invalid();
      size += Buffer.byteLength(pair[0]) + Buffer.byteLength(pair[1]);
    }
    if (size > 65536) invalid();
    const body = side.body;
    if (!exact(body,['state','mime','text','base64','truncated','reason']) || !['available','empty','missing','loading','error'].includes(body.state) ||
        !text(body.mime,8192) || !text(body.text,131072) || !text(body.base64,174764) || !text(body.reason,512) || typeof body.truncated !== 'boolean') invalid();
  }
  // The source-owned initiator projection remains data; ensure the shared copy
  // policy can inspect its known sites without accepting malformed containers.
  if (Object.hasOwn(record.initiator,'sites') && (!Array.isArray(record.initiator.sites) || record.initiator.sites.some(site => !object(site) || typeof site.source !== 'string'))) invalid();
  return {instance:source.instance_id,epoch:source.capture_epoch,request:source.request_id,target:source.target_id,started:source.started_monotonic_ms};
}

async function readInput(path) {
  let file;
  try {
    // Reject symlinks, pipes and devices; read at most the budget even if a file grows.
    file = await open(path,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maxInput) throw new Error();
    const bytes = Buffer.alloc(maxInput + 1); let length = 0;
    while (length <= maxInput) {
      const {bytesRead} = await file.read(bytes,length,bytes.length-length,null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > maxInput) throw new Error();
    const input = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes.subarray(0,length));
    const numbers = new Map(), document = client.capturedClientJSON(input,numbers);
    return {document,numbers};
  } catch {
    throw new Error('Input must be a readable regular UTF-8 JSON file of at most 1 MiB, without duplicate keys, invalid Unicode or excessive nesting. Symlinks are refused.');
  } finally { await file?.close(); }
}

async function saveArchive(output, bytes) {
  let directory, cleanupPending = false;
  try {
    // A private sibling holds complete bytes first. link() publishes only to a
    // new path, atomically refusing existing files, directories and symlinks.
    directory = await mkdtemp(join(dirname(output),'.reb-client-export-'));
    const temporary = join(directory,'project.zip');
    await writeFile(temporary,bytes,{flag:'wx',mode:0o600});
    await link(temporary,output);
  } catch {
    throw new Error('Could not publish the archive. Choose a new output path in an existing writable directory; existing paths are never replaced.');
  } finally {
    if (directory) {
      try { await rm(directory,{recursive:true,force:true}); }
      catch { cleanupPending = true; }
    }
  }
  return cleanupPending;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log(usage+'\nOffline only. Default mode is raw; raw evidence can contain secrets. Redaction is an explicit best-effort copy. No target requests are sent.'); return;
  }
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index+1];
    if (!['--input','--output','--mode'].includes(name) || Object.hasOwn(options,name) || !value || value.startsWith('--') || value === '-') throw new Error(usage);
    options[name] = value;
  }
  if (!options['--input'] || !options['--output'] || options['--mode'] && !['raw','redacted_copy'].includes(options['--mode'])) throw new Error(usage);
  const mode = options['--mode'] ?? 'raw';
  const {document,numbers} = await readInput(options['--input']);
  const identity = selection(document,numbers);
  const evidence = traffic.trafficCaptureDocument({captureRecord:document.request},'raw');
  evidence.coverage.scope = 'One saved exact-request response; current retention and freshness were not rechecked.';
  // GET /api/network/request contains no window-drop count or configured limits.
  evidence.coverage.dropped = null; evidence.coverage.limits = null;
  evidence.coverage.saved_response = {format:document.format,source:document.source,debugger_generation:document.debugger_generation};
  const source = client.capturedClientSource(identity,evidence);
  const project = client.capturedClientProject(source,mode);
  const cleanupPending = await saveArchive(options['--output'],project.bytes);
  console.log(JSON.stringify({format:'reb-client-export-result-v1',mode,archive_bytes:project.bytes.length,network_requests:0,
    problems:project.provenance.problems,temporary_cleanup_pending:cleanupPending,instruction:'Review the local evidence and configuration before any explicit send or sharing. This saved snapshot does not establish live capture freshness.'}));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
