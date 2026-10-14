// Shared cold-path saved-capture validation and private, no-overwrite publication.
import {constants} from 'node:fs';
import {open, mkdtemp, writeFile, link, rm} from 'node:fs/promises';
import {dirname, join} from 'node:path';
import client from '../apps/research-ui/captured_client.js';
import traffic from '../apps/research-ui/traffic_view.js';

const maxInput = 1048576;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const text = (value, limit, nonempty = false) => typeof value === 'string' && (!nonempty || value.length > 0) && Buffer.byteLength(value) <= limit;
const count = value => Number.isSafeInteger(value) && value >= 0;
const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const invalid = () => { throw new Error('Input must be one complete reb-network-request-v1 response with matching exact identity and valid retained fields.'); };


function timingEvidence(value) {
  const clocks = ['request_monotonic_seconds','request_wall_seconds','response_monotonic_seconds','completion_monotonic_seconds'];
  const flags = ['response_observed','completion_observed','duplicate_response','duplicate_completion','response_after_completion'];
  if (!exact(value,['format',...clocks,...flags,'resource_timing','response_source','completion_source']) || value.format !== 'reb-network-timing-v1' ||
      !flags.every(key => typeof value[key] === 'boolean') || !['none','redirectResponse','responseReceived'].includes(value.response_source) ||
      !['none','redirectRequest','loadingFailed','loadingFinished'].includes(value.completion_source)) invalid();
  const measurement = (item,offset = false) => exact(item,['state','value']) && item.state === 'available' && finite(item.value) && item.value <= 8640000000000 ||
    exact(item,['state']) && (offset ? ['missing','invalid','unavailable'] : ['missing','invalid']).includes(item.state);
  if (!clocks.every(key => measurement(value[key]))) invalid();
  const resource = value.resource_timing;
  if (exact(resource,['state']) && ['missing','invalid'].includes(resource.state)) return;
  const fields = ['requestTime','proxyStart','proxyEnd','dnsStart','dnsEnd','connectStart','connectEnd','sslStart','sslEnd','sendStart','sendEnd','receiveHeadersStart','receiveHeadersEnd','workerStart'];
  if (!exact(resource,['state','fields']) || resource.state !== 'available' || !exact(resource.fields,fields) ||
      !fields.every(key => measurement(resource.fields[key],key !== 'requestTime'))) invalid();
}

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
  if (Object.hasOwn(record,'timing_evidence')) timingEvidence(record.timing_evidence);
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

export async function saveArchive(output, bytes) {
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

export function captureDocument(document,numbers) {
  const identity = selection(document,numbers);
  const evidence = traffic.trafficCaptureDocument({captureRecord:document.request},'raw');
  evidence.coverage.scope = 'One saved exact-request response; current retention and freshness were not rechecked.';
  // GET /api/network/request contains no window-drop count or configured limits.
  evidence.coverage.dropped = null; evidence.coverage.limits = null;
  evidence.coverage.saved_response = {format:document.format,source:document.source,debugger_generation:document.debugger_generation};
  const source = client.capturedClientSource(identity,evidence);
  return source;
}

export async function readCapture(path) {
  const {document,numbers} = await readInput(path);
  return captureDocument(document,numbers);
}
