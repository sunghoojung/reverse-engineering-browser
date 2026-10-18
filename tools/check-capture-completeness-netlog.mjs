import assert from 'node:assert/strict';
import {mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  crosscheckNetlog,
  readBoundedNetlog,
  NetlogInputError,
} from './capture-completeness-netlog.mjs';

const origin = 'http://127.0.0.1:8123',
  runId = 'synthetic-run',
  browserVersion = '151.0.7922.108';
const op = (operationId, expectedReceipts = 1) => ({
  operationId: `${runId}:case:${operationId}`,
  caseId: 'case',
  path: `/reb-fixture/${runId}/case/${operationId}`,
  method: 'GET',
  expectedReceipts,
});
const url = (operationId) => `${origin}${op(operationId).path}?op=${runId}:case:${operationId}`;
const event = (operationId, id = 1) => ({
  type: 911,
  phase: 7,
  source: {type: 42, id},
  params: {url: url(operationId), method: 'GET', headers: 'PRIVATE_DO_NOT_OUTPUT'},
});
const log = (events) => ({
  constants: {
    logFormatVersion: 1,
    clientInfo: {version: browserVersion, command_line: 'PRIVATE_DO_NOT_OUTPUT'},
    logEventTypes: {URL_REQUEST_START_JOB: 911, OTHER: 912},
    logSourceType: {URL_REQUEST: 42, OTHER: 43},
    logEventPhase: {PHASE_BEGIN: 7, PHASE_END: 8, PHASE_NONE: 9},
  },
  events,
});
const options = (operations = [op('one')]) => ({
  manifest: {runId, origins: [origin], operations},
  receipts: operations.flatMap((o) =>
    Array.from({length: o.expectedReceipts}, () => ({
      operationId: o.operationId,
      method: 'GET',
      url: url(o.operationId.split(':').at(-1)),
    })),
  ),
  referenceHops: operations.map((o) => ({
    url: url(o.operationId.split(':').at(-1)),
    method: 'GET',
  })),
  browserVersion,
  capture: {
    cleanShutdown: true,
    startedBeforeFixture: true,
    limitReached: false,
    byteLength: 1000,
    limitBytes: 100000,
  },
});
let result = crosscheckNetlog(log([event('one')]), options());
assert.equal(result.state, 'corroborated');
assert.equal(result.completenessClaim, false);
assert(!JSON.stringify(result).includes(origin));
assert(!JSON.stringify(result).includes('PRIVATE_DO_NOT_OUTPUT'));
// Upstream serializes IDs as signed int32, including cross-process partition IDs.
for (const id of [-2147483648, -2147483647, -1, 1, 2147483647]) {
  const supported = crosscheckNetlog(log([event('one', id)]), options());
  assert.equal(supported.state, 'corroborated');
  assert.equal(supported.operations[0].urlRequestSources, 1);
}
const partitions = crosscheckNetlog(log([event('one', -1), event('one', 1)]), options());
assert.equal(partitions.operations[0].urlRequestSources, 2);
for (const id of [-2147483649, 2147483648, 4294967295, 1.5, '1', null]) {
  const refused = crosscheckNetlog(log([event('one', id)]), options());
  assert.equal(refused.state, 'incomplete');
  assert.deepEqual(refused.failures, ['event-source-id-not-signed-int32']);
}
assert.equal(crosscheckNetlog(log([event('one', 0)]), options()).state, 'incomplete');
for (const [change, failure] of [
  [
    (n) => {
      n.events[0] = null;
    },
    'event-not-object',
  ],
  [
    (n) => {
      delete n.events[0].type;
    },
    'event-type-not-nonnegative-integer',
  ],
  [
    (n) => {
      n.events[0].type = 999;
    },
    'event-type-absent-from-constants',
  ],
  [
    (n) => {
      n.events[0].phase = 'PRIVATE_DO_NOT_OUTPUT';
    },
    'event-phase-not-nonnegative-integer',
  ],
  [
    (n) => {
      n.events[0].phase = 999;
    },
    'event-phase-absent-from-constants',
  ],
  [
    (n) => {
      delete n.events[0].source;
    },
    'event-source-not-object',
  ],
  [
    (n) => {
      n.events[0].source.type = 'PRIVATE_DO_NOT_OUTPUT';
    },
    'event-source-type-not-nonnegative-integer',
  ],
  [
    (n) => {
      n.events[0].source.type = 999;
    },
    'event-source-type-absent-from-constants',
  ],
  [
    (n) => {
      delete n.events[0].source.id;
    },
    'event-source-id-not-signed-int32',
  ],
]) {
  const malformed = log([event('one')]);
  change(malformed);
  const refused = crosscheckNetlog(malformed, options());
  assert.equal(refused.state, 'incomplete');
  assert.deepEqual(refused.failures, [failure]);
  assert(!JSON.stringify(refused).includes('PRIVATE_DO_NOT_OUTPUT'));
}
// Repeated requests: distinct sources; retries/interception: repeated starts.
result = crosscheckNetlog(
  log([event('one'), event('one'), event('one', 2)]),
  options([op('one', 2)]),
);
assert.equal(result.state, 'corroborated');
assert.equal(result.operations[0].urlRequestSources, 2);
assert.equal(result.operations[0].jobStarts, 3);
// Redirect hops can share a source without being collapsed to one operation.
result = crosscheckNetlog(
  log([event('hop-0'), event('hop-1')]),
  options([op('hop-0'), op('hop-1')]),
);
assert.equal(result.operations.length, 2);
assert.equal(result.state, 'corroborated');
assert.equal(crosscheckNetlog(log([]), options()).state, 'mismatch');
assert.equal(crosscheckNetlog(log([]), options([op('cache', 0)])).state, 'corroborated');
const background = event('one');
background.params.url = 'https://public.invalid/secret?op=synthetic-run:case:one';
result = crosscheckNetlog(log([background]), options());
assert.equal(result.state, 'mismatch');
assert.equal(result.ignoredEvents, 1);
const duplicate = event('one');
duplicate.params.url += '&op=synthetic-run:case:one';
assert.equal(crosscheckNetlog(log([duplicate]), options()).state, 'mismatch');
for (const change of [
  (n) => {
    n.constants.logFormatVersion = 2;
  },
  (n) => {
    n.constants.clientInfo.version = '1.2.3.4';
  },
  (n) => {
    delete n.constants.logEventTypes.URL_REQUEST_START_JOB;
  },
  (n) => {
    n.constants.logEventPhase.PHASE_NONE = 7;
  },
  (n) => {
    n.events[0].type = 999;
  },
  (n) => {
    n.events[0].source.id = -2147483649;
  },
  (n) => {
    delete n.events[0].params;
  },
  (n) => {
    n.events[0].source.type = 43;
  },
]) {
  const n = log([event('one')]);
  change(n);
  assert.equal(crosscheckNetlog(n, options()).state, 'incomplete');
}
for (const change of [
  (o) => {
    o.capture.cleanShutdown = false;
  },
  (o) => {
    o.capture.startedBeforeFixture = false;
  },
  (o) => {
    o.capture.limitReached = true;
  },
  (o) => {
    o.capture.byteLength = o.capture.limitBytes;
  },
  (o) => {
    delete o.browserVersion;
  },
  (o) => {
    o.manifest.origins = ['https://public.invalid'];
  },
  (o) => {
    o.manifest.operations[0].operationId = 'secret:invalid';
  },
  (o) => {
    o.receipts[0].url = 'https://public.invalid/secret';
  },
]) {
  const o = options();
  change(o);
  assert.equal(crosscheckNetlog(log([event('one')]), o).state, 'incomplete');
}
const socketOptions = options([{...op('socket'), kind: 'websocket-handshake'}]);
socketOptions.referenceHops = [];
assert.equal(crosscheckNetlog(log([event('socket')]), socketOptions).state, 'corroborated');
const noReference = options();
noReference.referenceHops = [];
assert.equal(crosscheckNetlog(log([event('one')]), noReference).state, 'mismatch');
const end = event('one');
end.phase = 8;
delete end.params;
assert.equal(crosscheckNetlog(log([event('one'), end]), options()).operations[0].jobStarts, 1);
const preflight = options([
  {...op('cors'), method: 'OPTIONS'},
  {...op('cors'), method: 'POST'},
]);
preflight.receipts.forEach((r, i) => (r.method = i ? 'POST' : 'OPTIONS'));
preflight.referenceHops.forEach((r, i) => (r.method = i ? 'POST' : 'OPTIONS'));
const preflightEvents = [event('cors'), event('cors', 2)];
preflightEvents.forEach((e, i) => (e.params.method = i ? 'POST' : 'OPTIONS'));
const preflightResult = crosscheckNetlog(log(preflightEvents), preflight);
assert.equal(preflightResult.state, 'corroborated');
assert.deepEqual(
  preflightResult.operations.map((o) => o.jobStarts),
  [1, 1],
);
assert.equal(crosscheckNetlog(log(preflightEvents.slice(1)), preflight).state, 'mismatch');
const directory = await mkdtemp(join(tmpdir(), 'reb-netlog-test-'));
try {
  const path = join(directory, 'log.json');
  await writeFile(path, JSON.stringify(log([event('one')])));
  assert.equal((await readBoundedNetlog(path)).netlog.constants.logFormatVersion, 1);
  await assert.rejects(
    readBoundedNetlog(path, 10),
    (e) => e instanceof NetlogInputError && e.code === 'netlog-size-bound',
  );
  await writeFile(path, '{"events":[PRIVATE_DO_NOT_OUTPUT');
  await assert.rejects(
    readBoundedNetlog(path),
    (e) =>
      e.code === 'netlog-truncated-or-invalid-json' && !String(e).includes('PRIVATE_DO_NOT_OUTPUT'),
  );
  await writeFile(path, Buffer.from([255]));
  await assert.rejects(readBoundedNetlog(path), NetlogInputError);
  await assert.rejects(
    readBoundedNetlog(join(directory, 'missing')),
    (e) => e.code === 'netlog-read-failed',
  );
} finally {
  await rm(directory, {recursive: true, force: true});
}
console.log(
  'PASS NetLog diagnostic: constants, owned operation scope, redirects/retries, privacy, bounds, truncated/unsupported refusal',
);
