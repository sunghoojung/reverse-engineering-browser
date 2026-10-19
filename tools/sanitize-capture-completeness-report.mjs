// CI export is an explicit allowlisted copy. Never upload the source report/log.
import {readFile, stat, writeFile} from 'node:fs/promises';
import {lifecycleErrorCodes, captureReadinessEnums} from './capture-completeness-lifecycle.mjs';
import {startupTimelineKeys, startupTimelineLimitMs} from './capture-completeness-startup.mjs';
import {malformedHopFieldNames} from './capture-completeness-reference.mjs';
import {pathToFileURL} from 'node:url';
const count = (v) => {
  if (!Number.isSafeInteger(v) || v < 0 || v > 10000000) throw Error('invalid-count');
  return v;
};
const choice = (v, values) => {
  if (!values.includes(v)) throw Error('invalid-enum');
  return v;
};
const code = (v) => {
  if (typeof v !== 'string' || !/^[a-z][a-z0-9-]{0,79}$/.test(v)) throw Error('invalid-code');
  return v;
};
const codes = (v) => {
  if (!Array.isArray(v) || v.length > 64) throw Error('invalid-codes');
  return v.map(code);
};
const numbers = (v, keys) =>
  Object.fromEntries(
    keys.filter((k) => v?.[k] !== undefined).map((k) => [k, v[k] === null ? null : count(v[k])]),
  );
function sanitizeMalformedFields(value) {
  return Object.fromEntries(
    ['reference', 'reb'].map((side) => {
      const fields = value?.[side];
      if (!fields || typeof fields !== 'object' || Array.isArray(fields))
        throw Error('invalid-malformed-fields');
      return [
        side,
        Object.fromEntries(
          malformedHopFieldNames.map((name) => {
            const value = fields[name];
            if (!Number.isSafeInteger(value) || value < 0 || value > 10000)
              throw Error('invalid-malformed-fields');
            return [name, value];
          }),
        ),
      ];
    }),
  );
}
function sanitizeLifecycle(value) {
  const result = numbers(value, [
    'samples',
    'invalidSamples',
    'firstEpoch',
    'lastEpoch',
    'setupEpochTransitions',
    'epochChanges',
    'omittedEpochTransitions',
  ]);
  result.maxima = numbers(value.maxima, [
    'gaps',
    'dropped',
    'attached_targets',
    'eligible_targets',
    'failed_targets',
    'target_overflow',
    'cleanup_already_gone',
    'cleanup_failures',
  ]);
  if (
    !Array.isArray(value.epochTransitions) ||
    value.epochTransitions.length > 16 ||
    !Array.isArray(value.errorObservations) ||
    value.errorObservations.length > lifecycleErrorCodes.length
  )
    throw Error('invalid-lifecycle');
  result.epochTransitions = value.epochTransitions.map((item) => {
    if (typeof item.setup !== 'boolean') throw Error('invalid-lifecycle');
    return {from: count(item.from), to: count(item.to), setup: item.setup};
  });
  result.errorObservations = value.errorObservations.map((item) => ({
    code: choice(item.code, lifecycleErrorCodes),
    samples: count(item.samples),
  }));
  return result;
}
export function sanitizeCaptureReport(input) {
  if (
    input?.schema !== 'reb-capture-completeness-v1' ||
    !/^[a-f0-9]{40}$/.test(input.rebCommit) ||
    !Array.isArray(input.results) ||
    input.results.length !== 2
  )
    throw Error('invalid-report');
  const results = input.results.map((r, index) => {
    const mode = choice(r.mode, [index === 0 ? 'startup' : 'prearmed']);
    const result = {
      mode,
      verdict: choice(r.verdict, ['pass', 'fail', 'incomplete']),
      errorCode: r.errorCode === null ? null : code(r.errorCode),
    };
    if (r.browserVersion !== undefined) {
      if (
        r.browserVersion !== null &&
        !/^\d{1,4}\.\d{1,4}\.\d{1,6}\.\d{1,6}$/.test(r.browserVersion)
      )
        throw Error('invalid-version');
      result.browserVersion = r.browserVersion;
    }
    if (r.fixtureComplete !== undefined) {
      if (typeof r.fixtureComplete !== 'boolean') throw Error('invalid-fixture');
      result.fixtureComplete = r.fixtureComplete;
    }
    if (r.comparison) {
      result.comparison = {
        verdict: choice(r.comparison.verdict, ['pass', 'fail', 'incomplete']),
        issues: codes(r.comparison.issues),
        ...numbers(r.comparison, [
          'referenceHops',
          'rebHops',
          'matched',
          'missing',
          'extra',
          'ambiguous',
          'mismatched',
        ]),
      };
    }
    if (r.comparison?.malformedFields !== undefined)
      result.comparison.malformedFields = sanitizeMalformedFields(r.comparison.malformedFields);
    if (r.operations) {
      if (!Array.isArray(r.operations) || r.operations.length > 256)
        throw Error('invalid-operations');
      result.operations = r.operations.map((o) => {
        if (
          typeof o.operationId !== 'string' ||
          !new RegExp(`^${mode}:[a-z0-9-]{1,48}:[a-z0-9-]{1,48}$`).test(o.operationId)
        )
          throw Error('invalid-operation');
        return {
          operationId: o.operationId,
          method: choice(o.method, ['GET', 'POST', 'OPTIONS']),
          ...numbers(o, [
            'expected',
            'receipts',
            'reference',
            'reb',
            'referencePending',
            'rebPending',
          ]),
          ...(o.malformedFields !== undefined
            ? {malformedFields: sanitizeMalformedFields(o.malformedFields)}
            : {}),
          differences: numbers(o.differences, [
            'url',
            'method',
            'status',
            'state',
            'resourceType',
            'fromDiskCache',
            'fromServiceWorker',
          ]),
        };
      });
    }
    if (r.httpVerdict) result.httpVerdict = choice(r.httpVerdict, ['pass', 'fail', 'incomplete']);
    if (r.bodyComparison)
      result.bodyComparison = {
        verdict: choice(r.bodyComparison.verdict, ['pass', 'fail', 'incomplete', 'unassessed']),
        ...numbers(r.bodyComparison, [
          'expectedSamples',
          'checkedSamples',
          'missingSamples',
          'mismatchedSamples',
        ]),
      };
    if (r.headers) result.headers = {verdict: choice(r.headers.verdict, ['unassessed'])};
    Object.assign(result, numbers(r, ['readinessTransitions', 'duplicateSessionsRejected']));
    if (r.startupTimeline) {
      result.startupTimeline = Object.fromEntries(
        startupTimelineKeys.map((key) => {
          const value = r.startupTimeline[key];
          if (
            value !== null &&
            (!Number.isSafeInteger(value) || value < 0 || value > startupTimelineLimitMs)
          )
            throw Error('invalid-startup-timeline');
          return [key, value];
        }),
      );
    }
    if (r.captureReadiness) {
      result.captureReadiness = Object.fromEntries(
        Object.entries(captureReadinessEnums).map(([key, values]) => {
          const value = r.captureReadiness[key];
          return [key, value === null ? null : choice(value, values)];
        }),
      );
    }
    if (r.lifecycle) result.lifecycle = sanitizeLifecycle(r.lifecycle);
    if (r.referenceErrors) result.referenceErrors = codes(r.referenceErrors);
    if (r.rebCoverage)
      result.rebCoverage = numbers(r.rebCoverage, [
        'gaps',
        'target_overflow',
        'cleanup_already_gone',
        'cleanup_failures',
        'failed_targets',
        'unattached_targets_omitted',
        'attached_targets',
        'eligible_targets',
      ]);
    if (r.referenceCategories)
      result.referenceCategories = numbers(r.referenceCategories, [
        'preflight',
        'failed',
        'canceled',
        'diskCache',
        'cacheEvent',
        'serviceWorker',
      ]);
    if (r.netlog) {
      result.netlog = {
        state: choice(r.netlog.state, ['incomplete', 'mismatch', 'corroborated']),
        completenessClaim: false,
        failures: codes(r.netlog.failures),
      };
      if (r.netlog.operations) {
        if (!Array.isArray(r.netlog.operations) || r.netlog.operations.length > 256)
          throw Error('invalid-netlog-operations');
        result.netlog.operations = r.netlog.operations.map((o) => {
          if (
            typeof o.operationId !== 'string' ||
            !new RegExp(`^${mode}:[a-z0-9-]{1,48}:[a-z0-9-]{1,48}$`).test(o.operationId)
          )
            throw Error('invalid-operation');
          return {
            operationId: o.operationId,
            method: choice(o.method, ['GET', 'POST', 'OPTIONS']),
            ...numbers(o, ['wireReceipts', 'referenceHops', 'urlRequestSources', 'jobStarts']),
            issues: codes(o.issues),
          };
        });
      }
    }
    return result;
  });
  return {
    schema: 'reb-capture-completeness-sanitized-v1',
    rebCommit: input.rebCommit,
    completenessClaim: false,
    results,
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [source, destination] = process.argv.slice(2);
    if (!source || !destination || (await stat(source)).size > 1024 * 1024) throw Error();
    const report = sanitizeCaptureReport(JSON.parse(await readFile(source, 'utf8')));
    await writeFile(destination, JSON.stringify(report, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  } catch {
    console.error('Capture report export refused: invalid or unavailable aggregate report.');
    process.exitCode = 1;
  }
}
