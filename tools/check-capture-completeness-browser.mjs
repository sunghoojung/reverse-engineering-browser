// Owned localhost fixtures only. No public-site URLs are accepted.
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createCaptureFixture} from './capture-completeness-fixture.mjs';
import {
  PassiveReference,
  compareCapture,
  completenessVerdict,
  fixtureOperation,
  compareFixtureBodies,
  captureRunVerdict,
  CaptureIdentityTracker,
} from './capture-completeness-reference.mjs';
import {createStartupTimeline, startCaptureObservers} from './capture-completeness-startup.mjs';
import {createLifecycleObserver} from './capture-completeness-lifecycle.mjs';
import {readBoundedNetlog, crosscheckNetlog} from './capture-completeness-netlog.mjs';
import {stopBrowserTestProcess, waitForClose} from './browser-test-process.mjs';
const root = resolve(process.argv[2] ?? '.'),
  referenceOnly = process.env.REB_REFERENCE_ONLY === '1';
const browser = process.env.ORIGIN_TRACE_TEST_BROWSER || process.env.REB_UI_CHROMIUM || 'chromium';
const binary = resolve(
  process.env.ORIGIN_TRACE_BACKEND ||
    join(root, 'apps/origin-trace-backend/target/debug/origin-trace-backend'),
);
const transport = resolve(
  process.env.ORIGIN_TRACE_DEBUGGER_TRANSPORT || join(root, 'build/reb-debugger-transport'),
);
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(read, label, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try {
      const v = await read();
      if (v) return v;
    } catch {}
    await delay(40);
  }
  throw Error(label);
}
async function cohort(mode) {
  const directory = await mkdtemp(join(tmpdir(), 'reb-independent-')),
    fixture = await createCaptureFixture({runId: mode});
  const children = [];
  const identityTracker = new CaptureIdentityTracker();
  const lifecycle = createLifecycleObserver();
  const startupTimeline = createStartupTimeline();
  let ref,
    browserProcess,
    snapshot,
    version,
    netlog,
    netlogBytes,
    fixtureComplete = false,
    errorCode = null,
    cleanShutdown = false;
  const start = (exe, args) => {
    const child = spawn(exe, args, {cwd: directory}),
      closed = new Promise((r) => child.once('close', r));
    child.on('error', () => {});
    for (const pipe of [child.stdout, child.stderr]) pipe.resume();
    const p = {child, closed};
    children.push(p);
    return p;
  };
  const netlogPath = join(directory, 'netlog.json'),
    netlogLimit = 64 * 1024 * 1024;
  let sizeTimer;
  const deadline = setTimeout(() => {
    errorCode = 'cohort-deadline';
    ref?.ledger.gap('cohort-deadline');
    for (const p of children) p.child.kill('SIGTERM');
  }, 60000);
  try {
    startupTimeline.mark('browserLaunchMs');
    browserProcess = start(browser, [
      '--headless=new',
      '--disable-dev-shm-usage',
      '--site-per-process',
      '--disable-popup-blocking',
      '--disable-background-networking',
      '--no-first-run',
      '--remote-debugging-port=0',
      `--user-data-dir=${directory}/profile`,
      `--log-net-log=${netlogPath}`,
      '--net-log-capture-mode=Default',
      mode === 'startup' ? fixture.entryUrl : 'about:blank',
    ]);
    sizeTimer = setInterval(() => {
      stat(netlogPath)
        .then((s) => {
          if (s.size >= netlogLimit) {
            errorCode = 'netlog-limit';
            browserProcess.child.kill('SIGTERM');
          }
        })
        .catch(() => {});
    }, 100);
    let address;
    const state = async () => {
      const response = await fetch(new URL('/api/debugger', address), {
        signal: AbortSignal.timeout(2000),
      });
      if (!response.ok) throw Error('backend-state');
      const chunks = [];
      let bytes = 0;
      for await (const chunk of response.body) {
        bytes += chunk.length;
        if (bytes > 32 * 1024 * 1024) throw Error('backend-snapshot-limit');
        chunks.push(chunk);
      }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      lifecycle.observe(value);
      if (!identityTracker.observe(value)) {
        // REB can report before the independent socket exists. Keep the failure
        // sticky even when there is not yet a reference ledger to mark.
        errorCode = errorCode ?? 'reb-public-epoch-changed';
        ref?.ledger.gap('reb-public-epoch-changed');
      }
      return value;
    };
    await startCaptureObservers({
      timeline: startupTimeline,
      reference: async () => {
        const lines = await until(async () => {
          if (browserProcess.child.exitCode !== null) throw Error('browser-exited');
          return (await readFile(join(directory, 'profile/DevToolsActivePort'), 'utf8'))
            .trim()
            .split('\n');
        }, 'browser-startup-unavailable');
        startupTimeline.mark('devtoolsDiscoveredMs');
        const socket = new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
        await new Promise((resolveOpen, reject) => {
          const timer = setTimeout(() => {
            socket.close();
            reject(Error('socket-open-timeout'));
          }, 5000);
          socket.addEventListener(
            'open',
            () => {
              clearTimeout(timer);
              resolveOpen();
            },
            {once: true},
          );
          socket.addEventListener(
            'error',
            () => {
              clearTimeout(timer);
              reject(Error('socket-open-failed'));
            },
            {once: true},
          );
        });
        ref = new PassiveReference(socket);
        version = await ref.command('Browser.getVersion');
        if (version.product?.split('/').at(-1) !== process.env.REB_REFERENCE_BROWSER_VERSION)
          errorCode = 'browser-version-pin-missing-or-mismatch';
        await ref.start();
      },
      reb: referenceOnly
        ? null
        : async () => {
            start(binary, [
              '--port',
              '0',
              '--endpoint-file',
              join(directory, 'endpoint'),
              '--devtools-active-port',
              join(directory, 'profile/DevToolsActivePort'),
              '--debugger-transport',
              transport,
              '--capture-network-content',
            ]);
            address = await until(
              async () => (await readFile(join(directory, 'endpoint'), 'utf8')).trim(),
              'backend-startup-unavailable',
            );
            await until(async () => {
              snapshot = await state();
              return identityTracker.baseline !== null;
            }, 'backend-readiness-timeout');
          },
    });
    if (mode === 'prearmed') {
      const {targetInfos} = await ref.command('Target.getTargets');
      const page = targetInfos.find((t) => t.type === 'page' && t.url === 'about:blank');
      const sid = ref.attachments.get(page?.targetId);
      if (!sid) throw Error('page-session-missing');
      startupTimeline.mark('fixtureNavigationMs');
      await ref.command('Page.navigate', {url: fixture.entryUrl}, sid);
    }
    try {
      await fixture.waitForCompletion();
      fixtureComplete = true;
    } catch {
      errorCode = 'fixture-incomplete';
    }
    await ref.ready();
    await delay(250);
    if (!referenceOnly) {
      snapshot = await state();
      const bodyDeadline = Date.now() + 3000;
      while (
        compareFixtureBodies(snapshot.network, fixture.manifest).verdict === 'incomplete' &&
        Date.now() < bodyDeadline
      ) {
        await delay(100);
        snapshot = await state();
      }
    }
    ref.ledger.finalize();
    ref.closed = true;
    await ref.command('Browser.close');
    cleanShutdown = await waitForClose(browserProcess.closed, 5000);
    ref.close();
    if (!cleanShutdown) errorCode = 'browser-shutdown-incomplete';
    ({netlog, byteLength: netlogBytes} = await readBoundedNetlog(netlogPath, netlogLimit));
  } catch (error) {
    errorCode =
      errorCode ??
      ([
        'browser-startup-unavailable',
        'backend-startup-unavailable',
        'backend-readiness-timeout',
        'netlog-limit',
      ].includes(error.message)
        ? error.message
        : 'runner-incomplete');
  } finally {
    clearTimeout(deadline);
    clearInterval(sizeTimer);
    if (ref) ref.close();
    for (const p of children.reverse()) await stopBrowserTestProcess(p);
    await fixture.close();
  }
  const owns = (h) => fixtureOperation(h, fixture.manifest) !== null;
  const reference = ref?.ledger.snapshot() ?? {
    hops: [],
    websockets: [],
    errors: ['unavailable'],
    finalized: false,
  };
  const comparison = referenceOnly
    ? {verdict: 'incomplete', issues: ['reb-not-run']}
    : compareCapture(reference, snapshot?.network, {include: owns});
  // Each declared operation is checked independently of the CDP intersection.
  const operations = fixture.manifest.operations
    .filter((op) => op.kind === 'http')
    .map((op) => {
      const matching = (rows) =>
        rows.filter((h) => fixtureOperation(h, fixture.manifest) === op).length;
      const expected = op.expectedClientCompletions ?? op.expectedReceipts;
      return {
        operationId: op.operationId,
        method: op.method,
        caseId: op.caseId,
        expected,
        receipts: fixture.receipts.filter(
          (r) => r.operationId === op.operationId && r.method === op.method && r.kind === 'http',
        ).length,
        reference: matching(reference.hops),
        reb: referenceOnly ? null : matching(snapshot?.network?.requests ?? []),
        referencePending: reference.hops.filter(
          (h) => fixtureOperation(h, fixture.manifest) === op && h.state === 'pending',
        ).length,
        rebPending: (snapshot?.network?.requests ?? []).filter(
          (h) => fixtureOperation(h, fixture.manifest) === op && h.state === 'pending',
        ).length,
        differences: referenceOnly
          ? {}
          : (compareCapture(reference, snapshot?.network, {
              include: (h) => fixtureOperation(h, fixture.manifest) === op,
            }).mismatchReasons ?? {}),
      };
    });
  const uncovered = operations.some(
    (o) => o.reference !== o.expected || (!referenceOnly && o.reb !== o.expected),
  );
  let netlogResult = {state: 'incomplete', failures: ['netlog-unavailable']};
  if (netlog) {
    netlogResult = crosscheckNetlog(netlog, {
      manifest: fixture.manifest,
      receipts: fixture.receipts,
      referenceHops: reference.hops,
      browserVersion: version?.product?.split('/').at(-1),
      capture: {
        cleanShutdown,
        startedBeforeFixture: true,
        byteLength: netlogBytes,
        limitBytes: netlogLimit,
        limitReached: errorCode === 'netlog-limit',
      },
    });
  }
  const bodyComparison = compareFixtureBodies(snapshot?.network, fixture.manifest);
  const httpVerdict = completenessVerdict({
    errorCode,
    fixtureComplete,
    comparison,
    uncovered,
    netlog: netlogResult,
  });
  const verdict = captureRunVerdict(httpVerdict, bodyComparison);
  await rm(directory, {recursive: true, force: true});
  return {
    mode,
    browserVersion: /^\d+\.\d+\.\d+\.\d+$/.test(version?.product?.split('/').at(-1))
      ? version.product.split('/').at(-1)
      : null,
    scope: 'HTTP request-hop completeness for declared fixture operations',
    verdict,
    httpVerdict,
    bodyComparison,
    headers: {verdict: 'unassessed'},
    errorCode,
    fixtureComplete,
    comparison,
    operations,
    lifecycle: lifecycle.snapshot(),
    readinessTransitions: identityTracker.readinessTransitions,
    startupTimeline: startupTimeline.snapshot(),
    duplicateSessionsRejected: ref?.duplicateSessions ?? 0,
    referenceErrors: reference.errors.filter((code) => /^[a-z-]{1,64}$/.test(code)).slice(0, 32),
    rebCoverage: Object.fromEntries(
      [
        'gaps',
        'target_overflow',
        'cleanup_already_gone',
        'cleanup_failures',
        'failed_targets',
        'unattached_targets_omitted',
        'attached_targets',
        'eligible_targets',
      ].map((key) => [
        key,
        Number.isSafeInteger(snapshot?.network?.capture_status?.[key])
          ? snapshot.network.capture_status[key]
          : null,
      ]),
    ),
    referenceCategories: {
      preflight: reference.hops.filter((h) => owns(h) && h.resourceType === 'Preflight').length,
      failed: reference.hops.filter((h) => owns(h) && h.state === 'failed').length,
      canceled: reference.hops.filter((h) => owns(h) && h.canceled).length,
      diskCache: reference.hops.filter((h) => owns(h) && h.fromDiskCache).length,
      cacheEvent: reference.hops.filter((h) => owns(h) && h.servedFromCache).length,
      serviceWorker: reference.hops.filter((h) => owns(h) && h.fromServiceWorker).length,
    },
    netlog: netlogResult,
    websockets: {
      scope:
        'Separate HTTP-excluded coverage; fixture handshake and echo receipts only, REB WebSocket comparison not implemented.',
      referenceCreated: reference.websockets.filter((h) =>
        owns({...h, url: h.url?.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:')}),
      ).length,
      verdict: 'not-assessed-against-reb',
    },
    limitations: [
      'Fresh owned profile only; no universal losslessness claim.',
      'Passive startup remains in the denominator.',
      'CDP observers share instrumentation blind spots; server and NetLog are separate crosschecks.',
    ],
  };
}
const results = [];
for (const mode of ['startup', 'prearmed']) {
  try {
    results.push(await cohort(mode));
  } catch {
    results.push({mode, verdict: 'incomplete', errorCode: 'cohort-setup-or-cleanup-failed'});
  }
}
console.log(
  JSON.stringify(
    {
      schema: 'reb-capture-completeness-v1',
      rebCommit: /^[a-f0-9]{40}$/.test(
        process.env.GITHUB_SHA ?? process.env.REB_REFERENCE_COMMIT ?? '',
      )
        ? (process.env.GITHUB_SHA ?? process.env.REB_REFERENCE_COMMIT)
        : null,
      results,
    },
    null,
    2,
  ),
);
if (results.some((r) => r.verdict !== 'pass')) process.exitCode = 1;
