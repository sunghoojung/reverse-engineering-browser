import {runPackagedSmoke} from "./check-origin-trace-package.mjs";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, access, mkdir, cp, rename, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

if (process.argv.includes("--cleanup-only")) {
  await checkLiveSessionCleanup();
  process.exit(0);
}

const root = resolve(process.argv[2] ?? ".");
const temporary = await mkdtemp(join(tmpdir(), "origin-trace-launcher-"));
const app = resolve(process.argv[3] ?? join(root, "build/Origin Trace.app"));
const contents = join(app, "Contents");
const browser =
  process.env.ORIGIN_TRACE_TEST_BROWSER ??
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const wrapper = join(temporary, "brave");
const browserPid = join(temporary, "brave.pid");
// The wrapper accepts only a quoted, explicit local executable path.
await writeFile(
  wrapper,
  `#!/bin/sh\nprintf '%s\\n' "$$" > '${browserPid.replaceAll("'", "'\\''")}'\nexec '${browser.replaceAll("'", "'\\''")}' --headless=new --disable-gpu "$@"\n`,
  { mode: 0o700 },
);
const handshake = join(temporary, "handshake");
const environment = {
  ...process.env,
  REB_EMBEDDED_SESSION: "1",
  REB_SESSION_OWNER_PID: String(process.pid),
  REB_SESSION_HANDSHAKE: handshake,
  REB_LIVE_SESSION_ROOT: join(temporary, "sessions"),
  REB_BRAVE_BINARY: wrapper,
  REB_USE_SYSTEM_KEYCHAIN: "0",
  REB_API_COLLECTION_STORE: join(temporary, "collection.json"),
  REB_LOCAL_ANALYST_STORE: join(temporary, "analyst.json"),
  REB_ACTIVE_ENDPOINT_FILE: join(temporary, "active.endpoint"),
};
for (const [key, name] of Object.entries({
  REB_BROKER_BINARY: "OriginTraceEventBroker",
  REB_ARTIFACT_RECEIVER_BINARY: "OriginTraceArtifactReceiver",
  REB_DEBUGGER_TRANSPORT_BINARY: "OriginTraceDebuggerTransport",
  REB_HEAP_SNAPSHOT_BINARY: "OriginTraceHeapSnapshot",
  REB_DECODER_BINARY: "OriginTraceDecoder",
  REB_ORIGIN_TRACE_BACKEND: "OriginTraceBackend",
  REB_VM_ANALYZER: "OriginTraceVMAnalyzer",
  REB_DEOBFUSCATOR_WORKER: "OriginTraceDeobfuscator",
}))
  environment[key] = join(contents, "MacOS", name);
const child = spawn(join(contents, "Resources/run-live-session.sh"), [], {
  cwd: temporary,
  env: environment,
  detached: true,
});
const exited = new Promise((resolveExit, reject) => {
  child.once("exit", resolveExit);
  child.once("error", reject);
});
let diagnostics = "";
for (const pipe of [child.stdout, child.stderr]) {
  pipe.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk).slice(-16384);
  });
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let endpoint;
try {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      endpoint = (await readFile(handshake, "utf8")).trim();
      break;
    } catch {}
    assert.equal(child.exitCode, null, diagnostics);
    await wait(50);
  }
  assert(endpoint, "Launcher did not publish its endpoint: " + diagnostics);
  const health = await (
    await fetch(new URL("/api/health", endpoint), {
      signal: AbortSignal.timeout(3000),
    })
  ).json();
  assert.equal(health.capture_mode, "live");
  let state;
  for (let i = 0; i < 200; i++) {
    state = await (
      await fetch(new URL("/api/debugger", endpoint), {
        signal: AbortSignal.timeout(3000),
      })
    ).json();
    if (state.state === "running") break;
    await wait(50);
  }
  assert.equal(state.state, "running");
  console.log(
    "PASS packaged launcher starts a disposable live browser session",
  );
  if (process.env.REB_CHECK_PACKAGED_APP_UI === "1") {
    // Prove the running backend reads the relocated subtree, even while the
    // compiler's development source directory still exists. Restore before
    // starting the signed native app.
    const css = join(contents, "Resources/research-ui/app.css");
    const cssURL = new URL("/app.css", endpoint);
    const cssResponse = await fetch(cssURL);
    assert.equal(cssResponse.status, 200);
    assert.deepEqual(Buffer.from(await cssResponse.arrayBuffer()), await readFile(css));
    await rename(css, `${css}.package-check`);
    try {
      assert.equal((await fetch(cssURL)).status, 404, "Backend silently fell back to source-tree CSS");
    } finally {
      await rename(`${css}.package-check`, css);
    }
    execFileSync("codesign", ["--verify", "--deep", "--strict", app], {cwd: temporary});
    try {
      const {result} = await runPackagedSmoke(app, temporary, "live", ["--ui-url", endpoint]);
      assert.equal(new URL(result.location).protocol, "http:");
      assert.equal(result.captureMode, "live");
    } finally {
      const reports = join(root, "build/package-qa");
      await mkdir(reports, {recursive: true});
      await cp(join(temporary, "live.log"), join(reports, "live.log"));
    }
  }
} finally {
  child.kill("SIGTERM");
  let timer;
  try {
    await Promise.race([
      exited,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Launcher survived shutdown")),
          8000,
        );
      }),
    ]);
  } catch (error) {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {}
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
await assert.rejects(access(handshake));
await assert.rejects(
  fetch(new URL("/api/health", endpoint), {
    signal: AbortSignal.timeout(1000),
  }),
);
console.log(
  "PASS launcher exits, removes its handshake, and stops the backend",
);

// Reproduce a browser exit after readiness through the actual packaged launcher.
// Only the PID recorded by our disposable wrapper is terminated.
await writeFile(browserPid, "");
const interrupted = spawn(join(contents, "Resources/run-live-session.sh"), [], {
  cwd: temporary,
  env: environment,
  detached: true,
});
let interruptionDiagnostics = "";
for (const pipe of [interrupted.stdout, interrupted.stderr]) {
  pipe.on("data", chunk => {
    interruptionDiagnostics = (interruptionDiagnostics + chunk).slice(-16384);
  });
}
const interruptionExit = new Promise((resolveExit, reject) => {
  interrupted.once("exit", resolveExit);
  interrupted.once("error", reject);
});
let interruptionTimer;
let interruptedBrowserPid;
const processState = pid => {
  if (!pid) return "unknown";
  try {
    process.kill(pid, 0);
    return "alive";
  } catch (error) {
    return error.code === "ESRCH" ? "exited" : `unknown (${error.code})`;
  }
};
try {
  let interruptionEndpoint;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      interruptionEndpoint = (await readFile(handshake, "utf8")).trim();
      if (interruptionEndpoint) break;
    } catch {}
    assert.equal(interrupted.exitCode, null, interruptionDiagnostics);
    await wait(50);
  }
  assert(interruptionEndpoint, "Second launcher did not become ready: " + interruptionDiagnostics);
  const pid = Number((await readFile(browserPid, "utf8")).trim());
  assert(Number.isSafeInteger(pid) && pid > 0, "Disposable browser PID missing");
  interruptedBrowserPid = pid;
  process.kill(pid, "SIGTERM");
  const code = await Promise.race([
    interruptionExit,
    new Promise((_, reject) => {
      interruptionTimer = setTimeout(() => reject(new Error(
        `Browser shutdown left the live coordinator running: browser ${pid} ${processState(pid)}; ` +
        `coordinator ${interrupted.pid} ${processState(interrupted.pid)}\n${interruptionDiagnostics}`,
      )), 8000);
    }),
  ]);
  assert.equal(code, 1, interruptionDiagnostics);
  assert.match(interruptionDiagnostics, /Brave stopped; the live capture connection has closed/);
  await assert.rejects(access(handshake));
  await assert.rejects(fetch(new URL("/api/health", interruptionEndpoint), {signal: AbortSignal.timeout(1000)}));
  console.log("PASS browser exit after readiness reports failure and tears down its live session");
} finally {
  clearTimeout(interruptionTimer);
  const state = `browser ${interruptedBrowserPid ?? "unknown"} ${processState(interruptedBrowserPid)}; ` +
    `coordinator ${interrupted.pid} ${processState(interrupted.pid)}; exit ${interrupted.exitCode}; signal ${interrupted.signalCode}`;
  if (interrupted.exitCode === null) {
    try { process.kill(-interrupted.pid, "SIGKILL"); } catch {}
  }
  // Only this disposable fixture's bounded coordinator output is retained.
  // Never copy browser logs or captured session content into the CI report.
  const reports = join(root, "build/package-qa");
  await mkdir(reports, {recursive: true});
  await writeFile(join(reports, "launcher-interruption.log"), `${state}\n${interruptionDiagnostics}`);
}
console.log(JSON.stringify({ temporary }));

async function checkLiveSessionCleanup() {
  // Exercise the exact coordinator teardown and analyzer loop without sockets,
  // a browser, or a native bundle. Packaged acceptance above remains separate.
  const source = await readFile(new URL("../scripts/run-live-session.sh", import.meta.url), "utf8");
  const section = (start, end) => {
    const from = source.indexOf(start);
    const to = end === null ? source.length : source.indexOf(end, from + start.length);
    assert(from >= 0 && to > from, `Missing live launcher fixture boundary: ${start}`);
    return source.slice(from, to);
  };
  const failure = section('fail_live_session() {', '\nscript_dir=');
  const cleanup = section('broker_pid=""', '"${broker_binary}" --store');
  const analyzer = section('analyzer_log=', 'ui_arguments=(');
  const monitor = section('if [[ "${embedded_session}" == 1 ]]; then\n  while kill', null);
  const quote = value => `'${value.replaceAll("'", "'\\''")}'`;
  const temporary = await mkdtemp(join(tmpdir(), "origin-trace-cleanup-"));
  const helper = join(temporary, "helper.cjs");
  const worker = join(temporary, "analyzer");
  await writeFile(helper, `
const {writeFileSync} = require("node:fs");
const {join} = require("node:path");
const role = process.argv[2];
const root = process.env.REB_CLEANUP_TEST_ROOT;
process.on("SIGTERM", () => {
  writeFileSync(join(root, role + ".term"), String(Date.now()));
  if (!process.env.REB_CLEANUP_TEST_STUBBORN.split(",").includes(role)) process.exit(0);
});
writeFileSync(join(root, role + ".pid"), String(process.pid));
setInterval(() => {}, 1000);
`);
  await writeFile(worker, `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(helper)} analyzer\n`, {mode: 0o700});
  const pause = ms => new Promise(resolvePause => setTimeout(resolvePause, ms));
  const alive = pid => {
    try { process.kill(pid, 0); return true; }
    catch (error) { if (error.code === "ESRCH") return false; throw error; }
  };
  for (const scenario of [
    {name: "responsive-browser-exit", stubborn: [], signal: "browser", code: 1},
    {name: "shared-grace-and-analyzer-worker", stubborn: ["broker", "ui", "analyzer"], signal: "browser", code: 1},
    {name: "coordinator-cancellation", stubborn: [], signal: "coordinator", code: 143},
  ]) {
    const directory = join(temporary, scenario.name);
    await mkdir(directory);
    const handshake = join(directory, "handshake");
    const launch = role => `${quote(process.execPath)} ${quote(helper)} ${role}`;
    const script = join(directory, "coordinator.sh");
    await writeFile(script, `#!/bin/bash
set -euo pipefail
session_directory=${quote(directory)}
artifact_store_path=${quote(directory)}
store_path=${quote(join(directory, "events"))}
socket_path=${quote(join(directory, "socket"))}
artifact_socket_path=${quote(join(directory, "artifact-socket"))}
session_handshake=${quote(handshake)}
embedded_session=1
session_owner_pid=${process.pid}
brave_log=${quote(join(directory, "brave.log"))}
vm_analyzer=${quote(worker)}
${failure}
${cleanup}
${launch("broker")} & broker_pid=$!
${launch("receiver")} & artifact_receiver_pid=$!
${analyzer}
${launch("ui")} & ui_pid=$!
${launch("browser")} & brave_pid=$!
printf '%s\\n' "\${analyzer_pid}" > ${quote(join(directory, "analyzer-shell.pid"))}
touch "\${session_handshake}"
${monitor}`);
    const child = spawn("bash", [script], {
      detached: true,
      env: {...process.env, REB_CLEANUP_TEST_ROOT: directory, REB_CLEANUP_TEST_STUBBORN: scenario.stubborn.join(",")},
    });
    let output = "";
    for (const pipe of [child.stdout, child.stderr]) pipe.on("data", chunk => { output = (output + chunk).slice(-16384); });
    const exit = new Promise((resolveExit, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveExit({code, signal}));
    });
    let timer;
    try {
      const pids = {};
      const deadline = Date.now() + 10000;
      while (true) {
        try {
          await access(handshake);
          for (const role of ["broker", "receiver", "ui", "browser", "analyzer", "analyzer-shell"]) {
            const pid = Number((await readFile(join(directory, `${role}.pid`), "utf8")).trim());
            assert(Number.isSafeInteger(pid) && pid > 0);
            pids[role] = pid;
          }
          break;
        } catch (error) {
          assert(child.exitCode === null && Date.now() < deadline, `${scenario.name} startup failed: ${error}\n${output}`);
          await pause(20);
        }
      }
      const started = Date.now();
      process.kill(scenario.signal === "browser" ? pids.browser : child.pid, "SIGTERM");
      const result = await Promise.race([
        exit,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${scenario.name} survived 8-second shutdown bound\n${output}`)), 8000); }),
      ]);
      const elapsed = Date.now() - started;
      assert.equal(result.code, scenario.code, output);
      assert.equal(result.signal, null, output);
      assert.match(output, /Live session cleanup started:/);
      assert.match(output, /Live session cleanup complete\./);
      const markedFailures = output.split("\n").filter(line => line.startsWith("REB_LIVE_SESSION_FAILURE: "));
      if (scenario.signal === "browser") {
        assert.deepEqual(markedFailures, [`REB_LIVE_SESSION_FAILURE: Brave stopped; the live capture connection has closed. See: ${join(directory, "brave.log")}`]);
        assert(output.indexOf(markedFailures[0]) < output.indexOf("Live session cleanup started:"),
          "The actionable cause must be recorded before teardown diagnostics");
      } else {
        assert.deepEqual(markedFailures, [], "Cancellation must not invent a diagnosed failure");
      }
      await assert.rejects(access(handshake));
      for (const [role, pid] of Object.entries(pids)) assert.equal(alive(pid), false, `${scenario.name} orphaned ${role} ${pid}\n${output}`);
      if (scenario.stubborn.length) {
        for (const role of scenario.stubborn) assert.match(output, new RegExp(`forcing owned child ${pids[role]} to stop`));
        const times = await Promise.all(["broker", "receiver", "ui", "analyzer"].map(async role => Number(await readFile(join(directory, `${role}.term`), "utf8"))));
        assert(Math.max(...times) - Math.min(...times) < 1500, `Helpers were not signaled together: ${times}`);
      }
      console.log(`PASS live cleanup ${scenario.name}: ${elapsed}ms, all owned children reaped`);
    } finally {
      clearTimeout(timer);
      try { process.kill(-child.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; }
    }
  }
  await rm(temporary, {recursive: true, force: true});
}
