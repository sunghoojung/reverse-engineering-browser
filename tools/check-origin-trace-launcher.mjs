import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, readFile, access } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const root = resolve(process.argv[2] ?? ".");
const temporary = await mkdtemp(join(tmpdir(), "origin-trace-launcher-"));
const contents = join(root, "build/Origin Trace.app/Contents");
const browser =
  process.env.ORIGIN_TRACE_TEST_BROWSER ??
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const wrapper = join(temporary, "brave");
// The wrapper accepts only a quoted, explicit local executable path.
await writeFile(
  wrapper,
  `#!/bin/sh\nexec '${browser.replaceAll("'", "'\\''")}' --headless=new --disable-gpu "$@"\n`,
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
console.log(JSON.stringify({ temporary }));
