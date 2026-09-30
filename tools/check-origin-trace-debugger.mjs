import { spawn } from "node:child_process";
import { runInNewContext } from "node:vm";
import {
  readFile,
  mkdtemp,
  mkdir,
  writeFile,
  appendFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import assert from "node:assert/strict";
const root = process.argv[2] || new URL("..", import.meta.url).pathname;
const temporary = await mkdtemp(join(tmpdir(), "origin-trace-debugger-"));
const resources = [];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const ui = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
    ";({isDebuggerResponse,isRequestInterception,isActionScope,isObjectExperiment,isRuntimeHooks,isAutomationRecipes,isRepeater})",
  { TextEncoder, URL },
);
const fixture = createServer((req, res) => {
  if (process.env.ORIGIN_TRACE_FIXTURE_LOG)
    console.log("FIXTURE", req.method, req.url);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.url === "/slow") {
    setTimeout(() => {
      if (!res.destroyed) {
        res.writeHead(200);
        res.end("slow");
      }
    }, 5000);
    return;
  }
  if (req.url === "/worker.js") {
    res.setHeader("Content-Type", "text/javascript");
    res.end(
      'function workerPayload(input){\nconst out=input+"-worker";\nreturn out;\n}\nself.onmessage=e=>fetch("/echo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:workerPayload(e.data)})});',
    );
    return;
  }
  if (req.url === "/page") {
    res.setHeader("Content-Type", "text/html");
    res.end(`<!doctype html><title>Origin Trace disposable fixture</title><link rel="icon" href="data:,"><button id="click">Click</button><script>globalThis.fixtureObject={originTraceMarker:"fixture",count:1};
function makePayload(input){
const out=input+"-observed";
return out;
}
globalThis.worker=new Worker("/worker.js");
document.querySelector("button").onclick=()=>{fixtureObject.count++;fetch("/echo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:makePayload("fixture")})});worker.postMessage("fixture");};</script>`);
    return;
  }
  res.setHeader("Content-Type", "text/plain");
  res.end("fixture response");
});
await new Promise((r) => fixture.listen(0, "127.0.0.1", r));
const fixtureUrl = `http://127.0.0.1:${fixture.address().port}`;
let passed = 0;
try {
  for (const name of ["rust"]) {
    const directory = join(temporary, name);
    await mkdir(directory);
    const profile = join(directory, "browser");
    await mkdir(profile);
    const browser = spawn(
      process.env.ORIGIN_TRACE_TEST_BROWSER ||
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      [
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--remote-debugging-port=0",
        `--user-data-dir=${profile}`,
        fixtureUrl + "/page",
      ],
      { stdio: "ignore" },
    );
    resources.push(browser);
    let portReady = false;
    for (let i = 0; i < 300; i++) {
      try {
        await readFile(join(profile, "DevToolsActivePort"));
        portReady = true;
        break;
      } catch {}
      if (browser.exitCode !== null) throw Error(`${name} browser exited`);
      await wait(50);
    }
    assert(portReady);
    const endpoint = join(directory, "endpoint");
    const prefix = [];
    const binary =
      process.env.ORIGIN_TRACE_BACKEND ||
      join(root, "apps/origin-trace-backend/target/debug/origin-trace-backend");
    const bundled = !!process.env.ORIGIN_TRACE_BACKEND;
    const backend = spawn(
      binary,
      [
        ...prefix,
        "--port",
        "0",
        "--store",
        join(directory, "events.jsonl"),
        "--trace-store",
        join(directory, "trace.jsonl"),
        "--signal-store",
        join(directory, "signals.jsonl"),
        "--artifacts",
        join(directory, "artifacts"),
        "--api-collection",
        join(directory, "collection.json"),
        "--local-analyst",
        join(directory, "analyst.json"),
        "--devtools-active-port",
        join(profile, "DevToolsActivePort"),
        ...(bundled
          ? []
          : [
              "--debugger-transport",
              join(root, "build/reb-debugger-transport"),
            ]),
        "--endpoint-file",
        endpoint,
        ...(bundled
          ? []
          : [
              "--ui-directory",
              join(root, "apps/research-ui"),
              "--deobfuscator",
              join(
                root,
                "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker",
              ),
            ]),
      ],
      {
        cwd: root,
        env: process.env.ORIGIN_TRACE_TEST_EMPTY_PATH
          ? { ...process.env, PATH: "/nonexistent" }
          : process.env,
      },
    );
    resources.push(backend);
    let diagnostics = "";
    backend.stdout.resume();
    backend.stderr.on("data", (x) => {
      diagnostics += x;
      appendFile(join(directory, "stderr.log"), x);
    });
    backend.on("exit", (code) => {
      if (code) console.log(`${name} EXIT ${code}: ${diagnostics}`);
    });
    let url;
    for (let i = 0; i < 200; i++) {
      try {
        url = (await readFile(endpoint, "utf8")).trim();
        break;
      } catch {}
      if (backend.exitCode !== null)
        throw Error(`${name} startup ${diagnostics}`);
      await wait(50);
    }
    assert(url);
    const get = async () => {
      const r = await fetch(url + "/api/debugger");
      assert.equal(r.status, 200);
      const body = await r.json();
      if (!ui.isDebuggerResponse(body)) {
        const invalid = [
          "request_interception",
          "action_scope",
          "object_experiment",
          "runtime_hooks",
          "automation_recipes",
          "repeater",
        ].filter((key, i) => !Object.values(ui)[i + 1](body[key]));
        throw Error(
          "UI rejected debugger state " + JSON.stringify({ invalid, body }),
        );
      }
      return body;
    };
    const action = async (action, values = {}) => {
      const r = await fetch(url + "/api/debugger/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ...values }),
      });
      const v = await r.json();
      for (const [key, validate] of Object.entries({
        experiment: ui.isRequestInterception,
        action_scope: ui.isActionScope,
        object_experiment: ui.isObjectExperiment,
        runtime_hooks: ui.isRuntimeHooks,
        automation_recipes: ui.isAutomationRecipes,
        repeater: ui.isRepeater,
      })) {
        if (v[key])
          assert(
            validate(v[key]),
            `UI rejected ${action} ${key}: ${JSON.stringify(v[key])}`,
          );
      }
      if (r.status !== 200)
        throw Error(`${name} ${action}: HTTP ${r.status} ${JSON.stringify(v)}`);
      return v;
    };
    const click = async () => {
      const state = await get();
      const devtools = Number(
        (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split(
          "\n",
        )[0],
      );
      const targets = await (
        await fetch(`http://127.0.0.1:${devtools}/json/list`)
      ).json();
      const target = targets.find(
        (t) => t.id === state.request_interception.target_id,
      );
      assert(target);
      const socket = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((resolve, reject) => {
        socket.addEventListener("open", () => {
          socket.send(
            JSON.stringify({
              id: 1,
              method: "Runtime.evaluate",
              params: {
                expression: 'document.querySelector("button").click()',
                returnByValue: true,
              },
            }),
          );
        });
        socket.addEventListener("message", (e) => {
          const v = JSON.parse(e.data);
          if (v.id === 1) {
            socket.close();
            v.error ? reject(Error(JSON.stringify(v.error))) : resolve();
          }
        });
        socket.addEventListener("error", reject);
      });
    };
    const until = async (predicate) => {
      for (let i = 0; i < 300; i++) {
        const s = await get();
        if (predicate(s)) return s;
        await wait(50);
      }
      throw Error(
        `${name} state timeout ${JSON.stringify(((s) => ({ state: s.state, error: s.error, target: s.target, targets: s.targets, workers: s.runtime_hooks.workers, hooks: s.runtime_hooks, console: s.console, interception: s.request_interception }))(await get()))}`,
      );
    };
    await until((s) => s.state === "running");
    await action("create_request_interception_experiment");
    let s = await until(
      (s) =>
        s.state === "running" &&
        s.target?.id === s.request_interception.target_id &&
        s.action_scope.state === "ready",
    );
    assert(s.request_interception.isolated);
    const primary = s.target.id;
    assert(s.action_scope.targets.every((t) => t.connected && t.matched));
    console.log(`PASS ${name} isolated context`);
    passed++;
    await action("configure_request_interception", {
      mode: "fulfill",
      url_pattern: "*",
      response_code: 201,
      response_body: "synthetic fixture",
    });
    let result = await action("run_request_interception", {
      url: fixtureUrl + "/echo",
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "fixture request",
    });
    assert.equal(result.experiment.result.status, 201);
    assert.equal(result.experiment.result.body, "synthetic fixture");
    console.log(`PASS ${name} fulfill`);
    passed++;
    const newPage = await action("create_experiment_page", {
      url: "about:blank",
    });
    const second = newPage.target_id;
    await until(
      (s) =>
        s.action_scope.targets.length === 2 &&
        s.action_scope.targets.every((t) => t.connected),
    );
    await action("set_action_scope", { mode: "target", target_id: second });
    result = await action("run_request_interception", {
      url: fixtureUrl + "/echo",
      method: "GET",
      target_id: second,
    });
    assert.equal(result.experiment.result.status, 201);
    await action("close_experiment_page", { target_id: second });
    await action("set_action_scope", { mode: "global" });
    console.log(`PASS ${name} scope and page lifecycle`);
    passed++;
    await action("configure_request_interception", {
      mode: "continue",
      url_pattern: "*",
    });
    await action("configure_repeater_variables", {
      variables: { base: fixtureUrl },
    });
    await action("run_repeater_request", {
      url: "{{base}}/echo",
      method: "GET",
      timeout_ms: 1000,
    });
    s = await until(
      (s) => s.repeater.history.length === 1 && !s.repeater.active_execution,
    );
    assert.equal(s.repeater.history[0].response.status, 200);
    assert.equal(s.repeater.history[0].response.body, "fixture response");
    await action("run_repeater_request", {
      url: "{{base}}/echo",
      method: "GET",
      timeout_ms: 1000,
    });
    s = await until(
      (s) => s.repeater.history.length === 2 && !s.repeater.active_execution,
    );
    await action("compare_repeater_history", {
      baseline_id: s.repeater.history[0].id,
      current_id: s.repeater.history[1].id,
    });
    s = await get();
    assert.equal(s.repeater.comparison.body_changed, false);
    console.log(`PASS ${name} repeater variables/history/comparison`);
    passed++;
    await action("run_repeater_request", {
      url: "{{base}}/slow",
      method: "GET",
      timeout_ms: 100,
    });
    s = await until(
      (s) => s.repeater.history.length === 3 && !s.repeater.active_execution,
    );
    assert(s.repeater.history[2].response.timed_out);
    console.log(`PASS ${name} repeater timeout`);
    passed++;
    await action("run_repeater_request", {
      url: "{{base}}/slow",
      method: "GET",
      timeout_ms: 10000,
    });
    await action("cancel_repeater_request");
    s = await until(
      (s) => s.repeater.history.length === 4 && !s.repeater.active_execution,
    );
    assert(s.repeater.history[3].response.cancelled);
    console.log(`PASS ${name} repeater cancellation`);
    passed++;
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    await until((s) => s.request_interception.pending_requests === 0);
    result = await action("search_object_experiment", {
      property_query: "originTraceMarker",
    });
    assert(result.object_experiment.results.length > 0);
    const object = result.object_experiment.results.find((v) =>
      v.preview.some((p) => p.name === "originTraceMarker"),
    );
    assert(object);
    const searchId = result.object_experiment.search_id;
    result = await action("mutate_object_experiment", {
      operation: "set",
      search_id: searchId,
      result_id: object.id,
      property: "count",
      value: 42,
      confirmed: true,
    });
    assert.equal(result.object_experiment.last_mutation.ok, true);
    assert.equal(result.object_experiment.last_mutation.outcome, "updated");
    result = await action("mutate_object_experiment", {
      operation: "delete",
      search_id: searchId,
      result_id: object.id,
      property: "count",
      confirmed: true,
    });
    assert.equal(result.object_experiment.last_mutation.outcome, "deleted");
    console.log(`PASS ${name} Object Lab search/set/delete/audit`);
    passed++;
    result = await action("search_live_objects", {
      property_query: "originTraceMarker",
    });
    assert(result.search.results.length > 0);
    console.log(`PASS ${name} passive live object search`);
    passed++;
    await until(
      (s) =>
        s.runtime_hooks.workers.length === 1 &&
        s.scripts.some((s) => s.target_type === "worker"),
    );
    let state = await get();
    let script = state.scripts.find((s) => s.url === fixtureUrl + "/page");
    assert(script);
    let source = await (
      await fetch(
        url +
          "/api/debugger/source?script_id=" +
          encodeURIComponent(script.script_id),
      )
    ).json();
    const lines = source.source.split("\n");
    const line =
      script.start_line +
      lines.findIndex((l) => l.includes('const out=input+"-observed"'));
    assert(line >= 0);
    let breakpoint = await action("set_breakpoint", {
      url: "",
      script_id: script.script_id,
      line,
      column: 0,
      kind: "line",
      expression: "",
    });
    const bp = breakpoint.breakpoint?.id || (await get()).breakpoints.at(-1).id;
    const clicking = click();
    state = await until((s) => s.state === "paused");
    assert(state.paused.call_frames.length > 0);
    await action("add_watch", { expression: "input" });
    await action("evaluate_watches", {
      call_frame_id: state.paused.call_frames[0].id,
    });
    state = await get();
    assert.equal(state.watches[0].result.value, "fixture");
    await action("step_over");
    await until((s) => s.state === "paused");
    await action("resume");
    await clicking;
    await action("remove_breakpoint", { breakpoint_id: bp });
    await until((s) => s.state === "running");
    console.log(`PASS ${name} breakpoint/watch/step/resume`);
    passed++;
    result = await action("search_heap_snapshot", {
      query: "originTraceMarker",
      scope: "all",
      case_sensitive: true,
    });
    assert(result.snapshot.results.length > 0);
    await action("capture_heap_diff_baseline");
    result = await action("compare_heap_diff");
    assert(result.diff);
    await action("clear_heap_diff_baseline");
    console.log(`PASS ${name} heap search/baseline/diff`);
    passed++;
    await action("start_memory_origin_trace", {
      query: "fixture",
      scope: "all",
      case_sensitive: true,
      before_steps: 0,
      after_steps: 1,
    });
    const memoryClick = click();
    state = await until((s) =>
      ["found", "not_found", "error", "aborted"].includes(
        s.memory_origin_trace.state,
      ),
    );
    assert.notEqual(
      state.memory_origin_trace.state,
      "error",
      JSON.stringify(state.memory_origin_trace),
    );
    assert(state.memory_origin_trace.steps.length > 0);
    await memoryClick;
    await action("clear_memory_origin_trace");
    console.log(`PASS ${name} memory origin trace`);
    passed++;

    await action("configure_runtime_field_test", {
      enabled: true,
      url: fixtureUrl + "/echo",
      method: "POST",
      kind: "json",
      pointer: "/payload",
      confirmed: true,
    });
    await action("add_runtime_hook", {
      label: "Payload return",
      script_id: script.script_id,
      line,
      column: 0,
      entry_enabled: true,
      return_enabled: true,
      return_mode: "none",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until(
      (s) =>
        s.runtime_hooks.hits.some((h) => h.category === "return") &&
        s.runtime_hooks.field_test.observations.some(
          (o) => o.status === "available",
        ),
    );
    assert(state.runtime_hooks.hits.some((h) => h.category === "entry"));
    await action("disarm_runtime_hooks");
    const baseline = state.runtime_hooks.field_test.observations.find(
      (o) => o.target_type === "page" && o.status === "available",
    );
    assert(baseline);
    await action("remove_runtime_hook", {
      hook_id: state.runtime_hooks.definitions[0].id,
    });
    await action("add_runtime_hook", {
      label: "Payload replacement",
      script_id: script.script_id,
      line,
      column: 0,
      entry_enabled: false,
      return_enabled: true,
      return_mode: "json",
      return_value: "changed",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until(
      (s) =>
        s.runtime_hooks.hits.some((h) => h.operation === "return_overridden") &&
        s.runtime_hooks.field_test.observations.some(
          (o) =>
            o.target_type === "page" &&
            o.status === "available" &&
            o.sha256 !== baseline.sha256,
        ),
    );
    await action("disarm_runtime_hooks");
    const variant = state.runtime_hooks.field_test.observations.find(
      (o) =>
        o.target_type === "page" &&
        o.status === "available" &&
        o.sha256 !== baseline.sha256,
    );
    result = await action("compare_runtime_field_test", {
      baseline_id: baseline.id,
      variant_id: variant.id,
    });
    assert(result.runtime_hooks.field_test.comparison.changed);
    assert.equal(
      result.runtime_hooks.field_test.comparison.interpretation,
      "intervention-associated",
    );
    console.log(
      `PASS ${name} hook entry/return/replacement and request-field comparison`,
    );
    passed++;
    await action("remove_runtime_hook", {
      hook_id: state.runtime_hooks.definitions[0].id,
    });
    state = await get();
    const workerScript = state.scripts.find(
      (s) => s.target_type === "worker" && s.url === fixtureUrl + "/worker.js",
    );
    assert(workerScript);
    source = await (
      await fetch(
        url +
          "/api/debugger/source?script_id=" +
          encodeURIComponent(workerScript.script_id),
      )
    ).json();
    assert(source.source.includes("workerPayload"));
    await action("add_runtime_hook", {
      label: "Worker return",
      script_id: workerScript.script_id,
      line: 1,
      column: 0,
      entry_enabled: true,
      return_enabled: true,
      return_mode: "none",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until((s) =>
      s.runtime_hooks.hits.some(
        (h) => h.target_type === "worker" && h.category === "return",
      ),
    );
    await action("disarm_runtime_hooks");
    await action("clear_runtime_hook_hits");
    await action("configure_runtime_field_test", { enabled: false });
    console.log(`PASS ${name} isolated worker source/hooks`);
    passed++;
    let recipe = await action("add_automation_recipe", {
      label: "Fixture recipe",
      source:
        'console.log("fixture automation");return Number(Utils.getVar("answer"));',
      trigger: "manual",
    });
    result = await action("run_automation_recipe", {
      recipe_id: recipe.recipe.id,
      variables: { answer: "42" },
      confirmed: true,
    });
    assert.equal(result.run.result_text, "42", JSON.stringify(result.run));
    assert.equal(result.run.operation, "completed");
    assert(result.run.logs.some((l) => l.text.includes("fixture automation")));
    console.log(`PASS ${name} manual automation with variables/logs`);
    passed++;
    const after = await action("add_automation_recipe", {
      label: "After load fixture",
      source: "return document.title;",
      trigger: "after-load",
    });
    await action("arm_automation_recipes", { confirmed: true });
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    s = await until((s) =>
      s.automation_recipes.runs.some((r) => r.category === "after-load"),
    );
    assert.equal(
      s.automation_recipes.runs.find((r) => r.category === "after-load")
        .result_text,
      '"Origin Trace disposable fixture"',
    );
    await action("disarm_automation_recipes");
    await action("remove_automation_recipe", { recipe_id: after.recipe.id });
    const before = await action("add_automation_recipe", {
      label: "Before load fixture",
      source: "globalThis.originTraceBeforeLoad=42;return 42;",
      trigger: "before-load",
    });
    await action("arm_automation_recipes", { confirmed: true });
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    s = await until((s) =>
      s.automation_recipes.runs.some((r) => r.category === "before-load"),
    );
    assert.equal(
      s.automation_recipes.runs.find((r) => r.category === "before-load")
        .operation,
      "completed",
    );
    await action("disarm_automation_recipes");
    console.log(`PASS ${name} before/after-load automation triggers`);
    passed++;

    const analyst = async (body) => {
      const response = await fetch(url + "/api/local-analyst/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      assert.equal(response.status, 200, JSON.stringify(result));
      return result;
    };
    await analyst({
      action: "replace_local_analyst_workspace",
      expected_generation: 0,
      folders: [{ id: 1, name: "Analyst Workspace", parent_id: null }],
      files: [
        {
          id: 1,
          folder_id: 1,
          name: "Fixture analyst",
          kind: "analyst-script",
          language: "javascript",
          content: "return WB.Node.Evidence.events().length;",
        },
      ],
    });
    let analystGeneration = 1;
    const analystRequest = (run_id, source) => ({
      action: "run_local_analyst_script",
      protocol_version: 1,
      run_id,
      script_id: 1,
      library_generation: analystGeneration,
      source,
      variables: {},
      evidence: {
        events: [],
        artifacts: [],
        trace_edges: [],
        signal_profiles: [],
        vm_analysis: null,
        selected_artifact: null,
        summary: {},
      },
      confirmed: true,
      confirmed_sensitive: false,
    });
    result = await analyst(
      analystRequest(1, "return WB.Node.Evidence.events().length;"),
    );
    assert.equal(result.outcome, "completed");
    assert.equal(result.result_text, "0");
    await analyst({
      action: "replace_local_analyst_workspace",
      expected_generation: 1,
      folders: [{ id: 1, name: "Analyst Workspace", parent_id: null }],
      files: [
        {
          id: 1,
          folder_id: 1,
          name: "Fixture analyst",
          kind: "analyst-script",
          language: "javascript",
          content: "while(true){}",
        },
      ],
    });
    analystGeneration = 2;
    result = await analyst(analystRequest(2, "while(true){}"));
    assert.equal(result.outcome, "timed_out");
    const pendingAnalyst = analyst(analystRequest(3, "while(true){}"));
    for (let i = 0; i < 100; i++) {
      const state = await (
        await fetch(url + "/api/local-analyst/runner")
      ).json();
      if (state.active_run_id === 3) break;
      await wait(10);
    }
    await analyst({ action: "cancel_local_analyst_script", run_id: 3 });
    result = await pendingAnalyst;
    assert.equal(result.outcome, "cancelled");
    console.log(`PASS ${name} analyst success/timeout/cancellation`);
    passed++;
    await action("clear_automation_runs");
    await action("clear_repeater_history");
    s = await get();
    assert.equal(s.repeater.history.length, 0);
    await action("dispose_request_interception_experiment");
    s = await get();
    assert.equal(s.request_interception.state, "disposed");
    assert.equal(s.request_interception.target_id, null);
    assert.equal(s.repeater.variables.length, 0);
    assert.equal(s.runtime_hooks.hits.length, 0);
    assert.equal(s.runtime_hooks.definitions.length, 0);
    assert.equal(s.automation_recipes.runs.length, 0);
    assert.equal(s.action_scope.targets.length, 0);
    const port = Number(
      (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split(
        "\n",
      )[0],
    );
    const targets = await (
      await fetch(`http://127.0.0.1:${port}/json/list`)
    ).json();
    assert(!targets.some((t) => t.id === primary || t.id === second));
    console.log(`PASS ${name} verified context disposal`);
    passed++;
    backend.kill("SIGTERM");
    browser.kill("SIGTERM");
    await wait(500);
  }
  console.log(JSON.stringify({ temporary, passed }));
} finally {
  for (const child of resources) {
    if (child.exitCode === null) child.kill("SIGTERM");
  }
  fixture.closeAllConnections();
  await new Promise((r) => fixture.close(r));
}
