#!/usr/bin/env node

"use strict";

const fs = require("node:fs");
const vm = require("node:vm");

let correlation = {run_id: 0, script_id: 0, library_generation: 0};
let answered = false;

const write = value => {
  answered = true;
  process.stdout.write(JSON.stringify(value));
};

const writeFailure = message => write({
  protocol_version: 1,
  ...correlation,
  ok: false,
  outcome: "failed",
  result_type: "error",
  result_text: "",
  result_truncated: false,
  logs: [],
  logs_truncated: false,
  duration_ms: 0,
  error: String(message).slice(0, 512)
});

// The script's realm has no timers or I/O, so once this process has nothing
// left to do, a promise the script still awaits can never settle.
process.once("beforeExit", () => {
  if (!answered) writeFailure("The analyst script awaited a promise that nothing can settle");
});

const main = async () => {
  const corePath = process.argv[2];
  if (!corePath) throw new Error("Analyst runner core path is required");
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = Buffer.concat(chunks);
  chunks.length = 0;
  // Runner input v2: one JSON line, then the selected artifact's bytes.
  const end = input.indexOf(10);
  if (end < 0) throw new Error("Analyst runner input has no header line");
  const header = JSON.parse(input.toString("utf8", 0, end));
  if (!header || typeof header !== "object" || Array.isArray(header) || header.protocol_version !== 2 ||
      typeof header.source !== "string") {
    throw new Error("Analyst runner input is malformed");
  }
  correlation = {
    run_id: Number.isSafeInteger(header.run_id) ? header.run_id : 0,
    script_id: Number.isSafeInteger(header.script_id) ? header.script_id : 0,
    library_generation: Number.isSafeInteger(header.library_generation) ? header.library_generation : 0
  };
  const bytes = input.subarray(end + 1);
  const selected = header.evidence && header.evidence.selected_artifact;
  if (selected ? bytes.length !== selected.byte_size : bytes.length !== 0) {
    throw new Error("Analyst runner input does not match the selected artifact's byte size");
  }
  const source = header.source;
  delete header.source;
  const core = fs.readFileSync(corePath, "utf8");
  const program = `${core}\nREBExecuteAnalyst(...REBTakeInput(), async function(WB, Utils, console) {\n"use strict";\n${source}\n});\n//# sourceURL=reb-local-analyst.js`;
  const context = vm.createContext(Object.create(null), {
    name: "reb-local-analyst",
    codeGeneration: {strings: false, wasm: false}
  });
  // Only primitives, and a byte array made in the script's realm, cross into
  // it, so nothing the script can reach leads back to this realm.
  context.REBInput = JSON.stringify(header);
  if (selected) {
    let text = null;
    try { text = new TextDecoder("utf-8", {fatal: true}).decode(bytes); } catch { text = null; }
    context.REBSelectedText = text;
    const inner = vm.runInContext(`new Uint8Array(${bytes.length})`, context);
    inner.set(bytes);
    context.REBSelectedBytes = inner;
  }
  const script = new vm.Script(program, {filename: "reb-local-analyst.js"});
  write(await script.runInContext(context, {breakOnSigint: true}));
};

main().catch(error => {
  writeFailure(error && error.message ? error.message : error);
  process.exitCode = 1;
});
