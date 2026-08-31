#!/usr/bin/env node

"use strict";

const fs = require("node:fs");
const vm = require("node:vm");

const MAX_INPUT_BYTES = 800 * 1024;
const MAX_SOURCE_BYTES = 32 * 1024;
const MAX_OUTPUT_BYTES = 128 * 1024;

let correlation = {run_id: 0, script_id: 0, library_generation: 0};

const writeFailure = message => {
  const text = String(message);
  const timedOut = text.toLowerCase().includes("timed out");
  const value = {
    protocol_version: 1,
    ...correlation,
    ok: false,
    outcome: timedOut ? "timed_out" : "failed",
    result_type: "error",
    result_text: "",
    result_truncated: false,
    logs: [],
    logs_truncated: false,
    duration_ms: timedOut ? 2000 : 0,
    error: (timedOut ? "Analyst script exceeded the 2 second execution limit" : text).slice(0, 512)
  };
  process.stdout.write(JSON.stringify(value));
};

const main = async () => {
  const corePath = process.argv[2];
  if (!corePath) throw new Error("Analyst runner core path is required");
  const chunks = [];
  let inputBytes = 0;
  for await (const chunk of process.stdin) {
    inputBytes += chunk.length;
    if (inputBytes > MAX_INPUT_BYTES) throw new Error("Analyst runner input exceeds 800 KiB");
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!input || typeof input !== "object" || Array.isArray(input) || typeof input.source !== "string" ||
      Buffer.byteLength(input.source, "utf8") > MAX_SOURCE_BYTES) {
    throw new Error("Analyst runner source is malformed or oversized");
  }
  correlation = {
    run_id: Number.isSafeInteger(input.run_id) ? input.run_id : 0,
    script_id: Number.isSafeInteger(input.script_id) ? input.script_id : 0,
    library_generation: Number.isSafeInteger(input.library_generation) ? input.library_generation : 0
  };
  const source = input.source;
  delete input.source;
  const core = fs.readFileSync(corePath, "utf8");
  const program = `${core}\nREBExecuteAnalyst(${JSON.stringify(input)}, async function(WB, Utils, console) {\n"use strict";\n${source}\n});\n//# sourceURL=reb-local-analyst.js`;
  const context = vm.createContext(Object.create(null), {
    name: "reb-local-analyst",
    codeGeneration: {strings: false, wasm: false}
  });
  const script = new vm.Script(program, {filename: "reb-local-analyst.js"});
  const keepAlive = setInterval(() => {}, 1000);
  let result;
  try {
    result = await script.runInContext(context, {timeout: 2100, breakOnSigint: true});
  } finally {
    clearInterval(keepAlive);
  }
  const output = JSON.stringify(result);
  if (Buffer.byteLength(output, "utf8") > MAX_OUTPUT_BYTES) {
    throw new Error("Analyst runner response exceeds 128 KiB");
  }
  process.stdout.write(output);
};

main().catch(error => {
  writeFailure(error && error.message ? error.message : error);
  process.exitCode = 1;
});
