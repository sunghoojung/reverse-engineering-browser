"use strict";

// The host leaves the run's input as globals: REBInput (the JSON header
// text), REBSelectedText (the selected artifact as UTF-8 text, or null when it
// is not) and REBSelectedBytes (its bytes, made in this realm). They are taken
// and removed before the script runs.
function REBTakeInput() {
  const input = JSON.parse(globalThis.REBInput);
  const bytes = globalThis.REBSelectedBytes instanceof Uint8Array ? globalThis.REBSelectedBytes : null;
  const selected = input && input.evidence && input.evidence.selected_artifact;
  if (selected && typeof selected === "object") {
    selected.content = typeof globalThis.REBSelectedText === "string" ? globalThis.REBSelectedText : null;
  }
  delete globalThis.REBInput;
  delete globalThis.REBSelectedText;
  delete globalThis.REBSelectedBytes;
  return [input, bytes];
}

async function REBExecuteAnalyst(input, selectedBytes, userFunction) {
  const started = Date.now();
  // Errors, symbol descriptions and function names are kept whole, like
  // results and logs; only a value that cannot be turned into text is named.
  const textOf = value => {
    try { return String(value); } catch { return "<unavailable>"; }
  };
  // Results and logs are kept whole. Only nesting is bounded, because each
  // level is a frame of this recursion and of JSON.stringify.
  const serialize = value => {
    const seen = new WeakSet();
    let truncated = false;
    const clone = (candidate, depth) => {
      if (candidate === null || typeof candidate === "boolean" || typeof candidate === "number") return candidate;
      if (typeof candidate === "string") return candidate;
      if (typeof candidate === "bigint") return `${candidate}n`;
      if (typeof candidate === "undefined") return "[undefined]";
      if (typeof candidate === "symbol") return textOf(candidate);
      if (typeof candidate === "function") return `[Function ${textOf(candidate.name || "anonymous")}]`;
      if (depth >= 256) { truncated = true; return "[MaxDepth]"; }
      if (seen.has(candidate)) return "[Circular]";
      seen.add(candidate);
      let keys;
      try { keys = Reflect.ownKeys(candidate); } catch { return "[Uninspectable]"; }
      const output = Array.isArray(candidate) ? [] : {};
      for (const rawKey of keys) {
        const key = typeof rawKey === "symbol" ? textOf(rawKey) : rawKey;
        let descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(candidate, rawKey); } catch { descriptor = null; }
        if (!descriptor) output[key] = "[Unavailable]";
        else if (!("value" in descriptor)) output[key] = "[Accessor not invoked]";
        else output[key] = clone(descriptor.value, depth + 1);
      }
      return output;
    };
    let text;
    try { text = JSON.stringify(clone(value, 0)); } catch { text = '"[Unserializable]"'; truncated = true; }
    if (text === undefined) text = '"[undefined]"';
    return {text, truncated};
  };
  const deepFreeze = value => {
    const pending = [value];
    const seen = new WeakSet();
    while (pending.length) {
      const current = pending.pop();
      if (!current || typeof current !== "object" || seen.has(current)) continue;
      seen.add(current);
      for (const key of Reflect.ownKeys(current)) {
        const descriptor = Object.getOwnPropertyDescriptor(current, key);
        if (descriptor && "value" in descriptor && descriptor.value && typeof descriptor.value === "object") {
          pending.push(descriptor.value);
        }
      }
      Object.freeze(current);
    }
    return value;
  };
  const failure = message => ({
    protocol_version: 1,
    run_id: Number.isSafeInteger(input && input.run_id) ? input.run_id : 0,
    script_id: Number.isSafeInteger(input && input.script_id) ? input.script_id : 0,
    library_generation: Number.isSafeInteger(input && input.library_generation) ? input.library_generation : 0,
    ok: false,
    outcome: "failed",
    result_type: "error",
    result_text: "",
    result_truncated: false,
    logs: [],
    logs_truncated: false,
    duration_ms: Math.max(0, Date.now() - started),
    error: textOf(message)
  });

  try {
    if (!input || input.protocol_version !== 2 || !Number.isSafeInteger(input.run_id) || input.run_id <= 0 ||
        !Number.isSafeInteger(input.script_id) || input.script_id <= 0 ||
        !Number.isSafeInteger(input.library_generation) || input.library_generation < 0 ||
        !input.variables || typeof input.variables !== "object" || Array.isArray(input.variables) ||
        !input.evidence || typeof input.evidence !== "object" || Array.isArray(input.evidence) ||
        (selectedBytes !== null && !(selectedBytes instanceof Uint8Array)) || typeof userFunction !== "function") {
      return failure("Analyst runner input is malformed");
    }
    const variables = deepFreeze(input.variables);
    const evidence = deepFreeze(input.evidence);
    const safeJsonStringify = value => serialize(value).text;
    function* iterate(value) {
      if (value == null) return;
      if (value instanceof Map) {
        yield* value.entries();
        return;
      }
      if (value instanceof Set || Array.isArray(value) || ArrayBuffer.isView(value)) {
        let count = 0;
        for (const item of value) yield [count++, item];
        return;
      }
      let keys;
      try { keys = Object.keys(value); } catch { return; }
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor && "value" in descriptor) yield [key, descriptor.value];
      }
    }
    const Utils = Object.freeze({
      getVar: name => typeof name === "string" ? variables[name] : undefined,
      safeJsonStringify,
      iterate
    });
    const arrayValue = name => Array.isArray(evidence[name]) ? evidence[name] : Object.freeze([]);
    const Evidence = Object.freeze({
      events: () => arrayValue("events"),
      artifacts: () => arrayValue("artifacts"),
      traceEdges: () => arrayValue("trace_edges"),
      signalProfiles: () => arrayValue("signal_profiles"),
      vmAnalysis: () => evidence.vm_analysis || null,
      selectedArtifact: () => evidence.selected_artifact || null,
      // A fresh copy of the selected artifact's bytes, or of [start, end), so
      // the evidence a script reads stays as it was captured.
      selectedArtifactBytes: (start, end) => selectedBytes ? selectedBytes.slice(start, end) : null,
      summary: () => evidence.summary || Object.freeze({}),
      capabilities: () => Object.freeze([
        "events", "artifacts", "trace-edges", "signal-profiles", "vm-analysis", "selected-artifact",
        "selected-artifact-bytes"
      ])
    });
    const WB = Object.freeze({Node: Object.freeze({Utils, Evidence})});
    const logs = [];
    let logsTruncated = false;
    const capture = (level, values) => {
      const serialized = values.map(value => serialize(value));
      if (serialized.some(value => value.truncated)) logsTruncated = true;
      logs.push({level, text: serialized.map(value => value.text).join(" ")});
    };
    const analystConsole = Object.freeze({
      log: (...values) => capture("log", values),
      info: (...values) => capture("info", values),
      warn: (...values) => capture("warn", values),
      error: (...values) => capture("error", values)
    });

    try {
      const result = await userFunction(WB, Utils, analystConsole);
      const serialized = serialize(result);
      return {
        protocol_version: 1,
        run_id: input.run_id,
        script_id: input.script_id,
        library_generation: input.library_generation,
        ok: true,
        outcome: "completed",
        result_type: result === null ? "null" : typeof result,
        result_text: serialized.text,
        result_truncated: serialized.truncated,
        logs,
        logs_truncated: logsTruncated,
        duration_ms: Math.max(0, Date.now() - started),
        error: ""
      };
    } catch (error) {
      const result = failure(error && error.message ? error.message : error);
      result.logs = logs;
      result.logs_truncated = logsTruncated;
      return result;
    }
  } catch (error) {
    return failure(error && error.message ? error.message : error);
  }
}
