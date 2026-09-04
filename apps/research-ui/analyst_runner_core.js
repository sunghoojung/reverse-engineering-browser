"use strict";

async function REBExecuteAnalyst(input, userFunction) {
  const started = Date.now();
  const utf8Bytes = value => {
    let bytes = 0;
    for (let index = 0; index < value.length;) {
      const point = value.codePointAt(index);
      index += point > 0xffff ? 2 : 1;
      bytes += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
    }
    return bytes;
  };
  const boundedText = (value, limit) => {
    let text;
    try { text = String(value); } catch { text = "<unavailable>"; }
    if (utf8Bytes(text) <= limit) return text;
    const parts = [];
    let bytes = 0;
    for (let index = 0; index < text.length;) {
      const point = text.codePointAt(index);
      const width = point > 0xffff ? 2 : 1;
      const encoded = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
      if (bytes + encoded > limit) break;
      parts.push(text.slice(index, index + width));
      bytes += encoded;
      index += width;
    }
    return parts.join("");
  };
  const serialize = (value, limit) => {
    const seen = new WeakSet();
    let entries = 0;
    let truncated = false;
    const clone = (candidate, depth) => {
      if (candidate === null || typeof candidate === "boolean" || typeof candidate === "number") return candidate;
      if (typeof candidate === "string") {
        const result = boundedText(candidate, Math.min(limit, 8192));
        if (result !== candidate) truncated = true;
        return result;
      }
      if (typeof candidate === "bigint") return `${candidate}n`;
      if (typeof candidate === "undefined") return "[undefined]";
      if (typeof candidate === "symbol") return boundedText(candidate, 256);
      if (typeof candidate === "function") return `[Function ${boundedText(candidate.name || "anonymous", 128)}]`;
      if (depth >= 8) { truncated = true; return "[MaxDepth]"; }
      if (seen.has(candidate)) return "[Circular]";
      seen.add(candidate);
      let keys;
      try { keys = Reflect.ownKeys(candidate); } catch { return "[Uninspectable]"; }
      const output = Array.isArray(candidate) ? [] : {};
      for (const rawKey of keys) {
        if (entries >= 512) { truncated = true; break; }
        entries += 1;
        const key = boundedText(rawKey, 256);
        let descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(candidate, rawKey); } catch { descriptor = null; }
        if (!descriptor) output[key] = "[Unavailable]";
        else if (!("value" in descriptor)) output[key] = "[Accessor not invoked]";
        else output[key] = clone(descriptor.value, depth + 1);
      }
      return output;
    };
    let text;
    try { text = JSON.stringify(clone(value, 0)); } catch { text = '"[Unserializable]"'; }
    if (text === undefined) text = '"[undefined]"';
    const byteLength = utf8Bytes(text);
    return {text: boundedText(text, limit), truncated: truncated || byteLength > limit};
  };
  const deepFreeze = value => {
    const pending = [value];
    const seen = new WeakSet();
    let entries = 0;
    while (pending.length) {
      const current = pending.pop();
      if (!current || typeof current !== "object" || seen.has(current)) continue;
      seen.add(current);
      if (entries++ > 50000) throw new Error("Evidence snapshot exceeds the runner entry limit");
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
    error: boundedText(message, 512)
  });

  try {
    if (!input || input.protocol_version !== 1 || !Number.isSafeInteger(input.run_id) || input.run_id <= 0 ||
        !Number.isSafeInteger(input.script_id) || input.script_id <= 0 ||
        !Number.isSafeInteger(input.library_generation) || input.library_generation < 0 ||
        !input.variables || typeof input.variables !== "object" || Array.isArray(input.variables) ||
        !input.evidence || typeof input.evidence !== "object" || Array.isArray(input.evidence) ||
        typeof userFunction !== "function") {
      return failure("Analyst runner input is malformed");
    }
    const variables = deepFreeze(input.variables);
    const evidence = deepFreeze(input.evidence);
    const safeJsonStringify = value => serialize(value, 32768).text;
    function* iterate(value) {
      if (value == null) return;
      let count = 0;
      if (value instanceof Map) {
        for (const entry of value.entries()) { if (count++ >= 512) return; yield entry; }
        return;
      }
      if (value instanceof Set || Array.isArray(value) || ArrayBuffer.isView(value)) {
        for (const item of value) { if (count >= 512) return; yield [count++, item]; }
        return;
      }
      let keys;
      try { keys = Object.keys(value); } catch { return; }
      for (const key of keys) {
        if (count++ >= 512) return;
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
      summary: () => evidence.summary || Object.freeze({}),
      capabilities: () => Object.freeze([
        "events", "artifacts", "trace-edges", "signal-profiles", "vm-analysis", "selected-artifact"
      ])
    });
    const WB = Object.freeze({Node: Object.freeze({Utils, Evidence})});
    const logs = [];
    let logsTruncated = false;
    const capture = (level, values) => {
      if (logs.length >= 64) { logsTruncated = true; return; }
      const text = boundedText(values.map(value => safeJsonStringify(value)).join(" "), 1024);
      logs.push({level, text});
    };
    const analystConsole = Object.freeze({
      log: (...values) => capture("log", values),
      info: (...values) => capture("info", values),
      warn: (...values) => capture("warn", values),
      error: (...values) => capture("error", values)
    });

    try {
      const result = await userFunction(WB, Utils, analystConsole);
      const serialized = serialize(result, 32768);
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
