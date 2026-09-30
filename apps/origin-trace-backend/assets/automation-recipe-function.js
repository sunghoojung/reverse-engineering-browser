async function(config) {
  const started = Date.now();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const boundedText = (value, limit) => {
    let text;
    try { text = String(value); } catch { text = "<unavailable>"; }
    const encoded = encoder.encode(text);
    if (encoded.length <= limit) return text;
    text = decoder.decode(encoded.subarray(0, limit));
    while (text && encoder.encode(text).length > limit) text = text.slice(0, -1);
    return text;
  };
  const serialize = (value, limit) => {
    const seen = new WeakSet();
    let entries = 0;
    let truncated = false;
    const clone = (candidate, depth) => {
      if (candidate === null || typeof candidate === "boolean" || typeof candidate === "number") return candidate;
      if (typeof candidate === "string") {
        const result = boundedText(candidate, Math.min(limit, 4096));
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
        if (entries >= 256) { truncated = true; break; }
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
    const byteLength = encoder.encode(text).length;
    return {text: boundedText(text, limit), truncated: truncated || byteLength > limit};
  };
  const safeJsonStringify = value => serialize(value, config.resultLimit).text;
  function* iterate(value) {
    if (value == null) return;
    let count = 0;
    if (value instanceof Map) {
      for (const entry of value.entries()) { if (count++ >= 256) return; yield entry; }
      return;
    }
    if (value instanceof Set || Array.isArray(value) || ArrayBuffer.isView(value) ||
        (typeof NodeList !== "undefined" && value instanceof NodeList) ||
        (typeof HTMLCollection !== "undefined" && value instanceof HTMLCollection)) {
      for (const item of value) { if (count >= 256) return; yield [count++, item]; }
      return;
    }
    let keys;
    try { keys = Object.keys(value); } catch { return; }
    for (const key of keys) {
      if (count++ >= 256) return;
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { descriptor = null; }
      if (descriptor && "value" in descriptor) yield [key, descriptor.value];
    }
  }
  const variables = Object.freeze({...config.variables});
  const Utils = Object.freeze({
    getVar: name => typeof name === "string" ? variables[name] : undefined,
    safeJsonStringify,
    iterate
  });
  const WB = Object.freeze({Browser: Object.freeze({Utils})});
  const logs = [];
  let logsTruncated = false;
  const capture = (level, values) => {
    if (logs.length >= config.logLimit) { logsTruncated = true; return; }
    const text = boundedText(values.map(value => safeJsonStringify(value)).join(" "), config.logBytes);
    logs.push({level, text});
  };
  const recipeConsole = Object.freeze({
    log: (...values) => capture("log", values),
    info: (...values) => capture("info", values),
    warn: (...values) => capture("warn", values),
    error: (...values) => capture("error", values)
  });
  const timeoutToken = Object.freeze({});
  let timeoutId = null;
  try {
    const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
    const run = new AsyncFunction(
      "WB", "Utils", "console",
      `"use strict";\n${config.source}\n//# sourceURL=reb-automation-recipe.js`
    );
    const execution = run(WB, Utils, recipeConsole);
    const timeout = new Promise((_, reject) => {
      timeoutId = setTimeout(() => reject(timeoutToken), config.timeoutMs);
    });
    const result = await Promise.race([execution, timeout]);
    const serialized = serialize(result, config.resultLimit);
    return {
      protocolVersion: 1,
      ok: true,
      resultType: result === null ? "null" : typeof result,
      resultText: serialized.text,
      resultTruncated: serialized.truncated,
      logs,
      logsTruncated,
      elapsedMs: Math.max(0, Date.now() - started),
      timedOut: false
    };
  } catch (error) {
    const timedOut = error === timeoutToken;
    return {
      protocolVersion: 1,
      ok: false,
      resultType: "error",
      resultText: "",
      resultTruncated: false,
      logs,
      logsTruncated,
      elapsedMs: Math.max(0, Date.now() - started),
      error: timedOut ? "Recipe exceeded the 2 second execution limit" : boundedText(error && error.message ? error.message : error, 512),
      timedOut
    };
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}
