from __future__ import annotations

AUTOMATION_RECIPE_FUNCTION = r"""async function(config) {
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
}"""


LIVE_OBJECT_SEARCH_FUNCTION = r"""function(criteria) {
  const started = Date.now();
  const deadline = started + criteria.timeoutMs;
  let propertyLimitReached = false;
  const hasQuery = value => typeof value === "string" && value.length > 0;
  const compile = value => {
    if (!hasQuery(value)) return null;
    if (!criteria.regex) {
      const needle = criteria.caseSensitive ? value : value.toLowerCase();
      return input => {
        const text = criteria.caseSensitive ? String(input) : String(input).toLowerCase();
        return text.includes(needle);
      };
    }
    const expression = new RegExp(value, criteria.caseSensitive ? "" : "i");
    return input => expression.test(String(input));
  };
  const propertyMatches = compile(criteria.propertyQuery);
  const valueMatches = compile(criteria.valueQuery);
  const classMatches = compile(criteria.classQuery);
  const boundedText = value => {
    let text;
    try { text = String(value); } catch { return "<unavailable>"; }
    return text.length > 160 ? `${text.slice(0, 160)}...` : text;
  };
  const className = value => {
    if (Array.isArray(value)) return "Array";
    try {
      const prototype = Object.getPrototypeOf(value);
      const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, "constructor");
      const name = descriptor && "value" in descriptor && descriptor.value && descriptor.value.name;
      return typeof name === "string" && name ? name.slice(0, 160) : "Object";
    } catch { return "Object"; }
  };
  const primitiveType = value => value === null ? "null" : typeof value;
  const tokenSet = (root, includeValues) => {
    const tokens = [];
    const seen = new WeakSet();
    const walk = (value, path, depth) => {
      if (tokens.length >= 256 || depth > 3) {
        propertyLimitReached = true;
        return;
      }
      if ((typeof value !== "object" && typeof value !== "function") || value === null) {
        const type = primitiveType(value);
        tokens.push(includeValues ? `${path}:${type}=${boundedText(value)}` : `${path}:${type}`);
        return;
      }
      if (seen.has(value)) {
        tokens.push(`${path}:circular`);
        return;
      }
      seen.add(value);
      let names;
      try { names = Object.getOwnPropertyNames(value); } catch { return; }
      if (names.length > 96) propertyLimitReached = true;
      names = names.slice(0, 96).sort();
      if (names.length === 0) tokens.push(`${path}:empty`);
      for (const name of names) {
        if (tokens.length >= 256) break;
        let descriptor;
        try { descriptor = Object.getOwnPropertyDescriptor(value, name); } catch { continue; }
        if (name.length > 160) propertyLimitReached = true;
        const boundedName = name.slice(0, 160);
        const childPath = path ? `${path}.${boundedName}` : boundedName;
        if (!descriptor || !("value" in descriptor)) {
          tokens.push(`${childPath}:accessor`);
          continue;
        }
        walk(descriptor.value, childPath, depth + 1);
      }
    };
    walk(root, "", 0);
    return new Set(tokens);
  };
  const shapeTokens = criteria.shape === null
    ? null
    : tokenSet(criteria.shape, criteria.includeShapeValues);
  const similarity = candidate => {
    if (shapeTokens === null) return null;
    const candidateTokens = tokenSet(candidate, criteria.includeShapeValues);
    let intersection = 0;
    for (const token of candidateTokens) if (shapeTokens.has(token)) intersection += 1;
    const union = candidateTokens.size + shapeTokens.size - intersection;
    return union === 0 ? 1 : intersection / union;
  };
  const preview = (candidate, names) => names.slice(0, criteria.previewProperties).map(name => {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch {}
    if (!descriptor || !("value" in descriptor)) {
      return {name: name.slice(0, 256), type: "accessor", value: "<getter not invoked>"};
    }
    const value = descriptor.value;
    const type = primitiveType(value);
    if ((typeof value === "object" && value !== null) || typeof value === "function") {
      return {name: name.slice(0, 256), type, value: `[${className(value)}]`};
    }
    return {name: name.slice(0, 256), type, value: boundedText(value)};
  });

  let totalObjects = 0;
  try { totalObjects = Number(this.length) || 0; } catch { totalObjects = 0; }
  const scanLimit = Math.min(totalObjects, criteria.scanLimit);
  const results = [];
  let analyzed = 0;
  let visited = 0;
  let timedOut = false;
  for (let index = 0; index < scanLimit; index += 1) {
    if (Date.now() >= deadline) {
      timedOut = true;
      break;
    }
    visited += 1;
    let candidate;
    let names;
    try {
      candidate = this[index];
      if ((typeof candidate !== "object" && typeof candidate !== "function") || candidate === null) continue;
      names = Object.getOwnPropertyNames(candidate);
    } catch { continue; }
    analyzed += 1;
    if (names.length > criteria.propertyScanLimit) propertyLimitReached = true;
    const inspectedNames = names.slice(0, criteria.propertyScanLimit);
    const candidateClass = className(candidate);
    if (propertyMatches && !inspectedNames.some(name => {
      if (name.length > 512) propertyLimitReached = true;
      return propertyMatches(name.slice(0, 512));
    })) continue;
    if (classMatches && !classMatches(candidateClass)) continue;
    if (valueMatches && !inspectedNames.some(name => {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch { return false; }
      if (!descriptor || !("value" in descriptor)) return false;
      const value = descriptor.value;
      if ((typeof value === "object" && value !== null) || typeof value === "function") return false;
      return valueMatches(boundedText(value));
    })) continue;
    const score = similarity(candidate);
    if (score !== null && score < criteria.similarityThreshold) continue;
    results.push({
      id: String(index),
      className: candidateClass,
      propertyCount: names.length,
      propertiesTruncated: names.length > criteria.previewProperties,
      similarity: score,
      preview: preview(candidate, inspectedNames)
    });
    if (results.length >= criteria.resultLimit) break;
  }
  return {
    protocolVersion: 2,
    analyzed,
    totalObjects,
    results,
    resultLimit: criteria.resultLimit,
    resultLimitReached: results.length >= criteria.resultLimit,
    scanLimitReached: totalObjects > scanLimit || visited < scanLimit,
    propertyLimitReached,
    timedOut,
    durationMs: Math.max(0, Date.now() - started)
  };
}"""


OBJECT_EXPERIMENT_MUTATE_FUNCTION = r"""function(config) {
  const boundedText = value => {
    let text;
    try { text = String(value); } catch { return "<unavailable>"; }
    return text.length > 160 ? `${text.slice(0, 160)}...` : text;
  };
  const valueType = value => value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
  const className = value => {
    if (Array.isArray(value)) return "Array";
    try {
      const prototype = Object.getPrototypeOf(value);
      const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, "constructor");
      const name = descriptor && "value" in descriptor && descriptor.value && descriptor.value.name;
      return typeof name === "string" && name ? name.slice(0, 160) : "Object";
    } catch { return "Object"; }
  };
  const descriptorSummary = descriptor => {
    if (!descriptor) return {exists: false, type: "missing", className: "", writable: false, configurable: false};
    if (!("value" in descriptor)) {
      return {exists: true, type: "accessor", className: "", writable: false, configurable: descriptor.configurable === true};
    }
    const value = descriptor.value;
    const type = valueType(value);
    return {
      exists: true,
      type,
      className: (type === "object" || type === "array" || type === "function") && value !== null ? className(value) : "",
      writable: descriptor.writable === true,
      configurable: descriptor.configurable === true,
      preview: (type === "object" || type === "array" || type === "function") && value !== null
        ? `[${className(value)}]`
        : boundedText(value)
    };
  };
  const inspect = candidate => {
    let names;
    try { names = Object.getOwnPropertyNames(candidate).sort(); }
    catch { names = []; }
    const preview = [];
    for (const name of names.slice(0, config.previewProperties)) {
      let descriptor;
      try { descriptor = Object.getOwnPropertyDescriptor(candidate, name); } catch {}
      if (!descriptor || !("value" in descriptor)) {
        preview.push({name: name.slice(0, 256), type: "accessor", value: "<getter not invoked>"});
        continue;
      }
      const value = descriptor.value;
      const type = value === null ? "null" : typeof value;
      preview.push({
        name: name.slice(0, 256),
        type,
        value: ((typeof value === "object" && value !== null) || typeof value === "function")
          ? `[${className(value)}]`
          : boundedText(value)
      });
    }
    return {
      id: config.resultId,
      className: className(candidate),
      propertyCount: names.length,
      propertiesTruncated: names.length > config.previewProperties,
      similarity: config.similarity,
      preview
    };
  };

  try {
    const beforeDescriptor = Object.getOwnPropertyDescriptor(this, config.property);
    const before = descriptorSummary(beforeDescriptor);
    let outcome;
    if (beforeDescriptor && !("value" in beforeDescriptor)) {
      return {protocolVersion: 1, ok: false, error: "Accessor properties cannot be patched", outcome: "accessor", before, after: before, object: inspect(this)};
    }
    if (config.operation === "delete") {
      if (!beforeDescriptor) {
        return {protocolVersion: 1, ok: false, error: "The selected own property does not exist", outcome: "missing", before, after: before, object: inspect(this)};
      }
      if (!beforeDescriptor.configurable) {
        return {protocolVersion: 1, ok: false, error: "The selected own property is not configurable", outcome: "non_configurable", before, after: before, object: inspect(this)};
      }
      if (!Reflect.deleteProperty(this, config.property)) {
        return {protocolVersion: 1, ok: false, error: "The selected own property could not be deleted", outcome: "rejected", before, after: before, object: inspect(this)};
      }
      outcome = "deleted";
    } else {
      if (beforeDescriptor && !beforeDescriptor.writable) {
        return {protocolVersion: 1, ok: false, error: "The selected own property is not writable", outcome: "non_writable", before, after: before, object: inspect(this)};
      }
      if (!beforeDescriptor && !Object.isExtensible(this)) {
        return {protocolVersion: 1, ok: false, error: "The selected object is not extensible", outcome: "non_extensible", before, after: before, object: inspect(this)};
      }
      const descriptor = beforeDescriptor
        ? {...beforeDescriptor, value: config.value}
        : {value: config.value, writable: true, enumerable: true, configurable: true};
      Object.defineProperty(this, config.property, descriptor);
      outcome = beforeDescriptor ? "updated" : "created";
    }
    const after = descriptorSummary(Object.getOwnPropertyDescriptor(this, config.property));
    return {protocolVersion: 1, ok: true, error: null, outcome, before, after, object: inspect(this)};
  } catch (error) {
    return {
      protocolVersion: 1,
      ok: false,
      error: boundedText(error && error.message ? error.message : error),
      outcome: "error",
      before: {exists: false, type: "unknown", className: "", writable: false, configurable: false},
      after: {exists: false, type: "unknown", className: "", writable: false, configurable: false},
      object: null
    };
  }
}"""


REQUEST_INTERCEPTION_FUNCTION = r"""async function(config) {
  const started = performance.now();
  const registry = config.controllerRegistryKey
    ? globalThis[config.controllerRegistryKey]
    : null;
  const controller = registry instanceof Map
    ? registry.get(config.executionId)
    : new AbortController();
  if (!(controller instanceof AbortController)) {
    return {
      protocolVersion: 1,
      ok: false,
      error: "Request controller is unavailable",
      durationMs: 0,
      cancelled: false,
      timedOut: false
    };
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, config.timeoutMs);
  try {
    const options = {
      method: config.method,
      headers: config.headers,
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    };
    if (config.body !== "") options.body = config.body;
    const response = await fetch(config.url, options);
    const decoder = new TextDecoder();
    const bodyParts = [];
    let bodyBytes = 0;
    let bodyTruncated = false;
    if (response.body) {
      const reader = response.body.getReader();
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        const remaining = Math.max(0, config.responseByteLimit - bodyBytes);
        if (value.byteLength > remaining) {
          if (remaining > 0) {
            bodyParts.push(decoder.decode(value.subarray(0, remaining), {stream: true}));
            bodyBytes += remaining;
          }
          bodyTruncated = true;
          try { await reader.cancel(); } catch {}
          break;
        }
        bodyParts.push(decoder.decode(value, {stream: true}));
        bodyBytes += value.byteLength;
        if (bodyBytes === config.responseByteLimit) {
          const next = await reader.read();
          if (!next.done) {
            bodyTruncated = true;
            try { await reader.cancel(); } catch {}
          }
          break;
        }
      }
      bodyParts.push(decoder.decode());
    }
    const headers = [];
    const headerEncoder = new TextEncoder();
    let headerBytes = 0;
    let headersTruncated = false;
    for (const [name, value] of response.headers.entries()) {
      if (["set-cookie", "set-cookie2"].includes(name.toLowerCase())) continue;
      if (headers.length >= config.headerLimit) {
        headersTruncated = true;
        break;
      }
      const encodedValue = headerEncoder.encode(value);
      const boundedValue = encodedValue.byteLength <= config.headerValueLimit
        ? value
        : new TextDecoder().decode(encodedValue.subarray(0, config.headerValueLimit));
      const entryBytes = headerEncoder.encode(name).byteLength + headerEncoder.encode(boundedValue).byteLength;
      if (headerBytes + entryBytes > config.headerTotalLimit) {
        headersTruncated = true;
        break;
      }
      headerBytes += entryBytes;
      headers.push({name, value: boundedValue});
      if (encodedValue.byteLength > config.headerValueLimit) headersTruncated = true;
    }
    return {
      protocolVersion: 1,
      ok: true,
      status: response.status,
      statusText: response.statusText.slice(0, 256),
      url: response.url,
      headers,
      headersTruncated,
      body: bodyParts.join(""),
      bodyTruncated,
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      cancelled: false,
      timedOut: false
    };
  } catch (error) {
    let message = "Request failed";
    try { message = String(error && error.message ? error.message : error); } catch {}
    const cancelled = controller.signal.aborted && !timedOut;
    return {
      protocolVersion: 1,
      ok: false,
      error: (timedOut ? "Request timed out" : cancelled ? "Request cancelled" : message).slice(0, 512),
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      cancelled,
      timedOut
    };
  } finally {
    clearTimeout(timer);
    if (registry instanceof Map) {
      registry.delete(config.executionId);
      if (registry.size === 0) {
        try { delete globalThis[config.controllerRegistryKey]; } catch {}
      }
    }
  }
}"""
