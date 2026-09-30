function(criteria) {
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
}
