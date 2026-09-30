function(config) {
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
}
