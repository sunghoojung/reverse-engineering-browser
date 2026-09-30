async function(config) {
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
}
