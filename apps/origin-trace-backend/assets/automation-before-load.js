(() => {
  if (globalThis !== globalThis.top) return;
  const report = globalThis[@@binding@@];
  if (typeof report !== "function") return;
  const run = (@@AUTOMATION_RECIPE_FUNCTION@@);
  const nonce = @@encoded_nonce@@;
  const documentId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const configs = @@encoded_configs@@;
  const reportEncoder = new TextEncoder();
  const send = value => {
    let payload = JSON.stringify(value);
    if (reportEncoder.encode(payload).length > @@MAX_AUTOMATION_BINDING_REPORT_BYTES@@) {
      const result = value && value.kind === "done" && value.result;
      if (!result || typeof result !== "object") return;
      value = {...value, result: {...result, resultText: "", resultTruncated: true,
        logs: [], logsTruncated: true}};
      payload = JSON.stringify(value);
      if (reportEncoder.encode(payload).length > @@MAX_AUTOMATION_BINDING_REPORT_BYTES@@) return;
    }
    report(payload);
  };
  void (async () => {
    for (const entry of configs) {
      send({protocolVersion:1, nonce, kind:"start", recipeId:entry.recipeId, documentId});
      const result = await run(entry.config);
      send({protocolVersion:1, nonce, kind:"done", recipeId:entry.recipeId, documentId, result});
    }
  })();
})();
//# sourceURL=reb-automation-before-load.js
