// Example document-start Console snippet for the repository-authored synthetic
// page. It runs in the page main world before that document's own scripts, so
// it can observe the page defining `window.syntheticTransform`.
//
// It logs only argument kinds and lengths, the return length, and a digest. It
// never logs a raw string, so it cannot leak a token, cookie, credential or
// body even if the observed function handled one. Keep that property in any
// snippet you write: output is bounded, ephemeral page JavaScript, but it is
// still readable by anything that reads the API.
const digest = (text) => {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash = Math.imul(hash ^ text.charCodeAt(index), 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
};
const shape = (value) =>
  typeof value === 'string'
    ? `string:${value.length}`
    : Array.isArray(value)
      ? `array:${value.length}`
      : typeof value;
let target;
let calls = 0;
const observe = (original) =>
  function observed(...args) {
    const result = original.apply(this, args);
    calls += 1;
    // Bound the snippet's own output well under the per-document budget so the
    // interesting first calls are never evicted by a chatty page.
    if (calls <= 8) {
      report(
        `call=${calls} args=${args.map(shape).join(',')} return=${shape(result)}` +
          (typeof result === 'string' ? ` digest=${digest(result)}` : ''),
      );
    }
    return result;
  };
Object.defineProperty(window, 'syntheticTransform', {
  configurable: true,
  get() {
    return target;
  },
  set(value) {
    report(`defined=${shape(value)}`);
    target = typeof value === 'function' ? observe(value) : value;
  },
});
report('observer=installed');
