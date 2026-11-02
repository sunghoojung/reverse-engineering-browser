// Repository-owned original fixture. No vendor code or injected probe.
// Bootstrap creates the real instance; initialize is ordinary later activity.
function createOwnedColdIdentityProgram(bytes, mutate, eager = false) {
  const module = new WebAssembly.Module(bytes);
  const instance = new WebAssembly.Instance(module, { owned: { mutate } });
  const program = Object.freeze({ module, instance, initialize: instance.exports.initialize });
  if (eager) program.initialize();
  return program;
}
