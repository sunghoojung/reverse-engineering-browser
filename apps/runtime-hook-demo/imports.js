"use strict";

// (module (import "env" "clock" (func (result i32)))
//   (func (export "run") (result i32) call 0))
const ownedModuleBytes = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0,
  1, 5, 1, 96, 0, 1, 127,
  2, 13, 1, 3, 101, 110, 118, 5, 99, 108, 111, 99, 107, 0, 0,
  3, 2, 1, 0,
  7, 7, 1, 3, 114, 117, 110, 0, 1,
  10, 6, 1, 4, 0, 16, 0, 11,
]);
let calls = 0;
let unexpectedInspection = 0;
function ownedClock() {
  const result = ++calls;
  return result;
}
function createOwnedModule(pause) {
  const imports = {
    env: { clock: ownedClock },
    get accessorNamespace() { unexpectedInspection++; throw new Error("Do not invoke getters"); },
    proxyNamespace: new Proxy({}, { ownKeys() { unexpectedInspection++; throw new Error("Do not inspect proxies"); } }),
  };
  if (pause) debugger; // Explicit fixture button only, never automatic instrumentation.
  return new WebAssembly.Instance(new WebAssembly.Module(ownedModuleBytes), imports);
}
let instance = createOwnedModule(false);
document.querySelector("#inspect").addEventListener("click", () => {
  instance = createOwnedModule(true);
  document.querySelector("#result").textContent = `Inspection finished; unexpected getters/proxy traps: ${unexpectedInspection}`;
});
document.querySelector("#run").addEventListener("click", () => {
  document.querySelector("#result").textContent = `env.clock returned ${instance.exports.run()}; unexpected getters/proxy traps: ${unexpectedInspection}`;
});
