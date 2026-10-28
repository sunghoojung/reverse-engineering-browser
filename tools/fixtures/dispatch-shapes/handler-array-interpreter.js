// Repository-owned fixture. A function-array handler table indexed by the
// opcode at the cursor, called once per loop iteration.
function runHandlers(code) {
  const state = { acc: 0, halted: false };
  const handlers = [
    function (s) { s.acc += 1; },
    function (s) { s.acc -= 1; },
    function (s) { s.halted = true; },
  ];
  let pc = 0;
  while (!state.halted && pc < code.length) {
    handlers[code[pc++]](state);
  }
  return state.acc;
}
