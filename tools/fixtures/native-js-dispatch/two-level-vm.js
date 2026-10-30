// Repository-owned fixture for the native JavaScript dispatch probe. The
// comment characters Ω and 𝔵 make UTF-8 byte offsets differ from the UTF-16
// offsets V8 uses, so every anchor conversion is exercised.
// The outer interpreter switches on its opcode; opcode 3 runs an inner
// handler-table interpreter over its own bytecode and opcode 4 dispatches one
// extended handler from the outer program.
'use strict';
function runInner(code, s) {
  const ops = [
    function (st) { st.acc += 1; },
    function (st) { st.acc *= 2; },
    function (st) { st.acc -= 3; },
    function (st) { st.halt = true; },
  ];
  let pc = 0;
  s.halt = false;
  while (!s.halt && pc < code.length) {
    ops[code[pc++]](s);
  }
  return s.acc;
}
function runOuter(program, inner) {
  const s = { acc: 0, halt: false, out: [] };
  const ext = [
    function (st) { st.acc = 0; },
    function (st) { st.acc += 100; },
    function (st) { st.out.push(-1); },
    function (st) { st.out.push(st.acc); },
  ];
  let pc = 0;
  while (pc < program.length) {
    switch (program[pc++]) {
      case 0: s.acc = 0; break;
      case 1: s.acc += 10; break;
      case 2: s.out.push(s.acc); break;
      case 3: runInner(inner, s); break;
      case 4: ext[program[pc++]](s); break;
      case 7: return s.out;
      default: return s.out;
    }
  }
  return s.out;
}
runOuter([0, 1, 3, 2, 4, 3, 7], [0, 1, 3]);
