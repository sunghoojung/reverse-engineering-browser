// Repository-owned fixture. Threaded code: each handler fetches the next
// opcode at the cursor and tail-calls that opcode's handler. No loop drives
// the dispatch; the handler table re-enters itself.
function runThreaded(code) {
  let pc = 0;
  const state = { acc: 0 };
  const ops = [
    function (s) {
      s.acc += 1;
      return ops[code[pc++]](s);
    },
    function (s) {
      s.acc -= 1;
      return ops[code[pc++]](s);
    },
    function (s) {
      return s.acc;
    },
  ];
  return ops[code[pc++]](state);
}
