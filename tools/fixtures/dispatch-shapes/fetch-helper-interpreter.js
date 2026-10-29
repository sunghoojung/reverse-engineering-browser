// Repository-owned fixture. The opcode is fetched through a statically bound
// helper that returns the byte at the cursor and advances the cursor.
function runFetched(code) {
  let pc = 0;
  let acc = 0;
  function fetch() {
    return code[pc++];
  }
  while (pc < code.length) {
    switch (fetch()) {
      case 1:
        acc += 1;
        break;
      case 2:
        acc -= 1;
        break;
      case 3:
        return acc;
    }
  }
  return acc;
}
