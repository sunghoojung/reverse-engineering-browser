// Repository-owned fixture. A rotated loop: the first opcode is fetched
// before the loop and each later opcode at the end of the body.
function runRotated(code) {
  let pc = 0;
  let acc = 0;
  let op = code[pc++];
  while (op !== 0) {
    switch (op) {
      case 1:
        acc += 1;
        break;
      case 2:
        acc -= 1;
        break;
      case 3:
        return acc;
    }
    op = code[pc++];
  }
  return acc;
}
