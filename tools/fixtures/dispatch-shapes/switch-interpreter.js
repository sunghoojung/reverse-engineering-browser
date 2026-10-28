// Repository-owned fixture. A switch interpreter over a byte array cursor.
function runSwitch(code) {
  let pc = 0;
  let acc = 0;
  while (pc < code.length) {
    switch (code[pc++]) {
      case 0:
        break;
      case 1:
        acc += 1;
        break;
      case 2:
        acc -= 1;
        break;
      case 3:
        return acc;
      default:
        throw new Error("unknown opcode");
    }
  }
  return acc;
}
