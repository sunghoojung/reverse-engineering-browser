function runStackVm(program) {
  let pc = 0;
  const stack = [];
  while (pc < program.length) {
    const opcode = program[pc++];
    switch (opcode) {
      case 80: // push
        stack.push(program[pc++] - 48);
        break;
      case 81: // add
        stack.push(stack.pop() + stack.pop());
        break;
      case 82: // jump
        pc = program[pc];
        break;
      case 83: // halt
        return stack.pop();
      default:
        throw new Error("unknown opcode");
    }
  }
}

const program = new Uint8Array([80, 49, 80, 50, 81, 83]);
