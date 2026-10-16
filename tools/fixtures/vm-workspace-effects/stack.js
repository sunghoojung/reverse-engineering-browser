// Repository-owned byte-encoded fixture. PC and branch targets are byte offsets.
function runOwnedStack(program) {
  let pc = 0;
  const stack = [];
  const memory = new Map();
  while (pc < program.length) {
    const opcode = program[pc++];
    switch (opcode) {
      case 1:
        stack.push(BigInt(program[pc++]));
        break;
      case 2: {
        const right = stack.pop();
        const left = stack.pop();
        stack.push(BigInt.asUintN(64, left + right));
        break;
      }
      case 3:
        memory.set(program[pc++], stack.pop());
        break;
      case 4:
        stack.push(memory.get(program[pc++]));
        break;
      case 5: {
        const target = program[pc++];
        if (stack.at(-1) === 0n) pc = target;
        break;
      }
      case 6:
        pc = program[pc];
        break;
      case 7: {
        const target = program[pc++];
        if (stack.at(-1) !== 0n) pc = target;
        break;
      }
      case 8:
        return;
      default:
        throw new Error("Unknown owned opcode");
    }
  }
}
const program = new Uint8Array([1, 7, 1, 5, 2, 3, 16, 4, 16, 5, 15, 7, 15, 6, 15, 8]);
