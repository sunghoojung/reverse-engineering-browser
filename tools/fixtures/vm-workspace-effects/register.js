// Repository-owned byte-encoded fixture. PC and branch targets are byte offsets.
function runOwnedRegister(program) {
  let pc = 0;
  const registers = [];
  const memory = new Map();
  while (pc < program.length) {
    const opcode = program[pc++];
    switch (opcode) {
      case 1: {
        const destination = program[pc++];
        registers[destination] = BigInt(program[pc++]);
        break;
      }
      case 2: {
        const destination = program[pc++];
        const left = program[pc++];
        const right = program[pc++];
        registers[destination] = BigInt.asUintN(64, registers[left] + registers[right]);
        break;
      }
      case 3: {
        const address = program[pc++];
        memory.set(address, registers[program[pc++]]);
        break;
      }
      case 4: {
        const destination = program[pc++];
        registers[destination] = memory.get(program[pc++]);
        break;
      }
      case 5: {
        const condition = program[pc++];
        const target = program[pc++];
        if (registers[condition] === 0n) pc = target;
        break;
      }
      case 6:
        pc = program[pc];
        break;
      case 7: {
        const condition = program[pc++];
        const target = program[pc++];
        if (registers[condition] !== 0n) pc = target;
        break;
      }
      case 8:
        return;
      default:
        throw new Error("Unknown owned opcode");
    }
  }
}
const program = new Uint8Array([1, 0, 7, 1, 1, 5, 2, 0, 0, 1, 3, 16, 0, 4, 2, 16, 5, 2, 24, 7, 2, 24, 6, 24, 8]);
