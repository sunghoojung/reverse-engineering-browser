const guestProgram = Uint8Array.of(1, 7, 2, 3, 0);

export function runGuest(host, program = guestProgram) {
  let accumulator = 0;
  let pc = 0;
  while (pc < program.length) {
    switch (program[pc++]) {
      case 0: return accumulator;
      case 1: accumulator += program[pc++]; break;
      case 2: accumulator ^= program[pc++]; break;
      case 3: return host.canvasReadback(accumulator);
      default: throw new Error("unknown guest opcode");
    }
  }
  return accumulator;
}
