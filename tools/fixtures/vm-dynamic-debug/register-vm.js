function runRegisterVm(program) {
  let ip = 0;
  const regs = new Uint8Array(8);
  while (ip < program.length) {
    const opcode = program[ip++];
    switch (opcode) {
      case 16:
        regs[program[ip++]] = program[ip++];
        break;
      case 17:
        regs[program[ip++]] += regs[program[ip++]];
        break;
      case 18:
        ip = regs[program[ip++]];
        break;
      case 19:
        return regs[0];
      default:
        return 0;
    }
  }
}
