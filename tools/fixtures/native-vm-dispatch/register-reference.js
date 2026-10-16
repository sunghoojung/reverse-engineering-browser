// Inert reference for owned-register-v1, never executed by the recorder/analyzer.
// Declared source mapping only. Native execution remains src/analysis/owned_vm_fixture.cpp.
// PC units: instruction-index. Entries 7 and 9 are unsupported, not guest bytes.
function ownedRegisterReference() {
  const program = [1, 1, 2, 3, 4, 5, 6, null, 7, null, 8];
  const immediates = [7n, 5n];
  const registers = [null, null, null];
  const memory = {};
  let pc = 0;
  while (pc < program.length) {
    const position = pc;
    switch (program[pc++]) {
      case 1: registers[position] = immediates[position]; break;
      case 2: registers[0] = (registers[0] + registers[1]) & ((1n << 64n) - 1n); break;
      case 3: memory[16] = registers[0]; break;
      case 4: registers[2] = memory[16]; break;
      case 5: if (registers[2] === 0n) pc = 10; break;
      case 6: pc = 8; break;
      case 7: if (registers[2] !== 0n) pc = 10; break;
      case 8: pc = position; return {pc, registers, memory};
      default: throw new Error('Unsupported owned instruction');
    }
  }
}
