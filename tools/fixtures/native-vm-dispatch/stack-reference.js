// Inert reference for owned-stack-v1, never executed by the recorder/analyzer.
// Declared source mapping only. Native execution remains src/analysis/owned_vm_fixture.cpp.
// PC units: instruction-index. Entries 7 and 9 are unsupported, not guest bytes.
function ownedStackReference() {
  const program = [1, 1, 2, 3, 4, 5, 6, null, 7, null, 8];
  const immediates = [7n, 5n];
  const stack = [];
  const memory = {};
  let pc = 0;
  while (pc < program.length) {
    const position = pc;
    switch (program[pc++]) {
      case 1: stack.push(immediates[position]); break;
      case 2: stack[0] = (stack[0] + stack.pop()) & ((1n << 64n) - 1n); break;
      case 3: memory[16] = stack.pop(); break;
      case 4: stack.push(memory[16]); break;
      case 5: if (stack[0] === 0n) pc = 10; break;
      case 6: pc = 8; break;
      case 7: if (stack[0] !== 0n) pc = 10; break;
      case 8: pc = position; return {pc, stack, memory};
      default: throw new Error('Unsupported owned instruction');
    }
  }
}
