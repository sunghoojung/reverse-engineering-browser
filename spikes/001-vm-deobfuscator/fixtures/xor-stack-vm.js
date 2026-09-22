// Synthetic fixture: XOR-encoded bytecode plus a stack VM dispatcher.
const bytecode = [0x9a, 7, 0x9a, 5, 0xaa, 0xea];
let pc = 0;
const stack = [];
while (pc < bytecode.length) {
  const opcode = bytecode[pc++] ^ 0x8a;
  switch (opcode) {
    case 0x10: stack.push(bytecode[pc++]); break;
    case 0x20: { const right = stack.pop(); const left = stack.pop(); stack.push(left + right); break; }
    case 0x60: return stack.pop();
  }
}
