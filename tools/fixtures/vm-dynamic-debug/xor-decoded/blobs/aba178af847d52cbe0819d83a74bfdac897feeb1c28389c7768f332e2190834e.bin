function runDecodedVm(program) {
  let pc = 0;
  const stack = [];
  while (pc < program.length) {
    const opcode = program[pc++];
    switch (opcode) {
      case 80:
        stack.push(program[pc++] - 48);
        break;
      case 81:
        stack.push(stack.pop() + stack.pop());
        break;
      case 82:
        pc = program[pc];
        break;
      case 83:
        return stack.pop();
      default:
        return 0;
    }
  }
}

function decodeAndRun(ciphertext, key) {
  const program = new Uint8Array(ciphertext.length);
  for (let index = 0; index < ciphertext.length; index++) {
    program[index] = ciphertext.charCodeAt(index) ^ key;
  }
  return runDecodedVm(program);
}

const ciphertext = "\\x0a\\x6b\\x0a\\x68\\x0b\\x09";
decodeAndRun(ciphertext, 0x5a);
