// Owned source fixture. The integration harness supplies initialized bytes;
// running this source is reserved for the patched-browser acceptance gate.
const guestProgram = new Uint8Array(32);
function runGuest(host, program = guestProgram) {
  let accumulator = 0;
  let pc = 0;
  while (pc < program.length) {
    switch (program[pc++]) {
      case 0: return accumulator;
      case 1: accumulator += program[pc++]; break;
      case 2: accumulator ^= program[pc++]; break;
      case 3: return host.canvasReadback(accumulator);
      default: throw new Error('unknown guest opcode');
    }
  }
  return accumulator;
}
