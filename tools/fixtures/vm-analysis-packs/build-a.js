// Owned comparison fixture. Effects are explicit fixture declarations, not recovered code.
function fixture(opcode, state) {
  switch (opcode) {
    case 1: state.stack.push(7); break;
    case 2: return;
    case 4: state.registers[0] += state.registers[1]; break;
    case 7: return state.dynamic(opcode);
    case 8: state.stack.push(8); break;
  }
}
