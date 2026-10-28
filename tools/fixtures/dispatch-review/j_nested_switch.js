function run(program, mode){
  var pc=0, stack=[];
  switch(mode){
    case 0: stack.push(0); break;
    case 1: stack.push(1); break;
    case 2: while(pc<program.length){ switch(program[pc++]){ case 10: stack.push(1); break; case 11: stack.pop(); break; case 12: return stack; } } break;
  }
  return stack;
}
