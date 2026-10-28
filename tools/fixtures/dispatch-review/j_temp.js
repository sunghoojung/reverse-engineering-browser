function run(program){
  var pc=0, stack=[], handlers=[];
  handlers[0]=function(){stack.push(1)};
  handlers[1]=function(){stack.pop()};
  handlers[2]=function(){stack.push(stack.pop()+stack.pop())};
  while(pc<program.length){ var h=handlers[program[pc++]]; h(); }
  return stack;
}
